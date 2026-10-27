"""risk_rerank.py — promote catch-all files the path rules could not classify.

`node_map_modules_and_risk` rates a file from its path. A source file that hit
only a catch-all rule (``src/main/java/`` -> MEDIUM "application source
(unclassified package)", ``.ts`` -> MEDIUM "application source
(unclassified)") says nothing about what the file does: a
`GlobalExceptionHandler` under ``config/`` landed there, was never reviewed by
the deep scan and matched no regex.

One LLM pass reads the head of each such file and answers whether it handles
authentication/authorisation, untrusted input, error responses, or security
configuration. A file that does is promoted MEDIUM -> HIGH (the caller picks
CRITICAL instead when the project deep-scans CRITICAL files only). The pass is
additive only: it never demotes, never promotes past that one tier, only ever sees
files that matched no specific rule, and a failed or over-budget call leaves
the file where the path rules put it.
"""

from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence

from llm_client import call_llm, parse_llm_json_array
from pipeline import llm_file_scan

LLM_STEP = "rerank_leftover_files"
HEAD_CHARS = 2000
GENERATED_PEEK_CHARS = 4000
BATCH_FILES = 8
MAX_CANDIDATES = 150
TOKENS_PER_FILE = 40
TOKEN_HEADROOM = 200
HANDLES = ("auth", "input", "errors", "config")

_SYSTEM = (
    "You triage source files for a security review. For each file you are given "
    "(its path and the first lines), say what security-relevant work it does. "
    "Allowed values: auth (authentication, authorisation, sessions, tokens, "
    "crypto), input (reads or parses untrusted input: HTTP requests, files, "
    "messages, queries, deserialisation), errors (builds responses or logs from "
    "exceptions or request data), config (security or framework configuration: "
    "CORS, CSRF, filters, interceptors, credentials, endpoints). Use \"none\" for "
    "plain models, DTOs, constants, mappers, pure computation and anything else. "
    "Precision matters: when the head does not show it, answer \"none\".\n"
    'Respond with one JSON object only: {"decisions": [{"path": "<path as given>", '
    '"handles": ["auth"|"input"|"errors"|"config"] or ["none"]}]}. One decision per file.'
)


def build_user_prompt(batch: Sequence[Dict[str, str]]) -> str:
    parts: List[str] = []
    for item in batch:
        parts.append(f"### FILE {item['path']}\n{item['head']}")
    return "\n\n".join(parts)


def _read_candidate(root: Path, path: str) -> Optional[str]:
    try:
        with open(root / path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read(GENERATED_PEEK_CHARS)
    except OSError:
        return None


def select_candidates(root: Path, paths: Sequence[str], limit: int = MAX_CANDIDATES) -> List[Dict[str, str]]:
    """Readable, non-test, non-generated, non-vendored catch-all files, in the
    order given, capped. Mirrors the filters the deep-scan bucket applies."""
    out: List[Dict[str, str]] = []
    for path in paths:
        if len(out) >= limit:
            break
        if (
            llm_file_scan.is_test_path(path)
            or llm_file_scan.is_non_source_path(path)
            or llm_file_scan.is_excluded_from_finding_scan(path)
        ):
            continue
        text = _read_candidate(root, path)
        if not text or not text.strip():
            continue
        if llm_file_scan.looks_generated(text) or llm_file_scan.looks_vendored_or_minified(path, text):
            continue
        out.append({"path": path, "head": text[:HEAD_CHARS]})
    return out


def _handles_from(value: Any) -> List[str]:
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, list):
        return []
    found = [str(v).strip().lower() for v in value]
    return [h for h in HANDLES if h in found]


def _rerank_batch(
    batch: List[Dict[str, str]],
    *,
    usage: Optional[Dict[str, Any]],
    llm_provider: Optional[str],
    llm_model: Optional[str],
    call_llm_fn: Callable[..., str],
) -> Dict[str, List[str]]:
    user = build_user_prompt(batch)
    max_tokens = TOKEN_HEADROOM + TOKENS_PER_FILE * len(batch)
    known = {item["path"] for item in batch}

    def _call(prompt: str) -> str:
        with llm_file_scan._INFLIGHT:
            return call_llm_fn(
                _SYSTEM, prompt, usage=usage, step=LLM_STEP,
                provider=llm_provider, model=llm_model, json_mode=True,
                max_tokens=max_tokens,
            )

    try:
        items, parse_err = parse_llm_json_array(_call(user))
        if parse_err and not items:
            items, parse_err = parse_llm_json_array(
                _call(user + '\n\nReturn the {"decisions": [...]} JSON object only.')
            )
    except Exception:  # noqa: BLE001 — never fail the scan (incl. LlmBudgetExhausted); files keep their risk
        return {}
    promoted: Dict[str, List[str]] = {}
    if not isinstance(items, list):
        return promoted
    for item in items:
        if not isinstance(item, dict):
            continue
        path = str(item.get("path") or "").strip()
        handles = _handles_from(item.get("handles"))
        if path in known and handles:
            promoted[path] = handles
    return promoted


def rerank_leftover_files(
    root: Path,
    paths: Sequence[str],
    *,
    usage: Optional[Dict[str, Any]] = None,
    llm_provider: Optional[str] = None,
    llm_model: Optional[str] = None,
    call_llm_fn: Optional[Callable[..., str]] = None,
    max_candidates: int = MAX_CANDIDATES,
    workers: int = llm_file_scan.DEFAULT_FILE_WORKERS,
) -> Dict[str, Any]:
    """Return {"promoted": {path: [handles]}, "considered": n}. `paths` are the
    catch-all MEDIUM files, highest priority first."""
    call_llm_fn = call_llm_fn or call_llm  # resolved at call time so tests can patch call_llm
    candidates = select_candidates(root, paths, max_candidates)
    result: Dict[str, Any] = {"promoted": {}, "considered": len(candidates)}
    if not candidates:
        return result
    batches = [candidates[i:i + BATCH_FILES] for i in range(0, len(candidates), BATCH_FILES)]
    lock = threading.Lock()

    def run(batch: List[Dict[str, str]]) -> None:
        got = _rerank_batch(
            batch, usage=usage, llm_provider=llm_provider, llm_model=llm_model,
            call_llm_fn=call_llm_fn,
        )
        with lock:
            result["promoted"].update(got)

    if len(batches) < 2 or workers < 2:
        for batch in batches:
            run(batch)
    else:
        with ThreadPoolExecutor(max_workers=min(workers, len(batches))) as pool:
            list(pool.map(run, batches))
    return result
