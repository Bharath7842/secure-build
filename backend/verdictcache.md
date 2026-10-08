"""
Fingerprint-based verdict caching for LLM-assisted SAST triage.

Design:
  - Fingerprint = stable identity for a finding across scans, based on
    rule_id + file_path + normalized code content — NOT raw line number,
    since that shifts whenever unrelated lines are added/removed elsewhere
    in the file.
  - Verdict cache: once an LLM has triaged a fingerprint, that verdict is
    reused on every later scan until the code at that exact location
    actually changes. The LLM is invoked only for new or changed findings.
  - No self-consistency voting in this hot path — one confident call per
    new/changed finding. Multi-vote self-consistency is deliberately left
    out; run it as a separate offline eval script if you want to measure
    triage stability, not something that runs on every scan.
"""
import hashlib
import json
import re
from pathlib import Path
from typing import Optional


def normalize_snippet(code: str) -> str:
    """Collapse comment/whitespace differences so trivial formatting
    changes don't invalidate the fingerprint, while real code changes do.
    Deliberately naive (regex, not a real parser) — good enough for a
    stable hash key, not meant to be a code analyzer."""
    code = re.sub(r"//.*", "", code)
    code = re.sub(r"/\*.*?\*/", "", code, flags=re.DOTALL)
    code = re.sub(r"#.*", "", code)
    code = re.sub(r"\s+", " ", code).strip()
    return code


def compute_fingerprint(rule_id: str, file_path: str, matched_code: str) -> str:
    """Stable identity for a finding. Deliberately excludes line number
    so the finding survives unrelated edits elsewhere in the file."""
    key = f"{rule_id}::{file_path}::{normalize_snippet(matched_code)}"
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]


def code_hash(matched_code: str) -> str:
    """Detects 'the code at this exact spot changed', even for edits the
    normalizer would otherwise treat as insignificant."""
    return hashlib.sha256(matched_code.encode("utf-8")).hexdigest()[:16]


class VerdictCache:
    def __init__(self, cache_path: Path):
        self.cache_path = cache_path
        self.data: dict = json.loads(cache_path.read_text()) if cache_path.exists() else {}

    def get(self, fingerprint: str, current_code_hash: str) -> Optional[dict]:
        entry = self.data.get(fingerprint)
        if entry and entry.get("code_hash") == current_code_hash:
            return entry
        return None

    def set(self, fingerprint: str, current_code_hash: str, verdict: dict) -> None:
        self.data[fingerprint] = {
            "code_hash": current_code_hash,
            "verdict": verdict["verdict"],
            "reasoning": verdict.get("reasoning", ""),
            "confidence": verdict.get("confidence"),
        }

    def save(self) -> None:
        self.cache_path.write_text(json.dumps(self.data, indent=2))


def triage_finding(finding: dict) -> dict:
    """
    Single LLM call, no self-consistency voting — this is the hot path.
    Wire this to one Claude API request: temperature 0, one sample, ask
    for {verdict: confirmed|false_positive|needs_review, reasoning,
    confidence}. Left unimplemented here since this environment has no
    live API key configured for you to call against.
    """
    raise NotImplementedError(
        "Wire this to a single Claude API call (temperature 0, one "
        "sample) with the finding's rule, matched code, and surrounding "
        "stack context. Return {verdict, reasoning, confidence}."
    )


def process_findings(findings: list[dict], cache: VerdictCache) -> list[dict]:
    """
    findings: normalized results, each needs rule_id, file_path,
    matched_code (the actual snippet — required for fingerprinting).
    Returns findings annotated with verdict and whether it was a cache hit.
    """
    results, cache_hits, llm_calls = [], 0, 0

    for finding in findings:
        fp = compute_fingerprint(finding["rule_id"], finding["file_path"], finding["matched_code"])
        ch = code_hash(finding["matched_code"])
        cached = cache.get(fp, ch)

        if cached:
            cache_hits += 1
            results.append({**finding, "fingerprint": fp, "verdict": cached["verdict"],
                             "reasoning": cached["reasoning"], "source": "cache"})
            continue

        llm_calls += 1
        verdict = triage_finding(finding)
        cache.set(fp, ch, verdict)
        results.append({**finding, "fingerprint": fp, "verdict": verdict["verdict"],
                         "reasoning": verdict.get("reasoning", ""), "source": "llm"})

    cache.save()
    print(f"Triage: {cache_hits} from cache, {llm_calls} new LLM call(s), "
          f"{len(findings)} total findings")
    return results