"""Scan one accuracy case with the real graph, offline, and compare the result
with what the case expects.

The scan is `agent_bridge.run_real_scan` with the real `scan_runner` writers
against a throwaway SQLite database, so identity, verdict history, exports and
the consistency check all see exactly what a production scan would write. Only
the LLM provider is replaced:

* **replay** (default): every call is answered from the case's recorded
  responses; a call with no recording fails the case ("unrecorded LLM call").
  The provider functions are stubbed to refuse, cloud credentials are removed
  from the environment for the run, and the engine loader is pinned (it reloads
  `llm_client` on every call, which would otherwise undo the stubs). A replay
  run cannot reach the network.
* **record, scripted** (`ACCURACY_RECORD=scripted`): a fake provider answers from
  the case's `scripted:` entries and writes the recordings. No network.
* **record, live** (`ACCURACY_RECORD=live`): the real provider answers; this is
  the only mode that spends money, and it must be chosen explicitly.
"""

from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator

from accuracy.case import (
    LINE_TOLERANCE,
    PINNED_MODEL,
    PINNED_PROVIDER,
    Case,
    Expected,
)
from accuracy.replay_cache import RECORD, REPLAY, ReplayResultCache, UnrecordedLlmCall

RECORD_SCRIPTED = "scripted"
RECORD_LIVE = "live"

_CLOUD_ENV_PREFIXES = ("AWS_", "OPENAI_", "ANTHROPIC_")


@dataclass
class CaseResult:
    case_id: str
    area: str
    polarity: str
    adjudication: str
    xfail: str | None
    status: str = "pass"  # pass | fail | xfail | xpass
    missing: list[str] = field(default_factory=list)
    unexpected: list[str] = field(default_factory=list)
    mismatches: list[str] = field(default_factory=list)
    unrecorded: list[str] = field(default_factory=list)
    error: str | None = None
    findings: list[dict[str, Any]] = field(default_factory=list)
    consistency: list[str] = field(default_factory=list)

    @property
    def problems(self) -> list[str]:
        out = [*self.missing, *self.unexpected, *self.mismatches, *self.unrecorded]
        if self.error:
            out.append(self.error)
        return out

    @property
    def passed(self) -> bool:
        return not self.problems

    def to_dict(self) -> dict[str, Any]:
        return {
            "case": self.case_id, "area": self.area, "polarity": self.polarity,
            "adjudication": self.adjudication, "xfail": self.xfail, "status": self.status,
            "missing": self.missing, "unexpected": self.unexpected,
            "mismatches": self.mismatches, "unrecorded": self.unrecorded,
            "error": self.error, "consistency": self.consistency, "findings": self.findings,
        }


# --- comparing findings with expectations -----------------------------------

def _identifies(expected: Expected, finding: dict[str, Any]) -> bool:
    if finding["file_path"] != expected.file:
        return False
    if abs(int(finding["line"] or 0) - expected.sink_line) > LINE_TOLERANCE:
        return False
    if expected.rule_id and finding["rule_id"] == expected.rule_id:
        return True
    return bool(expected.cwe and (finding["cwe"] or "").upper() == expected.cwe.upper())


def compare(case: Case, findings: list[dict[str, Any]]) -> tuple[list[str], list[str], list[str]]:
    """(missing, unexpected, mismatches) for one case's persisted findings."""
    missing: list[str] = []
    mismatches: list[str] = []
    claimed: set[int] = set()
    for expected in case.expected:
        label = f"{expected.rule_id or expected.cwe} {expected.file}:{expected.sink_line}"
        candidates = [
            (i, f) for i, f in enumerate(findings) if i not in claimed and _identifies(expected, f)
        ]
        if not candidates:
            if not (case.allow_absent and expected.verdict == "false_positive"):
                missing.append(f"missing expected finding: {label} ({expected.verdict})")
            continue
        # Prefer the candidate that names the expected rule, then one that
        # already agrees on the verdict, then the nearest line.
        index, finding = min(
            candidates,
            key=lambda item: (
                item[1]["rule_id"] != expected.rule_id,
                item[1]["verdict"] != expected.verdict,
                abs(int(item[1]["line"] or 0) - expected.sink_line),
            ),
        )
        claimed.add(index)
        if finding["verdict"] != expected.verdict:
            mismatches.append(
                f"verdict mismatch: {label} expected {expected.verdict}, got {finding['verdict']}"
            )
            continue
        if expected.issue_class and finding["issue_class"] != expected.issue_class:
            mismatches.append(
                f"issue_class mismatch: {label} expected {expected.issue_class}, "
                f"got {finding['issue_class']}"
            )
        if expected.unresolved_reason and finding["unresolved_reason"] != expected.unresolved_reason:
            mismatches.append(
                f"unresolved_reason mismatch: {label} expected {expected.unresolved_reason}, "
                f"got {finding['unresolved_reason']}"
            )
        if expected.reason_tag and expected.reason_tag.lower() not in (
            finding["verdict_reason"] or ""
        ).lower():
            mismatches.append(
                f"reason_tag mismatch: {label} reason does not mention {expected.reason_tag!r}"
            )
    unexpected = [
        f"unexpected finding: {f['rule_id']} {f['file_path']}:{f['line']} ({f['verdict']})"
        for i, f in enumerate(findings) if i not in claimed
    ]
    return missing, unexpected, mismatches


# --- the LLM provider stand-ins ---------------------------------------------

def _scripted_provider(case: Case):
    """A fake `llm_client._call_bedrock` answering from the case's `scripted`
    entries: the first entry whose `step` matches and whose `when_user_contains`
    substrings all appear in the prompt. Anything unscripted gets an empty but
    valid answer for its step, so a recording is always complete."""

    def provider(system, user, model_id, max_tokens, temperature, retries, *,
                 usage=None, step="unknown", meta_out=None, **_kwargs):
        for entry in case.scripted:
            if entry.get("step") not in (None, step):
                continue
            if all(token in user for token in entry.get("when_user_contains") or []):
                text = json.dumps(entry["response"])
                break
        else:
            text = json.dumps(
                {"findings": []} if step in ("scan_deep_files", "verify_flow_slices")
                else {"decisions": []}
            )
        if meta_out is not None:
            meta_out.update({
                "input_tokens": max(1, (len(system) + len(user)) // 4),
                "output_tokens": max(1, len(text) // 4), "stop_reason": "end_turn",
            })
        return text

    return provider


def _refusing_provider(unrecorded: list[str]):
    def provider(system, user, *_args, step="unknown", **_kwargs):
        unrecorded.append(f"unrecorded LLM call: step={step} prompt={user[:60].strip()!r}…")
        raise UnrecordedLlmCall(f"no recorded response for a {step!r} call")

    return provider


@contextmanager
def _isolated_environment() -> Iterator[None]:
    """No cloud credentials, no Joern, for the duration of a replayed run."""
    saved = {k: v for k, v in os.environ.items() if k.startswith(_CLOUD_ENV_PREFIXES)}
    saved_joern = os.environ.get("JOERN_HOME")
    empty = tempfile.mkdtemp(prefix="no-joern-")
    for key in saved:
        del os.environ[key]
    os.environ["AWS_EC2_METADATA_DISABLED"] = "true"
    os.environ["JOERN_HOME"] = empty
    try:
        yield
    finally:
        os.environ.pop("AWS_EC2_METADATA_DISABLED", None)
        os.environ.update(saved)
        if saved_joern is None:
            os.environ.pop("JOERN_HOME", None)
        else:
            os.environ["JOERN_HOME"] = saved_joern
        shutil.rmtree(empty, ignore_errors=True)


def _summarize(finding: Any) -> dict[str, Any]:
    return {
        "file_path": finding.file_path, "line": finding.line, "rule_id": finding.rule_id,
        "cwe": finding.cwe, "verdict": finding.verdict, "issue_class": finding.issue_class,
        "unresolved_reason": finding.unresolved_reason, "verdict_reason": finding.verdict_reason,
        "kind": finding.kind, "confidence": finding.confidence,
        "occurrence_id": finding.occurrence_id,
    }


def run_case(case: Case, *, record: str | None = None) -> CaseResult:
    """Scan `case` and compare. `record` is None (replay), RECORD_SCRIPTED or
    RECORD_LIVE."""
    from app import db as db_module
    from app.db import init_db
    from app.models import Finding, Project, Scan
    from app.services import agent_bridge, scan_runner

    result = CaseResult(
        case_id=case.id, area=case.area, polarity=case.polarity,
        adjudication=case.adjudication, xfail=case.xfail,
    )
    if record not in (None, RECORD_SCRIPTED, RECORD_LIVE):
        raise ValueError(f"unknown record mode {record!r}")

    cache = ReplayResultCache(case.responses_dir, RECORD if record else REPLAY)
    if record:
        cache.clear()
    unrecorded: list[str] = []

    with tempfile.TemporaryDirectory(prefix="accuracy-") as tmp_name:
        tmp = Path(tmp_name)
        workspace = tmp / "repo"
        shutil.copytree(case.source_dir, workspace)
        init_db(f"sqlite:///{(tmp / 'case.db').as_posix()}")
        isolation = _isolated_environment() if record != RECORD_LIVE else _null_context()
        original_loader = agent_bridge._load_agent_module
        with isolation:
            try:
                agent = original_loader()
                llm_client = sys.modules["llm_client"]
                # The loader reloads llm_client on every call; pin it so the
                # provider stand-ins installed below survive run_real_scan.
                agent_bridge._load_agent_module = lambda: agent
                if record != RECORD_LIVE:
                    provider = (
                        _scripted_provider(case) if record == RECORD_SCRIPTED
                        else _refusing_provider(unrecorded)
                    )
                    llm_client._call_bedrock = provider
                    llm_client._call_openai_compat = _refusing_provider(unrecorded)
                    llm_client._call_ollama = _refusing_provider(unrecorded)

                with db_module.SessionLocal() as db:
                    project = Project(
                        name=f"accuracy-{case.id}", default_git_url="https://example.invalid/repo.git",
                        llm_provider=PINNED_PROVIDER, llm_model=PINNED_MODEL,
                        limitations_config=dict(case.limitations),
                    )
                    db.add(project)
                    db.commit()
                    scan = Scan(
                        project_id=project.id, git_url=project.default_git_url,
                        llm_provider=PINNED_PROVIDER, llm_model=PINNED_MODEL,
                    )
                    db.add(scan)
                    db.commit()
                    project_id, scan_id = project.id, scan.id

                with db_module.SessionLocal() as db:
                    agent_bridge.run_real_scan(
                        project=db.get(Project, project_id), workspace=workspace,
                        changed_paths=None, scan_id=scan_id, scan=db.get(Scan, scan_id),
                        findings_writer=scan_runner._make_findings_writer(scan_id),
                        verdict_updates_writer=scan_runner._make_verdict_updates_writer(scan_id),
                        reachability_updates_writer=scan_runner._make_reachability_updates_writer(scan_id),
                        result_cache=cache, state_overrides=dict(case.state_overrides),
                    )
                with db_module.SessionLocal() as db:
                    rows = db.query(Finding).filter(Finding.scan_id == scan_id).all()
                    result.findings = sorted(
                        (_summarize(f) for f in rows),
                        key=lambda f: (f["file_path"] or "", f["line"] or 0, f["rule_id"] or ""),
                    )
            except Exception as exc:  # noqa: BLE001 - a crashed case is a failed case
                result.error = f"{type(exc).__name__}: {exc}"
            finally:
                agent_bridge._load_agent_module = original_loader

    if unrecorded:
        result.unrecorded = sorted(set(unrecorded))
    if not result.error and not result.unrecorded:
        result.missing, result.unexpected, result.mismatches = compare(case, result.findings)
    result.status = _status(case, result)
    return result


@contextmanager
def _null_context() -> Iterator[None]:
    yield


def _status(case: Case, result: CaseResult) -> str:
    if case.xfail:
        return "xpass" if result.passed else "xfail"
    return "pass" if result.passed else "fail"


def summarize(results: list[CaseResult]) -> dict[str, Any]:
    """Totals by area and polarity for the build artifact."""
    def tally(key: str) -> dict[str, dict[str, int]]:
        out: dict[str, dict[str, int]] = {}
        for r in results:
            bucket = out.setdefault(getattr(r, key), {"pass": 0, "fail": 0, "xfail": 0, "xpass": 0})
            bucket[r.status] += 1
        return out

    return {
        "cases": [r.to_dict() for r in results],
        "totals": {
            "cases": len(results),
            **{s: sum(1 for r in results if r.status == s) for s in ("pass", "fail", "xfail", "xpass")},
        },
        "by_area": tally("area"),
        "by_polarity": tally("polarity"),
    }
