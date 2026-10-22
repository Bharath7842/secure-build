"""Drives a single scan from queued -> running -> success/failed.

For the mock engine, `start_scan_background` runs `execute_scan` inline
(synchronously) so tests get fully deterministic results with no polling or
sleeping. Non-mock scans run `execute_scan` on a daemon thread so the
triggering HTTP request returns immediately.
"""

import logging
import re
import threading
import traceback
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import func, or_

from app import db as db_module
from app.config import settings
from app.models import DAST_SETTINGS_SNAPSHOT_KEY, UNVERIFIED_VERDICT, Finding, FindingDecision, Scan
from app.dast.domain.identities import identity_from_public
from app.dast.domain.redaction import redact_json, redact_text
from app.services import (
    agent_bridge,
    decisions,
    engine_adapter,
    git_token,
    git_workspace,
    scan_export,
    scan_log,
    scan_versions,
)
from app.services.credential_holder import InMemoryCredentialHolder
from app.services.dast_findings import DastFindingsWriter
from app.services.finding_rows import build_evidence_row, build_finding_row
from app.services.scan_progress import ProgressTracker, infer_progress_from_lines

_cancel_lock = threading.Lock()
_cancel_requested: set[str] = set()
# set = the worker may run; clear = the worker waits inside _should_abort. Cancel sets it so a
# paused worker wakes and then sees the cancel flag.
_pause_events: dict[str, threading.Event] = {}

_PROVIDER_LABELS = {"bedrock": "Bedrock", "ollama": "Ollama", "openai_compat": "OpenAI-compatible"}

# DAST credentials (passwords, tokens, saved sessions), handed over by the trigger endpoint and
# popped when the scan starts: identity id -> secret fields, per scan id. Deliberately in-memory
# only: never written to Scan.metadata_json, the DB, or the scan log (which masks them, see
# `credential_holder.InMemoryCredentialHolder`). A restart loses them, and the scan then fails
# with "credentials lost" rather than running unauthenticated (DAST-06-050).
_dast_secrets_lock = threading.Lock()
_dast_credentials: dict[str, dict[str, dict[str, str]]] = {}


def set_dast_credentials(scan_id: str, credentials: dict[str, dict[str, str]]) -> None:
    with _dast_secrets_lock:
        _dast_credentials[scan_id] = credentials


def _pop_dast_credentials(scan_id: str) -> dict[str, dict[str, str]]:
    with _dast_secrets_lock:
        return _dast_credentials.pop(scan_id, {})


def set_dast_password(scan_id: str, password: str) -> None:
    """Original single-credential entry point, kept for callers that predate identities."""
    set_dast_credentials(scan_id, {"identity-default": {"password": password}})


def _friendly_model_label(provider: str, model: str | None) -> str | None:
    """Turn a raw Bedrock model id (e.g. 'us.anthropic.claude-haiku-4-5-20251001-v1:0')
    into a readable name ('Claude Haiku 4.5'). Ollama tags (e.g. 'granite-code:3b')
    are already short/conventional and left as-is."""
    if not model:
        return None
    if provider != "bedrock":
        return model
    name = re.sub(r"^(us\.|eu\.|apac\.)?anthropic\.", "", model)
    name = re.sub(r"-\d{8}-v\d+:\d+$", "", name)
    name = re.sub(r"(?<=\d)-(?=\d)", ".", name)
    words = [w for w in name.split("-") if w]
    pretty = " ".join(w if w[:1].isdigit() else w.capitalize() for w in words)
    return pretty or model


def _friendly_llm_label(provider: str | None, model: str | None, use_llm: bool) -> str:
    if not use_llm:
        return "heuristics only (no LLM)"
    provider_key = (provider or "").strip().lower()
    provider_label = _PROVIDER_LABELS.get(provider_key, provider or "an LLM")
    model_label = _friendly_model_label(provider_key, model)
    return f"{provider_label} ({model_label})" if model_label else provider_label


def _friendly_scope_label(repo_path: str | None) -> str:
    return f"subdirectory '{repo_path}'" if repo_path else "the full repository"


def _pause_event(scan_id: str) -> threading.Event:
    with _cancel_lock:
        event = _pause_events.get(scan_id)
        if event is None:
            event = threading.Event()
            event.set()
            _pause_events[scan_id] = event
        return event


def request_pause(scan_id: str) -> None:
    _pause_event(scan_id).clear()


def request_resume(scan_id: str) -> None:
    _pause_event(scan_id).set()


def request_cancel(scan_id: str) -> None:
    with _cancel_lock:
        _cancel_requested.add(scan_id)
        event = _pause_events.get(scan_id)
        if event is not None:
            event.set()


def is_cancel_requested(scan_id: str) -> bool:
    with _cancel_lock:
        return scan_id in _cancel_requested


def clear_cancel(scan_id: str) -> None:
    with _cancel_lock:
        _cancel_requested.discard(scan_id)
        _pause_events.pop(scan_id, None)


def _wait_if_paused(scan_id: str) -> None:
    event = _pause_event(scan_id)
    while not event.is_set():
        if is_cancel_requested(scan_id):
            return
        event.wait(0.25)


def _should_abort(scan: Scan | None, scan_id: str) -> bool:
    if scan is None:
        clear_cancel(scan_id)
        return True
    _wait_if_paused(scan_id)
    return scan.status == "cancelled" or is_cancel_requested(scan_id)


def _build_report_from_db_findings(db, scan_id: str) -> dict | None:
    """Build a scan report rollup from persisted Finding rows."""
    from app.services.feedback import effective_verdicts_by_id

    rows = db.query(Finding).filter(Finding.scan_id == scan_id).all()
    if not rows:
        return None
    # Reviewer verdicts win over the LLM's; read through a map so the rows stay untouched.
    verdicts = effective_verdicts_by_id(db, scan_id, rows)
    tp_count = sum(1 for row in rows if verdicts[row.id] == "true_positive")
    fp_count = sum(1 for row in rows if verdicts[row.id] == "false_positive")
    # Regex-only findings carry `unverified`. They are counted separately so
    # they neither inflate the confirmed total nor vanish from the report.
    unverified_count = sum(1 for row in rows if verdicts[row.id] == UNVERIFIED_VERDICT)
    file_paths = {row.file_path for row in rows if row.file_path}
    by_owasp: dict[str, dict[str, int]] = {}
    for row in rows:
        category = row.owasp_category or "Unknown"
        bucket = by_owasp.setdefault(
            category, {"true_positive": 0, "false_positive": 0, UNVERIFIED_VERDICT: 0}
        )
        if verdicts[row.id] in bucket:
            bucket[verdicts[row.id]] += 1
    return {
        "files_scanned": len(file_paths),
        "tp_count": tp_count,
        "fp_count": fp_count,
        "unverified_count": unverified_count,
        "by_owasp_category": by_owasp,
    }


def sync_findings_report_to_metadata(db, scan_id: str, force: bool = False) -> dict | None:
    """Merge DB finding counts into Scan.metadata_json.discovery.report.

    Called when a scan is cancelled so the UI can show partial results that
    were written incrementally during CRITICAL-file scanning."""
    report = _build_report_from_db_findings(db, scan_id)
    if report is None:
        return None
    scan = db.get(Scan, scan_id)
    if scan is None:
        return None
    metadata = dict(scan.metadata_json or {})
    discovery = dict(metadata.get("discovery") or {})
    existing = discovery.get("report") or {}
    existing_total = int(existing.get("tp_count") or 0) + int(existing.get("fp_count") or 0)
    new_total = report["tp_count"] + report["fp_count"]
    # `force`: a reviewer decision can lower the confirmed total, which the guard would block.
    if force or new_total >= existing_total:
        discovery["report"] = report
        metadata["discovery"] = discovery
        scan.metadata_json = metadata
        db.commit()
    return report


def _merge_engine_metadata(
    db,
    scan_id: str,
    discovery: dict | None,
    usage_summary: dict | None,
) -> None:
    """Persist final engine output, preserving incremental discovery writes."""
    scan = db.get(Scan, scan_id)
    if scan is None:
        return
    metadata = dict(scan.metadata_json or {})
    if discovery:
        existing = dict(metadata.get("discovery") or {})
        merged = {**existing, **discovery}
        if discovery.get("report"):
            merged["report"] = discovery["report"]
        metadata["discovery"] = merged
    if usage_summary:
        metadata["usage_summary"] = usage_summary
        metadata[scan_versions.VERSIONS_KEY] = scan_versions.with_prompt_hashes(
            metadata.get(scan_versions.VERSIONS_KEY), usage_summary
        )
    scan.metadata_json = metadata
    db.commit()


def _resolve_scan_root(workspace: Path, repo_path: str | None) -> Path:
    """Mirror `sast_scan_agent._resolve_scan_root`'s scope-joining logic so the
    reconciliation sweep re-reads source text from the same subtree the
    original scan used."""
    root = workspace.resolve()
    scope = (repo_path or "").strip()
    if not scope:
        return root
    candidate = (root / scope).resolve()
    try:
        candidate.relative_to(root)
    except ValueError:
        return root
    return candidate if candidate.is_dir() else root


def reconcile_unverified_findings(scan_id: str, *, capped: bool = False) -> None:
    """Best-effort, idempotent, one-shot LLM confirmation sweep for any
    `Finding` rows still stuck at `verdict="unverified"` once a scan reaches
    a terminal state (success/failed/cancelled).

    This closes the gap left when `node_confirm_triage_groups` never ran (a
    cancelled scan stopped before reaching it) or a grouped confirmation call
    failed twice during the normal run (batch + per-group fallback both
    failed). It re-invokes the exact same confirmation machinery
    (`llm_file_scan.group_confirm_unverified_findings`) directly against
    persisted rows, then re-syncs `Scan.metadata_json.discovery.report` so the
    existing UI reflects the reconciled counts with no frontend changes.

    Never touches the mock engine (test suite safety) or scans that opted out
    of LLM usage entirely (`use_llm=False` findings are expected to stay
    unverified). Marks `metadata_json["auto_confirm"]["attempted"] = True`
    unconditionally once it does real work — including on failure — so this
    only ever retries once per scan, never looping forever on a persistently
    unavailable LLM provider.

    `capped`, when true, bounds how many unverified groups (by occurrence
    count) get confirmed in this sweep to `llm_file_scan.TRIAGE_CONFIRM_GROUP_CAP`
    — used by the cancelled-scan call site, where the backlog can be far
    larger than a normal end-of-scan residual since the scan may have
    stopped before any grouping/confirmation ran at all.
    """
    if engine_adapter.mock_engine_enabled():
        return

    db = db_module.SessionLocal()
    try:
        scan = db.get(Scan, scan_id)
        if scan is None:
            return

        meta = dict(scan.metadata_json or {})
        if not bool(meta.get("use_llm", True)):
            return

        if (meta.get("auto_confirm") or {}).get("attempted"):
            return

        rows = (
            db.query(Finding)
            .filter(
                Finding.scan_id == scan_id,
                Finding.verdict == UNVERIFIED_VERDICT,
                # Legacy agentic-hunt rows (the hunt was removed) are
                # unverified *by design* — an evidence cap, not a pending
                # judgement — so a manual re-run on an old scan leaves them be.
                or_(Finding.kind.is_(None), Finding.kind != "hunt"),
            )
            .all()
        )
        if not rows:
            return

        project = scan.project
        if project is None:
            return

        file_results_by_path: dict[str, dict] = {}
        for row in rows:
            file_path = row.file_path or ""
            bucket = file_results_by_path.setdefault(
                file_path, {"file_path": file_path, "findings": []}
            )
            bucket["findings"].append(
                {
                    "rule_id": row.rule_id,
                    "title": row.title,
                    "severity": row.severity,
                    "cwe": row.cwe,
                    "owasp_category": row.owasp_category,
                    "line": row.line,
                    "matched_text": row.matched_text,
                    "group_by_rule": bool(row.group_by_rule),
                    "verdict": row.verdict,
                    "kind": row.kind,
                    "file_path": file_path,
                    "reachability": row.reachability,
                    # The occurrence facts decide which findings are one group
                    # (and carry any validator outcomes the model's answer must
                    # still respect); rebuilt without them the sweep would group
                    # differently from the scan that wrote these rows.
                    "facts": row.facts,
                }
            )

        try:
            workspace = git_workspace.ensure_workspace(
                project.id,
                scan.git_url,
                scan.branch,
                scan.commit_sha,
                project.git_provider,
                git_token.fresh_access_token(project),
            )
            scope = (
                (meta.get("repo_path") or "").strip()
                or (getattr(project, "monorepo_path", None) or "").strip()
                or None
            )
            repo_root = _resolve_scan_root(workspace, scope)

            agent = agent_bridge._load_agent_module()
            group_cap = agent.llm_file_scan.TRIAGE_CONFIRM_GROUP_CAP if capped else None
            rules = agent.regex_scan.load_rules(Path(settings.sast_framework_path) / "rules")
            usage = agent.init_usage(
                scan.llm_provider,
                scan.llm_model,
                fallback_provider=scan.fallback_llm_provider,
                fallback_model=scan.fallback_llm_model,
                **agent_bridge.llm_usage_options(project, scan),
            )
            stack_context = (
                (meta.get("discovery") or {}).get("llm_analysis", {}).get("tech_stack") or "unknown"
            )

            result = agent.llm_file_scan.group_confirm_unverified_findings(
                file_results=list(file_results_by_path.values()),
                repo_root=repo_root,
                rules=rules,
                stack_context=stack_context,
                usage=usage,
                llm_provider=scan.llm_provider,
                llm_model=scan.llm_model,
                group_cap=group_cap,
                groups_per_call=agent.llm_file_scan.DEFAULT_GROUPS_PER_CALL,
                verdict_updates_writer=_make_verdict_updates_writer(scan_id, stage="reconcile"),
            )
            sync_findings_report_to_metadata(db, scan_id)
            scan_log.log(
                scan_id,
                f"Auto-confirmed {result['confirm_group_count']} of {result['group_count']} "
                f"remaining unverified finding group(s): {result['tp_group_count']} TP, "
                f"{result['fp_group_count']} FP, {result['error_group_count']} still unresolved.",
            )
            auto_confirm: dict = {
                "attempted": True,
                "at": datetime.now(timezone.utc).isoformat(),
                "result": result,
            }
        except Exception as exc:  # noqa: BLE001 - a failed sweep must not crash the caller
            auto_confirm = {
                "attempted": True,
                "at": datetime.now(timezone.utc).isoformat(),
                "error": str(exc),
            }
            scan_log.log(scan_id, f"Auto-confirm sweep for remaining unverified findings failed: {exc}")

        scan = db.get(Scan, scan_id)
        if scan is None:
            return
        metadata = dict(scan.metadata_json or {})
        metadata["auto_confirm"] = auto_confirm
        scan.metadata_json = metadata
        db.commit()
    finally:
        db.close()


def unresolved_counts(db, scan_id: str) -> dict[str, int]:
    """Unverified findings of a scan, counted by why they are undecided.
    Rows with no stored reason (written before the column) count as `unknown`."""
    rows = (
        db.query(Finding.unresolved_reason, func.count(Finding.id))
        .filter(Finding.scan_id == scan_id, Finding.verdict == UNVERIFIED_VERDICT)
        .group_by(Finding.unresolved_reason)
        .all()
    )
    return {(reason or "unknown"): count for reason, count in rows}


def decision_counts(db, scan_id: str) -> dict[str, int]:
    """Decision rows of a scan by stage. A stage that silently stops writing
    decisions shows up as a count that is missing or far too low."""
    rows = (
        db.query(FindingDecision.stage, func.count(FindingDecision.id))
        .filter(FindingDecision.scan_id == scan_id)
        .group_by(FindingDecision.stage)
        .all()
    )
    return {stage: count for stage, count in rows}


def _record_decision_counts(scan_id: str) -> None:
    """Put the per-stage decision counts in the scan's `usage_summary`, and log them."""
    db = db_module.SessionLocal()
    try:
        counts = decision_counts(db, scan_id)
        scan = db.get(Scan, scan_id)
        if scan is None:
            return
        metadata = dict(scan.metadata_json or {})
        summary = dict(metadata.get("usage_summary") or {})
        summary["decisions_by_stage"] = counts
        metadata["usage_summary"] = summary
        scan.metadata_json = metadata
        db.commit()
    finally:
        db.close()
    if counts:
        detail = ", ".join(f"{stage}={count}" for stage, count in sorted(counts.items()))
        scan_log.log(scan_id, f"Decision history rows by stage: {detail}.")


def _log_report_consistency(scan_id: str) -> None:
    """Check that the scan's API counts, Excel export and PDF agree, and log any
    contradiction as a warning naming the scan. Never fails the scan."""
    db = db_module.SessionLocal()
    try:
        scan = db.get(Scan, scan_id)
        if scan is None:
            return
        problems = scan_export.check_report_consistency(db, scan)
    except Exception as exc:  # noqa: BLE001 - a diagnostic must not break a finished scan
        logger.warning("report consistency check for scan %s could not run: %s", scan_id, exc)
        return
    finally:
        db.close()
    for problem in problems:
        logger.warning("scan %s report inconsistency: %s", scan_id, problem)
        scan_log.log(scan_id, f"Warning — report inconsistency: {problem}")


def _log_identity_summary(scan_id: str) -> None:
    """One log line per scan: how many occurrence identities could only be
    resolved to the file. A high share means rescan joins are weak for it."""
    db = db_module.SessionLocal()
    try:
        total = db.query(func.count(Finding.id)).filter(
            Finding.scan_id == scan_id, Finding.occurrence_id.isnot(None)
        ).scalar() or 0
        file_level = db.query(func.count(Finding.id)).filter(
            Finding.scan_id == scan_id, Finding.identity_quality == "file_level"
        ).scalar() or 0
    finally:
        db.close()
    if total:
        scan_log.log(
            scan_id,
            f"Occurrence identity: {file_level} of {total} finding(s) resolved to the file only "
            f"({file_level * 100 // total}% file-level).",
        )


def _log_unresolved_summary(scan_id: str) -> None:
    """One log line per scan: how many findings ended unresolved, and why."""
    db = db_module.SessionLocal()
    try:
        counts = unresolved_counts(db, scan_id)
    finally:
        db.close()
    if counts:
        detail = ", ".join(f"{reason}={count}" for reason, count in sorted(counts.items()))
        scan_log.log(scan_id, f"Unresolved findings by reason: {detail}.")


def _unfinished_progress(scan: Scan) -> int:
    """Progress for a DAST scan that ended without succeeding: where it got to, never 100 (a scan
    that failed or was cancelled did not finish)."""
    return max(10, min(int(scan.progress or 0), 99))


def _mark_cancelled(db, scan_id: str) -> None:
    scan = db.get(Scan, scan_id)
    if scan is None:
        clear_cancel(scan_id)
        return
    sync_findings_report_to_metadata(db, scan_id)
    # A cancelled scan may have stopped well before node_confirm_triage_groups
    # ever ran, so the unconfirmed backlog can be much larger than a normal
    # end-of-scan residual — cap it rather than auto-spending on the whole
    # thing when the user explicitly asked to stop.
    reconcile_unverified_findings(scan_id, capped=True)
    scan = db.get(Scan, scan_id)
    if scan is None:
        clear_cancel(scan_id)
        return
    scan.status = "cancelled"
    scan.progress = _unfinished_progress(scan) if (scan.scan_type or "sast") == "dast" else 100
    scan.message = "Cancelled by user"
    db.commit()
    scan_log.log(scan_id, "Scan cancelled by user.")
    clear_cancel(scan_id)


# The engine's parallel stages call the writers from several threads at once.
# Each call has its own session, but SQLite takes one writer at a time — so
# commits are serialized here instead of failing with "database is locked".
logger = logging.getLogger(__name__)

_DB_WRITE_LOCK = threading.Lock()


def _make_findings_writer(scan_id: str):
    """One short-lived DB session per file — the writer is called once per
    scanned file with both true- and false-positive findings together, so
    each call is a single `add_all` + `commit` rather than accumulating rows
    across the whole scan."""

    def write_findings(file_path: str, findings: list[dict]) -> None:
        session = db_module.SessionLocal()
        try:
            if not findings:
                scan_log.log(scan_id, f"  No findings for {file_path}.")
                return
            scan = session.get(Scan, scan_id)
            project_id = scan.project_id if scan is not None else None
            rows = [build_finding_row(scan_id, f, file_path, project_id) for f in findings]
            with _DB_WRITE_LOCK:
                session.add_all(rows)
                session.flush()  # assign finding ids so evidence rows can reference them
                decisions.record_initial(session, rows, findings, scan)
                for finding_row, f in zip(rows, findings):
                    evidence = f.get("evidence")
                    if evidence:
                        session.add(build_evidence_row(finding_row.id, evidence))
                session.commit()
            tp = sum(1 for f in findings if f.get("verdict") == "true_positive")
            fp = sum(1 for f in findings if f.get("verdict") == "false_positive")
            # Counted explicitly rather than as "everything that isn't a TP" —
            # regex-only findings are `unverified`, and calling those dismissed
            # would misreport them as reviewed-and-rejected.
            unverified = len(findings) - tp - fp
            summary = f"{tp} confirmed, {fp} dismissed"
            if unverified:
                summary += f", {unverified} unverified"
            scan_log.log(
                scan_id,
                f"  Saved {len(findings)} finding(s) for {file_path} to database ({summary}).",
            )
        finally:
            session.close()

    return write_findings


def _make_reachability_updates_writer(scan_id: str):
    """Like `_make_verdict_updates_writer`, for Joern paths that
    node_corroborate_flows attaches to already-persisted findings: updates
    `reachability` and `confidence` in place, keyed the same way."""

    def write_reachability_updates(file_path: str, updates: list[dict]) -> None:
        if not updates:
            return
        session = db_module.SessionLocal()
        try:
            changed = 0
            with _DB_WRITE_LOCK:
                scan = session.get(Scan, scan_id)
                for update in updates:
                    rule_id = update.get("rule_id")
                    line = update.get("line")
                    if rule_id is None or line is None:
                        continue
                    for row in _matching_findings(session, scan_id, file_path, rule_id, line):
                        before_verdict, before_confidence = row.verdict, row.confidence
                        row.reachability = update.get("reachability")
                        row.confidence = update.get("confidence")
                        changed += 1
                        # A path can lift a confirmed finding's confidence to the
                        # reachability floor; that is a decision. Evidence that leaves
                        # confidence where it was is not.
                        if (row.confidence or 0) > (before_confidence or 0):
                            decisions.record_change(
                                session, row, before_verdict=before_verdict,
                                before_confidence=before_confidence, stage="reachability_floor",
                                scan=scan,
                            )
                session.commit()
            if changed:
                scan_log.log(scan_id, f"  Attached code property graph dataflow evidence to {changed} finding(s) in {file_path}.")
        finally:
            session.close()

    return write_reachability_updates


def _matching_findings(session, scan_id: str, file_path: str, rule_id: str, line: int) -> list[Finding]:
    """The rows an update keyed (scan, file, rule, line) applies to."""
    return (
        session.query(Finding)
        .filter(
            Finding.scan_id == scan_id,
            Finding.file_path == file_path,
            Finding.rule_id == rule_id,
            Finding.line == line,
        )
        .all()
    )


def _make_verdict_updates_writer(scan_id: str, stage: str | None = None):
    """One short-lived DB session per file — updates existing Finding rows in
    place after grouped confirmation of unverified findings (never a fresh
    insert, unlike `_make_findings_writer`). Each change of verdict or confidence
    also appends a `FindingDecision`, under the same lock and transaction; the
    stage is the update's own `decision_stage`, else `stage`, else group_confirm
    (the reconcile sweep passes `stage="reconcile"`)."""

    def write_verdict_updates(file_path: str, updates: list[dict]) -> None:
        if not updates:
            return
        session = db_module.SessionLocal()
        try:
            changed = 0
            with _DB_WRITE_LOCK:
                scan = session.get(Scan, scan_id)
                for update in updates:
                    rule_id = update.get("rule_id")
                    line = update.get("line")
                    if rule_id is None or line is None:
                        continue
                    # Only the keys an update carries are written: a group that
                    # could not be decided sends just `unresolved_reason`, so
                    # its earlier reasoning is left alone.
                    values = {
                        column: update[column]
                        for column in (
                            "verdict", "confidence", "verdict_reason", "ai_fix", "unresolved_reason",
                            "reason_tag", "review_coverage",
                        )
                        if column in update
                    }
                    if values.get("verdict") in ("true_positive", "false_positive"):
                        values["unresolved_reason"] = None
                    if not values:
                        continue
                    for row in _matching_findings(session, scan_id, file_path, rule_id, line):
                        before_verdict, before_confidence = row.verdict, row.confidence
                        for column, value in values.items():
                            setattr(row, column, value)
                        changed += 1
                        decisions.record_change(
                            session, row, before_verdict=before_verdict,
                            before_confidence=before_confidence,
                            stage=stage or update.get("decision_stage") or decisions.DEFAULT_CONFIRM_STAGE,
                            scan=scan, result_cache_hit=bool(update.get("result_cache_hit")),
                            actor=update.get("decision_actor"),
                            detail=update.get("decision_detail") or (
                                {"review_coverage": update["review_coverage"]}
                                if update.get("review_coverage") else None
                            ),
                        )
                session.commit()
            if changed:
                scan_log.log(scan_id, f"  Confirmed {changed} finding(s) for {file_path} via grouped review.")
        finally:
            session.close()

    return write_verdict_updates


def _make_discovery_writer(scan_id: str, secrets=None):
    """Persist partial/final discovery onto Scan.metadata_json mid-graph so the
    UI can open Discovery results after Mapping module risk, before CRITICAL
    file scanning finishes. `secrets` (a callable) masks credential values first."""

    def write_discovery(discovery: dict) -> None:
        if not discovery:
            return
        if secrets is not None:
            discovery = redact_json(discovery, secrets())
        session = db_module.SessionLocal()
        try:
            scan = session.get(Scan, scan_id)
            if scan is None:
                return
            metadata = dict(scan.metadata_json or {})
            metadata["discovery"] = discovery
            scan.metadata_json = metadata
            with _DB_WRITE_LOCK:
                session.commit()
        finally:
            session.close()

    return write_discovery


_CRITICAL_FILE_RE = re.compile(r"CRITICAL file (\d+)/(\d+)")


def _progress_hook_factory(db, scan_id: str, last_progress: list[int]):
    """Return a scan_log line hook that bumps Scan.progress from engine output.

    Parallel engine stages log from several threads, and `db` is one session:
    the lock keeps both the tracker and the session single-threaded."""
    tracker = ProgressTracker(floor=last_progress[0])
    lock = threading.Lock()

    def _store(pct: int) -> None:
        last_progress[0] = pct
        try:
            scan = db.get(Scan, scan_id)
            if scan is None or scan.status != "running":
                return
            scan.progress = pct
            db.commit()
        except Exception:  # noqa: BLE001 — never break logging on progress write
            db.rollback()

    def on_line(line: str) -> None:
        with lock:
            m = _CRITICAL_FILE_RE.search(line)
            if m:
                idx, total = int(m.group(1)), int(m.group(2))
                if total > 0:
                    pct = min(97 + int((idx / total) * 2), 99)
                    if pct > last_progress[0]:
                        _store(pct)
                    return
            pct = tracker.feed(line)
            if pct > last_progress[0]:
                _store(pct)

    return on_line


def _execute_sca_scan(db, scan: Scan, project) -> None:
    """Lean SCA counterpart to `execute_scan`'s main SAST body: still drives
    the same queued -> running -> success/failed lifecycle (status/progress/
    log capture) and still checks out the workspace via `git_workspace`, but
    skips everything SAST/LLM-specific — provider snapshotting, the
    CRITICAL-file progress hook, and `reconcile_unverified_findings` (there
    is no LLM confirmation step for `kind="sca"` findings in this pass)."""
    scan_id = scan.id
    scan_log.reset(scan_id)
    try:
        with scan_log.capture(scan_id):
            scan_log.log(scan_id, f"Starting SCA scan v{scan.version} for {project.name}.")

            workspace = Path(settings.workspaces_dir) / project.id
            # Mock engine never touches git, same invariant as the SAST path.
            if not engine_adapter.mock_engine_enabled():
                if not engine_adapter.run_live_sca_enabled():
                    scan.status = "failed"
                    scan.progress = 100
                    scan.message = (
                        "Real SCA engine requested (USE_MOCK_ENGINE=false) but live SCA is "
                        "disabled. Set RUN_SCA=1 or enable run_sca in settings."
                    )
                    scan_log.log(scan_id, f"Aborted: {scan.message}")
                    db.commit()
                    return
                scan_log.log(scan_id, f"Cloning {scan.git_url} (branch: {scan.branch})...")
                try:
                    workspace = git_workspace.ensure_workspace(
                        project.id,
                        scan.git_url,
                        scan.branch,
                        scan.commit_sha,
                        project.git_provider,
                        git_token.fresh_access_token(project),
                    )
                except Exception as exc:  # noqa: BLE001 - surface checkout errors on the scan row
                    db.rollback()
                    scan = db.get(Scan, scan_id)
                    if scan is None:
                        return
                    scan.status = "failed"
                    scan.progress = 100
                    scan.message = f"workspace checkout failed: {exc}"
                    scan_log.log(scan_id, f"Could not check out the repository: {exc}")
                    db.commit()
                    return
                resolved_sha = git_workspace.resolve_head_sha(workspace)
                if resolved_sha:
                    scan.commit_sha = resolved_sha
                    db.commit()
                scan_log.log(scan_id, "Repository ready.")
            else:
                scan_log.log(scan_id, "Using the local mock workspace — no checkout needed.")

            if _should_abort(db.get(Scan, scan_id), scan_id):
                _mark_cancelled(db, scan_id)
                return

            scan_log.log(
                scan_id, "Scanning dependency manifests for known vulnerabilities (OSV.dev)..."
            )
            try:
                engine_result = engine_adapter.run_sca_scan(
                    project=project,
                    workspace=workspace,
                    scan_id=scan.id,
                    findings_writer=_make_findings_writer(scan.id),
                    discovery_writer=_make_discovery_writer(scan.id),
                )
                discovery = engine_result.get("discovery") or {}
            except Exception as exc:  # noqa: BLE001 - surface engine errors on the scan row
                db.rollback()
                scan = db.get(Scan, scan_id)
                if scan is None:
                    return
                scan.status = "failed"
                scan.progress = 100
                scan.message = str(exc)
                scan_log.log(scan_id, f"The SCA engine hit an error: {exc}")
                scan_log.log(scan_id, traceback.format_exc())
                db.commit()
                return

            scan = db.get(Scan, scan_id)
            if scan is None:
                return
            if _should_abort(scan, scan_id):
                _merge_engine_metadata(db, scan_id, discovery, None)
                _mark_cancelled(db, scan_id)
                return

            scan.progress = 95
            metadata = dict(scan.metadata_json or {})
            if discovery:
                metadata["discovery"] = discovery
            scan.metadata_json = metadata
            db.commit()

            scan = db.get(Scan, scan_id)
            if scan is None or _should_abort(scan, scan_id):
                _mark_cancelled(db, scan_id)
                return

            summary = discovery.get("dependency_summary") or {}
            scan_log.log(
                scan_id,
                f"Found {summary.get('total_dependencies', 0)} dependencies, "
                f"{summary.get('vulnerable_dependencies', 0)} with known vulnerabilities.",
            )
            scan.status = "success"
            scan.progress = 100
            scan.message = None
            db.commit()
            scan_log.log(scan_id, "SCA scan complete.")
    finally:
        scan_log.unregister_line_hooks(scan_id)


def _execute_sbom_scan(db, scan: Scan, project) -> None:
    """Lean SBOM counterpart to `_execute_sca_scan` — same lifecycle
    (checkout, run engine, persist discovery, mark success/failed) but calls
    `engine_adapter.run_sbom_scan` and writes no findings (SBOM has no
    vulnerability-detection step of its own)."""
    scan_id = scan.id
    scan_log.reset(scan_id)
    try:
        with scan_log.capture(scan_id):
            scan_log.log(scan_id, f"Starting SBOM scan v{scan.version} for {project.name}.")

            workspace = Path(settings.workspaces_dir) / project.id
            # Mock engine never touches git, same invariant as the SAST/SCA paths.
            if not engine_adapter.mock_engine_enabled():
                if not engine_adapter.run_live_sbom_enabled():
                    scan.status = "failed"
                    scan.progress = 100
                    scan.message = (
                        "Real SBOM engine requested (USE_MOCK_ENGINE=false) but live SBOM is "
                        "disabled. Set RUN_SBOM=1 or enable run_sbom in settings."
                    )
                    scan_log.log(scan_id, f"Aborted: {scan.message}")
                    db.commit()
                    return
                scan_log.log(scan_id, f"Cloning {scan.git_url} (branch: {scan.branch})...")
                try:
                    workspace = git_workspace.ensure_workspace(
                        project.id,
                        scan.git_url,
                        scan.branch,
                        scan.commit_sha,
                        project.git_provider,
                        git_token.fresh_access_token(project),
                    )
                except Exception as exc:  # noqa: BLE001 - surface checkout errors on the scan row
                    db.rollback()
                    scan = db.get(Scan, scan_id)
                    if scan is None:
                        return
                    scan.status = "failed"
                    scan.progress = 100
                    scan.message = f"workspace checkout failed: {exc}"
                    scan_log.log(scan_id, f"Could not check out the repository: {exc}")
                    db.commit()
                    return
                resolved_sha = git_workspace.resolve_head_sha(workspace)
                if resolved_sha:
                    scan.commit_sha = resolved_sha
                    db.commit()
                scan_log.log(scan_id, "Repository ready.")
            else:
                scan_log.log(scan_id, "Using the local mock workspace — no checkout needed.")

            if _should_abort(db.get(Scan, scan_id), scan_id):
                _mark_cancelled(db, scan_id)
                return

            scan_log.log(
                scan_id, "Scanning dependency manifests and classifying licenses..."
            )
            try:
                engine_result = engine_adapter.run_sbom_scan(
                    project=project,
                    workspace=workspace,
                    scan_id=scan.id,
                    discovery_writer=_make_discovery_writer(scan.id),
                )
                discovery = engine_result.get("discovery") or {}
            except Exception as exc:  # noqa: BLE001 - surface engine errors on the scan row
                db.rollback()
                scan = db.get(Scan, scan_id)
                if scan is None:
                    return
                scan.status = "failed"
                scan.progress = 100
                scan.message = str(exc)
                scan_log.log(scan_id, f"The SBOM engine hit an error: {exc}")
                scan_log.log(scan_id, traceback.format_exc())
                db.commit()
                return

            scan = db.get(Scan, scan_id)
            if scan is None:
                return
            if _should_abort(scan, scan_id):
                _merge_engine_metadata(db, scan_id, discovery, None)
                _mark_cancelled(db, scan_id)
                return

            scan.progress = 95
            metadata = dict(scan.metadata_json or {})
            if discovery:
                metadata["discovery"] = discovery
            scan.metadata_json = metadata
            db.commit()

            scan = db.get(Scan, scan_id)
            if scan is None or _should_abort(scan, scan_id):
                _mark_cancelled(db, scan_id)
                return

            summary = discovery.get("component_summary") or {}
            scan_log.log(
                scan_id,
                f"Found {summary.get('total_components', 0)} components across "
                f"{len(summary.get('ecosystems', []))} ecosystem(s).",
            )
            scan.status = "success"
            scan.progress = 100
            scan.message = None
            db.commit()
            scan_log.log(scan_id, "SBOM scan complete.")
    finally:
        scan_log.unregister_line_hooks(scan_id)


def _credentials_lost_message(missing: list[str]) -> str:
    who = f" for {', '.join(missing)}" if missing else ""
    return (
        f"The target credentials{who} were lost (the server restarted before the scan "
        "started). Start the scan again."
    )


def _execute_dast_scan(db, scan: Scan, project) -> None:
    """DAST lifecycle: no git checkout — the scan targets a URL. Runs the
    Playwright/model-gateway crawl + per-REST-API security analysis
    (`engine_adapter.run_dast_scan`), persists the discovery dict (which carries
    the per-API analysis tree), writes FAIL/INCONCLUSIVE checks as `Finding`
    rows incrementally, and marks success/failed/cancelled.

    Credentials live only in the in-memory holder created here. Every secret is registered with the
    log redactor before the engine starts, anything the engine returns or raises is redacted
    before it is stored, and the holder is cleared on every exit path (success, failure, cancel)."""
    scan_id = scan.id
    scan_log.reset(scan_id)
    dast_input = dict((scan.metadata_json or {}).get("dast_input") or {})
    stored_identities = list(dast_input.get("identities") or [])
    holder = InMemoryCredentialHolder(scan_id)
    credentials = _pop_dast_credentials(scan_id)
    for spec in stored_identities:
        secret = credentials.get(spec.get("identity_id") or "")
        if secret:
            holder.store(identity_from_public(spec), secret)
    if not stored_identities and credentials:  # a legacy single-credential hand-over
        for identity_id, secret in credentials.items():
            holder.store(identity_from_public({"identity_id": identity_id, "label": identity_id, "role": "user"}), secret)

    def redact(text: str) -> str:
        return redact_text(text, holder.secrets()) if text else text

    last_progress = [10]
    scan_log.register_line_hook(scan_id, _progress_hook_factory(db, scan_id, last_progress))
    try:
        with scan_log.capture(scan_id):
            scan_log.log(
                scan_id,
                f"Starting DAST scan v{scan.version} for {project.name} "
                f"against {dast_input.get('target_url') or scan.git_url}.",
            )
            expected = [s for s in stored_identities if s.get("has_secret")]
            missing = [s.get("label") or "" for s in expected if holder.read(s.get("identity_id") or "") is None]
            if missing or (not stored_identities and dast_input.get("has_password") and holder.is_empty()):
                scan.status = "failed"
                scan.progress = _unfinished_progress(scan)
                scan.message = _credentials_lost_message(missing)
                scan_log.log(scan_id, f"Aborted: {scan.message}")
                db.commit()
                return
            if not engine_adapter.mock_engine_enabled() and not engine_adapter.run_live_dast_enabled():
                scan.status = "failed"
                scan.progress = _unfinished_progress(scan)
                scan.message = (
                    "Real DAST engine requested (USE_MOCK_ENGINE=false) but live DAST is "
                    "disabled. Set RUN_DAST=1 or enable run_dast in settings."
                )
                scan_log.log(scan_id, f"Aborted: {scan.message}")
                db.commit()
                return
            db.commit()

            metadata_now = scan.metadata_json or {}
            try:
                engine_result = engine_adapter.run_dast_scan(
                    project=project,
                    dast_input=dict(dast_input),
                    scan_id=scan_id,
                    discovery_writer=_make_discovery_writer(scan_id, holder.secrets),
                    findings_writer=DastFindingsWriter(scan_id),
                    should_abort=lambda: _should_abort(_fresh_scan(scan_id), scan_id),
                    effective_settings=metadata_now.get("dast_effective") or metadata_now.get(DAST_SETTINGS_SNAPSHOT_KEY),
                    credentials=holder,
                    scan=scan,
                )
                discovery = redact_json(engine_result.get("discovery") or {}, holder.secrets())
                usage_summary = engine_result.get("usage_summary") or {}
            except Exception as exc:  # noqa: BLE001 - surface engine errors on the scan row
                db.rollback()
                scan = db.get(Scan, scan_id)
                if scan is None:
                    return
                scan.status = "failed"
                scan.progress = _unfinished_progress(scan)
                scan.message = redact(str(exc))
                scan_log.log(scan_id, f"The DAST engine hit an error: {exc}")
                scan_log.log(scan_id, traceback.format_exc())
                db.commit()
                return

            scan = db.get(Scan, scan_id)
            if scan is None:
                return
            metadata = dict(scan.metadata_json or {})
            if discovery:
                metadata["discovery"] = discovery
            if usage_summary:
                metadata["usage_summary"] = usage_summary
            scan.metadata_json = metadata
            db.commit()

            scan = db.get(Scan, scan_id)
            if scan is None or _should_abort(scan, scan_id):
                _mark_cancelled(db, scan_id)
                return

            if discovery and not discovery.get("connection_ok", True):
                scan.status = "failed"
                scan.message = f"Could not reach the target: {discovery.get('connection_error') or 'connection failed'}"
            elif discovery and discovery.get("credentials_lost"):
                scan.status = "failed"
                scan.message = discovery.get("credentials_lost_reason") or _credentials_lost_message([])
            elif discovery and discovery.get("authentication_failed"):
                scan.status = "failed"
                scan.message = discovery["authentication_failed"]
            elif discovery and not discovery.get("pages") and (
                discovery.get("stop_reason") or discovery.get("login_error")
            ):
                scan.status = "failed"
                scan.message = (
                    f"Crawl did not start: {discovery.get('login_error') or discovery.get('stop_reason')}"
                )
            else:
                scan.status = "success"
                scan.message = None
            scan.message = redact(scan.message) if scan.message else scan.message
            scan.progress = 100 if scan.status == "success" else _unfinished_progress(scan)
            db.commit()
            if scan.status == "success":
                try:  # first/last seen across scans; a bookkeeping failure must not fail the scan
                    from app.services.dast_diff import refresh_seen

                    refresh_seen(db, scan)
                except Exception as exc:  # noqa: BLE001
                    db.rollback()
                    scan_log.log(scan_id, f"Could not refresh first/last seen for this scan: {exc}")
            if scan.status in ("success", "failed"):
                try:
                    from app.services.dast_notify import notify_scan_finished

                    notify_scan_finished(scan_id, scan.status, scan.message)
                except Exception:  # noqa: BLE001 - a notification must not change the scan result
                    scan_log.log(scan_id, "Could not send the scan notification.")
            scan_log.log(
                scan_id,
                "DAST scan complete." if scan.status == "success" else f"DAST scan failed: {scan.message}",
            )
    finally:
        try:  # store the final counters and drop the live entry, whichever way the scan ended
            from app.services import dast_summary

            final = db.get(Scan, scan_id)
            if final is not None:
                dast_summary.finalize(db, final)
        except Exception:  # noqa: BLE001 - a summary problem must not mask the scan's own outcome
            db.rollback()
        holder.clear()  # success, failure and cancel all pass through here
        scan_log.unregister_line_hooks(scan_id)
        scan_log.register_secrets(scan_id, [])


def _fresh_scan(scan_id: str) -> Scan | None:
    """Read the scan row on a short-lived session (the crawl thread's own
    session must not be shared with the cancel-check callback)."""
    session = db_module.SessionLocal()
    try:
        scan = session.get(Scan, scan_id)
        if scan is not None:
            session.expunge(scan)
        return scan
    finally:
        session.close()


def execute_scan(scan_id: str) -> None:
    # Look up SessionLocal via the module (not a direct import) because
    # tests call init_db(tmp_url) *after* this module has already been
    # imported, which rebinds app.db.SessionLocal to a fresh sessionmaker.
    db = db_module.SessionLocal()
    try:
        scan = db.get(Scan, scan_id)
        if scan is None:
            return

        if _should_abort(scan, scan_id):
            if scan.status != "cancelled":
                _mark_cancelled(db, scan_id)
            else:
                clear_cancel(scan_id)
            return

        scan.status = "running"
        scan.progress = 10
        project = scan.project

        # SCA/SBOM scans use a completely separate, lean, LLM-free execution
        # path (deterministic manifest parsing) — none of the LLM-provider
        # snapshotting or reconcile_unverified_findings sweep below applies
        # to them.
        if (scan.scan_type or "sast") == "sca":
            db.commit()
            _execute_sca_scan(db, scan, project)
            return
        if (scan.scan_type or "sast") == "sbom":
            db.commit()
            _execute_sbom_scan(db, scan, project)
            return
        if (scan.scan_type or "sast") == "dast":
            db.commit()
            _execute_dast_scan(db, scan, project)
            return

        # Keep LLM snapshot from trigger (per-scan override). Backfill from
        # project only when the scan row predates those columns — and only when
        # this scan actually opted into LLM usage.
        meta = scan.metadata_json or {}
        use_llm = bool(meta.get("use_llm", True))
        if use_llm:
            if not scan.llm_provider:
                scan.llm_provider = getattr(project, "llm_provider", None) or "bedrock"
            if not scan.llm_model:
                scan.llm_model = (
                    getattr(project, "llm_model", None)
                    or "us.anthropic.claude-haiku-4-5-20251001-v1:0"
                )
            if (scan.llm_provider or "").strip().lower() != "ollama":
                if not scan.fallback_llm_provider:
                    scan.fallback_llm_provider = (
                        getattr(project, "fallback_llm_provider", None) or "none"
                    )
                if not scan.fallback_llm_model:
                    scan.fallback_llm_model = getattr(project, "fallback_llm_model", None) or None
            else:
                scan.fallback_llm_provider = None
                scan.fallback_llm_model = None
        else:
            scan.llm_provider = None
            scan.llm_model = None
            scan.fallback_llm_provider = None
            scan.fallback_llm_model = None
        db.commit()

        scan_log.reset(scan_id)
        last_progress = [10]
        scan_log.register_line_hook(scan_id, _progress_hook_factory(db, scan_id, last_progress))
        try:
            with scan_log.capture(scan_id):
                scan_log.log(scan_id, f"Starting scan v{scan.version} for {project.name}.")
                scan_log.log(
                    scan_id,
                    f"Analyzing with {_friendly_llm_label(scan.llm_provider, scan.llm_model, use_llm)} "
                    f"— scanning {_friendly_scope_label(meta.get('repo_path'))}.",
                )
                workspace = Path(settings.workspaces_dir) / project.id

                # Mock engine never touches git — the mock test suite pre-seeds
                # `workspace` directly (or leaves it empty) and must stay network-free.
                # Real engine gate (defaults on; set RUN_LIVE_SAST=0 to disable).
                if not engine_adapter.mock_engine_enabled():
                    if not engine_adapter.run_live_sast_enabled():
                        scan.status = "failed"
                        scan.progress = 100
                        scan.message = (
                            "Real engine requested (USE_MOCK_ENGINE=false) but live SAST is disabled. "
                            "Set RUN_LIVE_SAST=1 or enable run_live_sast in settings."
                        )
                        scan_log.log(scan_id, f"Aborted: {scan.message}")
                        db.commit()
                        return
                    scan_log.log(scan_id, f"Cloning {scan.git_url} (branch: {scan.branch})...")
                    try:
                        workspace = git_workspace.ensure_workspace(
                            project.id,
                            scan.git_url,
                            scan.branch,
                            scan.commit_sha,
                            project.git_provider,
                            git_token.fresh_access_token(project),
                        )
                    except Exception as exc:  # noqa: BLE001 - surface checkout errors on the scan row
                        db.rollback()
                        scan = db.get(Scan, scan_id)
                        if scan is None:
                            return
                        scan.status = "failed"
                        scan.progress = 100
                        scan.message = f"workspace checkout failed: {exc}"
                        scan_log.log(scan_id, f"Could not check out the repository: {exc}")
                        db.commit()
                        return
                    resolved_sha = git_workspace.resolve_head_sha(workspace)
                    if resolved_sha:
                        scan.commit_sha = resolved_sha
                        db.commit()
                    scan_log.log(scan_id, "Repository ready.")
                else:
                    scan_log.log(scan_id, "Using the local mock workspace — no checkout needed.")

                if _should_abort(db.get(Scan, scan_id), scan_id):
                    _mark_cancelled(db, scan_id)
                    return

                metadata = dict(scan.metadata_json or {})
                metadata[scan_versions.VERSIONS_KEY] = scan_versions.static_versions(
                    scan, mock=engine_adapter.mock_engine_enabled()
                )
                scan.metadata_json = metadata
                db.commit()

                scan_log.log(scan_id, "Starting the discovery agent...")
                try:
                    engine_result = engine_adapter.run_scan(
                        project=project,
                        git_url=scan.git_url,
                        branch=scan.branch,
                        commit_sha=scan.commit_sha,
                        changed_paths=None,
                        workspace=workspace,
                        scan_id=scan.id,
                        scan=scan,
                        findings_writer=_make_findings_writer(scan.id),
                        discovery_writer=_make_discovery_writer(scan.id),
                        verdict_updates_writer=_make_verdict_updates_writer(scan.id),
                        reachability_updates_writer=_make_reachability_updates_writer(scan.id),
                    )
                    discovery = engine_result.get("discovery") or {}
                    usage_summary = engine_result.get("usage_summary") or {}
                except Exception as exc:  # noqa: BLE001 - surface engine errors on the scan row
                    db.rollback()
                    scan = db.get(Scan, scan_id)
                    if scan is None:
                        return
                    # Findings may already have been persisted incrementally
                    # before the engine failed — sweep those for any that
                    # never made it to node_confirm_triage_groups.
                    reconcile_unverified_findings(scan_id)
                    scan = db.get(Scan, scan_id)
                    if scan is None:
                        return
                    scan.status = "failed"
                    scan.progress = 100
                    scan.message = str(exc)
                    scan_log.log(scan_id, f"The discovery agent hit an error: {exc}")
                    scan_log.log(scan_id, traceback.format_exc())
                    db.commit()
                    return

                scan = db.get(Scan, scan_id)
                if scan is None:
                    return
                if _should_abort(scan, scan_id):
                    _merge_engine_metadata(db, scan_id, discovery, usage_summary)
                    _mark_cancelled(db, scan_id)
                    return

                scan.progress = max(last_progress[0], 95)
                metadata = dict(scan.metadata_json or {})
                metadata[scan_versions.VERSIONS_KEY] = scan_versions.with_prompt_hashes(
                    metadata.get(scan_versions.VERSIONS_KEY), usage_summary
                )
                if discovery:
                    metadata["discovery"] = discovery
                if usage_summary:
                    metadata["usage_summary"] = usage_summary
                    total = int(usage_summary.get("total_tokens") or 0)
                    cost = float(usage_summary.get("cost_usd") or 0)
                    if total > 0:
                        scan_log.log(
                            scan_id,
                            f"LLM token usage: {total:,} tokens — estimated cost ${cost:.4f}.",
                        )
                scan.metadata_json = metadata
                db.commit()

                scan = db.get(Scan, scan_id)
                if scan is None or _should_abort(scan, scan_id):
                    _mark_cancelled(db, scan_id)
                    return

                reconcile_unverified_findings(scan_id)
                _log_unresolved_summary(scan_id)
                _log_identity_summary(scan_id)
                _record_decision_counts(scan_id)
                if not engine_adapter.mock_engine_enabled():
                    _log_report_consistency(scan_id)
                scan = db.get(Scan, scan_id)
                if scan is None:
                    return

                scan.status = "success"
                scan.progress = 100
                scan.message = None
                db.commit()
                scan_log.log(scan_id, "Scan complete.")
        finally:
            scan_log.unregister_line_hooks(scan_id)
    finally:
        db.close()


def recover_interrupted_dast_scans() -> int:
    """At startup, fail every DAST scan a previous process left `queued` or `running`.

    A DAST scan's credentials live only in that process's memory, so after a restart the scan can
    neither continue nor be trusted to: it is failed with the credentials-lost reason (or a plain
    "interrupted" one when it held no credentials), keeping the findings and audit rows it wrote.
    Never resumes unauthenticated. Returns how many scans were failed."""
    db = db_module.SessionLocal()
    try:
        scans = db.query(Scan).filter(Scan.scan_type == "dast", Scan.status.in_(("queued", "running", "paused"))).all()
        for scan in scans:
            identities = ((scan.metadata_json or {}).get("dast_input") or {}).get("identities") or []
            had_secrets = any(i.get("has_secret") for i in identities) or bool(((scan.metadata_json or {}).get("dast_input") or {}).get("has_password"))
            scan.status = "failed"
            scan.progress = 100
            scan.message = (
                "The target credentials were lost (the server restarted while the scan was running). Start the scan again."
                if had_secrets
                else "The scan was interrupted by a server restart. Start it again."
            )
            scan_log.log(scan.id, f"Aborted: {scan.message}")
        db.commit()
        return len(scans)
    finally:
        db.close()


def start_scan_background(scan_id: str) -> None:
    if engine_adapter.mock_engine_enabled():
        execute_scan(scan_id)
    else:
        thread = threading.Thread(target=execute_scan, args=(scan_id,), daemon=True)
        thread.start()
