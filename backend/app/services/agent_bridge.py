"""Bridge into the in-repo discovery agent.

`sast_scan_agent.py` lives under `backend/sast_engine/` (default
`settings.sast_framework_path`). Imported lazily so the mock-engine test suite
never needs boto3 / langgraph installed.

Pipeline: scan_directory -> analyze_tech_stack -> categorize_files ->
map_modules_and_risk -> scan_deep_files -> scan_triage_files -> generate_report.

`scan_deep_files` runs the full LLM scan over CRITICAL/HIGH files;
`scan_triage_files` regex-gates MEDIUM/LOW, sending only regex hits and their
surrounding context to the LLM (zero-hit files cost no LLM call at all).
"""

import importlib
import importlib.util
import logging
import os
import sys
from pathlib import Path
from typing import Callable

from app.config import settings
from app.models import Project, Scan

logger = logging.getLogger(__name__)


_INSTALL_HINT = """Real SAST engine requested but the in-repo agent could not be imported.

SAST_FRAMEWORK_PATH: {path}
Original import error: {error}

Fix:
  1. Confirm backend/sast_engine contains sast_scan_agent.py
  2. Install backend deps: pip install -r backend/requirements.txt
  3. For Bedrock: configure AWS credentials with bedrock:InvokeModel
  4. For Ollama: run a local daemon at OLLAMA_BASE_URL with the chosen model
  5. Re-run with USE_MOCK_ENGINE=false RUN_LIVE_SAST=1.
"""


def _sync_env_from_settings() -> None:
    os.environ.setdefault("AWS_REGION", settings.aws_region)
    os.environ.setdefault("BEDROCK_MODEL_ID", settings.bedrock_model_id)
    os.environ.setdefault("OLLAMA_BASE_URL", settings.ollama_base_url)
    os.environ.setdefault("OLLAMA_REQUEST_TIMEOUT", str(settings.ollama_request_timeout))


def _load_agent_module():
    framework_path = Path(settings.sast_framework_path)
    agent_file = framework_path / "sast_scan_agent.py"
    if not agent_file.is_file():
        raise RuntimeError(
            _INSTALL_HINT.format(
                path=framework_path,
                error=f"Missing sast_scan_agent.py at {agent_file}",
            )
        )
    engine_dir = str(framework_path)
    if engine_dir not in sys.path:
        sys.path.insert(0, engine_dir)
    _sync_env_from_settings()
    if "llm_client" in sys.modules:
        importlib.reload(sys.modules["llm_client"])
    try:
        spec = importlib.util.spec_from_file_location("sast_scan_agent", agent_file)
        if spec is None or spec.loader is None:
            raise ImportError(f"Could not load spec for {agent_file}")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        sys.modules["sast_scan_agent"] = module
        return module
    except Exception as exc:  # noqa: BLE001
        raise RuntimeError(_INSTALL_HINT.format(path=framework_path, error=exc)) from exc


def _project_context_note(project: Project) -> str:
    parts = [*(project.languages or []), *(project.frameworks or [])]
    if project.build_tool:
        parts.append(project.build_tool)
    return ", ".join(p for p in parts if p)


def run_real_scan(
    *,
    project: Project,
    workspace: Path,
    changed_paths: list[str] | None,
    scan_id: str | None = None,
    scan: Scan | None = None,
    findings_writer: Callable[[str, list[dict]], None] | None = None,
    discovery_writer: Callable[[dict], None] | None = None,
    verdict_updates_writer: Callable[[str, list[dict]], None] | None = None,
) -> dict:
    """Run the discovery agent against `workspace` and return its findings."""
    agent = _load_agent_module()

    llm_provider = (
        (scan.llm_provider if scan else None)
        or getattr(project, "llm_provider", None)
        or "bedrock"
    )
    llm_model = (
        (scan.llm_model if scan else None)
        or getattr(project, "llm_model", None)
        or None
    )
    fallback_llm_provider = (
        (getattr(scan, "fallback_llm_provider", None) if scan else None)
        or getattr(project, "fallback_llm_provider", None)
        or "ollama"
    )
    fallback_llm_model = (
        (getattr(scan, "fallback_llm_model", None) if scan else None)
        or getattr(project, "fallback_llm_model", None)
        or "granite-code:3b"
    )

    source_meta = (scan.metadata_json if scan else None) or {}
    scope = (
        (source_meta.get("repo_path") or "").strip()
        or (getattr(project, "monorepo_path", None) or "").strip()
        or None
    )
    use_llm = bool(source_meta.get("use_llm", True))

    # Project-level scan limitations (app/defaults/scan_limitations.py). A
    # project that has never touched the Limitations panel has
    # limitations_config=None, so .get(...) falls back to each entry's
    # documented enabled_by_default.
    limitations_config = getattr(project, "limitations_config", None) or {}
    suppress_no_cwe_findings = limitations_config.get("cwe-less-findings-suppressed", True)
    suppress_http_findings = limitations_config.get("https-enforced-suppress-http", False)
    suppress_low_confidence_false_positives = limitations_config.get(
        "low-confidence-fp-suppressed", True
    )
    inter_file_flow = use_llm and limitations_config.get("inter-file-call-graph", True)
    derive_runtime_rules = limitations_config.get("runtime-derived-regex", True)
    deep_scan_critical_only = limitations_config.get("deep-scan-critical-only", True)
    triage_mode = (
        agent.llm_file_scan.TRIAGE_MODE_LLM
        if limitations_config.get("triage-mode-llm-confirm", True)
        else agent.llm_file_scan.TRIAGE_MODE_REGEX_ONLY
    )
    max_derived = getattr(project, "max_derived_regex_rules", None)
    if max_derived is None:
        max_derived = 50

    initial_state: dict = {
        "local_path": str(workspace),
        "scope": scope,
        "project_name": getattr(project, "name", None) or workspace.name,
        "context_note": _project_context_note(project),
        "use_llm": use_llm,
        "llm_provider": llm_provider if use_llm else None,
        "llm_model": llm_model if use_llm else None,
        "fallback_llm_provider": fallback_llm_provider if use_llm else None,
        "fallback_llm_model": fallback_llm_model if use_llm else None,
        "persist_to_disk": False,
        # LLM-confirm unverified MEDIUM/LOW groups (node_confirm_triage_groups)
        # whenever this scan is doing any LLM work at all. Uncapped (every
        # group gets confirmed, not just the top N by occurrence) so a scan
        # never finishes with findings sitting at "unverified" — batching
        # (groups_per_call, still defaulted in the node) is what keeps this
        # affordable, with LLM_COST_CUTOFF_USD as the real spend backstop.
        "confirm_triage_groups": use_llm,
        "triage_confirm_group_cap": None,
        "suppress_no_cwe_findings": suppress_no_cwe_findings,
        "suppress_http_findings": suppress_http_findings,
        "suppress_low_confidence_false_positives": suppress_low_confidence_false_positives,
        "inter_file_flow": inter_file_flow,
        "derive_runtime_rules": derive_runtime_rules,
        "deep_scan_critical_only": deep_scan_critical_only,
        "triage_mode": triage_mode,
        "max_derived_regex_rules": max_derived,
        "findings_writer": findings_writer,
        "discovery_writer": discovery_writer,
        "verdict_updates_writer": verdict_updates_writer,
        "usage": agent.init_usage(
            llm_provider if use_llm else None,
            llm_model if use_llm else None,
            fallback_provider=fallback_llm_provider if use_llm else None,
            fallback_model=fallback_llm_model if use_llm else None,
        ),
        # verbose=True: AgentTrace's narration prints are what scan_log.capture()
        # tails live for the frontend's Agent log tab.
        "_tracer": agent.AgentTrace(verbose=True),
    }

    graph = agent.build_graph()
    final_state = agent.invoke_graph(graph, initial_state)

    scan_summary = dict(final_state.get("scan") or {})
    scan_summary.pop("files", None)  # per-file list lives in module_plan.files instead
    llm_analysis = final_state.get("llm_analysis") or {}
    categorized = final_state.get("categorized") or {}
    module_plan = final_state.get("module_plan") or {}
    usage = final_state.get("usage") or {}

    # Server-side debug detail only (logging writes to stderr, not the tee'd
    # stdout scan_log.capture() records) — the human-facing summary already
    # printed via AgentTrace's map_modules_and_risk wrap-up.
    logger.info(
        "discovery agent finished tech_stack=%s files=%s risk_counts=%s llm_calls=%d",
        llm_analysis.get("tech_stack"),
        scan_summary.get("total_files"),
        module_plan.get("risk_counts"),
        len(usage.get("calls") or []),
    )

    discovery = {
        "scan_summary": scan_summary,
        "llm_analysis": llm_analysis,
        "categorized_counts": {k: len(v) for k, v in categorized.items()},
        "module_plan": module_plan,
        "derived_rules": agent.derived_rules_payload(final_state.get("derived_rules")),
        "derived_rules_summary": final_state.get("derived_rules_summary") or {},
        "report": final_state.get("report"),
    }

    return {
        "discovery": discovery,
        "usage_summary": agent.usage_cost_summary(usage),
    }
