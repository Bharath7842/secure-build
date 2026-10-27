"""Bridge into the in-repo discovery agent.

`sast_scan_agent.py` lives under `backend/sast_engine/` (default
`settings.sast_framework_path`). Imported lazily so the mock-engine test suite
never needs boto3 / langgraph installed.

Pipeline: scan_directory -> analyze_tech_stack -> categorize_files ->
map_modules_and_risk -> build_joern_cpg -> build_call_graph -> derive_runtime_rules
-> discover_flows -> verify_flow_slices -> scan_deep_files -> scan_triage_files
-> joern_scan -> group_triage_findings -> confirm_triage_groups
-> generate_report.

`scan_deep_files` runs the full LLM scan over CRITICAL/HIGH files;
`scan_triage_files` regex-gates MEDIUM/LOW, sending only regex hits and their
surrounding context to the LLM (zero-hit files cost no LLM call at all).
"""

import importlib
import importlib.util
import logging
import os
import shutil
import sys
import tempfile
import uuid
from pathlib import Path
from typing import Callable

from app.config import settings
from app.defaults.scan_limitations import SCAN_LIMITATIONS
from app.models import Project, Scan

logger = logging.getLogger(__name__)

# Fixed namespace so a scan id always maps to the same Claude session UUID.
_CLAUDE_SESSION_NAMESPACE = uuid.UUID("6f1c1f0e-5a53-4a52-9d57-2c1d6b0f7a11")

# Toggle defaults come from the catalog, never a second hard-coded copy.
_LIMITATION_DEFAULTS = {lim.id: lim.enabled_by_default for lim in SCAN_LIMITATIONS}


_INSTALL_HINT = """Real SAST engine requested but the in-repo agent could not be imported.

SAST_FRAMEWORK_PATH: {path}
Original import error: {error}

Fix:
  1. Confirm backend/sast_engine contains sast_scan_agent.py
  2. Install backend deps: pip install -r backend/requirements.txt
  3. For Bedrock: configure AWS credentials with bedrock:InvokeModel
  4. For an OpenAI-compatible server: set the project's LLM base URL (or
     OPENAI_COMPAT_BASE_URL) and model
  5. For Ollama: run a local daemon at OLLAMA_BASE_URL with the chosen model
  6. Re-run with USE_MOCK_ENGINE=false RUN_LIVE_SAST=1.
"""


def _sync_env_from_settings() -> None:
    os.environ.setdefault("AWS_REGION", settings.aws_region)
    os.environ.setdefault("BEDROCK_MODEL_ID", settings.bedrock_model_id)
    os.environ.setdefault("OLLAMA_BASE_URL", settings.ollama_base_url)
    os.environ.setdefault("OLLAMA_REQUEST_TIMEOUT", str(settings.ollama_request_timeout))
    os.environ.setdefault("OPENAI_COMPAT_BASE_URL", settings.openai_compat_base_url)
    os.environ.setdefault("OPENAI_COMPAT_REQUEST_TIMEOUT", str(settings.openai_compat_request_timeout))
    if settings.claude_cli_path:
        os.environ.setdefault("CLAUDE_CLI_PATH", settings.claude_cli_path)
    os.environ.setdefault("CLAUDE_CLI_REQUEST_TIMEOUT", str(settings.claude_cli_request_timeout))
    if settings.codex_cli_path:
        os.environ.setdefault("CODEX_CLI_PATH", settings.codex_cli_path)
    os.environ.setdefault("CODEX_CLI_REQUEST_TIMEOUT", str(settings.codex_cli_request_timeout))
    if settings.joern_home:
        os.environ.setdefault("JOERN_HOME", settings.joern_home)
    os.environ.setdefault("JOERN_TIMEOUT_SEC", str(settings.joern_timeout_sec))
    os.environ.setdefault("JOERN_JAVA_OPTS", settings.joern_java_opts)
    if settings.joern_java_home:
        os.environ.setdefault("JOERN_JAVA_HOME", settings.joern_java_home)


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


def llm_usage_options(project: Project, scan: Scan | None = None) -> dict:
    """Keyword arguments for the engine's init_usage carrying this scan's
    openai_compat endpoint/key and its claude_cli session. The key comes from
    the project (never snapshotted); the base URL prefers the scan's
    snapshot so a re-run matches what the scan originally used."""
    base_url = (
        (getattr(scan, "llm_base_url", None) if scan else None)
        or getattr(project, "llm_base_url", None)
        or settings.openai_compat_base_url
    )
    api_key = getattr(project, "llm_api_key", None) or (
        settings.openai_compat_api_key.get_secret_value() if settings.openai_compat_api_key else ""
    )
    options: dict = {"openai_compat": {"base_url": base_url, "api_key": api_key}}
    if getattr(scan, "id", None):
        options["claude_cli"] = claude_cli_session(scan)
        options["openai_cli"] = openai_cli_session(scan)
    return {"provider_options": options}


def claude_cli_session(scan: Scan) -> dict:
    """The scan's one Claude session: a UUID derived from the scan id (so the
    reconcile sweep continues the same session) and the empty directory every
    call of the scan runs in (Claude keys sessions by working directory).
    Reopen it with `cd <workdir> && claude --resume <session_id>`."""
    return {
        "session_id": str(uuid.uuid5(_CLAUDE_SESSION_NAMESPACE, str(scan.id))),
        "workdir": str(Path(settings.claude_cli_dir) / str(scan.id)),
    }


def openai_cli_session(scan: Scan) -> dict:
    """The scan's key into the engine's thread registry (the CLI chooses the real
    thread id on the first call) and the empty directory every call runs in."""
    return {
        "session_id": str(uuid.uuid5(_CLAUDE_SESSION_NAMESPACE, f"openai_cli:{scan.id}")),
        "workdir": str(Path(settings.openai_cli_dir) / str(scan.id)),
    }


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
    reachability_updates_writer: Callable[[str, list[dict]], None] | None = None,
    result_cache: object | None = None,
    state_overrides: dict | None = None,
) -> dict:
    """Run the discovery agent against `workspace` and return its findings.

    `result_cache` (a `get`/`put` object, see `llm_client.RESULT_CACHE_USAGE_KEY`)
    replaces the project's DB-backed LLM result cache, and `state_overrides` is
    merged over the initial graph state last. Both exist for the accuracy
    corpus (`backend/accuracy/`), which replays recorded LLM responses and pins
    engine knobs the API does not expose; the API never passes either."""
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
        or "none"
    )
    fallback_llm_model = (
        (getattr(scan, "fallback_llm_model", None) if scan else None)
        or getattr(project, "fallback_llm_model", None)
        or None
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
    # limitations_config=None, so every toggle falls back to its catalog
    # entry's enabled_by_default — the same rule the settings page uses, so
    # what the page shows is what the scan does.
    limitations_config = getattr(project, "limitations_config", None) or {}

    def enabled(limitation_id: str) -> bool:
        return bool(limitations_config.get(limitation_id, _LIMITATION_DEFAULTS[limitation_id]))

    suppress_no_cwe_findings = enabled("cwe-less-findings-suppressed")
    suppress_http_findings = enabled("https-enforced-suppress-http")
    suppress_low_confidence_false_positives = enabled("low-confidence-fp-suppressed")
    occurrence_validators = enabled("occurrence-validators")
    inter_file_flow = use_llm and enabled("inter-file-call-graph")
    derive_runtime_rules = enabled("runtime-derived-regex")
    joern_dataflow = enabled("joern-dataflow")
    joern_scan_queries = enabled("joern-scan-queries")
    deep_scan_critical_only = enabled("deep-scan-critical-only")
    triage_mode = (
        agent.llm_file_scan.TRIAGE_MODE_LLM
        if enabled("triage-mode-llm-confirm")
        else agent.llm_file_scan.TRIAGE_MODE_REGEX_ONLY
    )
    catalog_prefilter = enabled("ripgrep-catalog-prefilter")
    parallel_stages = enabled("parallel-scan-stages")
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
        "occurrence_validators": occurrence_validators,
        "inter_file_flow": inter_file_flow,
        "derive_runtime_rules": derive_runtime_rules,
        "joern_dataflow": joern_dataflow,
        "joern_scan_queries": joern_scan_queries,
        "deep_scan_critical_only": deep_scan_critical_only,
        "triage_mode": triage_mode,
        "catalog_prefilter": catalog_prefilter,
        "parallel_stages": parallel_stages,
        "max_derived_regex_rules": max_derived,
        "findings_writer": findings_writer,
        "discovery_writer": discovery_writer,
        "verdict_updates_writer": verdict_updates_writer,
        "reachability_updates_writer": reachability_updates_writer,
        "usage": agent.init_usage(
            llm_provider if use_llm else None,
            llm_model if use_llm else None,
            fallback_provider=fallback_llm_provider if use_llm else None,
            fallback_model=fallback_llm_model if use_llm else None,
            **llm_usage_options(project, scan),
        ),
        # verbose=True: AgentTrace's narration prints are what scan_log.capture()
        # tails live for the frontend's Agent log tab.
        "_tracer": agent.AgentTrace(verbose=True),
    }

    # Cross-scan LLM result reuse: an identical prompt to the same model (an
    # unchanged file chunk, flow slice or hit set) is answered from the
    # project's cache instead of the provider. `metadata.bypass_llm_cache`
    # on the scan request forces every call live, e.g. to measure a cold run.
    project_id = getattr(project, "id", None)
    if use_llm and result_cache is not None:
        initial_state["usage"][agent.RESULT_CACHE_USAGE_KEY] = result_cache
    elif use_llm and project_id and not source_meta.get("bypass_llm_cache"):
        from app.services.llm_result_cache import DbLlmResultCache

        initial_state["usage"][agent.RESULT_CACHE_USAGE_KEY] = DbLlmResultCache(project_id)
    if state_overrides:
        initial_state.update(state_overrides)

    # Joern CPGs can run to gigabytes; own the scratch dir here so it is
    # removed even when the graph raises partway through.
    joern_work_dir = Path(tempfile.mkdtemp(prefix="sast-joern-"))
    initial_state["joern_work_dir"] = str(joern_work_dir)
    if parallel_stages and scan_id:
        from app.services import scan_log

        # Each parallel stage's printed lines get "[[stage:<name>]] " so the
        # UI and progress can tell the interleaved stages apart.
        initial_state["_stage_log_context"] = (
            lambda stage: scan_log.capture(scan_id, prefix=f"[[stage:{stage}]] ")
        )
    graph = agent.build_graph(parallel=parallel_stages)
    try:
        final_state = agent.invoke_graph(graph, initial_state)
    finally:
        shutil.rmtree(joern_work_dir, ignore_errors=True)

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
