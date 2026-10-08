"""Adapter between the scan runner and the underlying SAST discovery engine.

Mock path: deterministic fake discovery output so tests and local development
can exercise the full scan lifecycle without a real engine or network.

Real path: bridges into the LangGraph discovery agent via
`app.services.agent_bridge.run_real_scan` (`backend/sast_engine`).
"""

import logging
import os
from typing import Any, Callable, TypedDict

from app.config import settings
from app.models import Project


class ScanRunResult(TypedDict, total=False):
    discovery: dict[str, Any]
    usage_summary: dict[str, Any]


logger = logging.getLogger(__name__)


def mock_engine_enabled() -> bool:
    env_flag = os.environ.get("USE_MOCK_ENGINE", "false").lower() in ("1", "true")
    return env_flag or settings.use_mock_engine


def run_live_sast_enabled() -> bool:
    env_flag = os.environ.get("RUN_LIVE_SAST")
    if env_flag is not None:
        return env_flag.strip().lower() not in ("0", "false", "no", "off")
    return settings.run_live_sast


def run_live_sca_enabled() -> bool:
    """Mirrors `run_live_sast_enabled()` for the SCA engine path — reads the
    `RUN_SCA` env var, falling back to `settings.run_sca` (already existed,
    previously a dead flag since nothing read it before this feature)."""
    env_flag = os.environ.get("RUN_SCA")
    if env_flag is not None:
        return env_flag.strip().lower() not in ("0", "false", "no", "off")
    return settings.run_sca


def run_live_sbom_enabled() -> bool:
    """Mirrors `run_live_sca_enabled()` for the SBOM engine path — reads the
    `RUN_SBOM` env var, falling back to `settings.run_sbom`."""
    env_flag = os.environ.get("RUN_SBOM")
    if env_flag is not None:
        return env_flag.strip().lower() not in ("0", "false", "no", "off")
    return settings.run_sbom


def run_live_dast_enabled() -> bool:
    """Mirrors `run_live_sbom_enabled()` for the DAST crawl — reads `RUN_DAST`,
    falling back to `settings.run_dast`."""
    env_flag = os.environ.get("RUN_DAST")
    if env_flag is not None:
        return env_flag.strip().lower() not in ("0", "false", "no", "off")
    return settings.run_dast


def run_sbom_llm_enrichment_enabled() -> bool:
    """Reads the `SBOM_LLM_ENRICHMENT` env var, falling back to
    `settings.sbom_llm_enrichment` — gates `sbom_scan.run_sbom_scan`'s
    best-effort Bedrock Claude Haiku supplier/license/type fill-in."""
    env_flag = os.environ.get("SBOM_LLM_ENRICHMENT")
    if env_flag is not None:
        return env_flag.strip().lower() not in ("0", "false", "no", "off")
    return settings.sbom_llm_enrichment


def run_scan(
    project: Project,
    git_url: str,
    branch: str,
    commit_sha: str | None,
    changed_paths: list[str] | None = None,
    workspace=None,
    scan_id: str | None = None,
    scan=None,
    findings_writer: Callable[[str, list[dict]], None] | None = None,
    discovery_writer: Callable[[dict], None] | None = None,
    verdict_updates_writer: Callable[[str, list[dict]], None] | None = None,
) -> ScanRunResult:
    if mock_engine_enabled():
        discovery = _mock_discovery(project)
        if discovery_writer:
            discovery_writer(discovery)
        return {"discovery": discovery}

    if not run_live_sast_enabled():
        raise RuntimeError(
            "Real engine requested (USE_MOCK_ENGINE=false) but live SAST is disabled. "
            "Set RUN_LIVE_SAST=1 or run_live_sast=true in settings."
        )

    if workspace is None:
        raise RuntimeError(
            "run_scan called without a checked-out workspace; "
            "git_workspace.ensure_workspace must run before the real engine adapter."
        )

    from app.services.agent_bridge import run_real_scan

    return run_real_scan(
        project=project,
        workspace=workspace,
        changed_paths=changed_paths,
        scan_id=scan_id,
        scan=scan,
        findings_writer=findings_writer,
        discovery_writer=discovery_writer,
        verdict_updates_writer=verdict_updates_writer,
    )


def run_sca_scan(
    project: Project,
    workspace=None,
    scan_id: str | None = None,
    findings_writer: Callable[[str, list[dict]], None] | None = None,
    discovery_writer: Callable[[dict], None] | None = None,
) -> ScanRunResult:
    """SCA counterpart to `run_scan` — deterministic manifest-parsing + OSV.dev
    lookup (`sast_engine/pipeline/sca_scan.py`), no LangGraph/LLM involved.
    Mirrors the same mock/live gating so the test suite never hits the
    network regardless of which scan_type is exercised."""
    if mock_engine_enabled():
        discovery = _mock_sca_discovery(project)
        if discovery_writer:
            discovery_writer(discovery)
        return {"discovery": discovery}

    if not run_live_sca_enabled():
        raise RuntimeError(
            "Real SCA engine requested (USE_MOCK_ENGINE=false) but live SCA is disabled. "
            "Set RUN_SCA=1 or run_sca=true in settings."
        )

    if workspace is None:
        raise RuntimeError(
            "run_sca_scan called without a checked-out workspace; "
            "git_workspace.ensure_workspace must run before the SCA engine adapter."
        )

    from sast_engine.pipeline import sca_scan

    return sca_scan.run_sca_scan(
        repo_root=workspace,
        findings_writer=findings_writer,
        discovery_writer=discovery_writer,
    )


def run_sbom_scan(
    project: Project,
    workspace=None,
    scan_id: str | None = None,
    discovery_writer: Callable[[dict], None] | None = None,
) -> ScanRunResult:
    """SBOM counterpart to `run_sca_scan` — deterministic manifest-parsing +
    PURL/deps.dev-license classification + CycloneDX/SPDX build
    (`sast_engine/pipeline/sbom_scan.py`), no LangGraph involved. Unlike SCA,
    this path does make one LLM detour: `run_sbom_llm_enrichment_enabled()`
    gates a best-effort Bedrock Claude Haiku supplier/license/type fill-in
    for whatever deps.dev + the static tables left unresolved (see
    `sbom_scan.llm_enrich_components`) — mock scans never reach it, and it
    fails open (never raises) even when live. Mirrors the same mock/live
    gating so the test suite never hits the network regardless of which
    scan_type is exercised. Produces no findings — SBOM has no
    vulnerability-detection step of its own."""
    if mock_engine_enabled():
        discovery = _mock_sbom_discovery(project)
        if discovery_writer:
            discovery_writer(discovery)
        return {"discovery": discovery}

    if not run_live_sbom_enabled():
        raise RuntimeError(
            "Real SBOM engine requested (USE_MOCK_ENGINE=false) but live SBOM is disabled. "
            "Set RUN_SBOM=1 or run_sbom=true in settings."
        )

    if workspace is None:
        raise RuntimeError(
            "run_sbom_scan called without a checked-out workspace; "
            "git_workspace.ensure_workspace must run before the SBOM engine adapter."
        )

    from sast_engine.pipeline import sbom_scan

    return sbom_scan.run_sbom_scan(
        repo_root=workspace,
        scan_id=scan_id,
        discovery_writer=discovery_writer,
        use_llm_enrichment=run_sbom_llm_enrichment_enabled(),
    )


def _oast_url() -> str | None:
    """The OAST callback address (the stored override, else the environment)."""
    try:
        from app.services.dast_settings import current_oast_url

        return current_oast_url()
    except Exception:  # noqa: BLE001 - no database yet (a bare CLI run): the environment value
        return settings.dast_oast_callback_url


def _training_sink(project: Any, scan_id: str | None, target_url: str, credentials: Any):
    """The training-data sink for a project that opted in; None for everyone else (the default)."""
    if project is None or not getattr(project, "training_capture_enabled", False) or not scan_id:
        return None
    from app.services.dast_training import TrainingSink

    return TrainingSink(project.id, scan_id, target_url=target_url, secrets=lambda: credentials.secrets() if hasattr(credentials, "secrets") else [])


def run_dast_scan(
    project: Project,
    dast_input: dict[str, Any],
    scan_id: str | None = None,
    discovery_writer: Callable[[dict], None] | None = None,
    findings_writer: Callable[[str, list[dict]], None] | None = None,
    should_abort: Callable[[], bool] | None = None,
    effective_settings: dict[str, Any] | None = None,
    gateway: Any = None,
    credentials: Any = None,
    scan: Any = None,
) -> ScanRunResult:
    """DAST counterpart to `run_sbom_scan` — Playwright + model-gateway login/crawl,
    then per-REST-API security analysis (`app/dast/runner.py`). Needs no git
    workspace: the target is a URL. Mock engine returns deterministic discovery
    + findings so tests never launch a browser or touch the network.

    `effective_settings` is the scan's snapshot (`Settings.dast_effective_settings()` at scan
    start); its `model_routing` decides which provider and model serves each gateway task, so a
    settings change mid-scan or later cannot alter a running or past scan. `gateway` lets a test
    inject a fake; otherwise one is built here, which is the only place the engine gets a model.
    `credentials` is the scan's in-memory credential holder (`dast_input["identities"]` says who
    the identities are; the holder has their secrets)."""
    if mock_engine_enabled():
        from app.dast.mock_engine import run_mock_dast

        result, batches = run_mock_dast(dast_input)
        if discovery_writer:
            discovery_writer(result["discovery"])
        if findings_writer:
            for label, rows in batches:
                findings_writer(label, rows)
        return result

    if not run_live_dast_enabled():
        raise RuntimeError(
            "Real DAST engine requested (USE_MOCK_ENGINE=false) but live DAST is disabled. "
            "Set RUN_DAST=1 or run_dast=true in settings."
        )

    from app.dast.domain.identities import spec_from_public
    from app.dast.runner import run_dast_scan as _run
    from app.services.dast_runtime import build_runtime
    from app.services.model_gateway import build_gateway

    snapshot = effective_settings or settings.dast_effective_settings()
    routing = {task: tuple(route) for task, route in (snapshot.get("model_routing") or {}).items()} or None
    gateway = gateway or build_gateway(routing)
    problems = gateway.check_configuration() if hasattr(gateway, "check_configuration") else []
    for problem in problems:  # not fatal: the task falls back, but the operator should know why
        print(f"Model configuration problem: {problem}")

    if credentials is None:
        from app.services.credential_holder import InMemoryCredentialHolder

        credentials = InMemoryCredentialHolder(scan_id or "")
    stored = dast_input.get("identities") or []
    if stored:
        identities = [spec_from_public(i) for i in stored]
    else:  # a scan created before identities existed: one anonymous baseline
        from app.dast.domain.identities import build_identities

        identities = build_identities([])
    metadata = getattr(scan, "metadata_json", None) or {}
    runtime = build_runtime(
        scan_id=scan_id or "",
        target_url=dast_input["target_url"],
        effective=snapshot,
        identities=identities,
        gateway=gateway,
        credentials=credentials,
        is_cancelled=should_abort,
        findings_writer=findings_writer,
        rule_set=metadata.get("dast_rule_set"),
        skipped_degraded=metadata.get("dast_skipped_degraded"),
        oast_url=_oast_url() if snapshot.get("oast_configured") else None,
        oast_poll_url=settings.dast_oast_poll_url,
        training_capture=_training_sink(project, scan_id, dast_input["target_url"], credentials),
    )
    try:
        result = _run(runtime=runtime, discovery_writer=discovery_writer, findings_writer=findings_writer, should_abort=should_abort)
    finally:
        runtime.close()
    usage = getattr(getattr(gateway, "usage", None), "summary", None)
    if usage is not None:
        result["usage_summary"] = usage()
    return result


def _mock_sbom_discovery(project: Project) -> dict[str, Any]:
    """Deterministic fake component inventory for the mock engine — no
    filesystem walk, no network. Mirrors `_mock_sca_discovery`'s spirit, but
    also builds real (if tiny) CycloneDX/SPDX documents via `sbom_scan`'s
    own builders so the export endpoints have something to convert even
    under the mock engine."""
    from sast_engine.pipeline import sbom_scan

    print("STAGE 1 — Mock dependency manifest scan (SBOM)")
    components = [
        {
            "bom-ref": "pkg:pypi/requests@2.25.0",
            "type": "library",
            "name": "requests",
            "version": "2.25.0",
            "purl": "pkg:pypi/requests@2.25.0",
            "group": None,
            "ecosystem": "pypi",
            "scope": "runtime",
            "source_file": "requirements.txt",
            "licenses": [{"spdx_id": "Apache-2.0", "name": "Apache License 2.0"}],
            "cost_classification": "fully_free",
            "vendor": "Python Software Foundation",
            "origin_type": "Open Source",
            "dependency_relationship": "Direct",
            "direct": True,
        },
        {
            "bom-ref": "pkg:npm/lodash@4.17.15",
            "type": "library",
            "name": "lodash",
            "version": "4.17.15",
            "purl": "pkg:npm/lodash@4.17.15",
            "group": None,
            "ecosystem": "npm",
            "scope": "runtime",
            "source_file": "package.json",
            "licenses": [{"spdx_id": "MIT", "name": "MIT License"}],
            "cost_classification": "fully_free",
            "vendor": "OpenJS Foundation",
            "origin_type": "Open Source",
            "dependency_relationship": "Direct",
            "direct": True,
        },
    ]
    for comp in components:
        print(f"  {comp['ecosystem']}:{comp['name']}@{comp['version']} ({comp['source_file']})")
    print("STAGE 2 — Mock complete (no network deps.dev lookup in mock mode)")
    return {
        "component_summary": {
            "total_components": len(components),
            "ecosystems": sorted({c["ecosystem"] for c in components}),
            "manifests_parsed": sorted({c["source_file"] for c in components}),
            "license_summary": {"fully_free": len(components), "partially_free": 0, "fully_paid": 0, "unknown": 0},
        },
        "components": components,
        "sbom_cyclonedx": sbom_scan.build_cyclonedx_sbom(components, "mock-sbom-scan"),
        "sbom_spdx": sbom_scan.build_spdx_sbom(components, "mock-sbom-scan"),
    }


def _mock_sca_discovery(project: Project) -> dict[str, Any]:
    """Deterministic fake dependency inventory for the mock engine — no
    filesystem walk, no network. Mirrors `_mock_discovery`'s spirit."""
    print("STAGE 1 — Mock dependency manifest scan")
    dependencies = [
        {"ecosystem": "pypi", "name": "requests", "version": "2.25.0", "source_file": "requirements.txt"},
        {"ecosystem": "pypi", "name": "flask", "version": "1.1.2", "source_file": "requirements.txt"},
        {"ecosystem": "npm", "name": "lodash", "version": "4.17.15", "source_file": "package.json"},
    ]
    for dep in dependencies:
        print(f"  {dep['ecosystem']}:{dep['name']}@{dep['version']} ({dep['source_file']})")
    print("STAGE 2 — Mock complete (no network OSV lookup in mock mode)")
    return {
        "dependency_summary": {
            "total_dependencies": len(dependencies),
            "vulnerable_dependencies": 0,
            "manifests_parsed": sorted({d["source_file"] for d in dependencies}),
            "ecosystems": sorted({d["ecosystem"] for d in dependencies}),
            "severity_counts": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0},
        },
        "dependencies": dependencies,
    }


def _mock_discovery(project: Project) -> dict[str, Any]:
    print("STAGE 1 — Mock directory scan / tech-stack detection")
    languages = project.languages or ["Python"]
    frameworks = project.frameworks or []
    tech_stack = " + ".join([*languages, *frameworks]) or "Unrecognized stack"
    print(f"  languages={languages} frameworks={frameworks} build_tool={project.build_tool or 'n/a'}")

    files = [
        {
            "path": "app/db/queries.py",
            "stack": "python",
            "module": "(root)",
            "category": "source",
            "risk_level": "CRITICAL",
            "reason": "database / ORM layer (injection surface)",
        },
        {
            "path": "app/config/legacy.py",
            "stack": "python",
            "module": "(root)",
            "category": "config",
            "risk_level": "CRITICAL",
            "reason": "runtime config — possible embedded secrets",
        },
        {
            "path": "app/services/auth.py",
            "stack": "python",
            "module": "(root)",
            "category": "source",
            "risk_level": "CRITICAL",
            "reason": "authentication / authorization logic",
        },
        {
            "path": "tests/test_queries.py",
            "stack": "python",
            "module": "(root)",
            "category": "test",
            "risk_level": "LOW",
            "reason": "test code",
        },
    ]
    risk_counts = {"CRITICAL": 3, "HIGH": 0, "MEDIUM": 0, "LOW": 1}

    print(f"STAGE 2 — Mock tech-stack analysis (tech_stack={tech_stack})")
    print(f"STAGE 3-4 — Mock file categorization and risk mapping — {len(files)} file(s)")
    for f in files:
        print(f"  [{f['risk_level']}] {f['path']} ({f['reason']})")
    print("STAGE 5 — Mock discovery complete")

    return {
        "scan_summary": {
            "root": "(mock)",
            "total_files": len(files),
            "max_depth": 2,
            "top_level_entries": ["app", "tests"],
            "extension_histogram": {".py": len(files)},
            "marker_files_found": ["requirements.txt"],
        },
        "llm_analysis": {
            "heuristic_stacks": ["python"],
            "llm_used": False,
            "tech_stack": tech_stack,
            "project_type": "web app",
            "confidence": "medium",
            "risk_areas": ["Injection", "Authentication", "Secrets management"],
            "reasoning": "Mock discovery result — no LLM call made.",
        },
        "categorized_counts": {
            "source": 2,
            "config": 1,
            "dependency": 0,
            "test": 1,
            "build": 0,
            "other": 0,
        },
        "module_plan": {
            "modules_by_stack": {"python": ["(root)"]},
            "risk_counts": risk_counts,
            "files": files,
            "scan_priority": [f for f in files if f["risk_level"] in ("CRITICAL", "HIGH")],
        },
    }
