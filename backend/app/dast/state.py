"""Shared LangGraph state definition and its constructor."""

from __future__ import annotations

import argparse
from typing import Any, Optional, TypedDict



class GraphState(TypedDict):
    # inputs
    url: str
    login_url: str
    username: str
    password: str
    gateway: Any  # a ModelGateway (app.dast.domain.interfaces); the only way the engine reaches a model

    # playwright handles (kept out of pydantic since they are not serializable)
    # (typed Any, not Browser/Page: LangGraph resolves TypedDict hints at runtime and
    # playwright is deliberately not imported at module load)
    browser: Optional[Any]
    page: Optional[Any]

    # node 1 outputs
    connection_ok: bool
    connection_error: str

    # node 2 outputs
    page_details: dict
    login_type: str
    login_type_reason: str

    # node 3 outputs
    identified_username_selector: str
    identified_password_selector: str
    identified_submit_selector: str
    identified_success_indicator: str
    selector_source: str
    login_success: bool
    login_error: str

    # control
    stop_reason: str

    # per-scan collaborators and run state (see runtime.py). `runtime` holds the gateway, the
    # guarded executor, the browser factory and the credential holder; `sessions` one isolated
    # session per identity. Not serializable by design.
    runtime: Optional[Any]
    sessions: Optional[Any]
    root_response: Optional[Any]  # the preflight's response snapshot, reused by the fingerprint
    preflight: dict
    fingerprint: dict
    schema_document: Optional[str]  # an API description the fingerprint already fetched
    schema_found: bool
    schema_too_large: str  # url of an API description that exceeded the size cap
    traffic_cursor: dict
    inventory: Optional[Any]  # domain Inventory, merged observed + schema endpoints
    inventory_diff: dict
    authentication_failed: str  # a human-readable reason when a required identity could not log in
    credentials_lost: bool
    credentials_lost_reason: str
    relogin_requested: list  # identity ids whose session was lost and may be re-established once
    relogin_counts: dict
    crawl_progress: dict  # identity id -> crawl state kept across a re-login
    identity_results: list

    # crawl configuration (from CLI)
    max_depth: int
    max_pages: int
    max_runtime_minutes: float
    max_per_pattern: int
    same_domain_mode: str
    noise_params: list
    storage_state: Optional[str]
    verbose: bool

    # node 4 (crawl) state
    crawl_start_url: str
    visited: set
    queue: list
    pattern_counts: dict
    pages_data: list
    skipped_duplicate_patterns: list
    api_calls: list
    failed_urls: list
    warnings: list
    crawl_stop_reason: str
    crawl_start_time: float
    consecutive_low_value_visits: int
    relogin_count: int

    # node 5 (analyze_apis) config + output
    run_analysis: bool
    dast_max_apis: Optional[int]
    dast_max_tests_per_api: Optional[int]
    api_analysis: list
    passive_analysis: dict  # summary of the passive stage (checks run, findings, CORS assessability)
    authorization: dict  # replay summaries and notes from the authorization stage (the matrix is derived from them)
    active_testing: dict  # counters from the active stage (tests sent, dropped, guardrail changes, not tested)
    browser_probe: dict  # counters from the browser input probes (probes, submits, findings)

    # incremental finding sink (set by the FastAPI runner; None for the CLI).
    # Called once per API with that API's FAIL/INCONCLUSIVE findings.
    findings_writer: Any

    # optional cancel hook (set by the FastAPI runner; None for the CLI)
    should_abort: Any


def make_initial_state(args: argparse.Namespace, gateway: Any, noise_params: list) -> GraphState:
    return GraphState(
        url=args.url,
        login_url=args.login_url or "",
        username=args.username or "",
        password=args.password or "",
        gateway=gateway,
        browser=None,
        page=None,
        connection_ok=False,
        connection_error="",
        page_details={},
        login_type="",
        login_type_reason="",
        identified_username_selector="",
        identified_password_selector="",
        identified_submit_selector="",
        identified_success_indicator="",
        selector_source="",
        login_success=False,
        login_error="",
        stop_reason="",
        runtime=getattr(args, "runtime", None),
        sessions=getattr(args, "sessions", None),
        root_response=None,
        preflight={},
        fingerprint={},
        schema_document=None,
        schema_found=False,
        schema_too_large="",
        traffic_cursor={},
        inventory=None,
        inventory_diff={},
        authentication_failed="",
        credentials_lost=False,
        credentials_lost_reason="",
        relogin_requested=[],
        relogin_counts={},
        crawl_progress={},
        identity_results=[],
        max_depth=args.max_depth,
        max_pages=args.max_pages,
        max_runtime_minutes=args.max_runtime_minutes,
        max_per_pattern=args.max_per_pattern,
        same_domain_mode=args.same_domain_mode,
        noise_params=noise_params,
        storage_state=args.storage_state,
        verbose=args.verbose,
        crawl_start_url=args.url,
        visited=set(),
        queue=[],
        pattern_counts={},
        pages_data=[],
        skipped_duplicate_patterns=[],
        api_calls=[],
        failed_urls=[],
        warnings=[],
        crawl_stop_reason="",
        crawl_start_time=0.0,
        consecutive_low_value_visits=0,
        relogin_count=0,
        run_analysis=getattr(args, "run_analysis", True),
        dast_max_apis=getattr(args, "dast_max_apis", None),
        dast_max_tests_per_api=getattr(args, "dast_max_tests_per_api", None),
        api_analysis=[],
        passive_analysis={},
        active_testing={},
        browser_probe={},
        authorization={},
        findings_writer=getattr(args, "findings_writer", None),
        should_abort=getattr(args, "should_abort", None),
    )
