#!/usr/bin/env python3
"""
DAST tool CLI: preflight -> fingerprint -> authenticate -> discover -> API analysis.

CLI entry point. The pipeline itself is defined across:
    state.py / runtime.py - GraphState and the per-scan collaborators (model gateway, guarded executor, ...)
    llm_utils.py       - small helpers for asking the model gateway for a JSON reply
    url_utils.py        - URL normalization/dedup helpers used by the crawl node
    nodes/             - check_connection, fingerprint, authenticate, discover (crawl), analyze_apis
    graph.py           - wires the nodes into the LangGraph pipeline
    runner.py          - runs the graph over a runtime and builds the discovery summary

Targets local practice apps (e.g. DVWA, Juice Shop) that you own or are authorized to test.
"""

import argparse
import json
import sys

from ..config import settings
from ..services.dast_runtime import build_standalone_runtime
from .runner import run_dast_scan
from .url_utils import NOISE_QUERY_KEYS_DEFAULT


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="DAST tool: connection check + login-type classification + login + crawl"
    )
    parser.add_argument("--url", required=True, help="Target application's base URL")
    parser.add_argument("--login-url", required=False, help="Login page URL (required unless --storage-state is given)")
    parser.add_argument("--username", required=False)
    parser.add_argument("--password", required=False)
    parser.add_argument("--headless", action="store_true", default=False)
    parser.add_argument("--ollama-model", default=settings.dast_ollama_model)
    parser.add_argument("--ollama-base-url", default=settings.dast_ollama_url)

    parser.add_argument(
        "--storage-state",
        default=None,
        help="Path to a Playwright storage state JSON file. If given, check_connection, "
             "classify_login_type, and login are skipped entirely; this session is loaded "
             "into a new browser context and the crawl starts directly from --url.",
    )
    parser.add_argument("--max-depth", type=int, default=settings.dast_max_depth)
    parser.add_argument("--max-pages", type=int, default=settings.dast_max_pages)
    parser.add_argument("--max-runtime-minutes", type=float, default=settings.dast_max_runtime_minutes)
    parser.add_argument("--max-per-pattern", type=int, default=settings.dast_max_per_pattern)
    parser.add_argument("--same-domain-mode", choices=["exact", "root-domain"], default=settings.dast_same_domain_mode)
    parser.add_argument("--noise-params", default=NOISE_QUERY_KEYS_DEFAULT)
    parser.add_argument("--verbose", action=argparse.BooleanOptionalAction, default=True)

    args = parser.parse_args()

    if not args.storage_state:
        required = [("--login-url", args.login_url), ("--username", args.username), ("--password", args.password)]
        missing = [name for name, val in required if not val]
        if missing:
            parser.error(f"{', '.join(missing)} required unless --storage-state is provided")

    return args


def main() -> None:
    args = parse_args()

    storage_state = None
    if args.storage_state:
        with open(args.storage_state, encoding="utf-8") as handle:
            storage_state = json.load(handle)
    runtime = build_standalone_runtime(
        target_url=args.url,
        login_url=args.login_url or "",
        username=args.username or "",
        password=args.password or "",
        storage_state=storage_state,
        headless=args.headless,
        ollama_model=args.ollama_model,
        ollama_base_url=args.ollama_base_url,
        budgets={
            "max_depth": args.max_depth,
            "max_pages": args.max_pages,
            "max_runtime_minutes": args.max_runtime_minutes,
            "max_per_pattern": args.max_per_pattern,
        },
    )
    try:
        discovery = run_dast_scan(runtime=runtime)["discovery"]

        print("\n--- Run summary ---")
        print(f"connection_ok: {discovery['connection_ok']}")
        fingerprint = discovery.get("fingerprint") or {}
        if fingerprint:
            print(f"fingerprint: shape={fingerprint.get('shape')} auth={fingerprint.get('auth')} schema={fingerprint.get('schema')}")
        if discovery.get("authentication_failed"):
            print(f"authentication_failed: {discovery['authentication_failed']}")
        if discovery.get("stop_reason"):
            print(f"stop_reason: {discovery['stop_reason']}")
        if discovery.get("crawl_stop_reason"):
            print(f"crawl_stop_reason: {discovery['crawl_stop_reason']}")
            print(f"pages_visited: {len(discovery['pages'])}")
            print(f"api_endpoints_found: {len(discovery['api_calls'])}")
            if discovery["pages"]:
                print("\nDiscovered pages:")
                for p in discovery["pages"]:
                    print(f"  [depth {p['depth']}] {p['url']}")
            if discovery["api_calls"]:
                print("\nDiscovered API endpoints:")
                for call in discovery["api_calls"]:
                    print(f"  {call['method']} {call['url']}")
    except Exception as exc:  # noqa: BLE001
        print(f"Unexpected error: {exc}")
        sys.exit(1)
    finally:
        if runtime.credentials is not None:
            runtime.credentials.clear()
        runtime.close()


if __name__ == "__main__":
    main()
