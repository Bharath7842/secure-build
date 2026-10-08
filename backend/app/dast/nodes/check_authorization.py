"""NODE: check_authorization (DAST-10-010 .. -030): replay what each identity reached as every other
identity and as Anonymous, and write the broken-authentication / BFLA / BOLA findings.

With a single authenticated identity only the anonymous replay runs (the cross-role cells are
`untested`, and the reason is stored). The replay summaries kept in `state["authorization"]` are what
the authorization matrix is derived from.
"""

from __future__ import annotations

from ..authorization import authz_checks, run_replays
from ..domain.authz import matrix_notes
from ..state import GraphState

DEFAULT_MAX_REPLAYS = 180


def check_authorization(state: GraphState) -> GraphState:
    runtime, store = state["runtime"], state["sessions"]
    specs = list(runtime.identities)
    notes = matrix_notes(specs)
    authorization: dict = {
        "ran": False, "identities": [s.to_public() for s in specs if not s.is_anonymous], "baseline_identity": next((s.label for s in specs if s.is_anonymous), "anonymous"),
        "replays": [], "total_replays": 0, "findings": 0, **notes,
    }
    state["authorization"] = authorization
    if not state.get("run_analysis", True):
        return state
    if runtime.cancelled():
        state["stop_reason"] = "cancelled"
        return state
    checks = authz_checks(runtime.rule_set, runtime.skipped_degraded)
    if not checks:
        print("[authz] No authorization check is enabled for this scan; nothing to replay.")
        return state
    authenticated = [s for s in store.authenticated()]
    if not authenticated:
        print("[authz] No identity signed in, so there is nothing to replay as another identity.")
        authorization["degraded_reason"] = "no authenticated identity: nothing to replay"
        return state
    inventory = state.get("inventory")
    if inventory is None:
        return state
    if notes["degraded"]:
        print(f"[authz] {notes['degraded_reason'].capitalize()}.")
    effective = runtime.effective
    secrets = runtime.credentials.secrets() if runtime.credentials is not None and hasattr(runtime.credentials, "secrets") else []
    max_replays = int(effective.get("max_targets") or 15) * int(effective.get("max_tests_per_target") or 12)
    writer = state.get("findings_writer") or runtime.findings_writer
    privilege = effective.get("role_privilege") or None

    def on_rows(rows: list[dict]) -> None:
        if writer:
            try:
                writer("authorization", rows)
            except Exception as exc:  # noqa: BLE001
                print(f"    Could not persist the authorization findings: {exc}")

    live = [s for s in specs if s.is_anonymous or store.get(s.identity_id).status == "authenticated"]
    spa = state.get("fingerprint", {}).get("shape") == "spa"
    result = run_replays(
        inventory.endpoints(), live, store, runtime.executor, checks, allow_state_changing=bool(effective.get("allow_state_changing")),
        max_replays=max_replays, privilege=privilege, secrets=secrets, cancelled=runtime.cancelled, log=print, on_rows=on_rows, spa=spa,
    )
    authorization.update(
        ran=True, replays=[s.to_dict() for s in result.summaries], total_replays=result.replays, findings=len(result.rows),
        cap=max_replays, cap_reached=result.cap_reached,
    )
    runtime.counters.set("replays", result.replays)
    print(f"[authz] {result.replays} replay(s) across {len(result.summaries)} role pair(s): {len(result.rows)} finding(s).")
    if result.cancelled:
        state["stop_reason"] = "cancelled"
    return state
