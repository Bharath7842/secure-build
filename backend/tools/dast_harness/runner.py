"""Run a scan against a practice target through the backend API and score it (DAST-16-010). `live`:
needs the practice targets, a model host and a running backend; not part of the default test run.
"""

from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

import httpx

from . import ground_truth
from .scoring import build_result, findings_from_api, guardrail_override_rate, score, summary_text

HERE = Path(__file__).resolve().parent
TERMINAL = ("success", "failed", "cancelled")


class HarnessError(RuntimeError):
    pass


def load_targets() -> dict[str, Any]:
    with open(HERE / "targets.json", encoding="utf-8") as handle:
        data = json.load(handle)
    return {k: v for k, v in data.items() if not k.startswith("_")}


def parse_identity(text: str) -> dict[str, Any]:
    """`label:role:username:password` (form login). The login URL comes from the target."""
    parts = text.split(":", 3)
    if len(parts) != 4 or not all(parts):
        raise HarnessError("--identity must look like label:role:username:password")
    return {"label": parts[0], "role": parts[1], "username": parts[2], "password": parts[3]}


def scan_payload(project_id: str, target: Mapping[str, Any], truth: ground_truth.GroundTruth, extra_identities: Sequence[Mapping[str, Any]] = ()) -> dict[str, Any]:
    identities = [dict(i) for i in target.get("identities") or []]
    for item in extra_identities:
        identities.append({"label": item["label"], "role": item["role"], "auth_method": "form", "login_url": target.get("login_url") or "", "username": item["username"], "password": item["password"]})
    dast: dict[str, Any] = {"target_url": target["target_url"], "authorized": True}
    if identities:
        dast["identities"] = identities
    if truth.rule_packs:
        dast["rule_packs"] = list(truth.rule_packs)
    if any("state_changing" in e.needs for e in truth.expected) and target.get("allow_state_changing"):
        dast.update(method_policy="opt_in_mutating", target_disposable=True)
    if any("browser_marker_posts" in e.needs for e in truth.expected):
        dast.update(browser_marker_posts=True, target_disposable=True)
    return {"project_id": project_id, "scan_type": "dast", "dast": dast}


def run(
    target_name: str,
    *,
    backend: str,
    token: str,
    project_id: str | None = None,
    identities: Sequence[Mapping[str, Any]] = (),
    timeout_s: float = 3600,
    poll_s: float = 5,
    client: httpx.Client | None = None,
    sleep: Callable[[float], None] = time.sleep,
    log: Callable[[str], None] = print,
) -> dict[str, Any]:
    targets = load_targets()
    if target_name not in targets:
        raise HarnessError(f"unknown target {target_name!r}; known: {', '.join(sorted(targets))}")
    target = targets[target_name]
    truth = ground_truth.load(HERE / target["truth"])
    http = client or httpx.Client(base_url=backend, headers={"Authorization": f"Bearer {token}"}, timeout=60)
    try:
        if not project_id:
            created = http.post("/projects", json={"name": f"harness-{target_name}", "default_git_url": ""})
            created.raise_for_status()
            project_id = created.json()["id"]
        started = time.monotonic()
        response = http.post("/scans", json=scan_payload(project_id, target, truth, identities))
        if response.status_code >= 400:
            raise HarnessError(f"the backend refused the scan ({response.status_code}): {response.text[:300]}")
        scan_id = response.json()["scan_id"]
        log(f"scan {scan_id} started against {target['target_url']}")
        while True:
            status = http.get(f"/scans/{scan_id}/status").json()
            if status["status"] in TERMINAL:
                break
            if time.monotonic() - started > timeout_s:
                http.post(f"/scans/{scan_id}/cancel")
                raise HarnessError(f"scan {scan_id} did not finish within {timeout_s:.0f}s and was cancelled")
            log(f"  {status['status']} {status.get('progress', 0)}%")
            sleep(poll_s)
        duration = time.monotonic() - started
        if status["status"] != "success":
            raise HarnessError(f"scan {scan_id} ended {status['status']}: {status.get('message') or 'no reason given'}")
        findings = http.get(f"/scans/{scan_id}/findings").json()
        results = http.get(f"/scans/{scan_id}/results").json()
        summary = http.get(f"/scans/{scan_id}/summary").json()
    finally:
        if client is None:
            http.close()
    discovery = results.get("discovery") or {}
    have = {"schema"} if discovery.get("inventory_diff", {}).get("compared") or (discovery.get("fingerprint") or {}).get("schema") not in (None, "none") else set()
    have |= {"second_identity"} if len([i for i in discovery.get("identities") or [] if i.get("status") == "authenticated"]) >= 2 else set()
    effective = (results.get("dast_effective") or {})
    if effective.get("allow_state_changing"):
        have.add("state_changing")
    if effective.get("oast_configured"):
        have.add("oast")
    if effective.get("browser_probe_enabled", True):
        have.add("browser_probe")
    if effective.get("browser_marker_posts"):
        have.add("browser_marker_posts")
    scored = score(findings_from_api(findings), truth, available=have)
    return build_result(
        scored, truth, scan_id=scan_id, duration_s=duration, cost_usd=float(summary.get("model_cost_usd") or 0), override_rate=guardrail_override_rate(discovery),
        pack_ids=effective.get("rule_packs") or truth.rule_packs,
    )


def write_result(result: Mapping[str, Any], out_dir: str | Path) -> tuple[Path, Path]:
    """Write `<target>-<UTC timestamp>.json`, a `<target>-latest.json` copy and a readable summary."""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    stamped = out / f"{result['target']}-{stamp}.json"
    text = json.dumps(result, indent=2, sort_keys=True) + "\n"
    stamped.write_text(text, encoding="utf-8")
    (out / f"{result['target']}-latest.json").write_text(text, encoding="utf-8")
    summary = out / f"{result['target']}-{stamp}.txt"
    summary.write_text(summary_text(result) + "\n", encoding="utf-8")
    return stamped, summary
