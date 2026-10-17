"""DAST-03-040 / -050: rule-set endpoints, snapshots and custom rules (API + DB, offline)."""

from __future__ import annotations

import pytest
import yaml
from fastapi.testclient import TestClient

from app import db as app_db
from app.config import settings
from app.main import app
from app.models import DastCustomRule, Scan
from app.services import dast_rules
from app.dast.domain.ruleset import ScanInputs, evaluate_dependencies

pytestmark = pytest.mark.integration

from tests.auth_helpers import ADMIN_HEADERS  # noqa: E402

HDR = ADMIN_HEADERS


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("USE_MOCK_ENGINE", "true")
    settings.use_mock_engine = True
    settings.scan_logs_dir = str(tmp_path / "scan_logs")
    app_db.init_db(f"sqlite:///{(tmp_path / 'rules.db').as_posix()}")
    return TestClient(app)


@pytest.fixture()
def project_id(client):
    return client.post("/projects", json={"name": "rules", "default_git_url": ""}, headers=HDR).json()["id"]


RULE = {
    "id": "dast-custom-reflect", "title": "Custom reflection", "owasp": ["A03:2021"], "cwe": ["CWE-79"],
    "location": "query", "signal": ["input_reflected_unescaped"], "severity": "MEDIUM", "mode": "automated",
}


def test_catalog_endpoint_lists_checks_and_packs(client):
    body = client.get("/dast/catalog", headers=HDR).json()
    assert {p["id"] for p in body["packs"]} >= {"owasp-api-top10-2023", "owasp-web-top10", "wstg-full", "passive-only"}
    sqli = next(c for c in body["checks"] if c["id"] == "dast-sqli")
    assert sqli["severity"] == "HIGH" and "OWASP" not in sqli["standards"]["owasp"][0]
    assert body["catalog_version"]


def test_endpoints_require_the_bearer_token(client):
    assert client.get("/dast/catalog").status_code in (401, 403)
    assert client.patch("/dast/rules", json={}).status_code in (401, 403)


def test_global_config_persists_and_patches_merge(client):
    assert client.get("/dast/rules", headers=HDR).json()["config"] == {"packs": {}, "checks": {}}
    r = client.patch("/dast/rules", json={"packs": {"wstg-full": True}, "checks": {"dast-sqli": {"severity": "LOW"}}}, headers=HDR)
    assert r.status_code == 200
    r = client.patch("/dast/rules", json={"checks": {"dast-sqli": {"mode": "opt-in"}}}, headers=HDR)
    assert r.json()["config"] == {"packs": {"wstg-full": True}, "checks": {"dast-sqli": {"severity": "LOW", "mode": "opt-in"}}}
    assert client.get("/dast/rules", headers=HDR).json()["config"] == r.json()["config"]


@pytest.mark.parametrize("body", [{"packs": {"nope": True}}, {"checks": {"dast-nope": {"enabled": True}}}, {"checks": {"dast-sqli": {"severity": "x"}}}])
def test_invalid_patch_is_rejected(client, body):
    assert client.patch("/dast/rules", json=body, headers=HDR).status_code == 422


def test_project_config_overrides_global_and_can_be_reset(client, project_id):
    client.patch("/dast/rules", json={"checks": {"dast-sqli": {"severity": "LOW"}}}, headers=HDR)
    assert client.get(f"/projects/{project_id}/dast-rules", headers=HDR).json()["inherits_global"] is True
    client.patch(f"/projects/{project_id}/dast-rules", json={"checks": {"dast-sqli": {"severity": "CRITICAL"}}}, headers=HDR)

    def sqli_severity(project=None):
        params = {"project_id": project} if project else {}
        rs = client.get("/dast/rules/effective", params=params, headers=HDR).json()["rule_set"]
        return next(c for c in rs["checks"] if c["id"] == "dast-sqli")["severity"]

    assert sqli_severity() == "LOW" and sqli_severity(project_id) == "CRITICAL"
    assert client.delete(f"/projects/{project_id}/dast-rules", headers=HDR).status_code == 204
    assert sqli_severity(project_id) == "LOW"
    assert client.get("/projects/nope/dast-rules", headers=HDR).status_code == 404


def test_project_without_stored_config_resolves_to_defaults(client, project_id):
    rs = client.get("/dast/rules/effective", params={"project_id": project_id}, headers=HDR).json()["rule_set"]
    assert rs["packs"] == ["owasp-api-top10-2023", "owasp-web-top10"]
    api4 = next(c for c in rs["checks"] if c["id"] == "dast-resource-consumption")
    assert api4["enabled"] is False


def test_effective_preview_reports_skipped_and_degraded(client):
    body = client.get("/dast/rules/effective", params={"second_identity": False, "oast": False}, headers=HDR).json()
    by_id = {e["check_id"]: e for e in body["skipped_degraded"]}
    assert by_id["dast-bola"]["status"] == "degraded" and by_id["dast-ssrf"]["effective_mode"] == "assist-only"


# ---- custom rules -----------------------------------------------------------------------------


def post_rule(client, **over):
    return client.post("/dast/custom-rules", json={"yaml": yaml.safe_dump({**RULE, **over})}, headers=HDR)


def test_custom_rule_lifecycle_and_versioning(client):
    created = post_rule(client)
    assert created.status_code == 201 and created.json()["version"] == 1
    assert client.get("/dast/custom-rules", headers=HDR).json()["rules"][0]["check_id"] == "dast-custom-reflect"
    updated = client.put("/dast/custom-rules/dast-custom-reflect", json={"yaml": yaml.safe_dump({**RULE, "severity": "HIGH"})}, headers=HDR)
    assert updated.json()["version"] == 2 and updated.json()["definition"]["severity"] == "HIGH"
    assert client.delete("/dast/custom-rules/dast-custom-reflect", headers=HDR).status_code == 204
    assert client.get("/dast/custom-rules/dast-custom-reflect", headers=HDR).status_code == 404
    assert client.delete("/dast/custom-rules/dast-custom-reflect", headers=HDR).status_code == 404
    assert client.put("/dast/custom-rules/gone", json={"yaml": yaml.safe_dump(RULE)}, headers=HDR).status_code == 404


@pytest.mark.parametrize(
    "over, expected",
    [
        ({"id": "dast-sqli"}, "already used"),
        ({"id": "dast-authz"}, "already used"),
        ({"signal": ["made_up_signal"]}, "unknown detector signal"),
        ({"payload": "' OR 1=1"}, "fixed payload"),
        ({"owasp": [], "cwe": []}, "standard tag"),
        ({"mode": "whenever"}, "mode"),
        ({"id": "not-prefixed"}, "must start with"),
    ],
)
def test_custom_rule_rejections(client, over, expected):
    r = post_rule(client, **over)
    assert r.status_code == 422
    assert any(expected in e for e in r.json()["detail"]["errors"]), r.json()


def test_duplicate_custom_id_rejected_and_id_cannot_change(client):
    assert post_rule(client).status_code == 201
    assert post_rule(client).status_code == 422
    r = client.put("/dast/custom-rules/dast-custom-reflect", json={"yaml": yaml.safe_dump({**RULE, "id": "dast-renamed"})}, headers=HDR)
    assert r.status_code == 422 and "cannot change" in r.json()["detail"]["errors"][0]


def test_rule_with_no_signal_is_accepted_as_assist_only_and_says_so(client):
    r = post_rule(client, id="dast-custom-review", signal=[])
    assert r.status_code == 201
    assert r.json()["definition"]["mode"] == "assist-only" and "assist-only" in r.json()["notes"][0]


def test_custom_rule_joins_the_effective_rule_set_and_the_snapshot(client, project_id):
    post_rule(client)
    rs = client.get("/dast/rules/effective", headers=HDR).json()["rule_set"]
    custom = next(c for c in rs["checks"] if c["id"] == "dast-custom-reflect")
    assert custom["enabled"] and custom["definition"]["source"] == "custom" and "custom-rules" in custom["packs"]
    assert rs["custom_rules"] == [{"id": "dast-custom-reflect", "version": 1}]
    assert "custom-rules" in rs["packs"]


def test_deleting_a_custom_rule_does_not_alter_a_stored_snapshot(client, project_id):
    post_rule(client)
    with app_db.SessionLocal() as db:
        project = db.get(__import__("app.models", fromlist=["Project"]).Project, project_id)
        resolved = dast_rules.resolve_for_scan(db, project, None, ScanInputs(has_second_identity=True, oast_configured=True))
        snapshot = resolved.snapshot
    client.delete("/dast/custom-rules/dast-custom-reflect", headers=HDR)
    assert any(c["id"] == "dast-custom-reflect" for c in snapshot["checks"])  # the snapshot is a plain dict, untouched
    from app.dast.domain.ruleset import effective_from_dict

    assert effective_from_dict(snapshot).get("dast-custom-reflect").check.source == "custom"
    with app_db.SessionLocal() as db:
        again = dast_rules.resolve_for_scan(db, project_id and db.get(__import__("app.models", fromlist=["Project"]).Project, project_id), None, ScanInputs())
        assert not any(c["id"] == "dast-custom-reflect" for c in again.snapshot["checks"])


def test_a_custom_rule_that_stops_validating_is_skipped_and_reported(client):
    post_rule(client)
    with app_db.SessionLocal() as db:
        row = db.query(DastCustomRule).one()
        row.yaml_text = yaml.safe_dump({**RULE, "signal": ["detector_that_was_removed"]})
        db.commit()
    overview = client.get("/dast/catalog", headers=HDR).json()
    assert [r["check_id"] for r in overview["invalid_custom_rules"]] == ["dast-custom-reflect"]
    assert not any(c["id"] == "dast-custom-reflect" for c in overview["checks"])
