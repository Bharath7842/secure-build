import pytest
from fastapi.testclient import TestClient

from app.config import settings
from app.db import init_db
from app.main import app

from tests.auth_helpers import ADMIN_HEADERS, make_user  # noqa: E402

HDR = ADMIN_HEADERS


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("USE_MOCK_ENGINE", "true")
    settings.use_mock_engine = True
    settings.scan_logs_dir = str(tmp_path / "scan_logs")
    init_db(f"sqlite:///{(tmp_path / 'test.db').as_posix()}")
    return TestClient(app)


@pytest.fixture()
def project_id(client):
    resp = client.post(
        "/projects",
        json={"name": "scan-target", "default_git_url": "https://github.com/org/repo.git"},
        headers=HDR,
    )
    assert resp.status_code == 201
    return resp.json()["id"]


@pytest.fixture()
def scan(client, project_id, monkeypatch):
    """A scan with: a TP SQLi, a group of 3 identical regex hits, an LLM FP and an unverified hit."""
    from app.db import SessionLocal
    from app.models import Finding
    from app.services import scan_runner

    monkeypatch.setattr(scan_runner, "execute_scan", lambda scan_id: None)
    scan_id = client.post("/scans", headers=HDR, json={"project_id": project_id, "commit_sha": "fb"}).json()["scan_id"]
    db = SessionLocal()
    try:
        rows = {
            "sqli": Finding(scan_id=scan_id, severity="HIGH", title="SQL injection", cwe="CWE-89", rule_id="sqli",
                            file_path="src/A.java", line=10, verdict="true_positive", confidence=0.9,
                            verdict_reason="user input reaches the query", ai_fix="use a prepared statement",
                            kind="llm", owasp_category="A03:2021-Injection"),
            "fp": Finding(scan_id=scan_id, severity="MEDIUM", title="Weak hash", cwe="CWE-328", rule_id="weak-hash",
                          file_path="src/B.java", line=20, verdict="false_positive", confidence=0.1,
                          verdict_reason="checksum only", kind="llm"),
            "unv": Finding(scan_id=scan_id, severity="LOW", title="Serializable", cwe="CWE-502", rule_id="svuid",
                           group_by_rule=True, file_path="src/C.java", line=1, verdict="unverified", kind="regex"),
        }
        for i in range(3):
            rows[f"rx{i}"] = Finding(scan_id=scan_id, severity="MEDIUM", title="Hardcoded secret", cwe="CWE-798",
                                     rule_id="secret", matched_text='password = "x"', file_path=f"src/D{i}.java",
                                     line=5, verdict="unverified", kind="regex")
        db.add_all(rows.values())
        db.commit()
        ids = {k: v.id for k, v in rows.items()}
    finally:
        db.close()
    return scan_id, ids


def _finish(scan_id):
    from app.db import SessionLocal
    from app.models import Scan

    db = SessionLocal()
    try:
        db.get(Scan, scan_id).status = "success"
        db.commit()
    finally:
        db.close()


def _review(client, scan_id, finding_id, reviewer="alice", **body):
    """Review as the signed-in user `<reviewer>@test.local`; that user, not a
    name in the body, is what gets recorded."""
    headers = make_user(f"{reviewer}@test.local", role="admin")[1]
    return client.post(f"/scans/{scan_id}/findings/{finding_id}/review", headers=headers, json=body)


def _findings(client, scan_id, **params):
    return client.get(f"/scans/{scan_id}/findings", headers=HDR, params=params).json()


def test_override_requires_reason_and_is_recorded(client, scan):
    scan_id, ids = scan
    resp = _review(client, scan_id, ids["sqli"], decision="false_positive")
    assert resp.status_code == 422 and "reason" in resp.json()["detail"]

    resp = _review(client, scan_id, ids["sqli"], decision="false_positive", comment="Input is validated upstream")
    assert resp.status_code == 200
    body = resp.json()
    assert body["is_override"] is True
    assert body["llm_verdict"] == "true_positive"
    assert body["reviewer_verdict"] == "false_positive"
    assert body["is_closed"] is True and body["issue_status"] == "closed_false_positive"
    assert body["learning_status"] == "pending_learning"
    assert body["reviewed_at"] is not None


def test_agreeing_with_llm_needs_no_comment_but_is_not_closed(client, scan):
    scan_id, ids = scan
    body = _review(client, scan_id, ids["sqli"], decision="confirmed_issue").json()
    assert body["is_override"] is False
    assert body["is_closed"] is False and body["issue_status"] == "open"


def test_the_signed_in_user_is_the_reviewer_whatever_the_body_says(client, scan):
    scan_id, ids = scan
    headers = make_user("carol@test.local", role="admin")[1]
    r = client.post(f"/scans/{scan_id}/findings/{ids['sqli']}/review", headers=headers,
                    json={"decision": "confirmed_issue", "reviewer": "mallory"})
    assert r.status_code == 200, r.text
    assert r.json()["reviewer"] == "carol@test.local"


def test_original_llm_result_is_preserved(client, scan):
    from app.db import SessionLocal
    from app.models import Finding

    scan_id, ids = scan
    _review(client, scan_id, ids["sqli"], decision="false_positive", comment="not reachable")
    db = SessionLocal()
    try:
        row = db.get(Finding, ids["sqli"])
        assert row.verdict == "true_positive"
        assert row.verdict_reason == "user input reaches the query"
    finally:
        db.close()
    review = client.get(f"/scans/{scan_id}/findings/{ids['sqli']}/review", headers=HDR).json()
    assert review["llm_verdict"] == "true_positive"
    assert review["llm_explanation"] == "user input reaches the query"
    assert review["llm_remediation"] == "use a prepared statement"
    assert review["confidence"] == 0.9 and review["cwe"] == "CWE-89" and review["line"] == 10


def test_history_records_every_change(client, scan):
    scan_id, ids = scan
    _review(client, scan_id, ids["sqli"], decision="needs_more_info", comment="Need the threat model")
    _review(client, scan_id, ids["sqli"], decision="confirmed_issue")
    _review(client, scan_id, ids["sqli"], decision="false_positive", comment="Mitigated by WAF")
    events = client.get(f"/scans/{scan_id}/findings/{ids['sqli']}/review", headers=HDR).json()["events"]
    assert [(e["action"], e["from_verdict"], e["to_verdict"]) for e in events] == [
        ("verdict_set", None, "needs_more_info"),
        ("verdict_changed", "needs_more_info", "confirmed_issue"),
        ("verdict_changed", "confirmed_issue", "false_positive"),
    ]
    assert events[2]["comment"] == "Mitigated by WAF"


def test_needs_more_info_is_not_closed_and_not_learnable(client, scan):
    scan_id, ids = scan
    body = _review(client, scan_id, ids["sqli"], decision="needs_more_info", comment="unclear").json()
    assert body["is_closed"] is False and body["issue_status"] == "needs_info"
    assert body["learning_status"] is None
    assert body["review_status"] == "needs_info"


def test_resolve_and_accept_risk_need_confirmation_and_notes(client, scan):
    scan_id, ids = scan
    assert _review(client, scan_id, ids["sqli"], decision="resolved", resolution_notes="fixed").status_code == 409
    _review(client, scan_id, ids["sqli"], decision="confirmed_issue")
    assert _review(client, scan_id, ids["sqli"], decision="resolved").status_code == 422
    assert _review(client, scan_id, ids["sqli"], decision="accept_risk").status_code == 422

    body = _review(client, scan_id, ids["sqli"], decision="resolved", resolution_notes="Parameterised in #123").json()
    assert body["is_closed"] is True and body["issue_status"] == "resolved"
    assert body["resolution_notes"] == "Parameterised in #123" and body["resolved_by"] == "alice@test.local"
    assert body["resolved_at"] is not None


def test_risk_acceptance_closes(client, scan):
    scan_id, ids = scan
    _review(client, scan_id, ids["sqli"], decision="confirmed_issue")
    body = _review(client, scan_id, ids["sqli"], decision="accept_risk", comment="Internal tool, owner signed off").json()
    assert body["is_closed"] is True and body["issue_status"] == "risk_accepted"


def test_changing_verdict_after_resolution_reopens(client, scan):
    scan_id, ids = scan
    _review(client, scan_id, ids["sqli"], decision="confirmed_issue")
    _review(client, scan_id, ids["sqli"], decision="resolved", resolution_notes="fixed")
    body = _review(client, scan_id, ids["sqli"], decision="needs_more_info", comment="Regression suspected").json()
    assert body["is_closed"] is False and body["resolution_status"] == "open"
    assert body["resolution_notes"] is None
    actions = [e["action"] for e in body["events"]]
    assert "reopened" in actions and actions.index("reopened") < len(actions) - 1


def test_review_covers_the_whole_group(client, scan):
    scan_id, ids = scan
    # Review through a non-representative member: the three identical hits are one group.
    body = _review(client, scan_id, ids["rx2"], decision="false_positive", comment="test fixtures").json()
    assert body["occurrence_count"] == 3
    findings = _findings(client, scan_id)
    group = [f for f in findings["findings"] if f["rule_id"] == "secret"]
    assert len(group) == 1 and group[0]["occurrence_count"] == 3
    assert group[0]["verdict"] == "false_positive" and group[0]["llm_verdict"] == "unverified"
    assert group[0]["review"]["reviewer_verdict"] == "false_positive"
    # A second decision through another member updates the same review.
    again = _review(client, scan_id, ids["rx0"], decision="confirmed_issue", comment="real secret").json()
    assert again["review_id"] == body["review_id"]


def test_effective_verdict_drives_counts_and_filter(client, scan):
    scan_id, ids = scan
    before = _findings(client, scan_id)
    assert (before["tp_count"], before["fp_count"], before["unverified_count"]) == (1, 1, 4)

    _review(client, scan_id, ids["sqli"], decision="false_positive", comment="not exploitable")
    _review(client, scan_id, ids["unv"], decision="confirmed_issue", comment="serialised over the wire")
    after = _findings(client, scan_id)
    assert (after["tp_count"], after["fp_count"], after["unverified_count"]) == (1, 2, 3)
    assert after["severity_group_counts"]["dismissed"]["groups"] == 2

    only_fp = _findings(client, scan_id, verdict="false_positive")
    assert {f["rule_id"] for f in only_fp["findings"]} == {"sqli", "weak-hash"}
    # The scan's cached report follows the reviewer too.
    results = client.get(f"/scans/{scan_id}/results", headers=HDR).json()
    report = (results.get("discovery") or {}).get("report") or {}
    assert not report or report.get("fp_count") == 2


def test_gate_ignores_resolved_findings(client, scan):
    from app.db import SessionLocal
    from app.models import Scan
    from app.services.feedback import effective_scan_findings
    from app.services.gates import build_gate_summary

    scan_id, ids = scan
    db = SessionLocal()
    try:
        row = db.get(Scan, scan_id)
        project = row.project
        project.gate_max_high = 0
        assert build_gate_summary(project, effective_scan_findings(db, row))["gate_failed"] is True
    finally:
        db.close()
    _review(client, scan_id, ids["sqli"], decision="confirmed_issue")
    _review(client, scan_id, ids["sqli"], decision="resolved", resolution_notes="fixed")
    db = SessionLocal()
    try:
        row = db.get(Scan, scan_id)
        row.project.gate_max_high = 0
        assert build_gate_summary(row.project, effective_scan_findings(db, row))["gate_failed"] is False
    finally:
        db.close()


def test_feedback_list_filters(client, scan):
    scan_id, ids = scan
    _review(client, scan_id, ids["sqli"], decision="false_positive", comment="mitigated", reviewer="alice")
    _review(client, scan_id, ids["fp"], decision="confirmed_issue", comment="actually used for auth", reviewer="bob")
    _review(client, scan_id, ids["unv"], decision="needs_more_info", comment="who owns this?", reviewer="alice")

    def listing(**params):
        return client.get("/feedback", headers=HDR, params={"scan_id": scan_id, **params}).json()

    assert listing()["total"] == 4  # three reviewed groups + the unreviewed "secret" group
    assert listing(review_status="unreviewed")["total"] == 1
    assert listing(review_status="needs_info")["total"] == 1
    assert {r["rule_id"] for r in listing(reviewer_verdict="false_positive")["items"]} == {"sqli"}
    assert {r["rule_id"] for r in listing(llm_verdict="false_positive")["items"]} == {"weak-hash"}
    assert {r["rule_id"] for r in listing(override=True)["items"]} == {"sqli", "weak-hash"}
    assert listing(override=False)["total"] == 2
    assert {r["rule_id"] for r in listing(severity="high")["items"]} == {"sqli"}
    assert {r["rule_id"] for r in listing(rule_id="weak-hash")["items"]} == {"weak-hash"}
    assert {r["rule_id"] for r in listing(cwe="CWE-502")["items"]} == {"svuid"}
    assert {r["rule_id"] for r in listing(reviewer="bob@test.local")["items"]} == {"weak-hash"}
    assert {r["rule_id"] for r in listing(closed=True)["items"]} == {"sqli"}
    assert listing(resolution_status="resolved")["total"] == 0
    assert listing(learning_status="pending_learning")["total"] == 2
    assert listing(reviewed_from="2999-01-01")["total"] == 0
    assert listing(reviewed_to="2000-01-01")["total"] == 0
    assert listing(reviewed_from="2000-01-01", reviewed_to="2999-12-31", review_status="reviewed")["total"] == 2
    page = listing(limit=2, offset=0)
    assert len(page["items"]) == 2 and page["total"] == listing()["total"]
    assert client.get("/feedback", headers=HDR, params={"reviewed_from": "garbage"}).status_code == 422

    # Without a scan only reviewed items are listed.
    flat = client.get("/feedback", headers=HDR).json()
    assert flat["total"] == 3 and all(r["review_id"] for r in flat["items"])


def test_learning_lifecycle_and_export(client, scan):
    scan_id, ids = scan
    r1 = _review(client, scan_id, ids["sqli"], decision="false_positive", comment="mitigated").json()
    r2 = _review(client, scan_id, ids["fp"], decision="confirmed_issue", comment="used for auth").json()
    assert r1["learning_status"] == r2["learning_status"] == "pending_learning"

    # Processing needs approval first.
    skipped = client.post("/feedback/learning/mark-processed", headers=HDR,
                          json={"review_ids": [r1["review_id"]], "actor": "lead"}).json()
    assert skipped == {"updated": 0, "skipped": 1}

    approved = client.post("/feedback/learning/approve", headers=HDR,
                           json={"review_ids": [r1["review_id"]], "actor": "lead"}).json()
    assert approved == {"updated": 1, "skipped": 0}

    exp = client.get("/feedback/export", headers=HDR, params={"learning_status": "approved_for_learning"})
    assert exp.status_code == 200 and "attachment" in exp.headers["content-disposition"]
    lines = [__import__("json").loads(line) for line in exp.text.splitlines()]
    assert len(lines) == 1
    assert lines[0]["label"] == "false_positive" and lines[0]["llm_verdict"] == "true_positive"
    assert lines[0]["is_override"] is True and lines[0]["reviewer_comment"] == "mitigated"
    # Exporting alone changes nothing.
    assert client.get(f"/feedback/{r1['review_id']}", headers=HDR).json()["learning_status"] == "approved_for_learning"

    csv_text = client.get("/feedback/export", headers=HDR, params={"format": "csv"}).text
    assert csv_text.splitlines()[0].startswith("review_id,") and len(csv_text.splitlines()) == 3

    # The signed-in user is recorded as the actor; no name needs to be passed.
    client.get("/feedback/export", headers=HDR, params={"mark_processed": True})
    done = client.get(f"/feedback/{r1['review_id']}", headers=HDR).json()
    assert done["learning_status"] == "processed" and done["learning_processed_at"] is not None
    # The other item was never approved, so it stays pending.
    assert client.get(f"/feedback/{r2['review_id']}", headers=HDR).json()["learning_status"] == "pending_learning"


def test_changed_verdict_after_approval_goes_back_to_pending(client, scan):
    scan_id, ids = scan
    r = _review(client, scan_id, ids["sqli"], decision="false_positive", comment="mitigated").json()
    client.post("/feedback/learning/approve", headers=HDR, json={"review_ids": [r["review_id"]], "actor": "lead"})
    back = _review(client, scan_id, ids["sqli"], decision="confirmed_issue").json()
    assert back["learning_status"] == "pending_learning" and back["learning_approved_at"] is None
    assert "learning_reset" in [e["action"] for e in back["events"]]


def test_reviews_survive_verdict_writer_updates(client, scan):
    from app.db import SessionLocal
    from app.models import Finding

    scan_id, ids = scan
    _review(client, scan_id, ids["unv"], decision="false_positive", comment="never serialised")
    # The engine's reconcile/verdict writers UPDATE findings in place, as this does.
    db = SessionLocal()
    try:
        db.query(Finding).filter(Finding.id == ids["unv"]).update({"verdict": "true_positive", "confidence": 0.8})
        db.commit()
    finally:
        db.close()
    group = [f for f in _findings(client, scan_id)["findings"] if f["rule_id"] == "svuid"][0]
    assert group["verdict"] == "false_positive" and group["llm_verdict"] == "true_positive"
    assert group["review"]["reviewer_verdict"] == "false_positive"


def test_reviews_survive_scan_deletion_but_not_project_deletion(client, project_id, scan):
    scan_id, ids = scan
    r = _review(client, scan_id, ids["sqli"], decision="false_positive", comment="mitigated").json()
    _finish(scan_id)
    assert client.delete(f"/scans/{scan_id}", headers=HDR).status_code in (200, 204)
    kept = client.get(f"/feedback/{r['review_id']}", headers=HDR)
    assert kept.status_code == 200 and kept.json()["llm_verdict"] == "true_positive"
    assert client.delete(f"/projects/{project_id}", headers=HDR).status_code == 200
    assert client.get(f"/feedback/{r['review_id']}", headers=HDR).status_code == 404


def test_unknown_finding_and_unreviewed_lookup(client, scan):
    scan_id, ids = scan
    assert _review(client, scan_id, "nope", decision="confirmed_issue").status_code == 404
    assert client.get(f"/scans/{scan_id}/findings/{ids['sqli']}/review", headers=HDR).status_code == 404
    assert client.post(f"/scans/{scan_id}/findings/{ids['sqli']}/review",
                       json={"decision": "confirmed_issue", "reviewer": "a"}).status_code in (401, 403)


def test_exports_use_effective_verdict(client, scan, monkeypatch):
    import json

    scan_id, ids = scan
    _finish(scan_id)
    _review(client, scan_id, ids["sqli"], decision="false_positive", comment="mitigated")
    sarif = client.get(f"/scans/{scan_id}/export.sarif", headers=HDR)
    assert sarif.status_code == 200
    verdicts = {r["ruleId"]: r["properties"]["verdict"] for r in json.loads(sarif.text)["runs"][0]["results"]}
    assert verdicts["sqli"] == "false_positive"


def test_a_review_of_an_old_group_is_still_found_after_the_group_key_changes(client, scan):
    """Group keys now end in a semantic signature, so a rescan's fingerprints differ
    from an old review's. Reviews are located through the member ids stored with
    them, so an existing review keeps covering its rows (SAST-01-060)."""
    from app.db import SessionLocal
    from app.models import Finding
    from app.services import feedback

    scan_id, ids = scan
    body = _review(client, scan_id, ids["rx0"], decision="false_positive", comment="fixtures").json()
    assert body["occurrence_count"] == 3
    db = SessionLocal()
    try:
        for key in ("rx0", "rx1", "rx2"):
            row = db.get(Finding, ids[key])
            # Resolved facts arrive for these rows after the review was taken.
            row.facts = {"call": {"callee": "x", "arity": 0, "owner_fqn": "a.B", "receiver_fqn": "a.B"}, "args": []}
        db.commit()
        for key in ("rx0", "rx1", "rx2"):
            assert feedback.find_review(db, scan_id, ids[key]) is not None
    finally:
        db.close()
    group = [f for f in _findings(client, scan_id)["findings"] if f["rule_id"] == "secret"]
    assert len(group) == 1 and group[0]["review"]["reviewer_verdict"] == "false_positive"
