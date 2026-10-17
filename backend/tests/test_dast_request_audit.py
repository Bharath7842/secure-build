"""DAST-01-050: audit persistence and `GET /scans/{id}/requests` (DB, fake target)."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

from app import db as app_db
from app.config import settings
from app.dast.domain.policy import MethodPolicy, Scope
from app.dast.domain.interfaces import RequestSpec
from app.main import app
from app.models import DastRequestAudit
from app.services.guarded_executor import GuardedExecutor
from app.services.request_audit import AuditRecord, DbAuditWriter
from app.services.safety_guard import SafetyGuard

pytestmark = pytest.mark.integration

from tests.auth_helpers import ADMIN_HEADERS  # noqa: E402

HDR = ADMIN_HEADERS
BASE = "http://target.test"
PASSWORD = "s3cr3t-pw-value"


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("USE_MOCK_ENGINE", "true")
    settings.use_mock_engine = True
    settings.scan_logs_dir = str(tmp_path / "scan_logs")
    app_db.init_db(f"sqlite:///{(tmp_path / 'test.db').as_posix()}")
    return TestClient(app)


@pytest.fixture()
def scan_id(client):
    project = client.post("/projects", json={"name": "audit", "default_git_url": "https://github.com/org/repo.git"}, headers=HDR)
    payload = {
        "project_id": project.json()["id"],
        "scan_type": "dast",
        "dast": {"target_url": "http://localhost:3000", "authorized": True},
    }
    resp = client.post("/scans", headers=HDR, json=payload)
    assert resp.status_code == 202
    return resp.json()["scan_id"]


def run_traffic(scan_id: str, fake_target, **writer_kwargs) -> DbAuditWriter:
    """3 allowed requests and 2 denied ones through the real guard + executor + DB writer."""
    fake_target.add_page("/", "home")
    fake_target.add_page("/a", "a")
    fake_target.add_page("/b", "b")
    writer = DbAuditWriter(scan_id, **writer_kwargs)
    guard = SafetyGuard(Scope.for_target(BASE), MethodPolicy(), rate_limit_per_sec=100_000.0, max_concurrent=2)
    with GuardedExecutor(guard, writer, transport=fake_target.transport, secrets=lambda: [PASSWORD]) as executor:
        executor.execute(RequestSpec("GET", f"{BASE}/", identity_label="admin"))
        executor.execute(RequestSpec("GET", "http://evil.test/x", identity_label="admin"))
        executor.execute(RequestSpec("GET", f"{BASE}/a?token=abc123&q={PASSWORD}", headers={"Authorization": f"Bearer {PASSWORD}"}))
        executor.execute(RequestSpec("POST", f"{BASE}/b", body={"password": PASSWORD}))
        executor.execute(RequestSpec("GET", f"{BASE}/b"))
    return writer


def get_page(client, scan_id: str, **params):
    resp = client.get(f"/scans/{scan_id}/requests", headers=HDR, params=params)
    assert resp.status_code == 200, resp.text
    return resp.json()


def test_counts_match_requests_issued_and_denied_requests_are_present(client, scan_id, fake_target):
    run_traffic(scan_id, fake_target)
    page = get_page(client, scan_id)

    assert page["scan_id"] == scan_id and page["next_after"] is None
    assert [e["seq"] for e in page["entries"]] == [1, 2, 3, 4, 5]
    assert [e["allowed"] for e in page["entries"]] == [True, False, True, False, True]
    assert len(fake_target.requests) == 3  # exactly the allowed ones reached the target
    denied = [e for e in page["entries"] if not e["allowed"]]
    assert [(e["method"], e["deny_reason"]) for e in denied] == [("GET", "off_scope"), ("POST", "method_not_permitted")]
    assert page["entries"][0]["identity_label"] == "admin" and page["entries"][0]["response_status"] == 200


def test_allowed_denied_filter(client, scan_id, fake_target):
    run_traffic(scan_id, fake_target)
    assert [e["seq"] for e in get_page(client, scan_id, allowed="true")["entries"]] == [1, 3, 5]
    assert [e["seq"] for e in get_page(client, scan_id, allowed="false")["entries"]] == [2, 4]


def test_pagination_by_sequence_is_stable(client, scan_id, fake_target):
    run_traffic(scan_id, fake_target)
    first = get_page(client, scan_id, limit=2)
    assert [e["seq"] for e in first["entries"]] == [1, 2] and first["next_after"] == 2
    second = get_page(client, scan_id, limit=2, after=first["next_after"])
    assert [e["seq"] for e in second["entries"]] == [3, 4] and second["next_after"] == 4
    last = get_page(client, scan_id, limit=2, after=second["next_after"])
    assert [e["seq"] for e in last["entries"]] == [5] and last["next_after"] is None
    # Reading again returns the same rows; later rows never shift earlier pages.
    assert get_page(client, scan_id, limit=2)["entries"] == first["entries"]
    # Filtered pagination walks the same cursor.
    f1 = get_page(client, scan_id, limit=2, allowed="true")
    assert [e["seq"] for e in f1["entries"]] == [1, 3] and f1["next_after"] == 3
    assert [e["seq"] for e in get_page(client, scan_id, limit=2, allowed="true", after=3)["entries"]] == [5]


def test_no_secret_is_stored_in_any_column(client, scan_id, fake_target):
    run_traffic(scan_id, fake_target)
    with app_db.engine.connect() as conn:
        rows = conn.execute(text("SELECT * FROM dast_request_audit")).fetchall()
    assert len(rows) == 5
    stored = " ".join(repr(value) for row in rows for value in row)
    assert PASSWORD not in stored and "abc123" not in stored
    assert "[REDACTED]" in stored  # redaction happened, not omission of the whole row
    # And nothing secret comes back over the API either.
    assert PASSWORD not in str(get_page(client, scan_id))
    first_get = next(e for e in get_page(client, scan_id)["entries"] if e["seq"] == 3)
    assert first_get["request_headers"]["Authorization"] == "[REDACTED]"
    assert "token=[REDACTED]" in first_get["url"]


def test_requests_endpoint_requires_the_bearer_token(client, scan_id):
    assert client.get(f"/scans/{scan_id}/requests").status_code == 401
    assert client.get(f"/scans/{scan_id}/requests", headers={"Authorization": "Bearer wrong"}).status_code == 401


def test_unknown_scan_is_404_and_a_scan_without_traffic_is_empty(client, scan_id):
    assert client.get("/scans/nope/requests", headers=HDR).status_code == 404
    assert get_page(client, scan_id) == {"scan_id": scan_id, "entries": [], "next_after": None}


def test_bad_query_values_are_rejected(client, scan_id):
    for params in ({"limit": 0}, {"limit": 501}, {"after": -1}):
        assert client.get(f"/scans/{scan_id}/requests", headers=HDR, params=params).status_code == 422


# ---- writer behaviour -----------------------------------------------------------------------


def count_rows(scan_id: str) -> int:
    with app_db.SessionLocal() as session:
        return session.query(DastRequestAudit).filter(DastRequestAudit.scan_id == scan_id).count()


def record(n: int = 0) -> AuditRecord:
    return AuditRecord(method="GET", url=f"{BASE}/p{n}", allowed=True, response_status=200)


def test_rows_are_written_in_batches_not_per_request(client, scan_id):
    now = {"t": 0.0}
    writer = DbAuditWriter(scan_id, batch_size=3, flush_interval_s=10.0, clock=lambda: now["t"])
    writer.record(record(1))
    writer.record(record(2))
    assert count_rows(scan_id) == 0  # still buffered
    writer.record(record(3))
    assert count_rows(scan_id) == 3  # batch full -> one write
    writer.record(record(4))
    assert count_rows(scan_id) == 3
    now["t"] = 11.0  # the flush interval elapsed: rows become visible mid-scan even if the batch is not full
    writer.record(record(5))
    assert count_rows(scan_id) == 5


def test_rows_survive_a_scan_that_fails_or_is_cancelled(client, scan_id, fake_target):
    fake_target.add_page("/", "x")
    writer = DbAuditWriter(scan_id, batch_size=100)
    guard = SafetyGuard(Scope.for_target(BASE), MethodPolicy(), rate_limit_per_sec=100_000.0, max_concurrent=1)
    with pytest.raises(RuntimeError):
        with GuardedExecutor(guard, writer, transport=fake_target.transport) as executor:
            executor.execute(RequestSpec("GET", f"{BASE}/"))
            executor.execute(RequestSpec("GET", "http://evil.test/"))
            raise RuntimeError("scan blew up mid-flight")
    assert count_rows(scan_id) == 2  # flushed by the executor's close despite the failure


def test_a_new_writer_continues_the_sequence(client, scan_id):
    first = DbAuditWriter(scan_id)
    first.record(record(1))
    first.record(record(2))
    first.flush()
    second = DbAuditWriter(scan_id)
    assert second.record(record(3)) == 3
    second.flush()
    assert [e["seq"] for e in get_page(client, scan_id)["entries"]] == [1, 2, 3]


def test_a_failed_flush_keeps_rows_for_retry_and_never_raises(client, scan_id):
    calls = {"n": 0}

    def flaky_session():
        calls["n"] += 1
        if calls["n"] == 2:  # 1 = sequence lookup, 2 = first flush
            raise RuntimeError("db unavailable")
        return app_db.SessionLocal()

    writer = DbAuditWriter(scan_id, batch_size=1, session_factory=flaky_session)
    writer.record(record(1))  # flush fails here; must not raise
    assert count_rows(scan_id) == 0
    writer.flush()  # retry succeeds
    assert count_rows(scan_id) == 1


def test_oversized_values_are_clipped_to_the_column(client, scan_id):
    writer = DbAuditWriter(scan_id)
    writer.record(AuditRecord(method="GET", url="http://target.test/" + "x" * 5000, allowed=True, identity_label="i" * 500))
    writer.flush()
    entry = get_page(client, scan_id)["entries"][0]
    assert len(entry["url"]) == 2000 and len(entry["identity_label"]) == 120
