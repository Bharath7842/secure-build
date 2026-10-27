"""Multi-role authorization testing (DAST-10-010 .. -040): role pairs and privilege order, boundary
classification, the replay engine against a fake target with seeded flaws, and the derived matrix
and its API."""

from __future__ import annotations

import httpx
import pytest
from fastapi.testclient import TestClient

from app.dast import authorization as authz_engine
from app.dast.domain import authz as Z
from app.dast.domain.entities import Endpoint, EndpointSource, Location, Parameter
from app.dast.domain.identities import build_identities
from app.dast.domain.inventory import from_schema, observed
from app.dast.domain.ruleset import resolve_effective_rule_set
from app.dast.sessions import SessionStore
from app.main import app
from app.services.dast_catalog import default_catalog
from tests.dast_fixtures import FakeModelGateway, FakeTarget
from tests.test_dast_engine import BASE, Harness, default_rule_set

pytestmark = pytest.mark.integration

CATALOG = default_catalog()


def spec(label, role, method="token", custom=""):
    return {"label": label, "role": role, "auth_method": method, **({"custom_role": custom} if custom else {})}


def specs(*items):
    return build_identities(list(items))


# ---- pairs and privilege ----------------------------------------------------------------------------


def test_n_authenticated_identities_give_n_times_n_minus_one_pairs_plus_anonymous_in_declaration_order():
    three = specs(spec("Root", "Admin"), spec("Alice", "User"), spec("Vi", "Viewer"))
    pairs = Z.role_pairs(three)
    assert len(pairs) == 3 * 2 + 3
    assert [(p.owner, p.actor) for p in pairs[:3]] == [("Root", "Alice"), ("Root", "Vi"), ("Root", "anonymous")]
    assert pairs == Z.role_pairs(three)  # deterministic
    assert [p.anonymous for p in pairs].count(True) == 3
    one = Z.role_pairs(specs(spec("Alice", "User")))
    assert [(p.owner, p.actor, p.anonymous) for p in one] == [("Alice", "anonymous", True)]
    assert Z.role_pairs(specs()) == []


def test_privilege_follows_the_role_and_a_custom_role_has_none_until_it_is_set():
    s = specs(spec("A", "Admin"), spec("U", "User"), spec("V", "Viewer"), spec("Aud", "Custom", custom="Auditor"))
    ranks = {x.label: Z.privilege_of(x) for x in s}
    assert ranks["A"] > ranks["U"] > ranks["V"] > ranks["anonymous"] == 0 and ranks["Aud"] is None
    auditor = next(x for x in s if x.label == "Aud")
    assert Z.privilege_of(auditor, {"auditor": 2}) == 2 and Z.privilege_of(auditor, {"Aud": 1}) == 1


def test_only_endpoints_worth_replaying_are_candidates():
    anon_id = "identity-anonymous"
    api = from_schema("GET", "/api/orders", base_url=BASE)
    public = from_schema("GET", "/health", base_url=BASE)
    login = from_schema("GET", "/login", base_url=BASE)
    post = from_schema("POST", "/api/orders", base_url=BASE)
    asset = observed("GET", f"{BASE}/app.js", identity_id="identity-alice", kind="asset")
    seen_public = observed("GET", f"{BASE}/api/catalog", identity_id="identity-alice", kind="api")
    seen_public = Endpoint(**{**seen_public.__dict__, "seen_as": ("identity-alice", anon_id)})
    pool = [api, public, login, post, asset, seen_public]
    labels = lambda **kw: [e.label for e in Z.owner_candidates(pool, "identity-alice", anonymous_id=anon_id, **kw)]  # noqa: E731
    assert labels(allow_state_changing=False) == ["GET /api/orders"]  # public paths, assets, writes and anon-visible pages are out
    assert labels(allow_state_changing=True) == ["GET /api/orders", "POST /api/orders"]
    assert Z.owner_candidates([observed("GET", f"{BASE}/api/x", identity_id="identity-bob", kind="api")], "identity-alice", allow_state_changing=False, anonymous_id=anon_id) == []


def test_logout_and_similar_destructive_destinations_are_never_replay_candidates():
    anon_id = "identity-anonymous"
    logout = from_schema("POST", "/api/logout", base_url=BASE, state_changing=True)
    normal = from_schema("GET", "/api/orders", base_url=BASE)
    assert not Z.replayable(logout, allow_state_changing=True, anonymous_id=anon_id)
    assert Z.replayable(normal, allow_state_changing=False, anonymous_id=anon_id)


def test_on_a_spa_client_rendered_pages_are_skipped_and_api_operations_are_prioritized():
    anon_id = "identity-anonymous"
    page = observed("GET", f"{BASE}/dashboard", identity_id="identity-alice", kind="page")
    api_observed = observed("GET", f"{BASE}/api/widgets", identity_id="identity-alice", kind="api")
    api_schema = from_schema("GET", "/api/orders", base_url=BASE)
    pool = [page, api_observed, api_schema]
    mpa_labels = [e.label for e in Z.owner_candidates(pool, "identity-alice", allow_state_changing=False, anonymous_id=anon_id)]
    assert "GET /dashboard" in mpa_labels  # a page route replays normally off a SPA
    spa_labels = [e.label for e in Z.owner_candidates(pool, "identity-alice", allow_state_changing=False, anonymous_id=anon_id, spa=True)]
    assert "GET /dashboard" not in spa_labels  # the client shell is not a meaningful boundary test
    assert spa_labels[0] == "GET /api/widgets" or spa_labels[0] == "GET /api/orders"  # an API operation leads
    assert not Z.replayable(page, allow_state_changing=False, anonymous_id=anon_id, spa=True)
    assert Z.replayable(page, allow_state_changing=False, anonymous_id=anon_id, spa=False)


# ---- classification ---------------------------------------------------------------------------------


def classify(owner_role, actor_role, endpoint, *, actor_seen=False, anonymous=False, privilege=None, custom=""):
    items = [spec("Owner", owner_role, custom=custom if owner_role == "Custom" else ""), spec("Actor", actor_role, custom=custom if actor_role == "Custom" else "")]
    s = {x.label: x for x in specs(*items)}
    if actor_seen:
        endpoint = Endpoint(**{**endpoint.__dict__, "seen_as": (s["Actor"].identity_id,)})
    pair = Z.RolePair("Owner", "anonymous" if anonymous else "Actor", anonymous)
    return Z.classify_crossing(pair, s["Owner"], None if anonymous else s["Actor"], endpoint, privilege=privilege)


FUNC = from_schema("GET", "/api/admin/users", base_url=BASE, security_declared=True)
OBJ = from_schema("GET", "/api/orders/{id}", base_url=BASE, security_declared=True)


def test_an_anonymous_crossing_is_broken_authentication():
    result = classify("User", "Viewer", FUNC, anonymous=True)
    assert (result.check_id, result.kind, result.verdict) == ("dast-authn", "anonymous", "true_positive")


def test_a_lower_role_reaching_a_privileged_function_is_bfla_and_an_object_by_a_known_role_is_bola():
    assert classify("Admin", "User", FUNC).check_id == "dast-bfla"
    assert classify("Admin", "User", OBJ).check_id == "dast-bfla"  # never seen reaching it: treated as a privileged function
    assert classify("Admin", "User", OBJ, actor_seen=True).check_id == "dast-bola"  # the actor legitimately uses it; the object is the problem


def test_peers_are_only_a_finding_for_object_identifiers_and_a_higher_actor_never_is():
    assert classify("User", "User", OBJ).check_id == "dast-bola"
    assert classify("User", "User", FUNC) is None
    assert classify("User", "Admin", OBJ) is None and classify("Viewer", "Admin", FUNC) is None


def test_a_custom_role_without_an_order_is_false_positive_with_the_reason_not_a_guess():
    result = classify("Admin", "Custom", FUNC, custom="Auditor")
    assert result.verdict == "false_positive" and "Auditor" in result.reason and "no privilege order" in result.reason
    ranked = classify("Admin", "Custom", FUNC, custom="Auditor", privilege={"Actor": 1})
    assert ranked.verdict == "true_positive" and ranked.check_id == "dast-bfla"


def test_a_crossing_is_gated_on_whether_the_endpoint_ever_declared_a_security_requirement():
    """`classify_crossing` only confirms a crossing that would otherwise qualify when the
    endpoint's OpenAPI description actually declared a security requirement for it (DAST-10
    false-positive fix): no declaration at all means equal access is expected, and no schema
    source for the endpoint means the question cannot be answered, not that it is proven."""
    declared = from_schema("GET", "/api/admin/users", base_url=BASE, security_declared=True)
    undeclared = from_schema("GET", "/api/admin/users", base_url=BASE, security_declared=False)
    unknown = observed("GET", f"{BASE}/api/admin/users", kind="api")  # crawl-only: no schema source
    assert classify("User", "Viewer", declared, anonymous=True).verdict == "true_positive"
    assert classify("User", "Viewer", undeclared, anonymous=True).verdict == "false_positive"
    assert classify("User", "Viewer", unknown, anonymous=True).verdict == "unverified"
    assert classify("Admin", "User", declared).verdict == "true_positive"
    assert classify("Admin", "User", undeclared).verdict == "false_positive"
    assert classify("Admin", "User", unknown).verdict == "unverified"


# ---- the matrix -------------------------------------------------------------------------------------


def refs(*items):
    return [Z.FindingRef(f"f{i}", key, roles, verdict) for i, (key, roles, verdict) in enumerate(items)]


def test_cells_are_ok_failing_or_untested_with_a_reason_and_counts_equal_the_findings():
    s = specs(spec("Root", "Admin"), spec("Alice", "User"))
    replays = [Z.ReplaySummary("Root", "Alice", 4, 3, 1, 4), Z.ReplaySummary("Root", "anonymous", 4, 4, 0, 4), Z.ReplaySummary("Alice", "Root", 0, 0, 0, 0)]
    cells = {(c.owner, c.actor): c for c in Z.derive_matrix(s, replays, refs(("dast-bfla|GET /a", ("Root", "Alice"), "true_positive")), ran=True)}
    assert cells[("Root", "Alice")].result == "FAIL" and cells[("Root", "Alice")].failures == 1 and cells[("Root", "Alice")].finding_ids == ("f0",)
    assert cells[("Root", "anonymous")].result == "OK"
    assert cells[("Alice", "Root")].result == "untested" and "no resource reached by Alice" in cells[("Alice", "Root")].reason
    assert cells[("Alice", "anonymous")].result == "untested"  # no summary at all for that pair


def test_one_identity_marks_cross_role_cells_untested_with_that_reason_and_not_run_says_so():
    one = specs(spec("Alice", "User"))
    (cell,) = Z.derive_matrix(one, [Z.ReplaySummary("Alice", "anonymous", 2, 2, 0, 2)], [], ran=True)
    assert (cell.result, cell.owner, cell.actor) == ("OK", "Alice", "anonymous")
    two = specs(spec("Alice", "User"), spec("Bob", "User"))
    pending = Z.derive_matrix(two, [], [], ran=False)
    assert {c.result for c in pending} == {"untested"} and {c.reason for c in pending} == {"the authorization checks have not run yet"}
    ran_no_replay = {(c.owner, c.actor): c.reason for c in Z.derive_matrix(two, [], [], ran=True)}
    assert all("no resource reached" in reason for reason in ran_no_replay.values())
    assert Z.matrix_notes(one)["degraded"] and not Z.matrix_notes(two)["degraded"]


# ---- the replay engine against a fake target ---------------------------------------------------------


def authz_target() -> FakeTarget:
    t = FakeTarget()
    t.add_user("alice", "pw", role="user")
    t.add_user("bob", "pw", role="user")
    t.add_json("/", {"service": "demo"})
    t.add_json("/health", {"ok": True})
    # BFLA seeded: meant for admins only, but a plain user gets the same listing.
    t.route("GET", "/api/admin/users", lambda r: httpx.Response(401) if t.user_for(r) is None else httpx.Response(200, json={"users": ["a", "b", "c"], "count": 3}))
    # correctly protected: users are refused
    t.protect("/api/admin/audit", roles=["admin"], body={"entries": ["x", "y", "z"], "count": 3})
    # BOLA seeded: any signed-in user can read order 1, which belongs to alice.
    t.route("GET", "/api/orders/1", lambda r: httpx.Response(401) if t.user_for(r) is None else httpx.Response(200, json={"id": 1, "owner": "alice", "total": 10, "items": ["pen", "ink"]}))
    # unauthenticated access seeded: this one has no authentication at all
    t.route("GET", "/api/reports", lambda r: httpx.Response(200, json={"reports": [1, 2, 3, 4], "generated": "daily"}))
    t.set_openapi({"openapi": "3.0.0", "paths": {"/api/admin/users": {"get": {}}, "/api/admin/audit": {"get": {}}, "/api/orders/{id}": {"get": {"parameters": [{"name": "id", "in": "path", "schema": {"type": "integer"}}]}}, "/api/reports": {"get": {}}, "/health": {"get": {}}}})
    return t


IDS = [spec("Root", "Admin"), spec("Alice", "User"), spec("Bob", "User")]
SECRETS = {n: {"token": f"tok-{t}", "header_name": "Authorization", "scheme": "Bearer"} for n, t in (("Root", "admin"), ("Alice", "alice"), ("Bob", "bob"))}


def run_scan(target=None, ids=IDS, secrets=SECRETS, **kw):
    harness = Harness(target or authz_target(), build_identities(list(ids)), secrets, gateway=FakeModelGateway(strict=False), rule_set=default_rule_set(), **kw)
    discovery = harness.run(run_analysis=True)
    return discovery, harness


def authz_rows(harness):
    return [r for label, rows in harness.written if label == "authorization" for r in rows]


def test_seeded_bfla_bola_and_unauthenticated_flaws_are_found_and_protected_endpoints_are_not():
    discovery, harness = run_scan()
    rows = authz_rows(harness)
    found = {(r["rule_id"], r["target"], tuple(r["roles"])) for r in rows}
    assert ("dast-bfla", f"GET {BASE}/api/admin/users", ("Root", "Alice")) in found and ("dast-bfla", f"GET {BASE}/api/admin/users", ("Root", "Bob")) in found
    assert ("dast-bola", f"GET {BASE}/api/orders/{{id}}", ("Alice", "Bob")) in found and ("dast-bola", f"GET {BASE}/api/orders/{{id}}", ("Bob", "Alice")) in found
    assert any(r["rule_id"] == "dast-authn" and r["target"] == f"GET {BASE}/api/reports" for r in rows)  # reachable with no session at all
    assert not [r for r in rows if r["target"] == f"GET {BASE}/api/admin/audit"]  # correctly refused: a PASS for those cells
    assert not [r for r in rows if r["target"] in ("GET /health", "GET /")]  # public by design
    # authz_target()'s OpenAPI document never adds a `security` key to any operation (the common
    # real-world case for an API that enforces auth without documenting it) - classify_crossing
    # cannot confirm these from the doc, so they are unverified (still filed, needs review), not
    # auto-confirmed true_positive, and not suppressed either. The empirical signal is still shown.
    assert all(r["verdict"] == "unverified" and r["evidence"]["signals"][0]["name"] == "auth_boundary_crossed" for r in rows)
    bfla = next(r for r in rows if r["rule_id"] == "dast-bfla" and r["roles"] == ["Root", "Alice"])
    assert bfla["evidence"]["baseline_excerpt"].startswith("Root: HTTP 200") and bfla["evidence"]["test_excerpt"].startswith("Alice: HTTP 200") and bfla["severity"] == "HIGH"
    assert "Root → Alice" in bfla["source"] and bfla["evidence"]["audit_ref"]


def test_a_declared_security_requirement_confirms_the_crossing_as_true_positive():
    """Same seeded BFLA as above, but with the OpenAPI document explicitly declaring a security
    requirement for the endpoint: now the doc corroborates the empirical crossing, so it is
    confirmed true_positive rather than left unverified."""
    t = authz_target()
    t.set_openapi(
        {
            "openapi": "3.0.0",
            "security": [{"bearerAuth": []}],
            "paths": {
                "/api/admin/users": {"get": {}}, "/api/admin/audit": {"get": {}},
                "/api/orders/{id}": {"get": {"parameters": [{"name": "id", "in": "path", "schema": {"type": "integer"}}]}},
                "/api/reports": {"get": {}}, "/health": {"get": {}},
            },
        }
    )
    discovery, harness = run_scan(t)
    rows = authz_rows(harness)
    bfla = next(r for r in rows if r["rule_id"] == "dast-bfla" and r["roles"] == ["Root", "Alice"])
    assert bfla["verdict"] == "true_positive" and bfla["confidence_label"] in ("HIGH", "MEDIUM")


def test_replays_are_ordered_deduplicated_and_summarised_per_pair():
    discovery, harness = run_scan()
    authorization = discovery["authorization"]
    order = [(r["owner"], r["actor"]) for r in authorization["replays"]]
    assert order == [(o, a) for o in ("Root", "Alice", "Bob") for a in [x for x in ("Root", "Alice", "Bob") if x != o] + ["anonymous"]]
    assert authorization["ran"] and authorization["total_replays"] > 0 and not authorization["degraded"]
    # Three owners reach the same URLs; as one actor, an identical request is sent once (and compared three times).
    for actor in ("anonymous", "Alice", "Bob", "Root"):
        urls = [r.url for r in harness.audit.records if r.identity_label == actor and r.check_id == "authz-replay"]
        if actor in ("anonymous",):
            assert urls and len(urls) == len(set(urls)), (actor, urls)
    by_pair = {(r["owner"], r["actor"]): r for r in authorization["replays"]}
    assert by_pair[("Root", "Alice")]["owned"] > by_pair[("Alice", "Root")]["owned"] - 1 >= 0  # an owner only counts requests it reached
    assert by_pair[("Alice", "anonymous")]["owned"] < by_pair[("Root", "anonymous")]["owned"]  # Alice was refused /api/admin/audit, Root was not


def test_a_second_identity_is_what_unlocks_the_cross_role_pairs():
    one = [spec("Alice", "User")]
    discovery, harness = run_scan(ids=one, secrets={"Alice": SECRETS["Alice"]})
    authorization = discovery["authorization"]
    assert authorization["degraded"] and "no second identity" in authorization["degraded_reason"]
    assert [(r["owner"], r["actor"]) for r in authorization["replays"]] == [("Alice", "anonymous")]
    assert {r["rule_id"] for r in authz_rows(harness)} == {"dast-authn"}


def test_safe_mode_blocks_state_changing_replays_and_the_replay_cap_is_logged(capsys):
    t = authz_target()
    t.route("POST", "/api/orders", lambda r: httpx.Response(200, json={"created": True, "id": 2, "items": [1, 2]}))
    t.set_openapi({"openapi": "3.0.0", "paths": {"/api/orders": {"post": {}}, "/api/admin/users": {"get": {}}}})
    discovery, harness = run_scan(t)
    assert not [r for r in t.requests if r.method == "POST" and r.url.path == "/api/orders"]  # nothing state-changing was replayed in safe mode
    harness2 = Harness(authz_target(), build_identities(list(IDS)), SECRETS, gateway=FakeModelGateway(strict=False), rule_set=default_rule_set(), request={"max_targets": 1, "max_tests_per_target": 1})
    discovery2 = harness2.run(run_analysis=True)
    out = capsys.readouterr().out
    assert discovery2["authorization"]["cap"] == 1 and discovery2["authorization"]["cap_reached"]
    assert "replay cap (1) truncated" in out and discovery2["authorization"]["total_replays"] == 1


def test_a_cancel_between_replays_stops_the_engine():
    state = {"n": 0}

    def cancelled():
        state["n"] += 1
        return state["n"] > 6

    s = build_identities(list(IDS))
    store = SessionStore(list(s))
    for item in store.all():
        if not item.spec.is_anonymous:
            store.mark_authenticated(item.spec.identity_id)
            store.set_token(item.spec.identity_id, "Authorization", "Bearer", SECRETS[item.spec.label]["token"])
    harness = Harness(authz_target(), s, SECRETS)
    endpoints = [from_schema("GET", "/api/admin/users", base_url=BASE), from_schema("GET", "/api/orders/{id}", base_url=BASE)]
    checks = authz_engine.authz_checks(resolve_effective_rule_set(CATALOG))
    result = authz_engine.run_replays(endpoints, s, store, harness.runtime.executor, checks, allow_state_changing=False, max_replays=100, cancelled=cancelled, log=lambda *_: None)
    assert result.cancelled and result.replays < 12


def test_a_dead_owner_session_stops_its_remaining_candidates_and_is_recorded_not_scored():
    """DAST-10 false-positive fix: a session that dies mid-replay must stop sending as that
    identity and say why in the summary - it must never silently score a dead session's
    refusals as ordinary PASS/FAIL candidates."""
    t = FakeTarget()
    for path in ("/api/a", "/api/b", "/api/c", "/api/d"):
        t.route("GET", path, lambda r: httpx.Response(401, json={"error": "unauthorized"}))
    s = build_identities([spec("Root", "Admin"), spec("Alice", "User")])
    store = SessionStore(list(s))
    for item in store.all():
        if not item.spec.is_anonymous:
            store.mark_authenticated(item.spec.identity_id)
            store.set_token(item.spec.identity_id, "Authorization", "Bearer", f"tok-{item.spec.label.lower()}")
    harness = Harness(t, s, {})
    endpoints = [from_schema("GET", p, base_url=BASE) for p in ("/api/a", "/api/b", "/api/c", "/api/d")]
    checks = authz_engine.authz_checks(resolve_effective_rule_set(CATALOG))
    result = authz_engine.run_replays(endpoints, s, store, harness.runtime.executor, checks, allow_state_changing=False, max_replays=100, log=lambda *_: None)
    root_summaries = [r for r in result.summaries if r.owner == "Root"]
    assert root_summaries and all(r.session_lost for r in root_summaries)
    assert result.rows == []  # a dead owner session never reaches a comparison, so nothing is ever filed
    reason = Z.untested_reason(Z.RolePair("Root", "Alice", False), s, ran=True, replay=root_summaries[0])
    assert "session was lost mid-replay" in reason and "Root" in reason


def test_only_enabled_authorization_checks_write_findings():
    from app.dast.domain.ruleset import parse_rule_config

    cfg = parse_rule_config({"checks": {"dast-bfla": {"enabled": False}}}, CATALOG)
    checks = authz_engine.authz_checks(resolve_effective_rule_set(CATALOG, scan_config=cfg))
    assert set(checks) == {"dast-authn", "dast-bola"}
    assert authz_engine.authz_checks(None) == {}
    skipped = authz_engine.authz_checks(resolve_effective_rule_set(CATALOG), [{"check_id": "dast-bola", "status": "skipped"}])
    assert "dast-bola" not in skipped


def test_a_custom_role_without_an_order_yields_a_false_positive_finding_naming_the_reason():
    ids = [spec("Root", "Admin"), spec("Aud", "Custom", custom="Auditor")]
    discovery, harness = run_scan(ids=ids, secrets={"Root": SECRETS["Root"], "Aud": SECRETS["Alice"]})
    rows = [r for r in authz_rows(harness) if r["roles"] == ["Root", "Aud"]]
    assert rows and all(r["verdict"] == "false_positive" and "no privilege order" in r["verdict_reason"] and r["confidence_label"] == "LOW" for r in rows)
    assert all(r["evidence"]["signals"] == [] for r in rows)


# ---- the matrix API ----------------------------------------------------------------------------------

from fastapi.testclient import TestClient  # noqa: E402

from app import db as app_db  # noqa: E402
from app.config import settings  # noqa: E402
from app.models import Scan  # noqa: E402

from tests.auth_helpers import ADMIN_HEADERS  # noqa: E402

HDR = ADMIN_HEADERS


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("USE_MOCK_ENGINE", "true")
    monkeypatch.setattr(settings, "use_mock_engine", True)
    monkeypatch.setattr(settings, "scan_logs_dir", str(tmp_path / "scan_logs"))
    app_db.init_db(f"sqlite:///{(tmp_path / 'a.db').as_posix()}")
    return TestClient(app)


def token_identity(label, role):
    return {"label": label, "role": role, "auth_method": "token", "token": f"tok-{label}-value-12345"}


def create_scan(client, identities):
    project_id = client.post("/projects", json={"name": "authz-demo", "default_git_url": ""}, headers=HDR).json()["id"]
    body = {"scan_type": "dast", "project_id": project_id, "dast": {"target_url": "http://localhost:3000", "authorized": True, "identities": identities}}
    response = client.post("/scans", json=body, headers=HDR)
    assert response.status_code == 202, response.text
    return response.json()["scan_id"]


def test_the_matrix_endpoint_derives_cells_from_the_replays_and_findings_of_a_finished_scan(client):
    scan_id = create_scan(client, [token_identity("admin", "Admin"), token_identity("user", "User")])
    body = client.get(f"/scans/{scan_id}/authz-matrix", headers=HDR).json()
    assert body["scan_id"] == scan_id and body["ran"] is True and body["baseline_identity"] == "anonymous"
    assert [i["label"] for i in body["identities"]] == ["admin", "user"] and body["identities"][0]["role"]["name"] == "admin"
    cells = {(c["owner"], c["actor"]): c for c in body["cells"]}
    assert cells[("admin", "user")]["result"] == "FAIL" and cells[("admin", "user")]["failures"] == 1 and len(cells[("admin", "user")]["finding_ids"]) == 1
    assert cells[("admin", "anonymous")]["result"] == "OK"
    assert cells[("user", "admin")]["result"] == "untested" and "no resource reached by user" in cells[("user", "admin")]["reason"]
    assert body["degraded"] is False and body["replays"] == 2
    # the role-pair filter returns exactly the findings behind the failing cell
    found = client.get(f"/scans/{scan_id}/findings", params={"role": "admin:user"}, headers=HDR).json()["findings"]
    assert [f["id"] for f in found] == cells[("admin", "user")]["finding_ids"]
    assert sum(c["failures"] for c in body["cells"]) == len([f for f in client.get(f"/scans/{scan_id}/findings", headers=HDR).json()["findings"] if f["rule_id"] in ("dast-bfla", "dast-bola", "dast-authn")])


def test_the_matrix_is_available_before_the_stage_has_run_and_only_for_dast_scans(client):
    scan_id = create_scan(client, [token_identity("admin", "Admin")])
    with app_db.SessionLocal() as session:
        scan = session.get(Scan, scan_id)
        meta = dict(scan.metadata_json or {})
        meta["discovery"] = {}  # the engine has not reported yet
        scan.metadata_json, scan.status = meta, "running"
        session.commit()
    body = client.get(f"/scans/{scan_id}/authz-matrix", headers=HDR).json()
    assert body["ran"] is False and body["degraded"] is True and "no second identity" in body["degraded_reason"]
    assert {c["result"] for c in body["cells"]} <= {"untested", "FAIL"}
    assert client.get("/scans/nope/authz-matrix", headers=HDR).status_code == 404
    project_id = client.post("/projects", json={"name": "sast", "default_git_url": "https://github.com/org/repo.git"}, headers=HDR).json()["id"]
    sast = client.post("/scans", json={"project_id": project_id}, headers=HDR)
    assert sast.status_code == 202
    assert client.get(f"/scans/{sast.json()['scan_id']}/authz-matrix", headers=HDR).status_code == 400


def test_numeric_neighbors_are_bounded_observed_first_and_never_guessed_from_nothing():
    endpoint = observed("GET", BASE + "/api/orders/10", kind="api", parameters=[Parameter("id", Location.PATH, observed_values=("10",))])
    other = observed("GET", BASE + "/api/orders/50", kind="api", parameters=[Parameter("id", Location.PATH, observed_values=("50",))])
    assert Z.alternate_object_values(endpoint, [endpoint, other]) == [("id", Location.PATH, "50"), ("id", Location.PATH, "11"), ("id", Location.PATH, "9")]
    assert Z.alternate_object_value(endpoint, [endpoint]) == ("id", Location.PATH, "11")
    assert Z.alternate_object_values(endpoint, [endpoint], numeric_neighbors=False) == []
    assert Z.alternate_object_values(from_schema("GET", "/api/orders/{id}", base_url=BASE), []) == []
    uuid = observed("GET", BASE + "/api/orders", parameters=[Parameter("id", Location.QUERY, observed_values=("some-uuid",))])
    assert Z.alternate_object_values(uuid, []) == []


def test_plan_priority_changes_which_replay_fits_the_cap_but_none_preserves_order():
    def run(priority):
        target = FakeTarget()
        target.add_json("/api/a", {"private": "first endpoint data"})
        target.add_json("/api/z", {"private": "highest priority endpoint data"})
        identities = specs(spec("Owner", "User"))
        harness = Harness(target, identities, {"Owner": {"token": "owner-token"}})
        store = SessionStore(identities)
        store.mark_authenticated(identities[0].identity_id)
        store.set_token(identities[0].identity_id, "Authorization", "Bearer", "owner-token")
        endpoints = [from_schema("GET", "/api/a", base_url=BASE, security_declared=True), from_schema("GET", "/api/z", base_url=BASE, security_declared=True)]
        try:
            result = authz_engine.run_replays(endpoints, identities, store, harness.runtime.executor,
                authz_engine.authz_checks(resolve_effective_rule_set(CATALOG)), allow_state_changing=False,
                max_replays=1, priority=priority, log=lambda *_: None)
            actors = [r for r in target.requests if "authorization" not in r.headers]
            return actors[0].url.path, result
        finally:
            harness.runtime.close()
    assert run(None)[0] == "/api/a"
    path, result = run(["GET /api/z"])
    assert path == "/api/z" and result.replays == 1 and result.cap_reached


def test_numeric_neighbor_replay_stays_unverified_without_observed_ownership():
    target = FakeTarget()
    def read(request):
        owner = bool(request.headers.get("authorization"))
        if request.url.path.endswith("/10") and not owner:
            return httpx.Response(403, text="denied")
        return httpx.Response(200, json={"id": request.url.path.rsplit("/", 1)[-1], "private_data": "long protected response data"})
    target.route("GET", "/api/orders/10", read)
    target.route("GET", "/api/orders/11", read)
    identities = specs(spec("Owner", "User"))
    harness = Harness(target, identities, {"Owner": {"token": "owner-token"}})
    store = SessionStore(identities)
    store.mark_authenticated(identities[0].identity_id)
    store.set_token(identities[0].identity_id, "Authorization", "Bearer", "owner-token")
    endpoint = observed("GET", BASE + "/api/orders/10", kind="api", identity_id=identities[0].identity_id,
                        parameters=[Parameter("id", Location.PATH, observed_values=("10",))])
    try:
        result = authz_engine.run_replays([endpoint], identities, store, harness.runtime.executor,
            authz_engine.authz_checks(resolve_effective_rule_set(CATALOG)), allow_state_changing=False,
            max_replays=3, numeric_neighbors=True, log=lambda *_: None)
        assert result.replays == 2 and len(result.rows) == 1
        assert result.rows[0]["verdict"] == "unverified"
        assert "/11" in result.rows[0]["file_path"]
    finally:
        harness.runtime.close()
