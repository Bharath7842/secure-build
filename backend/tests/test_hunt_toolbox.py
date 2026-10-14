"""Hunt toolbox, symbol services and dossier against tests/fixtures/hunt_java.

Needs rg (RG_PATH / PATH / the `ripgrep` wheel) and tree-sitter-java for the
call-graph parts; each test skips cleanly without them.
"""

import sys
from pathlib import Path

import pytest

pytest.importorskip("boto3", reason="pipeline modules import llm_client")

_ENGINE_DIR = Path(__file__).resolve().parents[1] / "sast_engine"
if str(_ENGINE_DIR) not in sys.path:
    sys.path.insert(0, str(_ENGINE_DIR))

from pipeline.hunt import retry_policy  # noqa: E402
from pipeline.hunt.evidence import EvidenceLedger  # noqa: E402
from pipeline.hunt.redact import REDACTED  # noqa: E402
from pipeline.hunt.rg_runner import RgRunner, find_rg_binary  # noqa: E402
from pipeline.hunt.symbols import SymbolService, build_lazy_graph_builder, parse_symbol  # noqa: E402

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "hunt_java"
INVENTORY = sorted(str(p.relative_to(FIXTURE)) for p in FIXTURE.rglob("*.java"))
CONTROLLER = "src/main/java/com/acme/web/OrderController.java"
SERVICE = "src/main/java/com/acme/service/OrderService.java"
DAO = "src/main/java/com/acme/repo/OrderDao.java"
SECURITY = "src/main/java/com/acme/security/SecurityConfig.java"
RISK = {
    CONTROLLER: "CRITICAL",
    SERVICE: "HIGH",
    DAO: "MEDIUM",
    "src/main/java/com/acme/util/Paging.java": "LOW",
    SECURITY: "CRITICAL",
}

needs_rg = pytest.mark.skipif(find_rg_binary() is None, reason="ripgrep (rg) is not installed")


def _has_tree_sitter() -> bool:
    try:
        import tree_sitter_java  # noqa: F401
    except ImportError:
        return False
    return True


needs_graph = pytest.mark.skipif(not _has_tree_sitter(), reason="tree-sitter-java is not installed")


def _graph():
    from pipeline.call_graph import build_call_graph

    return build_call_graph(FIXTURE, INVENTORY)


def _toolbox(*, graph=None, lazy=False, **kwargs):
    from pipeline.hunt.tools import HuntToolbox

    runner = RgRunner(FIXTURE, allowed_files=INVENTORY)
    symbols = SymbolService(
        FIXTURE, runner, graph=graph,
        graph_builder=build_lazy_graph_builder(FIXTURE, INVENTORY) if lazy else None,
    )
    ledger = EvidenceLedger()
    box = HuntToolbox(root=FIXTURE, runner=runner, symbols=symbols, ledger=ledger,
                      risk_by_path=RISK, inventory=INVENTORY, **kwargs)
    return box, ledger, symbols


# --- symbols ---------------------------------------------------------------


@pytest.mark.parametrize("raw,expected", [
    ("OrderDao.findByName(", ("OrderDao", "findByName")),
    ("OrderDao", ("OrderDao", None)),
    ("findByName", (None, "findByName")),
    ("com.acme.repo.OrderDao", ("OrderDao", None)),
    ("x; rm -rf /", (None, None)),
])
def test_parse_symbol(raw, expected):
    assert parse_symbol(raw) == expected


@needs_graph
@needs_rg
def test_graph_resolves_callers_definitions_and_sinks():
    _box, _ledger, symbols = _toolbox(graph=_graph())
    callers = symbols.callers("findByName", "OrderDao")
    assert [(c.file, c.line, c.resolution) for c in callers] == [(SERVICE, 16, "graph")]
    defs = symbols.definitions("OrderDao.findByName")
    assert defs and defs[0].file == DAO and defs[0].resolution == "graph"
    assert "findByName(String name)" in defs[0].signature
    assert symbols.graph_sink_kind(DAO, 15) == "sql"
    assert symbols.edge_resolution(caller_file=CONTROLLER, call_line=24, callee_file=SERVICE, callee_name="search") == "graph"
    # No edge from the controller straight into the DAO.
    assert symbols.edge_resolution(caller_file=CONTROLLER, call_line=24, callee_file=DAO) is None
    assert symbols.is_framework_entry_at(CONTROLLER, 24)
    assert symbols.enclosing_method(SERVICE, 16).name == "search"


@needs_graph
@needs_rg
def test_lazy_graph_is_built_on_first_query():
    _box, _ledger, symbols = _toolbox(lazy=True)
    assert symbols._graph is None
    assert symbols.callers("search", "OrderService")[0].resolution == "graph"
    assert symbols._graph is not None


@needs_rg
def test_without_graph_callers_are_textual():
    _box, _ledger, symbols = _toolbox(graph=None)
    hits = symbols.callers("findByName")
    assert hits and all(h.resolution == "textual" for h in hits)
    assert {h.file for h in hits} == {SERVICE}


# --- dossier ---------------------------------------------------------------


@needs_graph
@needs_rg
def test_dossier_is_bounded_and_grounded_in_the_repo():
    from pipeline.hunt.repo_index import build_dossier

    _box, _ledger, symbols = _toolbox(graph=_graph())
    dossier = build_dossier(
        runner=symbols.runner, symbols=symbols, stack="Java / Spring Boot",
        frameworks=["Spring Boot"], seed_entries=[{"path": p, "risk_level": r} for p, r in RISK.items()],
        inventory=INVENTORY, catalog_hits={"java-sql-concat": 2},
    )
    text = dossier.render()
    assert len(text) <= 24_000
    assert dossier.entry_point_count == 5
    sql = next(s for s in dossier.sinks if s.kind == "sql")
    assert sql.resolution == "graph"
    assert SECURITY in dossier.security_config_files
    assert "java-sql-concat: 2" in text
    assert "call graph" in text
    # Nothing from the repository's text is quoted into the dossier body
    # beyond paths and identifiers (the injection comment never appears).
    assert "ignore previous instructions" not in text


# --- toolbox ---------------------------------------------------------------


@needs_rg
def test_search_samples_ranks_and_records_evidence():
    box, ledger, _symbols = _toolbox()
    result = box.run("search", {"pattern": r"executeQuery\(", "intent": "sql sinks"})
    assert result.ok and result.outcome == retry_policy.OUTCOME_OK
    # The generated file is excluded by default; the test file is kept but last.
    assert "generated/OrderQueries.java" not in result.text
    assert result.text.index(DAO) < result.text.index("OrderDaoTest.java")
    assert "<untrusted_code" in result.text
    assert ledger.covers(DAO, 15)
    assert result.data["filtered"]["generated"] == 1


@needs_rg
def test_secrets_are_redacted_in_search_and_read_output():
    box, ledger, _symbols = _toolbox()
    searched = box.run("search", {"pattern": "dbPassword"})
    assert "Sup3rS3cretDbPass" not in searched.text
    assert REDACTED in searched.text
    read = box.run("read", {"file": DAO, "start": 9, "end": 12})
    assert "Sup3rS3cretDbPass" not in read.text
    assert ledger.covers(DAO, 10)


@needs_rg
def test_zero_result_search_tries_a_relaxed_variant():
    box, _ledger, _symbols = _toolbox()
    result = box.run("search", {"pattern": r"\bEXECUTEQUERY\b"})
    assert result.outcome == retry_policy.OUTCOME_ZERO
    assert result.data.get("relaxed_pattern")
    assert "relaxed variant" in result.text


@needs_rg
def test_too_many_results_force_narrowing(monkeypatch):
    monkeypatch.setattr(retry_policy, "TOO_MANY_THRESHOLD", 3)
    box, _ledger, _symbols = _toolbox()
    result = box.run("search", {"pattern": "import"})
    assert result.outcome == retry_policy.OUTCOME_TOO_MANY
    assert "Narrow it" in result.text
    assert "<untrusted_code" not in result.text  # totals only, no code


@needs_rg
def test_noisy_results_are_filtered_and_reported(monkeypatch):
    monkeypatch.setattr(retry_policy, "NOISY_FRACTION", 0.6)
    box, _ledger, _symbols = _toolbox(test_policy="exclude")
    # Two of the three executeQuery-concat sites are generated/test code.
    result = box.run("search", {"pattern": r"executeQuery\(\"SELECT \* FROM (?:orders|t) WHERE (?:name|v) = '\""})
    assert result.outcome == retry_policy.OUTCOME_NOISY
    assert "filtered out" in result.text
    assert "OrderDaoTest.java" not in result.text


@needs_rg
def test_invalid_pattern_feedback():
    box, _ledger, _symbols = _toolbox()
    result = box.run("search", {"pattern": "executeQuery("})
    assert not result.ok
    assert result.outcome == retry_policy.OUTCOME_INVALID
    assert "hint" in result.text


@needs_rg
def test_read_is_bounded_numbered_and_confined():
    box, ledger, _symbols = _toolbox()
    result = box.run("read", {"file": SERVICE, "start": 1, "end": 500})
    assert result.ok
    assert "    15:" in result.text
    assert result.data["end"] <= 200
    outside = box.run("read", {"file": "../../conftest.py"})
    assert not outside.ok and "not a file in the scan scope" in outside.text
    unknown = box.run("delete_everything", {})
    assert not unknown.ok


@needs_graph
@needs_rg
def test_callers_record_graph_edges_in_the_ledger():
    box, ledger, _symbols = _toolbox(graph=_graph())
    result = box.run("callers", {"method": "findByName", "class_name": "OrderDao"})
    assert "[graph]" in result.text
    edge = ledger.best_edge(caller_file=SERVICE, callee_file=DAO)
    assert edge is not None and edge.resolution == "graph"


@needs_graph
@needs_rg
def test_search_sinks_marks_graph_resolved_sinks():
    box, _ledger, _symbols = _toolbox(graph=_graph())
    result = box.run("search_sinks", {"kind": "sql"})
    assert "[graph-resolved sql sink]" in result.text
    assert box.run("search_sinks", {"kind": "nope"}).outcome == retry_policy.OUTCOME_INVALID


@needs_rg
def test_find_sanitizers_within_a_method_span():
    box, _ledger, _symbols = _toolbox()
    escaped = box.run("find_sanitizers", {"kind": "xss", "file": CONTROLLER, "start": 38, "end": 41})
    assert "htmlEscape" in escaped.text
    raw = box.run("find_sanitizers", {"kind": "xss", "file": CONTROLLER, "start": 33, "end": 36})
    assert raw.outcome == retry_policy.OUTCOME_ZERO
    assert "No known xss sanitizer" in raw.text


@needs_graph
@needs_rg
def test_find_authz_shows_method_annotations_and_security_rules():
    box, _ledger, _symbols = _toolbox(graph=_graph())
    result = box.run("find_authz", {"file": CONTROLLER, "line": 45})
    assert "DeleteMapping" in result.text
    assert "PreAuthorize" not in result.text.split("Security configuration rules:")[0]
    assert "permitAll" in result.text
    assert "csrf" in result.text


def test_list_files_and_bad_globs():
    from pipeline.hunt.tools import HuntToolbox

    runner = RgRunner(FIXTURE, binary="", allowed_files=INVENTORY)
    box = HuntToolbox(root=FIXTURE, runner=runner, symbols=SymbolService(FIXTURE, runner),
                      ledger=EvidenceLedger(), risk_by_path=RISK, inventory=INVENTORY)
    listed = box.run("list_files", {"glob": "**/*Controller.java"})
    assert CONTROLLER in listed.text
    assert not box.run("list_files", {"glob": "../*"}).ok
