"""SQL method summaries (SAST-02-050): each method summarised once — does it
execute SQL with fixed or dynamic text, which parameters reach the text, what
SQL it returns or appends — and reused at every call, resolved by receiver and
signature rather than by name.

Over `fixtures/sql_summaries/`, a small multi-class project re-creating the
facade, batch, helper and IN-list shapes of the accuracy review.
"""

import sys
from pathlib import Path

import pytest

pytest.importorskip("tree_sitter")
pytest.importorskip("tree_sitter_java")
pytest.importorskip("boto3", reason="pipeline modules import llm_client")

_ENGINE = Path(__file__).resolve().parents[1] / "sast_engine"
if str(_ENGINE) not in sys.path:
    sys.path.insert(0, str(_ENGINE))

from pipeline import call_graph as cg  # noqa: E402
from pipeline import sql_semantics as sq  # noqa: E402
from pipeline.validators import ValidatorContext  # noqa: E402
from pipeline.validators import sql_binding as sb  # noqa: E402

pytestmark = pytest.mark.unit

ROOT = Path(__file__).parent / "fixtures" / "sql_summaries"
PKG = "src/main/java/com/acme"


def _paths():
    return sorted(str(p.relative_to(ROOT)) for p in ROOT.rglob("*.java"))


def _read(path):
    try:
        return (ROOT / path).read_text()
    except OSError:
        return None


@pytest.fixture()
def summaries():
    graph = cg.build_call_graph(ROOT, _paths())
    return sq.SqlSummaries(graph, _read)


def _key(s: sq.SqlSummaries, owner: str, name: str, params=None) -> str:
    for key, m in s.graph.methods.items():
        if m.fqcn.endswith(owner) and m.name == name and (params is None or m.param_types == params):
            return key
    raise AssertionError(f"{owner}.{name} not in the graph")


def _summary(s, owner, name, params=None):
    return s.summarise(_key(s, owner, name, params))


# --- summaries -------------------------------------------------------------------

def test_a_bound_dao_method_is_fixed_bound(summaries):
    summary = _summary(summaries, "SafeOrderDao", "findByCustomer")
    assert summary.executes == "fixed_bound" and summary.binds_params == (0,)


def test_a_concatenating_dao_method_names_the_parameter_that_reaches_sql(summaries):
    summary = _summary(summaries, "UnsafeOrderDao", "findByCustomer")
    assert summary.executes == "dynamic" and summary.positions == (0,)


def test_overloads_are_summarised_apart(summaries):
    assert _summary(summaries, "BatchWriter", "add", ["String"]).executes == "fixed_bound"
    unsafe = _summary(summaries, "BatchWriter", "add", ["String", "String"])
    assert unsafe.executes == "dynamic" and unsafe.positions == (0, 1)


def test_a_wrapper_passes_its_parameter_through(summaries):
    summary = _summary(summaries, "ReportService", "userFilter")
    assert summary.executes == "dynamic" and summary.positions == (0,)


def test_a_wrapper_called_with_a_constant_is_not_dynamic(summaries):
    assert _summary(summaries, "ReportService", "constantFilter").executes != "dynamic"


def test_a_facade_call_is_the_union_of_its_implementations(summaries):
    summary = _summary(summaries, "ReportService", "viaFacade")
    assert summary.executes == "dynamic" and summary.positions == (0,)


def test_a_call_on_the_safe_implementation_is_fixed_bound(summaries):
    assert _summary(summaries, "ReportService", "viaSafe").executes == "fixed_bound"


@pytest.mark.parametrize("method, returns", [
    ("defaultWhere", "fixed"),
    ("placeholders", "placeholder_list"),
    ("rawList", "dynamic"),
])
def test_query_helpers_are_summarised_by_what_they_return(summaries, method, returns):
    assert _summary(summaries, "QueryHelper", method).returns_sql == returns


@pytest.mark.parametrize("method, executes", [
    ("listActive", "fixed_bound"),    # a default-WHERE helper (#46)
    ("findIn", "fixed_bound"),        # a placeholder-list helper, bound in a loop (#67)
    ("findInRaw", "dynamic"),         # raw values joined into IN (...)
    ("byStatus", "fixed_bound"),      # a builder appended to by a helper
    ("byOwner", "dynamic"),           # ... one that appends a value
])
def test_helpers_resolve_at_the_call_site(summaries, method, executes):
    assert _summary(summaries, "ReportDao", method).executes == executes


def test_a_recursive_method_with_a_decided_path_is_decided(summaries):
    assert _summary(summaries, "ReportDao", "walk").executes == "fixed_bound"


def test_a_pure_cycle_is_unknown(summaries):
    summary = _summary(summaries, "ReportDao", "ping")
    assert summary.executes == "unknown" and summary.reason == "cycle"


def test_a_callee_outside_the_repo_is_a_named_unknown(summaries):
    summary = _summary(summaries, "ReportDao", "external")
    assert summary.executes == "unknown"
    assert "ExternalSql.build" in summary.missing


def test_summaries_are_computed_once_per_method(summaries):
    key = _key(summaries, "UnsafeOrderDao", "findByCustomer")
    summaries.summarise(key)
    computed = summaries.stats["methods"]
    summaries.summarise(key)
    summaries.summarise(_key(summaries, "ReportService", "viaFacade"))
    assert summaries.stats["cache_hits"] >= 2
    # viaFacade computed itself and SafeOrderDao; UnsafeOrderDao came from the cache.
    assert summaries.stats["methods"] == computed + 2


def test_the_depth_bound_is_honoured_and_counted():
    graph = cg.build_call_graph(ROOT, _paths())
    shallow = sq.SqlSummaries(graph, _read, max_depth=0)
    summary = shallow.summarise(_key(shallow, "ReportService", "userFilter"))
    assert summary.executes == "unknown"
    assert shallow.stats["summary_depth_exceeded"] >= 1


def test_counters_reach_the_usage_summary():
    usage = {}
    graph = cg.build_call_graph(ROOT, _paths())
    s = sq.SqlSummaries(graph, _read, usage=usage)
    s.summarise(_key(s, "ReportService", "viaFacade"))
    assert usage["_counters"]["sql_summaries"]["methods"] >= 3


# --- the validator, with the scan's summaries ---------------------------------------

def _validate(summaries, rel: str, needle: str, **over):
    text = _read(rel)
    line = next(n for n, c in enumerate(text.splitlines(), 1) if needle in c)
    finding = {"file_path": rel, "line": line, "rule_id": "java-jdbc-prepare-concat", "cwe": "CWE-89",
               "verdict": "true_positive", **over}
    ctx = ValidatorContext(file_text={rel: text}, sql=summaries)
    return sb.sql_binding(finding, None, ctx)


@pytest.mark.parametrize("rel, needle, outcome, tag", [
    (f"{PKG}/dao/ReportDao.java", "QueryHelper.defaultWhere()", "negative_proof", "sql_fixed_template_bound"),
    (f"{PKG}/dao/ReportDao.java", "QueryHelper.placeholders", "negative_proof", "sql_fixed_template_bound"),
    (f"{PKG}/dao/ReportDao.java", "QueryHelper.rawList", "positive_fact", "sql_dynamic_text"),
    (f"{PKG}/dao/ReportDao.java", "ExternalSql.build", "evidence_gap", None),
    (f"{PKG}/dao/BatchWriter.java", "insert.addBatch", "negative_proof", "sql_fixed_template_bound"),
    (f"{PKG}/dao/BatchWriter.java", "st.executeUpdate", "positive_fact", "sql_dynamic_text"),
    (f"{PKG}/service/ReportService.java", "orders.findByCustomer", "positive_fact", "sql_dynamic_text"),
    (f"{PKG}/service/ReportService.java", "safeOrders.findByCustomer", "negative_proof", "sql_fixed_template_bound"),
    (f"{PKG}/service/ReportService.java", "reports.runWhere(connection, filter)", "positive_fact", "sql_dynamic_text"),
    (f"{PKG}/service/ReportService.java", '"status = 1"', "no_opinion", None),
    (f"{PKG}/service/ReportService.java", "reports.count()", "negative_proof", "sql_callee_no_sql"),
])
def test_validator_with_summaries(summaries, rel, needle, outcome, tag):
    result = _validate(summaries, rel, needle)
    assert (result.outcome, result.reason_tag) == (outcome, tag), result


def test_the_gap_names_the_unresolved_callee(summaries):
    result = _validate(summaries, f"{PKG}/dao/ReportDao.java", "ExternalSql.build")
    assert "ExternalSql.build" in result.missing


def test_a_facade_proof_names_the_implementations(summaries):
    result = _validate(summaries, f"{PKG}/service/ReportService.java", "orders.findByCustomer")
    assert "findByCustomer" in result.proof and "`name`" in result.proof


def test_a_generated_insert_builder_returns_text_from_its_table_and_columns(summaries):
    summary = _summary(summaries, "SqlGen", "insert")
    assert summary.returns_sql == "dynamic" and summary.return_positions == (0, 1)


def test_a_generated_dao_with_constant_table_and_columns_is_fixed_bound(summaries):
    # #73: the table and column names are constants at the call; every value is
    # bound in the loop over the generated placeholder list.
    assert _summary(summaries, "GeneratedOrderDao", "insert").executes == "fixed_bound"


def test_a_generated_dao_with_a_caller_supplied_table_is_dynamic(summaries):
    summary = _summary(summaries, "GeneratedOrderDao", "insertInto")
    assert summary.executes == "dynamic" and summary.positions == (1,)


def test_the_time_budget_counts_summarising_time_not_scan_time():
    graph = cg.build_call_graph(ROOT, _paths())
    exhausted = sq.SqlSummaries(graph, _read, time_budget=0.0)
    exhausted.spent = 0.001
    assert exhausted.summarise(_key(exhausted, "ReportService", "userFilter")).reason == "summary_time_exceeded"
    fresh = sq.SqlSummaries(graph, _read, time_budget=0.0)
    assert fresh.summarise(_key(fresh, "SafeOrderDao", "findByCustomer")).executes == "fixed_bound"
