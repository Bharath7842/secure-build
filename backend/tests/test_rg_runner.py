"""ripgrep runner: scoping, hardening against LLM-written patterns, limits.

Needs a real `rg` (RG_PATH, PATH, or the `ripgrep` wheel from
requirements.txt); skipped otherwise.
"""

import sys
from pathlib import Path

import pytest

_ENGINE_DIR = Path(__file__).resolve().parents[1] / "sast_engine"
if str(_ENGINE_DIR) not in sys.path:
    sys.path.insert(0, str(_ENGINE_DIR))

from pipeline import rg_runner  # noqa: E402
from pipeline.rg_runner import PatternRejected, RgRunner, check_glob, check_pattern_policy  # noqa: E402

RG = rg_runner.find_rg_binary()
needs_rg = pytest.mark.skipif(RG is None, reason="ripgrep (rg) is not installed")


def _repo(tmp_path: Path) -> Path:
    files = {
        "src/main/java/com/acme/UserDao.java": (
            "class UserDao {\n"
            "  ResultSet find(String id) {\n"
            '    return stmt.executeQuery("SELECT * FROM u WHERE id=" + id);\n'
            "  }\n"
            "}\n"
        ),
        "src/main/java/com/acme/SafeDao.java": (
            "class SafeDao {\n"
            '  PreparedStatement ps = conn.prepareStatement("SELECT * FROM u WHERE id=?");\n'
            "}\n"
        ),
        "src/test/java/com/acme/UserDaoTest.java": 'stmt.executeQuery("SELECT 1");\n',
        "target/generated/Gen.java": 'stmt.executeQuery("generated");\n',
        "-rf.java": "executeQuery in an awkwardly named file\n",
    }
    for rel, text in files.items():
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return tmp_path


def test_pattern_policy_rejects_oversized_and_overbranching_patterns():
    with pytest.raises(PatternRejected):
        check_pattern_policy("a" * 401, pcre2=False)
    with pytest.raises(PatternRejected):
        check_pattern_policy("|".join(f"w{i}" for i in range(13)), pcre2=False)
    # Alternations inside a character class don't count.
    check_pattern_policy("[|]" * 20, pcre2=False)
    with pytest.raises(PatternRejected):
        check_pattern_policy("", pcre2=False)


def test_pattern_policy_rejects_catastrophic_pcre2_constructs():
    for pattern in (r"(a+)+$", r"(.*)*x", r"(\w+){2,}y"):
        with pytest.raises(PatternRejected):
            check_pattern_policy(pattern, pcre2=True)
    with pytest.raises(PatternRejected):
        check_pattern_policy(r"(\w+)=\1", pcre2=True)
    # The linear-time default engine has no such hazard.
    check_pattern_policy(r"(a+)+$", pcre2=False)


@pytest.mark.parametrize("glob", ["/etc/*", "../secrets/*", "src/../../x", "C:/Windows/*", ""])
def test_globs_must_stay_inside_the_repo(glob):
    with pytest.raises(PatternRejected):
        check_glob(glob)


def test_allowed_globs_including_exclusions():
    assert check_glob("**/*.java") == "**/*.java"
    assert check_glob("!**/test/**") == "!**/test/**"


@needs_rg
def test_search_returns_repo_relative_matches_with_context(tmp_path):
    root = _repo(tmp_path)
    result = RgRunner(root).search(r"executeQuery\(", context=1, globs=["**/*.java"])
    assert result.ok, result.error
    files = {m.file for m in result.matches}
    assert "src/main/java/com/acme/UserDao.java" in files
    # target/ is pruned like the engine's own directory walk.
    assert not any(f.startswith("target/") for f in files)
    dao = next(m for m in result.matches if m.file.endswith("UserDao.java"))
    assert dao.line == 3
    assert "executeQuery(" in dao.submatches
    assert result.context["src/main/java/com/acme/UserDao.java"][2].strip().startswith("ResultSet find")


@needs_rg
def test_inventory_post_filter_is_authoritative(tmp_path):
    root = _repo(tmp_path)
    runner = RgRunner(root, allowed_files={"src/main/java/com/acme/UserDao.java"})
    result = runner.search("executeQuery")
    assert {m.file for m in result.matches} == {"src/main/java/com/acme/UserDao.java"}
    assert result.dropped_out_of_scope >= 1


@needs_rg
def test_pattern_starting_with_dash_is_never_a_flag(tmp_path):
    root = _repo(tmp_path)
    # Were this parsed as flags, "--files" would list every file instead.
    result = RgRunner(root).search("--files")
    assert result.ok
    assert result.matches == []
    hit = RgRunner(root).search("-rf")
    assert hit.ok
    assert {m.file for m in hit.matches} == set()  # filename, not content
    in_content = RgRunner(root).search("awkwardly")
    assert [m.file for m in in_content.matches] == ["-rf.java"]


@needs_rg
def test_explicit_paths_must_be_in_scope(tmp_path):
    root = _repo(tmp_path)
    outside = tmp_path.parent / "outside.java"
    outside.write_text("executeQuery\n", encoding="utf-8")
    result = RgRunner(root).search("executeQuery", paths=["../outside.java"])
    assert not result.ok
    assert "outside the scan scope" in result.error


@needs_rg
def test_invalid_regex_returns_rg_error_and_hint(tmp_path):
    result = RgRunner(_repo(tmp_path)).search("executeQuery(")
    assert not result.ok
    assert "unclosed group" in result.error.lower()
    assert "\\(" in result.hint


@needs_rg
def test_lookaround_without_pcre2_explains_how_to_rewrite(tmp_path):
    runner = RgRunner(_repo(tmp_path))
    result = runner.search(r"(?<!prepare)Statement")
    if runner.pcre2_available():
        assert result.ok
        assert result.engine == "pcre2"
    else:
        assert not result.ok
        assert "rewrite without" in result.hint


@needs_rg
def test_output_cap_truncates_instead_of_growing_unbounded(tmp_path):
    big = tmp_path / "Big.java"
    big.write_text("token();\n" * 5000, encoding="utf-8")
    result = RgRunner(tmp_path, max_output_bytes=4096).search("token", max_count_per_file=5000)
    assert result.ok
    assert result.output_truncated
    assert 0 < result.match_count < 5000


@needs_rg
def test_max_count_per_file_bounds_matches(tmp_path):
    big = tmp_path / "Many.java"
    big.write_text("hit();\n" * 200, encoding="utf-8")
    result = RgRunner(tmp_path).search("hit", max_count_per_file=7)
    assert result.match_count == 7


@needs_rg
def test_files_with_matches(tmp_path):
    result = RgRunner(_repo(tmp_path)).files_with_matches("prepareStatement")
    assert result.files == ["src/main/java/com/acme/SafeDao.java"]


def test_missing_binary_reports_unavailable(tmp_path):
    runner = RgRunner(tmp_path, binary="")
    assert not runner.available()
    result = runner.search("x")
    assert not result.ok
    assert "not installed" in result.error


@needs_rg
def test_rg_runs_under_the_memory_capping_shell(tmp_path):
    root = _repo(tmp_path)
    runner = RgRunner(root, memory_limit_mb=512)
    if runner.memory_limit_kb:
        assert runner._argv(["rg", "x"])[:2] == ["/bin/sh", "-c"]
    result = runner.search(r"executeQuery\(")
    assert result.ok and result.match_count >= 1
    if sys.platform.startswith("linux"):
        assert runner.memory_limit_enforced()


@needs_rg
def test_shell_wrapper_never_evaluates_patterns(tmp_path):
    root = _repo(tmp_path)
    marker = tmp_path / "pwned"
    for pattern in (f"$(touch {marker})", f'"; touch {marker}; "', f"`touch {marker}`"):
        RgRunner(root, memory_limit_mb=512).search(pattern, fixed_strings=True)
    assert not marker.exists()


@needs_rg
@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="RLIMIT_AS is only enforced on Linux")
def test_rg_over_the_memory_cap_is_an_error_not_zero_matches(tmp_path):
    result = RgRunner(_repo(tmp_path), memory_limit_mb=4).search("executeQuery")
    assert not result.ok
    assert "abnormally" in result.error or result.error


def test_abnormal_exit_is_never_reported_as_no_matches(tmp_path, monkeypatch):
    runner = RgRunner(tmp_path, binary="/usr/bin/true")
    monkeypatch.setattr(runner, "validate_pattern", lambda *a, **k: (True, "default", None, None))
    monkeypatch.setattr(runner, "_run_streaming", lambda cmd, timeout: ([], "", False, False, -9))
    result = runner.search("anything")
    assert not result.ok and "abnormally" in result.error
