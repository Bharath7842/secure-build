"""ripgrep literal prefilter for the regex catalog pass.

The gate: for every eligible rule, every file with a Python hit must be in
rg's candidate set (superset), over real code (this repository and the hunt
fixture, every rule against every file regardless of language) and over
synthetic edge cases rg would otherwise skip. Plus: triage output is
identical with and without the prefilter.
"""

import os
import sys
from pathlib import Path

import pytest

pytest.importorskip("boto3", reason="pipeline modules import llm_client")

_BACKEND = Path(__file__).resolve().parents[1]
_ENGINE_DIR = _BACKEND / "sast_engine"
if str(_ENGINE_DIR) not in sys.path:
    sys.path.insert(0, str(_ENGINE_DIR))

from pipeline import llm_file_scan, regex_scan  # noqa: E402
from pipeline.hunt.rg_runner import RgRunner, find_rg_binary  # noqa: E402
from pipeline.regex_scan import RegexRule  # noqa: E402
from pipeline.rg_prefilter import build_prefilter, required_literal, rules_for_path_fn  # noqa: E402

needs_rg = pytest.mark.skipif(find_rg_binary() is None, reason="ripgrep (rg) is not installed")
CATALOG = regex_scan.load_rules(_ENGINE_DIR / "rules")
_CORPUS_SKIP = {"node_modules", ".next", ".git", "__pycache__", ".venv", "venv", ".pytest_cache"}
_CORPUS_EXTS = {".py", ".java", ".ts", ".tsx", ".js", ".xml", ".json", ".md", ".properties", ".yml", ".yaml", ".html", ".sql", ".txt"}


@pytest.mark.parametrize("pattern,expected", [
    (r"(?i)password\s*=", ("password", True)),
    (r"new\s+SecretKeySpec\s*\(", ("SecretKeySpec", False)),
    (r"(?:executeQuery|executeUpdate)\(", ("execute", False)),
    (r"(?:foo)?barbaz", ("barbaz", False)),
    (r"x{2,}yyyyy", ("yyyyy", False)),
    (r"(?i)Cipher\.getInstance", ("pher.getInstance".replace("I", ""), True)),
])
def test_required_literal(pattern, expected):
    literal, icase = required_literal(pattern)
    # Under IGNORECASE the run breaks at i/I (Python also matches U+0130/U+0131).
    if expected[1]:
        assert "i" not in literal.lower()
    assert icase == expected[1]
    assert literal in pattern.replace("\\", "")


@pytest.mark.parametrize("pattern", [
    r"(password|pwd)\s*=",       # alternation: nothing required
    r"a(?i:bcdef)g",             # local inline flag
    r"ab.c",                     # literal too short
    r"(?:abcdef)?x",             # optional group
    "caféab",               # non-ASCII breaks the run; what's left is too short
])
def test_no_literal_means_full_python_scan(pattern):
    assert required_literal(pattern) is None


# PREFILTER_CORPUS_LIMIT=5000 for a thorough gate run; the default keeps the
# suite quick while still exercising dozens of eligible rules.
def _corpus_files(root: Path, limit: int = int(os.environ.get("PREFILTER_CORPUS_LIMIT", "600"))):
    out = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _CORPUS_SKIP]
        for name in filenames:
            path = Path(dirpath) / name
            if path.suffix.lower() in _CORPUS_EXTS and path.stat().st_size < 1_000_000:
                out.append(path.relative_to(root).as_posix())
                if len(out) >= limit:
                    return out
    return out


def _python_hit_files(root: Path, paths, rules):
    hits = {r.id: set() for r in rules}
    for rel in paths:
        text = (root / rel).read_text(encoding="utf-8", errors="replace")
        for rule in rules:
            if regex_scan.scan_text_by_rule(text, rule):
                hits[rule.id].add(rel)
    return hits


@needs_rg
@pytest.mark.parametrize("corpus", ["repository", "hunt_fixture"])
def test_prefilter_is_a_superset_of_python_hits_on_real_code(corpus):
    root = _BACKEND.parent if corpus == "repository" else _BACKEND / "tests" / "fixtures" / "hunt_java"
    paths = _corpus_files(root)
    pre = build_prefilter(root, paths, CATALOG)
    assert pre is not None and pre.eligible, "expected most catalog rules to be prefilter-eligible"
    hits = _python_hit_files(root, paths, CATALOG)
    violations = {
        rule_id: sorted(hits[rule_id] - pre.candidates[rule_id])[:3]
        for rule_id in pre.eligible
        if hits[rule_id] - pre.candidates[rule_id]
    }
    assert violations == {}
    # The repository corpus must actually exercise the gate (the small hunt
    # fixture's catalog hits all come from alternation rules, which are
    # ineligible and so always run in full).
    if corpus == "repository":
        assert sum(len(hits[r]) for r in pre.eligible) > 10


@needs_rg
def test_prefilter_covers_files_rg_would_normally_skip(tmp_path):
    rule = RegexRule({"id": "tok", "pattern": r"(?i)secret_token\s*=", "cwe": "CWE-798"})
    sensitive = RegexRule({"id": "fixed", "pattern": r"dangerCall\(", "cwe": "CWE-20"})
    files = {
        ".env": "SECRET_TOKEN = abc\n",                                    # hidden file
        "big/Huge.java": ("// pad\n" * 400_000) + "dangerCall(x);\n",        # > 2 MB
        "bin/Nul.java": "a\x00b\ndangerCall(x);\n",                          # NUL byte
        "target/Skip.java": "dangerCall(y);\n",                              # engine skip dir name
        "Upper.java": "SECRET_TOKEN=1\n",                                    # case-insensitive
        "Kelvin.java": "SECRET_TOKEN = 2\n",                            # K (U+212A) folds to k
        "LongS.java": "ſECRET_TOKEN = 3\n",                             # long s folds to s
    }
    for rel, text in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    real = tmp_path / "real" / "Linked.java"
    real.parent.mkdir()
    real.write_text("dangerCall(z);\n", encoding="utf-8")
    (tmp_path / "Linked.java").symlink_to(real)

    paths = list(files) + ["Linked.java", "real/Linked.java"]
    pre = build_prefilter(tmp_path, paths, [rule, sensitive])
    hits = _python_hit_files(tmp_path, paths, [rule, sensitive])
    for r in (rule, sensitive):
        assert r.id in pre.eligible
        assert hits[r.id] <= pre.candidates[r.id], (r.id, hits[r.id] - pre.candidates[r.id])
    assert {".env", "Upper.java", "Kelvin.java", "LongS.java"} <= hits["tok"]
    assert {"big/Huge.java", "bin/Nul.java", "target/Skip.java", "Linked.java"} <= hits["fixed"]


@needs_rg
def test_failed_search_falls_back_to_full_scan(tmp_path, monkeypatch):
    (tmp_path / "A.java").write_text("dangerCall(x);\n", encoding="utf-8")
    rule = RegexRule({"id": "fixed", "pattern": r"dangerCall\(", "cwe": "CWE-20"})
    runner = RgRunner(tmp_path, allowed_files=["A.java"])
    original = runner.search

    def truncated(*args, **kwargs):
        result = original(*args, **kwargs)
        result.output_truncated = True
        return result

    monkeypatch.setattr(runner, "search", truncated)
    pre = build_prefilter(tmp_path, ["A.java"], [rule], runner=runner)
    assert "fixed" in pre.ineligible and "fixed" not in pre.eligible
    assert [r.id for r in pre.rules_for("A.java", [rule])] == ["fixed"]


@needs_rg
def test_triage_findings_identical_with_and_without_prefilter():
    root = _BACKEND / "tests" / "fixtures" / "hunt_java"
    paths = _corpus_files(root)
    entries = [{"path": p, "module": "(root)", "lang": "java", "risk_level": "MEDIUM"} for p in paths]

    def run(rules_for_path):
        out = llm_file_scan.scan_triage_files(
            module_plan={"files": entries}, entries=entries, repo_root=root, rules=CATALOG,
            triage_mode=llm_file_scan.TRIAGE_MODE_REGEX_ONLY, file_workers=1,
            rules_for_path=rules_for_path,
        )
        return sorted(
            (f["file_path"], g["rule_id"], g["line"], g["matched_text"])
            for f in out["files"] for g in f["findings"]
        )

    baseline = run(None)
    pre = build_prefilter(root, paths, CATALOG)
    assert baseline, "fixture should produce catalog findings"
    assert run(rules_for_path_fn(pre, CATALOG)) == baseline


def test_no_rg_means_no_prefilter(tmp_path):
    rule = RegexRule({"id": "fixed", "pattern": r"dangerCall\(", "cwe": "CWE-20"})
    assert build_prefilter(tmp_path, ["A.java"], [rule], runner=RgRunner(tmp_path, binary="")) is None
    assert rules_for_path_fn(None, [rule]) is None
