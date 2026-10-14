"""Learned-rule promotion gates (pipeline/hunt/learned.py)."""

import sys
from pathlib import Path

import pytest

pytest.importorskip("boto3", reason="pipeline modules import llm_client")

_ENGINE_DIR = Path(__file__).resolve().parents[1] / "sast_engine"
if str(_ENGINE_DIR) not in sys.path:
    sys.path.insert(0, str(_ENGINE_DIR))

from pipeline.hunt.learned import (  # noqa: E402
    STATUS_PROMOTED,
    STATUS_REJECTED,
    Candidate,
    candidates_from_investigations,
    evaluate_candidates,
)
from pipeline.hunt.rg_runner import RgRunner, find_rg_binary  # noqa: E402

needs_rg = pytest.mark.skipif(find_rg_binary() is None, reason="ripgrep (rg) is not installed")


def _repo(tmp_path, files):
    for rel, text in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    return RgRunner(tmp_path, allowed_files=list(files)), lambda rel: (tmp_path / rel).read_text().splitlines()


def test_candidates_come_only_from_model_written_searches_that_surfaced_the_sink():
    searches = {"S1": [
        {"tool": "search", "model_written": True, "pattern": r"st\.executeQuery\(\"SELECT", "shown": [("Dao.java", 15)]},
        {"tool": "search", "model_written": True, "pattern": "unrelated", "shown": [("Other.java", 3)]},
        {"tool": "search_sinks", "model_written": False, "pattern": "seed", "shown": [("Dao.java", 15)]},
        {"tool": "search", "model_written": True, "pattern": "typo(", "relaxed_pattern": "typo", "shown": [("Dao.java", 14)]},
    ]}
    confirmed = [{"file_path": "Dao.java", "line": 15, "cwe": "CWE-89", "title": "SQLi", "hypothesis_id": "S1"}]
    cands = {c.pattern: c for c in candidates_from_investigations(searches, confirmed)}
    # The relaxed variant the engine actually ran is what gets credited.
    assert set(cands) == {r"st\.executeQuery\(\"SELECT", "typo"}
    assert cands["typo"].positives == {("Dao.java", 15)}


@needs_rg
def test_promotion_requires_positives_no_negatives_and_low_noise(tmp_path):
    runner, read = _repo(tmp_path, {
        "Dao.java": 'class Dao {\n  void a(String n) { st.executeQuery("SELECT * FROM t WHERE n=\'" + n + "\'"); }\n}\n',
        "Safe.java": 'class Safe {\n  void b() { st.executeQuery("SELECT * FROM t WHERE n=\'" + CONST + "\'"); }\n}\n',
        "Noise.java": "".join(f"log.info(x{i});\n" for i in range(80)),
    })
    good = Candidate(pattern=r"executeQuery\(\"SELECT .*\+ n \+", cwe="CWE-89", title="SQLi", positives={("Dao.java", 2)})
    broad = Candidate(pattern=r"executeQuery\(", cwe="CWE-89", title="SQLi", positives={("Dao.java", 2)})
    noisy = Candidate(pattern=r"log\.info\(|void a\(String", cwe="CWE-117", title="Log", positives={("Dao.java", 2)})
    misses = Candidate(pattern=r"prepareStatement\(", cwe="CWE-89", title="SQLi", positives={("Dao.java", 2)})
    python_only = Candidate(pattern=r"(?<=st\.)executeQuery", cwe="CWE-89", title="SQLi", positives={("Dao.java", 2)})

    rows = {r["pattern"]: r for r in evaluate_candidates(
        [good, broad, noisy, misses, python_only], negatives=[("Safe.java", 2)], runner=runner, read_lines=read,
    )}
    assert rows[good.pattern]["status"] == STATUS_PROMOTED
    assert rows[good.pattern]["rule"]["derived"] is True
    assert rows[good.pattern]["repo_matches"] == 1
    assert rows[broad.pattern]["status"] == STATUS_REJECTED
    assert "refuted/disputed" in rows[broad.pattern]["reasons"][0]
    assert "repository-wide" in rows[noisy.pattern]["reasons"][0]
    assert "misses 1" in rows[misses.pattern]["reasons"][0]
    # Valid in Python but rg (no PCRE2 build) can't measure it: never promoted blind.
    assert rows[python_only.pattern]["status"] == STATUS_REJECTED


def test_invalid_python_regex_is_rejected(tmp_path):
    runner = RgRunner(tmp_path, binary="")
    rows = evaluate_candidates([Candidate(pattern="(unclosed", cwe="CWE-89", title="x", positives={("A.java", 1)})],
                               negatives=[], runner=runner, read_lines=lambda _f: ["x"])
    assert rows[0]["status"] == STATUS_REJECTED
    assert "not a valid Python regex" in rows[0]["reasons"][0]
