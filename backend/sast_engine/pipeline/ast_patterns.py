"""ast_patterns.py — greps `ast_rules.json` patterns against the cached AST.

Mirrors the shape of `pipeline/regex_scan.py`'s `RegexRule`/`load_rules`, but
matches against tree-sitter node text already persisted in the SQLite AST
cache (`pipeline/ast_index.py`) instead of re-reading files line by line:
for each rule, pull every `ast_nodes` row whose `node_type`/`lang` match,
then `re.search` the rule's pattern against that node's captured text —
i.e. "grep, scoped to AST nodes of the right shape" rather than a flat
line-oriented regex pass.
"""

from __future__ import annotations

import json
import re
import sqlite3
from pathlib import Path
from typing import Any, Dict, List


class AstRule:
    __slots__ = (
        "id", "title", "description", "cwe", "severity", "category", "cvss",
        "languages", "node_types", "pattern", "regex", "requires_confirmation",
    )

    def __init__(self, raw: Dict[str, Any]):
        self.id = raw["id"]
        self.title = raw.get("title", self.id)
        self.description = raw.get("description", "")
        self.cwe = raw.get("cwe", "")
        self.severity = raw.get("severity", "MEDIUM")
        self.category = raw.get("category", "code")
        self.cvss = raw.get("cvss")
        self.languages = set(raw.get("languages") or [])
        self.node_types = list(raw.get("node_types") or [])
        self.pattern = raw["pattern"]
        self.regex = re.compile(self.pattern)
        self.requires_confirmation = bool(raw.get("requires_confirmation", True))


def load_ast_rules(rules_path: Path) -> List[AstRule]:
    raw = json.loads(Path(rules_path).read_text(encoding="utf-8"))
    rules: List[AstRule] = []
    for entry in raw:
        try:
            rules.append(AstRule(entry))
        except re.error:
            continue
    return rules


def _snippet(text: str, max_len: int = 160) -> str:
    text = text.strip()
    return text[:max_len] + "..." if len(text) > max_len else text


def query_ast_findings(conn: sqlite3.Connection, rules: List[AstRule], langs: set) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    for rule in rules:
        applicable_langs = (rule.languages & langs) if rule.languages else langs
        if not applicable_langs or not rule.node_types:
            continue
        placeholders_types = ",".join("?" for _ in rule.node_types)
        placeholders_langs = ",".join("?" for _ in applicable_langs)
        query = (
            f"SELECT file_path, line_number, node_text FROM ast_nodes "
            f"WHERE node_type IN ({placeholders_types}) AND lang IN ({placeholders_langs})"
        )
        rows = conn.execute(query, [*rule.node_types, *applicable_langs]).fetchall()
        for file_path, line_number, node_text in rows:
            if node_text is None:
                continue
            if rule.regex.search(node_text):
                findings.append({
                    "rule_id": rule.id,
                    "title": rule.title,
                    "category": rule.category,
                    "cwe": rule.cwe,
                    "severity": rule.severity,
                    "cvss": rule.cvss,
                    "file_path": file_path,
                    "line_number": line_number,
                    "code_snippet": _snippet(node_text),
                    "requires_confirmation": rule.requires_confirmation,
                    "description": rule.description,
                })
    return findings


def node_ast_pattern_queries(state: Dict[str, Any]) -> dict:
    """Loads ast_rules.json, runs every applicable rule against the cached
    AST for this scan, and returns raw findings (pre-confirmation)."""
    tracer = state["_tracer"]
    db_path = state.get("ast_db_path")
    if not db_path or not Path(db_path).exists():
        tracer.log(5, "ast_patterns", "No AST cache available — skipping pattern queries",
                    narrative="No AST database to query — skipping AST pattern matching.")
        return {"ast_findings": []}

    rules_path = Path(state.get("ast_rules_path") or (Path(__file__).resolve().parent.parent / "ast_rules.json"))
    if not rules_path.is_file():
        tracer.log(5, "ast_patterns", f"ast_rules.json missing at {rules_path}", detail=str(rules_path))
        return {"ast_findings": []}

    rules = load_ast_rules(rules_path)
    conn = sqlite3.connect(db_path)
    try:
        langs = {row[0] for row in conn.execute("SELECT DISTINCT lang FROM ast_nodes").fetchall()}
        tracer.log(5, "ast_patterns", f"Running {len(rules)} AST pattern rule(s) against languages: {sorted(langs)}",
                    narrative=f"Grepping the AST for {len(rules)} known vulnerability pattern(s) "
                              f"across {', '.join(sorted(langs)) or '(no indexed languages)'}...")
        findings = query_ast_findings(conn, rules, langs)
    finally:
        conn.close()

    tracer.log(5, "ast_patterns", f"AST pattern queries complete: {len(findings)} raw finding(s)",
                detail=f"by_rule={sorted({f['rule_id'] for f in findings})}",
                narrative=f"Found {len(findings)} raw match(es) — next, confirming which are worth an LLM look.")
    return {"ast_findings": findings}
