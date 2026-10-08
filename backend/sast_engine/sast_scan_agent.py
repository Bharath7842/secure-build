#!/usr/bin/env python3
"""
sast_scan_agent.py — Agentic SAST project discovery agent (LangGraph)

Pipeline:
  node_scan_directory      -> walk the project, list files/folders, note types & depth
  node_analyze_tech_stack  -> three deterministic, LLM-free evidence passes: marker-file
                               heuristic, dependency-manifest parsing + signature matching
                               (pipeline/dependency_scan.py — any ecosystem, not just
                               Java/Angular), and tree-sitter AST structure (Java/Angular
                               only) -> stack / project type / risk areas
  node_categorize_files    -> buckets files: source / config / dependency / test / build / other
  node_map_modules_and_risk -> stack-specific module & per-file risk mapping (CRITICAL /
                               HIGH / MEDIUM / LOW), with a generic fallback so the agent
                               never dead-ends on an unrecognized stack
  node_build_call_graph    -> Java call graph (no-op on other stacks)
  node_discover_flows      -> typed-sink flows across files
  node_verify_flow_slices  -> LLM-verify full-body slices of those flows
  node_derive_runtime_rules -> extra regex from call-graph wrappers + optional LLM pass
  node_scan_deep_files     -> LLM-primary detect+triage of every CRITICAL / HIGH file
  node_scan_triage_files   -> regex scan of MEDIUM / LOW files; LLM triages the hits only
  node_generate_report     -> TP/FP rollup across flow + deep + triage stages

This agent maps a repo's structure, tech stack, and file-level risk, then runs
vulnerability detection: an LLM-primary scan of CRITICAL/HIGH files, and a
regex-gated pass over MEDIUM/LOW files where a file with no regex hit costs no
LLM call at all and a file with hits sends only those hits plus their context
windows. Standalone CLI runs may optionally persist JSON + SQLite after the
graph finishes (`--out` / `--db`).

Every node emits structured trace events (AgentTrace) so you can see exactly what the
agent looked at and why — printed live via plain `print()` (captured by the API's
live scan log), and always saved in full inside the state's "trace" key.

Usage:
    python sast_scan_agent.py --path /path/to/project
    python sast_scan_agent.py --path /path/to/project --verbose-files --db sast_history.db --out ./sast_output
    python sast_scan_agent.py --path /path/to/project --no-llm
    python sast_scan_agent.py --path /path/to/project --llm-provider ollama --llm-model granite-code:3b
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sqlite3
import sys
import uuid
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple, TypedDict

from langgraph.graph import END, START, StateGraph

_ENGINE_DIR = Path(__file__).resolve().parent
if str(_ENGINE_DIR) not in sys.path:
    sys.path.insert(0, str(_ENGINE_DIR))

try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:
    pass

from llm_client import init_usage, usage_cost_summary  # noqa: E402
import ast_struct  # noqa: E402
from pipeline import call_graph, call_graph_python, dependency_scan, derive_rules, flow_verify, llm_file_scan, regex_scan  # noqa: E402

# ===========================================================================
# 0. CONFIG — extension map, skip dirs, per-stack risk profiles
# ===========================================================================

EXT_LANG_MAP: Dict[str, str] = {
    ".java": "Java", ".kt": "Kotlin", ".scala": "Scala",
    ".py": "Python", ".pyi": "Python (stub)",
    ".js": "JavaScript", ".jsx": "JavaScript (React)",
    ".ts": "TypeScript", ".tsx": "TypeScript (React)",
    ".php": "PHP", ".cs": "C#", ".vb": "VB.NET",
    ".go": "Go", ".rb": "Ruby", ".rs": "Rust", ".c": "C", ".cpp": "C++", ".h": "C/C++ Header",
    ".html": "HTML",
    ".sql": "SQL",
    ".yml": "YAML", ".yaml": "YAML",
    ".json": "JSON", ".xml": "XML", ".toml": "TOML",
    ".properties": "Java Properties", ".env": "Env File",
    ".sh": "Shell", ".ps1": "PowerShell", ".bat": "Batch",
    ".dockerfile": "Docker", ".tf": "Terraform",
    ".md": "Markdown",
}

# Extension -> rule-catalog "languages" tag vocabulary. Deliberately a
# Directories that are never worth scanning for source-level SAST findings.
# Note: any directory starting with "." is skipped regardless of this list
# (see node_scan_directory) — .git, .settings, .idea, etc. are pruned that way.
DEFAULT_SKIP_DIRS = {
    ".git", ".svn", ".hg",
    "node_modules", "bower_components",
    "target", "build", "dist", "out", "bin", "obj",
    "__pycache__", ".mypy_cache", ".pytest_cache",
    ".venv", "venv", "env",
    ".idea", ".vscode", ".vs",
    "vendor", ".gradle", ".mvn", ".angular", ".next", "coverage",
    "config", "configuration", "cvs", "xsd",
}
_SKIP_DIRS_LOWER = {d.lower() for d in DEFAULT_SKIP_DIRS}

# Purely presentational/binary assets — never security-relevant, excluded
# from the walk entirely (not counted, not categorized, not risk-mapped).
SKIP_FILE_EXTS = {
    ".css", ".scss", ".sass", ".less",
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".bmp",
    # Compiled / binary artifacts — not human-readable source; LLM cannot review.
    ".class", ".jar", ".war", ".ear", ".pyc", ".pyo",
    ".dll", ".so", ".dylib", ".exe", ".bin", ".o", ".a", ".lib",
    ".woff", ".woff2", ".ttf", ".eot",
    ".mp3", ".mp4", ".wav", ".avi", ".mov", ".wasm",
    ".xsd", ".wsdl", ".dtd", ".compose", ".parse",
    ".library", ".prefs", ".project", ".classpath",
    ".jpx", ".jbx", ".jsdtscope",
    ".map", ".gz", ".crt", ".pid", ".csv", ".mf", ".name",
}

# Tooling/VCS metadata files and build-tool wrapper scripts — noise, not
# application code.
SKIP_FILENAMES = {
    ".gitignore", ".gitattributes", ".gitmodules", ".gitkeep",
    ".dockerignore", ".npmignore", ".eslintignore", ".prettierignore",
    ".editorconfig",
    "mvnw", "mvnw.cmd", "gradlew", "gradlew.bat",
    ".cvsignore", ".project", ".classpath", ".jsdtscope", ".prefs",
    "MANIFEST.MF",
}
_SKIP_FILENAMES_LOWER = {name.lower() for name in SKIP_FILENAMES}
_LOG4J_SKIP_EXTS = {".xml", ".dtd"}

# Unit-test/spec scaffolding — excluded outright rather than just bucketed
# LOW risk, since it's pure test boilerplate.
SKIP_FILENAME_SUFFIXES = (
    ".spec.ts", ".spec.tsx", ".spec.js", ".spec.jsx",
    ".test.ts", ".test.tsx", ".test.js", ".test.jsx",
)

# .properties files are usually build tooling (maven/gradle wrapper), test
# fixtures, i18n resource bundles, or logging config — noise, not application
# code — except files following the Spring Boot naming convention
# (application.properties, application-<profile>.properties), which the
# maven-java risk profile flags CRITICAL for possible embedded secrets and
# must keep being scanned. Anchored to that convention: a bare "starts with
# application" prefix would let Struts-style ApplicationResources*.properties
# slip through.
_SPRING_PROPERTIES_RE = re.compile(r"^application(-[\w.]+)?\.properties$", re.IGNORECASE)


def _is_excluded_properties_file(fname: str, ext: str) -> bool:
    return ext == ".properties" and not _SPRING_PROPERTIES_RE.match(fname)


def _is_skipped_walk_file(fname: str, ext: str) -> bool:
    fname_l = fname.lower()
    return (
        ext in SKIP_FILE_EXTS
        or fname_l in _SKIP_FILENAMES_LOWER
        or fname.endswith(SKIP_FILENAME_SUFFIXES)
        or _is_excluded_properties_file(fname, ext)
        or ("log4j" in fname_l and ext in _LOG4J_SKIP_EXTS)
    )


RiskRule = tuple  # (pattern, risk_level, reason, category) — matched against POSIX relative path

# Per-stack module/risk profiles. `markers` = files whose presence identifies the stack.
# `rules` are evaluated top-to-bottom, first match wins (specific before generic).
STACK_PROFILES: Dict[str, Dict[str, Any]] = {
    "maven-java": {
        "label": "Maven / Java",
        "markers": ["pom.xml"],
        "rules": [
            (r"(^|/)pom\.xml$",                                   "MEDIUM",   "dependency & plugin manifest",        "dependency"),
            (r"(^|/)src/main/java/.*/(controller|controllers|web|rest)/", "HIGH",     "user input entry point (controller layer)", "source"),
            (r"(^|/)src/main/java/.*(ExceptionHandler|ControllerAdvice)\w*\.java$", "HIGH", "exception handler / controller advice (builds HTTP responses from exception data, regardless of package)", "source"),
            (r"(^|/)src/main/java/.*(SecurityConfig|WebSecurityConfig|SecurityFilterChain)\w*\.java$", "CRITICAL", "Spring Security configuration (CSRF/CORS/authorization rules, regardless of package)", "source"),
            (r"(^|/)src/main/java/.*/(service|services)/",        "HIGH",     "business logic",                      "source"),
            (r"(^|/)src/main/java/.*/(repository|repositories|dao)/", "CRITICAL", "database queries (injection surface)", "source"),
            (r"(^|/)src/main/java/.*/(security|auth)/",           "CRITICAL", "authentication / authorization logic", "source"),
            (r"(^|/)src/main/java/.*/(util|utils|helper|helpers)/", "MEDIUM",   "utility code",                        "source"),
            (r"(^|/)src/main/java/",                               "MEDIUM",   "application source (unclassified package)", "source"),
            (r"(^|/)src/main/resources/application[-.].*\.(properties|ya?ml)$", "CRITICAL", "runtime config — possible embedded secrets", "config"),
            (r"(^|/)src/main/resources/",                          "MEDIUM",   "resources / static config",           "config"),
            (r"(^|/)src/test/",                                    "LOW",      "test code",                           "test"),
        ],
    },
    "angular": {
        "label": "Angular",
        "markers": ["angular.json"],
        "rules": [
            (r"(^|/)package\.json$",                    "MEDIUM",   "dependency manifest",                   "dependency"),
            (r"environment(\.\w+)?\.ts$",                "CRITICAL", "env config — possible API keys/secrets", "config"),
            (r"\.guard\.ts$",                            "CRITICAL", "route auth guard",                      "source"),
            (r"\.interceptor\.ts$",                      "HIGH",     "HTTP interceptor (auth headers, tokens)", "source"),
            (r"\.service\.ts$",                          "HIGH",     "business logic / API calls",            "source"),
            (r"\.component\.ts$",                        "HIGH",     "user input & rendering (XSS surface)",  "source"),
            (r"\.(spec|test)\.ts$",                       "LOW",      "test code",                             "test"),
            (r"\.ts$",                                    "MEDIUM",   "application source (unclassified)",     "source"),
        ],
    },
    "dotnet": {
        "label": ".NET",
        "markers": [".csproj", ".sln"],
        "rules": [
            (r"\.(csproj|sln)$",                          "MEDIUM",   "project / dependency manifest",         "dependency"),
            (r"(^|/)Controllers?/",                       "HIGH",     "user input entry point",                "source"),
            (r"(^|/)Services?/",                           "HIGH",     "business logic",                        "source"),
            (r"(^|/)(Repositor(y|ies)|Data)/",             "CRITICAL", "database access (injection surface)",   "source"),
            (r"(^|/)(Auth|Identity|Security)/",            "CRITICAL", "authentication / authorization logic",  "source"),
            (r"appsettings(\..*)?\.json$",                 "CRITICAL", "runtime config — possible embedded secrets", "config"),
            (r"(^|/)Tests?/",                              "LOW",      "test code",                             "test"),
            (r"\.cs$",                                     "MEDIUM",   "application source (unclassified)",     "source"),
        ],
    },
    "python": {
        "label": "Python",
        "markers": ["requirements.txt", "pyproject.toml", "setup.py"],
        "rules": [
            (r"(^|/)(requirements.*\.txt|pyproject\.toml|setup\.py|Pipfile)$", "MEDIUM", "dependency manifest", "dependency"),
            (r"(^|/)(views|routes|api)\.py$",               "HIGH",     "user input entry point",                "source"),
            (r"(^|/)(routes?|views?|api)/",                 "HIGH",     "user input entry point",                "source"),
            (r"(^|/)(main|app|server|asgi|wsgi)\.py$",      "HIGH",     "app/route entrypoint (FastAPI/Flask apps commonly define every route here, regardless of filename)", "source"),
            (r"(^|/)(models?)\.py$|(^|/)models?/",          "CRITICAL", "database / ORM layer (injection surface)", "source"),
            (r"(^|/)(auth|security)/|(^|/)(auth|security)\.py$", "CRITICAL", "authentication / authorization logic", "source"),
            (r"(^|/)settings\.py$|(^|/)config\.py$|\.env$", "CRITICAL", "runtime config — possible embedded secrets", "config"),
            (r"(^|/)tests?/|test_.*\.py$|.*_test\.py$",     "LOW",      "test code",                             "test"),
            (r"\.py$",                                      "MEDIUM",   "application source (unclassified)",     "source"),
        ],
    },
    "nodejs-generic": {
        "label": "Node.js (generic / Express-style)",
        "markers": ["package.json"],
        "rules": [
            (r"(^|/)package\.json$",                        "MEDIUM",   "dependency manifest",                   "dependency"),
            (r"(^|/)(routes?|controllers?)/",                "HIGH",     "user input entry point",                "source"),
            (r"(^|/)(index|app|server)\.js$",                "HIGH",     "app/route entrypoint (small Express apps commonly define every route here, regardless of filename)", "source"),
            (r"(^|/)(models?|db|prisma)/",                   "CRITICAL", "database layer (injection surface)",    "source"),
            (r"(^|/)(auth|middleware)/",                     "CRITICAL", "authentication / authorization logic",  "source"),
            (r"\.env(\..*)?$|(^|/)config.*\.(js|json)$",     "CRITICAL", "runtime config — possible embedded secrets", "config"),
            (r"(^|/)(test|tests)/|\.(spec|test)\.js$",       "LOW",      "test code",                             "test"),
            (r"\.js$",                                       "MEDIUM",   "application source (unclassified)",     "source"),
        ],
    },
}

# Applied when no stack profile above matched a given file — keeps the agent useful on
# unrecognized stacks instead of silently skipping everything.
GENERIC_FALLBACK_RULES: List[RiskRule] = [
    (r"\.(env|pem|key|pfx|p12)$",                 "CRITICAL", "credential/secret-like file",           "config"),
    (r"(^|/)(config|conf|settings)/",              "HIGH",     "configuration directory",               "config"),
    (r"(^|/)(auth|security)/",                     "CRITICAL", "likely auth/authz code",                "source"),
    (r"(^|/)pom\.xml$|(^|/)build\.gradle(\.kts)?$", "MEDIUM",  "dependency / build manifest",           "dependency"),
    (r"(^|/)package\.json$",                        "MEDIUM",   "dependency manifest",                   "dependency"),
    (r"(^|/)(requirements.*\.txt|pyproject\.toml|setup\.py|Pipfile)$", "MEDIUM", "dependency manifest", "dependency"),
    (r"\.(csproj|sln)$",                            "MEDIUM",   "project / dependency manifest",         "dependency"),
    (r"\.java$",                                    "MEDIUM",   "Java source (unclassified)",              "source"),
    (r"\.tsx?$",                                    "MEDIUM",   "TypeScript source (unclassified)",        "source"),
    (r"\.py$",                                      "MEDIUM",   "Python source (unclassified)",            "source"),
    (r"(^|/)(test|tests|spec|specs)/|\.(spec|test)\.(java|tsx?|py)$", "LOW", "test code",                "test"),
    (r".*",                                         "LOW",      "unclassified file",                     "other"),
]

DEPENDENCY_MARKER_FILES = {
    "pom.xml": "maven-java", "build.gradle": "maven-java", "build.gradle.kts": "maven-java",
    "package.json": "nodejs-generic", "angular.json": "angular",
    "requirements.txt": "python", "pyproject.toml": "python", "setup.py": "python", "Pipfile": "python",
    "go.mod": "go-generic",
    "Gemfile": "ruby-generic", "composer.json": "php-generic", "Cargo.toml": "rust-generic",
}
DEPENDENCY_MARKER_EXTS = {".csproj": "dotnet", ".sln": "dotnet"}


# ===========================================================================
# 1. TRACE — visibility into what the agent is doing at every step
# ===========================================================================

# Human-readable section labels, printed once as a "### <label>" banner the
# first time each step logs — the frontend's live agent feed splits on this
# marker to group narration into sections without needing structured events.
STEP_LABELS = {
    1: "Scanning the repository",
    2: "Detecting the tech stack",
    3: "Categorizing files",
    4: "Mapping module risk",
    5: "Deriving runtime regex",
    6: "Tracing inter-file flows",
    7: "Scanning CRITICAL/HIGH files",
    8: "Scanning MEDIUM/LOW files",
    9: "Grouping MEDIUM/LOW findings",
    10: "Generating report",
}

DEFAULT_RECURSION_LIMIT = 500


def invoke_graph(graph, state: dict, *, recursion_limit: Optional[int] = None):
    """Invoke the discovery/AST graph with a generous recursion limit."""
    if recursion_limit is None:
        raw = os.environ.get("SAST_GRAPH_RECURSION_LIMIT", str(DEFAULT_RECURSION_LIMIT))
        try:
            recursion_limit = max(25, int(raw))
        except ValueError:
            recursion_limit = DEFAULT_RECURSION_LIMIT
    return graph.invoke(state, config={"recursion_limit": recursion_limit})



class AgentTrace:
    """Collects structured step-by-step events (always kept in full, for the JSON trace)
    and — when verbose — prints a natural-language narration of what's happening. The
    prints are what the API's live scan log tails, so narration doubles as the UI feed."""

    def __init__(self, verbose: bool = True):
        self.verbose = verbose
        self.events: List[Dict[str, Any]] = []
        self._last_step: Optional[int] = None

    def log(self, step: int, node: str, message: str, detail: Optional[str] = None,
            narrative: Optional[str] = None) -> None:
        entry = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "step": step,
            "node": node,
            "message": message,
            "detail": detail,
        }
        self.events.append(entry)
        if self.verbose and step != self._last_step:
            self._last_step = step
            print(f"### {STEP_LABELS.get(step, node.replace('_', ' '))}")
        if self.verbose and narrative:
            print(narrative)

    def say(self, text: str, end: str = "\n") -> None:
        """Print a line with no structured event behind it — pure narration."""
        if self.verbose:
            print(text, end=end, flush=True)


# ===========================================================================
# 2. STATE — what flows between LangGraph nodes
# ===========================================================================

class SastState(TypedDict, total=False):
    local_path: str
    scope: Optional[str]
    context_note: str
    project_name: str
    scan_id: str
    verbose: bool
    verbose_files: bool
    use_llm: bool
    llm_provider: Optional[str]
    llm_model: Optional[str]
    fallback_llm_provider: Optional[str]
    fallback_llm_model: Optional[str]
    persist_to_disk: bool
    output_dir: str
    db_path: str
    regex_rules_path: str             # override rules dir or file (defaults to ./rules next to this file)
    deep_scan_file_cap: int           # override for llm_file_scan.DEEP_SCAN_FILE_CAP
    backfill_deep_scan: bool          # fill unused deep-scan slots with MEDIUM/LOW when CRITICAL/HIGH is under cap; default True
    # When True, only CRITICAL files get the full deep-scan LLM pass; HIGH
    # moves into the triage tier alongside MEDIUM/LOW (pair with
    # triage_mode="llm_triage" for regex-gated LLM confirmation on HIGH too).
    # Default False (HIGH stays in the deep-scan bucket, current behavior).
    deep_scan_critical_only: bool
    triage_batch_size: int            # override for node_scan_triage_files' _DEFAULT_TRIAGE_BATCH_SIZE
    triage_mode: str                  # "regex_only" (default) | "llm_triage" — see llm_file_scan
    # Group unverified MEDIUM/LOW findings by construct and report the
    # collapse (node_group_triage_findings) — no LLM call, verdicts untouched.
    # Default True; only has an effect when triage_mode is regex_only.
    group_triage_mode: bool
    # LLM-confirm TP/FP for unverified MEDIUM/LOW groups after grouping
    # (node_confirm_triage_groups). Opt-in — default False/absent.
    confirm_triage_groups: bool
    triage_confirm_group_cap: int        # override for llm_file_scan.TRIAGE_CONFIRM_GROUP_CAP
    triage_confirm_groups_per_call: int  # override for llm_file_scan.DEFAULT_GROUPS_PER_CALL
    # Drop deep-scan (kind=llm) findings with no CWE mapping — too generic to
    # act on. Default True; scan_limitations id "cwe-less-findings-suppressed".
    suppress_no_cwe_findings: bool
    # Drop deep-scan findings about cleartext HTTP / missing HTTPS enforcement.
    # Opt-in per project (HTTPS enforced at a layer the scan can't see) via
    # scan_limitations id "https-enforced-suppress-http". Default False.
    suppress_http_findings: bool
    # Drop deep-scan false_positive-verdict findings the model confidently
    # self-dismissed (confidence <= FALSE_POSITIVE_SUPPRESS_CONFIDENCE_CEILING).
    # Default True in agent_bridge via scan_limitations id
    # "low-confidence-fp-suppressed"; default False here/CLI.
    suppress_low_confidence_false_positives: bool
    # Java inter-file call-graph flows (off when use_llm is false, tree-sitter
    # missing, or the stack is not maven-java). Default True when use_llm.
    inter_file_flow: bool
    flow_verify_cap: int
    flow_max_hop_depth: int
    call_graph: Dict[str, Any]
    flow_candidates: List[Dict[str, Any]]
    flow_scan_results: Dict[str, Any]
    # Runtime regex derived from this scan's analysis (call-graph wrappers +
    # optional LLM pass). Default on; CLI --no-derived-regex / limitations id
    # "runtime-derived-regex". Merged onto the static catalog in _scan_context.
    derive_runtime_rules: bool
    max_derived_regex_rules: int
    derived_rules: List[Any]
    # {compiled, failed, failed_by_reason} — how many derive candidates didn't
    # make it in (unsafe pattern, compile error, duplicate, over cap).
    derived_rules_summary: Dict[str, Any]
    # Injected by the caller (agent_bridge/scan_runner) — called once per
    # scanned file as (file_path, findings) right after that file's scan
    # completes, so persistence happens incrementally.
    findings_writer: Optional[Callable[[str, List[Dict[str, Any]]], None]]
    # Injected by the caller — called once per file with a list of
    # {rule_id, line, verdict, confidence, verdict_reason, ai_fix} updates for
    # findings whose verdict changed after grouped confirmation, so the caller
    # can update the already-persisted rows in place (never a fresh insert).
    verdict_updates_writer: Optional[Callable[[str, List[Dict[str, Any]]], None]]
    # Called after map_modules_and_risk (discovery without report) and again
    # after generate_report (full discovery) so the UI can show Discovery
    # results mid-scan before file scanning finishes.
    discovery_writer: Optional[Callable[[Dict[str, Any]], None]]

    scan: Dict[str, Any]              # node_scan_directory output
    llm_analysis: Dict[str, Any]      # node_analyze_tech_stack output
    categorized: Dict[str, Any]       # node_categorize_files output
    module_plan: Dict[str, Any]       # node_map_modules_and_risk output
    scan_results: Dict[str, Any]         # node_scan_deep_files output
    triage_scan_results: Dict[str, Any]  # node_scan_triage_files output
    triage_group_summary: Dict[str, Any]  # node_group_triage_findings output
    report: Dict[str, Any]            # node_generate_report output
    usage: Dict[str, Any]
    persisted: Dict[str, Any]         # CLI-only disk persist after graph (optional)

    trace: List[Dict[str, Any]]
    _tracer: Any                      # AgentTrace instance (not serialized to JSON)


def to_posix(path: str) -> str:
    return path.replace(os.sep, "/")


def rule_to_dict(rule: Any) -> Dict[str, Any]:
    """Serialize a `RegexRule` (static or derived) for the API/UI."""
    return {
        "id": rule.id,
        "title": rule.title,
        "description": rule.description,
        "cwe": rule.cwe,
        "severity": rule.severity,
        "category": rule.category,
        "owasp": rule.owasp,
        "languages": list(rule.languages),
        "frameworks": list(rule.frameworks),
        "pattern": rule.pattern,
        "derived": bool(getattr(rule, "derived", False)),
    }


def derived_rules_payload(state_or_rules: Any) -> List[Dict[str, Any]]:
    """Serialize `state["derived_rules"]` (or a plain list of `RegexRule`) for
    the API/UI — shared by the mid-scan discovery emit and agent_bridge's
    final discovery blob so both stay in sync."""
    rules = (
        state_or_rules.get("derived_rules")
        if isinstance(state_or_rules, dict)
        else state_or_rules
    ) or []
    return [rule_to_dict(r) for r in rules]


def _build_discovery_payload(
    state: SastState,
    *,
    module_plan: Dict[str, Any] | None = None,
    report: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    """Shape the discovery blob the API/UI consume (matches agent_bridge)."""
    scan_summary = dict(state.get("scan") or {})
    scan_summary.pop("files", None)
    categorized = state.get("categorized") or {}
    return {
        "scan_summary": scan_summary,
        "llm_analysis": state.get("llm_analysis") or {},
        "categorized_counts": {k: len(v) for k, v in categorized.items()},
        "module_plan": module_plan if module_plan is not None else (state.get("module_plan") or {}),
        "derived_rules": derived_rules_payload(state),
        "derived_rules_summary": state.get("derived_rules_summary") or {},
        "report": report,
    }


def _emit_discovery(
    state: SastState,
    *,
    module_plan: Dict[str, Any] | None = None,
    report: Dict[str, Any] | None = None,
) -> None:
    writer = state.get("discovery_writer")
    if not writer:
        return
    writer(_build_discovery_payload(state, module_plan=module_plan, report=report))


# Source languages — shown as package directories only, never as individual files.
_SOURCE_EXTS = {
    ".java", ".kt", ".scala", ".py", ".pyi",
    ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs",
    ".php", ".cs", ".vb", ".go", ".rb", ".rs",
    ".c", ".cpp", ".h", ".hpp", ".vue", ".svelte",
}

# Markers that define a module boundary (Maven module, npm package, …).
_MODULE_MARKER_FILENAMES = set(DEPENDENCY_MARKER_FILES) | {
    "settings.gradle", "settings.gradle.kts",
    "angular.json", "nest-cli.json",
    "Cargo.toml",
}

# Config shown only when it sits beside a module marker (not nested under src/).
_ROOT_CONFIG_FILENAMES = {
    "Dockerfile", "docker-compose.yml", "docker-compose.yaml",
    "tsconfig.json", "jsconfig.json",
    "go.sum",
}


def _is_module_marker(name: str, ext: str) -> bool:
    return name in _MODULE_MARKER_FILENAMES or ext in DEPENDENCY_MARKER_EXTS


def _pom_role_label(rel_path: str) -> str:
    """Annotate Maven poms: root = parent, nested = child."""
    if not rel_path.endswith("pom.xml"):
        return ""
    return " (parent)" if "/" not in rel_path else " (child)"


def _format_project_structure_tree(
    files: List[Dict[str, Any]],
    project_name: str,
    cap: int = 80,
) -> List[str]:
    """Compact module-level project tree for the agent log.

    Shows the project name, module folders, and build markers (pom.xml,
    package.json, …). Source under each module is one summary line — never
    expanded into controller/dto/component folders.
    """
    _MODULE_GROUP_DIRS = frozenset({"modules", "apps", "packages", "libs", "projects"})
    _PKG_SKIP = frozenset({
        "src", "main", "test", "java", "kotlin", "scala", "resources",
        "app", "lib", "components", "pages", "shared",
    })

    markers_by_dir: Dict[str, List[str]] = {}
    module_roots: set[str] = set()
    all_dirs: set[str] = set()

    for f in files:
        name = f["name"]
        ext = f.get("ext") or os.path.splitext(name)[1].lower()
        parent = os.path.dirname(f["path"]) or ""
        parts = [p for p in f["path"].split("/")[:-1] if p]
        for i in range(len(parts)):
            all_dirs.add("/".join(parts[: i + 1]))

        if _is_module_marker(name, ext):
            module_roots.add(parent)
            markers_by_dir.setdefault(parent, []).append(
                f"{name}{_pom_role_label(f['path'])}"
            )

    # Root-level config (tsconfig, Dockerfile, …) beside an existing module marker.
    for f in files:
        name = f["name"]
        parent = os.path.dirname(f["path"]) or ""
        if name in _ROOT_CONFIG_FILENAMES and parent in module_roots:
            existing = markers_by_dir.setdefault(parent, [])
            if name not in existing:
                existing.append(name)

    # Angular/Nx-style: each child of modules/apps/packages is a module even
    # without its own package.json.
    for d in list(all_dirs):
        parent = os.path.dirname(d) or ""
        base = os.path.basename(d)
        parent_base = os.path.basename(parent) if parent else ""
        if parent_base in _MODULE_GROUP_DIRS and base:
            module_roots.add(d)

    def deepest_module(path: str) -> str:
        best = ""
        best_len = -1
        for root in module_roots:
            if root == "":
                if best_len < 0:
                    best, best_len = "", 0
                continue
            if path == root or path.startswith(root + "/"):
                if len(root) > best_len:
                    best, best_len = root, len(root)
        return best

    source_files: Dict[str, int] = {}
    source_packages: Dict[str, set] = {}
    for f in files:
        ext = f.get("ext") or os.path.splitext(f["name"])[1].lower()
        if ext not in _SOURCE_EXTS:
            continue
        mod = deepest_module(f["path"])
        source_files[mod] = source_files.get(mod, 0) + 1

        leaf = os.path.basename(os.path.dirname(f["path"]) or "")
        if leaf and leaf not in _PKG_SKIP:
            source_packages.setdefault(mod, set()).add(leaf)

    root_node: Dict[str, Any] = {"dirs": {}, "is_module": "" in module_roots}

    def ensure_path(rel: str) -> Dict[str, Any]:
        node = root_node
        if not rel:
            return node
        for part in rel.split("/"):
            node = node["dirs"].setdefault(part, {"dirs": {}, "is_module": False})
        return node

    for mod in sorted(module_roots, key=lambda m: (m.count("/"), m)):
        node = ensure_path(mod)
        node["is_module"] = True

    lines: List[str] = [f"{project_name}:"]

    def package_summary(mod: str) -> Optional[str]:
        n = source_files.get(mod, 0)
        if not n:
            return None
        pkgs = sorted(source_packages.get(mod, set()))
        noun = "file" if n == 1 else "files"
        if not pkgs:
            return f"src/… ({n} {noun})"
        shown = pkgs[:5]
        extra = len(pkgs) - len(shown)
        pkg_txt = ", ".join(shown)
        if extra > 0:
            pkg_txt += f", +{extra} more"
        return f"src/… ({n} {noun} · {pkg_txt})"

    def render(node: Dict[str, Any], path_so_far: str, prefix: str) -> None:
        child_names = sorted(node["dirs"].keys())
        is_module = bool(node.get("is_module"))
        markers = sorted(set(markers_by_dir.get(path_so_far, []))) if is_module else []
        summary = package_summary(path_so_far) if is_module else None

        entries: List[tuple] = []
        for m in markers:
            entries.append(("file", m))
        if summary:
            entries.append(("summary", summary))
        for name in child_names:
            entries.append(("dir", name))

        for i, (kind, name) in enumerate(entries):
            if len(lines) >= cap:
                remaining = len(entries) - i
                if remaining > 0:
                    lines.append(f"{prefix}└── ...and {remaining} more not shown")
                return
            last = i == len(entries) - 1
            branch = "└── " if last else "├── "
            next_prefix = prefix + ("    " if last else "│   ")
            if kind in ("file", "summary"):
                lines.append(f"{prefix}{branch}{name}")
                continue

            child = node["dirs"][name]
            child_path = f"{path_so_far}/{name}" if path_so_far else name
            lines.append(f"{prefix}{branch}{name}/")
            render(child, child_path, next_prefix)

    render(root_node, "", "")

    if len(lines) == 1:
        lines.append("(empty — no modules found)")
    return lines


def _module_summary_lines(
    files: List[Dict[str, Any]],
    project_name: str = "Project",
    cap: int = 80,
) -> List[str]:
    """Compatibility wrapper — prefer the tree formatter."""
    return _format_project_structure_tree(files, project_name=project_name, cap=cap)


def _resolve_scan_root(state: SastState) -> Path:
    root = Path(state["local_path"]).resolve()
    scope = (state.get("scope") or "").strip()
    if not scope:
        return root
    tracer: AgentTrace = state["_tracer"]
    candidate = (root / scope).resolve()
    try:
        candidate.relative_to(root)
    except ValueError:
        tracer.say(f"Ignoring out-of-repo scope path: {scope}")
        return root
    if candidate.is_dir():
        return candidate
    tracer.say(f"Scope path not found, scanning full repo: {scope}")
    return root


# ===========================================================================
# STEP 1 — node_scan_directory
#   Lists all files/folders, identifies file types, notes directory depth.
# ===========================================================================

def node_scan_directory(state: SastState) -> dict:
    tracer: AgentTrace = state["_tracer"]
    root = _resolve_scan_root(state)
    root_str = str(root)
    tracer.log(1, "scan_directory", f"Starting directory walk at: {root_str}",
                narrative="Looking through the repository...")

    files: List[Dict[str, Any]] = []
    dirs_seen: List[str] = []
    ext_counts: Dict[str, int] = {}
    max_depth = 0
    marker_files_found: List[str] = []

    for current_root, dirnames, filenames in os.walk(root):
        pruned = [d for d in dirnames if d.lower() in _SKIP_DIRS_LOWER or d.startswith(".")]
        for d in pruned:
            dirnames.remove(d)

        rel_dir = os.path.relpath(current_root, root)
        rel_dir = "" if rel_dir == "." else to_posix(rel_dir)
        depth = 0 if rel_dir == "" else rel_dir.count("/") + 1
        max_depth = max(max_depth, depth)
        dirs_seen.append(rel_dir or "(root)")

        if pruned:
            tracer.log(1, "scan_directory", f"Skipping generated/vendor dirs under '{rel_dir or '.'}'",
                        detail=", ".join(sorted(pruned)),
                        narrative=f"Skipping {', '.join(sorted(pruned))} — generated or vendor files, nothing to scan there.")

        for fname in filenames:
            ext = os.path.splitext(fname)[1].lower()
            if _is_skipped_walk_file(fname, ext):
                continue
            rel_path = to_posix(os.path.join(rel_dir, fname)) if rel_dir else fname
            lang = EXT_LANG_MAP.get(ext)
            try:
                size = os.path.getsize(os.path.join(current_root, fname))
            except OSError:
                size = None

            files.append({
                "path": rel_path, "name": fname, "ext": ext, "lang": lang,
                "size_bytes": size, "depth": depth,
            })
            ext_counts[ext] = ext_counts.get(ext, 0) + 1

            if fname in DEPENDENCY_MARKER_FILES or ext in DEPENDENCY_MARKER_EXTS:
                marker_files_found.append(rel_path)

    top_level_dirs = sorted({f["path"].split("/")[0] for f in files if "/" in f["path"]})

    scan_summary = {
        "root": root_str,
        "total_files": len(files),
        "max_depth": max_depth,
        "top_level_entries": top_level_dirs,
        "extension_histogram": dict(sorted(ext_counts.items(), key=lambda kv: -kv[1])),
        "marker_files_found": marker_files_found,
        "files": files,
    }

    tracer.log(1, "scan_directory",
                f"Walk complete: {len(files)} files across {len(dirs_seen)} directories, max depth {max_depth}",
                detail=f"top-level entries: {', '.join(top_level_dirs) if top_level_dirs else '(none)'}",
                narrative=f"Found {len(files)} files across {len(dirs_seen)} directories (max depth {max_depth}) — "
                          f"top-level: {', '.join(top_level_dirs) if top_level_dirs else '(none)'}.")

    project_name = (state.get("project_name") or "").strip() or (root.name or "Project")
    module_lines = _module_summary_lines(files, project_name=project_name)
    tracer.log(
        1,
        "scan_directory",
        f"Project structure: {len(module_lines) - 1} tree entries",
        detail="; ".join(module_lines[:12]),
        narrative="Project structure:\n" + "\n".join(module_lines),
    )

    if marker_files_found:
        tracer.log(1, "scan_directory", "Dependency/build marker files detected",
                    detail=", ".join(marker_files_found),
                    narrative=f"Spotted {', '.join(marker_files_found)} — that's usually a strong signal for the stack.")
    else:
        tracer.log(1, "scan_directory", "No dependency/build marker files found",
                    narrative="No dependency manifest (pom.xml, package.json, etc.) turned up — might be an unusual layout.")

    if state.get("verbose_files"):
        for f in files:
            tracer.log(1, "scan_directory", f"Found file: {f['path']}",
                        detail=f"type={f['lang'] or f['ext'] or 'unknown'}, depth={f['depth']}, size={f['size_bytes']}B",
                        narrative=f"  {f['path']} ({f['lang'] or f['ext'] or 'unknown type'})")

    return {"scan": scan_summary}


# ===========================================================================
# STEP 2 — node_analyze_tech_stack
#   Heuristic stack detection (fast, offline) + one LLM call for project type /
#   risk-area reasoning. Falls back cleanly if the LLM call fails so the
#   pipeline never hard-fails.
# ===========================================================================

def detect_stacks_heuristic(scan: Dict[str, Any]) -> List[str]:
    """Identify candidate stacks from marker files. A monorepo can match more than one."""
    found = set()
    for f in scan["files"]:
        if f["name"] in DEPENDENCY_MARKER_FILES:
            found.add(DEPENDENCY_MARKER_FILES[f["name"]])
        elif f["ext"] in DEPENDENCY_MARKER_EXTS:
            found.add(DEPENDENCY_MARKER_EXTS[f["ext"]])
    # angular.json also implies package.json's nodejs-generic profile; keep angular as the
    # more specific profile and drop the redundant generic one when both are present.
    if "angular" in found and "nodejs-generic" in found:
        found.discard("nodejs-generic")
    return sorted(found) or ["unknown"]


_AST_COVERED_STACKS = ("maven-java", "angular")
_BACKEND_STACKS = ("maven-java", "dotnet", "python", "nodejs-generic")


# Which dependency-scan ecosystem(s) correspond to each heuristic stack key —
# lets _describe_stack pull in dependency-signature evidence (any ecosystem)
# alongside/in place of AST evidence (Java/Angular only).
_STACK_ECOSYSTEMS = {
    "maven-java": ("maven",),
    "nodejs-generic": ("npm",),
    "angular": ("npm",),
    "python": ("pypi",),
    "go-generic": ("go",),
    "dotnet": ("nuget",),
    "ruby-generic": ("rubygems",),
    "php-generic": ("packagist",),
    "rust-generic": ("cratesio",),
}

# Dependency-signature labels that just restate what the AST pass's
# "Spring Boot REST API" phrase already says — skip these when appending
# extra dependency-derived detail to a Spring project's description.
_SPRING_LABELS_REDUNDANT_WITH_AST = {"Spring Framework", "Spring Boot", "Spring Security", "Spring Data"}


def _dependency_labels_for_stack(stack: str, dependency_summary: Optional[Dict[str, Any]]) -> List[str]:
    if not dependency_summary:
        return []
    ecosystems = _STACK_ECOSYSTEMS.get(stack, ())
    return [f["label"] for f in dependency_summary.get("frameworks", []) if f["ecosystem"] in ecosystems]


def _describe_stack(
    stack: str,
    ast_summary: Optional[Dict[str, Any]],
    dependency_summary: Optional[Dict[str, Any]] = None,
) -> str:
    """Human-readable phrase for one detected stack. Prefers structurally-
    verified detail from the AST pass (real annotation/entry-point counts,
    Java/Angular only) enriched with dependency-signature evidence (real
    framework names parsed from pom.xml/package.json/requirements.txt/etc. —
    works for any ecosystem). When AST found nothing (a non-Spring Java
    project's zero annotation counts, or any ecosystem AST never covers),
    dependency-derived labels carry the whole description instead of falling
    back to the bare stack key. Behavior is unchanged from before when no
    dependency evidence is available, so a project with no manifest matches
    describes identically to today."""
    data = (ast_summary or {}).get("stacks", {}).get(stack) if ast_summary else None
    dep_labels = _dependency_labels_for_stack(stack, dependency_summary)

    if stack == "maven-java":
        n_ctrl = (data or {}).get("annotations", {}).get("RestController", 0) + (data or {}).get("annotations", {}).get("Controller", 0)
        n_ep = (data or {}).get("entry_point_count", 0)
        n_ent = (data or {}).get("annotations", {}).get("Entity", 0)
        extra_labels = [l for l in dep_labels if l not in _SPRING_LABELS_REDUNDANT_WITH_AST]

        if n_ctrl:
            parts = [f"{n_ctrl} controller{'s' if n_ctrl != 1 else ''}"]
            if n_ep:
                parts.append(f"{n_ep} endpoint{'s' if n_ep != 1 else ''}")
            if n_ent:
                parts.append("JPA persistence")
            base = f"Spring Boot REST API ({', '.join(parts)})"
            return f"{base} + {', '.join(extra_labels)}" if extra_labels else base

        if extra_labels:
            return " + ".join(extra_labels)
        return stack

    if stack == "angular":
        if not data:
            return stack
        n_comp = data["decorators"].get("Component", 0)
        n_guard = data["guard_files"]
        parts = []
        if n_comp:
            parts.append(f"{n_comp} component{'s' if n_comp != 1 else ''}")
        if n_guard:
            parts.append(f"{n_guard} guard{'s' if n_guard != 1 else ''}")
        return f"Angular SPA ({', '.join(parts)})" if parts else "Angular SPA"

    # Every other stack has no AST coverage at all — dependency-signature
    # evidence is the entire structural-evidence story for it.
    return " + ".join(dep_labels) if dep_labels else stack


# Dependency-signature categories that count as "this is a backend/service
# framework" evidence for project-type inference — deliberately excludes
# categories like orm/logging/testing/database-driver, which are present in
# almost every backend project and wouldn't discriminate "REST API" from
# "library".
_BACKEND_DEP_CATEGORIES = {"rest-framework", "web-framework"}


def _infer_project_type(
    heuristic_stacks: List[str],
    ast_summary: Optional[Dict[str, Any]],
    dependency_summary: Optional[Dict[str, Any]] = None,
) -> str:
    """Claims a project type when AST evidence (Java/Angular) or recognized
    dependency-signature evidence (any ecosystem) backs it up — otherwise
    stays "unknown" rather than guessing from file extensions alone. This is
    what fixes the reported bug for non-Spring Java projects: a JAX-RS/EJB
    project has zero AST signal (ast_struct.py only recognizes Spring
    annotations) but real recognized dependencies, which now count as
    backend confirmation on their own."""
    if heuristic_stacks == ["unknown"]:
        return "unknown"
    stacks = (ast_summary or {}).get("stacks", {}) if ast_summary else {}
    mj = stacks.get("maven-java")
    ng = stacks.get("angular")
    rest_confirmed = bool(mj and mj["entry_point_count"] > 0)
    spa_confirmed = bool(ng and (ng["route_count"] > 0 or sum(ng["decorators"].values()) > 0))

    dep_backend_confirmed = any(
        f["category"] in _BACKEND_DEP_CATEGORIES for f in (dependency_summary or {}).get("frameworks", [])
    ) and any(s in _BACKEND_STACKS for s in heuristic_stacks)

    backend_confirmed = rest_confirmed or dep_backend_confirmed
    if backend_confirmed and spa_confirmed:
        return "web app"
    if backend_confirmed:
        return "REST API"
    if spa_confirmed:
        return "web app"
    return "unknown"


def _infer_confidence(
    heuristic_stacks: List[str],
    ast_summary: Optional[Dict[str, Any]],
    dependency_summary: Optional[Dict[str, Any]] = None,
) -> str:
    if heuristic_stacks == ["unknown"]:
        return "low"
    for data in (ast_summary or {}).get("stacks", {}).values():
        signal = (
            data.get("entry_point_count", 0) + data.get("route_count", 0)
            + sum(data.get("annotations", {}).values()) + sum(data.get("decorators", {}).values())
        )
        if signal > 0:
            return "high"
    if dependency_summary and dependency_summary.get("frameworks"):
        # recognized dependencies alone are solid evidence; config-file
        # corroboration (e.g. an actual struts-config.xml, not just the
        # dependency) pushes it to the same "high" tier AST signal gets.
        return "high" if dependency_summary.get("config_evidence") else "medium"
    # a real marker file matched a known stack profile, just no AST/dependency evidence for it
    return "medium" if any(s in STACK_PROFILES for s in heuristic_stacks) else "low"


def _build_reasoning(
    heuristic_stacks: List[str],
    ast_summary: Optional[Dict[str, Any]],
    dependency_summary: Optional[Dict[str, Any]] = None,
) -> str:
    if heuristic_stacks == ["unknown"]:
        return "No recognized dependency/build marker files found."
    stacks = (ast_summary or {}).get("stacks", {}) if ast_summary else {}
    mj, ng = stacks.get("maven-java"), stacks.get("angular")
    parts = []
    if mj:
        parts.append(
            f"{mj['entry_point_count']} REST endpoint(s) confirmed via AST across "
            f"{sum(mj['annotations'].values())} annotated Spring class(es)"
        )
    if ng:
        parts.append(
            f"{ng['route_count']} Angular route(s) confirmed via AST across "
            f"{sum(ng['decorators'].values())} decorated class(es)"
        )
    if dependency_summary and dependency_summary.get("frameworks"):
        labels = ", ".join(f["label"] for f in dependency_summary["frameworks"][:8])
        parts.append(
            f"{len(dependency_summary['frameworks'])} recognized framework(s) from "
            f"{len(dependency_summary['manifests_parsed'])} dependency manifest(s): {labels}"
        )
    if dependency_summary and dependency_summary.get("config_evidence"):
        parts.extend(dependency_summary["config_evidence"])
    if parts:
        return "; ".join(parts) + "."
    return (
        f"Detected from dependency marker files ({', '.join(heuristic_stacks)}); "
        "no AST or dependency-signature coverage for this stack."
    )


def node_analyze_tech_stack(state: SastState) -> dict:
    """Stack / project-type / risk-area verdict — three deterministic, LLM-free
    evidence passes, no LLM call anywhere in this step:
      1. marker-file heuristic (which build tool is present)
      2. dependency-manifest parsing + signature matching (pipeline/dependency_scan.py)
         — what real frameworks are declared, for ANY ecosystem the marker
         heuristic recognizes (Java, Node, Python, Go, Ruby, PHP, .NET, Rust),
         not just the two ast_struct.py can structurally parse
      3. tree-sitter AST structure (ast_struct.py, Java/Angular only) — what's
         actually exposed/risky in source (entry points, auth coverage)
    Dependency-signature evidence is what fixes non-Spring Java projects
    (JAX-RS/RESTEasy/EJB/Struts/Axis2, etc.): ast_struct.py's annotation
    vocabulary is Spring-only, so a JAX-RS project scores zero AST signal,
    but its pom.xml still declares real, parseable dependencies."""
    tracer: AgentTrace = state["_tracer"]
    scan = state["scan"]

    heuristic_stacks = detect_stacks_heuristic(scan)
    tracer.log(2, "analyze_tech_stack", "Ran offline heuristic stack detection from marker files",
                detail=f"candidates: {heuristic_stacks}",
                narrative=f"Based on the marker files, this looks like: {', '.join(heuristic_stacks)}.")

    # --- Dependency-manifest pass ---------------------------------------------
    # Parses the actual pom.xml/package.json/requirements.txt/go.mod/etc.
    # dependency declarations and matches them against a curated framework
    # signature table — generalizes to any ecosystem the marker heuristic
    # recognizes, unlike the AST pass below which only covers Java/Angular.
    dependency_summary = dependency_scan.analyze_dependencies(scan, Path(scan["root"]))
    if dependency_summary:
        tracer.log(2, "analyze_tech_stack",
                    f"Dependency scan: {len(dependency_summary['manifests_parsed'])} manifest(s) parsed, "
                    f"{dependency_summary['dependency_count']} dependencies, "
                    f"{len(dependency_summary['frameworks'])} recognized framework(s)",
                    detail=str(dependency_summary),
                    narrative=(
                        f"Parsed {len(dependency_summary['manifests_parsed'])} dependency manifest(s): "
                        + (", ".join(f["label"] for f in dependency_summary["frameworks"]) or "no recognized frameworks")
                        + (f" ({dependency_summary['unrecognized_count']} unrecognized dependencies)"
                           if dependency_summary["unrecognized_count"] else "") + "."
                    ))
        for evidence in dependency_summary["config_evidence"]:
            tracer.log(2, "analyze_tech_stack", evidence, narrative=evidence + ".")

    # --- AST structural pass -------------------------------------------------
    # Marker files only say what tools are in play; this parses the actual
    # source (tree-sitter) so the stacks we can annotate-count (Maven/Java,
    # Angular) get real evidence — annotation counts, REST entry points,
    # route-guard coverage — instead of a guess from file extensions alone.
    ast_summary: Optional[Dict[str, Any]] = None
    covered_stacks = [s for s in heuristic_stacks if s in _AST_COVERED_STACKS]
    if covered_stacks and not ast_struct.tree_sitter_available():
        tracer.log(2, "analyze_tech_stack", "AST pass skipped — tree-sitter not installed",
                    narrative="tree-sitter isn't installed, so skipping the structural AST pass and going straight to heuristics.")
    elif covered_stacks:
        tracer.say(f"Parsing {', '.join(covered_stacks)} source with tree-sitter for structural evidence...")
        ast_summary = ast_struct.build_ast_summary(scan, heuristic_stacks, Path(scan["root"]))
        if ast_summary:
            for stack_key, data in ast_summary["stacks"].items():
                parsed_key = "java" if stack_key == "maven-java" else "typescript"
                parsed_n = ast_summary["parsed_files"].get(parsed_key, 0)
                capped = ast_summary["capped"].get(parsed_key, False)
                detail_suffix = f" (capped at {parsed_n})" if capped else ""
                tracer.log(2, "analyze_tech_stack", f"AST pass complete for {stack_key}: {parsed_n} file(s) parsed{detail_suffix}",
                            detail=str(data),
                            narrative=ast_struct.narrate_stack_summary(stack_key, data))

    risk_areas = ast_struct.structural_risk_areas(ast_summary)
    tech_stack = " + ".join(
        _describe_stack(s, ast_summary, dependency_summary) for s in heuristic_stacks if s != "unknown"
    ) or "Unrecognized stack"
    project_type = _infer_project_type(heuristic_stacks, ast_summary, dependency_summary)
    confidence = _infer_confidence(heuristic_stacks, ast_summary, dependency_summary)
    reasoning = _build_reasoning(heuristic_stacks, ast_summary, dependency_summary)

    result: Dict[str, Any] = {
        "heuristic_stacks": heuristic_stacks,
        "llm_used": False,
        "tech_stack": tech_stack,
        "project_type": project_type,
        "confidence": confidence,
        "risk_areas": risk_areas,
        "reasoning": reasoning,
        "ast_summary": ast_summary,
        "dependency_summary": dependency_summary,
    }

    tracer.log(2, "analyze_tech_stack", "Tech-stack verdict finalized from heuristics + dependency scan + AST (no LLM call)",
                detail=f"tech_stack={tech_stack}, project_type={project_type}, confidence={confidence}, risk_areas={risk_areas}",
                narrative=f"-> {tech_stack}, a {project_type} ({confidence} confidence). "
                          f"Risk areas to prioritize: {', '.join(risk_areas) or 'none flagged'}.")

    _log_active_surfaces(state, {**state, "llm_analysis": result}, tracer)

    usage = state.get("usage") or init_usage(state.get("llm_provider"), state.get("llm_model"))
    return {"llm_analysis": result, "usage": usage}


def _log_active_surfaces(state: SastState, resolved_state: dict, tracer: "AgentTrace") -> None:
    """Narrate which vulnerability surfaces this repo's stack turns on.

    This is the `Tech Stack Detected -> Known Vulnerability Surface -> Targeted
    Regex` chain the legacy audit docs spell out by hand, reproduced for
    whatever repo is being scanned. Surfaces order the prompt catalog and
    explain the scan; they never gate a rule, so a failure here must not stop
    the scan.
    """
    rules_path = Path(state.get("regex_rules_path") or (_ENGINE_DIR / "rules"))
    try:
        surfaces = _resolve_active_surfaces(resolved_state, rules_path)
    except Exception as exc:  # noqa: BLE001 - narration must never fail a scan
        tracer.log(2, "analyze_tech_stack", f"Surface mapping unavailable: {type(exc).__name__}: {exc}",
                    narrative="Could not map vulnerability surfaces for this stack; scanning continues with the full rule catalog.")
        return
    if not surfaces:
        return

    tracer.log(2, "analyze_tech_stack",
                f"{len(surfaces)} vulnerability surface(s) active for this stack",
                detail=", ".join(s.surface for s in surfaces),
                narrative=f"Mapping the detected stack onto {len(surfaces)} known vulnerability surface(s):")
    for surface in surfaces:
        tracer.log(2, "analyze_tech_stack",
                    f"{surface.surface}: {len(surface.rules)} rule(s)",
                    detail=surface.rationale,
                    narrative=f"  {surface.rationale} -> {len(surface.rules)} targeted rule(s).")


# ===========================================================================
# STEP 3 — node_categorize_files
#   Buckets every file into: source / config / dependency / test / build / other
#   using the matched stack profile's rules (generic fallback if no stack rule fires).
# ===========================================================================

def _match_rules(rel_path: str, rules: List[RiskRule]):
    for pattern, risk, reason, category in rules:
        if re.search(pattern, rel_path):
            return risk, reason, category
    return None


def node_categorize_files(state: SastState) -> dict:
    tracer: AgentTrace = state["_tracer"]
    scan = state["scan"]
    stacks = state["llm_analysis"]["heuristic_stacks"]
    active_profiles = [s for s in stacks if s in STACK_PROFILES]

    tracer.log(3, "categorize_files",
                f"Categorizing {scan['total_files']} files using profiles: "
                f"{[STACK_PROFILES[s]['label'] for s in active_profiles] or ['(none — generic fallback only)']}",
                narrative=f"Sorting {scan['total_files']} files into source/config/dependency/test/build...")

    buckets: Dict[str, List[str]] = {"source": [], "config": [], "dependency": [], "test": [], "build": [], "other": []}

    for f in scan["files"]:
        matched = None
        for stack in active_profiles:
            matched = _match_rules(f["path"], STACK_PROFILES[stack]["rules"])
            if matched:
                break
        if not matched:
            matched = _match_rules(f["path"], GENERIC_FALLBACK_RULES)

        _, _, category = matched if matched else (None, None, "other")
        buckets.setdefault(category, []).append(f["path"])

        if state.get("verbose_files"):
            tracer.log(3, "categorize_files", f"{f['path']} -> category={category}",
                        narrative=f"  {f['path']} -> {category}")

    counts = {k: len(v) for k, v in buckets.items()}
    tracer.log(3, "categorize_files", "Categorization complete", detail=f"counts: {counts}",
                narrative=f"Done — {counts['source']} source, {counts['config']} config, "
                          f"{counts['dependency']} dependency, {counts['test']} test, {counts['build']} build.")
    return {"categorized": buckets}


# ===========================================================================
# STEP 4 — node_map_modules_and_risk
#   Stack-specific module & risk-level mapping. Generic across Maven, Angular,
#   .NET, Python, Node — degrades to GENERIC_FALLBACK_RULES for anything else.
# ===========================================================================


def _discover_modules(scan: Dict[str, Any], stack: str) -> List[str]:
    """Find sub-directories that themselves contain a stack marker file — i.e. a
    multi-module Maven build, an Nx/Angular workspace with multiple apps, etc.
    Falls back to the project root as the single module."""
    marker_names = [name for name, s in DEPENDENCY_MARKER_FILES.items() if s == stack]
    module_dirs = set()
    for f in scan["files"]:
        if f["name"] in marker_names:
            module_dir = os.path.dirname(f["path"])
            module_dirs.add(module_dir if module_dir else "(root)")
    return sorted(module_dirs) if module_dirs else ["(root)"]


def node_map_modules_and_risk(state: SastState) -> dict:
    tracer: AgentTrace = state["_tracer"]
    scan = state["scan"]
    stacks = state["llm_analysis"]["heuristic_stacks"]
    active_profiles = [s for s in stacks if s in STACK_PROFILES]

    tracer.log(4, "map_modules_and_risk",
                f"Building module/risk scan plan for detected stack(s): {active_profiles or ['unrecognized']}",
                narrative="Working out module boundaries and flagging risk per file...")

    file_risk: List[Dict[str, Any]] = []
    risk_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    modules_by_stack: Dict[str, List[str]] = {}

    for stack in active_profiles:
        mods = _discover_modules(scan, stack)
        modules_by_stack[stack] = mods
        tracer.log(4, "map_modules_and_risk",
                    f"[{STACK_PROFILES[stack]['label']}] discovered module(s): {mods}",
                    narrative=f"{STACK_PROFILES[stack]['label']} module(s): {', '.join(mods)}.")

    for f in scan["files"]:
        matched = None
        matched_stack = None
        for stack in active_profiles:
            m = _match_rules(f["path"], STACK_PROFILES[stack]["rules"])
            if m:
                matched, matched_stack = m, stack
                break
        if not matched:
            matched = _match_rules(f["path"], GENERIC_FALLBACK_RULES)
            matched_stack = "generic-fallback"

        risk, reason, category = matched
        if risk in risk_counts:
            risk_counts[risk] += 1

        module = "(root)"
        if matched_stack in modules_by_stack:
            candidates = [m for m in modules_by_stack[matched_stack] if m != "(root)" and f["path"].startswith(m + "/")]
            if candidates:
                module = max(candidates, key=len)

        entry = {
            "path": f["path"], "stack": matched_stack, "module": module,
            "category": category, "risk_level": risk, "reason": reason,
            "lang": llm_file_scan.lang_for_path(f["path"]),
        }
        file_risk.append(entry)

        if state.get("verbose_files") and risk in ("CRITICAL", "HIGH"):
            tracer.log(4, "map_modules_and_risk", f"{f['path']} -> {risk}",
                        detail=f"module={module}, category={category}, reason={reason}",
                        narrative=f"  {f['path']} -> {risk} ({reason})")

    # Bucket order: CRITICAL entries first, then HIGH, walk order within each
    # bucket. `files_for_risk_levels` (not the raw file_risk list) is what
    # applies the is_non_source_path / is_excluded_from_finding_scan filters,
    # so a schema/log4j-excluded "CRITICAL" file can never occupy a deep-scan
    # slot.
    critical_only = state.get("deep_scan_critical_only", False)
    deep_risk_levels = frozenset({"CRITICAL"}) if critical_only else llm_file_scan.LLM_RISK_LEVELS
    triage_risk_levels = (
        llm_file_scan.TRIAGE_RISK_LEVELS | {"HIGH"} if critical_only else llm_file_scan.TRIAGE_RISK_LEVELS
    )
    _RISK_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

    critical_high = llm_file_scan.files_for_risk_levels(
        {"files": file_risk}, deep_risk_levels
    )
    critical_high.sort(key=lambda e: _RISK_RANK.get(e["risk_level"], 9))
    medium_low = llm_file_scan.files_for_risk_levels(
        {"files": file_risk}, triage_risk_levels
    )
    medium_low.sort(key=lambda e: _RISK_RANK.get(e["risk_level"], 9))

    deep_cap = state.get("deep_scan_file_cap", llm_file_scan.DEEP_SCAN_FILE_CAP)
    deep_entries, overflow_entries = critical_high[:deep_cap], critical_high[deep_cap:]

    # Backfill unused deep-scan budget with the highest-priority MEDIUM (then
    # LOW) files instead of leaving those LLM-call slots idle when
    # CRITICAL/HIGH is small. Same fixed budget as before (still bounded by
    # deep_cap) — this only changes how much of it a small CRITICAL/HIGH
    # bucket leaves on the table.
    backfill_entries: list = []
    # critical_only means every non-CRITICAL file (including HIGH) belongs in
    # the triage tier with no exceptions — never let backfill pull it back
    # into the deep-scan bucket just to use up spare cap.
    if not critical_only and state.get("backfill_deep_scan", True) and len(deep_entries) < deep_cap:
        room = deep_cap - len(deep_entries)
        backfill_entries, medium_low = medium_low[:room], medium_low[room:]

    deep_scan_paths = [e["path"] for e in deep_entries] + [e["path"] for e in backfill_entries]
    # Overflow CRITICAL/HIGH goes first so it isn't stuck behind every
    # MEDIUM/LOW file once the triage tier batches (node_scan_triage_files).
    triage_scan_paths = [e["path"] for e in overflow_entries] + [e["path"] for e in medium_low]

    module_plan = {
        "modules_by_stack": modules_by_stack,
        "risk_counts": risk_counts,
        "files": file_risk,
        "scan_priority": [e for e in file_risk if e["risk_level"] == "CRITICAL"] +
                          [e for e in file_risk if e["risk_level"] == "HIGH"],
        "deep_scan_paths": deep_scan_paths,
        "triage_scan_paths": triage_scan_paths,
    }

    llm_analysis = state.get("llm_analysis") or {}
    wrap = (
        f"Discovery finished — {llm_analysis.get('tech_stack')}, "
        f"{state['scan']['total_files']} files scanned."
    )
    deep_tier_label = "CRITICAL" if critical_only else "CRITICAL/HIGH"
    overflow_note = (
        f" (including {len(overflow_entries)} {deep_tier_label} file(s) beyond the "
        f"{deep_cap}-file deep-scan cap)" if overflow_entries else ""
    )
    backfill_note = (
        f" plus {len(backfill_entries)} MEDIUM/LOW file(s) backfilled to use the "
        f"remaining {deep_cap}-file budget" if backfill_entries else ""
    )
    triage_mode = state.get("triage_mode", llm_file_scan.DEFAULT_TRIAGE_MODE)
    triage_llm_note = (
        "regex hits get an LLM TP/FP ruling"
        if triage_mode == llm_file_scan.TRIAGE_MODE_LLM
        else "only regex hits are written up (no LLM ruling)"
    )
    tracer.log(4, "map_modules_and_risk", "Risk mapping complete",
                detail=f"{risk_counts} — {len(module_plan['scan_priority'])} files flagged CRITICAL/HIGH; "
                       f"deep_cap={deep_cap}, critical_only={critical_only}, "
                       f"overflow={len(overflow_entries)}, backfill={len(backfill_entries)}; "
                       f"tech_stack={llm_analysis.get('tech_stack')}",
                narrative=f"{risk_counts['CRITICAL']} critical-risk file(s), {risk_counts['HIGH']} high, "
                          f"{risk_counts['MEDIUM']} medium, {risk_counts['LOW']} low "
                          f"(path heuristics — not findings yet). "
                          f"{len(deep_scan_paths)} file(s) (top {deep_tier_label} by priority"
                          f"{backfill_note}) queued for the full LLM scan; "
                          f"{len(triage_scan_paths)} file(s) queued for regex-gated triage{overflow_note}, "
                          f"where {triage_llm_note}. "
                          f"{wrap}")
    # Persist discovery now so the UI can show Discovery results before the
    # LLM file scan (which can take a long time).
    _emit_discovery(state, module_plan=module_plan, report=None)
    return {"module_plan": module_plan}


# ===========================================================================
# STEP 5 — node_build_call_graph / node_discover_flows / node_verify_flow_slices
#   Java inter-file call graph, then LLM-verify full method-body slices.
# STEP 6 — node_derive_runtime_rules
#   Pass A (call-graph wrappers) + optional Pass B (one LLM derive call).
#   Merged onto the static catalog; later scan nodes read them via _scan_context.
# STEP 7 — node_scan_deep_files
#   LLM-primary detect+triage of every CRITICAL / HIGH file. The rule catalog
#   is prompt guidance (titles + OWASP vocabulary), never a gate — every file
#   at those risk levels is scanned whether or not a regex would have matched.
# ===========================================================================

_EMPTY_SCAN_RESULTS = {"files_scanned": 0, "tp_count": 0, "fp_count": 0, "files": []}


def _repo_languages(state: SastState) -> set:
    """Language tags present in the walked repo (drives surface activation)."""
    return {
        f.get("lang") for f in (state.get("scan") or {}).get("files", []) if f.get("lang")
    }


def _resolve_active_surfaces(state: SastState, rules_path: Path):
    """Surfaces this repo activates, from its detected stack. Never gates a
    rule — see regex_scan's surfaces section."""
    llm_analysis = state.get("llm_analysis") or {}
    dependency_summary = llm_analysis.get("dependency_summary") or {}
    return regex_scan.active_surfaces(
        regex_scan.load_surfaces(rules_path),
        languages=_repo_languages(state),
        active_frameworks={f["label"] for f in dependency_summary.get("frameworks", [])},
        dependency_index=regex_scan.build_dependency_index(dependency_summary),
    )


def _scan_context(state: SastState) -> tuple:
    root = _resolve_scan_root(state)
    rules_path = Path(state.get("regex_rules_path") or (_ENGINE_DIR / "rules"))
    static_rules = regex_scan.load_rules(rules_path)
    derived_rules = list(state.get("derived_rules") or [])
    rules = static_rules + derived_rules
    llm_analysis = state.get("llm_analysis") or {}
    dependency_summary = llm_analysis.get("dependency_summary") or {}
    active_frameworks = {f["label"] for f in dependency_summary.get("frameworks", [])}
    dependency_index = regex_scan.build_dependency_index(dependency_summary)
    priority_rule_ids = regex_scan.surface_rule_ids(
        _resolve_active_surfaces(state, rules_path)
    )
    priority_rule_ids = set(priority_rule_ids) | {r.id for r in derived_rules}
    stack_context = llm_analysis.get("tech_stack") or "unknown"
    usage = state.get("usage") or init_usage(state.get("llm_provider"), state.get("llm_model"))
    return (root, rules, active_frameworks, dependency_index,
            priority_rule_ids, stack_context, usage)


def _inter_file_enabled(state: SastState) -> bool:
    if state.get("inter_file_flow") is False:
        return False
    if not state.get("use_llm", True):
        return False
    if not ast_struct.tree_sitter_available():
        return False
    return call_graph.is_java_stack(state) or call_graph_python.is_python_stack(state)


def node_build_call_graph(state: SastState) -> dict:
    tracer: AgentTrace = state["_tracer"]
    if not _inter_file_enabled(state):
        tracer.log(5, "build_call_graph", "Skipping call graph — disabled or not a Java/Python scan",
                    narrative="Inter-file call-graph tracing is off for this run "
                              "(flag, no LLM, missing tree-sitter, or not maven-java/python).")
        return {"call_graph": {"files_parsed": 0, "methods": 0, "edges": 0, "sinks": 0,
                               "unresolved": [], "entry_tier": "", "_graph_lang": None}}

    is_python = call_graph_python.is_python_stack(state) and not call_graph.is_java_stack(state)
    lang_module = call_graph_python if is_python else call_graph
    lang_label = "Python" if is_python else "Java"
    file_ext = "py" if is_python else "java"

    root = _resolve_scan_root(state)
    paths = (
        call_graph_python.python_paths_from_scan(state.get("scan"))
        if is_python
        else call_graph.java_paths_from_scan(state.get("scan"))
    )
    tracer.log(5, "build_call_graph",
                f"Building {lang_label} call graph from {len(paths)} .{file_ext} file(s)",
                narrative=f"Parsing {len(paths)} {lang_label} file(s) into a call graph "
                          f"(typed sinks, name+argc overloads)...")
    graph = lang_module.build_call_graph(root, paths)
    # Per-reason breakdown, not just a total: which failure dominates says
    # whether receiver types aren't resolving (unresolved_type) or interfaces
    # have no single in-repo implementor (unresolved_interface, e.g. Spring
    # Data repositories whose impl is generated at runtime).
    unresolved_by_reason = dict(Counter(graph.unresolved).most_common())
    summary = {
        "files_parsed": graph.files_parsed,
        "methods": len(graph.functions) if is_python else len(graph.methods),
        "edges": len(graph.edges),
        "sinks": len(graph.sinks),
        "unresolved": list(graph.unresolved),
        "unresolved_by_reason": unresolved_by_reason,
        "entry_tier": "",
        "_graph": graph,
        "_graph_lang": "python" if is_python else "java",
    }
    # A call site is one of exactly three things: a resolved in-repo edge, an
    # `unresolved` reason, or a hop into JDK/framework (or stdlib/third-party,
    # for Python) code that is skipped on purpose. Report the third as a
    # remainder so the buckets always add up.
    framework_skipped = max(
        0, graph.call_sites - len(graph.edges) - len(graph.unresolved)
    )
    unresolved_note = (
        ", ".join(f"{reason}={count}" for reason, count in unresolved_by_reason.items())
        or "none"
    )
    summary["call_sites"] = graph.call_sites
    summary["framework_skipped"] = framework_skipped
    tracer.log(5, "build_call_graph",
                f"Call graph ready: {graph.files_parsed} file(s), {summary['methods']} method(s)/function(s), "
                f"{len(graph.edges)} edge(s), {len(graph.sinks)} typed sink(s)",
                detail=f"call_sites={graph.call_sites}, unresolved={len(graph.unresolved)} "
                       f"({unresolved_note}), framework_or_stdlib_skipped={framework_skipped}",
                narrative=f"Call graph: {summary['methods']} method(s)/function(s), {len(graph.edges)} resolved "
                          f"edges, {len(graph.sinks)} typed sink(s).")
    return {"call_graph": summary}


def node_discover_flows(state: SastState) -> dict:
    tracer: AgentTrace = state["_tracer"]
    packed = state.get("call_graph") or {}
    graph = packed.get("_graph")
    graph_lang = packed.get("_graph_lang")
    if graph is None:
        tracer.log(6, "discover_flows", "No call graph — skipping flow discovery",
                    narrative="No call graph was built, so there are no inter-file flows to walk.")
        return {"flow_candidates": [], "call_graph": packed}

    lang_module = call_graph_python if graph_lang == "python" else call_graph
    cap = state.get("flow_verify_cap", call_graph.FLOW_VERIFY_CAP)
    max_hop_depth = state.get("flow_max_hop_depth", call_graph.MAX_HOP_DEPTH)
    flows = lang_module.discover_flows(graph, cap=cap, max_hop_depth=max_hop_depth)
    packed["entry_tier"] = graph.entry_tier
    packed["_flows"] = flows
    candidates = [lang_module.flow_to_dict(f) for f in flows]
    total_found = graph.flows_discovered_total
    flows_note = (
        f"Found {total_found} inter-file flow(s) from typed sinks — sending the top {len(flows)} to the LLM."
        if total_found > len(flows)
        else f"Found {len(flows)} inter-file flow(s) from typed sinks."
    )
    tracer.log(6, "discover_flows",
                f"Discovered {len(flows)} multi-file flow(s) (entry_tier={graph.entry_tier or 'none'}, "
                f"cap={cap}, max_hop_depth={max_hop_depth}, total_found={total_found})",
                narrative=flows_note)
    return {"flow_candidates": candidates, "call_graph": packed}


def node_verify_flow_slices(state: SastState) -> dict:
    tracer: AgentTrace = state["_tracer"]
    empty = {**dict(_EMPTY_SCAN_RESULTS), "flows_verified": 0, "flows_skipped_large": 0, "findings": []}
    if not _inter_file_enabled(state):
        tracer.log(6, "verify_flow_slices", "Skipping flow verification — inter-file tracing disabled",
                    narrative="Inter-file flow slices are not being sent to the LLM for this run.")
        return {"flow_scan_results": empty}

    flows = list((state.get("call_graph") or {}).get("_flows") or [])
    if not flows:
        tracer.log(6, "verify_flow_slices", "No inter-file flows to verify",
                    narrative="No multi-file source→sink flows were discovered.")
        return {"flow_scan_results": empty}

    (_, _, _, _, _, stack_context, usage) = _scan_context(state)
    cap = state.get("flow_verify_cap", call_graph.FLOW_VERIFY_CAP)
    tracer.log(6, "verify_flow_slices",
                f"Verifying {min(len(flows), cap)} flow slice(s) with the LLM (full method bodies)",
                narrative=f"Sending {min(len(flows), cap)} inter-file flow slice(s) to the LLM — "
                          f"each hop is the complete method body.")

    results = flow_verify.verify_flows(
        flows,
        stack_context=stack_context,
        usage=usage,
        llm_provider=state.get("llm_provider"),
        llm_model=state.get("llm_model"),
        findings_writer=state.get("findings_writer"),
        cap=cap,
        suppress_no_cwe=state.get("suppress_no_cwe_findings", True),
        suppress_http_findings=state.get("suppress_http_findings", False),
        suppress_low_confidence_false_positives=state.get(
            "suppress_low_confidence_false_positives", False
        ),
    )
    tracer.log(6, "verify_flow_slices",
                f"Flow verification complete: {results['flows_verified']} verified, "
                f"{results['tp_count']} TP, {results['fp_count']} FP, "
                f"{results['flows_skipped_large']} skipped (slice too large)",
                narrative=f"Inter-file flows — {results['tp_count']} confirmed, "
                          f"{results['fp_count']} dismissed "
                          f"({results['flows_skipped_large']} skipped as too large).")
    return {"flow_scan_results": results, "usage": usage}


def node_derive_runtime_rules(state: SastState) -> dict:
    tracer: AgentTrace = state["_tracer"]
    if state.get("derive_runtime_rules") is False:
        tracer.log(5, "derive_runtime_rules", "Skipping runtime regex derive — disabled for this scan",
                    narrative="Runtime-derived regex is off, so the scan uses the static catalog only.")
        return {"derived_rules": []}

    rules_path = Path(state.get("regex_rules_path") or (_ENGINE_DIR / "rules"))
    try:
        static_rules = regex_scan.load_rules(rules_path)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        tracer.log(5, "derive_runtime_rules",
                    f"Could not load static catalog: {type(exc).__name__}: {exc}",
                    narrative="Static rule catalog could not be loaded; skipping runtime regex derive.")
        return {"derived_rules": []}

    packed = state.get("call_graph") or {}
    graph = packed.get("_graph")
    graph_lang = packed.get("_graph_lang")
    if graph is not None and graph_lang == "java":
        adapter = call_graph.JavaGraphAdapter(graph)
    elif graph is not None and graph_lang == "python":
        adapter = call_graph_python.PythonGraphAdapter(graph)
    else:
        adapter = None
    llm_analysis = state.get("llm_analysis") or {}
    dependency_summary = llm_analysis.get("dependency_summary") or {}
    frameworks = [f.get("label") or "" for f in dependency_summary.get("frameworks", [])]
    try:
        surfaces = [s.surface for s in _resolve_active_surfaces(state, rules_path)]
    except Exception:  # noqa: BLE001 — surfaces are prompt context only
        surfaces = []
    usage = state.get("usage") or init_usage(state.get("llm_provider"), state.get("llm_model"))
    cap = state.get("max_derived_regex_rules", derive_rules.DEFAULT_MAX_DERIVED)
    use_llm = bool(state.get("use_llm"))

    tracer.log(5, "derive_runtime_rules",
                "Deriving runtime regex from call-graph wrappers"
                + (" and one LLM pass" if use_llm else " (no LLM pass)"),
                narrative="Deriving regex...")

    dropped: List[str] = []
    derived = derive_rules.derive_runtime_rules(
        graph=adapter,
        static_rules=static_rules,
        stack_context=llm_analysis.get("tech_stack") or "unknown",
        frameworks=frameworks,
        surfaces=surfaces,
        use_llm=use_llm,
        usage=usage,
        llm_provider=state.get("llm_provider"),
        llm_model=state.get("llm_model"),
        max_rules=cap if cap is not None else derive_rules.DEFAULT_MAX_DERIVED,
        dropped=dropped,
    )
    dropped_by_reason = dict(Counter(dropped).most_common())
    derived_rules_summary = {
        "compiled": len(derived),
        "failed": len(dropped),
        "failed_by_reason": dropped_by_reason,
    }
    failed_note = f", {len(dropped)} failed ({dropped_by_reason})" if dropped else ""
    tracer.log(5, "derive_runtime_rules",
                f"Derived {len(derived)} runtime regex rule(s) (cap={cap}){failed_note}",
                detail=", ".join(r.id for r in derived) or "none",
                narrative=f"Derived {len(derived)} regex rule(s)."
                          + (f" {len(dropped)} candidate(s) failed validation "
                             f"({dropped_by_reason})." if dropped else ""))
    _emit_discovery({**state, "derived_rules": derived, "derived_rules_summary": derived_rules_summary})
    return {"derived_rules": derived, "derived_rules_summary": derived_rules_summary, "usage": usage}


def node_scan_deep_files(state: SastState) -> dict:
    tracer: AgentTrace = state["_tracer"]
    module_plan = state["module_plan"]
    # module_plan["deep_scan_paths"] (built in node_map_modules_and_risk) is
    # already the capped, priority-ordered CRITICAL/HIGH set — the source of
    # truth for what this tier scans, not a raw risk_level re-derivation.
    deep_files = llm_file_scan.files_for_paths(module_plan, module_plan["deep_scan_paths"])
    deep_file_count = len(deep_files)

    if not state.get("use_llm"):
        tracer.log(7, "scan_deep_files",
                    "Skipping LLM file scan — use_llm is disabled for this scan",
                    narrative="LLM scanning is disabled for this run, so CRITICAL/HIGH files aren't scanned for findings "
                              "(the risk mapping above is path-heuristic only).")
        return {"scan_results": dict(_EMPTY_SCAN_RESULTS)}

    if deep_file_count == 0:
        tracer.log(7, "scan_deep_files", "No CRITICAL/HIGH-risk files selected for LLM scan",
                    narrative="No CRITICAL- or HIGH-risk files were selected for LLM scanning.")
        return {"scan_results": dict(_EMPTY_SCAN_RESULTS)}

    (root, rules, active_frameworks, dependency_index,
     priority_rule_ids, stack_context, usage) = _scan_context(state)
    findings_writer = state.get("findings_writer")
    completed: List[Dict[str, Any]] = []

    tracer.log(7, "scan_deep_files",
                f"Starting LLM scan of {deep_file_count} file(s) "
                f"({len(rules)} catalog rule(s) loaded)",
                narrative=f"Scanning {deep_file_count} CRITICAL/HIGH-risk file(s) with the LLM "
                          f"(rule catalog + OWASP context guide the review, but the LLM owns detection)...")

    def _on_file_start(index: int, total: int, path: str) -> None:
        remaining = total - index
        tracer.log(
            7, "scan_deep_files",
            f"Deep-risk file {index}/{total}: {path}",
            narrative=f"Scanning deep-risk file {index}/{total}: {path} "
                      f"({remaining} remaining after this one).",
        )

    def _on_file(result: Dict[str, Any]) -> None:
        completed.append(result)
        tp, fp = result["tp_count"], result["fp_count"]
        total_findings = tp + fp
        tracer.log(
            7, "scan_deep_files",
            f"{result['file_path']}: {result['chunks']} chunk(s), {tp} TP, {fp} FP",
            narrative=f"  {result['file_path']} — {tp} confirmed, {fp} dismissed "
                      f"({total_findings} saved to database).",
        )
        partial = llm_file_scan.build_report_from_file_results(
            completed + list((state.get("triage_scan_results") or {}).get("files") or [])
        )
        _emit_discovery(state, report=partial)

    scan_results = llm_file_scan.scan_deep_files(
        module_plan=module_plan,
        entries=deep_files,
        repo_root=root,
        rules=rules,
        active_frameworks=active_frameworks,
        dependency_index=dependency_index,
        priority_rule_ids=priority_rule_ids,
        stack_context=stack_context,
        usage=usage,
        llm_provider=state.get("llm_provider"),
        llm_model=state.get("llm_model"),
        findings_writer=findings_writer,
        on_file_start=_on_file_start,
        on_file=_on_file,
        suppress_no_cwe=state.get("suppress_no_cwe_findings", True),
        suppress_http_findings=state.get("suppress_http_findings", False),
        suppress_low_confidence_false_positives=state.get(
            "suppress_low_confidence_false_positives", False
        ),
    )

    tracer.log(7, "scan_deep_files",
                f"LLM scan complete: {scan_results['files_scanned']} file(s), "
                f"{scan_results['tp_count']} TP, {scan_results['fp_count']} FP",
                detail=f"files_scanned={scan_results['files_scanned']}",
                narrative=f"Done — {scan_results['tp_count']} finding(s) confirmed across "
                          f"{scan_results['files_scanned']} CRITICAL/HIGH file(s) "
                          f"({scan_results['fp_count']} dismissed).")

    return {"scan_results": scan_results, "usage": usage}


# ===========================================================================
# STEP 8 — node_scan_triage_files
#   Regex-scan MEDIUM/LOW-risk files, plus any CRITICAL/HIGH overflow past the
#   deep-scan cap. Files with zero hits cost nothing, and machine-generated
#   files are skipped even when they do hit.
#
#   By default (llm_file_scan.TRIAGE_MODE_REGEX_ONLY) the surviving hits become
#   `unverified` findings directly, with no LLM involvement — this is what
#   takes a multi-thousand-file repo from hours to minutes. Set
#   state["triage_mode"] to "llm_triage" to restore the per-file LLM TP/FP
#   ruling instead.
#
#   Runs in batches — one per real module when the repo has more than one,
#   else fixed-size slices of the single bucket — so results and progress
#   narration surface module-by-module on large repos instead of one giant
#   unbroken pass. Batches run strictly sequentially (each batch's worker pool
#   fully drains before the next starts); this trades a small amount of
#   worker-idle time at each boundary for readable per-batch log output.
# ===========================================================================

_DEFAULT_TRIAGE_BATCH_SIZE = 250


def _batch_triage_entries(
    entries: List[Dict[str, Any]], batch_size: int
) -> List[Tuple[str, List[Dict[str, Any]]]]:
    """Partition triage-tier file entries into (label, entries) batches.

    One batch per real module when the repo has more than one distinct
    module; otherwise fixed-size slices of the single "(root)" bucket, in
    original order (which is overflow-CRITICAL/HIGH first, then MEDIUM/LOW —
    see node_map_modules_and_risk)."""
    modules = sorted({e.get("module") or "(root)" for e in entries})
    if len(modules) > 1:
        by_module: Dict[str, List[Dict[str, Any]]] = {}
        for e in entries:
            by_module.setdefault(e.get("module") or "(root)", []).append(e)
        return [(m, by_module[m]) for m in modules]
    batch_size = max(1, batch_size)
    return [
        (f"batch {i // batch_size + 1}", entries[i:i + batch_size])
        for i in range(0, len(entries), batch_size)
    ]


def node_scan_triage_files(state: SastState) -> dict:
    tracer: AgentTrace = state["_tracer"]
    module_plan = state["module_plan"]
    # module_plan["triage_scan_paths"] (built in node_map_modules_and_risk) is
    # the source of truth: MEDIUM/LOW plus any CRITICAL/HIGH overflow past the
    # deep-scan cap, not a raw risk_level re-derivation.
    triage_files = llm_file_scan.files_for_paths(module_plan, module_plan["triage_scan_paths"])
    triage_count = len(triage_files)

    triage_mode = state.get("triage_mode") or llm_file_scan.DEFAULT_TRIAGE_MODE
    regex_only = triage_mode == llm_file_scan.TRIAGE_MODE_REGEX_ONLY

    # `use_llm=False` only disables this tier when the tier would actually call
    # an LLM. In regex-only mode there is nothing to disable, so --no-llm still
    # produces a full set of regex findings.
    if not state.get("use_llm") and not regex_only:
        tracer.log(8, "scan_triage_files",
                    "Skipping MEDIUM/LOW regex+triage scan — use_llm is disabled for this scan",
                    narrative="MEDIUM/LOW regex triage is skipped because LLM scanning is disabled.")
        return {"triage_scan_results": dict(_EMPTY_SCAN_RESULTS)}

    if triage_count == 0:
        tracer.log(8, "scan_triage_files", "No MEDIUM/LOW-risk files to regex-scan",
                    narrative="No MEDIUM- or LOW-risk files were flagged for regex scanning.")
        return {"triage_scan_results": dict(_EMPTY_SCAN_RESULTS)}

    (root, rules, active_frameworks, dependency_index,
     priority_rule_ids, stack_context, usage) = _scan_context(state)
    findings_writer = state.get("findings_writer")
    completed: List[Dict[str, Any]] = []

    batch_size = state.get("triage_batch_size", _DEFAULT_TRIAGE_BATCH_SIZE)
    batches = _batch_triage_entries(triage_files, batch_size)

    mode_note = (
        "hits are recorded directly as unverified findings (no LLM call)"
        if regex_only else
        "only hits go to the LLM for TP/FP"
    )
    tracer.log(8, "scan_triage_files",
                f"Starting MEDIUM/LOW regex scan of {triage_count} file(s) across {len(batches)} batch(es) "
                f"({len(rules)} rule(s), mode={triage_mode}); {mode_note}",
                narrative=f"Regex-scanning {triage_count} MEDIUM/LOW-risk file(s) in {len(batches)} batch(es). "
                          f"Files with no hit are skipped entirely, and machine-generated files are skipped too; "
                          + ("every surviving hit is saved as an unverified finding for review..."
                             if regex_only else
                             "files with hits send just those hits plus surrounding context to the LLM..."))

    def _on_file_start(index: int, total: int, path: str) -> None:
        # Per-file narration is far too noisy in regex-only mode — thousands of
        # files complete in seconds, and the batch lines already show progress.
        if regex_only:
            return
        remaining = total - index
        tracer.log(
            8, "scan_triage_files",
            f"Triage-risk file {index}/{total}: {path}",
            narrative=f"Regex-scanning triage-risk file {index}/{total}: {path} "
                      f"({remaining} remaining after this one).",
        )

    def _on_file(result: Dict[str, Any]) -> None:
        completed.append(result)
        if regex_only:
            # No per-file log line and, crucially, no per-file discovery
            # re-emit: rebuilding the whole report and re-persisting it once
            # per file would dominate the runtime now that the scan itself is
            # this fast. Discovery is emitted once per batch instead (below).
            return
        tp, fp = result["tp_count"], result["fp_count"]
        tracer.log(
            8, "scan_triage_files",
            f"{result['file_path']}: {tp} TP, {fp} FP",
            narrative=f"  {result['file_path']} — {tp} confirmed, {fp} dismissed "
                      f"({tp + fp} saved to database).",
        )
        deep_files = list((state.get("scan_results") or {}).get("files") or [])
        partial = llm_file_scan.build_report_from_file_results(deep_files + completed)
        _emit_discovery(state, report=partial)

    accum = {"files_scanned": 0, "files_regex_scanned": 0, "files_skipped_generated": 0,
             "files_skipped_vendored": 0,
             "tp_count": 0, "fp_count": 0, "unverified_count": 0,
             "chunk_errors": 0, "files": []}

    for batch_index, (label, batch_entries) in enumerate(batches, start=1):
        tracer.log(8, "scan_triage_files",
                    f"Batch {batch_index}/{len(batches)} — {label} ({len(batch_entries)} file(s))",
                    narrative=f"Batch {batch_index}/{len(batches)} — {label}: "
                              f"regex-scanning {len(batch_entries)} file(s)...")

        batch_result = llm_file_scan.scan_triage_files(
            module_plan=module_plan,
            entries=batch_entries,
            repo_root=root,
            rules=rules,
            active_frameworks=active_frameworks,
            dependency_index=dependency_index,
            priority_rule_ids=priority_rule_ids,
            stack_context=stack_context,
            usage=usage,
            llm_provider=state.get("llm_provider"),
            llm_model=state.get("llm_model"),
            findings_writer=findings_writer,
            on_file_start=_on_file_start,
            on_file=_on_file,
            triage_mode=triage_mode,
        )

        for key in ("files_scanned", "files_regex_scanned", "files_skipped_generated",
                    "files_skipped_vendored",
                    "tp_count", "fp_count", "unverified_count", "chunk_errors"):
            accum[key] += batch_result.get(key) or 0
        accum["files"].extend(batch_result.get("files") or [])

        batch_found = (
            f"{batch_result.get('unverified_count') or 0} unverified finding(s)"
            if regex_only else
            f"{batch_result.get('tp_count') or 0} confirmed, {batch_result.get('fp_count') or 0} dismissed"
        )
        tracer.log(8, "scan_triage_files",
                    f"Batch {batch_index}/{len(batches)} complete — {batch_result.get('files_scanned') or 0} of "
                    f"{batch_result.get('files_regex_scanned') or 0} file(s) had hits, {batch_found}",
                    narrative=f"Batch {batch_index}/{len(batches)} done — {batch_found}.")

        # One discovery re-emit per batch rather than per file (see _on_file).
        if regex_only:
            deep_files = list((state.get("scan_results") or {}).get("files") or [])
            _emit_discovery(state, report=llm_file_scan.build_report_from_file_results(
                deep_files + completed
            ))

    triage_scan_results = accum

    regex_scanned = triage_scan_results.get("files_regex_scanned") or 0
    triaged = triage_scan_results["files_scanned"]
    generated_skipped = triage_scan_results.get("files_skipped_generated") or 0
    vendored_skipped = triage_scan_results.get("files_skipped_vendored") or 0
    skipped_total = generated_skipped + vendored_skipped
    generated_note = (
        f" {generated_skipped} machine-generated file(s) were skipped."
        if generated_skipped else ""
    )
    vendored_note = (
        f" {vendored_skipped} vendored/minified file(s) were skipped."
        if vendored_skipped else ""
    )
    if regex_only:
        unverified = triage_scan_results.get("unverified_count") or 0
        tracer.log(8, "scan_triage_files",
                    f"MEDIUM/LOW regex scan complete: {triaged} of {regex_scanned} file(s) had hits, "
                    f"{unverified} unverified finding(s)",
                    detail=f"files_regex_scanned={regex_scanned}, mode=regex_only, "
                           f"generated_skipped={generated_skipped}, vendored_skipped={vendored_skipped}",
                    narrative=f"Done — {unverified} unverified finding(s) recorded from MEDIUM/LOW regex hits "
                              f"(pattern matches, not LLM-reviewed). "
                              f"{max(regex_scanned - triaged - skipped_total, 0)} file(s) had no regex hit."
                              f"{generated_note}{vendored_note}")
    else:
        tracer.log(8, "scan_triage_files",
                    f"MEDIUM/LOW scan complete: {triaged} of {regex_scanned} file(s) had hits, "
                    f"{triage_scan_results['tp_count']} TP, {triage_scan_results['fp_count']} FP",
                    detail=f"files_regex_scanned={regex_scanned}, mode={triage_mode}, "
                           f"generated_skipped={generated_skipped}, vendored_skipped={vendored_skipped}",
                    narrative=f"Done — {triage_scan_results['tp_count']} finding(s) confirmed from MEDIUM/LOW regex hits "
                              f"({triage_scan_results['fp_count']} dismissed). "
                              f"{max(regex_scanned - triaged - skipped_total, 0)} file(s) had no regex hit and cost no LLM call."
                              f"{generated_note}{vendored_note}")

    return {"triage_scan_results": triage_scan_results, "usage": usage}


# ===========================================================================
# STEP 9 — node_group_triage_findings
#   Groups unverified findings (MEDIUM/LOW plus any CRITICAL/HIGH overflow
#   routed into this tier) by construct and reports the collapse — no LLM
#   call, no verdicts touched. TP/FP confirmation of these groups happens
#   immediately after, in node_confirm_triage_groups.
# ===========================================================================

def node_group_triage_findings(state: SastState) -> dict:
    tracer: AgentTrace = state["_tracer"]
    triage_scan_results = state.get("triage_scan_results") or dict(_EMPTY_SCAN_RESULTS)
    file_results = triage_scan_results.get("files") or []

    triage_mode = state.get("triage_mode") or llm_file_scan.DEFAULT_TRIAGE_MODE
    regex_only = triage_mode == llm_file_scan.TRIAGE_MODE_REGEX_ONLY
    group_triage_mode = state.get("group_triage_mode", True)

    if not regex_only:
        tracer.log(9, "group_triage_findings",
                    "Skipping grouping — triage_mode already produced reviewed verdicts",
                    narrative="MEDIUM/LOW findings were already LLM-triaged, so there is nothing unverified to group.")
        return {"triage_scan_results": triage_scan_results}

    if not group_triage_mode:
        tracer.log(9, "group_triage_findings", "Skipping grouping — disabled for this scan",
                    narrative="Grouping of unverified findings is disabled for this run.")
        return {"triage_scan_results": triage_scan_results}

    unverified_before = triage_scan_results.get("unverified_count") or 0
    if unverified_before == 0:
        tracer.log(9, "group_triage_findings", "No unverified MEDIUM/LOW findings to group",
                    narrative="No unverified MEDIUM/LOW findings were produced, so there is nothing to group.")
        return {"triage_scan_results": triage_scan_results}

    grouping = llm_file_scan.group_unverified_findings(file_results)

    top_groups = grouping["groups"][:5]
    top_lines = "; ".join(
        f"{g['rule_id']} x{g['occurrence_count']}" for g in top_groups
    ) or "(none)"
    tracer.log(9, "group_triage_findings",
                f"Grouped {grouping['candidate_count']} unverified finding(s) into "
                f"{grouping['group_count']} unique pattern(s)",
                detail=f"top patterns: {top_lines}",
                narrative=f"Grouped {grouping['candidate_count']} unverified MEDIUM/LOW finding(s) by matched "
                          f"pattern into {grouping['group_count']} unique construct(s) — no LLM call made, "
                          f"verdicts are still unverified. "
                          f"Top pattern(s) by occurrence: {top_lines}.")

    return {"triage_scan_results": triage_scan_results, "triage_group_summary": grouping}


# ===========================================================================
# STEP 9b — node_confirm_triage_groups
#   Optional: TP/FP-confirms the unverified groups from node_group_triage_findings
#   with batched LLM calls (llm_file_scan.group_confirm_unverified_findings).
#   Off by default — state["confirm_triage_groups"] / --confirm-triage-groups.
# ===========================================================================

def node_confirm_triage_groups(state: SastState) -> dict:
    tracer: AgentTrace = state["_tracer"]
    triage_scan_results = state.get("triage_scan_results") or dict(_EMPTY_SCAN_RESULTS)
    triage_group_summary = state.get("triage_group_summary")

    if not state.get("confirm_triage_groups"):
        tracer.log(9, "confirm_triage_groups", "Skipping group confirmation — disabled for this scan",
                    narrative="LLM confirmation of unverified MEDIUM/LOW groups is disabled for this run.")
        return {"triage_scan_results": triage_scan_results}

    if not triage_group_summary or not triage_group_summary.get("group_count"):
        tracer.log(9, "confirm_triage_groups", "No unverified groups to confirm",
                    narrative="No unverified MEDIUM/LOW groups were produced, so there is nothing to confirm.")
        return {"triage_scan_results": triage_scan_results}

    (root, rules, active_frameworks, dependency_index,
     priority_rule_ids, stack_context, usage) = _scan_context(state)

    group_cap = state.get("triage_confirm_group_cap", llm_file_scan.TRIAGE_CONFIRM_GROUP_CAP)
    groups_per_call = state.get("triage_confirm_groups_per_call", llm_file_scan.DEFAULT_GROUPS_PER_CALL)

    file_results = triage_scan_results.get("files") or []
    result = llm_file_scan.group_confirm_unverified_findings(
        file_results=file_results, repo_root=root, rules=rules,
        stack_context=stack_context, usage=usage,
        llm_provider=state.get("llm_provider"), llm_model=state.get("llm_model"),
        group_cap=group_cap, groups_per_call=groups_per_call,
        verdict_updates_writer=state.get("verdict_updates_writer"),
    )

    tracer.log(9, "confirm_triage_groups",
                f"Confirmed {result['confirm_group_count']} of {result['group_count']} group(s): "
                f"{result['tp_group_count']} TP, {result['fp_group_count']} FP, {result['error_group_count']} error(s)",
                detail=f"skipped_by_cap={result['skipped_group_count']}, groups_per_call={groups_per_call}",
                narrative=f"LLM-confirmed {result['confirm_group_count']} of {result['group_count']} unverified "
                          f"pattern group(s) (top by occurrence, capped at {group_cap}), "
                          f"{groups_per_call} per LLM call — {result['tp_group_count']} true positive, "
                          f"{result['fp_group_count']} false positive, {result['error_group_count']} left "
                          f"unverified on LLM error. {result['confirmed_finding_count']} finding(s) updated.")

    merged_summary = dict(triage_group_summary)
    merged_summary["confirm_result"] = result
    return {"triage_scan_results": triage_scan_results, "triage_group_summary": merged_summary}


# ===========================================================================
# STEP 10 — node_generate_report
#   Aggregates deep-scan + regex-triage results into a summary.
# ===========================================================================

def node_generate_report(state: SastState) -> dict:
    tracer: AgentTrace = state["_tracer"]
    deep_files = list((state.get("scan_results") or {}).get("files") or [])
    triage_files = list((state.get("triage_scan_results") or {}).get("files") or [])
    flow_files = list((state.get("flow_scan_results") or {}).get("files") or [])
    report = llm_file_scan.build_report_from_file_results(deep_files + triage_files + flow_files)
    unverified = report.get("unverified_count") or 0
    unverified_note = f", {unverified} unverified" if unverified else ""

    tracer.log(10, "generate_report",
                f"Report: {report['tp_count']} true positive(s), {report['fp_count']} false positive(s)"
                f"{unverified_note} across {report['files_scanned']} file(s)",
                detail=f"by_owasp_category={report['by_owasp_category']}",
                narrative=f"Scan report — {report['tp_count']} confirmed finding(s), {report['fp_count']} dismissed"
                          f"{unverified_note}, across {report['files_scanned']} file(s).")

    _emit_discovery(state, report=report)
    return {"report": report}


# ===========================================================================
# CLI-only disk persist (not a graph node — API scans never write local files)
# ===========================================================================

SQLITE_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    scan_id      TEXT PRIMARY KEY,
    local_path   TEXT NOT NULL,
    scanned_at   TEXT NOT NULL,
    tech_stack   TEXT,
    project_type TEXT,
    confidence   TEXT,
    total_files  INTEGER,
    critical_count INTEGER,
    high_count     INTEGER,
    medium_count   INTEGER,
    low_count      INTEGER
);

CREATE TABLE IF NOT EXISTS scan_files (
    scan_id     TEXT NOT NULL,
    path        TEXT NOT NULL,
    stack       TEXT,
    module      TEXT,
    category    TEXT,
    risk_level  TEXT,
    reason      TEXT,
    FOREIGN KEY (scan_id) REFERENCES scans(scan_id)
);

CREATE INDEX IF NOT EXISTS idx_scan_files_scan_id ON scan_files(scan_id);
CREATE INDEX IF NOT EXISTS idx_scan_files_risk ON scan_files(risk_level);

CREATE TABLE IF NOT EXISTS ast_findings (
    scan_id     TEXT NOT NULL,
    rule_id     TEXT NOT NULL,
    severity    TEXT,
    category    TEXT,
    file_path   TEXT NOT NULL,
    line_number INTEGER,
    llm_verdict TEXT,
    explanation TEXT,
    FOREIGN KEY (scan_id) REFERENCES scans(scan_id)
);

CREATE INDEX IF NOT EXISTS idx_ast_findings_scan_id ON ast_findings(scan_id);
"""


def persist_to_disk(state: SastState) -> Dict[str, Any]:
    """Write JSON + SQLite for standalone CLI runs. Quiet (no AgentTrace banners)."""
    output_dir = state.get("output_dir") or "./sast_output"
    db_path = state.get("db_path") or "./sast_history.db"
    os.makedirs(output_dir, exist_ok=True)

    json_path = os.path.join(output_dir, f"scan_result_{state['scan_id']}.json")
    tracer = state.get("_tracer")
    json_payload = {
        "scan_id": state["scan_id"],
        "local_path": state["local_path"],
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "scan_summary": {k: v for k, v in state["scan"].items() if k != "files"},
        "llm_analysis": state["llm_analysis"],
        "categorized_counts": {k: len(v) for k, v in state["categorized"].items()},
        "module_plan": state["module_plan"],
        "report": state.get("report"),
        "trace": tracer.events if tracer is not None else [],
    }
    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump(json_payload, fh, indent=2)

    conn = sqlite3.connect(db_path)
    try:
        conn.executescript(SQLITE_SCHEMA)
        rc = state["module_plan"]["risk_counts"]
        conn.execute(
            "INSERT INTO scans (scan_id, local_path, scanned_at, tech_stack, project_type, confidence, "
            "total_files, critical_count, high_count, medium_count, low_count) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (
                state["scan_id"], state["local_path"], json_payload["scanned_at"],
                state["llm_analysis"]["tech_stack"], state["llm_analysis"]["project_type"],
                state["llm_analysis"]["confidence"], state["scan"]["total_files"],
                rc.get("CRITICAL", 0), rc.get("HIGH", 0), rc.get("MEDIUM", 0), rc.get("LOW", 0),
            ),
        )
        conn.executemany(
            "INSERT INTO scan_files (scan_id, path, stack, module, category, risk_level, reason) VALUES (?,?,?,?,?,?,?)",
            [
                (state["scan_id"], e["path"], e["stack"], e["module"], e["category"], e["risk_level"], e["reason"])
                for e in state["module_plan"]["files"]
            ],
        )
        conn.commit()
    finally:
        conn.close()

    return {"json_path": json_path, "db_path": db_path}


# ===========================================================================
# GRAPH
# ===========================================================================

def build_graph():
    graph = StateGraph(SastState)
    graph.add_node("scan_directory", node_scan_directory)
    graph.add_node("analyze_tech_stack", node_analyze_tech_stack)
    graph.add_node("categorize_files", node_categorize_files)
    graph.add_node("map_modules_and_risk", node_map_modules_and_risk)
    graph.add_node("build_call_graph", node_build_call_graph)
    graph.add_node("derive_runtime_rules", node_derive_runtime_rules)
    graph.add_node("discover_flows", node_discover_flows)
    graph.add_node("verify_flow_slices", node_verify_flow_slices)
    graph.add_node("scan_deep_files", node_scan_deep_files)
    graph.add_node("scan_triage_files", node_scan_triage_files)
    graph.add_node("group_triage_findings", node_group_triage_findings)
    graph.add_node("confirm_triage_groups", node_confirm_triage_groups)
    graph.add_node("generate_report", node_generate_report)

    graph.add_edge(START, "scan_directory")
    graph.add_edge("scan_directory", "analyze_tech_stack")
    graph.add_edge("analyze_tech_stack", "categorize_files")
    graph.add_edge("categorize_files", "map_modules_and_risk")
    graph.add_edge("map_modules_and_risk", "build_call_graph")
    graph.add_edge("build_call_graph", "derive_runtime_rules")
    graph.add_edge("derive_runtime_rules", "discover_flows")
    graph.add_edge("discover_flows", "verify_flow_slices")
    graph.add_edge("verify_flow_slices", "scan_deep_files")
    graph.add_edge("scan_deep_files", "scan_triage_files")
    graph.add_edge("scan_triage_files", "group_triage_findings")
    graph.add_edge("group_triage_findings", "confirm_triage_groups")
    graph.add_edge("confirm_triage_groups", "generate_report")
    graph.add_edge("generate_report", END)
    return graph.compile()


# ===========================================================================
# CLI
# ===========================================================================

def main() -> None:
    # Windows consoles default to cp1252; tree/narration characters must not crash print().
    for _stream in (sys.stdout, sys.stderr):
        _reconfigure = getattr(_stream, "reconfigure", None)
        if callable(_reconfigure):
            try:
                _reconfigure(encoding="utf-8", errors="replace")
            except (OSError, ValueError, AttributeError):
                pass
    parser = argparse.ArgumentParser(description="Agentic SAST project discovery agent")
    parser.add_argument("--path", required=True, help="Local path to the project to scan")
    parser.add_argument("--scope", default=None, help="Optional subdirectory within --path to limit the scan")
    parser.add_argument("--out", default="./sast_output", help="Directory for the JSON output file")
    parser.add_argument("--db", default="./sast_history.db", help="SQLite DB path for historical tracking")
    parser.add_argument("--no-llm", action="store_true", help="Skip the LLM call; heuristics only")
    parser.add_argument("--llm-provider", choices=["bedrock", "ollama"], default=None)
    parser.add_argument("--llm-model", default=None)
    parser.add_argument("--verbose-files", action="store_true",
                         help="Log every individual file (noisy — off by default; summaries always shown)")
    parser.add_argument("--quiet", action="store_true", help="Suppress live trace printing (still saved to JSON)")
    parser.add_argument("--no-persist", action="store_true",
                         help="Don't write JSON/SQLite output to disk (state is still returned)")
    parser.add_argument("--deep-scan-cap", type=int, default=None,
                         help="Override the top-N CRITICAL/HIGH deep-scan cap (default: "
                              "llm_file_scan.DEEP_SCAN_FILE_CAP)")
    parser.add_argument("--no-backfill-deep-scan", action="store_true",
                         help="Don't backfill spare deep-scan slots with MEDIUM/LOW files "
                              "when CRITICAL/HIGH doesn't fill the cap (default: backfill on)")
    parser.add_argument("--critical-only-deep-scan", action="store_true",
                         help="Only CRITICAL files get the full LLM deep scan; HIGH moves into "
                              "the triage tier with MEDIUM/LOW (pair with --triage-mode llm_triage "
                              "so HIGH/MEDIUM/LOW still get an LLM TP/FP ruling on regex hits, "
                              "i.e. hybrid regex+LLM instead of a full LLM read). Also disables "
                              "deep-scan backfill, so HIGH never re-enters the deep-scan bucket.")
    parser.add_argument("--triage-batch-size", type=int, default=None,
                         help="Override the triage-tier batch size for single-module repos "
                              "(default: node_scan_triage_files._DEFAULT_TRIAGE_BATCH_SIZE)")
    parser.add_argument("--triage-mode", choices=sorted(llm_file_scan.TRIAGE_MODES), default=None,
                         help="How MEDIUM/LOW regex hits become findings: 'regex_only' (default) "
                              "records them as unverified with no LLM call; 'llm_triage' sends each "
                              "file's hits to the LLM for a true/false-positive ruling")
    parser.add_argument("--no-group-triage", action="store_true",
                         help="Skip grouping unverified MEDIUM/LOW findings by construct "
                              "(only applies when --triage-mode is regex_only)")
    parser.add_argument("--confirm-triage-groups", action="store_true",
                         help="LLM-confirm TP/FP for unverified MEDIUM/LOW groups after grouping "
                              "(opt-in, off by default; only applies when --triage-mode is regex_only)")
    parser.add_argument("--triage-confirm-group-cap", type=int, default=None,
                         help="Override the top-N-by-occurrence group confirm cap (default: "
                              "llm_file_scan.TRIAGE_CONFIRM_GROUP_CAP)")
    parser.add_argument("--triage-confirm-groups-per-call", type=int, default=None,
                         help="Override how many groups are packed into one LLM call (default: "
                              "llm_file_scan.DEFAULT_GROUPS_PER_CALL)")
    parser.add_argument("--allow-no-cwe-findings", action="store_true",
                         help="Do not drop deep-scan findings with no CWE mapping "
                              "(suppressed by default)")
    parser.add_argument("--suppress-http-findings", action="store_true",
                         help="Drop deep-scan findings about cleartext HTTP / missing HTTPS "
                              "enforcement (off by default; opt in when HTTPS is enforced at a "
                              "layer this scan can't see)")
    parser.add_argument("--suppress-low-confidence-false-positives", action="store_true",
                         help="Drop deep-scan false_positive findings the model confidently "
                              "self-dismissed (confidence <= "
                              "FALSE_POSITIVE_SUPPRESS_CONFIDENCE_CEILING); off by default here, "
                              "on by default for real (API-triggered) scans")
    parser.add_argument("--no-inter-file-flow", action="store_true",
                         help="Skip Java inter-file call-graph tracing and flow-slice LLM verify")
    parser.add_argument("--flow-verify-cap", type=int, default=None,
                         help="Override max inter-file flow slices sent to the LLM "
                              f"(default: {call_graph.FLOW_VERIFY_CAP})")
    parser.add_argument("--flow-max-depth", type=int, default=None,
                         help="Override max call-graph hops (source to sink) when walking "
                              f"inter-file flows (default: {call_graph.MAX_HOP_DEPTH})")
    parser.add_argument("--no-derived-regex", action="store_true",
                         help="Skip runtime regex derive (call-graph wrappers + LLM pass); "
                              "use the static catalog only")
    parser.add_argument("--max-derived-regex-rules", type=int, default=None,
                         help="Cap on runtime-derived regex rules merged onto the catalog "
                              f"(default: {derive_rules.DEFAULT_MAX_DERIVED})")
    args = parser.parse_args()

    use_llm = not args.no_llm
    tracer = AgentTrace(verbose=not args.quiet)
    initial_state: SastState = {
        "local_path": args.path,
        "scope": args.scope,
        "context_note": "",
        "scan_id": uuid.uuid4().hex[:12],
        "verbose": not args.quiet,
        "verbose_files": args.verbose_files,
        "use_llm": use_llm,
        "llm_provider": args.llm_provider,
        "llm_model": args.llm_model,
        "persist_to_disk": not args.no_persist,
        "output_dir": args.out,
        "db_path": args.db,
        "usage": init_usage(args.llm_provider, args.llm_model),
        "group_triage_mode": not args.no_group_triage,
        "confirm_triage_groups": args.confirm_triage_groups,
        "suppress_no_cwe_findings": not args.allow_no_cwe_findings,
        "suppress_http_findings": args.suppress_http_findings,
        "suppress_low_confidence_false_positives": args.suppress_low_confidence_false_positives,
        "backfill_deep_scan": not args.no_backfill_deep_scan,
        "deep_scan_critical_only": args.critical_only_deep_scan,
        "inter_file_flow": use_llm and not args.no_inter_file_flow,
        "derive_runtime_rules": not args.no_derived_regex,
        "_tracer": tracer,
    }
    if args.flow_verify_cap is not None:
        initial_state["flow_verify_cap"] = args.flow_verify_cap
    if args.flow_max_depth is not None:
        initial_state["flow_max_hop_depth"] = args.flow_max_depth
    if args.max_derived_regex_rules is not None:
        initial_state["max_derived_regex_rules"] = args.max_derived_regex_rules
    if args.deep_scan_cap is not None:
        initial_state["deep_scan_file_cap"] = args.deep_scan_cap
    if args.triage_batch_size is not None:
        initial_state["triage_batch_size"] = args.triage_batch_size
    if args.triage_mode is not None:
        initial_state["triage_mode"] = args.triage_mode
    if args.triage_confirm_group_cap is not None:
        initial_state["triage_confirm_group_cap"] = args.triage_confirm_group_cap
    if args.triage_confirm_groups_per_call is not None:
        initial_state["triage_confirm_groups_per_call"] = args.triage_confirm_groups_per_call

    app = build_graph()
    final_state = invoke_graph(app, initial_state)
    final_state["trace"] = tracer.events

    if not args.no_persist:
        final_state["persisted"] = persist_to_disk(final_state)

    print("\n=== SUMMARY ===")
    print(f"scan_id:      {final_state['scan_id']}")
    print(f"scanned:      {final_state['scan']['root']}")
    print(f"tech_stack:   {final_state['llm_analysis']['tech_stack']}")
    print(f"project_type: {final_state['llm_analysis']['project_type']}")
    print(f"confidence:   {final_state['llm_analysis']['confidence']}")
    print(f"risk_areas:   {final_state['llm_analysis']['risk_areas']}")
    print(f"risk_counts:  {final_state['module_plan']['risk_counts']}")
    report = final_state.get("report") or {}
    print(f"findings:     {report.get('tp_count', 0)} true positive(s), {report.get('fp_count', 0)} false positive(s)")
    if final_state.get("persisted"):
        print(f"JSON:         {final_state['persisted']['json_path']}")
        print(f"SQLite:       {final_state['persisted']['db_path']}")


if __name__ == "__main__":
    main()
