#!/usr/bin/env python3
"""
Agentic SAST Project Structure Analyzer — Phase 1 (Discovery & Scanning)
=========================================================================

LangGraph-orchestrated agent that:
  Step 1  scan_directory        -> walks the project, lists files/folders, notes types & depth
  Step 2  analyze_tech_stack    -> LLM (Claude Haiku on Bedrock) identifies stack/project type/risk areas
  Step 3  categorize_files      -> buckets files: source / config / dependency / test / build
  Step 4  map_modules_and_risk  -> stack-specific module & risk mapping (Maven example + generic profiles
                                    for Angular / .NET / Python / Node; unknown stacks fall back to a
                                    generic heuristic so the agent never dead-ends on an unrecognized stack)
  Step 5  persist_results       -> writes JSON (for immediate Phase-2 LLM consumption) + SQLite
                                    (for historical tracking / reporting), per Ganesh's storage call

Every node emits structured trace events (AgentTrace) so you can see exactly what the agent
looked at and why it made each call — printed live in default mode, and always saved in full
inside the output JSON's "trace" key regardless of verbosity setting.

Usage:
    python sast_agent.py /path/to/project
    python sast_agent.py /path/to/project --verbose-files --db sast_history.db --out ./sast_output
    python sast_agent.py /path/to/project --no-llm            # skip Bedrock call, heuristics only
    python sast_agent.py /path/to/project --region us-east-1 --model us.anthropic.claude-haiku-4-5-20251001-v1:0

Requires: langgraph, boto3 (only needed if you don't pass --no-llm and want the real LLM step)
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import os
import re
import sqlite3
import sys
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, TypedDict

# ---------------------------------------------------------------------------
# LangGraph
# ---------------------------------------------------------------------------
from langgraph.graph import StateGraph, START, END


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
    ".html": "HTML", ".css": "CSS", ".scss": "SCSS",
    ".sql": "SQL",
    ".yml": "YAML", ".yaml": "YAML",
    ".json": "JSON", ".xml": "XML", ".toml": "TOML",
    ".properties": "Java Properties", ".env": "Env File",
    ".sh": "Shell", ".ps1": "PowerShell", ".bat": "Batch",
    ".dockerfile": "Docker", ".tf": "Terraform",
    ".md": "Markdown",
}

# Directories that are never worth scanning for source-level SAST findings.
DEFAULT_SKIP_DIRS = {
    ".git", ".svn", ".hg",
    "node_modules", "bower_components",
    "target", "build", "dist", "out", "bin", "obj",
    "__pycache__", ".mypy_cache", ".pytest_cache",
    ".venv", "venv", "env",
    ".idea", ".vscode", ".vs",
    "vendor", ".gradle", ".mvn", ".angular", ".next", "coverage",
}

RiskRule = tuple  # (pattern, risk_level, reason, category) — pattern matched against POSIX-style relative path

# Per-stack module/risk profiles. `markers` = files whose presence identifies the stack.
# `rules` are evaluated top-to-bottom, first match wins (order matters: specific before generic).
STACK_PROFILES: Dict[str, Dict[str, Any]] = {
    "maven-java": {
        "label": "Maven / Java",
        "markers": ["pom.xml"],
        "rules": [
            (r"(^|/)pom\.xml$",                                   "CRITICAL", "dependency & plugin manifest",        "dependency"),
            (r"(^|/)src/main/java/.*/(controller|controllers|web|rest)/", "HIGH",     "user input entry point (controller layer)", "source"),
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
            (r"(^|/)package\.json$",                    "CRITICAL", "dependency manifest",                   "dependency"),
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
            (r"\.(csproj|sln)$",                          "CRITICAL", "project / dependency manifest",         "dependency"),
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
            (r"(^|/)(requirements.*\.txt|pyproject\.toml|setup\.py|Pipfile)$", "CRITICAL", "dependency manifest", "dependency"),
            (r"(^|/)(views|routes|api)\.py$",               "HIGH",     "user input entry point",                "source"),
            (r"(^|/)(routes?|views?|api)/",                 "HIGH",     "user input entry point",                "source"),
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
            (r"(^|/)package\.json$",                        "CRITICAL", "dependency manifest",                   "dependency"),
            (r"(^|/)(routes?|controllers?)/",                "HIGH",     "user input entry point",                "source"),
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
    (r"(^|/)src/",                                  "MEDIUM",   "generic source directory",              "source"),
    (r"(^|/)(test|tests|spec|specs)/",              "LOW",      "generic test directory",                "test"),
    (r".*",                                         "LOW",      "unclassified file",                     "other"),
]

DEPENDENCY_MARKER_FILES = {
    "pom.xml": "maven-java", "build.gradle": "maven-java", "build.gradle.kts": "maven-java",
    "package.json": "nodejs-generic", "angular.json": "angular",
    "requirements.txt": "python", "pyproject.toml": "python", "setup.py": "python", "Pipfile": "python",
    "go.mod": "go-generic",
}
DEPENDENCY_MARKER_EXTS = {".csproj": "dotnet", ".sln": "dotnet"}


# ===========================================================================
# 1. TRACE — visibility into what the agent is doing at every step
# ===========================================================================

class AgentTrace:
    """Collects structured step-by-step events (always kept in full, for the JSON trace)
    and — when verbose — prints a natural-language narration of what's happening, without
    step numbers or node-name tags cluttering the console."""

    def __init__(self, verbose: bool = True):
        self.verbose = verbose
        self.events: List[Dict[str, Any]] = []

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
        if self.verbose and narrative:
            print(narrative)

    def say(self, text: str, end: str = "\n") -> None:
        """Print a line with no structured event behind it — pure narration."""
        if self.verbose:
            print(text, end=end, flush=True)


# ===========================================================================
# 2. STATE — what flows between LangGraph nodes
# ===========================================================================

class SASTState(TypedDict, total=False):
    project_path: str
    scan_id: str
    verbose_files: bool
    use_llm: bool
    aws_region: str
    bedrock_model_id: str
    output_dir: str
    db_path: str

    scan: Dict[str, Any]              # Step 1 output
    llm_analysis: Dict[str, Any]      # Step 2 output
    categorized: Dict[str, Any]       # Step 3 output
    module_plan: Dict[str, Any]       # Step 4 output
    persisted: Dict[str, Any]         # Step 5 output

    trace: List[Dict[str, Any]]
    _tracer: Any                      # AgentTrace instance (not serialized to JSON)


def to_posix(path: str) -> str:
    return path.replace(os.sep, "/")


# ===========================================================================
# STEP 1 — scan_directory
#   Lists all files/folders, identifies file types, notes directory depth.
# ===========================================================================

def scan_directory(state: SASTState) -> SASTState:
    tracer: AgentTrace = state["_tracer"]
    root = state["project_path"]
    tracer.log(1, "scan_directory", f"Starting directory walk at: {root}",
                narrative=f"Looking through {root}...")

    files: List[Dict[str, Any]] = []
    dirs_seen: List[str] = []
    ext_counts: Dict[str, int] = {}
    max_depth = 0
    marker_files_found: List[str] = []

    for current_root, dirnames, filenames in os.walk(root):
        # prune skip-dirs in place so os.walk doesn't descend into them
        pruned = [d for d in dirnames if d in DEFAULT_SKIP_DIRS or d.startswith(".")]
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
            rel_path = to_posix(os.path.join(rel_dir, fname)) if rel_dir else fname
            ext = os.path.splitext(fname)[1].lower()
            lang = EXT_LANG_MAP.get(ext, None)
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
        "root": root,
        "total_files": len(files),
        "max_depth": max_depth,
        "top_level_entries": top_level_dirs,
        "extension_histogram": dict(sorted(ext_counts.items(), key=lambda kv: -kv[1])),
        "marker_files_found": marker_files_found,
        "files": files,
    }
    state["scan"] = scan_summary

    tracer.log(1, "scan_directory",
                f"Walk complete: {len(files)} files across {len(dirs_seen)} directories, max depth {max_depth}",
                detail=f"top-level entries: {', '.join(top_level_dirs) if top_level_dirs else '(none)'}",
                narrative=f"Found {len(files)} files across {len(dirs_seen)} directories (max depth {max_depth}) — "
                          f"top-level: {', '.join(top_level_dirs) if top_level_dirs else '(none)'}.")
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

    return state


# ===========================================================================
# STEP 2 — analyze_tech_stack (LLM)
#   Heuristic stack detection (fast, offline) + Claude Haiku on Bedrock for
#   project type / risk-area reasoning. Falls back cleanly if Bedrock is
#   unavailable (no creds, no network) so the pipeline never hard-fails.
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


def _build_llm_prompt(scan: Dict[str, Any], heuristic_stacks: List[str]) -> str:
    hist = list(scan["extension_histogram"].items())[:15]
    return f"""You are assisting a SAST (static application security testing) agent's project-discovery phase.

Scan summary:
- top-level entries: {scan['top_level_entries']}
- marker files found: {scan['marker_files_found']}
- heuristically detected stacks: {heuristic_stacks}
- file extension histogram (top 15): {hist}
- total files: {scan['total_files']}, max directory depth: {scan['max_depth']}

First, in 2-3 plain sentences, think out loud about what stack this looks like, what kind of
application it probably is, and where the security risk is likely concentrated.

Then, on its own line, write exactly: ---JSON---
Then output ONLY a JSON object (no markdown fences) with exactly these keys:
{{
  "tech_stack": "<primary stack(s), e.g. 'Maven/Java + Angular monorepo'>",
  "project_type": "<web app | REST API | library | CLI tool | microservice | mobile backend | other>",
  "confidence": "<low|medium|high>",
  "risk_areas": ["<short phrase>", "..."],
  "reasoning": "<1-3 sentences>"
}}"""


def call_bedrock_haiku(prompt: str, region: str, model_id: str) -> str:
    """Blocking call — waits for the full response, returns it in one shot."""
    import boto3
    client = boto3.client("bedrock-runtime", region_name=region)
    body = {
        "anthropic_version": "bedrock-2023-05-31",
        "max_tokens": 700,
        "messages": [{"role": "user", "content": prompt}],
    }
    resp = client.invoke_model(modelId=model_id, body=json.dumps(body))
    payload = json.loads(resp["body"].read())
    return payload["content"][0]["text"]


def call_bedrock_haiku_stream(prompt: str, region: str, model_id: str, tracer: "AgentTrace",
                               step: int = 2, node: str = "analyze_tech_stack") -> str:
    """Streaming call — uses invoke_model_with_response_stream and prints each text delta
    as it arrives, the same way tokens stream in the Bedrock/Anthropic console. Returns the
    fully assembled text once the stream ends, for downstream JSON parsing."""
    import boto3
    client = boto3.client("bedrock-runtime", region_name=region)
    body = {
        "anthropic_version": "bedrock-2023-05-31",
        "max_tokens": 700,
        "messages": [{"role": "user", "content": prompt}],
    }
    resp = client.invoke_model_with_response_stream(modelId=model_id, body=json.dumps(body))

    full_text = ""
    printed_upto = 0
    marker = "---JSON---"
    marker_found = False
    tracer.say("Thinking through the stack, project type, and likely risk areas...\n  ")

    for event in resp["body"]:
        chunk = event.get("chunk")
        if not chunk:
            continue
        payload = json.loads(chunk["bytes"])
        # Bedrock's Anthropic Messages-API stream shape: message_start, content_block_delta
        # (carries the actual text pieces), content_block_stop, message_delta, message_stop.
        if payload.get("type") != "content_block_delta":
            continue
        full_text += payload.get("delta", {}).get("text", "")

        if marker_found:
            continue  # past the reasoning prose now — stay quiet through the JSON block

        idx = full_text.find(marker, printed_upto)
        if idx != -1:
            tracer.say(full_text[printed_upto:idx], end="")
            printed_upto = len(full_text)
            marker_found = True
        else:
            # hold back a small tail in case it's the start of a marker split across chunks
            safe_upto = max(printed_upto, len(full_text) - (len(marker) - 1))
            if safe_upto > printed_upto:
                tracer.say(full_text[printed_upto:safe_upto], end="")
                printed_upto = safe_upto

    tracer.say("")  # newline to close out the streamed line
    return full_text


def _parse_llm_json(text: str) -> Optional[Dict[str, Any]]:
    cleaned = text.strip()
    if "---JSON---" in cleaned:
        cleaned = cleaned.split("---JSON---", 1)[1].strip()
    if cleaned.startswith("```"):
        cleaned = re.sub(r"^```(json)?", "", cleaned).strip()
        cleaned = re.sub(r"```$", "", cleaned).strip()
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        match = re.search(r"\{.*\}", cleaned, re.DOTALL)
        if match:
            try:
                return json.loads(match.group(0))
            except json.JSONDecodeError:
                return None
    return None


def analyze_tech_stack(state: SASTState) -> SASTState:
    tracer: AgentTrace = state["_tracer"]
    scan = state["scan"]

    heuristic_stacks = detect_stacks_heuristic(scan)
    tracer.log(2, "analyze_tech_stack", "Ran offline heuristic stack detection from marker files",
                detail=f"candidates: {heuristic_stacks}",
                narrative=f"Based on the marker files, this looks like: {', '.join(heuristic_stacks)}.")

    result: Dict[str, Any] = {
        "heuristic_stacks": heuristic_stacks,
        "llm_used": False,
        "tech_stack": " + ".join(s for s in heuristic_stacks if s != "unknown") or "Unrecognized stack",
        "project_type": "unknown",
        "confidence": "low",
        "risk_areas": [],
        "reasoning": "Heuristic-only result (LLM step skipped or unavailable).",
    }

    if not state.get("use_llm", True):
        tracer.log(2, "analyze_tech_stack", "LLM step skipped (--no-llm flag set); using heuristic result only",
                    narrative="Skipping the LLM reasoning pass (heuristics only) as requested.")
        state["llm_analysis"] = result
        return state

    prompt = _build_llm_prompt(scan, heuristic_stacks)
    tracer.log(2, "analyze_tech_stack", "Calling Claude Haiku on Bedrock to reason about stack/project type/risk areas",
                detail=f"model={state.get('bedrock_model_id')}, region={state.get('aws_region')}, "
                       f"stream={state.get('stream_llm', True)}")

    try:
        if state.get("stream_llm", True):
            raw = call_bedrock_haiku_stream(prompt, state["aws_region"], state["bedrock_model_id"], tracer)
        else:
            tracer.say("Asking Claude Haiku to reason about the stack, project type, and risk areas...")
            raw = call_bedrock_haiku(prompt, state["aws_region"], state["bedrock_model_id"])
        parsed = _parse_llm_json(raw)
        if parsed is None:
            raise ValueError(f"could not parse JSON from model output: {raw[:200]!r}")
        result.update(parsed)
        result["llm_used"] = True
        tracer.log(2, "analyze_tech_stack", "Bedrock call succeeded, parsed structured verdict",
                    detail=f"tech_stack={result.get('tech_stack')}, project_type={result.get('project_type')}, "
                           f"risk_areas={result.get('risk_areas')}",
                    narrative=f"→ {result.get('tech_stack')}, a {result.get('project_type')}. "
                              f"Risk areas to prioritize: {', '.join(result.get('risk_areas', [])) or 'none flagged'}.")
    except Exception as exc:  # noqa: BLE001 — deliberately broad: any failure must degrade gracefully
        tracer.log(2, "analyze_tech_stack", "Bedrock call failed — falling back to heuristic-only result",
                    detail=f"{type(exc).__name__}: {exc}",
                    narrative=f"Couldn't reach Bedrock ({type(exc).__name__}) — continuing with the heuristic guess instead.")

    state["llm_analysis"] = result
    return state


# ===========================================================================
# STEP 3 — categorize_files
#   Buckets every file into: source / config / dependency / test / build / other
#   using the matched stack profile's rules (generic fallback if no stack rule fires).
# ===========================================================================

def _match_rules(rel_path: str, rules: List[RiskRule]):
    for pattern, risk, reason, category in rules:
        if re.search(pattern, rel_path):
            return risk, reason, category
    return None


def categorize_files(state: SASTState) -> SASTState:
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
                        narrative=f"  {f['path']} → {category}")

    counts = {k: len(v) for k, v in buckets.items()}
    state["categorized"] = buckets
    tracer.log(3, "categorize_files", "Categorization complete", detail=f"counts: {counts}",
                narrative=f"Done — {counts['source']} source, {counts['config']} config, "
                          f"{counts['dependency']} dependency, {counts['test']} test, {counts['build']} build.")
    return state


# ===========================================================================
# STEP 4 — map_modules_and_risk
#   Stack-specific module & risk-level mapping (the "what to actually feed the
#   scanner" output). Generic across Maven, Angular, .NET, Python, Node — and
#   degrades to GENERIC_FALLBACK_RULES for anything unrecognized.
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


def map_modules_and_risk(state: SASTState) -> SASTState:
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

        # which module does this file belong to?
        module = "(root)"
        if matched_stack in modules_by_stack:
            candidates = [m for m in modules_by_stack[matched_stack] if m != "(root)" and f["path"].startswith(m + "/")]
            if candidates:
                module = max(candidates, key=len)

        entry = {
            "path": f["path"], "stack": matched_stack, "module": module,
            "category": category, "risk_level": risk, "reason": reason,
        }
        file_risk.append(entry)

        if state.get("verbose_files") and risk in ("CRITICAL", "HIGH"):
            tracer.log(4, "map_modules_and_risk", f"{f['path']} -> {risk}",
                        detail=f"module={module}, category={category}, reason={reason}",
                        narrative=f"  {f['path']} → {risk} ({reason})")

    module_plan = {
        "modules_by_stack": modules_by_stack,
        "risk_counts": risk_counts,
        "files": file_risk,
        "scan_priority": [e for e in file_risk if e["risk_level"] == "CRITICAL"] +
                          [e for e in file_risk if e["risk_level"] == "HIGH"],
    }
    state["module_plan"] = module_plan

    tracer.log(4, "map_modules_and_risk", "Risk mapping complete",
                detail=f"{risk_counts} — {len(module_plan['scan_priority'])} files flagged CRITICAL/HIGH for priority scan",
                narrative=f"{risk_counts['CRITICAL']} critical, {risk_counts['HIGH']} high, {risk_counts['MEDIUM']} medium, "
                          f"{risk_counts['LOW']} low — {len(module_plan['scan_priority'])} files go into the Phase 2 priority queue.")
    return state


# ===========================================================================
# STEP 5 — persist_results
#   JSON  -> immediate hand-off to Phase 2 (LLM/scanner needs it right away)
#   SQLite -> historical tracking & cross-run reporting
# ===========================================================================

SQLITE_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    scan_id      TEXT PRIMARY KEY,
    project_path TEXT NOT NULL,
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
"""


def persist_results(state: SASTState) -> SASTState:
    tracer: AgentTrace = state["_tracer"]
    os.makedirs(state["output_dir"], exist_ok=True)

    # ---- JSON (Phase 2 hand-off) -----------------------------------------
    json_path = os.path.join(state["output_dir"], f"scan_result_{state['scan_id']}.json")
    json_payload = {
        "scan_id": state["scan_id"],
        "project_path": state["project_path"],
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "scan_summary": {k: v for k, v in state["scan"].items() if k != "files"},  # omit raw file list, kept below
        "llm_analysis": state["llm_analysis"],
        "categorized_counts": {k: len(v) for k, v in state["categorized"].items()},
        "module_plan": state["module_plan"],
        "trace": tracer.events,
    }
    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump(json_payload, fh, indent=2)
    tracer.log(5, "persist_results", "Wrote JSON hand-off file for Phase 2", detail=json_path,
                narrative=f"Saved the scan results to {json_path} — ready for Phase 2.")

    # ---- SQLite (historical tracking) -------------------------------------
    db_path = state["db_path"]
    conn = sqlite3.connect(db_path)
    try:
        conn.executescript(SQLITE_SCHEMA)
        rc = state["module_plan"]["risk_counts"]
        conn.execute(
            "INSERT INTO scans (scan_id, project_path, scanned_at, tech_stack, project_type, confidence, "
            "total_files, critical_count, high_count, medium_count, low_count) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (
                state["scan_id"], state["project_path"], json_payload["scanned_at"],
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
        n_files = len(state["module_plan"]["files"])
    finally:
        conn.close()

    tracer.log(5, "persist_results", f"Wrote {n_files} file records to SQLite for historical tracking", detail=db_path,
                narrative=f"Logged {n_files} file records to {db_path} for history/reporting.")

    state["persisted"] = {"json_path": json_path, "db_path": db_path}
    return state


# ===========================================================================
# GRAPH — linear Phase-1 pipeline
# ===========================================================================

def build_graph():
    graph = StateGraph(SASTState)
    graph.add_node("scan_directory", scan_directory)
    graph.add_node("analyze_tech_stack", analyze_tech_stack)
    graph.add_node("categorize_files", categorize_files)
    graph.add_node("map_modules_and_risk", map_modules_and_risk)
    graph.add_node("persist_results", persist_results)

    graph.add_edge(START, "scan_directory")
    graph.add_edge("scan_directory", "analyze_tech_stack")
    graph.add_edge("analyze_tech_stack", "categorize_files")
    graph.add_edge("categorize_files", "map_modules_and_risk")
    graph.add_edge("map_modules_and_risk", "persist_results")
    graph.add_edge("persist_results", END)
    return graph.compile()


def run(
    project_path: str,
    verbose: bool = True,
    verbose_files: bool = False,
    use_llm: bool = True,
    stream_llm: bool = True,
    stream_graph: bool = True,
    aws_region: str = "us-east-1",
    bedrock_model_id: str = "us.anthropic.claude-haiku-4-5-20251001-v1:0",
    output_dir: str = "./sast_output",
    db_path: str = "./sast_history.db",
) -> SASTState:
    tracer = AgentTrace(verbose=verbose)
    initial_state: SASTState = {
        "project_path": project_path,
        "scan_id": uuid.uuid4().hex[:12],
        "verbose_files": verbose_files,
        "use_llm": use_llm,
        "stream_llm": stream_llm,
        "aws_region": aws_region,
        "bedrock_model_id": bedrock_model_id,
        "output_dir": output_dir,
        "db_path": db_path,
        "_tracer": tracer,
    }
    app = build_graph()

    if not stream_graph:
        # Original behavior: one blocking call, graph runs start-to-finish, returns once.
        final_state = app.invoke(initial_state)
    else:
        # LangGraph's own streaming: we consume its event generator (rather than a single
        # blocking .invoke()) so each node's result lands as soon as it's ready — the console
        # narration above comes from inside the nodes themselves as they run, not from this loop.
        final_state: SASTState = dict(initial_state)  # type: ignore[assignment]
        for update in app.stream(initial_state, stream_mode="updates"):
            for node_name, node_output in update.items():
                final_state.update(node_output)

    final_state["trace"] = tracer.events
    return final_state


# ===========================================================================
# CLI
# ===========================================================================

def main():
    parser = argparse.ArgumentParser(description="Agentic SAST project structure analyzer (Phase 1)")
    parser.add_argument("project_path", help="Path to the project to scan")
    parser.add_argument("--out", default="./sast_output", help="Directory for the JSON hand-off file")
    parser.add_argument("--db", default="./sast_history.db", help="SQLite DB path for historical tracking")
    parser.add_argument("--region", default="us-east-1", help="AWS region for Bedrock")
    parser.add_argument("--model", default="us.anthropic.claude-haiku-4-5-20251001-v1:0", help="Bedrock model id")
    parser.add_argument("--no-llm", action="store_true", help="Skip the Bedrock call; heuristics only")
    parser.add_argument("--no-stream-llm", action="store_true",
                         help="Wait for the full Bedrock response instead of streaming tokens live")
    parser.add_argument("--no-stream-graph", action="store_true",
                         help="Use LangGraph's blocking .invoke() instead of its .stream() event API")
    parser.add_argument("--verbose-files", action="store_true",
                         help="Log every individual file (noisy — off by default; summaries always shown)")
    parser.add_argument("--quiet", action="store_true", help="Suppress live trace printing (still saved to JSON)")
    args = parser.parse_args()

    final_state = run(
        project_path=args.project_path,
        verbose=not args.quiet,
        verbose_files=args.verbose_files,
        use_llm=not args.no_llm,
        stream_llm=not args.no_stream_llm,
        stream_graph=not args.no_stream_graph,
        aws_region=args.region,
        bedrock_model_id=args.model,
        output_dir=args.out,
        db_path=args.db,
    )

    print("\n=== SUMMARY ===")
    print(f"scan_id:      {final_state['scan_id']}")
    print(f"tech_stack:   {final_state['llm_analysis']['tech_stack']}")
    print(f"project_type: {final_state['llm_analysis']['project_type']}")
    print(f"risk_areas:   {final_state['llm_analysis']['risk_areas']}")
    print(f"risk_counts:  {final_state['module_plan']['risk_counts']}")
    print(f"JSON:         {final_state['persisted']['json_path']}")
    print(f"SQLite:       {final_state['persisted']['db_path']}")


if __name__ == "__main__":
    main()