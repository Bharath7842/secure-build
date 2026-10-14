"""joern_runner.py — the only place that shells out to Joern.

Joern (https://joern.io) builds a Code Property Graph (AST + CFG + PDG) and
runs interprocedural dataflow over it. This module wraps the three CLI calls
the pipeline needs — ``joern-parse`` (build a CPG), ``joern --script`` (run a
query script against one) — and nothing else, so every failure mode (binary
missing, timeout, non-zero exit, bad JSON) collapses into a ``None`` return
the caller can fall back from. A scan never fails because Joern did.

``joern-parse`` builds a CPG for exactly one language frontend, so a polyglot
repo gets one CPG per language (see ``languages_for_scan``), each reused by
both ``flows.sc`` and ``queries.sc`` so the parse cost is paid once.

Configuration (env, set by agent_bridge from app.config):
  JOERN_HOME         install dir holding joern/joern-parse (default: PATH)
  JOERN_TIMEOUT_SEC  per-subprocess timeout, default 900
  JOERN_JAVA_OPTS    JVM heap etc. for Joern, e.g. "-Xmx4g"
  JOERN_JAVA_HOME    JDK for Joern only (exported to it as JAVA_HOME). Needed on
                     Apple Silicon when PATH's java is an Intel build — see _env.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import time
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

JOERN_DIR = Path(__file__).resolve().parent.parent / "joern"
FLOWS_SCRIPT = JOERN_DIR / "flows.sc"
QUERIES_SCRIPT = JOERN_DIR / "queries.sc"
TAINT_SPEC = JOERN_DIR / "taint_spec.json"

DEFAULT_TIMEOUT_SEC = 900
DEFAULT_MAX_LANGUAGES = 3
# A language needs at least this many files before it earns its own CPG — one
# stray build script shouldn't cost a JVM start and a full parse.
MIN_FILES_PER_LANGUAGE = 3

# Scan-file extension -> joern-parse --language value. Only frontends whose
# output flows.sc/queries.sc have been checked against are listed.
EXT_TO_FRONTEND: Dict[str, str] = {
    ".java": "javasrc",
    ".py": "pythonsrc",
    ".js": "jssrc", ".jsx": "jssrc", ".ts": "jssrc", ".tsx": "jssrc",
    ".mjs": "jssrc", ".cjs": "jssrc",
    ".c": "c", ".h": "c", ".cc": "c", ".cpp": "c", ".cxx": "c", ".hpp": "c",
    ".go": "golang",
    ".php": "php",
    ".kt": "kotlin",
    ".cs": "csharpsrc",
    ".rb": "rubysrc",
}

# Frontend-relative paths Joern should never parse: tests, deps, build output.
# Matches DEFAULT_SKIP_DIRS in spirit, minus "config" (Spring security config
# lives there and is exactly what we want analysed).
EXCLUDE_REGEX = (
    r"(?i)(.*[\\/])?("
    r"test|tests|__tests__|spec|specs|node_modules|bower_components|vendor|"
    r"target|build|dist|out|bin|obj|venv|\.venv|site-packages|\.[^\\/]+"
    r")[\\/].*|.*\.min\.js"
)


@dataclass
class CpgBuild:
    language: str
    cpg_path: Optional[Path]
    seconds: float
    error: Optional[str] = None


@dataclass
class JoernSession:
    """One scan's CPGs, built once and shared by flows + queries."""

    work_dir: Path
    builds: List[CpgBuild] = field(default_factory=list)

    @property
    def cpgs(self) -> List[CpgBuild]:
        return [b for b in self.builds if b.cpg_path is not None]

    def summary(self) -> Dict[str, Any]:
        return {
            "languages": [b.language for b in self.cpgs],
            "failed": {b.language: b.error for b in self.builds if b.cpg_path is None},
            "cpg_seconds": round(sum(b.seconds for b in self.builds), 1),
        }

    def cleanup(self) -> None:
        shutil.rmtree(self.work_dir, ignore_errors=True)


def _bin_dir() -> Optional[Path]:
    home = (os.environ.get("JOERN_HOME") or "").strip()
    if home:
        p = Path(home).expanduser()
        return p if (p / "joern").exists() else None
    found = shutil.which("joern")
    return Path(found).resolve().parent if found else None


def binary(name: str) -> Optional[str]:
    d = _bin_dir()
    if d is None:
        return None
    p = d / name
    return str(p) if p.exists() else None


def joern_available() -> bool:
    return binary("joern") is not None and binary("joern-parse") is not None


def timeout_sec() -> int:
    try:
        return int(os.environ.get("JOERN_TIMEOUT_SEC") or DEFAULT_TIMEOUT_SEC)
    except ValueError:
        return DEFAULT_TIMEOUT_SEC


def _env() -> Dict[str, str]:
    env = dict(os.environ)
    # Joern's launchers use JAVA_HOME, else the first `java` on PATH. On Apple
    # Silicon an Intel JDK there (e.g. Homebrew under /usr/local) runs under
    # Rosetta, so jssrc2cpg looks for the x86 `astgen-macos` binary that an
    # arm64 Joern install doesn't ship — JS/TS parsing then fails outright.
    java_home = (os.environ.get("JOERN_JAVA_HOME") or "").strip()
    if java_home:
        env["JAVA_HOME"] = str(Path(java_home).expanduser())
    java_opts = (os.environ.get("JOERN_JAVA_OPTS") or "").strip()
    if java_opts:
        # Joern's launch scripts pass JAVA_OPTS through to the JVM.
        env["JAVA_OPTS"] = f"{env.get('JAVA_OPTS', '')} {java_opts}".strip()
    return env


def _run(cmd: List[str], timeout: int, *, cwd: Optional[Path] = None) -> Optional[str]:
    """Run a Joern command. Returns None on success, else a short error."""
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, env=_env(),
            stdin=subprocess.DEVNULL, cwd=str(cwd) if cwd else None,
        )
    except subprocess.TimeoutExpired:
        return f"timeout after {timeout}s"
    except OSError as exc:
        return f"{type(exc).__name__}: {exc}"
    if proc.returncode != 0:
        return f"exit {proc.returncode}: {_error_summary(proc.stdout or '', proc.stderr or '')}"
    return None


def _error_summary(stdout: str, stderr: str) -> str:
    """The first Joern ERROR log line names the cause (missing frontend
    binary, OOM, ...); the stack trace tail usually only names the call site."""
    lines = [l.strip() for l in (stderr + "\n" + stdout).splitlines() if l.strip()]
    for line in lines:
        if " ERROR " in line and "Process exited with code" not in line:
            return line.split(" ERROR ", 1)[1].strip()[:300]
    for line in lines:
        if "OutOfMemoryError" in line:
            return "Java heap exhausted — raise JOERN_JAVA_OPTS (e.g. -Xmx8g)"
    return " | ".join(lines[-3:])[:300]


def languages_for_scan(
    file_paths: Iterable[str],
    *,
    max_languages: int = DEFAULT_MAX_LANGUAGES,
    min_files: int = MIN_FILES_PER_LANGUAGE,
) -> List[str]:
    """Joern frontends for this repo, most files first, capped."""
    counts: Counter = Counter()
    for p in file_paths:
        fe = EXT_TO_FRONTEND.get(Path(p).suffix.lower())
        if fe:
            counts[fe] += 1
    return [fe for fe, n in counts.most_common() if n >= min_files][:max_languages]


def build_cpg(root: Path, out_path: Path, language: str, *, timeout: Optional[int] = None) -> CpgBuild:
    parse = binary("joern-parse")
    start = time.monotonic()
    if parse is None:
        return CpgBuild(language, None, 0.0, "joern-parse not found")
    cmd = [
        parse, str(root), "--language", language, "-o", str(out_path),
        "--frontend-args", "--exclude-regex", EXCLUDE_REGEX,
    ]
    err = _run(cmd, timeout or timeout_sec(), cwd=out_path.parent)
    elapsed = time.monotonic() - start
    if err is None and not out_path.exists():
        err = "joern-parse produced no CPG"
    return CpgBuild(language, None if err else out_path, elapsed, err)


def start_session(
    root: Path,
    languages: List[str],
    *,
    work_dir: Optional[Path] = None,
    timeout: Optional[int] = None,
) -> JoernSession:
    if work_dir is None:
        work_dir = Path(tempfile.mkdtemp(prefix="sast-joern-"))
    else:
        work_dir.mkdir(parents=True, exist_ok=True)
    session = JoernSession(work_dir=work_dir)
    for lang in languages:
        session.builds.append(build_cpg(root, work_dir / f"cpg_{lang}.bin", lang, timeout=timeout))
    return session


def run_script(
    cpg_path: Path,
    script: Path,
    params: Optional[Dict[str, Any]] = None,
    *,
    timeout: Optional[int] = None,
    allow_partial: bool = False,
) -> Optional[Dict[str, Any]]:
    """Run a ``@main def exec(cpgFile, outFile, ...)`` script; return its JSON.

    Results come back through ``outFile`` rather than stdout — Joern's console
    output mixes banners and log lines with no stable format.

    Joern runs with the CPG's directory as its working directory: ``importCpg``
    copies the graph into ``./workspace/<name>``, and that has to land in the
    session's temp dir (removed by ``JoernSession.cleanup``) rather than
    wherever the backend was started, where copies piled up forever.

    ``allow_partial``: a script that rewrites ``outFile`` as it goes (flows.sc,
    marked ``"complete": false``) still returns what it wrote before failing
    or timing out, instead of None.
    """
    joern = binary("joern")
    if joern is None:
        return None
    out_file = cpg_path.with_suffix(f".{script.stem}.json")
    out_file.unlink(missing_ok=True)
    cmd = [joern, "--script", str(script), "--param", f"cpgFile={cpg_path}",
           "--param", f"outFile={out_file}"]
    for key, value in (params or {}).items():
        cmd += ["--param", f"{key}={value}"]
    err = _run(cmd, timeout or timeout_sec(), cwd=cpg_path.parent)
    if not out_file.exists() or (err is not None and not allow_partial):
        return None
    try:
        data = json.loads(out_file.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if err is not None:
        if not isinstance(data, dict) or data.get("complete") is not False:
            return None
        data["error"] = err
    return data


def run_flows(cpg_path: Path, *, max_flows: int = 200, timeout: Optional[int] = None) -> Optional[Dict[str, Any]]:
    """flows.sc results. ``max_flows`` caps each sink kind, not the total, so
    a noisy kind (log, response_body) can't crowd out SQL/command flows."""
    return run_script(cpg_path, FLOWS_SCRIPT,
                      {"specFile": TAINT_SPEC, "maxFlows": max_flows}, timeout=timeout,
                      allow_partial=True)


def run_queries(cpg_path: Path, *, timeout: Optional[int] = None) -> Optional[Dict[str, Any]]:
    return run_script(cpg_path, QUERIES_SCRIPT, timeout=timeout)
