"""ripgrep execution for the hunt, hardened for LLM-written patterns.

Every pattern and glob here may have been written by a model reading
untrusted repository text, so:

* patterns are passed as `--regexp=<p>` (a leading `-` can never become a
  flag) and globs as `--glob=<g>`, in an argv list, never through a shell;
* globs must be relative with no `..`, and every result path is resolved
  and confined to the repo root, then post-filtered to the engine's own file
  inventory so the hunt sees exactly the scan's scope;
* the default (Rust) regex engine runs in linear time; PCRE2 — only used
  when a pattern needs look-around/backreferences and the binary has it —
  gets a static nested-quantifier check and a shorter timeout;
* output is streamed and the process killed past `max_output_bytes`, with
  `--dfa-size-limit`/`--regex-size-limit`/`--max-filesize`/`--max-columns`
  bounding memory per pattern and per file.

Memory: rg is started through `/bin/sh -c 'ulimit -v <kb>; exec "$0" "$@"'`
so the child caps its own address space before becoming rg (same PID, so
timeouts still kill rg). preexec_fn would do the same in-process, but it is
documented as unsafe (it can deadlock the child) when the parent has threads,
and hunters run on worker threads. The rg arguments travel as "$@", never
through the script text. Linux enforces the cap; macOS refuses RLIMIT_AS, so
there it is best-effort and `memory_limit_enforced()` reports False.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Collection, Dict, Iterable, List, Optional, Sequence, Tuple

MAX_PATTERN_CHARS = 400
MAX_ALTERNATIONS = 12
MAX_GLOB_CHARS = 200
DEFAULT_TIMEOUT_SECONDS = 20.0
PCRE2_TIMEOUT_SECONDS = 10.0
DEFAULT_MAX_OUTPUT_BYTES = 8 * 1024 * 1024
DEFAULT_MAX_COUNT_PER_FILE = 50
DEFAULT_THREADS = 4
MAX_LINE_CHARS = 400
REGEX_SIZE_LIMIT = "10M"
DEFAULT_MEMORY_LIMIT_MB = int(os.environ.get("RG_MEMORY_LIMIT_MB", "2048"))  # 0 disables
_SH = "/bin/sh"

ENGINE_DEFAULT = "default"
ENGINE_PCRE2 = "pcre2"

# Mirrors sast_scan_agent.DEFAULT_SKIP_DIRS — only a speed-up (the inventory
# post-filter is what actually enforces scope), so drift here can't widen it.
SKIP_DIRS = (
    ".git", ".svn", ".hg", "node_modules", "bower_components", "target", "build",
    "dist", "out", "bin", "obj", "__pycache__", ".mypy_cache", ".pytest_cache",
    ".venv", "venv", "env", ".idea", ".vscode", ".vs", "vendor", ".gradle", ".mvn",
    ".angular", ".next", "coverage", "cvs", "xsd",
)

# (a+)+, (.*)*, (\w+){2,} ... — catastrophic only under a backtracking
# engine, i.e. PCRE2.
_NESTED_QUANTIFIER_RE = re.compile(r"\((?:[^()\\]|\\.)*[+*}]\)\s*[+*{]")
_BACKREF_RE = re.compile(r"\\[1-9]|\\k<")
_NEEDS_PCRE2_RE = re.compile(r"look-?around|look-?ahead|look-?behind|backreference", re.IGNORECASE)


def find_rg_binary() -> Optional[str]:
    """RG_PATH, then PATH, then the running interpreter's bin/ (where the
    `ripgrep` wheel in requirements.txt installs it even when the venv's bin
    is not on PATH)."""
    explicit = os.environ.get("RG_PATH", "").strip()
    if explicit:
        return explicit if os.access(explicit, os.X_OK) else None
    found = shutil.which("rg")
    if found:
        return found
    for candidate in (
        Path(sys.executable).parent / "rg",
        Path(sys.prefix) / "bin" / "rg",
        Path(sys.prefix) / "Scripts" / "rg.exe",
    ):
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
    return None


@dataclass(frozen=True)
class RgMatch:
    file: str  # repo-relative POSIX path
    line: int
    text: str
    submatches: Tuple[str, ...] = ()


@dataclass
class RgResult:
    ok: bool
    engine: str = ENGINE_DEFAULT
    matches: List[RgMatch] = field(default_factory=list)
    # {file: {line: text}} for --context lines (match lines are not repeated)
    context: Dict[str, Dict[int, str]] = field(default_factory=dict)
    files: List[str] = field(default_factory=list)  # for files_with_matches()
    error: Optional[str] = None
    hint: Optional[str] = None
    timed_out: bool = False
    output_truncated: bool = False
    dropped_out_of_scope: int = 0
    elapsed_ms: int = 0

    @property
    def match_count(self) -> int:
        return len(self.matches)

    @property
    def file_count(self) -> int:
        return len({m.file for m in self.matches}) if self.matches else len(self.files)


class PatternRejected(ValueError):
    pass


def check_pattern_policy(pattern: str, *, pcre2: bool) -> None:
    """Static checks that apply before rg ever sees the pattern."""
    if not pattern or not pattern.strip():
        raise PatternRejected("empty pattern")
    if len(pattern) > MAX_PATTERN_CHARS:
        raise PatternRejected(f"pattern longer than {MAX_PATTERN_CHARS} characters; split it into narrower searches")
    if _count_alternations(pattern) + 1 > MAX_ALTERNATIONS:
        raise PatternRejected(f"more than {MAX_ALTERNATIONS} alternatives; split it into separate searches")
    if pcre2:
        if _NESTED_QUANTIFIER_RE.search(pattern):
            raise PatternRejected("nested quantifier (e.g. (a+)+) is not allowed with look-around patterns")
        if _BACKREF_RE.search(pattern):
            raise PatternRejected("backreferences are not allowed; match the literal text instead")


def _count_alternations(pattern: str) -> int:
    count, escaped, in_class = 0, False, False
    for ch in pattern:
        if escaped:
            escaped = False
        elif ch == "\\":
            escaped = True
        elif ch == "[" and not in_class:
            in_class = True
        elif ch == "]" and in_class:
            in_class = False
        elif ch == "|" and not in_class:
            count += 1
    return count


def check_glob(glob: str) -> str:
    g = (glob or "").strip()
    body = g[1:] if g.startswith("!") else g
    if not body or len(g) > MAX_GLOB_CHARS:
        raise PatternRejected(f"invalid glob {glob!r}")
    if body.startswith("/") or body.startswith("\\") or re.match(r"^[A-Za-z]:", body):
        raise PatternRejected(f"glob must be relative to the repository: {glob!r}")
    if ".." in PurePosixPath(body.replace("\\", "/")).parts:
        raise PatternRejected(f"glob may not contain '..': {glob!r}")
    return g


class RgRunner:
    def __init__(
        self,
        root: Path | str,
        *,
        binary: Optional[str] = None,
        allowed_files: Optional[Collection[str]] = None,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        pcre2_timeout: float = PCRE2_TIMEOUT_SECONDS,
        max_output_bytes: int = DEFAULT_MAX_OUTPUT_BYTES,
        threads: int = DEFAULT_THREADS,
        memory_limit_mb: Optional[int] = None,
    ) -> None:
        self.root = Path(root).resolve()
        self.binary = binary if binary is not None else find_rg_binary()
        self.allowed_files = set(allowed_files) if allowed_files is not None else None
        # Directory names that appear in the inventory: an exhaustive search
        # may skip any skip-dir / dot-dir *not* among them, since nothing in
        # scope can live there (the engine's walk pruned them).
        self._inventory_dirs = {
            part.lower()
            for path in (self.allowed_files or ())
            for part in PurePosixPath(path).parts[:-1]
        }
        self.timeout = timeout
        self.pcre2_timeout = pcre2_timeout
        self.max_output_bytes = max_output_bytes
        self.threads = max(1, int(threads))
        self._pcre2: Optional[bool] = None
        self._lock = threading.Lock()
        limit = DEFAULT_MEMORY_LIMIT_MB if memory_limit_mb is None else memory_limit_mb
        self.memory_limit_kb = int(limit) * 1024 if limit and os.name == "posix" and os.path.exists(_SH) else 0
        self._limit_enforced: Optional[bool] = None

    # -- capability --------------------------------------------------------

    def _argv(self, cmd: List[str]) -> List[str]:
        """Prefix `cmd` with the memory-capping shell when a limit is set.
        Only the integer limit is part of the script; rg's own arguments are
        passed through "$@"."""
        if not self.memory_limit_kb:
            return cmd
        script = f'ulimit -v {self.memory_limit_kb} 2>/dev/null; exec "$0" "$@"'
        return [_SH, "-c", script, *cmd]

    def memory_limit_enforced(self) -> bool:
        """Whether this OS actually applies the cap (Linux yes, macOS no)."""
        with self._lock:
            if self._limit_enforced is None:
                self._limit_enforced = False
                if self.memory_limit_kb:
                    try:
                        proc = subprocess.run(
                            [_SH, "-c", f"ulimit -v {self.memory_limit_kb} 2>/dev/null && ulimit -v"],
                            stdin=subprocess.DEVNULL, capture_output=True, timeout=10,
                        )
                        self._limit_enforced = proc.stdout.decode().strip() == str(self.memory_limit_kb)
                    except (OSError, subprocess.SubprocessError):
                        self._limit_enforced = False
            return self._limit_enforced

    def available(self) -> bool:
        return bool(self.binary)

    def pcre2_available(self) -> bool:
        with self._lock:
            if self._pcre2 is None:
                self._pcre2 = False
                if self.binary:
                    try:
                        proc = subprocess.run(
                            self._argv([self.binary, "--pcre2-version"]), stdin=subprocess.DEVNULL,
                            capture_output=True, timeout=10,
                        )
                        self._pcre2 = proc.returncode == 0
                    except (OSError, subprocess.SubprocessError):
                        self._pcre2 = False
            return self._pcre2

    # -- validation --------------------------------------------------------

    def _compile_error(self, pattern: str, *, pcre2: bool, fixed: bool = False) -> Optional[str]:
        """rg's own compile error for `pattern`, or None if it compiles.
        Searching empty stdin exits 1 (no match) when valid, 2 when not."""
        cmd = [self.binary, "--no-config", "--quiet", *self._regex_limits()]
        if pcre2:
            cmd.append("--pcre2")
        if fixed:
            cmd.append("--fixed-strings")
        cmd += [f"--regexp={pattern}", "-"]
        try:
            proc = subprocess.run(
                self._argv(cmd), stdin=subprocess.DEVNULL, capture_output=True, timeout=10,
            )
        except subprocess.TimeoutExpired:
            return "pattern took too long to compile"
        except OSError as exc:
            return f"rg could not run: {exc}"
        if proc.returncode == 2:
            return _clean_rg_error(proc.stderr.decode("utf-8", errors="replace"))
        return None

    def validate_pattern(
        self, pattern: str, *, fixed: bool = False, trusted: bool = False,
    ) -> Tuple[bool, str, Optional[str], Optional[str]]:
        """(ok, engine, error, hint). Picks PCRE2 only when the default
        engine rejects the pattern for a feature PCRE2 provides. `trusted`
        (engine-authored seed patterns, never model output) skips only the
        size/alternation policy; rg still compiles it with the same limits."""
        if not self.binary:
            return False, ENGINE_DEFAULT, "ripgrep is not installed", None
        try:
            if not trusted:
                check_pattern_policy(pattern, pcre2=False)
            elif not pattern:
                raise PatternRejected("empty pattern")
        except PatternRejected as exc:
            return False, ENGINE_DEFAULT, str(exc), None
        error = self._compile_error(pattern, pcre2=False, fixed=fixed)
        if error is None:
            return True, ENGINE_DEFAULT, None, None
        if fixed or not _NEEDS_PCRE2_RE.search(error):
            return False, ENGINE_DEFAULT, error, _hint_for_error(error)
        if not self.pcre2_available():
            return False, ENGINE_DEFAULT, error, (
                "look-around and backreferences are unavailable here: rewrite without them "
                "(e.g. match the surrounding text, or search twice and compare)"
            )
        try:
            check_pattern_policy(pattern, pcre2=True)
        except PatternRejected as exc:
            return False, ENGINE_PCRE2, str(exc), None
        pcre_error = self._compile_error(pattern, pcre2=True)
        if pcre_error is not None:
            return False, ENGINE_PCRE2, pcre_error, _hint_for_error(pcre_error)
        return True, ENGINE_PCRE2, None, None

    # -- search ------------------------------------------------------------

    def _regex_limits(self) -> List[str]:
        return [f"--dfa-size-limit={REGEX_SIZE_LIMIT}", f"--regex-size-limit={REGEX_SIZE_LIMIT}"]

    def search(
        self,
        pattern: str,
        *,
        globs: Sequence[str] = (),
        paths: Optional[Sequence[str]] = None,
        ignore_case: bool = False,
        multiline: bool = False,
        fixed_strings: bool = False,
        context: int = 0,
        max_count_per_file: int = DEFAULT_MAX_COUNT_PER_FILE,
        files_only: bool = False,
        trusted: bool = False,
        exhaustive: bool = False,
    ) -> RgResult:
        """`exhaustive` searches every file the engine's own directory walk
        could have listed — hidden files, symlinked files, files of any size,
        files with NUL bytes, and the engine's skip dirs (the inventory
        post-filter still sets the scope). The catalog prefilter needs it to
        guarantee rg's candidate set is a superset of what Python scans."""
        started = time.monotonic()
        ok, engine, error, hint = self.validate_pattern(pattern, fixed=fixed_strings, trusted=trusted)
        if not ok:
            return RgResult(ok=False, engine=engine, error=error, hint=hint)
        try:
            safe_globs = [check_glob(g) for g in globs]
            safe_paths = [self._safe_rel_path(p) for p in (paths or ())]
        except PatternRejected as exc:
            return RgResult(ok=False, engine=engine, error=str(exc))

        cmd: List[str] = [self.binary, "--json", "--no-config", "--no-ignore",
                          f"--threads={self.threads}", *self._regex_limits()]
        if exhaustive:
            cmd += ["--hidden", "--follow", "--text"]
            if self.allowed_files is not None:
                for d in SKIP_DIRS:
                    if d.lower() not in self._inventory_dirs:
                        cmd.append(f"--iglob=!**/{d}/**")
                if not any(part.startswith(".") for part in self._inventory_dirs):
                    cmd.append("--glob=!**/.*/**")
        else:
            cmd += ["--no-follow", "--max-filesize=2M", f"--max-columns={MAX_LINE_CHARS}"]
        if files_only:
            cmd = [c for c in cmd if c != "--json"] + ["--files-with-matches"]
        else:
            cmd.append(f"--max-count={max(1, int(max_count_per_file))}")
            if context > 0:
                cmd.append(f"--context={min(int(context), 5)}")
        if engine == ENGINE_PCRE2:
            cmd.append("--pcre2")
        if ignore_case:
            cmd.append("--ignore-case")
        if multiline:
            cmd.append("--multiline")
        if fixed_strings:
            cmd.append("--fixed-strings")
        if not exhaustive:
            for d in SKIP_DIRS:
                cmd.append(f"--iglob=!**/{d}/**")
        for g in safe_globs:
            cmd.append(f"--glob={g}")
        cmd.append(f"--regexp={pattern}")
        cmd.append("--")
        cmd.extend(safe_paths or ["."])

        timeout = self.pcre2_timeout if engine == ENGINE_PCRE2 else self.timeout
        lines, stderr, timed_out, truncated, returncode = self._run_streaming(cmd, timeout)
        result = RgResult(ok=True, engine=engine, timed_out=timed_out, output_truncated=truncated)
        if returncode == 2 and not lines and stderr:
            result.ok = False
            result.error = _clean_rg_error(stderr)
            result.hint = _hint_for_error(result.error)
        elif returncode not in (0, 1, 2) and not (timed_out or truncated):
            # Killed or crashed (e.g. over the memory cap): never let that pass
            # as "no matches" — partial output is truncated, none is an error.
            if lines:
                result.output_truncated = True
            else:
                result.ok = False
                result.error = f"rg terminated abnormally (exit {returncode}); possibly over the memory limit"
        if files_only:
            for raw in lines:
                rel = self._scoped_path(raw.decode("utf-8", errors="replace").strip(), confine=not exhaustive)
                if rel is None:
                    result.dropped_out_of_scope += 1
                else:
                    result.files.append(rel)
        else:
            self._parse_json_lines(lines, result)
        result.elapsed_ms = int((time.monotonic() - started) * 1000)
        return result

    def files_with_matches(self, pattern: str, **kwargs) -> RgResult:
        return self.search(pattern, files_only=True, **kwargs)

    # -- internals ---------------------------------------------------------

    def _run_streaming(self, cmd: List[str], timeout: float):
        try:
            proc = subprocess.Popen(
                self._argv(cmd), cwd=str(self.root), stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
        except OSError as exc:
            return [], f"rg could not run: {exc}", False, False, 2
        lines: List[bytes] = []
        state = {"bytes": 0, "truncated": False}
        err_chunks: List[bytes] = []

        def _read_stdout() -> None:
            assert proc.stdout is not None
            for raw in proc.stdout:
                state["bytes"] += len(raw)
                if state["bytes"] > self.max_output_bytes:
                    state["truncated"] = True
                    proc.kill()
                    break
                lines.append(raw)

        def _read_stderr() -> None:
            assert proc.stderr is not None
            total = 0
            for raw in proc.stderr:
                if total < 8192:
                    err_chunks.append(raw)
                total += len(raw)

        readers = [threading.Thread(target=_read_stdout, daemon=True),
                   threading.Thread(target=_read_stderr, daemon=True)]
        for t in readers:
            t.start()
        timed_out = False
        try:
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            proc.kill()
            proc.wait()
        for t in readers:
            t.join(timeout=5)
        stderr = b"".join(err_chunks).decode("utf-8", errors="replace")
        return lines, stderr, timed_out, state["truncated"], proc.returncode

    def _parse_json_lines(self, lines: Iterable[bytes], result: RgResult) -> None:
        for raw in lines:
            try:
                event = json.loads(raw)
            except (json.JSONDecodeError, UnicodeDecodeError):
                continue  # a line cut by the output cap
            kind = event.get("type")
            if kind not in ("match", "context"):
                continue
            data = event.get("data") or {}
            rel = self._scoped_path(_json_text(data.get("path")))
            if rel is None:
                if kind == "match":
                    result.dropped_out_of_scope += 1
                continue
            line_no = int(data.get("line_number") or 0)
            text = _json_text(data.get("lines")).rstrip("\r\n")[:MAX_LINE_CHARS]
            if kind == "context":
                result.context.setdefault(rel, {})[line_no] = text
                continue
            subs = tuple(
                _json_text(s.get("match"))[:MAX_LINE_CHARS]
                for s in (data.get("submatches") or [])
            )
            result.matches.append(RgMatch(file=rel, line=line_no, text=text, submatches=subs))

    def _safe_rel_path(self, rel: str) -> str:
        scoped = self._scoped_path(rel)
        if scoped is None:
            raise PatternRejected(f"path is outside the scan scope: {rel!r}")
        return scoped

    def _scoped_path(self, raw: str, *, confine: bool = True) -> Optional[str]:
        """Repo-relative POSIX path if `raw` is inside the root (and in the
        inventory, when one is set); otherwise None. `confine` also requires
        the file a symlink points at to be inside the root; without it the
        path as listed is kept (the inventory filter still applies), which
        is how the engine's own walk lists a symlinked file."""
        if not raw:
            return None
        candidate = Path(raw)
        absolute = candidate if candidate.is_absolute() else self.root / candidate
        try:
            rel = Path(os.path.normpath(absolute)).relative_to(self.root).as_posix()
            if confine:
                absolute.resolve().relative_to(self.root)
        except (OSError, ValueError):
            return None
        if rel in ("", "."):
            return None
        if self.allowed_files is not None and rel not in self.allowed_files:
            return None
        return rel


def _json_text(obj) -> str:
    if not isinstance(obj, dict):
        return ""
    if "text" in obj:
        return str(obj["text"])
    if "bytes" in obj:
        import base64

        try:
            return base64.b64decode(obj["bytes"]).decode("utf-8", errors="replace")
        except (ValueError, TypeError):
            return ""
    return ""


def _clean_rg_error(stderr: str) -> str:
    text = (stderr or "").strip()
    text = re.sub(r"^rg: ", "", text)
    return text[:600] or "rg reported an error"


def _hint_for_error(error: Optional[str]) -> Optional[str]:
    e = (error or "").lower()
    if "unclosed group" in e or "unopened group" in e:
        return "escape literal parentheses as \\( and \\)"
    if "unclosed character class" in e:
        return "escape a literal [ as \\["
    if "repetition operator missing expression" in e:
        return "escape a literal *, + or ? (e.g. \\*)"
    if "size limit" in e:
        return "the pattern is too large; narrow it or split it into several searches"
    if "look-around" in e or "backreference" in e:
        return "look-around and backreferences need PCRE2; rewrite without them"
    if "unrecognized escape" in e:
        return "that escape is not supported; use a character class instead"
    return None
