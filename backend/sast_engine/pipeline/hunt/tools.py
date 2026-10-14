"""HuntToolbox: the read-only tools an investigator may call.

Every tool:
* stays inside the repository and the scan's file inventory;
* returns compact, sampled text (a 30k-file repo never floods a prompt);
* redacts secret values before anything is shown to the model;
* wraps repository text in <untrusted_code> blocks — it is data, never
  instructions;
* records exactly what it showed in the EvidenceLedger, which is all a
  finding may later cite.
"""

from __future__ import annotations

import fnmatch
import re
import threading
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Set, Tuple

from pipeline.call_graph import _is_test_path
from pipeline.hunt import catalog
from pipeline.hunt.evidence import RESOLUTION_GRAPH, EvidenceLedger
from pipeline.hunt.redact import redact
from pipeline.hunt.repo_index import _SECURITY_CONFIG_RE, _module_of
from pipeline.hunt.retry_policy import (
    OUTCOME_INVALID,
    OUTCOME_NOISY,
    OUTCOME_OK,
    OUTCOME_TOO_MANY,
    OUTCOME_ZERO,
    SearchStats,
    classify_search,
    relaxed_variants,
)
from pipeline.hunt.rg_runner import RgMatch, RgResult, RgRunner
from pipeline.hunt.symbols import SymbolService
from pipeline.llm_file_scan import leading_license_header_span, looks_generated

POLICY_EXCLUDE = "exclude"
POLICY_DEPRIORITIZE = "deprioritize"
POLICY_INCLUDE = "include"

DEFAULT_MAX_RESULTS = 40
MAX_PER_FILE = 3
READ_MAX_LINES = 200
CONTEXT_LINES = 2
_RISK_RANK = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "CRITICAL": 3}
_COMMENT_RE = re.compile(r"^\s*(//|/\*|\*|#|<!--|--\s)")

TOOL_NAMES = (
    "search", "search_sinks", "search_sources", "read", "definition", "callers",
    "find_sanitizers", "find_authz", "list_files",
)


@dataclass
class ToolResult:
    tool: str
    ok: bool
    text: str  # what the model sees
    summary: str  # one line for the rolling transcript
    outcome: str = OUTCOME_OK
    data: Dict[str, Any] = field(default_factory=dict)


def _wrap(file: str, body: str, *, note: str = "") -> str:
    attrs = f'file="{file}"' + (f' note="{note}"' if note else "")
    return f"<untrusted_code {attrs}>\n{body}\n</untrusted_code>"


class HuntToolbox:
    def __init__(
        self,
        *,
        root: Path | str,
        runner: RgRunner,
        symbols: SymbolService,
        ledger: EvidenceLedger,
        risk_by_path: Optional[Dict[str, str]] = None,
        inventory: Optional[Sequence[str]] = None,
        test_policy: str = POLICY_DEPRIORITIZE,
        generated_policy: str = POLICY_EXCLUDE,
        max_results: int = DEFAULT_MAX_RESULTS,
        rg_gate: Optional[Callable[[], bool]] = None,
    ) -> None:
        self.root = Path(root).resolve()
        self.runner = runner
        self.symbols = symbols
        self.ledger = ledger
        self.risk_by_path = dict(risk_by_path or {})
        self.inventory: Set[str] = set(inventory or ())
        self.test_policy = test_policy
        self.generated_policy = generated_policy
        self.max_results = max_results
        self._rg_gate = rg_gate or (lambda: True)
        self._text_cache: Dict[str, Optional[List[str]]] = {}
        self._generated_cache: Dict[str, bool] = {}
        self._cache_lock = threading.Lock()

    # -- dispatch ----------------------------------------------------------

    def run(self, action: str, args: Optional[Dict[str, Any]] = None) -> ToolResult:
        args = dict(args or {})
        handler = getattr(self, f"tool_{action}", None) if action in TOOL_NAMES else None
        if handler is None:
            return ToolResult(action, False, f"error: unknown tool {action!r}", f"{action}: unknown tool",
                              outcome=OUTCOME_INVALID)
        try:
            return handler(**args)
        except TypeError as exc:
            return ToolResult(action, False, f"error: bad arguments for {action}: {exc}",
                              f"{action}: bad arguments", outcome=OUTCOME_INVALID)

    # -- file helpers ------------------------------------------------------

    def _lines(self, rel: str) -> Optional[List[str]]:
        with self._cache_lock:
            if rel in self._text_cache:
                return self._text_cache[rel]
        try:
            text = (self.root / rel).read_text(encoding="utf-8", errors="replace")
            lines: Optional[List[str]] = text.splitlines()
        except OSError:
            lines = None
        with self._cache_lock:
            if len(self._text_cache) > 2000:
                self._text_cache.clear()
            self._text_cache[rel] = lines
        return lines

    def _is_generated(self, rel: str) -> bool:
        with self._cache_lock:
            if rel in self._generated_cache:
                return self._generated_cache[rel]
        lines = self._lines(rel)
        flag = looks_generated("\n".join(lines[:120]) if lines else "")
        with self._cache_lock:
            self._generated_cache[rel] = flag
        return flag

    def _in_scope(self, rel: str) -> Optional[str]:
        scoped = self.runner._scoped_path(rel)
        if scoped is None:
            return None
        if self.inventory and scoped not in self.inventory:
            return None
        return scoped

    def _rank_key(self, rel: str) -> Tuple[int, int, str]:
        test = _is_test_path(rel) and self.test_policy == POLICY_DEPRIORITIZE
        return (int(test), _RISK_RANK.get(self.risk_by_path.get(rel, ""), 4), rel)

    # -- searches ----------------------------------------------------------

    def _search(
        self,
        tool: str,
        pattern: str,
        *,
        intent: str = "",
        glob: Optional[str] = None,
        paths: Optional[Sequence[str]] = None,
        ignore_case: bool = False,
        multiline: bool = False,
        trusted: bool = False,
        annotate: Optional[Callable[[RgMatch], str]] = None,
        line_filter: Optional[Callable[[RgMatch], bool]] = None,
        relax: bool = True,
    ) -> ToolResult:
        if not self._rg_gate():
            return ToolResult(tool, False, "error: search budget exhausted", f"{tool}: budget exhausted",
                              outcome=OUTCOME_INVALID, data={"budget": True})
        result = self.runner.search(
            pattern, globs=[glob] if glob else (), paths=paths, ignore_case=ignore_case,
            multiline=multiline, context=CONTEXT_LINES, trusted=trusted,
        )
        label = f"{tool} /{pattern[:80]}/" + (f" in {glob}" if glob else "")
        if not result.ok:
            text = f"INVALID pattern: {result.error}" + (f"\nhint: {result.hint}" if result.hint else "")
            return ToolResult(tool, False, text, f"{label} -> INVALID", outcome=OUTCOME_INVALID,
                              data={"error": result.error, "hint": result.hint, "pattern": pattern})

        kept, stats = self._filter(result.matches, line_filter)
        outcome = classify_search(stats)
        data: Dict[str, Any] = {
            "pattern": pattern, "intent": intent, "raw_matches": stats.raw_matches,
            "kept_matches": stats.kept_matches, "files": len({m.file for m in kept}),
            "filtered": {"comment": stats.comment, "test": stats.test, "generated": stats.generated},
        }
        if result.output_truncated or result.timed_out:
            data["truncated"] = True

        if outcome == OUTCOME_ZERO and relax and not trusted:
            for variant in relaxed_variants(pattern):
                if not self._rg_gate():
                    break
                retry = self.runner.search(variant, globs=[glob] if glob else (), paths=paths,
                                           ignore_case=True, context=CONTEXT_LINES)
                if retry.ok and retry.matches:
                    relaxed_kept, relaxed_stats = self._filter(retry.matches, line_filter)
                    if relaxed_kept:
                        shown: List[Tuple[str, int]] = []
                        body = self._render_matches(relaxed_kept, retry, annotate, shown_out=shown)
                        data.update({"relaxed_pattern": variant, "relaxed_matches": relaxed_stats.kept_matches,
                                     "shown": shown})
                        text = (
                            f"ZERO matches for /{pattern}/.\nThe engine retried a relaxed variant "
                            f"/{variant}/ (case-insensitive): {relaxed_stats.kept_matches} match(es) in "
                            f"{len({m.file for m in relaxed_kept})} file(s). Check these are relevant before using them:\n{body}"
                        )
                        return ToolResult(tool, True, text, f"{label} -> ZERO; relaxed /{variant}/ -> {relaxed_stats.kept_matches}",
                                          outcome=OUTCOME_ZERO, data=data)
            text = (
                f"ZERO matches for /{pattern}/" + (f" in {glob}" if glob else "") + ", and relaxed variants "
                "found nothing either. Consider: different API names for this framework, a wider glob, "
                "or that this construct is simply absent."
            )
            return ToolResult(tool, True, text, f"{label} -> ZERO", outcome=OUTCOME_ZERO, data=data)
        if outcome == OUTCOME_ZERO:
            return ToolResult(tool, True, f"ZERO matches for {tool}.", f"{label} -> ZERO", outcome=OUTCOME_ZERO, data=data)

        if outcome == OUTCOME_TOO_MANY:
            histogram = Counter(_module_of(m.file) for m in kept)
            dirs = Counter(str(Path(m.file).parent) for m in kept)
            text = (
                f"TOO_MANY: {stats.kept_matches} matches in {data['files']} files — too broad to review.\n"
                "Narrow it: add a glob (e.g. a module or package directory), require a co-occurring token "
                "on the same line, or exclude tests with glob '!**/test/**'.\n"
                "Matches per module: " + ", ".join(f"{k} {v}" for k, v in histogram.most_common(10)) + "\n"
                "Busiest directories: " + ", ".join(f"{k} {v}" for k, v in dirs.most_common(8))
            )
            return ToolResult(tool, True, text, f"{label} -> TOO_MANY ({stats.kept_matches})",
                              outcome=OUTCOME_TOO_MANY, data=data)

        header = (
            f"{stats.kept_matches} match(es) in {data['files']} file(s)"
            + (f"; showing a sample" if stats.kept_matches > self.max_results else "")
        )
        if outcome == OUTCOME_NOISY:
            header = (
                f"NOISY: {stats.raw_matches - stats.kept_matches} of {stats.raw_matches} matches were in "
                f"comments/tests/generated code and were filtered out. " + header
            )
        shown = []
        body = self._render_matches(kept, result, annotate, shown_out=shown)
        data["shown"] = shown
        if data.get("truncated"):
            header += " (search output was truncated by the size/time limit)"
        return ToolResult(tool, True, f"{header}\n{body}" if body else header,
                          f"{label} -> {outcome} ({stats.kept_matches} in {data['files']} files)",
                          outcome=outcome, data=data)

    def _filter(
        self, matches: Sequence[RgMatch], line_filter: Optional[Callable[[RgMatch], bool]],
    ) -> Tuple[List[RgMatch], SearchStats]:
        kept: List[RgMatch] = []
        stats = SearchStats(raw_matches=len(matches), kept_matches=0)
        for m in matches:
            if line_filter is not None and not line_filter(m):
                stats.raw_matches -= 1
                continue
            if _COMMENT_RE.match(m.text):
                stats.comment += 1
                continue
            if _is_test_path(m.file):
                if self.test_policy == POLICY_EXCLUDE:
                    stats.test += 1
                    continue
            if self.generated_policy == POLICY_EXCLUDE and self._is_generated(m.file):
                stats.generated += 1
                continue
            kept.append(m)
        stats.kept_matches = len(kept)
        return kept, stats

    def _render_matches(
        self, matches: Sequence[RgMatch], result: RgResult, annotate: Optional[Callable[[RgMatch], str]],
        *, shown_out: Optional[List[Tuple[str, int]]] = None,
    ) -> str:
        """`shown_out` receives the (file, line) of every match shown — what
        learned-rule promotion needs to know which search surfaced a sink."""
        by_file: Dict[str, List[RgMatch]] = defaultdict(list)
        for m in matches:
            by_file[m.file].append(m)
        ordered_files = sorted(by_file, key=self._rank_key)
        # Round-robin across files so one noisy file can't take the sample.
        picked: Dict[str, List[RgMatch]] = defaultdict(list)
        budget = self.max_results
        for round_idx in range(MAX_PER_FILE):
            for f in ordered_files:
                if budget <= 0:
                    break
                if round_idx < len(by_file[f]):
                    picked[f].append(by_file[f][round_idx])
                    budget -= 1
        blocks: List[str] = []
        for f in ordered_files:
            if not picked.get(f):
                continue
            ctx = result.context.get(f, {})
            match_lines = {m.line: m for m in by_file[f]}
            shown: Dict[int, str] = {}
            for m in picked[f]:
                if shown_out is not None:
                    shown_out.append((f, m.line))
                for ln in range(m.line - CONTEXT_LINES, m.line + CONTEXT_LINES + 1):
                    if ln in match_lines:
                        shown[ln] = match_lines[ln].text
                    elif ln in ctx:
                        shown[ln] = ctx[ln]
            rows = []
            previous = None
            for ln in sorted(shown):
                if previous is not None and ln > previous + 1:
                    rows.append("  ...")
                marker = ">" if ln in match_lines else " "
                note = ""
                if marker == ">" and annotate is not None:
                    note = annotate(match_lines[ln])
                rows.append(f"{marker}{ln:>6}: {redact(shown[ln])}{('   ' + note) if note else ''}")
                self.ledger.record_line("search", f, ln, shown[ln])
                previous = ln
            extra = len(by_file[f]) - len(picked[f])
            if extra > 0:
                rows.append(f"  (+{extra} more match(es) in this file)")
            risk = self.risk_by_path.get(f)
            notes = [n for n in (risk, "test" if _is_test_path(f) else "") if n]
            blocks.append(_wrap(f, "\n".join(rows), note=",".join(notes)))
        omitted = len(by_file) - len(picked)
        if omitted > 0:
            blocks.append(f"(+{omitted} more file(s) with matches not shown)")
        return "\n".join(blocks)

    # -- tools: searches ---------------------------------------------------

    def tool_search(self, pattern: str = "", glob: Optional[str] = None, intent: str = "",
                    ignore_case: bool = False, multiline: bool = False) -> ToolResult:
        return self._search("search", str(pattern), intent=intent, glob=glob,
                            ignore_case=bool(ignore_case), multiline=bool(multiline))

    def tool_search_sinks(self, kind: str = "", glob: Optional[str] = None, intent: str = "") -> ToolResult:
        patterns = catalog.sink_patterns().get(str(kind))
        if not patterns:
            return ToolResult("search_sinks", False,
                              f"error: unknown sink kind {kind!r}; known: {', '.join(catalog.known_sink_kinds())}",
                              "search_sinks: unknown kind", outcome=OUTCOME_INVALID)
        combined = "|".join(f"(?:{p})" for p in patterns)

        def _annotate(m: RgMatch) -> str:
            resolved = self.symbols.graph_sink_kind(m.file, m.line)
            return f"[graph-resolved {resolved} sink]" if resolved else ""

        result = self._search("search_sinks", combined, intent=intent or f"{kind} sinks", glob=glob,
                              trusted=True, annotate=_annotate)
        result.summary = f"search_sinks {kind}" + (f" in {glob}" if glob else "") + " -> " + result.summary.split("-> ", 1)[-1]
        result.data["sink_kind"] = kind
        return result

    def tool_search_sources(self, glob: Optional[str] = None, intent: str = "") -> ToolResult:
        combined = "|".join(f"(?:{p})" for p in catalog.source_patterns())
        result = self._search("search_sources", combined, intent=intent or "untrusted input sources",
                              glob=glob, trusted=True)
        result.summary = "search_sources" + (f" in {glob}" if glob else "") + " -> " + result.summary.split("-> ", 1)[-1]
        return result

    def tool_find_sanitizers(self, kind: str = "", file: str = "", start: int = 0, end: int = 0) -> ToolResult:
        patterns = catalog.sanitizer_patterns().get(str(kind))
        if not patterns:
            return ToolResult("find_sanitizers", False, f"error: no sanitizer list for kind {kind!r}",
                              "find_sanitizers: unknown kind", outcome=OUTCOME_INVALID)
        paths = None
        line_filter = None
        if file:
            scoped = self._in_scope(file)
            if scoped is None:
                return ToolResult("find_sanitizers", False, f"error: {file!r} is not in the scan scope",
                                  "find_sanitizers: out of scope", outcome=OUTCOME_INVALID)
            paths = [scoped]
            if start and end:
                lo, hi = int(start), int(end)
                line_filter = lambda m: lo <= m.line <= hi  # noqa: E731
        combined = "|".join(f"(?:{p})" for p in patterns)
        result = self._search("find_sanitizers", combined, intent=f"{kind} sanitizers", paths=paths,
                              trusted=True, line_filter=line_filter)
        if result.outcome == OUTCOME_ZERO:
            where = f"{file}:{start}-{end}" if file and start else (file or "the repository")
            result.text = f"No known {kind} sanitizer/encoder calls in {where}."
        result.summary = f"find_sanitizers {kind} {file or ''} -> {result.outcome}"
        result.data["sanitizer_kind"] = kind
        result.data["checked_file"] = file
        return result

    # -- tools: reading and symbols ------------------------------------------

    def tool_read(self, file: str = "", start: int = 1, end: int = 0) -> ToolResult:
        scoped = self._in_scope(str(file))
        if scoped is None:
            return ToolResult("read", False, f"error: {file!r} is not a file in the scan scope",
                              f"read {file}: out of scope", outcome=OUTCOME_INVALID)
        lines = self._lines(scoped)
        if lines is None:
            return ToolResult("read", False, f"error: could not read {scoped}", f"read {scoped}: unreadable",
                              outcome=OUTCOME_INVALID)
        total = len(lines)
        lo = max(1, int(start or 1))
        hi = int(end or 0) or lo + READ_MAX_LINES - 1
        hi = min(total, hi, lo + READ_MAX_LINES - 1)
        if lo > total:
            return ToolResult("read", False, f"error: {scoped} has only {total} lines",
                              f"read {scoped}: past end", outcome=OUTCOME_INVALID)
        header_span = leading_license_header_span(lines)
        rows: List[str] = []
        shown_header = False
        for ln in range(lo, hi + 1):
            if header_span and header_span[0] <= ln <= header_span[1]:
                if not shown_header:
                    rows.append(f"       [license header, lines {header_span[0]}-{header_span[1]}, omitted]")
                    shown_header = True
                continue
            rows.append(f"{ln:>6}: {redact(lines[ln - 1])}")
        self.ledger.record_span("read", scoped, lo, hi, "\n".join(lines[lo - 1:hi]))
        notes = []
        method = self.symbols.enclosing_method(scoped, lo)
        if method is not None:
            notes.append(
                f"enclosing method: {method.fqcn.rsplit('.', 1)[-1]}.{method.name} "
                f"(lines {method.start_line}-{method.end_line}"
                + (", annotations: " + ", ".join("@" + a for a in method.annotations[:4]) if method.annotations else "")
                + ")"
            )
        if self._is_generated(scoped):
            notes.append("file is marked as generated code")
        if _is_test_path(scoped):
            notes.append("test code")
        more = f" ({total} lines total)" if hi < total else ""
        text = _wrap(scoped, "\n".join(rows), note=f"lines {lo}-{hi}{more}")
        if notes:
            text += "\n" + "; ".join(notes)
        return ToolResult("read", True, text, f"read {scoped}:{lo}-{hi}", data={"file": scoped, "start": lo, "end": hi})

    def tool_definition(self, symbol: str = "") -> ToolResult:
        hits = self.symbols.definitions(str(symbol))
        if not hits:
            return ToolResult("definition", True, f"No definition found for {symbol!r}.", f"definition {symbol} -> none",
                              outcome=OUTCOME_ZERO)
        rows = []
        for h in hits:
            scoped = self._in_scope(h.file)
            if scoped is None:
                continue
            self.ledger.record_line("definition", scoped, h.line, h.signature)
            rows.append(f"- {scoped}:{h.line}-{h.end_line} {redact(h.signature)} [{h.resolution}]")
        text = f"Definitions of {symbol}:\n" + "\n".join(rows)
        return ToolResult("definition", True, text, f"definition {symbol} -> {len(rows)}",
                          data={"resolutions": sorted({h.resolution for h in hits})})

    def tool_callers(self, method: str = "", class_name: Optional[str] = None) -> ToolResult:
        hits = self.symbols.callers(str(method), class_name)
        if not hits:
            return ToolResult("callers", True, f"No callers found for {method!r}.", f"callers {method} -> none",
                              outcome=OUTCOME_ZERO)
        rows = []
        for h in hits:
            scoped = self._in_scope(h.file)
            if scoped is None:
                continue
            lines = self._lines(scoped) or []
            code = lines[h.line - 1].strip() if 0 < h.line <= len(lines) else ""
            self.ledger.record_line("callers", scoped, h.line, code)
            self.ledger.record_edge(
                caller_file=scoped, call_line=h.line, callee_name=str(h.callee).rsplit(".", 1)[-1],
                callee_file=h.callee_file, resolution=h.resolution,
            )
            who = f" in {h.caller}" if h.caller else ""
            rows.append(f"- {scoped}:{h.line}{who}: {redact(code)[:160]} [{h.resolution}]")
        textual = all(h.resolution != RESOLUTION_GRAPH for h in hits)
        note = (
            "\nThese are text matches (no resolved call graph edge): the receiver type is unverified, "
            "so read each call site before relying on it." if textual else ""
        )
        text = f"Callers of {class_name + '.' if class_name else ''}{method}:\n" + "\n".join(rows) + note
        return ToolResult("callers", True, text, f"callers {method} -> {len(rows)} [{'textual' if textual else 'graph'}]",
                          data={"resolution": "textual" if textual else "graph"})

    def tool_find_authz(self, file: str = "", line: int = 0) -> ToolResult:
        scoped = self._in_scope(str(file))
        if scoped is None:
            return ToolResult("find_authz", False, f"error: {file!r} is not in the scan scope",
                              "find_authz: out of scope", outcome=OUTCOME_INVALID)
        lines = self._lines(scoped) or []
        parts: List[str] = []
        method = self.symbols.enclosing_method(scoped, int(line or 1))
        endpoint_paths: List[str] = []
        if method is not None:
            anns = ", ".join("@" + a for a in method.annotations) or "none"
            parts.append(f"Method {method.fqcn.rsplit('.', 1)[-1]}.{method.name} annotations: {anns}")
            for text in (method.body or "").splitlines()[:6]:
                endpoint_paths += re.findall(r"Mapping\s*\(\s*(?:value\s*=\s*|path\s*=\s*)?\"([^\"]+)\"", text)
            self.ledger.record_span("find_authz", scoped, method.start_line, min(method.start_line + 5, method.end_line))
        class_auth = [
            (i, t.strip()) for i, t in enumerate(lines, start=1)
            if re.search(r"@(PreAuthorize|Secured|RolesAllowed|PermitAll|DenyAll)\b|@RequestMapping", t)
            and (method is None or i < method.start_line or i > method.end_line)
        ][:8]
        if class_auth:
            parts.append("Other authorization/mapping annotations in this file:")
            for i, t in class_auth:
                parts.append(f"  {i}: {redact(t)[:160]}")
                self.ledger.record_line("find_authz", scoped, i, t)
                endpoint_paths += re.findall(r"RequestMapping\s*\(\s*(?:value\s*=\s*|path\s*=\s*)?\"([^\"]+)\"", t)
        config_files = [p for p in self.inventory if _SECURITY_CONFIG_RE.search(p) and not _is_test_path(p)]
        if config_files and self._rg_gate():
            combined = "|".join(f"(?:{p})" for p in catalog.sink_patterns().get("authz", []) + catalog.sink_patterns().get("csrf", []))
            result = self.runner.search(combined, paths=sorted(config_files)[:50], trusted=True, max_count_per_file=15)
            segments = [seg.strip("/").split("/")[0] for seg in endpoint_paths if seg.strip("/")]
            # Path-specific matchers are filtered to this endpoint; rules with no
            # path literal (csrf(), anyRequest(), method-level annotations)
            # apply everywhere and are always shown.
            relevant = [
                m for m in result.matches
                if '"/' not in m.text or not segments or any(seg in m.text for seg in segments)
            ] or result.matches
            if relevant:
                parts.append("Security configuration rules:")
                for m in relevant[:15]:
                    parts.append(f"  {m.file}:{m.line}: {redact(m.text.strip())[:180]}")
                    self.ledger.record_line("find_authz", m.file, m.line, m.text)
        else:
            parts.append("No security configuration files found in the inventory.")
        if endpoint_paths:
            parts.insert(0, f"Endpoint path(s): {', '.join(dict.fromkeys(endpoint_paths))}")
        text = _wrap(scoped, "\n".join(parts), note="authorization context")
        return ToolResult("find_authz", True, text, f"find_authz {scoped}:{line}",
                          data={"file": scoped, "line": int(line or 0)})

    def tool_list_files(self, glob: str = "", limit: int = 100) -> ToolResult:
        pattern = str(glob or "").strip()
        if not pattern or ".." in pattern or pattern.startswith("/"):
            return ToolResult("list_files", False, "error: give a relative glob like '**/*Controller.java'",
                              "list_files: bad glob", outcome=OUTCOME_INVALID)
        hits = sorted((p for p in self.inventory if fnmatch.fnmatch(p, pattern)), key=self._rank_key)
        shown = hits[: max(1, min(int(limit or 100), 200))]
        text = f"{len(hits)} file(s) match {pattern}:\n" + "\n".join(
            f"- {p}" + (f" [{self.risk_by_path[p]}]" if p in self.risk_by_path else "") for p in shown
        )
        if len(hits) > len(shown):
            text += f"\n(+{len(hits) - len(shown)} more)"
        return ToolResult("list_files", True, text, f"list_files {pattern} -> {len(hits)}",
                          outcome=OUTCOME_OK if hits else OUTCOME_ZERO)
