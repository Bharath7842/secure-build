"""What text a logged exception can carry (SAST-03-040).

"It is a Throwable overload" and "it uses `{}` placeholders" are not defences:
`log.error(msg, ex)` still writes the exception's message and its causes'
messages, and parameterised logging substitutes them unchanged. Whether that
text can be attacker-influenced depends on *which exceptions can arrive at the
catch* and *how their messages are built*:

* a project exception class: every place the repository constructs it (and its
  project subclasses) — if each passes only literals, constants or numbers its
  text is fixed; if one passes request data, or the message of a caught
  exception that can carry external text, it can carry it too. A rethrow
  (``throw new DBException(e.getMessage())``) carries the source exception's
  domain into the new one;
* a JDK or library exception: a small, explicit table. The VM writes its own
  messages for a few (``InterruptedException``, ``StackOverflowError``, ...);
  everything else — ``SQLException``, ``SAXException``, ``SOAPFaultException``,
  ``JMSException``, ``IOException``, a generic ``Exception``,
  ``NumberFormatException`` (which echoes its input) — may embed external or
  remote text, and so does anything not listed.

The answer for a catch is the worst of its candidates: ``external`` over
``unknown`` over ``constrained``. Nothing here reads the logger overload or the
message format. Whole-repository construction sites make the class summary a
sound over-approximation: it does not try to say which site a given try body
can reach.

Summaries are per scan, memoised, depth-bounded (a cycle is neutral for the
class it closes on, ``unknown`` for a variable), and counted under
``usage_summary.exception_summaries``.
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from llm_client import bump_counter

from . import occurrence_facts as of
from .validators._logging import SOURCE_RE
from .validators.log_value_domain import classify_arguments

CONSTRAINED = "constrained"
UNKNOWN = "unknown"
EXTERNAL = "external"
_RANK = {CONSTRAINED: 0, UNKNOWN: 1, EXTERNAL: 2}

MAX_DEPTH = 6

# JDK exceptions whose message the VM (or the specification) writes itself, so no
# caller-supplied text reaches it. Source for every entry: the JDK/JLS behaviour
# named in the comment. Anything not listed here may embed external text.
JDK_NO_EXTERNAL_TEXT: Dict[str, str] = {
    "InterruptedException": "thrown by Thread.sleep/wait/join with no message (JLS 17.8)",
    "StackOverflowError": "VM-generated, no message (JVMS 6.3)",
    "OutOfMemoryError": "VM-generated: 'Java heap space' and the like (JVMS 6.3)",
    "ArithmeticException": "VM-generated: '/ by zero' (JLS 15.17.2)",
    "ArrayIndexOutOfBoundsException": "VM-generated: the index and the length, numbers only",
    "StringIndexOutOfBoundsException": "JDK-generated: index and length, numbers only",
    "NegativeArraySizeException": "VM-generated: the (numeric) size",
    "ClassCastException": "VM-generated: class names, not data",
}
# A null dereference is VM-generated unless the try body constructs the exception itself.
NPE = "NullPointerException"
BROAD_CATCH = frozenset({"Throwable", "Exception", "RuntimeException", "Error"})
_NEW_RE = re.compile(r"\bnew\s+([A-Z][\w]*)\s*\(")
_CATCH_VAR_USE_RE = re.compile(
    r"\b(\w+)\s*\.\s*(?:getMessage|getLocalizedMessage|toString|getCause|get[A-Z]\w*)\s*\(\s*\)"
)


@dataclass
class Provenance:
    level: str
    types: List[str]
    detail: str = ""

    def merged(self, other: "Provenance") -> "Provenance":
        top = self if _RANK[self.level] >= _RANK[other.level] else other
        return Provenance(top.level, list(dict.fromkeys(self.types + other.types)),
                          top.detail or other.detail)


def _worst(items: List[Provenance]) -> Provenance:
    out = Provenance(CONSTRAINED, [], "")
    for item in items:
        out = out.merged(item)
    return out


@dataclass(frozen=True)
class _Site:
    path: str
    line: int
    cls: str


class ExceptionSummaries:
    """Per-scan, demand-driven summariser over the Java call graph."""

    def __init__(self, graph: Any, read_text: Callable[[str], Optional[str]], *,
                 usage: Optional[Dict[str, Any]] = None, max_depth: int = MAX_DEPTH) -> None:
        self.graph = graph
        self.read_text = read_text
        self.usage = usage
        self.max_depth = max_depth
        self._classes: Dict[str, Provenance] = {}
        self._vars: Dict[Tuple[str, int, int, str], Provenance] = {}
        self._class_stack: Set[str] = set()
        self._var_stack: Set[Tuple[str, int, int, str]] = set()
        self._sites: Optional[Dict[str, List[_Site]]] = None
        self.stats: Dict[str, int] = {}

    # -- counters --------------------------------------------------------------
    def _count(self, key: str, n: int = 1) -> None:
        self.stats[key] = self.stats.get(key, 0) + n
        bump_counter(self.usage, "exception_summaries", key, n)

    # -- project types ---------------------------------------------------------
    def _project_type(self, simple: str) -> bool:
        return self.graph is not None and bool(self.graph.types_by_simple.get(simple))

    def _subclasses(self, simple: str) -> List[str]:
        """The class and its project subclasses (by simple name), transitively."""
        found = [simple]
        seen = {simple}
        changed = True
        while changed and self.graph is not None:
            changed = False
            for jtype in self.graph.types.values():
                if jtype.simple_name in seen:
                    continue
                if any(s.rsplit(".", 1)[-1] in seen for s in jtype.super_types):
                    seen.add(jtype.simple_name)
                    found.append(jtype.simple_name)
                    changed = True
        return found

    def _exception_like(self, simple: str) -> bool:
        if re.search(r"(Exception|Error|Throwable)$", simple):
            return True
        for fqcn in (self.graph.types_by_simple.get(simple) or []) if self.graph else []:
            jtype = self.graph.types.get(fqcn)
            if jtype and any(re.search(r"(Exception|Error|Throwable)$", s.rsplit(".", 1)[-1]) for s in jtype.super_types):
                return True
        return False

    def _construction_sites(self) -> Dict[str, List[_Site]]:
        """Every `new X(` of a project exception class, found once per scan in the
        method bodies the graph already holds."""
        if self._sites is not None:
            return self._sites
        sites: Dict[str, List[_Site]] = {}
        if self.graph is not None:
            for method in self.graph.methods.values():
                body = method.body or ""
                if "new " not in body:
                    continue
                for m in _NEW_RE.finditer(body):
                    name = m.group(1)
                    if not self._project_type(name) or not self._exception_like(name):
                        continue
                    line = method.start_line + body.count("\n", 0, m.start())
                    sites.setdefault(name, []).append(_Site(method.file, line, name))
        self._sites = sites
        return sites

    # -- the arguments of one construction ---------------------------------------
    def _site_domain(self, site: _Site, depth: int) -> Provenance:
        text = self.read_text(site.path)
        facts = of.facts_for(site.path, text, site.line, sink_hint=f"new {site.cls}") if text else None
        call = (facts or {}).get("call") if facts else None
        if not call or not call.get("is_constructor"):
            return Provenance(UNKNOWN, [site.cls], f"{site.cls} constructed at {site.path}:{site.line} (not resolved)")
        results: List[Provenance] = []
        for arg in facts.get("args") or []:
            results.append(self._arg_domain(arg, site.path, text, call, facts, depth))
        return _worst(results) if results else Provenance(CONSTRAINED, [site.cls])

    def _arg_domain(self, arg: Dict[str, Any], path: str, text: str, call: Dict[str, Any],
                    facts: Dict[str, Any], depth: int) -> Provenance:
        arg_text = str(arg.get("text") or "")
        parts: List[Provenance] = []
        referenced = {m.group(1) for m in _CATCH_VAR_USE_RE.finditer(arg_text)}
        if str(arg.get("kind")) == "throwable" and re.fullmatch(r"\w+", arg_text.strip()):
            referenced.add(arg_text.strip())
        for var in sorted(referenced):
            parts.append(self.summarise_at(path, text, int(call.get("start_line") or 0),
                                           int(call.get("start_col") or 0), var, depth + 1))
        if SOURCE_RE.search(arg_text) and not referenced:
            parts.append(Provenance(EXTERNAL, [], f"request text in {arg_text[:40]}"))
        if not parts:
            _, ok, locale = classify_arguments([arg], self.graph)
            if ok and not locale:
                return Provenance(CONSTRAINED, [])
            enclosing = facts.get("enclosing") or {}
            return Provenance(UNKNOWN, [], f"{arg_text[:40]} comes from a parameter or call of "
                                           f"{enclosing.get('method') or 'its method'} that is not summarised")
        return _worst(parts)

    # -- classes ---------------------------------------------------------------
    def class_domain(self, simple: str, depth: int = 0) -> Provenance:
        """The message domain of an exception class by name."""
        if simple in self._classes:
            self._count("cache_hits")
            return self._classes[simple]
        if not self._project_type(simple):
            return self._jdk_domain(simple)
        if simple in self._class_stack:
            return Provenance(CONSTRAINED, [simple])  # a cycle adds nothing new
        if depth > self.max_depth:
            self._count("depth_exceeded")
            return Provenance(UNKNOWN, [simple], f"{simple}: summary depth exceeded")
        self._class_stack.add(simple)
        started = time.monotonic()
        try:
            sites = [s for cls in self._subclasses(simple) for s in self._construction_sites().get(cls, [])]
            if not sites:
                result = Provenance(UNKNOWN, [simple], f"{simple} is never constructed in the repository "
                                                       f"(reflection, a library or generated code)")
            else:
                result = _worst([self._site_domain(s, depth) for s in sites])
                result.types = list(dict.fromkeys([simple] + result.types))
                if result.level == CONSTRAINED:
                    result.detail = f"{simple} is always built from literals, constants or numbers"
        finally:
            self._class_stack.discard(simple)
        self._count("classes")
        self._count("milliseconds", int((time.monotonic() - started) * 1000))
        self._classes[simple] = result
        return result

    @staticmethod
    def _jdk_domain(simple: str) -> Provenance:
        if simple in JDK_NO_EXTERNAL_TEXT:
            return Provenance(CONSTRAINED, [simple], f"{simple}: {JDK_NO_EXTERNAL_TEXT[simple]}")
        return Provenance(EXTERNAL, [simple], f"{simple} may embed external or remote text")

    # -- a variable at a position ------------------------------------------------
    def summarise_at(self, path: str, text: str, line: int, col: int, var: str, depth: int = 0) -> Provenance:
        """The domain of the exception held by ``var`` where the code at
        (line, col) can see it: the enclosing catch clause's candidates."""
        key = (path, line, col, var)
        if key in self._vars:
            self._count("cache_hits")
            return self._vars[key]
        if key in self._var_stack:
            return Provenance(UNKNOWN, [], f"{var}: cyclic rethrow")
        if depth > self.max_depth:
            self._count("depth_exceeded")
            return Provenance(UNKNOWN, [], f"{var}: summary depth exceeded")
        self._var_stack.add(key)
        try:
            result = self._summarise_catch(path, text, line, col, var, depth)
        finally:
            self._var_stack.discard(key)
        self._count("variables")
        self._vars[key] = result
        return result

    def _summarise_catch(self, path: str, text: str, line: int, col: int, var: str, depth: int) -> Provenance:
        parsed = of._parse("java", text) if text else None
        if parsed is None:
            return Provenance(UNKNOWN, [], f"{path} could not be parsed")
        root, src, _ = parsed
        node = root.descendant_for_point_range((line - 1, col), (line - 1, col))
        clause = node
        while clause is not None and clause.type not in ("catch_clause", "method_declaration",
                                                          "constructor_declaration", "lambda_expression"):
            clause = clause.parent
        if clause is None or clause.type != "catch_clause":
            return Provenance(UNKNOWN, [], f"{var} is not a catch variable here (a parameter or local); "
                                           f"its callers are not summarised")
        param = next((c for c in clause.children if c.type == "catch_formal_parameter"), None)
        name = of._f(param, "name") if param is not None else None
        if param is None or name is None or of._t(name, src) != var:
            return Provenance(UNKNOWN, [], f"{var} is not the catch variable of the enclosing catch")
        catch_types: List[str] = []
        for ctype in param.children:
            if ctype.type == "catch_type":
                catch_types = [of._simple_type(t, src) for t in of._named(ctype)]
        candidates = [Provenance(CONSTRAINED, [])]
        explicit = self._explicit_throws(clause, src)
        for t in catch_types:
            candidates.append(self._type_domain(t, explicit.get(t, []), path, text, depth))
        # An exception built in the try body that the catch can receive (a narrower
        # type under a broad catch, or a subtype of a project catch type).
        for t, nodes in explicit.items():
            if t in catch_types or not self._assignable(t, catch_types):
                continue
            candidates.append(self._type_domain(t, nodes, path, text, depth))
        return _worst(candidates)

    @staticmethod
    def _explicit_throws(clause: Any, src: bytes) -> Dict[str, List[Any]]:
        """`throw new X(..)` creations in the try body of this catch."""
        found: Dict[str, List[Any]] = {}
        try_stmt = clause.parent
        body = of._f(try_stmt, "body") if try_stmt is not None else None
        if body is None:
            return found
        stack = [body]
        while stack:
            n = stack.pop()
            if n.type == "throw_statement":
                for child in of._named(n):
                    if child.type == "object_creation_expression":
                        found.setdefault(of._simple_type(of._f(child, "type"), src), []).append(child)
            stack.extend(n.children)
        return found

    def _assignable(self, thrown: str, catch_types: List[str]) -> bool:
        for c in catch_types:
            if c == thrown or c in BROAD_CATCH and not self._project_type(thrown):
                return True
            if self._project_type(c) and thrown in self._subclasses(c):
                return True
        return False

    def _type_domain(self, simple: str, creations: List[Any], path: str, text: str, depth: int) -> Provenance:
        if simple == NPE and creations:
            # An explicit `new NullPointerException(msg)`: judge its arguments.
            results = [self._creation_domain(n, path, text, depth) for n in creations]
            return _worst(results)
        if simple == NPE:
            return Provenance(CONSTRAINED, [NPE], "NullPointerException: VM-generated message")
        return self.class_domain(simple, depth)

    def _creation_domain(self, node: Any, path: str, text: str, depth: int) -> Provenance:
        site = _Site(path, node.start_point[0] + 1, "NullPointerException")
        return self._site_domain(site, depth)


def exception_vars(args: List[Dict[str, Any]]) -> Tuple[List[str], bool]:
    """(names of exception variables the call logs, whether some other
    non-constant argument is present). An argument is exception-derived when it
    is a throwable-typed variable or a getter on one."""
    names: List[str] = []
    other = False
    for arg in args:
        text = str(arg.get("text") or "").strip()
        kinds = set(str(arg.get("kind") or "unknown").split("+"))
        referenced = [m.group(1) for m in _CATCH_VAR_USE_RE.finditer(text)]
        if "throwable" in kinds and re.fullmatch(r"\w+", text):
            referenced.append(text)
        via = str(arg.get("via") or "")
        if referenced and (("throwable" in kinds) or via.startswith("throwable.") or ",throwable." in via):
            names.extend(referenced)
        elif kinds <= {"string_literal", "constant", "numeric", "boolean", "enum"}:
            continue
        else:
            _, ok, locale = classify_arguments([arg], None)
            if not (ok and not locale):
                other = True
    return list(dict.fromkeys(names)), other
