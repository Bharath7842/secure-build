"""Where does an Angular component's value end up on the page? (SAST-03-080)

A finding on a translation lookup (`translate.get/instant/stream`) or on a
component property (`this.msg = ...`, `this.errors.push(...)`) is only about
cross-site scripting or code execution if the value reaches a dangerous
rendering context. Angular escapes `{{ }}` interpolation and text bindings and
sanitises `[innerHTML]`; the dangerous contexts are a trusted-value bypass, a
native-element write and an evaluator. This module follows the property into
the component's template (a `templateUrl` file read through the repository, or
the inline `template`) and into the component class, and names each place it is
consumed.

Template reading is deliberately light — interpolation, bindings, `*ngFor` /
`@for` / `*ngIf ... as` aliases and pipes are regular enough for a few
expressions; there is no Angular compiler. Anything the reading cannot settle
(a child component receiving the value, a custom pipe on an `[innerHTML]`
binding, a missing template) is a consumer of kind ``unknown``, which the
validator turns into a named evidence gap, never a proof.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

import ast_struct

TEXT = "text"
ANGULAR_HTML = "angular_html"
BYPASS = "bypass"
RAW_DOM = "raw_dom"
EVALUATOR = "evaluator"
UNKNOWN = "unknown"
UNSAFE = frozenset({BYPASS, RAW_DOM, EVALUATOR})

# Rules whose findings are themselves the dangerous contexts: this check must
# never dismiss them.
POSITIVE_RULE_IDS = frozenset({
    "innerhtml-assign", "angular-renderer-setproperty-innerhtml", "angular-bypass-security-trust",
    "angular-elementref-nativeelement-html", "angular-innerhtml-binding",
})
BUILTIN_PIPES = frozenset({
    "async", "translate", "json", "date", "uppercase", "lowercase", "titlecase", "slice", "number",
    "currency", "percent", "keyvalue", "i18nselect", "i18nplural",
})
_HTML_BINDINGS = frozenset({"innerhtml", "outerhtml"})
_RAW_SINK_RE = re.compile(
    r"nativeElement\s*\.\s*(?:inner|outer)HTML|\.innerHTML\s*=|\.outerHTML\s*=|insertAdjacentHTML\s*\("
    r"|document\.write(?:ln)?\s*\(|setProperty\s*\([^)]*['\"](?:inner|outer)HTML['\"]|bypassSecurityTrust\w*\s*\("
    r"|\beval\s*\(|new\s+Function\s*\("
)
_TRANSLATE_CALL_RE = re.compile(r"\w*[tT]ranslate\w*\s*\.\s*(?:get|instant|stream)\s*\(")
_THIS_WRITE_RE = re.compile(r"\bthis\s*\.\s*(\w+)\s*(?:=(?!=)|\.\s*push\s*\(|\[[^\]]*\]\s*=(?!=))")
_CUSTOM_TRANSLATION_RE = re.compile(
    r"(?:implements|extends)\s+(?:[\w.]+\s*,\s*)*(?:TranslateCompiler|MissingTranslationHandler|TranslateParser)\b"
)


@dataclass
class Consumer:
    context: str
    where: str  # "file:line" or "inline template"
    detail: str = ""


@dataclass
class Analysis:
    anchor: str  # "translate" | "assignment" | "push"
    properties: List[str]
    component: str
    consumers: List[Consumer] = field(default_factory=list)
    problems: List[str] = field(default_factory=list)  # why the reading is incomplete

    def contexts(self) -> Set[str]:
        return {c.context for c in self.consumers}


# --- anchors -----------------------------------------------------------------------

def _statement_text(lines: List[str], line: int, window: int = 12) -> str:
    """The anchor statement: from its line to the first line that closes it
    (a `subscribe(...)` callback may span several lines)."""
    chunk: List[str] = []
    depth = 0
    for text in lines[line - 1: line - 1 + window]:
        chunk.append(text)
        depth += text.count("(") + text.count("{") + text.count("[") - text.count(")") - text.count("}") - text.count("]")
        if depth <= 0 and text.rstrip().endswith((";", "}")):
            break
    return "\n".join(chunk)


def find_anchor(text: str, line: int) -> Optional[Tuple[str, List[str], str]]:
    """(kind, written properties, statement) for a finding on a translation
    lookup or a component property write; None for anything else."""
    lines = text.splitlines()
    if line < 1 or line > len(lines):
        return None
    statement = _statement_text(lines, line)
    if _RAW_SINK_RE.search(statement):
        return None  # a dangerous context itself: other rules find it
    props = list(dict.fromkeys(_THIS_WRITE_RE.findall(statement)))
    translate = _TRANSLATE_CALL_RE.search(statement) is not None
    if not props and not translate:
        return None
    if not props:
        return None  # a lookup whose result is never stored: nothing to follow
    kind = "translate" if translate else ("push" if re.search(r"\.\s*push\s*\(", statement) else "assignment")
    return kind, props, statement


# --- templates -------------------------------------------------------------------------

def _ident(name: str) -> "re.Pattern[str]":
    return re.compile(rf"(?<![\w.$]){re.escape(name)}(?![\w$])|(?<![\w.$])this\s*\.\s*{re.escape(name)}(?![\w$])")


def _pipes(expression: str) -> List[str]:
    parts = re.split(r"(?<!\|)\|(?!\|)", expression)
    return [p.strip().split(":")[0].strip() for p in parts[1:] if p.strip()]


def _aliases(template: str, names: Set[str]) -> Set[str]:
    """The property plus every loop / `as` variable derived from it."""
    aliases = set(names)
    for _ in range(4):
        grew = False
        patterns = (
            r"\*ngFor\s*=\s*\"\s*let\s+(\w+)\s+of\s+([^\";]+)",
            r"@for\s*\(\s*(\w+)\s+of\s+([^;)]+)",
        )
        for pattern in patterns:
            for m in re.finditer(pattern, template):
                var, source = m.group(1), m.group(2)
                if var not in aliases and any(_ident(a).search(source) for a in aliases):
                    aliases.add(var)
                    grew = True
        for m in re.finditer(r"(?:\*ngIf\s*=\s*\"|@if\s*\(|\*ngFor\s*=\s*\"[^\"]*;)\s*([^\";]+?)\s+as\s+(\w+)", template):
            if m.group(2) not in aliases and any(_ident(a).search(m.group(1)) for a in aliases):
                aliases.add(m.group(2))
                grew = True
        for m in re.finditer(r"\(\s*([^()]*?)\s*\|\s*async\s*\)\s*as\s+(\w+)", template):
            if m.group(2) not in aliases and any(_ident(a).search(m.group(1)) for a in aliases):
                aliases.add(m.group(2))
                grew = True
        if not grew:
            break
    return aliases


def template_consumers(template: str, where: str, names: Set[str]) -> List[Consumer]:
    """Every place in a template that renders one of ``names`` (or an alias of it)."""
    aliases = _aliases(template, names)
    out: List[Consumer] = []

    def uses(expression: str) -> bool:
        return any(_ident(a).search(expression) for a in aliases)

    def line_of(index: int) -> int:
        return template.count("\n", 0, index) + 1

    for m in re.finditer(r"\{\{(.*?)\}\}", template, re.S):
        if uses(m.group(1)):
            out.append(Consumer(TEXT, f"{where}:{line_of(m.start())}", f"interpolation {{{{ {m.group(1).strip()[:40]} }}}}"))
    for m in re.finditer(r"\[\s*([\w.\-]+)\s*\]\s*=\s*\"([^\"]*)\"", template):
        attr, expression = m.group(1), m.group(2)
        if not uses(expression):
            continue
        loc = f"{where}:{line_of(m.start())}"
        tag = _tag_before(template, m.start())
        if attr.lower() in _HTML_BINDINGS:
            custom = [p for p in _pipes(expression) if p.lower() not in BUILTIN_PIPES]
            if custom:
                out.append(Consumer(UNKNOWN, loc, f"[{attr}] through custom pipe {custom[0]}"))
            else:
                out.append(Consumer(ANGULAR_HTML, loc, f"[{attr}] (Angular sanitises it)"))
        elif "-" in tag and not attr.lower().startswith(("attr.", "class.", "style.")):
            out.append(Consumer(UNKNOWN, loc, f"passed to <{tag}> [{attr}], which renders it elsewhere"))
        else:
            out.append(Consumer(TEXT, loc, f"binding [{attr}]"))
    return out


def _tag_before(template: str, index: int) -> str:
    start = template.rfind("<", 0, index)
    m = re.match(r"<\s*([\w\-]+)", template[start:index + 1]) if start >= 0 else None
    return m.group(1).lower() if m else ""


# --- component class -----------------------------------------------------------------

def class_consumers(class_text: str, where: str, names: Set[str]) -> List[Consumer]:
    """Dangerous contexts in the component class itself: a trusted-value bypass,
    a native-element write or an evaluator whose operand mentions the property."""
    out: List[Consumer] = []
    aliases = set(names)
    for m in re.finditer(r"(?:const|let|var)\s+(\w+)\s*=\s*([^;]*);", class_text):  # `const v = this.msg;`
        if any(_ident(a).search(m.group(2)) for a in aliases):
            aliases.add(m.group(1))
    for m in re.finditer(r"[^;{}]*;|[^;{}]*\{", class_text):
        statement = m.group(0)
        if not _RAW_SINK_RE.search(statement) or not any(_ident(a).search(statement) for a in aliases):
            continue
        context = BYPASS if "bypassSecurityTrust" in statement else (
            EVALUATOR if re.search(r"\beval\s*\(|new\s+Function\s*\(", statement) else RAW_DOM)
        line = class_text.count("\n", 0, m.start()) + 1
        out.append(Consumer(context, f"{where}+{line}", statement.strip()[:60]))
    return out


# --- the whole component -------------------------------------------------------------

def analyze(text: str, path: str, line: int, read_text: Callable[[str], Optional[str]]) -> Optional[Analysis]:
    anchor = find_anchor(text, line)
    if anchor is None:
        return None
    kind, props, _statement = anchor
    components = [c for c in ast_struct.component_metadata(text) if c["start_line"] <= line <= c["end_line"]]
    if not components:
        return Analysis(kind, props, "", problems=["the class is not an @Component"])
    comp = components[0]
    result = Analysis(kind, props, comp["class"])
    names = set(props)
    lines = text.splitlines()
    result.consumers.extend(class_consumers("\n".join(lines[comp["start_line"] - 1:comp["end_line"]]), path, names))
    if comp["template"] is not None:
        result.consumers.extend(template_consumers(comp["template"], f"{path} (inline template)", names))
    elif comp["templateUrl"]:
        rel = os.path.normpath(os.path.join(os.path.dirname(path), comp["templateUrl"])).replace(os.sep, "/")
        template = read_text(rel)
        if template is None:
            result.problems.append(f"template {rel} is not in the repository")
        else:
            result.consumers.extend(template_consumers(template, rel, names))
    else:
        result.problems.append("the component has no template or templateUrl the scan can read")
    if not result.consumers and not result.problems:
        result.problems.append(f"no template renders {', '.join(sorted(names))}")
    return result


# --- repo-wide: a custom translation pipeline --------------------------------------------

_SKIP = {"node_modules", ".git", "dist", "build", "target", ".angular"}


def custom_translation_pipeline(repo_root: Optional[Path]) -> List[str]:
    """Files that declare their own TranslateCompiler / MissingTranslationHandler /
    TranslateParser, or a TranslateLoader that evaluates what it loads. Such a
    component sits between the dictionary and the page, so the text a lookup
    returns is no longer plain dictionary text."""
    found: List[str] = []
    if repo_root is None:
        return found
    root = str(repo_root)
    budget = 4000
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP and not d.startswith(".")]
        for name in filenames:
            if not name.endswith(".ts") or name.endswith((".spec.ts", ".d.ts")):
                continue
            budget -= 1
            if budget < 0:
                return found
            full = os.path.join(dirpath, name)
            try:
                if os.path.getsize(full) > 400_000:
                    continue
                body = open(full, encoding="utf-8", errors="replace").read()
            except OSError:
                continue
            if "Translate" not in body and "MissingTranslation" not in body:
                continue
            rel = os.path.relpath(full, root).replace(os.sep, "/")
            if _CUSTOM_TRANSLATION_RE.search(body):
                found.append(rel)
            elif re.search(r"implements\s+TranslateLoader", body) and re.search(r"\beval\s*\(|new\s+Function\s*\(|innerHTML", body):
                found.append(rel)
    return sorted(found)
