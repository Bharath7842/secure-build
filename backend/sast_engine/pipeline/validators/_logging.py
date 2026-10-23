"""Shared pieces of the log-forging validators (SAST-03-020 to 03-050).

All of them answer one question about a logger call — can *this call* write
attacker-influenced, line-breaking text into a log record (CWE-117)? — so the
call's own source, its arguments and the CWE they apply to live here once.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

from .. import output_sinks

CWE_117 = ("CWE-117",)
LOG_RULE_IDS = ("java-log-injection-unsanitized-input",)
LOG_RULE_PREFIXES = ("runtime-sink-log",)

# Expressions that hand outside text to the callee: an exception's message and
# the request accessors `java-log-injection-unsanitized-input` is written for.
# Wider than the rule on purpose (any receiver, not just `request`): a wider
# source list only ever means fewer negative proofs.
SOURCE_RE = re.compile(
    r"\.\s*(?:getMessage|getLocalizedMessage)\s*\(\s*\)"
    r"|\.\s*get(?:Parameter|ParameterValues|Header|RequestURI|RequestURL|QueryString)\s*\("
)


def is_regex_candidate(finding: Dict[str, Any]) -> bool:
    """A hit the log-injection rule generated (its pattern names the sources), as
    opposed to a model finding whose source can be anything. A model finding that
    cites the same catalog rule id is still the model's."""
    return finding.get("kind") == "regex"


def logger_call(facts: Optional[Dict[str, Any]], path: str, ctx: Any) -> Optional[output_sinks.SinkClass]:
    if not facts or facts.get("lang") != "java" or not facts.get("call"):
        return None
    return output_sinks.sink_class(facts, file_path=path or "", read_text=getattr(ctx, "read_text", None))


def call_source(text: Optional[str], call: Dict[str, Any]) -> Optional[str]:
    """The exact source of the call (`log.info("a", x)`), cut from the file by the
    position facts recorded. None when the file or the position is missing."""
    if not text or call.get("end_col") is None or not call.get("start_line"):
        return None
    lines = text.splitlines()
    first, last = int(call["start_line"]) - 1, int(call["end_line"]) - 1
    if first < 0 or last >= len(lines) or last < first:
        return None
    if first == last:
        return lines[first][int(call["start_col"]):int(call["end_col"])]
    parts = [lines[first][int(call["start_col"]):], *lines[first + 1:last], lines[last][:int(call["end_col"])]]
    return "\n".join(parts)


def arguments_text(source: str) -> str:
    """The text inside the call's outermost parentheses (arguments only: a
    receiver chain such as `request.getSession().foo(` is not an argument)."""
    start = source.find("(")
    # `LoggerFactory.getLogger(X.class).info(msg)`: arguments belong to the last call.
    depth, last_open = 0, start
    for i, ch in enumerate(source):
        if ch == "(":
            if depth == 0:
                last_open = i
            depth += 1
        elif ch == ")":
            depth -= 1
    return source[last_open + 1:] if last_open >= 0 else source


def local_sources(method_text: str, argument_text: str) -> List[str]:
    """Source expressions reaching the call through a local: `String m =
    e.getMessage(); log.info(m);` names `m`."""
    found: List[str] = []
    for ident in dict.fromkeys(re.findall(r"\b[A-Za-z_]\w*\b", argument_text)):
        m = re.search(rf"\b{re.escape(ident)}\s*=\s*([^;]*)", method_text)
        if m and SOURCE_RE.search(m.group(1)):
            found.append(ident)
    return found


def method_text(text: Optional[str], facts: Dict[str, Any]) -> str:
    enclosing = facts.get("enclosing") or {}
    if not text or not enclosing.get("start_line"):
        return ""
    lines = text.splitlines()
    return "\n".join(lines[int(enclosing["start_line"]) - 1:int(enclosing["end_line"])])


def next_source_line(text: Optional[str], call: Dict[str, Any], reach: int = 8) -> Optional[Tuple[int, str]]:
    """The first line after the call that holds one of the rule's sources: where
    the regex window found the text it blamed on the call."""
    if not text:
        return None
    lines = text.splitlines()
    end = int(call.get("end_line") or call.get("start_line") or 0)
    end_col = int(call.get("end_col") or 0)
    for offset in range(0, reach + 1):
        index = end - 1 + offset
        if index >= len(lines):
            break
        segment = lines[index][end_col:] if offset == 0 else lines[index]
        m = SOURCE_RE.search(segment)
        if m:
            return index + 1, segment[max(0, m.start() - 20):m.end()].strip()
    return None
