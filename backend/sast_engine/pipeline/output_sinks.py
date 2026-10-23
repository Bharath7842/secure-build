"""What a print or log call really writes to (SAST-03-010).

`sink_class(facts)` classifies the call an occurrence sits on by what its
*receiver* is — not by how the variable is spelled and not by the rule that
matched — so the log-forging, disclosure and XSS validators each judge only the
sinks they apply to:

* ``logger``         an slf4j / log4j / jul / commons-logging / jboss logger
                     (any variable name, including a static import or a
                     ``LoggerFactory.getLogger(..)`` chain); in TypeScript
                     ``console`` / ``NGXLogger`` or a service that wraps one;
* ``process_stream`` ``System.out`` / ``System.err`` and an argument-less
                     ``printStackTrace()``;
* ``http_response``  ``response.getWriter()`` / ``getOutputStream()``, a
                     variable assigned from either, a ``JspWriter`` (the JSP
                     implicit ``out``) and a ``PrintWriter`` built over one;
* ``other``          a library type known not to be any of the above (a
                     ``PrintWriter`` over a file);
* ``unknown``        the receiver cannot be resolved. ``unknown`` is never a
                     proof: a project class named ``AppLogger`` may wrap a real
                     logger, and a variable's name proves nothing.

Pure: facts in, class out. ``read_text`` (path -> text) lets a TypeScript
service be looked into; without it such a receiver is ``unknown``.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Callable, Dict, Optional

from .occurrence_facts import LOGGER_PACKAGES

LOGGER = "logger"
PROCESS_STREAM = "process_stream"
HTTP_RESPONSE = "http_response"
OTHER = "other"
UNKNOWN = "unknown"

EXPOSURE_LOG = "log_record"
EXPOSURE_PROCESS = "process_output"
EXPOSURE_HTTP = "http_body"
_EXPOSURE = {LOGGER: EXPOSURE_LOG, PROCESS_STREAM: EXPOSURE_PROCESS, HTTP_RESPONSE: EXPOSURE_HTTP}

# --- type tables (one place; next to call_graph._WELL_KNOWN_TYPES by purpose) --
# Declared types whose instances write somewhere other than a logger.
WRITER_TYPES = frozenset({
    "PrintWriter", "PrintStream", "Writer", "BufferedWriter", "OutputStreamWriter",
    "FileWriter", "OutputStream", "BufferedOutputStream", "FileOutputStream",
    "ServletOutputStream", "StringWriter", "CharArrayWriter", "ByteArrayOutputStream",
})
HTTP_RESPONSE_WRITER_TYPES = frozenset({"JspWriter", "ServletOutputStream"})
# `response.getWriter()` / `getOutputStream()` on anything: a servlet response's.
_RESPONSE_STREAM_RE = re.compile(r"\.\s*(?:getWriter|getOutputStream)\s*\(\s*\)")
_SYSTEM_STREAM_RE = re.compile(r"^\s*System\s*\.\s*(?:out|err)\s*$")
_WRAPS_RE = re.compile(r"^\s*new\s+(?:\w+\.)*(?:PrintWriter|PrintStream|BufferedWriter|OutputStreamWriter|BufferedOutputStream)\s*\((.*)\)\s*$", re.S)
_PLAIN_STREAM_RE = re.compile(
    r"^\s*new\s+(?:\w+\.)*(?:FileWriter|FileOutputStream|StringWriter|CharArrayWriter|ByteArrayOutputStream)\b"
)
TS_LOGGER_TYPES = frozenset({"console", "NGXLogger"})
_TS_WRAPS_LOGGER_RE = re.compile(r"\bconsole\s*\.\s*(?:log|info|warn|error|debug)\b|\bNGXLogger\b")


@dataclass(frozen=True)
class SinkClass:
    kind: str
    exposure: Optional[str] = None
    detail: str = ""

    def __str__(self) -> str:  # for messages and tests
        return self.kind


def _result(kind: str, detail: str = "") -> SinkClass:
    return SinkClass(kind, _EXPOSURE.get(kind), detail)


def _stream_text_is_response(text: str) -> bool:
    return bool(text) and _RESPONSE_STREAM_RE.search(text) is not None


def _writer_kind(receiver: str, origin: str) -> Optional[SinkClass]:
    """Class of a PrintWriter/PrintStream-like receiver from where it came from."""
    if _SYSTEM_STREAM_RE.match(receiver) or _SYSTEM_STREAM_RE.match(origin):
        return _result(PROCESS_STREAM, "System stream")
    for text in (receiver, origin):
        if _stream_text_is_response(text):
            return _result(HTTP_RESPONSE, "writer taken from a servlet response")
    for text in (receiver, origin):
        if _PLAIN_STREAM_RE.match(text or ""):
            return _result(OTHER, "writer over a file or memory buffer")
        wrapped = _WRAPS_RE.match(text or "")
        if wrapped:
            inner = wrapped.group(1)
            if _stream_text_is_response(inner):
                return _result(HTTP_RESPONSE, "writer over a servlet response")
            if _SYSTEM_STREAM_RE.match(inner.strip()):
                return _result(PROCESS_STREAM, "writer over a System stream")
            return _result(OTHER, "writer over a non-response stream")
    return None


def _java_class(call: Dict[str, Any], file_path: str) -> SinkClass:
    receiver = call.get("receiver") or ""
    fqn = call.get("receiver_fqn") or ""
    declared = call.get("receiver_type") or ""
    origin = call.get("receiver_origin") or ""
    callee = call.get("callee") or ""

    if call.get("is_constructor"):
        return _result(UNKNOWN, "constructor")
    if fqn.startswith(LOGGER_PACKAGES):
        return _result(LOGGER, fqn)
    if callee == "printStackTrace" and not call.get("arity"):
        return _result(PROCESS_STREAM, "printStackTrace() writes to System.err")
    if declared in HTTP_RESPONSE_WRITER_TYPES or fqn.endswith((".JspWriter", ".ServletOutputStream")):
        return _result(HTTP_RESPONSE, declared or fqn)
    if declared in WRITER_TYPES or fqn.startswith(("java.io.",)):
        found = _writer_kind(receiver, origin)
        # A writer that arrived as a parameter or field may be the response's.
        return found or _result(UNKNOWN, f"{declared or fqn} of unknown origin")
    found = _writer_kind(receiver, origin)
    if found is not None:  # `response.getWriter().println(..)` — the receiver is the call itself
        return found
    if fqn.startswith(("java.", "javax.", "jakarta.")):
        return _result(OTHER, fqn)  # a JDK type that is not a logger or a response writer
    return _result(UNKNOWN, declared or receiver or "unresolved receiver")


def _ts_class(call: Dict[str, Any], file_path: str,
              read_text: Optional[Callable[[str], str]]) -> SinkClass:
    receiver = (call.get("receiver") or "").strip()
    declared = call.get("receiver_fqn") or call.get("receiver_type") or ""
    if receiver == "console" or declared in TS_LOGGER_TYPES:
        return _result(LOGGER, declared or receiver)
    if re.match(r"^process\.(stdout|stderr)$", receiver):
        return _result(PROCESS_STREAM, receiver)
    module = call.get("receiver_module") or ""
    if read_text is not None and module.startswith("."):
        base = file_path.rsplit("/", 1)[0] if "/" in file_path else ""
        parts = [p for p in (base + "/" + module).split("/") if p and p != "."]
        stack = []
        for part in parts:
            if part == "..":
                if stack:
                    stack.pop()
            else:
                stack.append(part)
        path = "/".join(stack)
        for suffix in (".ts", "/index.ts"):
            try:
                text = read_text(path + suffix)
            except Exception:  # noqa: BLE001
                text = ""
            if text:
                if _TS_WRAPS_LOGGER_RE.search(text):
                    return _result(LOGGER, f"{declared} wraps a logger ({path + suffix})")
                break
    return _result(UNKNOWN, declared or receiver or "unresolved receiver")


def sink_class(
    facts: Optional[Dict[str, Any]],
    *,
    file_path: str = "",
    read_text: Optional[Callable[[str], str]] = None,
) -> SinkClass:
    """Classify the call in ``facts``; ``unknown`` when there is none."""
    call = (facts or {}).get("call") if facts else None
    if not call:
        return _result(UNKNOWN, "no call at the anchor")
    if (facts or {}).get("lang") == "typescript":
        return _ts_class(call, file_path or "", read_text)
    return _java_class(call, file_path or "")


def is_logger(facts: Optional[Dict[str, Any]], **kw: Any) -> bool:
    return sink_class(facts, **kw).kind == LOGGER
