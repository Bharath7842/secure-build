"""Read a JSP's scriptlets as Java (SAST-03-010).

`rewrite(text)` turns the Java parts of a JSP (`<% .. %>` scriptlets and
`<%= .. %>` expressions) into the body of a synthetic servlet method whose
parameters are the JSP implicit objects, so `occurrence_facts` can resolve
`out` to a `JspWriter` and `request` to an `HttpServletRequest` with the same
tree-sitter pass it uses for `.java`. Everything else — markup, directives,
`<%-- --%>` comments, `<%! .. %>` declarations — becomes blanks.

Line numbers are preserved exactly (every newline stays where it was) and
columns are preserved on every line except the first (which carries the method
header) and a line holding a `<%= %>` expression, so a finding's line in the
original file is its line in the rewritten one.

Not modelled, on purpose: EL, taglibs and custom tags. A JSP with no scriptlet
rewrites to None and gets no facts, which means `unknown`, never a proof.
"""
from __future__ import annotations

import re
from typing import List, Optional

HEADER = (
    "class _Jsp { void _jspService(javax.servlet.http.HttpServletRequest request, "
    "javax.servlet.http.HttpServletResponse response, javax.servlet.jsp.JspWriter out, "
    "javax.servlet.http.HttpSession session) throws Exception { "
)
FOOTER = "\n}}\n"

_SEGMENT_RE = re.compile(r"<%(--.*?--|[@!=]?)(.*?)%>", re.S)


def _blank(chunk: str) -> str:
    """The same text with everything but newlines replaced by spaces."""
    return re.sub(r"[^\n]", " ", chunk)


def rewrite(text: str) -> Optional[str]:
    if not text or "<%" not in text:
        return None
    out: List[str] = []
    last = 0
    code_seen = False
    for m in _SEGMENT_RE.finditer(text):
        out.append(_blank(text[last:m.start()]))
        marker, body = m.group(1), m.group(2)
        whole = m.group(0)
        if marker == "" :
            # `<%` is two characters: keep the code at its original column.
            out.append("  " + body + "  ")
            code_seen = True
        elif marker == "=":
            expression = body.strip()
            lead = whole.count("\n")
            if expression:
                out.append("out.print(" + expression + ");" + "\n" * (lead - expression.count("\n")))
                code_seen = True
            else:
                out.append("\n" * lead)
        else:  # directive, declaration or comment
            out.append(_blank(whole))
        last = m.end()
    out.append(_blank(text[last:]))
    if not code_seen:
        return None
    return HEADER + "".join(out) + FOOTER
