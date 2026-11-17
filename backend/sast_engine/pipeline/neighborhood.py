"""neighborhood.py — repository context for a prompt, resolved without an LLM.

Two kinds:

* `member_neighborhood` — what an occurrence's excerpt cannot show: the bodies
  of the project methods its enclosing method calls (a `validate(input)` guard,
  a `buildQuery(...)` helper) and the values of the `Owner.CONSTANT`s its code
  names. Grouped confirmation appends it to the occurrences it shows.
* `security_entries` / `render_security_summary` — the repository's global
  security configuration: Spring Security filter chains, `web.xml` security
  constraints and security filters, Angular route guards. Whether an endpoint
  needs authentication at all is decided there, not in the controller, so the
  deep scan of a web entry point (`is_web_entry_file`) is shown it.

Deterministic over the repository (sorted, bounded), so the same tree always
gives the same text and prompts — and their result-cache keys — do not move
between runs. Both are context for the model, never a verdict.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any, Collection, Dict, List, Optional, Sequence, Tuple

MAX_NEIGHBORHOOD_CALLEES = 3
NEIGHBORHOOD_CALLEE_MAX_LINES = 35
NEIGHBORHOOD_CALLEE_CHARS = 1_800
MAX_NEIGHBORHOOD_CONSTANTS = 5
NEIGHBORHOOD_LINE_MAX_CHARS = 200

SECURITY_SUMMARY_MAX_CHARS = 1_200
SECURITY_LINE_MAX_CHARS = 160

_CONSTANT_REF_RE = re.compile(r"\b([A-Z]\w*)\.([A-Z][A-Z0-9_]*)\b")
# A body that is only `return field;`, `this.x = x;` or empty says nothing.
_TRIVIAL_BODY_RE = re.compile(
    r"^\s*(?:return\s+(?:this\.)?\w+\s*;|(?:this\.)?\w+\s*=\s*\w+\s*;|super\s*\([^()]*\)\s*;)?\s*$"
)

# --- callee / constant neighborhood -------------------------------------------


def _java_graph(ctx: Any) -> Any:
    graph = getattr(ctx, "call_graph", None)
    if graph is None:
        return None
    from . import call_graph as cg

    return graph if isinstance(graph, cg.CallGraph) else None


def _outgoing(graph: Any) -> Dict[str, List[Any]]:
    out = getattr(graph, "_neighborhood_outgoing", None)
    if out is None:
        out = {}
        for edge in graph.edges:
            out.setdefault(edge.caller_key, []).append(edge)
        graph._neighborhood_outgoing = out
    return out


def _is_trivial(method: Any) -> bool:
    body = method.body or ""
    first, last = body.find("{"), body.rfind("}")
    if first < 0 or last <= first:
        return True  # abstract / interface declaration: no body to show
    return bool(_TRIVIAL_BODY_RE.match(body[first + 1:last]))


def _overlaps(windows: Sequence[Tuple[int, int]], start: int, end: int) -> bool:
    return any(lo <= end and start <= hi for lo, hi in windows)


def _cut(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[:limit] + "…"


def _callee_candidates(
    graph: Any, member: Dict[str, Any], shown_windows: Dict[str, List[Tuple[int, int]]],
) -> List[Tuple[Any, int]]:
    """(callee method, call line) for the project methods the member's
    enclosing method calls, nearest the member's line first."""
    from . import call_graph as cg

    path = member.get("file_path") or ""
    line = int(member.get("line") or 0)
    method = cg.method_at_line(graph, path, line) if path and line else None
    if method is None:
        return []
    out: List[Tuple[Any, int]] = []
    seen = set()
    for edge in sorted(_outgoing(graph).get(method.key, ()), key=lambda e: (abs(e.call_line - line), e.call_line, e.callee_key)):
        callee = graph.methods.get(edge.callee_key)
        if callee is None or callee.key == method.key or callee.key in seen:
            continue
        seen.add(callee.key)
        if callee.end_line - callee.start_line + 1 > NEIGHBORHOOD_CALLEE_MAX_LINES or _is_trivial(callee):
            continue
        if _overlaps(shown_windows.get(callee.file, ()), callee.start_line, callee.end_line):
            continue  # the excerpt already shows it
        out.append((callee, edge.call_line))
    return out


def member_neighborhood(
    members: Sequence[Tuple[str, Dict[str, Any]]],
    ctx: Any,
    *,
    shown_windows: Optional[Dict[str, List[Tuple[int, int]]]] = None,
) -> str:
    """The `Neighborhood context` block for the (label, finding) members of one
    prompt: up to MAX_NEIGHBORHOOD_CALLEES in-repo callee bodies of their
    enclosing methods (taken in turn from each member, within
    NEIGHBORHOOD_CALLEE_CHARS) and the values of the repository constants
    their shown code names. "" without a Java call graph or anything found."""
    if ctx is None or not members:
        return ""
    shown_windows = shown_windows or {}
    parts: List[str] = []

    graph = _java_graph(ctx)
    if graph is not None:
        queues = [(label, _callee_candidates(graph, m, shown_windows)) for label, m in members]
        picked: List[Tuple[str, Any, int]] = []
        taken = set()
        budget = NEIGHBORHOOD_CALLEE_CHARS
        while len(picked) < MAX_NEIGHBORHOOD_CALLEES and any(q for _l, q in queues):
            for label, queue in queues:
                while queue and len(picked) < MAX_NEIGHBORHOOD_CALLEES:
                    callee, call_line = queue.pop(0)
                    if callee.key in taken:
                        continue
                    text = ctx.read_text(callee.file) or ""
                    body = text.splitlines()[callee.start_line - 1:callee.end_line]
                    cost = sum(min(len(b), NEIGHBORHOOD_LINE_MAX_CHARS) + 8 for b in body)
                    if not body or cost > budget:
                        continue
                    budget -= cost
                    taken.add(callee.key)
                    picked.append((label, callee, call_line))
                    break
        for label, callee, call_line in picked:
            lines = (ctx.read_text(callee.file) or "").splitlines()
            owner = callee.fqcn.rsplit(".", 1)[-1]
            block = [
                f"Callee {owner}.{callee.name} (called by {label} at line {call_line}) — "
                f"{callee.file} lines {callee.start_line}-{callee.end_line}:"
            ]
            block.extend(
                f"{n}: {_cut(lines[n - 1], NEIGHBORHOOD_LINE_MAX_CHARS)}"
                for n in range(callee.start_line, min(callee.end_line, len(lines)) + 1)
            )
            parts.append("\n".join(block))

    resolve = getattr(getattr(ctx, "sql", None), "constant_text", None)
    if resolve is not None:
        constants: List[str] = []
        seen_refs = set()
        for label, member in members:
            path = member.get("file_path") or ""
            lines = (ctx.read_text(path) or "").splitlines()
            line = int(member.get("line") or 0)
            windows = [w for w in shown_windows.get(path, ()) if w[0] <= line <= w[1]] or [(line, line)]
            for lo, hi in windows:
                for n in range(max(lo, 1), min(hi, len(lines)) + 1):
                    for owner, name in _CONSTANT_REF_RE.findall(lines[n - 1]):
                        if (owner, name) in seen_refs or len(constants) >= MAX_NEIGHBORHOOD_CONSTANTS:
                            continue
                        seen_refs.add((owner, name))
                        try:
                            value = resolve(owner, name)
                        except Exception:  # noqa: BLE001 - context is best-effort
                            value = None
                        if value is not None:
                            constants.append(
                                f"Constant {owner}.{name} (used by {label}) = "
                                + _cut(json.dumps(value, ensure_ascii=False), NEIGHBORHOOD_LINE_MAX_CHARS)
                            )
        parts.extend(constants)

    if not parts:
        return ""
    return (
        "Neighborhood context (resolved from the repository's code; context only — decide only "
        "the occurrences above):\n" + "\n\n".join(parts)
    )


# --- repository security configuration ----------------------------------------

_SKIP_DIRS = {".git", "node_modules", "target", "build", "dist", ".idea", ".gradle", "out", "venv", ".venv"}
_MAX_DEPTH = 14
_MAX_JAVA_FILES = 6_000
_JAVA_PEEK_CHARS = 64 * 1024
_MAX_CONFIG_FILES = 20

_SECURITY_NAME_RE = re.compile(r"(?:SecurityConfig|WebSecurity|SecurityFilterChain)\w*\.java$", re.I)
_SECURITY_CONTENT_RE = re.compile(
    r"@Enable(?:Web|Method|GlobalMethod|WebFlux)Security\b|\bSecurityFilterChain\b|\bSecurityWebFilterChain\b"
    r"|\bWebSecurityConfigurerAdapter\b"
)
_SECURITY_RULE_RE = re.compile(
    r"\b(?:requestMatchers|antMatchers|mvcMatchers|regexMatchers|securityMatcher|pathMatchers"
    r"|authorizeHttpRequests|authorizeRequests|authorizeExchange|anyRequest|anyExchange|csrf|cors"
    r"|sessionManagement|oauth2ResourceServer|oauth2Login|httpBasic|formLogin|permitAll|denyAll"
    r"|hasRole|hasAnyRole|hasAuthority|hasAnyAuthority|addFilterBefore|addFilterAfter|addFilterAt"
    r"|ignoring)\b|@Enable(?:Web|Method|GlobalMethod|WebFlux)Security\b"
)
_ROUTE_FILE_RE = re.compile(r"(?:routing(?:\.module)?|\.routes|^routes|-routes)\.ts$", re.I)
_GUARD_RE = re.compile(r"\b(?:canActivate|canActivateChild|canMatch|canLoad)\b")
_ROUTE_PATH_RE = re.compile(r"\bpath\s*:\s*(['\"`])([^'\"`]*)\1")
_XML_COMMENT_RE = re.compile(r"<!--[\s\S]*?-->")
_SECURITY_FILTER_RE = re.compile(r"secur|auth|csrf|jwt|token|login|sso|saml|keycloak|shiro|oauth", re.I)

# What makes a file a web entry point whose deep scan needs the summary.
_WEB_ENTRY_RE = {
    ".java": re.compile(
        r"@(?:RestController|Controller|RequestMapping|GetMapping|PostMapping|PutMapping|DeleteMapping"
        r"|PatchMapping|Path|WebServlet|WebFilter|ControllerAdvice|RestControllerAdvice)\b"
        r"|\bextends\s+(?:Http|Generic)Servlet\b|\bimplements\s+(?:[\w.]+\s*,\s*)*(?:javax\.servlet\.|jakarta\.servlet\.)?Filter\b"
        r"|@Enable(?:Web|Method|GlobalMethod|WebFlux)Security\b|\bSecurityFilterChain\b"
    ),
    ".ts": re.compile(r"@Component\s*\(|\bRoutes\b|\bRouterModule\b"),
}


def is_web_entry_file(rel_path: str, text: str) -> bool:
    """A controller, servlet, filter, JSP, security configuration or Angular
    component/routing file: code whose protection is configured elsewhere."""
    suffix = Path(rel_path).suffix.lower()
    if suffix == ".jsp":
        return True
    pattern = _WEB_ENTRY_RE.get(suffix)
    return bool(pattern and pattern.search(text[:_JAVA_PEEK_CHARS]))


def _is_test_path(rel: str) -> bool:
    parts = [p.lower() for p in re.split(r"[\\/]", rel)]
    return any(p in ("test", "tests", "__tests__") for p in parts) or bool(
        re.search(r"(?:Test|IT)\.java$|\.spec\.ts$", rel)
    )


def _walk(repo_root: Path) -> List[str]:
    root = str(repo_root)
    found: List[str] = []
    for dirpath, dirnames, filenames in os.walk(root):
        depth = dirpath[len(root):].count(os.sep)
        dirnames[:] = sorted(
            d for d in dirnames if d not in _SKIP_DIRS and not d.startswith(".")
        ) if depth < _MAX_DEPTH else []
        for name in sorted(filenames):
            rel = os.path.relpath(os.path.join(dirpath, name), root).replace(os.sep, "/")
            if not _is_test_path(rel):
                found.append(rel)
    return found


def _read(repo_root: Path, rel: str, limit: Optional[int] = None) -> Optional[str]:
    try:
        with open(repo_root / rel, encoding="utf-8", errors="replace") as fh:
            return fh.read(limit) if limit else fh.read()
    except OSError:
        return None


def _code_line(line: str) -> bool:
    stripped = line.strip()
    return bool(stripped) and not stripped.startswith(("//", "*", "/*", "#"))


def _spring_entries(rel: str, text: str) -> List[Tuple[str, int, str]]:
    return [
        (rel, n, " ".join(line.split()))
        for n, line in enumerate(text.splitlines(), start=1)
        if _code_line(line) and _SECURITY_RULE_RE.search(line)
    ]


def _tag_values(block: str, tag: str) -> List[str]:
    return [" ".join(v.split()) for v in re.findall(rf"<{tag}>\s*([^<]*?)\s*</{tag}>", block)]


def _web_xml_entries(rel: str, text: str) -> List[Tuple[str, int, str]]:
    # Comments out, line breaks kept, so every offset keeps its line number.
    text = _XML_COMMENT_RE.sub(lambda m: "\n" * m.group().count("\n"), text)

    def line_of(offset: int) -> int:
        return text.count("\n", 0, offset) + 1

    out: List[Tuple[str, int, str]] = []
    for match in re.finditer(r"<security-constraint\b[\s\S]*?</security-constraint>", text):
        block = match.group()
        urls = _tag_values(block, "url-pattern")
        methods = _tag_values(block, "http-method") + [f"not {m}" for m in _tag_values(block, "http-method-omission")]
        roles = _tag_values(block, "role-name")
        if roles:
            auth = "roles " + ", ".join(roles)
        elif "<auth-constraint" in block:
            auth = "empty auth-constraint (no access)"
        else:
            auth = "no auth-constraint (no login required)"
        guarantee = _tag_values(block, "transport-guarantee")
        text_out = (
            f"security-constraint url {', '.join(urls) or '?'}"
            + (f" methods {', '.join(methods)}" if methods else "")
            + f": {auth}" + (f"; transport {guarantee[0]}" if guarantee else "")
        )
        out.append((rel, line_of(match.start()), text_out))
    for match in re.finditer(r"<login-config\b[\s\S]*?</login-config>", text):
        method = _tag_values(match.group(), "auth-method")
        out.append((rel, line_of(match.start()), f"login-config auth-method {method[0] if method else '?'}"))
    for match in re.finditer(r"<filter-mapping\b[\s\S]*?</filter-mapping>", text):
        block = match.group()
        names = _tag_values(block, "filter-name")
        if names and _SECURITY_FILTER_RE.search(names[0]):
            targets = _tag_values(block, "url-pattern") + _tag_values(block, "servlet-name")
            out.append((rel, line_of(match.start()), f"filter {names[0]} on {', '.join(targets) or '?'}"))
    return out


def _route_guard_entries(rel: str, text: str) -> List[Tuple[str, int, str]]:
    lines = text.splitlines()
    out: List[Tuple[str, int, str]] = []
    for n, line in enumerate(lines, start=1):
        if not _code_line(line) or not _GUARD_RE.search(line):
            continue
        path = _ROUTE_PATH_RE.search(line)
        for back in range(n - 1, max(0, n - 7), -1):
            if path is not None:
                break
            path = _ROUTE_PATH_RE.search(lines[back - 1])
        route = f"route '{path.group(2)}': " if path is not None else ""
        out.append((rel, n, route + " ".join(line.split())))
    return out


def security_entries(repo_root: Optional[Path]) -> List[Tuple[str, int, str]]:
    """(path, line, text) for every global security rule found in the
    repository, sorted by path and line. Test code is ignored."""
    if repo_root is None or not Path(repo_root).is_dir():
        return []
    repo_root = Path(repo_root)
    entries: List[Tuple[str, int, str]] = []
    java_seen = configs = 0
    for rel in _walk(repo_root):
        if configs >= _MAX_CONFIG_FILES:
            break
        name = rel.rsplit("/", 1)[-1]
        if name.endswith(".java"):
            java_seen += 1
            if java_seen > _MAX_JAVA_FILES and not _SECURITY_NAME_RE.search(name):
                continue
            head = _read(repo_root, rel, _JAVA_PEEK_CHARS)
            if head is None or not (_SECURITY_NAME_RE.search(name) or _SECURITY_CONTENT_RE.search(head)):
                continue
            text = _read(repo_root, rel) or ""
            found = _spring_entries(rel, text)
        elif name == "web.xml":
            found = _web_xml_entries(rel, _read(repo_root, rel) or "")
        elif _ROUTE_FILE_RE.search(name):
            found = _route_guard_entries(rel, _read(repo_root, rel) or "")
        else:
            continue
        if found:
            configs += 1
            entries.extend(found)
    return sorted(entries)


def render_security_summary(
    entries: Sequence[Tuple[str, int, str]], *, exclude_paths: Collection[str] = (),
    max_chars: int = SECURITY_SUMMARY_MAX_CHARS,
) -> str:
    """`path:line: rule` lines, leaving out the files a prompt already shows,
    within `max_chars`."""
    out: List[str] = []
    used = 0
    kept = [e for e in entries if e[0] not in exclude_paths]
    for index, (path, line, text) in enumerate(kept):
        row = f"{path}:{line}: {_cut(text, SECURITY_LINE_MAX_CHARS)}"
        if used + len(row) + 1 > max_chars:
            out.append(f"… ({len(kept) - index} more rule line(s) not shown)")
            break
        out.append(row)
        used += len(row) + 1
    return "\n".join(out)


# --- authentication lifecycle (token purpose, account state, workflow status) ---
#
# Three logic bugs live between files, not in one: a refresh token accepted as an
# access token (the issuer is in one class, the validating filter in another), a
# locked user who keeps access (the status flag is on the user entity, the check
# is missing in the filter), and an approved registration that can be re-opened
# (the status enum is in one file, the handler in another). The deep scan sees one
# file, so it is shown what the OTHER files declare. Context only: it never decides.

AUTH_SUMMARY_MAX_CHARS = 1_800
_AUTH_SUFFIXES = (".java", ".kt", ".ts", ".js", ".py")
_MAX_AUTH_FILES = 6
_MAX_AUTH_LINES_PER_FILE = 3

_TOKEN_ISSUE_RE = re.compile(
    r"\bJwts\s*\.\s*builder\b|\bJWT\s*\.\s*create\b|\bjwt\s*\.\s*(?:sign|encode)\s*\(|\bJwtEncoder\b"
    r"|\b(?:generate|create|issue|build|sign|mint)\w*Token\s*\(|\bdef\s+(?:create|issue|generate)_\w*token\b",
    re.I,
)
_TOKEN_TYPE_RE = re.compile(
    r"""["'](?:typ|type|token_type|tokenType|token_use|tokenUse|purpose)["']\s*[,:=)]|\.type\s*\(|\bsetHeaderParam\b""",
)
_TOKEN_ISSUE_ONLY_RE = re.compile(r"refresh|access|expir", re.I)
_STATE_WORD_RE = re.compile(
    r"\b(?:LOCKED|DISABLED|SUSPENDED|BLOCKED|DEACTIVATED|BANNED|APPROVED|REJECTED|DENIED|PENDING|CANCELLED|CLOSED)\b",
    re.I,
)
_ACCOUNT_STATE_RE = re.compile(
    r"\bisAccountNonLocked\b|\bisAccountNonExpired\b|\bisEnabled\s*\(|\baccountNonLocked\b"
    r"|\b(?:is_?locked|locked_?(?:at|until)|failed_?(?:login_?)?attempts|is_?active|account_?status)\b",
    re.I,
)
_TRANSITION_RE = re.compile(
    r"\bset(?:Status|State)\s*\(|\.(?:status|state)\s*=(?!=)|\b(?:update|change)(?:Status|State)\b"
    r"|\b(?:approve|reject|reopen|resubmit|cancel)\w*\s*\(",
    re.I,
)
_AUTH_FILE_RE = re.compile(
    r"refresh[_-]?token|\bparseClaimsJws\b|\bJwtDecoder\b|\bjwt\s*\.\s*(?:verify|decode)\b"
    r"|\bOncePerRequestFilter\b|\bloadUserByUsername\b|\bUserDetailsService\b|\bAuthenticationProvider\b",
    re.I,
)


def is_auth_lifecycle_file(rel_path: str, text: str) -> bool:
    """A file that validates or issues tokens, loads the user for authentication,
    or changes a workflow status — where one of the three cross-file checks
    (token purpose, account state, status transition) is decided."""
    if not rel_path.lower().endswith(_AUTH_SUFFIXES):
        return False
    head = text[:_JAVA_PEEK_CHARS]
    if _AUTH_FILE_RE.search(head):
        return True
    return len({m.upper() for m in _STATE_WORD_RE.findall(head)}) >= 2 and bool(_TRANSITION_RE.search(head))


def _lines_matching(text: str, patterns: Sequence["re.Pattern[str]"]) -> List[Tuple[int, str]]:
    out: List[Tuple[int, str]] = []
    for n, line in enumerate(text.splitlines(), start=1):
        if _code_line(line) and any(p.search(line) for p in patterns):
            out.append((n, " ".join(line.split())))
    return out


def auth_lifecycle_entries(repo_root: Optional[Path]) -> List[Tuple[str, str, int, str]]:
    """(kind, path, line, text) for token-issuing sites (`token`) and for account /
    workflow state declarations (`state`) across the repository, sorted. Test code
    is ignored; bounded in files and in lines per file."""
    if repo_root is None or not Path(repo_root).is_dir():
        return []
    repo_root = Path(repo_root)
    entries: List[Tuple[str, str, int, str]] = []
    token_files = state_files = seen = 0
    for rel in _walk(repo_root):
        if not rel.lower().endswith(_AUTH_SUFFIXES):
            continue
        seen += 1
        if seen > _MAX_JAVA_FILES or (token_files >= _MAX_AUTH_FILES and state_files >= _MAX_AUTH_FILES):
            break
        head = _read(repo_root, rel, _JAVA_PEEK_CHARS)
        if not head:
            continue
        if token_files < _MAX_AUTH_FILES and _TOKEN_ISSUE_RE.search(head):
            # The issuing lines, then the lines that say what kind of token it is.
            found = _lines_matching(head, [_TOKEN_ISSUE_RE])[:2] + _lines_matching(head, [_TOKEN_TYPE_RE])[:2]
            if found:
                token_files += 1
                for n, text in sorted(set(found)):
                    entries.append(("token", rel, n, text))
        distinct_states = {m.upper() for m in _STATE_WORD_RE.findall(head)}
        if state_files < _MAX_AUTH_FILES and (len(distinct_states) >= 2 or _ACCOUNT_STATE_RE.search(head)):
            patterns = [_ACCOUNT_STATE_RE]
            if len(distinct_states) >= 2:
                patterns.append(_STATE_WORD_RE)
            found = _lines_matching(head, patterns)[:_MAX_AUTH_LINES_PER_FILE]
            if found:
                state_files += 1
                for n, text in found:
                    entries.append(("state", rel, n, text))
    return sorted(entries)


def render_auth_lifecycle_summary(
    entries: Sequence[Tuple[str, str, int, str]], *, exclude_paths: Collection[str] = (),
    max_chars: int = AUTH_SUMMARY_MAX_CHARS,
) -> str:
    """Two short lists — where tokens are issued (and whether a type claim is set),
    and which account/workflow states exist — leaving out the files a prompt
    already shows, within `max_chars`."""
    titles = {
        "token": "Token issuance in other files (a line naming a type/purpose claim means one is set):",
        "state": "Account and workflow states declared in other files:",
    }
    out: List[str] = []
    used = 0
    for kind in ("token", "state"):
        rows = [e for e in entries if e[0] == kind and e[1] not in exclude_paths]
        if not rows:
            continue
        out.append(titles[kind])
        used += len(titles[kind]) + 1
        for index, (_k, path, line, text) in enumerate(rows):
            row = f"{path}:{line}: {_cut(text, SECURITY_LINE_MAX_CHARS)}"
            if used + len(row) + 1 > max_chars:
                out.append(f"… ({len(rows) - index} more line(s) not shown)")
                break
            out.append(row)
            used += len(row) + 1
    return "\n".join(out)
