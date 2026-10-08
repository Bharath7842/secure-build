"""OPTIONS method probe, WAF/CDN fingerprint, and the opt-in framing probe.

Runs once, after a successful preflight, on the scan's own target URL. None of
these change `connection_ok`.
"""

from __future__ import annotations

from urllib.parse import urlsplit

from .domain.entities import Location
from .domain.framing import conflicting_request, framing_accepted, status_from_response
from .domain.recon import dangerous_methods, detect_waf
from .framing_probe import probe_framing
from .stage_findings import enabled_checks, one_row, publish

METHOD_CHECK = "dast-misconfig"
WAF_CHECK = "dast-waf"
FRAMING_CHECK = "dast-request-smuggling"
_CHECKS = (METHOD_CHECK, WAF_CHECK, FRAMING_CHECK)


def _header(headers, name: str) -> str:
    for key, value in (headers or {}).items():
        if str(key).lower() == name:
            return str(value)
    return ""


def run_connection_recon(state, runtime, url: str, response) -> None:
    """Classify the root response and send one OPTIONS request through the guarded executor."""
    checks = enabled_checks(getattr(runtime, "rule_set", None), _CHECKS, getattr(runtime, "skipped_degraded", ()) or ())
    if not checks:
        return
    secrets = []
    credentials = getattr(runtime, "credentials", None)
    if credentials is not None and hasattr(credentials, "secrets"):
        try:
            secrets = list(credentials.secrets())
        except Exception:  # noqa: BLE001
            secrets = []
    rows: list[dict] = []
    headers = dict(getattr(response, "headers", None) or {})
    body = getattr(response, "body_excerpt", "") or ""

    if WAF_CHECK in checks:
        for match in detect_waf(headers, body):
            rows.append(
                one_row(
                    checks[WAF_CHECK],
                    signal="waf_detected",
                    detail=f"{match.vendor} ({match.evidence})",
                    target=url,
                    title=f"WAF or CDN detected: {match.vendor}",
                    source="connection recon",
                    sink=url,
                    secrets=secrets,
                )
            )
        if any(r for r in rows):
            names = ", ".join(m.vendor for m in detect_waf(headers, body))
            print(f"    WAF/CDN: {names}.")

    if METHOD_CHECK in checks:
        store = state.get("sessions")
        allow = ""
        if store is not None and getattr(runtime, "executor", None) is not None:
            from .sessions import anonymous_id

            try:
                decision = store.send(runtime.executor, anonymous_id(store), "OPTIONS", url, check_id=METHOD_CHECK)
                opt = decision.response
                if opt is not None:
                    allow = _header(opt.headers, "allow")
            except Exception as exc:  # noqa: BLE001
                print(f"    OPTIONS probe skipped: {exc}")
        methods = dangerous_methods(allow)
        if methods:
            detail = f"Allow advertises {', '.join(methods)}"
            print(f"    Dangerous methods: {detail}.")
            rows.append(
                one_row(
                    checks[METHOD_CHECK],
                    signal="dangerous_method_accepted",
                    detail=detail,
                    target=url,
                    title=f"Dangerous HTTP methods accepted: {', '.join(methods)}",
                    source="connection recon",
                    sink=url,
                    secrets=secrets,
                    param="Allow",
                    location=Location.HEADER,
                )
            )
        elif allow:
            print(f"    OPTIONS Allow: {allow}. No dangerous methods.")

    if FRAMING_CHECK in checks:
        parts = urlsplit(url)
        host = parts.hostname or ""
        if host and parts.scheme == "https" or host and parts.scheme == "http":
            port = parts.port or (443 if parts.scheme == "https" else 80)
            try:
                raw = probe_framing(host, port, conflicting_request(host, parts.path or "/"), tls=parts.scheme == "https")
            except Exception as exc:  # noqa: BLE001
                print(f"    Framing probe skipped: {exc}")
                raw = b""
            status = status_from_response(raw)
            if framing_accepted(status):
                detail = f"a request with both Content-Length and Transfer-Encoding was accepted (HTTP {status})"
                print(f"    Framing: {detail}.")
                rows.append(
                    one_row(
                        checks[FRAMING_CHECK],
                        signal="ambiguous_request_framing",
                        detail=detail,
                        target=url,
                        title=f"Ambiguous request framing accepted: {host}",
                        source="connection recon",
                        sink=url,
                        secrets=secrets,
                        location=Location.HEADER,
                    )
                )
    state["recon"] = {
        "waf": [m.vendor for m in detect_waf(headers, body)],
        "allow": _header(headers, "allow"),
    }
    publish(state, runtime, "connection recon", rows)
