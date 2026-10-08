"""One-time TLS/SSL posture check at the target's own host (DAST-05-030 follow-up).

Not sent through the guarded executor: it is a raw TLS handshake, not an HTTP request, and
`guarded_executor`'s httpx client does not expose protocol/cipher/certificate details. This is
still safe within the existing scope model because it only ever connects to the exact host the
operator supplied as the scan's target (`state["url"]`, never a response-derived or redirected
address), makes at most two connections total, and reads connection metadata only - no path is
requested, nothing is sent that the target did not already receive as part of the TLS handshake
every HTTPS client performs.

Findings never gate the scan; a probe failure (any `OSError`/`ssl.SSLError` not specifically a
certificate-verification failure) is logged and produces no finding - a firewall dropping a
second connection says nothing about the certificate itself.
"""

from __future__ import annotations

import socket
import ssl
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Sequence
from urllib.parse import urlsplit

from .domain.catalog import standards_for
from .domain.entities import Confidence, DetectorSignal, Evidence, Finding, FindingVerdict, Location, Severity
from .domain.mapping import finding_to_row
from .domain.tls import evaluate_tls
from .domain.redaction import redact_text

SOURCE = "tls probe"
PROBE_TIMEOUT_S = 5.0
_TLS_TITLES = {
    "tls_cert_expired": "Expired TLS certificate",
    "tls_cert_expiring_soon": "TLS certificate expiring soon",
    "tls_weak_protocol": "Deprecated TLS protocol version",
    "tls_weak_cipher": "Weak TLS cipher suite",
    "tls_cert_self_signed": "Self-signed TLS certificate",
    "tls_hostname_mismatch": "TLS certificate hostname mismatch",
    "tls_cert_not_trusted": "TLS certificate not trusted",
}
_CHECK_ID_FOR_SIGNAL = {
    "tls_cert_expired": "dast-tls-expired",
    "tls_cert_expiring_soon": "dast-tls-expiring-soon",
    "tls_weak_protocol": "dast-tls-weak-protocol",
    "tls_weak_cipher": "dast-tls-weak-cipher",
    "tls_cert_self_signed": "dast-tls-self-signed",
    "tls_hostname_mismatch": "dast-tls-hostname-mismatch",
    "tls_cert_not_trusted": "dast-tls-not-trusted",
}


@dataclass(frozen=True)
class TlsProbeOutcome:
    ran: bool  # False when the target is not https:// at all - nothing to probe
    host: str = ""
    port: int = 443
    protocol: str | None = None
    cipher: str | None = None
    not_after: str | None = None  # ISO date, for the discovery summary
    verify_error: str | None = None
    probe_error: str | None = None  # the connection itself failed; no judgment possible
    findings: tuple = ()  # domain.tls.TlsFinding


def _connect_and_inspect(host: str, port: int, timeout: float) -> tuple[str | None, str | None, Any, str | None, str | None]:
    """`(protocol, cipher, not_after_cert_field, verify_error, probe_error)`. Two connections at
    most: the normal, verifying one, and - only if that one failed on certificate trust - a second,
    non-verifying one purely to read the protocol/cipher a trust failure would otherwise hide."""
    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls_sock:
                cert = tls_sock.getpeercert()
                cipher_name, protocol, _bits = tls_sock.cipher() or (None, None, None)
                not_after = cert.get("notAfter") if cert else None
                return protocol or tls_sock.version(), cipher_name, not_after, None, None
    except ssl.SSLCertVerificationError as exc:
        # The verifying connection above already failed and already told us why
        # (`exc.verify_message`, captured below) - that is the finding. This second connection
        # trusts nothing and sends nothing beyond the TLS handshake every client performs; its
        # only purpose is to read the protocol/cipher metadata a verification failure withholds,
        # so the *same* finding can report what was negotiated, not to treat the target as
        # trusted or to exchange any further data with it.
        protocol = cipher_name = None
        try:
            insecure = ssl._create_unverified_context()  # noqa: SLF001 - the stdlib's own documented escape hatch, used read-only
            with socket.create_connection((host, port), timeout=timeout) as sock2:
                with insecure.wrap_socket(sock2, server_hostname=host) as tls_sock2:
                    cipher_name, protocol, _ = tls_sock2.cipher() or (None, None, None)
                    protocol = protocol or tls_sock2.version()
        except Exception:  # noqa: BLE001 - the verifying attempt already told us what matters
            pass
        return protocol, cipher_name, None, (getattr(exc, "verify_message", "") or str(exc)), None
    except Exception as exc:  # noqa: BLE001 - DNS, refused, timeout, non-cert SSL errors: no judgment to make
        return None, None, None, None, str(exc)


def run_tls_probe(target_url: str, *, timeout: float = PROBE_TIMEOUT_S, now: datetime | None = None) -> TlsProbeOutcome:
    parts = urlsplit(target_url)
    if parts.scheme != "https":
        return TlsProbeOutcome(ran=False)
    host = parts.hostname or ""
    port = parts.port or 443
    if not host:
        return TlsProbeOutcome(ran=False)
    protocol, cipher, not_after_raw, verify_error, probe_error = _connect_and_inspect(host, port, timeout)
    if probe_error:
        return TlsProbeOutcome(ran=True, host=host, port=port, probe_error=probe_error)
    not_after = None
    if not_after_raw:
        try:
            not_after = datetime.fromtimestamp(ssl.cert_time_to_seconds(not_after_raw), tz=timezone.utc)
        except (ValueError, OverflowError):
            not_after = None
    findings = evaluate_tls(protocol=protocol, cipher=cipher, not_after=not_after, verify_error=verify_error, now=now or datetime.now(timezone.utc))
    return TlsProbeOutcome(
        ran=True, host=host, port=port, protocol=protocol, cipher=cipher,
        not_after=not_after.date().isoformat() if not_after else None, verify_error=verify_error, findings=findings,
    )


TLS_CHECK_IDS = frozenset(_CHECK_ID_FOR_SIGNAL.values())


def tls_checks(rule_set: Any, skipped: Sequence[Any] = ()) -> dict[str, Any]:
    """The TLS checks this probe may produce findings for: enabled by the effective rule set,
    not skipped for a missing dependency. Mirrors `authorization.authz_checks`."""
    if rule_set is None:
        return {}
    skipped_ids = {s.get("check_id") for s in skipped if s.get("status") == "skipped"}
    return {ec.check_id: ec for ec in rule_set.enabled_checks() if ec.check_id in TLS_CHECK_IDS and ec.check_id not in skipped_ids}


def finding_rows(outcome: TlsProbeOutcome, checks: Any, secrets: Sequence[str] = ()) -> list[dict[str, Any]]:
    """Finding rows for `outcome`'s findings, for whichever of them the effective rule set has
    enabled. `checks` is the usual `{check_id: EffectiveCheck}` mapping."""
    rows: list[dict[str, Any]] = []
    for item in outcome.findings:
        check_id = _CHECK_ID_FOR_SIGNAL.get(item.signal)
        ec = checks.get(check_id) if check_id else None
        if ec is None:
            continue
        check = ec.check
        title = _TLS_TITLES.get(item.signal, check.title)
        detail = redact_text(item.detail, secrets)
        finding = Finding(
            check_id=check.check_id, severity=Severity(ec.severity.value), confidence=Confidence.HIGH,
            verdict=FindingVerdict.TRUE_POSITIVE, target=f"{outcome.host}:{outcome.port}", param=None, location=Location.RESPONSE,
            standards=tuple(standards_for(check)), remediation_ref=check.remediation_ref,
            evidence=Evidence("", detail, (DetectorSignal(item.signal, detail),), ""),
        )
        rows.append(
            finding_to_row(
                finding, title=f"{title}: {outcome.host}", source=SOURCE, sink=f"{outcome.host}:{outcome.port}",
                verdict_reason=detail[0].upper() + detail[1:] + ".",
                snippet=f"Check: {title}\nHost: {outcome.host}:{outcome.port}\nProtocol: {outcome.protocol or 'unknown'}\nCipher: {outcome.cipher or 'unknown'}\nDetail: {detail}",
            )
        )
    return rows
