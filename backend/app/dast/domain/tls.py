"""TLS/SSL posture classification: pure judgment over facts a TLS handshake already produced.

No sockets, no I/O, no clock reads - `now` is always supplied by the caller (`tls_probe.py`,
which does the actual connection), the same separation `preflight.py` keeps between the request
and its classification.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

# TLS 1.2 is the oldest protocol version still broadly considered acceptable; everything older
# (SSLv2/3, TLS 1.0/1.1) is deprecated by every major browser and PCI-DSS 4.0.
WEAK_PROTOCOLS = frozenset({"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"})

# Cipher-suite name fragments identifying a known-weak algorithm. OpenSSL's cipher names carry
# the algorithm in the name itself (e.g. "ECDHE-RSA-AES128-GCM-SHA256" vs "EXP-RC4-MD5").
WEAK_CIPHER_MARKERS = ("RC4", "3DES", "DES-CBC", "EXPORT", "NULL", "_MD5", "-MD5")

EXPIRY_WARNING_DAYS = 30

TLS_EXPIRED = "tls_cert_expired"
TLS_EXPIRING_SOON = "tls_cert_expiring_soon"
TLS_WEAK_PROTOCOL = "tls_weak_protocol"
TLS_WEAK_CIPHER = "tls_weak_cipher"
TLS_SELF_SIGNED = "tls_cert_self_signed"
TLS_HOSTNAME_MISMATCH = "tls_hostname_mismatch"
TLS_NOT_TRUSTED = "tls_cert_not_trusted"

TLS_SIGNAL_NAMES = frozenset(
    {TLS_EXPIRED, TLS_EXPIRING_SOON, TLS_WEAK_PROTOCOL, TLS_WEAK_CIPHER, TLS_SELF_SIGNED, TLS_HOSTNAME_MISMATCH, TLS_NOT_TRUSTED}
)


@dataclass(frozen=True)
class TlsFinding:
    signal: str  # one of TLS_SIGNAL_NAMES
    detail: str


def _trust_error_signal(verify_error: str) -> tuple[str, str] | None:
    """Classify an OpenSSL verification-failure message (`SSLCertVerificationError.verify_message`,
    or the exception text as a fallback) into a specific signal, or a generic one when the
    message does not match a known shape."""
    text = verify_error.lower()
    if "expired" in text:
        return TLS_EXPIRED, "the certificate has expired"
    if "self-signed" in text or "self signed" in text:
        return TLS_SELF_SIGNED, "the certificate is self-signed"
    if "hostname mismatch" in text or "doesn't match" in text or "does not match" in text:
        return TLS_HOSTNAME_MISMATCH, f"the certificate does not match the host: {verify_error}"
    return TLS_NOT_TRUSTED, f"the certificate is not trusted by a standard trust store: {verify_error}"


def evaluate_tls(
    *,
    protocol: str | None,
    cipher: str | None,
    not_after: datetime | None,
    verify_error: str | None,
    now: datetime,
) -> tuple[TlsFinding, ...]:
    """Every TLS posture issue the supplied facts show. `not_after` is only meaningful when the
    certificate was otherwise trusted (an untrusted/expired cert surfaces through `verify_error`
    instead, since OpenSSL's own chain validation already rejects an expired certificate)."""
    findings: list[TlsFinding] = []
    if verify_error:
        signal, detail = _trust_error_signal(verify_error)
        findings.append(TlsFinding(signal, detail))
    elif not_after is not None:
        days_left = (not_after - now).days
        if days_left <= EXPIRY_WARNING_DAYS:
            findings.append(TlsFinding(TLS_EXPIRING_SOON, f"the certificate expires in {days_left} day(s) ({not_after.date()})"))
    if protocol and protocol in WEAK_PROTOCOLS:
        findings.append(TlsFinding(TLS_WEAK_PROTOCOL, f"the connection negotiated {protocol}, a deprecated TLS version"))
    if cipher and any(marker in cipher.upper() for marker in WEAK_CIPHER_MARKERS):
        findings.append(TlsFinding(TLS_WEAK_CIPHER, f"the connection negotiated a weak cipher suite ({cipher})"))
    return tuple(findings)
