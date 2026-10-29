"""endpoint_policy.py — where a scan may send repository code (LLM03).

An LLM endpoint receives source code and, for some providers, an API key. A free
text URL is therefore an SSRF and data-exfiltration surface, so every endpoint is
checked by this one stdlib-only module — by the app when a project or scan is
configured, and again by the engine right before each request (the address is
resolved again there, which narrows DNS rebinding).

Rules, in order:

* the scheme is ``http`` or ``https`` and the URL carries no ``user:pass@``;
* link-local addresses (``169.254.0.0/16`` incl. the cloud metadata address,
  ``fe80::/10``) and the well-known metadata host names are never allowed, not
  even for an approved host; neither are unspecified/multicast/reserved ranges;
* a private-range address (RFC 1918, CGNAT, unique-local) is allowed only for a
  host an administrator approved (``allowed_hosts``);
* a loopback address (``localhost``, ``127.0.0.0/8``, ``::1``) is allowed unless
  ``allow_loopback`` is off — a local Ollama or vLLM is the normal case;
* plain ``http`` is accepted for loopback and for an approved host only; every
  other host needs ``https``.

An approved host matches ``host`` or ``host:port`` exactly (case-insensitive).
A host name that does not resolve is not an error here — nothing can be said about
an address it does not have, and the request itself fails — but the scheme and
credential rules still apply.
"""

from __future__ import annotations

import ipaddress
import socket
from typing import Callable, Iterable, List, Optional
from urllib.parse import urlsplit

METADATA_HOSTS = frozenset({
    "metadata", "metadata.google.internal", "metadata.goog", "instance-data",
    "169.254.169.254", "100.100.100.200", "fd00:ec2::254",
})
_CGNAT = ipaddress.ip_network("100.64.0.0/10")


def _addresses(host: str, resolve: Callable[..., list]) -> List["ipaddress._BaseAddress"]:
    try:
        return [ipaddress.ip_address(host)]
    except ValueError:
        pass
    try:
        infos = resolve(host, None)
    except (OSError, UnicodeError):
        return []
    found = []
    for info in infos:
        try:
            found.append(ipaddress.ip_address(info[4][0].split("%")[0]))
        except (ValueError, IndexError):
            continue
    return found


def _unmap(ip: "ipaddress._BaseAddress") -> "ipaddress._BaseAddress":
    mapped = getattr(ip, "ipv4_mapped", None)
    return mapped if mapped is not None else ip


def check_endpoint(
    url: str,
    *,
    allowed_hosts: Iterable[str] = (),
    allow_loopback: bool = True,
    resolve: Callable[..., list] = socket.getaddrinfo,
) -> Optional[str]:
    """None when `url` may receive code, otherwise why not (one short sentence)."""
    try:
        parts = urlsplit((url or "").strip())
        host = (parts.hostname or "").lower().rstrip(".")
        port = parts.port
    except ValueError:
        return "the endpoint is not a valid URL"
    if parts.scheme not in ("http", "https"):
        return "the endpoint must be an http(s) URL"
    if not host:
        return "the endpoint has no host"
    if parts.username is not None or parts.password is not None:
        return "the endpoint must not contain credentials (user:password@)"
    if host in METADATA_HOSTS:
        return f"{host} is a cloud metadata address and can never be an LLM endpoint"

    approved_set = {str(h).strip().lower() for h in allowed_hosts if str(h).strip()}
    approved = host in approved_set or (port is not None and f"{host}:{port}" in approved_set)

    addresses = [_unmap(ip) for ip in _addresses(host, resolve)]
    for ip in addresses:
        if ip.is_link_local or str(ip) in METADATA_HOSTS:
            return f"{host} resolves to a link-local/metadata address ({ip}) and is never allowed"
        # `::1` is inside Python's "reserved" ::/8, so loopback is exempted from that test.
        if ip.is_unspecified or ip.is_multicast or (ip.is_reserved and not ip.is_loopback):
            return f"{host} resolves to a non-routable address ({ip})"

    loopback = host == "localhost" or bool(addresses) and all(ip.is_loopback for ip in addresses)
    if loopback:
        if not allow_loopback and not approved:
            return "loopback endpoints are not allowed on this server"
    elif not approved:
        for ip in addresses:
            if ip.is_private or ip in _CGNAT:
                return (
                    f"{host} resolves to a private address ({ip}); ask an administrator "
                    "to approve this host"
                )

    if parts.scheme == "http" and not (loopback or approved):
        return "the endpoint must use https"
    return None
