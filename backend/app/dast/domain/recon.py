"""Connection-time reconnaissance: dangerous methods, WAF/CDN fingerprints, hidden paths.

Pure. The preflight stage supplies the OPTIONS `Allow` header, the root response, and
later GET bodies. This module only classifies them.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# Advertised on the scan's own root URL. TRACE and CONNECT are never needed by a
# browser; PUT and DELETE on the document root are the same class of leftover.
DANGEROUS_METHODS = frozenset({"TRACE", "PUT", "DELETE", "CONNECT"})

# (vendor, header name or "body", substring or "" when the header's presence is enough).
WAF_SIGNATURES: tuple[tuple[str, str, str], ...] = (
    ("Cloudflare", "cf-ray", ""),
    ("Cloudflare", "cf-mitigated", ""),
    ("Cloudflare", "server", "cloudflare"),
    ("Cloudflare", "body", "attention required! | cloudflare"),
    ("Akamai", "x-akamai-transformed", ""),
    ("Akamai", "server", "akamaighost"),
    ("Akamai", "server", "akamai"),
    ("Amazon CloudFront", "x-amz-cf-id", ""),
    ("Amazon CloudFront", "x-amz-cf-pop", ""),
    ("Amazon CloudFront", "via", "cloudfront"),
    ("Fastly", "x-fastly-request-id", ""),
    ("Fastly", "x-served-by", "cache-"),
    ("Imperva", "x-iinfo", ""),
    ("Imperva", "x-cdn", "imperva"),
    ("Sucuri", "x-sucuri-id", ""),
    ("Sucuri", "server", "sucuri"),
    ("Sucuri", "body", "sucuri website firewall"),
    ("F5 BIG-IP", "server", "big-ip"),
    ("ModSecurity", "server", "mod_security"),
    ("ModSecurity", "body", "modsecurity"),
    ("Vercel", "server", "vercel"),
    ("Netlify", "server", "netlify"),
    ("Azure Front Door", "x-azure-ref", ""),
)

_TITLE = re.compile(r"<title>([^<]{1,160})</title>", re.IGNORECASE)
_LISTING = re.compile(r"index of /|directory listing for|<h1>index of", re.IGNORECASE)


@dataclass(frozen=True)
class WafMatch:
    vendor: str
    evidence: str


def dangerous_methods(allow_header: str) -> tuple[str, ...]:
    """Methods from an `Allow` header that a document root should not advertise."""
    found = []
    for part in (allow_header or "").split(","):
        method = part.strip().upper()
        if method in DANGEROUS_METHODS and method not in found:
            found.append(method)
    return tuple(found)


def _header(headers: dict | None, name: str) -> str:
    for key, value in (headers or {}).items():
        if str(key).lower() == name:
            return str(value)
    return ""


def detect_waf(headers: dict | None, body: str = "") -> tuple[WafMatch, ...]:
    """Vendors whose signature appears in the response headers or body. One match per vendor."""
    text = (body or "")[:8000].lower()
    seen: dict[str, WafMatch] = {}
    for vendor, where, needle in WAF_SIGNATURES:
        if vendor in seen:
            continue
        if where == "body":
            if needle and needle in text:
                seen[vendor] = WafMatch(vendor, f"response body contains {needle!r}")
            continue
        value = _header(headers, where)
        if not value:
            continue
        if not needle or needle in value.lower():
            shown = value if len(value) <= 80 else value[:77] + "..."
            seen[vendor] = WafMatch(vendor, f"{where}: {shown}")
    return tuple(seen.values())


def _title(html: str) -> str:
    match = _TITLE.search(html or "")
    return match.group(1).strip().lower() if match else ""


def looks_like_soft_404(body: str, root_body: str) -> bool:
    """The hidden-path response is the same document the root already returned (SPA shell, custom 404)."""
    body, root = body or "", root_body or ""
    if not root or not body:
        return False
    title, root_title = _title(body), _title(root)
    if title and title == root_title:
        return True
    floor = max(32, int(0.1 * len(root)))
    return abs(len(body) - len(root)) <= floor and body[:80] == root[:80]


def is_directory_listing(body: str) -> bool:
    return bool(_LISTING.search(body or ""))


def classify_hidden_response(status: int | None, body: str, root_body: str) -> str | None:
    """`listing` or `exposed` when a guessed path returned something of its own; None otherwise.

    A 401/403 is not proof the path exists (many servers deny every unknown URL the same way).
    A 200 that copies the root document is a soft 404."""
    if is_directory_listing(body):
        return "listing"
    if status != 200 or looks_like_soft_404(body, root_body):
        return None
    if len((body or "").strip()) < 16:
        return None
    return "exposed"
