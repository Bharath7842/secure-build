"""URL normalization/dedup utilities shared by the crawl node."""

from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

import tldextract

NOISE_QUERY_KEYS_DEFAULT = "utm_source,utm_medium,utm_campaign,session,token"


def _filter_query(query: str, noise_params: list) -> list:
    return sorted((k, v) for k, v in parse_qsl(query, keep_blank_values=True) if k not in noise_params)


def normalize_url(url: str, noise_params: list) -> str:
    """Normalize a URL for dedup purposes.

    1. Lowercase scheme and host only.
    2. Strip default ports.
    3. Preserve the fragment - many SPAs hash-route (e.g. "#/dashboard"), so
       dropping it would collapse distinct pages into one. If the fragment
       itself carries a query string (e.g. "#/page?foo=bar"), noise params are
       filtered from that too; a plain in-page anchor fragment just passes through.
    4. Strip a single trailing slash unless path is "/".
    5. Drop noise query params from the real query string, sort the rest
       alphabetically, re-serialize.
    """
    parsed = urlparse(url)
    scheme = parsed.scheme.lower()
    netloc = parsed.netloc.lower()
    if (scheme == "http" and netloc.endswith(":80")) or (scheme == "https" and netloc.endswith(":443")):
        netloc = netloc.rsplit(":", 1)[0]

    path = parsed.path
    if path != "/" and path.endswith("/"):
        path = path[:-1]

    query = urlencode(_filter_query(parsed.query, noise_params))

    fragment = parsed.fragment
    if "?" in fragment:
        frag_path, frag_query = fragment.split("?", 1)
        frag_pairs = _filter_query(frag_query, noise_params)
        fragment = frag_path + (("?" + urlencode(frag_pairs)) if frag_pairs else "")

    return urlunparse((scheme, netloc, path, "", query, fragment))


def get_url_pattern(normalized_url: str) -> str:
    """Derive a dedup pattern from a normalized URL: path (+ hash route) with query values blanked."""
    parsed = urlparse(normalized_url)
    query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
    pattern = parsed.path
    if query_pairs:
        pattern += "?" + "&".join(f"{k}={{}}" for k, _ in query_pairs)

    if parsed.fragment:
        fragment = parsed.fragment
        if "?" in fragment:
            frag_path, frag_query = fragment.split("?", 1)
            frag_pairs = parse_qsl(frag_query, keep_blank_values=True)
            fragment = frag_path + (("?" + "&".join(f"{k}={{}}" for k, _ in frag_pairs)) if frag_pairs else "")
        pattern += "#" + fragment

    return pattern


def is_same_domain(url: str, base_url: str, mode: str) -> bool:
    try:
        host = (urlparse(url).hostname or "").lower()
        base_host = (urlparse(base_url).hostname or "").lower()
    except Exception:  # noqa: BLE001
        return False
    if not host or not base_host:
        return False
    if mode == "exact":
        return host == base_host

    # root-domain: public-suffix-aware comparison via tldextract, so e.g.
    # "app.company.co.in" and "portal.company.co.in" both map to "company.co.in"
    # without misreading the last two labels of a multi-part suffix as the domain.
    target = tldextract.extract(host)
    base = tldextract.extract(base_host)
    target_root = f"{target.domain}.{target.suffix}" if target.suffix else target.domain
    base_root = f"{base.domain}.{base.suffix}" if base.suffix else base.domain
    return target_root == base_root
