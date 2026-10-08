"""Guess a small bundled list of sensitive paths. GETs only, through the guarded executor.

A 200 that is the same document as the site root is treated as a soft 404 and
dropped. The wordlist is a file (`app/data/dast/forced_browse.txt`), not a package.
"""

from __future__ import annotations

from pathlib import Path
from urllib.parse import urlsplit

from .domain.entities import Location
from .domain.recon import classify_hidden_response
from .stage_findings import enabled_checks, one_row, publish

WORDLIST = Path(__file__).resolve().parents[1] / "data" / "dast" / "forced_browse.txt"
EXPOSED = "dast-forced-browse"
LISTING = "dast-directory-listing"
_MAX_PATHS = 24


def load_paths(path: Path = WORDLIST) -> tuple[str, ...]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return ()
    out = []
    for line in lines:
        item = line.strip()
        if not item or item.startswith("#") or not item.startswith("/"):
            continue
        if item not in out:
            out.append(item)
        if len(out) >= _MAX_PATHS:
            break
    return tuple(out)


def run_forced_browse(state, runtime, root_url: str, root_body: str) -> None:
    checks = enabled_checks(
        getattr(runtime, "rule_set", None),
        (EXPOSED, LISTING),
        getattr(runtime, "skipped_degraded", ()) or (),
    )
    if not checks or getattr(runtime, "executor", None) is None:
        return
    store = state.get("sessions")
    if store is None:
        return
    from .sessions import anonymous_id

    identity = anonymous_id(store)
    parts = urlsplit(root_url)
    origin = f"{parts.scheme}://{parts.netloc}"
    rows = []
    for rel in load_paths():
        if getattr(runtime, "cancelled", lambda: False)():
            break
        url = origin + rel
        try:
            decision = store.send(runtime.executor, identity, "GET", url, check_id=EXPOSED)
        except Exception as exc:  # noqa: BLE001
            print(f"    Hidden-path probe skipped ({rel}): {exc}")
            return
        response = decision.response
        if response is None:
            continue
        kind = classify_hidden_response(response.status, response.body_excerpt or "", root_body)
        if kind == "listing" and LISTING in checks:
            rows.append(
                one_row(
                    checks[LISTING],
                    signal="directory_listed",
                    detail=f"{rel} returned a directory index",
                    target=url,
                    title=f"Directory listing: {rel}",
                    source="forced browse",
                    sink=url,
                    location=Location.RESPONSE,
                )
            )
        elif kind == "exposed" and EXPOSED in checks:
            rows.append(
                one_row(
                    checks[EXPOSED],
                    signal="hidden_path_exposed",
                    detail=f"{rel} returned HTTP {response.status} with its own body",
                    target=url,
                    title=f"Hidden path exposed: {rel}",
                    source="forced browse",
                    sink=url,
                    location=Location.PATH,
                )
            )
    if rows:
        print(f"    Hidden paths: {len(rows)} exposed.")
    publish(state, runtime, "forced browse", rows)
