"""Save a JPEG of the current page into the scan's screenshot directory.

Filenames are either `login.jpg` (the login page at classification time) or
`N.jpg` (the Nth crawled page). The HTTP route only serves those two shapes.
"""

from __future__ import annotations

from pathlib import Path

from app.config import settings


def save_page_screenshot(state: dict, page: object, filename: str, *, log: bool = True) -> str | None:
    """Write `filename` under the scan's screenshot dir. Never raises; returns None on failure."""
    try:
        scan_id = getattr(state.get("runtime"), "scan_id", "") or ""
        if not scan_id or page is None:
            return None
        path = Path(settings.dast_screenshots_dir) / scan_id / filename
        path.parent.mkdir(parents=True, exist_ok=True)
        page.screenshot(path=str(path), type="jpeg", quality=60)  # type: ignore[union-attr]
        if log:
            print(f"    [screenshot: {filename}]")
        return filename
    except Exception:  # noqa: BLE001 - a screenshot must never fail the scan
        return None
