#!/usr/bin/env python3
"""Re-score stored SAST findings with the standard (CVSS v3.1) severity.

    python scripts/rescore_severity.py --dry-run          # what would change
    python scripts/rescore_severity.py                    # every SAST scan
    python scripts/rescore_severity.py --scan <scan id>   # one scan

New findings are scored when they are written (`app/services/severity.py`).
This brings findings written before that, or under an older
`app/defaults/cwe_cvss.SCHEME`, onto the same scale. The rule's or model's
severity is kept as `severity_basis.original_severity` and every run starts
from it, so running it again changes nothing. DAST and SCA findings are left
alone. Uses the database the backend is configured with (`DATABASE_URL`).
"""

from __future__ import annotations

import argparse
import sys
from collections import Counter
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
BACKEND = REPO / "backend"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--scan", help="re-score only this scan")
    parser.add_argument("--dry-run", action="store_true", help="report the changes without saving them")
    args = parser.parse_args(argv)

    if str(BACKEND) not in sys.path:
        sys.path.insert(0, str(BACKEND))
    from sqlalchemy import func

    from app import db as db_module
    from app.config import settings
    from app.db import init_db
    from app.defaults.cwe_cvss import SCHEME
    from app.models import Finding, Scan
    from app.services.severity import apply_severity

    init_db(settings.database_url)
    transitions: Counter[tuple[str, str]] = Counter()
    seen = changed = 0
    with db_module.SessionLocal() as db:
        query = (
            db.query(Finding)
            .join(Scan, Scan.id == Finding.scan_id)
            .filter(func.coalesce(Scan.scan_type, "sast") == "sast")
            .order_by(Finding.id)
        )
        if args.scan:
            if db.get(Scan, args.scan) is None:
                print(f"No scan {args.scan}.", file=sys.stderr)
                return 2
            query = query.filter(Finding.scan_id == args.scan)
        for row in query.all():
            seen += 1
            before = row.severity
            if apply_severity(row):
                changed += 1
                if row.severity != before:
                    transitions[(str(before), row.severity)] += 1
        if args.dry_run:
            db.rollback()
        else:
            db.commit()

    verb = "Would change" if args.dry_run else "Changed"
    print(f"Scheme {SCHEME}: {seen} SAST finding(s) checked. {verb} {changed}.")
    for (before, after), count in sorted(transitions.items(), key=lambda kv: -kv[1]):
        print(f"  {before} -> {after}: {count}")
    if changed > sum(transitions.values()):
        print(f"  {changed - sum(transitions.values())} gained a CVSS score or basis without a severity change.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
