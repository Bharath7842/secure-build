"""What produced a scan: the engine, rules, prompts and model (SAST-00-040).

`Scan.metadata_json["versions"]` records this block so two scans can be compared
knowing whether the scanner itself changed between them, and so every decision
row (SAST-00-050) can carry the evidence version it was made under.

    engine_commit          git SHA of the backend checkout, or "unknown"
    rule_catalog_sha256    hash of the loaded rule catalog files
    result_cache_version   llm_client.RESULT_CACHE_VERSION
    severity_scheme        app/defaults/cwe_cvss.SCHEME (how severity was scored)
    system_prompt_sha256   per LLM step, the sha256 of each system prompt used
                           (filled in from the usage summary once the run ends)
    llm_provider, llm_model  the snapshot taken on the scan row

The mock engine records fixed values, so tests can assert the whole block.
"""

from __future__ import annotations

import hashlib
import re
import subprocess
from functools import lru_cache
from pathlib import Path
from typing import Any

from app.config import settings
from app.defaults.cwe_cvss import SCHEME as SEVERITY_SCHEME
from app.models import Scan

VERSIONS_KEY = "versions"
MOCK_VALUE = "mock"
UNKNOWN = "unknown"

_BACKEND_DIR = Path(__file__).resolve().parents[2]
_CACHE_VERSION_RE = re.compile(r'^RESULT_CACHE_VERSION\s*=\s*"([^"]*)"', re.MULTILINE)


@lru_cache(maxsize=1)
def engine_commit() -> str:
    try:
        out = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=_BACKEND_DIR, capture_output=True, text=True, timeout=5, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return UNKNOWN
    sha = out.stdout.strip()
    return sha if out.returncode == 0 and re.fullmatch(r"[0-9a-f]{7,64}", sha) else UNKNOWN


def rule_catalog_sha256(rules_dir: Path | None = None) -> str:
    """Hash of every catalog file (name and bytes, in name order)."""
    root = rules_dir or Path(settings.sast_framework_path) / "rules"
    digest = hashlib.sha256()
    for path in sorted(root.glob("*.json")):
        digest.update(path.name.encode("utf-8"))
        digest.update(path.read_bytes())
    return digest.hexdigest()


def result_cache_version() -> str:
    """Read from the engine source: the app cannot import `sast_engine`."""
    try:
        text = (Path(settings.sast_framework_path) / "llm_client.py").read_text(encoding="utf-8")
    except OSError:
        return UNKNOWN
    match = _CACHE_VERSION_RE.search(text)
    return match.group(1) if match else UNKNOWN


def static_versions(scan: Scan, *, mock: bool) -> dict[str, Any]:
    """The block known before the engine runs."""
    versions: dict[str, Any] = {
        "engine_commit": MOCK_VALUE if mock else engine_commit(),
        "rule_catalog_sha256": MOCK_VALUE if mock else _safe(rule_catalog_sha256),
        "result_cache_version": MOCK_VALUE if mock else result_cache_version(),
        "severity_scheme": SEVERITY_SCHEME,
        "system_prompt_sha256": {},
        "llm_provider": scan.llm_provider,
        "llm_model": scan.llm_model,
    }
    return versions


def _safe(fn) -> str:
    try:
        return fn()
    except OSError:
        return UNKNOWN


def with_prompt_hashes(versions: dict[str, Any] | None, usage_summary: dict[str, Any] | None) -> dict[str, Any]:
    """`versions` completed with the system prompts the run actually used."""
    merged = dict(versions or {})
    merged["system_prompt_sha256"] = dict((usage_summary or {}).get("system_prompt_sha256") or {})
    return merged
