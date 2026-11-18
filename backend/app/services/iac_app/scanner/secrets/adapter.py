"""Secret scanner exposed as a ScannerAdapter, peer to KICS and Trivy."""

from __future__ import annotations

from typing import Any

from app.services.iac_app.scanner.engines.base import ScannerAdapter
from app.services.iac_app.scanner.secrets.scanner import SecretScanner

SECRET_SCANNER_VERSION = "1.0.0"


class SecretScannerAdapter(ScannerAdapter):
    def __init__(self) -> None:
        self._scanner = SecretScanner()

    def get_name(self) -> str:
        return "secrets"

    def is_available(self) -> bool:
        return True

    def get_version(self) -> str:
        return f"secret-scanner-{SECRET_SCANNER_VERSION}"

    def scan(self, target_path: str, options: dict[str, Any]) -> list[dict]:
        del options
        return self._scanner.scan_path(target_path)
