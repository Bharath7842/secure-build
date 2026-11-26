from __future__ import annotations
from typing import Any, Optional, Set, List, TYPE_CHECKING

if TYPE_CHECKING:
    from checkov.common.checks.base_check import BaseCheck


class RunnerFilter:
    __EXTERNAL_CHECK_IDS: Set[str] = set()

    def __init__(
        self,
        framework: Optional[List[str]] = None,
        skip_framework: Optional[List[str]] = None,
        checks: Optional[List[str]] = None,
        skip_checks: Optional[List[str]] = None,
        **kwargs: Any,
    ) -> None:
        self.checks = checks or []
        self.skip_checks = skip_checks or []
        self.framework = framework or []
        self.skip_framework = skip_framework or []

    @staticmethod
    def notify_external_check(check_id: str) -> None:
        RunnerFilter.__EXTERNAL_CHECK_IDS.add(check_id)

    def should_run_check(self, check: "BaseCheck", **kwargs: Any) -> bool:
        if self.checks and check.id not in self.checks:
            return False
        if check.id in self.skip_checks:
            return False
        return True
