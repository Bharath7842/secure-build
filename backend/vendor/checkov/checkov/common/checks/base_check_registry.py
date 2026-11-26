from __future__ import annotations

import logging
from abc import abstractmethod
from collections import defaultdict
from typing import Dict, List, Optional, Any, Tuple, TYPE_CHECKING

from checkov.common.resource_code_logger_filter import add_resource_code_filter_to_logger
from checkov.common.models.enums import CheckResult

if TYPE_CHECKING:
    from checkov.common.checks.base_check import BaseCheck


class BaseCheckRegistry:
    __loading_external_checks = False
    __all_registered_checks: list = []

    def __init__(self, report_type: str) -> None:
        self.logger = logging.getLogger(__name__)
        add_resource_code_filter_to_logger(self.logger)
        self.checks: Dict[str, List] = defaultdict(list)
        self.wildcard_checks: Dict[str, List] = defaultdict(list)
        self.check_id_allowlist: Optional[List[str]] = None
        self.report_type = report_type
        self.definitions_raw = None
        self.graph = None

    def register(self, check) -> None:
        for entity in check.supported_entities:
            if "*" in entity or "?" in entity:
                if not any(c.id == check.id for c in self.wildcard_checks[entity]):
                    self.wildcard_checks[entity].append(check)
            else:
                if not any(c.id == check.id for c in self.checks[entity]):
                    self.checks[entity].append(check)
        BaseCheckRegistry.__all_registered_checks.append(check)

    @staticmethod
    def get_all_registered_checks():
        return BaseCheckRegistry.__all_registered_checks

    def get_checks(self, entity: str) -> list:
        import fnmatch
        if not self.wildcard_checks:
            return self.checks.get(entity) or []
        res = list(self.checks.get(entity, []))
        for pattern, checks in self.wildcard_checks.items():
            if entity and fnmatch.fnmatchcase(entity, pattern):
                res += checks
        return res

    @abstractmethod
    def extract_entity_details(self, entity: Dict[str, Any]) -> Tuple[str, str, Dict[str, Any]]:
        raise NotImplementedError()

    @staticmethod
    def _directory_has_init_py(directory: str) -> bool:
        import os
        return os.path.exists(os.path.join(directory, "__init__.py"))

    @staticmethod
    def _file_can_be_imported(entry) -> bool:
        return entry.is_file() and not entry.name.startswith("__") and entry.name.endswith(".py")
