from __future__ import annotations

import logging
import os
from abc import abstractmethod, ABC
from collections.abc import Iterable
from typing import List, Dict, Any, Optional

from checkov.common.resource_code_logger_filter import add_resource_code_filter_to_logger
from checkov.common.typing import _SkippedCheck, _CheckResult
from checkov.common.util.type_forcers import force_list
from checkov.common.models.enums import CheckResult, CheckCategories, CheckFailLevel


class BaseCheck(ABC):
    def __init__(
        self,
        name: str,
        id: str,
        categories: Iterable[CheckCategories],
        supported_entities: Iterable[str],
        block_type: str,
        bc_id: Optional[str] = None,
        guideline: Optional[str] = None,
    ) -> None:
        self.name = name
        self.id = id
        self.bc_id = bc_id
        self.categories = categories
        self.block_type = block_type
        self.path: str | None = None
        self.supported_entities = supported_entities
        self.logger = logging.getLogger("{}".format(self.__module__))
        add_resource_code_filter_to_logger(self.logger)
        self.evaluated_keys: List[str] = []
        self.entity_path = ""
        self.entity_type = ""
        self.guideline = guideline
        self.benchmarks: dict[str, list[str]] = {}
        self.severity = None
        self.bc_category = None
        self.graph = None
        self.details: List[str] = []
        self.check_fail_level = os.environ.get('CHECKOV_CHECK_FAIL_LEVEL', CheckFailLevel.ERROR)

    @abstractmethod
    def scan_entity_conf(self, conf: dict[str, Any], entity_type: str) -> CheckResult:
        raise NotImplementedError()

    def get_evaluated_keys(self) -> List[str]:
        return force_list(self.evaluated_keys)

    def get_output_id(self, use_bc_ids: bool) -> str:
        return self.bc_id if self.bc_id and use_bc_ids else self.id

    def log_check_error(self, scanned_file: str, entity_type: str, entity_name: str,
                        entity_configuration: Dict[str, Any]) -> None:
        logging.error(f'Failed to run check {self.id} on {scanned_file}:{entity_type}.{entity_name}', exc_info=True)
