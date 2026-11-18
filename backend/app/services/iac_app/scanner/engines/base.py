from abc import ABC, abstractmethod
from typing import Any


class ScannerAdapter(ABC):
    @abstractmethod
    def scan(self, target_path: str, options: dict[str, Any]) -> list[dict]:
        pass

    @abstractmethod
    def get_version(self) -> str:
        pass

    @abstractmethod
    def is_available(self) -> bool:
        pass

    @abstractmethod
    def get_name(self) -> str:
        pass
