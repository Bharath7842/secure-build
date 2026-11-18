"""Cache interfaces. Not used until correctness is established."""

from abc import ABC, abstractmethod
from typing import Any


class ParserCache(ABC):
    @abstractmethod
    def get(self, file_hash: str) -> Any | None:
        ...

    @abstractmethod
    def set(self, file_hash: str, value: Any) -> None:
        ...


class PolicyCache(ABC):
    @abstractmethod
    def get(self, policy_version: str) -> Any | None:
        ...

    @abstractmethod
    def set(self, policy_version: str, value: Any) -> None:
        ...


class ScannerCache(ABC):
    @abstractmethod
    def get(self, key: str) -> Any | None:
        ...

    @abstractmethod
    def set(self, key: str, value: Any) -> None:
        ...
