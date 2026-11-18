"""Parser adapter contract.

Parsers convert IaC source files into ParsedDocument objects.
Security queries never depend on parser-specific syntax — they consume
the normalized intermediate representation produced later.
"""

from abc import ABC, abstractmethod
from pathlib import Path

from app.services.iac_app.domain.document import ParsedDocument


class ParserAdapter(ABC):
    @abstractmethod
    def supports(self, file: str) -> bool:
        """Return True when this parser can handle the given file path."""

    @abstractmethod
    def parse(self, file: str) -> ParsedDocument | list[ParsedDocument]:
        """Parse a single file into one or more ParsedDocument objects."""

    def parse_path(self, path: Path) -> ParsedDocument | list[ParsedDocument]:
        return self.parse(str(path))
