"""Internal query engine exposed as a ScannerAdapter."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from app.services.iac_app.scanner.engines.base import ScannerAdapter
from app.services.iac_app.scanner.normalizer.document_normalizer import DocumentNormalizer
from app.services.iac_app.scanner.parsers import get_parser
from app.services.iac_app.scanner.queries.engine import QueryEngine

logger = logging.getLogger(__name__)

QUERY_PACK_VERSION = "2.0.0"


class InternalQueryAdapter(ScannerAdapter):
    def __init__(self) -> None:
        self.engine = QueryEngine()
        self.normalizer = DocumentNormalizer()

    def get_name(self) -> str:
        return "internal"

    def is_available(self) -> bool:
        return True

    def get_version(self) -> str:
        return f"internal-query-pack-{QUERY_PACK_VERSION}"

    def scan(self, target_path: str, options: dict[str, Any]) -> list[dict]:
        documents = options.get("normalized_documents")
        if documents:
            has_terraform = any(
                (d.get("document") or {}).get("iac_type") == "terraform"
                for d in documents if isinstance(d, dict)
            )
            if has_terraform:
                from app.services.iac_app.scanner.native.parsers.terraform_resolver import TerraformResolver
                parsed_docs = options.get("parsed_documents") or []
                terraform_parsed = [
                    d for d in parsed_docs
                    if (isinstance(d, dict) and d.get("iac_type") == "terraform")
                ]
                resolver = TerraformResolver(terraform_parsed, target_path)
                resolved_context = resolver.resolve_all()
                return self.engine.execute_global(documents, resolved_context)
            return self.engine.execute(documents)

        parsed_documents = options.get("parsed_documents")
        if parsed_documents:
            normalized = self.normalizer.normalize_many(parsed_documents)
            has_terraform = any(d.iac_type == "terraform" for d in normalized)
            if has_terraform:
                from app.services.iac_app.scanner.native.parsers.terraform_resolver import TerraformResolver
                terraform_parsed = [
                    d for d in parsed_documents
                    if (isinstance(d, dict) and d.get("iac_type") == "terraform")
                ]
                resolver = TerraformResolver(terraform_parsed, target_path)
                resolved_context = resolver.resolve_all()
                normalized_dicts = [d.to_dict() for d in normalized]
                return self.engine.execute_global(normalized_dicts, resolved_context)
            return self.engine.execute(normalized)

        classified = options.get("classified_files") or {}
        files = []
        for entries in classified.values():
            files.extend(entries)
        if not files:
            files = _discover(target_path)

        normalized = []
        for file_info in files:
            path = file_info.get("absolute_path") or file_info.get("path")
            if not path:
                continue
            parser = get_parser(path)
            if parser is None:
                continue
            try:
                result = parser.parse(path)
            except Exception as exc:
                logger.debug("Internal parser skipped %s: %s", path, exc)
                continue
            docs = result if isinstance(result, list) else [result]
            normalized.extend(self.normalizer.normalize_many(docs))
        has_terraform = any(d.iac_type == "terraform" for d in normalized)
        if has_terraform:
            from app.services.iac_app.scanner.native.parsers.terraform_resolver import TerraformResolver
            from app.services.iac_app.scanner.native.parsers.terraform_parser import TerraformParser
            tf_parser = TerraformParser()
            tf_files = [fi for fi in files if fi.get("path", "").endswith(".tf")]
            if tf_files:
                dirs_seen = set()
                for fi in tf_files:
                    p = fi.get("absolute_path") or fi.get("path", "")
                    if p:
                        dirs_seen.add(str(Path(p).parent))
                all_parsed = []
                for d in dirs_seen:
                    all_parsed.extend([
                        {"raw": r, "file_path": str(Path(d) / "merged.tf")}
                        for r in [{}] if False
                    ])
                from app.services.iac_app.scanner.collector.file_collector import collect_iac_files
                from app.services.iac_app.scanner.collector.classifier import classify_iac_files
                for d in dirs_seen:
                    for tf_file in Path(d).glob("*.tf"):
                        parsed = tf_parser.parse_file(tf_file)
                        if parsed:
                            all_parsed.append(parsed)
                resolver = TerraformResolver(all_parsed, target_path or str(dirs_seen.pop()) if dirs_seen else "")
                resolved_context = resolver.resolve_all()
                normalized_dicts = [d.to_dict() for d in normalized]
                return self.engine.execute_global(normalized_dicts, resolved_context)
        return self.engine.execute(normalized)


def _discover(target_path: str) -> list[dict]:
    from app.services.iac_app.scanner.collector.file_collector import collect_iac_files
    from app.services.iac_app.scanner.collector.classifier import classify_iac_files

    files = collect_iac_files(target_path)
    classified = classify_iac_files(files)
    result = []
    for entries in classified.values():
        result.extend(entries)
    return result
