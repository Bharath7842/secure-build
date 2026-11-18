"""Internal query engine.

Loads queries dynamically and evaluates them against normalized documents.
Queries never inspect Terraform/Kubernetes syntax directly — they receive
the canonical NormalizedDocument dictionary.
"""

from __future__ import annotations

import logging
from typing import Any

from app.services.iac_app.domain.document import NormalizedDocument
from app.services.iac_app.domain.enums import normalize_severity
from app.services.iac_app.scanner.queries.loader import LoadedQuery, QueryLoader

logger = logging.getLogger(__name__)

# Generated "not configured" rules in these categories are not security findings.
NON_SECURITY_CATEGORIES = frozenset({"COST", "RELIABILITY", "PERFORMANCE"})
# Placeholder — no duplicate rules in the current ruleset.
REDUNDANT_QUERY_IDS: frozenset[str] = frozenset()


def _query_is_active(meta) -> bool:
    if not getattr(meta, "enabled", True):
        return False
    if getattr(meta, "id", "") in REDUNDANT_QUERY_IDS:
        return False
    if str(getattr(meta, "category", "") or "").upper() in NON_SECURITY_CATEGORIES:
        return False
    return True


class QueryEngine:
    def __init__(self, queries_dir: str | None = None) -> None:
        self.loader = QueryLoader(queries_dir)
        self._queries: list[LoadedQuery] | None = None

    @property
    def queries(self) -> list[LoadedQuery]:
        if self._queries is None:
            self._queries = self.loader.load()
        return self._queries

    def reload(self) -> None:
        self._queries = self.loader.load()

    def list_metadata(self) -> list[dict[str, Any]]:
        return [q.metadata.to_dict() for q in self.queries]

    def execute(
        self,
        documents: list[NormalizedDocument] | list[dict[str, Any]],
        iac_types: set[str] | None = None,
    ) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        normalized = [_as_dict(doc) for doc in documents]

        for query in self.queries:
            meta = query.metadata
            if not _query_is_active(meta):
                continue
            if iac_types and meta.iac_type not in iac_types and meta.iac_type != "common":
                continue
            for document in normalized:
                doc_type = (document.get("document") or {}).get("iac_type") or document.get("iac_type")
                if meta.iac_type not in {"common", None, ""} and doc_type and meta.iac_type != doc_type:
                    continue
                try:
                    hits = query.evaluate(document) or []
                except Exception as exc:
                    logger.error("Query %s failed on %s: %s", meta.id, document.get("document"), exc)
                    continue
                for hit in hits:
                    results.append(self._to_finding(meta, document, hit))
        return results

    def execute_global(
        self,
        all_documents: list[dict[str, Any]],
        resolved_context: dict[str, Any] | None = None,
        iac_types: set[str] | None = None,
    ) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        terraform_docs = []
        kubernetes_docs = []
        cloudformation_docs = []
        other_docs = []
        for doc in all_documents:
            doc_type = (doc.get("document") or {}).get("iac_type") or doc.get("iac_type", "")
            if doc_type in {"terraform", "terraform_plan"}:
                terraform_docs.append(doc)
            elif doc_type == "kubernetes":
                kubernetes_docs.append(doc)
            elif doc_type == "cloudformation":
                cloudformation_docs.append(doc)
            else:
                other_docs.append(doc)
        if terraform_docs:
            merged = _build_merged_document(terraform_docs, resolved_context)
            for query in self.queries:
                meta = query.metadata
                if not _query_is_active(meta):
                    continue
                if iac_types and meta.iac_type not in iac_types and meta.iac_type != "common":
                    continue
                if meta.iac_type not in {"common", "terraform", "terraform_plan", None, ""}:
                    continue
                try:
                    hits = query.evaluate(merged) or []
                except Exception as exc:
                    logger.error("Query %s failed on merged document: %s", meta.id, exc)
                    continue
                for hit in hits:
                    results.append(self._to_finding(meta, merged, hit))
        if kubernetes_docs:
            merged_k8s = _build_merged_kubernetes_document(kubernetes_docs)
            for query in self.queries:
                meta = query.metadata
                if not _query_is_active(meta):
                    continue
                if iac_types and meta.iac_type not in iac_types and meta.iac_type != "common":
                    continue
                if meta.iac_type not in {"common", "kubernetes", None, ""}:
                    continue
                try:
                    hits = query.evaluate(merged_k8s) or []
                except Exception as exc:
                    logger.error("Query %s failed on merged k8s document: %s", meta.id, exc)
                    continue
                for hit in hits:
                    results.append(self._to_finding(meta, merged_k8s, hit))
        if cloudformation_docs:
            merged_cfn = _build_merged_cloudformation_document(cloudformation_docs)
            for query in self.queries:
                meta = query.metadata
                if not _query_is_active(meta):
                    continue
                if iac_types and meta.iac_type not in iac_types and meta.iac_type != "common":
                    continue
                if meta.iac_type not in {"common", "cloudformation", None, ""}:
                    continue
                try:
                    hits = query.evaluate(merged_cfn) or []
                except Exception as exc:
                    logger.error("Query %s failed on merged cfn document: %s", meta.id, exc)
                    continue
                for hit in hits:
                    results.append(self._to_finding(meta, merged_cfn, hit))
        for doc in other_docs:
            doc_type = (doc.get("document") or {}).get("iac_type") or doc.get("iac_type", "")
            for query in self.queries:
                meta = query.metadata
                if not _query_is_active(meta):
                    continue
                if iac_types and meta.iac_type not in iac_types and meta.iac_type != "common":
                    continue
                if meta.iac_type not in {"common", None, ""} and meta.iac_type != doc_type:
                    continue
                try:
                    hits = query.evaluate(doc) or []
                except Exception as exc:
                    logger.error("Query %s failed on %s: %s", meta.id, doc.get("document"), exc)
                    continue
                for hit in hits:
                    results.append(self._to_finding(meta, doc, hit))
        return results

    def _to_finding(self, meta, document: dict[str, Any], hit: dict[str, Any]) -> dict[str, Any]:
        header = document.get("document") or {}
        file_path = hit.get("file_path") or header.get("file") or document.get("file") or ""
        line_start = hit.get("line_start")
        line_end = hit.get("line_end")

        if _is_placeholder_path(file_path) or line_start is None:
            resource_id = hit.get("resource")
            if resource_id:
                for res in document.get("resources") or []:
                    if res.get("id") != resource_id:
                        continue
                    recovered = _resource_file_path(res, header)
                    if _is_placeholder_path(file_path) and recovered:
                        file_path = recovered
                    loc = res.get("location") or {}
                    if line_start is None:
                        line_start = loc.get("line_start")
                    if line_end is None:
                        line_end = loc.get("line_end")
                    break

        if _is_placeholder_path(file_path):
            file_path = ""

        return {
            "rule_id": meta.id,
            "title": meta.name,
            "description": hit.get("message") or meta.description,
            "severity": normalize_severity(hit.get("severity") or meta.severity),
            "category": meta.category,
            "finding_type": meta.finding_type,
            "iac_type": meta.iac_type,
            "provider": meta.provider,
            "resource": hit.get("resource"),
            "resource_type": hit.get("resource_type"),
            "scanner": "internal",
            "detected_by": ["internal"],
            "file_path": file_path,
            "line_start": line_start,
            "line_end": line_end,
            "evidence": _redact_secrets(hit.get("evidence")),
            "remediation": meta.remediation,
            "references": meta.references,
            "compliance": meta.compliance,
            "policy_id": meta.id,
            "policy_version": meta.version,
            "cwe": hit.get("cwe"),
            "owasp_category": hit.get("owasp_category"),
        }


def _is_placeholder_path(path: str | None) -> bool:
    value = (path or "").strip()
    return not value or value.startswith("<merged")


def _resource_file_path(resource: dict[str, Any], header: dict[str, Any] | None = None) -> str:
    loc = resource.get("location") or {}
    raw = resource.get("raw") or {}
    candidates = [
        loc.get("file_path"),
        loc.get("file"),
        raw.get("file"),
        raw.get("file_path"),
        (header or {}).get("file"),
    ]
    for candidate in candidates:
        if candidate and not _is_placeholder_path(str(candidate)):
            return str(candidate).replace("\\", "/")
    return ""


def _as_dict(document: NormalizedDocument | dict[str, Any]) -> dict[str, Any]:
    if isinstance(document, NormalizedDocument):
        return document.to_dict()
    if "document" in document and "resources" in document:
        return document
    return {
        "document": {
            "file": document.get("file") or document.get("file_path", ""),
            "iac_type": document.get("iac_type", "unknown"),
        },
        "resources": document.get("resources") or [],
        "raw_evidence": document,
    }


def _build_merged_document(
    terraform_docs: list[dict[str, Any]],
    resolved_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    all_resources: list[dict[str, Any]] = []
    merged_variables: dict[str, Any] = {}
    merged_locals: dict[str, Any] = {}
    merged_data_sources: list[dict[str, Any]] = []
    for doc in terraform_docs:
        doc_file = (doc.get("document") or {}).get("file") or doc.get("file") or ""
        for res in (doc.get("resources") or []):
            stamped = dict(res)
            loc = dict(stamped.get("location") or {})
            recovered = _resource_file_path(stamped, doc.get("document") or {})
            if _is_placeholder_path(loc.get("file_path")) and (recovered or doc_file):
                loc["file_path"] = recovered or doc_file
            stamped["location"] = loc
            all_resources.append(stamped)
        for var_name, var_val in (doc.get("variables") or {}).items():
            if var_name not in merged_variables:
                merged_variables[var_name] = var_val
        for local_name, local_val in (doc.get("locals") or {}).items():
            if local_name not in merged_locals:
                merged_locals[local_name] = local_val
        for ds in (doc.get("data_sources") or []):
            merged_data_sources.append(ds)
    if resolved_context:
        for res in (resolved_context.get("resources") or []):
            res_id = res.get("id") or ""
            if not any(r.get("id") == res_id for r in all_resources):
                all_resources.append(res)
        merged_variables.update(resolved_context.get("variables") or {})
        merged_locals.update(resolved_context.get("locals") or {})
    return {
        "document": {
            "file": "<merged>",
            "iac_type": "terraform",
            "provider": None,
        },
        "resources": all_resources,
        "variables": merged_variables,
        "locals": merged_locals,
        "data_sources": merged_data_sources,
        "raw_evidence": {},
    }


def _build_merged_kubernetes_document(
    k8s_docs: list[dict[str, Any]],
) -> dict[str, Any]:
    all_resources: list[dict[str, Any]] = []
    seen_names = set()
    for doc in k8s_docs:
        raw = doc.get("raw_evidence") or doc.get("raw") or doc
        kind = raw.get("kind", "")
        metadata = raw.get("metadata", {})
        name = metadata.get("name", "")
        namespace = metadata.get("namespace", "default")
        key = f"{namespace}/{kind}/{name}"
        if key in seen_names:
            continue
        seen_names.add(key)
        resource = {
            "id": f"{kind.lower()}.{name}",
            "type": kind,
            "provider": "kubernetes",
            "name": name,
            "attributes": raw,
            "location": {"file_path": doc.get("file_path") or (doc.get("document") or {}).get("file", ""), "line_start": 1},
            "raw": raw,
            "relationships": [],
        }
        all_resources.append(resource)
    return {
        "document": {
            "file": "<merged_kubernetes>",
            "iac_type": "kubernetes",
            "provider": "kubernetes",
        },
        "resources": all_resources,
        "raw_evidence": {},
    }


def _build_merged_cloudformation_document(
    cfn_docs: list[dict[str, Any]],
) -> dict[str, Any]:
    all_resources: list[dict[str, Any]] = []
    for doc in cfn_docs:
        raw = doc.get("raw_evidence") or doc.get("raw") or doc
        resources = raw.get("Resources", raw.get("resources", {}))
        for logical_id, resource_def in resources.items():
            if isinstance(resource_def, dict):
                resource_type = resource_def.get("Type", "")
                properties = resource_def.get("Properties", {})
                resource = {
                    "id": f"{resource_type}.{logical_id}",
                    "type": resource_type,
                    "provider": "aws",
                    "name": logical_id,
                    "attributes": properties or {},
                    "location": {"file_path": doc.get("file_path") or (doc.get("document") or {}).get("file", ""), "line_start": 1},
                    "raw": resource_def,
                    "relationships": [],
                }
                all_resources.append(resource)
    return {
        "document": {
            "file": "<merged_cloudformation>",
            "iac_type": "cloudformation",
            "provider": "aws",
        },
        "resources": all_resources,
        "raw_evidence": {},
    }


def _redact_secrets(evidence: Any) -> str | None:
    if evidence is None:
        return None
    text = str(evidence)
    lowered = text.lower()
    secret_keys = ("password", "secret", "token", "api_key", "private_key", "aws_secret")
    if any(key in lowered for key in secret_keys):
        if len(text) > 12:
            return text[:4] + "********"
        return "********"
    return text
