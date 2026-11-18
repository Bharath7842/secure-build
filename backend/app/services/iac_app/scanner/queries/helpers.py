"""Shared evaluate() helpers for generated and hand-written queries."""

from __future__ import annotations

from typing import Any, Callable, Iterable


def attrs(resource: dict) -> dict[str, Any]:
    return resource.get("attributes") or {}


def loc(resource: dict) -> dict[str, Any]:
    return resource.get("location") or {}


def hit(resource: dict, message: str, evidence: str, **extra: Any) -> dict[str, Any]:
    location = loc(resource)
    file_path = extra.get("file_path") or location.get("file_path") or location.get("file")
    return {
        "resource": resource.get("id"),
        "resource_type": resource.get("type"),
        "message": message,
        "evidence": evidence,
        "file_path": file_path,
        "line_start": extra.get("line_start") if extra.get("line_start") is not None else location.get("line_start"),
        "line_end": extra.get("line_end") if extra.get("line_end") is not None else location.get("line_end"),
    }


def resources_of(document: dict, types: Iterable[str]):
    wanted = set(types)
    for resource in document.get("resources") or []:
        if resource.get("type") in wanted:
            yield resource


def get_nested(obj: Any, *keys: str, default: Any = None) -> Any:
    current = obj
    for key in keys:
        if isinstance(current, list):
            if not current:
                return default
            current = current[0]
        if not isinstance(current, dict):
            return default
        current = current.get(key)
    return default if current is None else current


def is_falsey(value: Any) -> bool:
    if value is None:
        return True
    if isinstance(value, bool):
        return not value
    if isinstance(value, (int, float)):
        return value == 0
    if isinstance(value, str):
        return value.strip().lower() in {"", "false", "0", "none", "null", "disabled"}
    if isinstance(value, (list, dict)):
        return len(value) == 0
    return False


def is_open_cidr(value: Any) -> bool:
    if isinstance(value, list):
        return any(is_open_cidr(item) for item in value)
    return str(value or "") in {"0.0.0.0/0", "::/0", "*"}


def check_false(
    document: dict,
    resource_types: Iterable[str],
    fields: Iterable[str],
    message: str,
    *,
    missing_is_fail: bool = True,
) -> list[dict]:
    findings = []
    field_list = list(fields)
    for resource in resources_of(document, resource_types):
        values = attrs(resource)
        failed = []
        for field in field_list:
            value = get_nested(values, *field.split(".")) if "." in field else values.get(field)
            if value is None and not missing_is_fail:
                continue
            if is_falsey(value):
                failed.append(field)
        if failed:
            findings.append(hit(resource, message, f"{', '.join(failed)} is disabled or missing"))
    return findings


def check_equals(
    document: dict,
    resource_types: Iterable[str],
    field: str,
    bad_values: Iterable[Any],
    message: str,
) -> list[dict]:
    findings = []
    bad = {str(v).lower() for v in bad_values}
    for resource in resources_of(document, resource_types):
        values = attrs(resource)
        value = get_nested(values, *field.split(".")) if "." in field else values.get(field)
        if value is None:
            continue
        if str(value).lower() in bad:
            findings.append(hit(resource, message, f"{field} = {value}"))
    return findings


def check_missing(
    document: dict,
    resource_types: Iterable[str],
    field: str,
    message: str,
) -> list[dict]:
    findings = []
    for resource in resources_of(document, resource_types):
        values = attrs(resource)
        value = get_nested(values, *field.split(".")) if "." in field else values.get(field)
        if is_falsey(value):
            findings.append(hit(resource, message, f"{field} is not configured"))
    return findings


def check_predicate(
    document: dict,
    resource_types: Iterable[str],
    predicate: Callable[[dict, dict], str | None],
    message: str,
) -> list[dict]:
    findings = []
    for resource in resources_of(document, resource_types):
        evidence = predicate(resource, attrs(resource))
        if evidence:
            findings.append(hit(resource, message, evidence))
    return findings


def check_related_missing(
    document: dict,
    source_type: str,
    source_field: str,
    target_type: str,
    message: str,
) -> list[dict]:
    """Check that for each source resource, a related target resource exists.

    Example: For each aws_s3_bucket, check that an aws_s3_bucket_public_access_block exists.
    """
    findings = []
    related_values = set()
    for resource in document.get("resources") or []:
        if resource.get("type") == target_type:
            val = (resource.get("attributes") or {}).get(source_field) or ""
            if val:
                related_values.add(val)

    for resource in document.get("resources") or []:
        if resource.get("type") != source_type:
            continue
        resource_id = resource.get("name") or (resource.get("attributes") or {}).get("id") or ""
        if resource_id and resource_id not in related_values:
            findings.append(hit(resource, message, f"{source_type} '{resource_id}' has no matching {target_type}"))
    return findings


def check_attribute_value(
    document: dict,
    resource_types: Iterable[str],
    field: str,
    expected: Any,
    message: str,
) -> list[dict]:
    """Check that an attribute equals the expected value."""
    findings = []
    for resource in resources_of(document, resource_types):
        values = attrs(resource)
        value = get_nested(values, *field.split(".")) if "." in field else values.get(field)
        if value != expected:
            findings.append(hit(resource, message, f"{field}={value} (expected {expected})"))
    return findings


def check_nested_false(
    document: dict,
    resource_types: Iterable[str],
    nested_path: str,
    fields: Iterable[str],
    message: str,
) -> list[dict]:
    """Check fields within a nested object (e.g., metadata_options on aws_instance)."""
    findings = []
    field_list = list(fields)
    for resource in resources_of(document, resource_types):
        values = attrs(resource)
        nested = get_nested(values, *nested_path.split("."))
        if not isinstance(nested, dict):
            nested = {}
        failed = []
        for field in field_list:
            value = nested.get(field)
            if is_falsey(value):
                failed.append(field)
        if failed:
            findings.append(hit(resource, message, f"{nested_path}.{', '.join(failed)} is disabled or missing"))
    return findings
