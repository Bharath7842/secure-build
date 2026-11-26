from __future__ import annotations
import copy
from typing import Any


def pickle_deepcopy(obj: Any) -> Any:
    return copy.deepcopy(obj)


def find_in_dict(input_dict: dict, key_path: str) -> Any:
    keys = key_path.split(".")
    result = input_dict
    for key in keys:
        if isinstance(result, dict):
            result = result.get(key)
        else:
            return None
    return result


def get_resource_tags(entity: dict[str, Any]) -> dict[str, Any]:
    for key, value in entity.items():
        if isinstance(value, list) and len(value) > 0:
            inner = value[0]
            if isinstance(inner, dict) and "tags" in inner:
                tags = inner["tags"]
                if isinstance(tags, list) and len(tags) > 0:
                    return tags[0] if isinstance(tags[0], dict) else {}
                if isinstance(tags, dict):
                    return tags
    return {}
