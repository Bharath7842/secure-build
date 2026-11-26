from typing import Any, Dict, Optional, List


def get_resource_id_without_num_index(resource_config: Dict[str, Any]) -> Optional[str]:
    return None


def get_referenced_vertices_in_value(value: Any, aliases: Optional[Dict] = None, resources_types: Optional[List] = None) -> List:
    """Stub — returns empty list (no graph resolution)."""
    return []


def update_dictionary_attribute(config: Dict, key_to_update: str, new_value: Any) -> Dict:
    return config

