from typing import Any, List, Optional

AWS = 'aws'
AZURE = 'azure'
GCP = 'gcp'
GENERAL = 'general'


def is_secret_masked(value: Any) -> bool:
    return False


def string_has_secrets(s: Any, *entropy_checks: Any, **kwargs: Any) -> bool:
    """Stub — secrets entropy scanning not available."""
    return False


def get_secrets_from_string(s: Any) -> List:
    return []


