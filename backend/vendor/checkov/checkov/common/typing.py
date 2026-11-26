from __future__ import annotations
from typing import Any, Callable, Dict, TypeVar, Set, Union, TypedDict, Tuple, Optional
try:
    from typing import TypeAlias
except ImportError:
    from typing_extensions import TypeAlias


_BaseRunner = TypeVar("_BaseRunner")

_Resource: TypeAlias = str
_Attributes: TypeAlias = Set[str]
ResourceAttributesToOmit: TypeAlias = Dict[_Resource, _Attributes]


class _CheckResult(TypedDict, total=False):
    result: Any
    suppress_comment: str
    evaluated_keys: list
    results_configuration: Optional[dict]
    check: Any
    entity: dict


class _SkippedCheck(TypedDict, total=False):
    bc_id: Optional[str]
    id: str
    suppress_comment: str
    line_number: Optional[int]
