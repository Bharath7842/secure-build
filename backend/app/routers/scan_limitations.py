from fastapi import APIRouter, Depends

from app.auth.principal import Principal, require
from app.defaults.scan_limitations import limitations_as_dicts

router = APIRouter(prefix="/scan-limitations", tags=["config"])


@router.get("")
def list_scan_limitations(principal: Principal = Depends(require("projects.view"))):
    """Catalog of configurable scan engine limitations and security checks."""
    return limitations_as_dicts()
