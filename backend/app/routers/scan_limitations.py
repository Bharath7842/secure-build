from fastapi import APIRouter, Depends

from app.auth import verify_bearer
from app.defaults.scan_limitations import limitations_as_dicts

router = APIRouter(prefix="/scan-limitations", tags=["config"])


@router.get("")
def list_scan_limitations(_: None = Depends(verify_bearer)):
    """Catalog of configurable scan engine limitations and security checks."""
    return limitations_as_dicts()
