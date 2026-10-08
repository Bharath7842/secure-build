from fastapi import APIRouter, Depends

from app.auth import verify_bearer
from app.defaults.llm_presets import presets_as_dicts

router = APIRouter(prefix="/llm-presets", tags=["config"])


@router.get("")
def list_llm_presets(_: None = Depends(verify_bearer)):
    """Catalog of supported LLM provider/model pairs for projects and scans."""
    return presets_as_dicts()
