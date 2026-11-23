"""Monitor -> LLM observability (admin only).

Built from Secure Build's own per-scan usage summaries. The live, per-call
view is the separate Streamlit app (tools/llm_monitor).
"""

from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.auth.principal import Principal, require
from app.db import get_db
from app.services import llm_monitor

router = APIRouter(prefix="/monitor", tags=["monitor"])


@router.get("/llm")
def llm_observability(
    range_key: Literal["24h", "7d", "30d", "90d"] = Query(default=llm_monitor.DEFAULT_RANGE, alias="range"),
    _: Principal = Depends(require("monitor.view")),
    db: Session = Depends(get_db),
):
    return llm_monitor.collect(db, range_key)
