"""DB-backed cross-scan LLM result cache for the SAST engine.

`sast_engine/llm_client.call_llm` looks this object up on the shared scan
usage dict (llm_client.RESULT_CACHE_USAGE_KEY) and only ever calls
`get`/`put` — the engine has no dependency on the app package. Entries are
scoped per project and keyed by a hash of the complete prompt plus model and
generation parameters (llm_client.result_cache_key), so an unchanged file,
flow or hit group sent to the same model with the same prompt version is
answered from here instead of the provider.

Every method opens its own short-lived session: the engine calls in from
several worker threads at once, and a cache fault is swallowed by call_llm
(it falls back to a live call), never surfaced as a scan failure.
"""

from __future__ import annotations

import threading
from typing import Any

from sqlalchemy.exc import IntegrityError

from app import db as db_module
from app.models import LlmResultCache


class DbLlmResultCache:
    def __init__(self, project_id: str) -> None:
        self.project_id = project_id
        self._write_lock = threading.Lock()

    def get(self, key: str) -> dict[str, Any] | None:
        session = db_module.SessionLocal()
        try:
            row = (
                session.query(LlmResultCache)
                .filter(LlmResultCache.project_id == self.project_id, LlmResultCache.key == key)
                .one_or_none()
            )
            if row is None:
                return None
            row.hit_count = (row.hit_count or 0) + 1
            session.commit()
            return {
                "text": row.response_text,
                "input_tokens": row.input_tokens or 0,
                "output_tokens": row.output_tokens or 0,
            }
        finally:
            session.close()

    def put(
        self,
        key: str,
        *,
        step: str,
        model: str,
        text: str,
        input_tokens: int | None = None,
        output_tokens: int | None = None,
    ) -> None:
        with self._write_lock:
            session = db_module.SessionLocal()
            try:
                session.add(LlmResultCache(
                    project_id=self.project_id,
                    key=key,
                    step=(step or "")[:80],
                    model=(model or "")[:200],
                    response_text=text,
                    input_tokens=int(input_tokens or 0),
                    output_tokens=int(output_tokens or 0),
                ))
                session.commit()
            except IntegrityError:
                # Same prompt answered concurrently (or by a parallel scan) —
                # the first stored answer wins.
                session.rollback()
            finally:
                session.close()
