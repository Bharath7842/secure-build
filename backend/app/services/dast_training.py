"""Training-data capture with controls (DAST-16-050).

* **Off by default**, enabled per project (`Project.training_capture_enabled`) by an operator who
  presents the training admin token (`DAST_TRAINING_ADMIN_TOKEN`); with no token configured capture
  cannot be enabled at all.
* **Only agreeing records** (the model's proposal equals the detectors' verdict), scrubbed of hosts,
  addresses, credentials, tokens and identifiers before they are stored; **never an input the
  non-destructive validator rejects** (re-checked here).
* **Restricted reads**: examples are readable only through the endpoints in `routers/dast_training.py`,
  which need the bearer token *and* the training admin token, and every attempt, allowed or denied, is
  written to `dast_training_audit`.
* **Export** to the JSONL format of `spec/dast_training_samples.jsonl` (`{task, input, output}` per line),
  balanced across fail, pass and inconclusive, with a dataset version recorded in the audit trail.
"""

from __future__ import annotations

import hmac
import threading
from datetime import datetime, timezone
from typing import Any, Callable, Iterable, Mapping
from urllib.parse import urlsplit

from sqlalchemy import func
from sqlalchemy.orm import Session

from app import db as app_db
from app.config import settings
from app.dast.domain import training as T
from app.dast.domain.validation import ProposedTest, validate_test_input
from app.dast.input_gate import default_rule_list
from app.models import DastTrainingAudit, DastTrainingExample, Project

MAX_PER_LABEL_PER_PROJECT = 500  # a storage bound; export balances further


def admin_token_ok(presented: str | None) -> bool:
    configured = settings.dast_training_admin_token.get_secret_value() if settings.dast_training_admin_token else ""
    return bool(configured) and bool(presented) and hmac.compare_digest(configured.encode(), (presented or "").encode())


def audit(db: Session, reader: str, action: str, allowed: bool, detail: str = "", count: int = 0) -> None:
    db.add(DastTrainingAudit(reader=(reader or "unknown")[:120], action=action, allowed=allowed, detail=detail[:300], count=count))
    db.commit()


def set_capture(db: Session, project: Project, enabled: bool, reader: str) -> None:
    project.training_capture_enabled = bool(enabled)
    db.commit()
    audit(db, reader, "enable" if enabled else "disable", True, f"project {project.id}")


class TrainingSink:
    """What the engine's active stage calls with each finished target. One per scan; thread-safe.
    A no-op unless built for a project that has opted in."""

    def __init__(self, project_id: str, scan_id: str, *, target_url: str, secrets: Callable[[], Iterable[str]] = lambda: (), session_factory=None) -> None:
        self.project_id, self.scan_id = project_id, scan_id
        parts = urlsplit(target_url)
        self._hosts = tuple(h for h in {parts.hostname or "", parts.netloc, target_url.rstrip("/")} if h)
        self._secrets = secrets
        self._session_factory = session_factory
        self._lock = threading.Lock()
        self.captured = self.skipped = 0

    def _session(self):
        return (self._session_factory or app_db.SessionLocal)()

    def __call__(self, outcome: Any, checks: Mapping[str, Any]) -> None:
        records = []
        for record in outcome.records:
            if record.outcome is None or record.result is None or not record.result.usable or record.baseline is None:
                self.skipped += 1
                continue
            signals = [s.name for s in record.outcome.signals]
            proposed = record.outcome.proposed.value
            final = record.outcome.verdict.value
            label = T.label_for(final)
            if label is None or not T.agrees(proposed=proposed, final=final, signals=signals):
                self.skipped += 1  # the guardrail changed the model's mind: a disagreement, not training data
                continue
            method = outcome.endpoint.method
            if not validate_test_input(ProposedTest(method, record.location, record.input), default_rule_list(), safe_mode=False, allow_state_changing=True).ok:
                self.skipped += 1  # defence in depth: an input the validator rejects is never stored
                continue
            check = checks[record.check_id].check
            secrets = tuple(self._secrets())
            advice = record.advice
            rule = T.rule_example(
                check_id=check.check_id, target=f"{method} {outcome.endpoint.path_template}", signals=signals,
                baseline={"status": record.baseline.status, "len": record.baseline.length},
                test={"status": record.result.status, "len": record.result.length, "body_excerpt": record.result.body[:400]},
                verdict=final, severity=(advice.severity if advice and advice.severity else checks[record.check_id].severity.value), confidence=(advice.confidence if advice and advice.confidence else "MEDIUM"),
                finding=(advice.finding if advice and advice.finding else record.outcome.reason), hosts=self._hosts, secrets=secrets,
            )
            records.append((label, rule))
            if final == "FAIL":
                records.append(
                    (
                        label,
                        T.construct_example(
                            endpoint=f"{method} {outcome.endpoint.path_template}",
                            params=[{"name": p.name, "type": p.schema_type or "string", "location": p.location.value} for p in outcome.endpoint.parameters][:12],
                            test={"check_id": check.check_id, "parameter": record.parameter, "location": record.location, "input": record.input, "expected_signal": record.expected_signal},
                            hosts=self._hosts, secrets=secrets,
                        ),
                    )
                )
        if not records:
            return
        with self._lock, self._session() as db:
            counts: dict[str, int] = {}
            for label, example in records:
                if label not in counts:
                    counts[label] = db.query(func.count()).select_from(DastTrainingExample).filter(DastTrainingExample.project_id == self.project_id, DastTrainingExample.label == label).scalar() or 0
                if counts[label] >= MAX_PER_LABEL_PER_PROJECT:
                    self.skipped += 1
                    continue
                counts[label] += 1
                db.add(DastTrainingExample(project_id=self.project_id, scan_id=self.scan_id, task=example["task"], label=label, example=example))
                self.captured += 1
            db.commit()


def list_examples(db: Session, *, project_id: str | None = None, limit: int = 100, after: str | None = None) -> list[dict[str, Any]]:
    query = db.query(DastTrainingExample)
    if project_id:
        query = query.filter(DastTrainingExample.project_id == project_id)
    if after:
        query = query.filter(DastTrainingExample.id > after)
    rows = query.order_by(DastTrainingExample.id).limit(max(1, min(limit, 500))).all()
    return [{"id": r.id, "task": r.task, "label": r.label, **r.example} for r in rows]


def export_jsonl(db: Session, *, project_id: str | None = None, balance: bool = True, task: str | None = None, seed: int = 0) -> tuple[str, dict[str, Any]]:
    """`(JSONL text, info)`; `info` carries the dataset version and per-label counts."""
    query = db.query(DastTrainingExample)
    if project_id:
        query = query.filter(DastTrainingExample.project_id == project_id)
    if task:
        query = query.filter(DastTrainingExample.task == task)
    rows = query.order_by(DastTrainingExample.id).all()
    examples = [r.example for r in rows]
    labels = [r.label for r in rows]
    if balance:
        kept = T.balance(examples, labels, seed=seed)
        kept_labels = [labels[examples.index(e)] for e in kept] if kept else []
    else:
        kept, kept_labels = examples, labels
    created = datetime.now(timezone.utc).strftime("%Y%m%d")
    info = {
        "dataset_version": T.dataset_version(kept, created), "count": len(kept), "balanced": balance, "available": len(examples),
        "labels": {label: kept_labels.count(label) for label in T.LABELS},
    }
    return T.to_jsonl(kept), info
