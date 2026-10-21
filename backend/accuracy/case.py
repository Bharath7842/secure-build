"""Loading and validating accuracy corpus cases.

A case is a directory:

    <id>/case.yaml       the metadata and expectations (below)
    <id>/repo/           the (synthetic) repository that is scanned
    <id>/llm_responses/  recorded LLM responses, one <key>.json per call

`case.yaml` fields: `id`, `area`, `polarity` (positive | negative | uncertain),
`seed_findings` (review `#` numbers, traceability only), `adjudication`
(adjudicated | dev_label_only), optional `xfail` (the epic expected to fix a
known gap), optional `allow_absent` (a negative that may also pass by the rule
not firing at all), `limitations` (project scan-limitation overrides),
`state_overrides` (engine state knobs), `expected` (list of Expected), and
`scripted` (what the scripted recorder answers; see `runner`).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

POLARITIES = ("positive", "negative", "uncertain")
ADJUDICATIONS = ("adjudicated", "dev_label_only")

# Every response is keyed by provider + model + prompt, so the corpus pins them.
PINNED_PROVIDER = "bedrock"
PINNED_MODEL = "us.anthropic.claude-haiku-4-5-20251001-v1:0"

# Engine knobs every case runs with unless it overrides them: sequential and
# local-only (no Joern, no derived rules, no call graph) so a case's LLM calls are
# few and deterministic.
DEFAULT_LIMITATIONS: dict[str, bool] = {
    "inter-file-call-graph": False,
    "runtime-derived-regex": False,
    "joern-dataflow": False,
    "joern-scan-queries": False,
    "parallel-scan-stages": False,
}
# Without this a tiny repo backfills every MEDIUM/LOW file into the deep scan.
DEFAULT_STATE_OVERRIDES: dict[str, Any] = {"backfill_deep_scan": False}


class CaseError(ValueError):
    """A case.yaml that does not follow the schema."""


@dataclass(frozen=True)
class Expected:
    """One finding a case expects. `rule_id` or `cwe` (or both) identify it,
    `sink_line` locates it (matched within `LINE_TOLERANCE` lines)."""

    file: str
    sink_line: int
    verdict: str
    rule_id: str | None = None
    cwe: str | None = None
    issue_class: str | None = None
    reason_tag: str | None = None
    unresolved_reason: str | None = None


@dataclass
class Case:
    id: str
    area: str
    polarity: str
    adjudication: str
    directory: Path
    seed_findings: list[int] = field(default_factory=list)
    xfail: str | None = None
    allow_absent: bool = False
    limitations: dict[str, bool] = field(default_factory=dict)
    state_overrides: dict[str, Any] = field(default_factory=dict)
    expected: list[Expected] = field(default_factory=list)
    scripted: list[dict[str, Any]] = field(default_factory=list)

    @property
    def source_dir(self) -> Path:
        return self.directory / "repo"

    @property
    def responses_dir(self) -> Path:
        return self.directory / "llm_responses"


LINE_TOLERANCE = 2
_VERDICTS = ("true_positive", "false_positive", "unverified")


def _expected(raw: dict[str, Any], case_id: str) -> Expected:
    for required in ("file", "sink_line", "verdict"):
        if required not in raw:
            raise CaseError(f"{case_id}: expected entry is missing {required!r}: {raw}")
    if not (raw.get("rule_id") or raw.get("cwe")):
        raise CaseError(f"{case_id}: expected entry needs a rule_id or a cwe: {raw}")
    if raw["verdict"] not in _VERDICTS:
        raise CaseError(f"{case_id}: unknown verdict {raw['verdict']!r}")
    return Expected(
        file=str(raw["file"]),
        sink_line=int(raw["sink_line"]),
        verdict=raw["verdict"],
        rule_id=raw.get("rule_id"),
        cwe=raw.get("cwe"),
        issue_class=raw.get("issue_class"),
        reason_tag=raw.get("reason_tag"),
        unresolved_reason=raw.get("unresolved_reason"),
    )


def load_case(directory: Path) -> Case:
    path = directory / "case.yaml"
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as exc:
        raise CaseError(f"{directory.name}: cannot read case.yaml: {exc}") from exc
    case_id = str(raw.get("id") or "")
    if case_id != directory.name:
        raise CaseError(f"{directory.name}: case id {case_id!r} must equal its directory name")
    if raw.get("polarity") not in POLARITIES:
        raise CaseError(f"{case_id}: polarity must be one of {POLARITIES}")
    if raw.get("adjudication") not in ADJUDICATIONS:
        raise CaseError(f"{case_id}: adjudication must be one of {ADJUDICATIONS}")
    if not raw.get("area"):
        raise CaseError(f"{case_id}: area is required")
    if not (directory / "repo").is_dir():
        raise CaseError(f"{case_id}: missing repo/ directory")
    expected = [_expected(item, case_id) for item in raw.get("expected") or []]
    if not expected and not raw.get("allow_absent"):
        raise CaseError(f"{case_id}: a case needs expected findings (or allow_absent)")
    return Case(
        id=case_id,
        area=str(raw["area"]),
        polarity=raw["polarity"],
        adjudication=raw["adjudication"],
        directory=directory,
        seed_findings=[int(n) for n in raw.get("seed_findings") or []],
        xfail=raw.get("xfail") or None,
        allow_absent=bool(raw.get("allow_absent", False)),
        limitations={**DEFAULT_LIMITATIONS, **(raw.get("limitations") or {})},
        state_overrides={**DEFAULT_STATE_OVERRIDES, **(raw.get("state_overrides") or {})},
        expected=expected,
        scripted=list(raw.get("scripted") or []),
    )


def discover_cases(root: Path) -> list[Case]:
    """Every case directory under `root` (a directory holding a case.yaml), by id."""
    return [
        load_case(path.parent)
        for path in sorted(root.glob("*/case.yaml"))
        if not path.parent.name.startswith("_")
    ]
