"""Entities and value types shared across the DAST layers (types only)."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping, Sequence


class CheckVerdict(str, Enum):
    """Outcome of one executed check (maps to the existing PASS/FAIL/INCONCLUSIVE strings)."""

    PASS = "PASS"
    FAIL = "FAIL"
    INCONCLUSIVE = "INCONCLUSIVE"


class FindingVerdict(str, Enum):
    """Verdict stored on a finding. `unverified` mirrors `app.models.UNVERIFIED_VERDICT`
    (a test pins the two together). The scan itself only ever produces the first two;
    `false_positive` exists for a reviewer to dismiss a finding."""

    TRUE_POSITIVE = "true_positive"
    UNVERIFIED = "unverified"
    FALSE_POSITIVE = "false_positive"


Verdict = FindingVerdict


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Confidence(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class Location(str, Enum):
    """Where in the exchange a tested parameter lives."""

    QUERY = "query"
    PATH = "path"
    HEADER = "header"
    BODY = "body"
    RESPONSE = "response"


class CheckMode(str, Enum):
    AUTOMATED = "automated"
    OPT_IN = "opt-in"
    ASSIST_ONLY = "assist-only"


class RoleName(str, Enum):
    ADMIN = "admin"
    USER = "user"
    VIEWER = "viewer"
    ANONYMOUS = "anonymous"
    CUSTOM = "custom"


@dataclass(frozen=True)
class Role:
    name: RoleName
    label: str = ""  # display label, required when name is CUSTOM


@dataclass(frozen=True)
class Identity:
    """An actor the scan can authenticate as. Holds no secret: credentials live in a CredentialHolder."""

    identity_id: str
    label: str
    role: Role


@dataclass(frozen=True)
class Target:
    """The system under test."""

    base_url: str
    permitted_hosts: Sequence[str] = ()


class EndpointSource(str, Enum):
    OBSERVED = "observed"
    SCHEMA = "schema"
    BOTH = "both"


@dataclass(frozen=True)
class Parameter:
    """One parameter of an endpoint: where it lives and the values seen for it."""

    name: str
    location: Location
    observed_values: Sequence[str] = ()
    required: bool = False
    schema_type: str = ""


@dataclass(frozen=True)
class Endpoint:
    """One inventory item: a method + path template reached by the crawl or a schema.

    `params` (name -> location) is the compact view used by earlier stories; `parameters`
    carries the full detail. `inventory.merge_endpoints` keeps the two consistent."""

    method: str
    path_template: str
    params: Mapping[str, Location] = field(default_factory=dict)
    seen_as: Sequence[str] = ()  # identity ids that reached it
    url: str = ""  # a concrete example URL (first one seen)
    parameters: Sequence[Parameter] = ()
    body_schema: Mapping[str, Any] | None = None
    body_sample: str | None = None
    source: EndpointSource = EndpointSource.OBSERVED
    state_changing: bool = False  # method gate applies (POST/PUT/PATCH/DELETE or a GraphQL mutation)
    note: str = ""
    last_status: int | None = None  # HTTP status of the last observed response
    content_type: str = ""
    kind: str = "page"  # "page" (navigated HTML), "api" (XHR/fetch/schema operation), "asset" (static file)
    # Whether an OpenAPI operation declared a security requirement for this endpoint: True (a
    # non-empty `security`), False (an *explicit* `security: []` on the operation or document -
    # a deliberate "no auth needed here" statement), or None when the document never mentions
    # `security` for this operation at all (by far the most common case for a real API, and not
    # the same as an explicit opt-out) or there is no schema source to ask (crawl-only/observed).
    # Set by `openapi.endpoints_from_openapi` via `inventory.from_schema`; `inventory.merge_endpoints`
    # keeps the schema side's value when an observed and a schema sighting of the same endpoint
    # are merged.
    security_declared: bool | None = None

    @property
    def label(self) -> str:
        return f"{self.method.upper()} {self.path_template}"


@dataclass(frozen=True)
class Check:
    """A catalog entry (see architecture.md, "Check (catalog entry)"). Carries no payload:
    the model constructs inputs at scan time under the check's guidance."""

    check_id: str
    title: str
    standards: Mapping[str, Sequence[str]]  # e.g. {"owasp": [...], "apisec": [...], "wstg": [...], "cwe": [...]}
    location: Location
    detector_signals: Sequence[str]
    base_severity: Severity
    mode: CheckMode
    remediation_ref: str = ""
    requires: Sequence[str] = ()  # dependency names, e.g. ("second_identity", "oast")
    applies_to: Mapping[str, Any] = field(default_factory=dict)
    description: str = ""
    passive: bool = False  # needs no request beyond what discovery already observed
    load_generating: bool = False  # off until explicitly enabled, whatever the pack says
    enabled_by_default: bool = True
    # What happens when a dependency is missing: name -> "skip" | "degrade" | "assist-only".
    on_missing: Mapping[str, str] = field(default_factory=dict)
    degraded_note: str = ""  # what still runs when degraded, e.g. "no-session replay only"
    aliases: Sequence[str] = ()  # older ids that resolve to this check
    flags: Sequence[str] = ()  # load-time notes, e.g. "no_resolvable_signal"
    source: str = "catalog"  # "catalog" | "custom"
    version: int = 1  # custom rules are versioned


@dataclass(frozen=True)
class RulePack:
    pack_id: str
    title: str
    check_ids: Sequence[str]
    enabled_by_default: bool = True


@dataclass(frozen=True)
class ResponseSnapshot:
    """A response reduced to what detectors compare."""

    status: int | None
    length: int
    body_excerpt: str
    headers: Mapping[str, str] = field(default_factory=dict)
    elapsed_ms: float = 0.0


@dataclass(frozen=True)
class DetectorSignal:
    """A named observation from comparing a baseline to a test response."""

    name: str
    detail: str = ""


Signal = DetectorSignal


@dataclass(frozen=True)
class Evidence:
    baseline_excerpt: str
    test_excerpt: str
    signals: Sequence[DetectorSignal] = ()
    audit_ref: str = ""


@dataclass(frozen=True)
class Finding:
    check_id: str
    severity: Severity
    confidence: Confidence
    verdict: FindingVerdict
    target: str  # "METHOD path"
    param: str | None
    location: Location | None
    standards: Sequence[str] = ()
    remediation_ref: str = ""
    evidence: Evidence | None = None
    first_seen_scan_id: str | None = None
    last_seen_scan_id: str | None = None
    affected_targets: Sequence[str] = ()  # other endpoints the same issue was seen on (dedupe)
    roles: Sequence[str] = ()  # role labels involved (authorization findings)


@dataclass(frozen=True)
class Scan:
    """Identity of a scan as the domain sees it (the persisted row stays in `app.models`)."""

    scan_id: str
    project_id: str
    target: Target
    identities: Sequence[Identity] = ()
