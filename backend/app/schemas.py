import json
from datetime import datetime
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator, model_validator

from app.config import settings
from app.services.llm_policy import SAST_FALLBACK_PROVIDERS, SAST_LLM_PROVIDERS


class ReferenceSource(BaseModel):
    key: str = "Custom"
    name: str = "Custom"
    mode: str = "top10"  # top10|top15|custom|any free label
    urls: list[str] = Field(default_factory=list)


class ProjectBase(BaseModel):
    name: str = Field(max_length=500)
    description: str | None = None
    languages: list[str] = Field(default_factory=list)
    frameworks: list[str] = Field(default_factory=list)
    build_tool: str | None = None
    # Not required: a project used only for DAST scans has no repository —
    # DAST targets a URL directly (routers/scans.py's `is_dast` branch never
    # reads this field). SAST/SCA/SBOM scans still need one, enforced where
    # a scan of that type is actually triggered, not at project creation.
    default_git_url: str = ""
    default_branch: str = "main"
    monorepo_path: str | None = None
    enable_sast: bool = True
    enable_sca: bool = True
    enable_sbom: bool = True
    enable_secrets: bool = False
    scan_mode: str = "full"  # always full; incremental is no longer offered
    max_files_to_scan: int = 0  # 0 = entire repo; UI no longer exposes a cap
    max_derived_regex_rules: int = 50  # hard cap on LLM-derived regex rules per scan
    max_derived_semgrep_rules: int = 20  # hard cap on LLM-derived Semgrep rules per scan
    llm_provider: str = "bedrock"  # bedrock|openai_compat|ollama — which LLM backend each scan uses
    llm_model: str = "us.anthropic.claude-haiku-4-5-20251001-v1:0"
    # openai_compat endpoint (e.g. http://localhost:8000/v1); None = server default.
    llm_base_url: str | None = None
    # After the soft $ cutoff, continue on this provider/model; "none" stops
    # LLM work instead (ignored if primary is ollama).
    fallback_llm_provider: str = "ollama"
    fallback_llm_model: str = "granite-code:3b-instruct"
    owasp_mode: str = "top10"  # top10|top15|custom (synced from reference_sources)
    owasp_urls: list[str] = Field(default_factory=list)
    nvd_mode: str = "top10"  # top10|top15|custom (synced from reference_sources)
    nvd_urls: list[str] = Field(default_factory=list)
    reference_sources: list[ReferenceSource] = Field(default_factory=list)

    @field_validator("reference_sources", "owasp_urls", "nvd_urls", "languages", "frameworks", mode="before")
    @classmethod
    def _none_to_list(cls, value):
        return value or []

    @field_validator("llm_provider")
    @classmethod
    def _known_llm_provider(cls, value):
        return _check_choice("llm_provider", value, SAST_LLM_PROVIDERS)

    # mode="before": legacy rows can hold NULL here, which must coerce to the
    # default rather than fail ProjectOut's str type check.
    @field_validator("fallback_llm_provider", mode="before")
    @classmethod
    def _known_fallback_provider(cls, value):
        return _check_choice("fallback_llm_provider", value or "none", SAST_FALLBACK_PROVIDERS)



def _check_choice(field: str, value: str | None, allowed: tuple[str, ...]) -> str | None:
    if value is None:
        return None
    normalized = value.strip().lower()
    if normalized not in allowed:
        raise ValueError(f"{field} must be one of {', '.join(allowed)}")
    return normalized


class ProjectCreate(ProjectBase):
    # Set when "Connect GitHub"/"Connect GitLab" was authorized on the
    # new-project form before this project existed (see routers/git_auth.py's
    # pending-connection store). Consumed once at creation time — never
    # persisted as a project field itself.
    git_connection_id: str | None = None
    # Write-only; ProjectOut only reports llm_api_key_set.
    llm_api_key: SecretStr | None = None


class ProjectUpdate(BaseModel):
    name: str | None = Field(default=None, max_length=500)
    description: str | None = None
    languages: list[str] | None = None
    frameworks: list[str] | None = None
    build_tool: str | None = None
    default_git_url: str | None = None
    default_branch: str | None = None
    monorepo_path: str | None = None
    enable_sast: bool | None = None
    enable_sca: bool | None = None
    enable_sbom: bool | None = None
    enable_secrets: bool | None = None
    scan_mode: str | None = None
    max_files_to_scan: int | None = None
    max_derived_regex_rules: int | None = None
    max_derived_semgrep_rules: int | None = None
    llm_provider: str | None = None
    llm_model: str | None = None
    llm_base_url: str | None = None
    # Write-only. Omit to keep the stored key; send "" to clear it.
    llm_api_key: SecretStr | None = None
    fallback_llm_provider: str | None = None
    fallback_llm_model: str | None = None
    owasp_mode: str | None = None
    owasp_urls: list[str] | None = None
    nvd_mode: str | None = None
    nvd_urls: list[str] | None = None
    reference_sources: list[ReferenceSource] | None = None

    @field_validator("llm_provider")
    @classmethod
    def _known_llm_provider(cls, value):
        return _check_choice("llm_provider", value, SAST_LLM_PROVIDERS)

    @field_validator("fallback_llm_provider")
    @classmethod
    def _known_fallback_provider(cls, value):
        return _check_choice("fallback_llm_provider", value, SAST_FALLBACK_PROVIDERS)



class ProjectOut(ProjectBase):
    model_config = ConfigDict(from_attributes=True)

    id: str
    created_at: datetime
    updated_at: datetime
    limitations_config: dict[str, bool] | None = None
    # "Connect GitHub" / "Connect GitLab" status — never the token itself.
    git_provider: str | None = None
    git_connected: bool = False
    llm_api_key_set: bool = False


class ProjectDeleteOut(BaseModel):
    """Summary of what a `DELETE /projects/{id}` call actually cleaned up,
    so the frontend's delete modal can show a concrete per-step result."""

    project_id: str
    scans_deleted: int
    workspace_removed: bool
    git_disconnected: bool


_DAST_PROVIDERS = ("ollama", "bedrock", "openai", "anthropic")


class DastModelRoute(BaseModel):
    """One task's model for this scan (overrides the global routing for that task only)."""

    provider: str
    model: str = ""

    @field_validator("provider")
    @classmethod
    def _known_provider(cls, v: str) -> str:
        v = (v or "").strip().lower()
        if v not in _DAST_PROVIDERS:
            raise ValueError(f"must be one of: {', '.join(_DAST_PROVIDERS)}")
        return v


class DastIdentityIn(BaseModel):
    """One identity a scan acts as. Secret material (`password`, `token`, `storage_state`) is
    held in memory for the scan and never persisted, logged or returned; the stored scan keeps
    only the label, role, method and that a secret was supplied."""

    label: str
    role: str  # Admin | User | Viewer | Anonymous | Custom
    custom_role: str = ""
    auth_method: str = "form"  # form | token | preauth | none (Anonymous only)
    # form login
    login_url: str = ""
    username: str = ""
    password: SecretStr | None = None
    # token (bearer token, JWT or API key)
    token: SecretStr | None = None
    header_name: str = "Authorization"
    scheme: str = "Bearer"  # empty = send the token as the whole header value
    # pre-authenticated browser session (Playwright storage state JSON object)
    storage_state: SecretStr | None = None

    @field_validator("login_url")
    @classmethod
    def _http_login_url(cls, v: str) -> str:
        v = (v or "").strip()
        if v and not (v.startswith("http://") or v.startswith("https://")):
            raise ValueError("must start with http:// or https://")
        return v

    @field_validator("auth_method")
    @classmethod
    def _method(cls, v: str) -> str:
        v = (v or "").strip().lower() or "none"
        if v not in ("form", "token", "preauth", "none"):
            raise ValueError("must be one of: form, token, preauth, none")
        return v

    @field_validator("storage_state", mode="before")
    @classmethod
    def _storage_state_object(cls, v):
        # Accept the parsed JSON object or its text; keep it as a secret string either way.
        if isinstance(v, (dict, list)):
            return json.dumps(v)
        return v

    @model_validator(mode="after")
    def _method_has_its_fields(self):
        from app.dast.domain.auth import HEADER_NAME, validate_storage_state

        label = self.label
        if self.auth_method == "form":
            missing = [n for n, val in (("login_url", self.login_url), ("username", self.username), ("password", self.password)) if not val]
            if missing:
                raise ValueError(f"identity {label!r}: form login needs {', '.join(missing)}")
        elif self.auth_method == "token":
            if not self.token or not self.token.get_secret_value().strip():
                raise ValueError(f"identity {label!r}: token authentication needs a token")
            if not HEADER_NAME.match(self.header_name or ""):
                raise ValueError(f"identity {label!r}: header_name is not a valid HTTP header name")
            if any(c in self.token.get_secret_value() for c in "\r\n"):
                raise ValueError(f"identity {label!r}: the token may not contain a line break")
        elif self.auth_method == "preauth":
            if not self.storage_state:
                raise ValueError(f"identity {label!r}: a pre-authenticated identity needs a saved session (storage_state)")
            try:
                parsed = json.loads(self.storage_state.get_secret_value())
            except ValueError:
                raise ValueError(f"identity {label!r}: the saved session is not valid JSON") from None
            problems = validate_storage_state(parsed)
            if problems:
                raise ValueError(f"identity {label!r}: {problems[0]}")
        return self


class DastInput(BaseModel):
    """Inputs for a `dast` scan (see app/dast/runner.py).

    Two shapes are accepted. The original single-credential form (`login_url`, `username`,
    `password`) is a one-identity form login. The full shape lists `identities`, each with a role
    and an authentication method. Every secret is a SecretStr, never persisted on the Scan row:
    `scan_runner` holds it in memory until the scan starts."""

    target_url: str
    # --- original single-identity form login (kept working) ---
    login_url: str = ""
    username: str = ""
    password: SecretStr | None = None
    # --- identities and authorization testing ---
    identities: list[DastIdentityIn] = Field(default_factory=list, max_length=8)
    # --- budgets: None = take it from the intensity preset ---
    intensity: str = "standard"  # light | standard | deep
    max_depth: int | None = Field(default=None, ge=1, le=10)
    max_pages: int | None = Field(default=None, ge=1, le=1000)
    max_targets: int | None = Field(default=None, ge=1, le=500)
    max_tests_per_target: int | None = Field(default=None, ge=1, le=100)
    max_runtime_minutes: float | None = Field(default=None, gt=0, le=480)
    # Endpoints analysed concurrently; None = the configured default (DAST_MODEL_PARALLELISM).
    model_parallelism: int | None = Field(default=None, ge=1, le=8)
    headless: bool = True
    # --- safety ---
    # safe | opt_in_mutating (needs target_disposable). None = the configured default (safe mode on by default).
    method_policy: str | None = None
    target_disposable: bool = False
    # None = the configured default. Marker posts submit a stored-XSS probe and need a disposable target.
    browser_probe_enabled: bool | None = None
    browser_marker_posts: bool | None = None
    rate_limit_per_sec: float | None = Field(default=None, gt=0, le=100)
    # --- coverage and models ---
    rule_packs: list[str] | None = None  # exactly these packs; None = the configured defaults
    rule_overrides: dict[str, dict] | None = None  # check id -> {enabled, severity, mode}
    model_routing: dict[str, DastModelRoute] | None = None  # task -> provider/model for this scan
    # A published API description to ingest even when the fingerprint finds none.
    schema_url: str = ""
    # Explicit acknowledgement that the caller is allowed to test the target.
    authorized: bool = False

    @field_validator("target_url", "login_url", "schema_url")
    @classmethod
    def _http_url(cls, v: str) -> str:
        v = (v or "").strip()
        if v and not (v.startswith("http://") or v.startswith("https://")):
            raise ValueError("must start with http:// or https://")
        return v

    @field_validator("intensity")
    @classmethod
    def _intensity(cls, v: str) -> str:
        v = (v or "standard").strip().lower()
        if v not in ("light", "standard", "deep"):
            raise ValueError("must be one of: light, standard, deep")
        return v

    @field_validator("method_policy")
    @classmethod
    def _method_policy(cls, v: str | None) -> str | None:
        if v is None:
            return None
        v = (v or "safe").strip().lower().replace("-", "_")
        if v not in ("safe", "opt_in_mutating"):
            raise ValueError("must be one of: safe, opt_in_mutating")
        return v

    @model_validator(mode="after")
    def _one_credential_shape(self):
        legacy = bool(self.login_url or self.username or self.password)
        if self.identities and legacy:
            raise ValueError("use either the identities list or the single login_url/username/password, not both")
        return self


class ScanCreate(BaseModel):
    project_id: str
    git_url: str | None = None
    # Optional subdirectory inside the cloned workspace (engine `scope`).
    repo_path: str | None = None
    branch: str | None = None
    commit_sha: str | None = None
    metadata: dict = Field(default_factory=dict)
    force: bool = False
    # "sast" (default) | "sca" | "sbom" | "dast" — see Scan.scan_type. Selects which engine
    # adapter path runs; unrecognized values are rejected by the router.
    scan_type: str = "sast"
    # Required when scan_type == "dast".
    dast: DastInput | None = None
    # When false, skip the LLM tech-stack call and use path heuristics only.
    use_llm: bool = True
    llm_provider: str | None = None  # override project default for this scan
    llm_model: str | None = None
    fallback_llm_provider: str | None = None  # after Bedrock cutoff (ignored if primary is ollama)
    fallback_llm_model: str | None = None


class ScanTriggerOut(BaseModel):
    scan_id: str
    status: str
    status_url: str
    reused: bool = False
    reused_reason: str | None = None


class ScanOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    project_id: str
    git_url: str
    branch: str
    commit_sha: str | None = None
    status: str
    scan_type: str = "sast"
    version: int
    progress: int
    message: str | None = None
    # Who started it; None for CI scans and scans from before accounts existed.
    created_by_user_id: str | None = None
    llm_provider: str | None = None
    llm_model: str | None = None
    fallback_llm_provider: str | None = None
    fallback_llm_model: str | None = None
    triggered_by: str | None = None  # app | jenkins
    repo_path: str | None = None
    # Absolute local path of this project's checkout (workspaces_dir/<project_id>,
    # plus repo_path scope when set) — a pure string computation, not a filesystem
    # check, so it's present even for scans that never ran the real engine. Lets
    # the frontend build vscode://file/... and claude-cli://open?cwd=... deep
    # links without the browser needing to know the backend's config.
    local_root_path: str | None = None
    # DAST scans only (from `GET /scans`): confirmed findings by severity plus the unverified count, so a
    # list needs no per-scan request. None for every other scan type and for single-scan responses.
    dast_counts: dict[str, int] | None = None
    # Who started the scan: None for CI scans and scans from before accounts existed.
    created_by_user_id: str | None = None
    created_by_name: str | None = None  # display name, else email
    created_by_email: str | None = None
    created_by_deleted: bool = False  # the starter's account was deleted; name/email are kept from then
    created_at: datetime
    updated_at: datetime

    @model_validator(mode="before")
    @classmethod
    def _inject_repo_path(cls, data: Any):
        if isinstance(data, dict):
            return data
        meta = getattr(data, "metadata_json", None) or {}
        creator = getattr(data, "created_by", None)
        deleted_email = getattr(data, "deleted_creator_email", None)
        deleted_email_or_name = getattr(data, "deleted_creator_name", None) or deleted_email
        repo_path = meta.get("repo_path")
        root = Path(settings.workspaces_dir) / data.project_id
        if repo_path:
            root = root / repo_path
        return {
            "id": data.id,
            "project_id": data.project_id,
            "git_url": data.git_url,
            "branch": data.branch,
            "commit_sha": data.commit_sha,
            "status": data.status,
            "scan_type": getattr(data, "scan_type", None) or "sast",
            "version": data.version,
            "progress": data.progress,
            "message": data.message,
            "llm_provider": data.llm_provider,
            "llm_model": data.llm_model,
            "fallback_llm_provider": getattr(data, "fallback_llm_provider", None),
            "fallback_llm_model": getattr(data, "fallback_llm_model", None),
            "triggered_by": data.triggered_by,
            "repo_path": repo_path,
            "local_root_path": str(root),
            "dast_counts": getattr(data, "_dast_counts", None),
            "created_by_user_id": getattr(data, "created_by_user_id", None),
            "created_by_name": (creator.display_name or creator.email) if creator else deleted_email_or_name,
            "created_by_email": creator.email if creator else deleted_email,
            "created_by_deleted": creator is None and bool(deleted_email),
            "created_at": data.created_at,
            "updated_at": data.updated_at,
        }


class ScanStatusOut(BaseModel):
    scan_id: str
    project_id: str
    status: str
    scan_type: str = "sast"
    progress: int
    message: str | None = None
    created_by_user_id: str | None = None


class ScanLogLine(BaseModel):
    seq: int
    line: str


class ScanLogsOut(BaseModel):
    scan_id: str
    status: str
    lines: list[ScanLogLine]
    next_after: int


class ScanResultsOut(BaseModel):
    scan_id: str
    status: str
    discovery: dict | None = None
    usage_summary: dict | None = None
    # DAST only (None for other scan types): what the scan was frozen to run with at start, the
    # rule set it resolved, and the checks that could not run as designed, with reasons.
    dast_effective: dict | None = None
    dast_rule_set: dict | None = None
    dast_skipped_degraded: list[dict] | None = None


class ReviewSummaryOut(BaseModel):
    review_id: str
    reviewer_verdict: str | None = None
    is_override: bool = False
    reviewer: str | None = None
    reviewed_at: datetime | None = None
    comment: str | None = None
    resolution_status: str = "open"
    issue_status: str = "open"
    is_closed: bool = False
    learning_status: str | None = None


class FindingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    scan_id: str
    severity: str
    cvss: float | None = None
    cwe: str | None = None
    owasp_category: str | None = None
    rule_id: str | None = None
    title: str
    file_path: str | None = None
    line: int | None = None
    snippet: str | None = None
    ai_fix: str | None = None
    kind: str | None = None
    verdict: str | None = None
    confidence: float | None = None
    source: str | None = None
    sink: str | None = None
    data_flow: str | None = None
    verdict_reason: str | None = None
    # security | quality | inactive; null on findings that predate the column.
    issue_class: str | None = None
    # Why an `unverified` verdict is undecided (app.models.UNRESOLVED_REASONS).
    unresolved_reason: str | None = None
    affected_files: list[str] | None = None
    # Every file:line a merged group stands for ({file_path, line}); None for a single row.
    affected_lines: list[dict] | None = None
    # Stable per-occurrence identity (survives rescans and line shifts); a grouped
    # row lists its members' ids in `member_occurrence_ids`. `identity_quality` is
    # `exact`, or `file_level` when no enclosing method could be resolved.
    occurrence_id: str | None = None
    identity_quality: str | None = None
    member_occurrence_ids: list[str] | None = None
    # Rows this grouped finding stands for (group_findings_by_issue).
    occurrence_count: int | None = None
    matched_text: str | None = None
    flow_path: list[dict] | None = None
    reachability: dict | None = None
    triage_status: str | None = None
    assignee: str | None = None
    triage_note: str | None = None
    # `verdict` is the effective verdict (the reviewer's, when there is one); the engine's
    # original stays here. `review` is None until a reviewer has decided.
    llm_verdict: str | None = None
    review: ReviewSummaryOut | None = None


class DastTrafficOut(BaseModel):
    """What the scan sent for this finding (audit log + snippet). Response bodies live on
    `DastEvidenceOut` excerpts, not here — the audit table never stores bodies."""

    method: str = ""
    url: str = ""
    parameter: str | None = None
    location: str | None = None
    payload: str = ""
    identity_label: str | None = None
    headers: dict[str, str] | None = None
    allowed: bool | None = None
    deny_reason: str | None = None
    seq: int | None = None
    response_status: int | None = None
    response_headers: dict[str, str] | None = None


class DastEvidenceOut(BaseModel):
    """The proof behind a DAST finding: size-capped baseline and test excerpts, the detector
    signals that fired, and the request-audit sequence number of the test request."""

    model_config = ConfigDict(from_attributes=True)

    baseline_excerpt: str | None = None
    test_excerpt: str | None = None
    signals: list[dict] = Field(default_factory=list)
    audit_ref: str | None = None
    reproduction: str | None = None
    severity_source: str | None = None
    request: DastTrafficOut | None = None


class DastFindingOut(FindingOut):
    """A grouped DAST finding: `FindingOut` plus what a security engineer needs to triage it.
    Only DAST scans return this shape; SAST/SCA/SBOM responses keep `FindingOut`."""

    target: str | None = None
    param: str | None = None
    location: str | None = None
    confidence_label: str | None = None
    remediation_ref: str | None = None
    remediation: str = ""  # guidance text, not just the reference
    standards: list[str] = Field(default_factory=list)
    roles: list[str] = Field(default_factory=list)
    evidence: DastEvidenceOut | None = None

    @field_validator("standards", "roles", "remediation", mode="before")
    @classmethod
    def _none_to_empty(cls, value, info):
        # Columns the engine leaves unset come back as None; the API always returns a list/str.
        if value is None:
            return "" if info.field_name == "remediation" else []
        return value


class DastScanFindingsOut(BaseModel):
    scan_id: str
    tp_count: int
    fp_count: int
    unverified_count: int = 0
    files_scanned: int = 0
    # Counts across the whole scan, ignoring the request's filters, so a filtered view can
    # still say how much it is hiding.
    total_count: int = 0
    findings: list[DastFindingOut]


class ScanFindingsOut(BaseModel):
    scan_id: str
    tp_count: int
    fp_count: int
    # Findings from a regex match with no LLM review. Defaulted so older
    # persisted payloads and any caller not yet aware of it still validate.
    unverified_count: int = 0
    files_scanned: int = 0
    # scan_export.count_groups_by_severity over the whole scan (ignoring the
    # verdict filter): {"actionable": {sev: {groups, occurrences}},
    # "dismissed": {groups, occurrences}} — the same basis as the PDF headline.
    severity_group_counts: dict[str, Any] | None = None
    findings: list[FindingOut]


class DastRequestAuditEntryOut(BaseModel):
    """One request a DAST scan sent or was denied (`dast_request_audit`). Headers and
    bodies are redacted before they are stored. `curl` is built from that stored view."""

    model_config = ConfigDict(from_attributes=True)

    seq: int
    method: str
    url: str
    identity_label: str | None = None
    allowed: bool
    deny_reason: str | None = None
    response_status: int | None = None
    timestamp: datetime
    check_id: str | None = None
    request_headers: dict[str, str] | None = None
    response_headers: dict[str, str] | None = None
    request_body: str | None = None
    response_body: str | None = None
    curl: str = ""


class DastRequestAuditPageOut(BaseModel):
    scan_id: str
    entries: list[DastRequestAuditEntryOut]
    # Pass as `after` for the next page; None when there are no more rows.
    next_after: int | None = None


class ScanLimitationOut(BaseModel):
    id: str
    enabled_by_default: bool
    category: str
    title: str
    description: str
    affected_scope: str | None = None
    source: str | None = None


# ---- DAST authorization matrix, scan diff, report, live summary (Sprint 2) -----------------------


class DastRoleOut(BaseModel):
    name: str
    label: str = ""


class DastAuthzIdentityOut(BaseModel):
    identity_id: str
    label: str
    role: DastRoleOut


class DastAuthzCellOut(BaseModel):
    owner: str
    actor: str
    result: str  # OK | FAIL | untested
    failures: int = 0
    reason: str = ""
    finding_ids: list[str] = []
    finding_keys: list[str] = []


class DastAuthzMatrixOut(BaseModel):
    scan_id: str
    ran: bool
    identities: list[DastAuthzIdentityOut]
    baseline_identity: str
    replays: int
    degraded: bool
    degraded_reason: str = ""
    cells: list[DastAuthzCellOut]


# --- reviewer feedback ---------------------------------------------------------------------


class ReviewIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    decision: Literal["confirmed_issue", "false_positive", "needs_more_info", "resolved", "accept_risk"]
    # Ignored: the signed-in user is recorded as the reviewer. Accepted so
    # older clients that still send it keep working.
    reviewer: str | None = Field(default=None, max_length=120)
    comment: str | None = Field(default=None, max_length=5000)
    resolution_notes: str | None = Field(default=None, max_length=5000)


class ReviewEventOut(BaseModel):
    id: str
    at: datetime
    actor: str
    action: str
    from_verdict: str | None = None
    to_verdict: str | None = None
    from_resolution: str | None = None
    to_resolution: str | None = None
    comment: str | None = None
    detail: dict | None = None


class FeedbackRowOut(BaseModel):
    """One issue group with its LLM result and, once reviewed, the reviewer's decision."""

    review_id: str | None = None
    scan_id: str
    project_id: str | None = None
    finding_id: str
    rule_id: str | None = None
    cwe: str | None = None
    severity: str | None = None
    confidence: float | None = None
    file_path: str | None = None
    line: int | None = None
    title: str | None = None
    kind: str | None = None
    snippet: str | None = None
    occurrence_count: int | None = None
    llm_verdict: str | None = None
    llm_explanation: str | None = None
    llm_remediation: str | None = None
    reviewer_verdict: str | None = None
    is_override: bool = False
    reviewer_comment: str | None = None
    reviewer: str | None = None
    reviewed_at: datetime | None = None
    last_reviewed_at: datetime | None = None
    review_status: str = "unreviewed"
    resolution_status: str = "open"
    resolution_notes: str | None = None
    resolved_by: str | None = None
    resolved_at: datetime | None = None
    issue_status: str = "open"
    is_closed: bool = False
    learning_status: str | None = None
    learning_approved_by: str | None = None
    learning_approved_at: datetime | None = None
    learning_processed_at: datetime | None = None
    events: list[ReviewEventOut] = Field(default_factory=list)


class FeedbackListOut(BaseModel):
    total: int
    limit: int
    offset: int
    items: list[FeedbackRowOut]


class LearningActionIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    review_ids: list[str] = Field(min_length=1, max_length=5000)
    actor: str | None = Field(default=None, max_length=120)  # ignored: the signed-in user is recorded


class LearningActionOut(BaseModel):
    updated: int
    skipped: int
