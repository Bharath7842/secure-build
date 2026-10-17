import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    JSON,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def utcnow():
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


class Project(Base):
    __tablename__ = "projects"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name: Mapped[str] = mapped_column(String(500), unique=True, index=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    languages: Mapped[list] = mapped_column(JSON, default=list)
    frameworks: Mapped[list] = mapped_column(JSON, default=list)
    build_tool: Mapped[str | None] = mapped_column(String(80), nullable=True)
    default_git_url: Mapped[str] = mapped_column(String(500))
    default_branch: Mapped[str] = mapped_column(String(200), default="main")
    monorepo_path: Mapped[str | None] = mapped_column(String(300), nullable=True)
    # "Connect GitHub" / "Connect GitLab" OAuth — set once the project owner
    # authorizes access; used to clone private repos. Never serialized back
    # to the client (see ProjectOut) — only git_provider/git_connected are.
    git_provider: Mapped[str | None] = mapped_column(String(20), nullable=True)  # "github" | "gitlab"
    git_access_token: Mapped[str | None] = mapped_column(String(500), nullable=True)
    git_refresh_token: Mapped[str | None] = mapped_column(String(500), nullable=True)
    git_token_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    enable_sast: Mapped[bool] = mapped_column(Boolean, default=True)
    enable_sca: Mapped[bool] = mapped_column(Boolean, default=True)
    enable_sbom: Mapped[bool] = mapped_column(Boolean, default=True)
    enable_secrets: Mapped[bool] = mapped_column(Boolean, default=False)
    # Who created the project. Users see and change only their own; NULL (projects
    # from before ownership existed) is visible to admins alone.
    created_by_user_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"), nullable=True, index=True)
    scan_mode: Mapped[str] = mapped_column(String(20), default="full")  # always full
    max_files_to_scan: Mapped[int] = mapped_column(Integer, default=0)  # 0 = entire repo
    # Hard caps on LLM-derived (OWASP-driven) regex/Semgrep rules per scan.
    max_derived_regex_rules: Mapped[int] = mapped_column(Integer, default=50)
    max_derived_semgrep_rules: Mapped[int] = mapped_column(Integer, default=20)
    # Which LLM backend scans call: bedrock (Claude), openai_compat (any
    # OpenAI-compatible /chat/completions server, local or hosted) or ollama.
    llm_provider: Mapped[str] = mapped_column(String(20), default="bedrock")
    llm_model: Mapped[str] = mapped_column(
        String(200), default="us.anthropic.claude-haiku-4-5-20251001-v1:0"
    )
    # openai_compat endpoint; None = settings.openai_compat_base_url.
    llm_base_url: Mapped[str | None] = mapped_column(String(500), nullable=True)
    # Write-only, like git_access_token: never returned (ProjectOut only
    # exposes llm_api_key_set) and never snapshotted onto a Scan row.
    llm_api_key: Mapped[str | None] = mapped_column(String(500), nullable=True)
    # After spend hits the soft cutoff, continue on this provider/model;
    # "none" stops LLM work and leaves the rest unverified. Ignored when
    # llm_provider is ollama.
    fallback_llm_provider: Mapped[str] = mapped_column(String(20), default="ollama")
    fallback_llm_model: Mapped[str] = mapped_column(String(200), default="granite-code:3b-instruct")
    owasp_mode: Mapped[str] = mapped_column(String(20), default="top10")  # top10|top15|custom
    owasp_urls: Mapped[list] = mapped_column(JSON, default=list)
    nvd_mode: Mapped[str] = mapped_column(String(20), default="top10")  # top10|top15|custom
    nvd_urls: Mapped[list] = mapped_column(JSON, default=list)
    # Dynamic list: [{key, name, mode, urls}] — OWASP/NVD/MITRE/CISA/Custom…
    reference_sources: Mapped[list] = mapped_column(JSON, default=list)
    # Scan limitation toggles: {limitation_id: enabled} mapping (default: all enabled)
    limitations_config: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    # DAST rule-set defaults for this project: {"packs": {pack_id: bool}, "checks": {check_id: {...}}}.
    # None = inherit the global defaults (DAST-03-040).
    dast_rules_config: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    # Training-data capture (DAST-16-050): off by default, switched on per project by an authorized operator.
    training_capture_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    # CI gate: None means the gate stays informational (gate_failed is false).
    gate_max_critical: Mapped[int | None] = mapped_column(Integer, nullable=True)
    gate_max_high: Mapped[int | None] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)
    scans: Mapped[list["Scan"]] = relationship(back_populates="project")

    @property
    def git_connected(self) -> bool:
        return bool(self.git_access_token)

    @property
    def llm_api_key_set(self) -> bool:
        return bool(self.llm_api_key)


class Scan(Base):
    __tablename__ = "scans"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id"), index=True)
    git_url: Mapped[str] = mapped_column(String(500))
    branch: Mapped[str] = mapped_column(String(200), default="main")
    commit_sha: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    status: Mapped[str] = mapped_column(String(20), default="queued")  # queued|running|success|failed
    # "sast" (default, LangGraph discovery+LLM engine) | "sca" (deterministic
    # manifest-parsing + OSV.dev lookup, see sast_engine/pipeline/sca_scan.py)
    # | "sbom" (deterministic CycloneDX/SPDX component inventory + license
    # classification, see sast_engine/pipeline/sbom_scan.py).
    scan_type: Mapped[str] = mapped_column(String(20), default="sast")
    version: Mapped[int] = mapped_column(Integer, default=1)  # sequential per project_id, 1-based
    progress: Mapped[int] = mapped_column(Integer, default=0)
    message: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Snapshot of the project's LLM at scan start (history must not drift if
    # the project later switches Haiku <-> granite-code:3b).
    llm_provider: Mapped[str | None] = mapped_column(String(20), nullable=True)
    llm_model: Mapped[str | None] = mapped_column(String(200), nullable=True)
    fallback_llm_provider: Mapped[str | None] = mapped_column(String(20), nullable=True)
    fallback_llm_model: Mapped[str | None] = mapped_column(String(200), nullable=True)
    # openai_compat endpoint in force for this scan (the API
    # key is deliberately not snapshotted — it is read from the project).
    llm_base_url: Mapped[str | None] = mapped_column(String(500), nullable=True)
    # Who triggered the scan: "app" (Secure Build UI) or "jenkins" (CI).
    triggered_by: Mapped[str | None] = mapped_column(String(20), nullable=True)
    # The signed-in user who started the scan. None for CI-triggered scans and
    # scans from before accounts existed — those are visible only to admins
    # and users granted scans.view_all.
    created_by_user_id: Mapped[str | None] = mapped_column(
        ForeignKey("users.id"), nullable=True, index=True
    )
    # Set when that user is deleted, so the scan still says who started it.
    deleted_creator_name: Mapped[str | None] = mapped_column(String(254), nullable=True)
    deleted_creator_email: Mapped[str | None] = mapped_column(String(254), nullable=True)
    metadata_json: Mapped[dict] = mapped_column("metadata", JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)
    project: Mapped["Project"] = relationship(back_populates="scans")
    created_by: Mapped["User | None"] = relationship(foreign_keys=[created_by_user_id])
    findings: Mapped[list["Finding"]] = relationship(back_populates="scan")


# Verdict recorded for findings that came straight from a regex match with no
# LLM review (the default MEDIUM/LOW triage mode). Deliberately distinct from
# both true_positive (which would let pattern noise pose as confirmed
# vulnerabilities) and false_positive (which would hide real ones).
UNVERIFIED_VERDICT = "unverified"

# `Scan.metadata_json` key holding a DAST scan's effective settings (budgets,
# rate limit, safe mode, model routing — no secrets), snapshotted at scan start
# so history and diffs stay valid when configuration later changes. See
# `Settings.dast_effective_settings()`.
DAST_SETTINGS_SNAPSHOT_KEY = "dast_settings"


class Finding(Base):
    __tablename__ = "findings"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id"), index=True)
    severity: Mapped[str] = mapped_column(String(20))
    cvss: Mapped[float | None] = mapped_column(Float, nullable=True)
    cwe: Mapped[str | None] = mapped_column(String(40), nullable=True)
    owasp_ref: Mapped[str | None] = mapped_column(String(500), nullable=True)
    rule_id: Mapped[str | None] = mapped_column(String(80), nullable=True)
    title: Mapped[str] = mapped_column(String(500))
    file_path: Mapped[str | None] = mapped_column(String(500), nullable=True)
    line: Mapped[int | None] = mapped_column(Integer, nullable=True)
    snippet: Mapped[str | None] = mapped_column(Text, nullable=True)
    ai_fix: Mapped[str | None] = mapped_column(Text, nullable=True)
    kind: Mapped[str | None] = mapped_column(String(40), nullable=True)  # taint|secrets|sca|regex
    flow_path: Mapped[list | None] = mapped_column(JSON, nullable=True)
    # Joern source->sink path reaching this finding's sink (sast_engine
    # pipeline/reachability.py): {status, sink_kind, source, sink, taint_path,
    # sanitizers, guards}. Evidence only — never set on a finding Joern found
    # no path to.
    reachability: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    verdict: Mapped[str | None] = mapped_column(String(40), nullable=True)
    confidence: Mapped[float | None] = mapped_column(Float, nullable=True)
    # LLM-traced taint path (untrusted input expression → dangerous sink).
    source: Mapped[str | None] = mapped_column(String(300), nullable=True)
    sink: Mapped[str | None] = mapped_column(String(300), nullable=True)
    data_flow: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Why the LLM called this verdict (true or false positive) — separate from ai_fix,
    # which is remediation guidance.
    verdict_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Collapsed multi-file issues (e.g. path findings) list every affected location.
    affected_files: Mapped[list | None] = mapped_column(JSON, nullable=True)
    # The bare text a regex rule matched, kept separate from `snippet` (which
    # holds the surrounding context window). Grouping keys off this so the same
    # construct collapses across files while genuinely different code does not.
    matched_text: Mapped[str | None] = mapped_column(String(500), nullable=True)
    # Denormalized from RegexRule.group_by_rule at write time so report/export
    # grouping (scan_export._finding_group_key) never needs sast_engine's rule
    # catalog. True collapses this finding's group by rule_id alone, ignoring
    # matched_text — for rules whose match text is expected to vary every
    # occurrence (e.g. a class name) while still describing one issue.
    group_by_rule: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    owasp_category: Mapped[str | None] = mapped_column(String(64), nullable=True)
    exploitability: Mapped[float | None] = mapped_column(Float, nullable=True)
    root_cause_id: Mapped[str | None] = mapped_column(String(40), nullable=True)
    # Batched LLM report fields (Risk / Example Fix)
    risk: Mapped[str | None] = mapped_column(Text, nullable=True)
    example_fix: Mapped[str | None] = mapped_column(Text, nullable=True)
    # --- DAST fields (all nullable; SAST/SCA/SBOM rows leave them empty) ---
    target: Mapped[str | None] = mapped_column(String(300), nullable=True)  # "METHOD path"
    param: Mapped[str | None] = mapped_column(String(200), nullable=True)
    location: Mapped[str | None] = mapped_column(String(20), nullable=True)  # query|path|header|body|response
    # HIGH|MEDIUM|LOW. Kept apart from the float `confidence` above, which the SAST path owns.
    confidence_label: Mapped[str | None] = mapped_column(String(10), nullable=True)
    remediation_ref: Mapped[str | None] = mapped_column(String(120), nullable=True)
    standards: Mapped[list | None] = mapped_column(JSON, nullable=True)  # e.g. ["OWASP A03:2021", "CWE-89"]
    first_seen_scan_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    last_seen_scan_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    # Role labels involved in an authorization finding (e.g. ["user", "admin"]); None otherwise.
    roles: Mapped[list | None] = mapped_column(JSON, nullable=True)
    # Human triage. Null status means still open. Shared by SAST and DAST rows.
    triage_status: Mapped[str | None] = mapped_column(String(32), nullable=True)
    assignee: Mapped[str | None] = mapped_column(String(120), nullable=True)
    triage_note: Mapped[str | None] = mapped_column(Text, nullable=True)
    scan: Mapped["Scan"] = relationship(back_populates="findings")


class DastGlobalConfig(Base):
    """Global DAST configuration, one JSON document per key (e.g. key="rules" holds the
    global rule-set defaults, DAST-03-040). Small and rarely written, so a key/value table
    rather than a column per setting."""

    __tablename__ = "dast_global_config"
    key: Mapped[str] = mapped_column(String(80), primary_key=True)
    value: Mapped[dict] = mapped_column(JSON, default=dict)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class AppSetting(Base):
    """App-wide setting, one JSON document per key (e.g. key="hidden_models" holds the model
    keys hidden from the model selects). Small and rarely written, so a key/value table."""

    __tablename__ = "app_settings"
    key: Mapped[str] = mapped_column(String(80), primary_key=True)
    value: Mapped[dict] = mapped_column(JSON, default=dict)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class DastCustomRule(Base):
    """A user-supplied check (YAML, same schema as a catalog check), versioned (DAST-03-050).
    Scans snapshot the definition they ran with, so deleting or editing a rule never rewrites
    history."""

    __tablename__ = "dast_custom_rules"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    check_id: Mapped[str] = mapped_column(String(80), unique=True, index=True)
    version: Mapped[int] = mapped_column(Integer, default=1)
    yaml_text: Mapped[str] = mapped_column(Text)
    # The parsed, validated definition the YAML produced (what a scan snapshots).
    definition: Mapped[dict] = mapped_column(JSON, default=dict)
    # Why a rule was downgraded to assist-only on save, if it was.
    notes: Mapped[list | None] = mapped_column(JSON, nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class DastTrainingExample(Base):
    """One scrubbed `{task, input, output}` record captured from an authorized scan (DAST-16-050).
    Holds no hostname, address, credential, token or identifier (see `domain.training`)."""

    __tablename__ = "dast_training_examples"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    project_id: Mapped[str] = mapped_column(String(36), index=True)
    scan_id: Mapped[str] = mapped_column(String(36), index=True)
    task: Mapped[str] = mapped_column(String(20))  # rule | construct
    label: Mapped[str] = mapped_column(String(20), index=True)  # fail | pass | inconclusive
    example: Mapped[dict] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class DastTrainingAudit(Base):
    """Every attempt to read or administer training data, allowed or denied."""

    __tablename__ = "dast_training_audit"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    reader: Mapped[str] = mapped_column(String(120))
    action: Mapped[str] = mapped_column(String(40))  # list | export | enable | disable
    allowed: Mapped[bool] = mapped_column(Boolean)
    detail: Mapped[str] = mapped_column(String(300), default="")
    count: Mapped[int] = mapped_column(Integer, default=0)


class DastEvidence(Base):
    """The observable proof behind one DAST finding. Deleted with the finding
    (DB-level ON DELETE CASCADE — findings are bulk-deleted without the ORM)."""

    __tablename__ = "dast_evidence"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    finding_id: Mapped[str] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"), index=True
    )
    baseline_excerpt: Mapped[str | None] = mapped_column(Text, nullable=True)
    test_excerpt: Mapped[str | None] = mapped_column(Text, nullable=True)
    reproduction: Mapped[str | None] = mapped_column(Text, nullable=True)
    severity_source: Mapped[str | None] = mapped_column(String(40), nullable=True)
    # Named detector signals that proved the finding: [{"name": ..., "detail": ...}].
    signals: Mapped[list | None] = mapped_column(JSON, nullable=True)
    # Pointer into `dast_request_audit`, as "<seq>" for the scan the finding belongs to.
    audit_ref: Mapped[str | None] = mapped_column(String(80), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class DastRequestAudit(Base):
    """Every request a DAST scan sent (or refused to send) to the target — the
    durable record behind the safety guard. Covers requests that produced no
    finding, which is why it is not folded into evidence."""

    __tablename__ = "dast_request_audit"
    __table_args__ = (Index("ix_dast_request_audit_scan_seq", "scan_id", "seq", unique=True),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"))
    seq: Mapped[int] = mapped_column(Integer)  # 1-based, per scan
    method: Mapped[str] = mapped_column(String(10))
    url: Mapped[str] = mapped_column(String(2000))
    identity_label: Mapped[str | None] = mapped_column(String(120), nullable=True)
    allowed: Mapped[bool] = mapped_column(Boolean)
    deny_reason: Mapped[str | None] = mapped_column(String(80), nullable=True)
    response_status: Mapped[int | None] = mapped_column(Integer, nullable=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    check_id: Mapped[str | None] = mapped_column(String(80), nullable=True)
    # Header maps with credential values redacted before they reach this table; request and
    # response *bodies* are never stored. See `app.dast.domain.redaction`.
    request_headers: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    response_headers: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    # Redacted, size-capped bodies. Older rows leave these null.
    request_body: Mapped[str | None] = mapped_column(Text, nullable=True)
    response_body: Mapped[str | None] = mapped_column(Text, nullable=True)


class FindingTriageEvent(Base):
    """One human change to a finding: status, assignee, or note."""

    __tablename__ = "finding_triage_events"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    finding_id: Mapped[str] = mapped_column(ForeignKey("findings.id", ondelete="CASCADE"), index=True)
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    actor: Mapped[str] = mapped_column(String(120), default="")
    action: Mapped[str] = mapped_column(String(40))
    detail: Mapped[str] = mapped_column(String(500), default="")


class FindingReview(Base):
    """A reviewer's decision on one issue group of a scan.

    Reviewer state lives here, never on `Finding`: the engine's verdict writers and
    the reconcile sweep UPDATE `findings.verdict` in place, and the original LLM
    result must stay intact. The `llm_*` columns and the identifying fields are a
    snapshot written once at the first review. `scan_id` is deliberately not a
    foreign key, so labelled data survives deleting the scan.
    """

    __tablename__ = "finding_reviews"
    __table_args__ = (Index("uq_finding_reviews_scan_fp", "scan_id", "fingerprint", unique=True),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id: Mapped[str] = mapped_column(String(36), index=True)
    project_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    finding_id: Mapped[str] = mapped_column(String(36), index=True)  # the group's representative
    fingerprint: Mapped[str] = mapped_column(String(64))
    member_finding_ids: Mapped[list | None] = mapped_column(JSON, nullable=True)
    occurrence_count: Mapped[int] = mapped_column(Integer, default=1)

    # Snapshot of the LLM result, never updated after creation.
    rule_id: Mapped[str | None] = mapped_column(String(80), nullable=True, index=True)
    cwe: Mapped[str | None] = mapped_column(String(40), nullable=True, index=True)
    severity: Mapped[str | None] = mapped_column(String(20), nullable=True)
    confidence: Mapped[float | None] = mapped_column(Float, nullable=True)
    file_path: Mapped[str | None] = mapped_column(String(500), nullable=True)
    line: Mapped[int | None] = mapped_column(Integer, nullable=True)
    kind: Mapped[str | None] = mapped_column(String(40), nullable=True)
    title: Mapped[str | None] = mapped_column(String(500), nullable=True)
    snippet: Mapped[str | None] = mapped_column(Text, nullable=True)
    matched_text: Mapped[str | None] = mapped_column(String(500), nullable=True)
    llm_verdict: Mapped[str | None] = mapped_column(String(40), nullable=True, index=True)
    llm_explanation: Mapped[str | None] = mapped_column(Text, nullable=True)
    llm_remediation: Mapped[str | None] = mapped_column(Text, nullable=True)
    snapshot_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    # Reviewer decision.
    reviewer_verdict: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    is_override: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    reviewer_comment: Mapped[str | None] = mapped_column(Text, nullable=True)
    reviewer: Mapped[str | None] = mapped_column(String(120), nullable=True, index=True)
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    last_reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Resolution of a confirmed issue.
    resolution_status: Mapped[str] = mapped_column(String(20), default="open", index=True)
    resolution_notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    resolved_by: Mapped[str | None] = mapped_column(String(120), nullable=True)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    issue_status: Mapped[str] = mapped_column(String(32), default="open", index=True)
    is_closed: Mapped[bool] = mapped_column(Boolean, default=False, index=True)

    # Labelled-data lifecycle for the learning phase.
    learning_status: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    learning_approved_by: Mapped[str | None] = mapped_column(String(120), nullable=True)
    learning_approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    learning_processed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    events: Mapped[list["FindingReviewEvent"]] = relationship(
        back_populates="review", cascade="all, delete-orphan", order_by="FindingReviewEvent.at"
    )


class FindingReviewEvent(Base):
    """Append-only history of a review: every verdict change, resolution and learning-state move."""

    __tablename__ = "finding_review_events"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    review_id: Mapped[str] = mapped_column(ForeignKey("finding_reviews.id", ondelete="CASCADE"), index=True)
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    actor: Mapped[str] = mapped_column(String(120), default="")
    action: Mapped[str] = mapped_column(String(40))
    from_verdict: Mapped[str | None] = mapped_column(String(32), nullable=True)
    to_verdict: Mapped[str | None] = mapped_column(String(32), nullable=True)
    from_resolution: Mapped[str | None] = mapped_column(String(20), nullable=True)
    to_resolution: Mapped[str | None] = mapped_column(String(20), nullable=True)
    comment: Mapped[str | None] = mapped_column(Text, nullable=True)
    detail: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    review: Mapped[FindingReview] = relationship(back_populates="events")


class DastSchedule(Base):
    """A repeating DAST scan. `request_json` is a secret-free ScanCreate body (no passwords)."""

    __tablename__ = "dast_schedules"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    project_id: Mapped[str] = mapped_column(String(36), index=True)
    name: Mapped[str] = mapped_column(String(200))
    interval_minutes: Mapped[int] = mapped_column(Integer, default=1440)
    request_json: Mapped[dict] = mapped_column(JSON, default=dict)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    next_run_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_scan_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    # Each run is owned by, and permission-checked against, this user.
    created_by_user_id: Mapped[str | None] = mapped_column(
        ForeignKey("users.id"), nullable=True, index=True
    )


class FileSnapshot(Base):
    __tablename__ = "file_snapshots"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id"), index=True)
    path: Mapped[str] = mapped_column(String(700))
    content_hash: Mapped[str] = mapped_column(String(64))
    commit_sha: Mapped[str | None] = mapped_column(String(64), nullable=True)


class LlmResultCache(Base):
    """A validated LLM response, reused verbatim by later scans of the same
    project when the exact same prompt is sent to the same model.

    `key` hashes the full system + user prompt, provider/model, generation
    parameters and llm_client.RESULT_CACHE_VERSION — any change to the code
    under review, its context, the rule catalog or the prompt wording yields
    a different key, so there is no separate invalidation step. Only complete,
    untruncated JSON responses are stored (llm_client.is_complete_json_response)."""

    __tablename__ = "llm_result_cache"
    __table_args__ = (Index("ix_llm_result_cache_project_key", "project_id", "key", unique=True),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id"), index=True)
    key: Mapped[str] = mapped_column(String(64))
    step: Mapped[str] = mapped_column(String(80), default="")
    model: Mapped[str] = mapped_column(String(200), default="")
    response_text: Mapped[str] = mapped_column(Text)
    input_tokens: Mapped[int] = mapped_column(Integer, default=0)
    output_tokens: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    hit_count: Mapped[int] = mapped_column(Integer, default=0)


# --- Accounts, sessions and audit ---------------------------------------------
# Roles and the permission catalog live in code (app/authz/catalog.py); the
# database only stores each user's role and their per-permission overrides.
USER_ROLES = ("admin", "user")


class User(Base):
    """A person who signs in. Disabling keeps their scans, reviews and audit
    history attributable; an admin may delete a disabled account, which clears
    the owner on their scans (see admin_users.delete_user)."""

    __tablename__ = "users"
    __table_args__ = (CheckConstraint("role IN ('admin', 'user')", name="ck_users_role"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    email: Mapped[str] = mapped_column(String(254))  # as typed, for display
    # app.auth.passwords.normalize_email(email); lookups and uniqueness use this.
    email_normalized: Mapped[str] = mapped_column(String(254), unique=True, index=True)
    display_name: Mapped[str] = mapped_column(String(120), default="")
    role: Mapped[str] = mapped_column(String(16), default="user", index=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    # None until the user accepts their invite; such a user cannot sign in.
    password_hash: Mapped[str | None] = mapped_column(String(255), nullable=True)
    password_changed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    failed_login_count: Mapped[int] = mapped_column(Integer, default=0)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)
    created_by_user_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    disabled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    disabled_by_user_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    permission_overrides: Mapped[list["UserPermissionOverride"]] = relationship(
        back_populates="user",
        cascade="all, delete-orphan",
        foreign_keys="UserPermissionOverride.user_id",
    )

    @property
    def status(self) -> str:
        """"disabled", "invited" (no password set yet) or "active"."""
        if not self.is_active:
            return "disabled"
        return "active" if self.password_hash else "invited"

    @property
    def overrides(self) -> dict[str, str]:
        """{permission_key: "grant" | "deny"}."""
        return {o.permission_key: o.effect for o in self.permission_overrides}


class UserPermissionOverride(Base):
    """A per-user change to the role's default for one permission. One row per
    key, so a grant and a deny can never conflict; deleting the row restores
    the role default."""

    __tablename__ = "user_permission_overrides"
    __table_args__ = (
        UniqueConstraint("user_id", "permission_key", name="uq_user_permission_overrides_user_key"),
        CheckConstraint("effect IN ('grant', 'deny')", name="ck_user_permission_overrides_effect"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    permission_key: Mapped[str] = mapped_column(String(64))
    effect: Mapped[str] = mapped_column(String(8))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    created_by_user_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    user: Mapped["User"] = relationship(back_populates="permission_overrides", foreign_keys=[user_id])


class UserSession(Base):
    """A signed-in browser. Only the SHA-256 of the session token is stored, so
    a copy of the database holds no usable sessions."""

    __tablename__ = "user_sessions"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    remember: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    # Pushed forward on use; None for "remember me" sessions, which only
    # expire at absolute_expires_at.
    idle_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    absolute_expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_reason: Mapped[str | None] = mapped_column(String(40), nullable=True)
    ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(256), nullable=True)
    user: Mapped["User"] = relationship()


class UserToken(Base):
    """A single-use invite or password-reset link. Stored hashed, like sessions."""

    __tablename__ = "user_tokens"
    __table_args__ = (CheckConstraint("purpose IN ('invite', 'reset')", name="ck_user_tokens_purpose"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    purpose: Mapped[str] = mapped_column(String(16))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    created_by_user_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"), nullable=True)


class AuditEvent(Base):
    """Sign-ins, account and permission changes, and important scan actions.
    `details` never holds passwords, tokens or other secrets
    (app.services.audit drops secret-looking keys before writing)."""

    __tablename__ = "audit_events"
    __table_args__ = (Index("ix_audit_events_target", "target_type", "target_id"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    actor_user_id: Mapped[str | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )
    # Email at the time of the event, "ci-token" or "system".
    actor_label: Mapped[str] = mapped_column(String(254), default="")
    action: Mapped[str] = mapped_column(String(64), index=True)  # e.g. auth.login.failed
    outcome: Mapped[str] = mapped_column(String(16), default="success")  # success | failure | denied
    target_type: Mapped[str | None] = mapped_column(String(32), nullable=True)
    target_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(256), nullable=True)
    details: Mapped[dict] = mapped_column(JSON, default=dict)
