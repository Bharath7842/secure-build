import uuid
from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Index, Integer, JSON, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def utcnow():
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


class Project(Base):
    __tablename__ = "projects"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name: Mapped[str] = mapped_column(String(200), unique=True, index=True)
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
    # "allow_external" or "local_only" — the latter refuses any provider that
    # would send repository code off localhost/private networks.
    llm_data_policy: Mapped[str] = mapped_column(String(20), default="allow_external")
    # After spend hits the soft cutoff, continue on this provider/model;
    # "none" stops LLM work and leaves the rest unverified. Ignored when
    # llm_provider is ollama.
    fallback_llm_provider: Mapped[str] = mapped_column(String(20), default="none")
    fallback_llm_model: Mapped[str] = mapped_column(String(200), default="")
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
    # openai_compat endpoint and data policy in force for this scan (the API
    # key is deliberately not snapshotted — it is read from the project).
    llm_base_url: Mapped[str | None] = mapped_column(String(500), nullable=True)
    llm_data_policy: Mapped[str | None] = mapped_column(String(20), nullable=True)
    # Who triggered the scan: "app" (Secure Build UI) or "jenkins" (CI).
    triggered_by: Mapped[str | None] = mapped_column(String(20), nullable=True)
    metadata_json: Mapped[dict] = mapped_column("metadata", JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)
    project: Mapped["Project"] = relationship(back_populates="scans")
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
