from sqlalchemy import create_engine, event, inspect, text
from sqlalchemy.orm import sessionmaker

from app.config import settings
from app.models import Base

engine = None
SessionLocal = None


def _drop_data_policy_columns(engine) -> None:
    """The per-project "code sharing" policy was removed. Drop its columns from
    databases created before that; SQLite 3.35+ supports DROP COLUMN."""
    inspector = inspect(engine)
    for table in ("projects", "scans"):
        if table not in inspector.get_table_names():
            continue
        if "llm_data_policy" in {col["name"] for col in inspector.get_columns(table)}:
            with engine.begin() as conn:
                conn.execute(text(f"ALTER TABLE {table} DROP COLUMN llm_data_policy"))


def _run_light_migrations(engine) -> None:
    """`Base.metadata.create_all` only creates *missing tables* — it never
    alters an existing one, so columns added to a model after a DB already
    exists (e.g. `Scan.version`) need a manual, idempotent ADD COLUMN here.
    No alembic in this project; this is intentionally minimal."""
    inspector = inspect(engine)
    table_names = set(inspector.get_table_names())

    if "projects" in table_names:
        project_cols = {col["name"] for col in inspector.get_columns("projects")}
        if "created_by_user_id" not in project_cols:
            with engine.begin() as conn:
                conn.execute(text("ALTER TABLE projects ADD COLUMN created_by_user_id VARCHAR(36)"))

    if "scans" in table_names:
        existing_cols = {col["name"] for col in inspector.get_columns("scans")}
        if "version" not in existing_cols:
            with engine.begin() as conn:
                conn.execute(text("ALTER TABLE scans ADD COLUMN version INTEGER DEFAULT 1"))

            with engine.begin() as conn:
                rows = conn.execute(
                    text("SELECT id, project_id FROM scans ORDER BY project_id, created_at, id")
                ).fetchall()
                counters: dict[str, int] = {}
                for scan_id, project_id in rows:
                    counters[project_id] = counters.get(project_id, 0) + 1
                    conn.execute(
                        text("UPDATE scans SET version = :v WHERE id = :sid"),
                        {"v": counters[project_id], "sid": scan_id},
                    )
        for col in ("deleted_creator_name", "deleted_creator_email"):
            if col not in existing_cols:
                with engine.begin() as conn:
                    conn.execute(text(f"ALTER TABLE scans ADD COLUMN {col} VARCHAR(254)"))
        if "llm_provider" not in existing_cols:
            with engine.begin() as conn:
                conn.execute(text("ALTER TABLE scans ADD COLUMN llm_provider VARCHAR(20)"))
        if "llm_model" not in existing_cols:
            with engine.begin() as conn:
                conn.execute(text("ALTER TABLE scans ADD COLUMN llm_model VARCHAR(200)"))
        if "fallback_llm_provider" not in existing_cols:
            with engine.begin() as conn:
                conn.execute(text("ALTER TABLE scans ADD COLUMN fallback_llm_provider VARCHAR(20)"))
        if "fallback_llm_model" not in existing_cols:
            with engine.begin() as conn:
                conn.execute(text("ALTER TABLE scans ADD COLUMN fallback_llm_model VARCHAR(200)"))
        if "llm_base_url" not in existing_cols:
            with engine.begin() as conn:
                conn.execute(text("ALTER TABLE scans ADD COLUMN llm_base_url VARCHAR(500)"))
        if "triggered_by" not in existing_cols:
            with engine.begin() as conn:
                conn.execute(text("ALTER TABLE scans ADD COLUMN triggered_by VARCHAR(20)"))
        if "scan_type" not in existing_cols:
            with engine.begin() as conn:
                conn.execute(
                    text("ALTER TABLE scans ADD COLUMN scan_type VARCHAR(20) DEFAULT 'sast'")
                )

    # Owner columns. SQLite cannot add a foreign key with ALTER TABLE, so an
    # existing DB gets a plain indexed column; fresh DBs get the real FK from
    # create_all. Users are only ever disabled, never deleted.
    for table in ("scans", "dast_schedules"):
        if table in table_names:
            cols = {col["name"] for col in inspector.get_columns(table)}
            if "created_by_user_id" not in cols:
                with engine.begin() as conn:
                    conn.execute(text(f"ALTER TABLE {table} ADD COLUMN created_by_user_id VARCHAR(36)"))
                    conn.execute(
                        text(
                            f"CREATE INDEX IF NOT EXISTS ix_{table}_created_by_user_id "
                            f"ON {table} (created_by_user_id)"
                        )
                    )

    if "findings" in table_names:
        finding_cols = {col["name"] for col in inspector.get_columns("findings")}
        for col_name, col_sql in (
            ("kind", "ALTER TABLE findings ADD COLUMN kind VARCHAR(40)"),
            ("flow_path", "ALTER TABLE findings ADD COLUMN flow_path JSON"),
            ("reachability", "ALTER TABLE findings ADD COLUMN reachability JSON"),
            ("verdict", "ALTER TABLE findings ADD COLUMN verdict VARCHAR(40)"),
            ("confidence", "ALTER TABLE findings ADD COLUMN confidence FLOAT"),
            ("source", "ALTER TABLE findings ADD COLUMN source VARCHAR(300)"),
            ("sink", "ALTER TABLE findings ADD COLUMN sink VARCHAR(300)"),
            ("data_flow", "ALTER TABLE findings ADD COLUMN data_flow TEXT"),
            ("verdict_reason", "ALTER TABLE findings ADD COLUMN verdict_reason TEXT"),
            ("affected_files", "ALTER TABLE findings ADD COLUMN affected_files JSON"),
            ("owasp_category", "ALTER TABLE findings ADD COLUMN owasp_category VARCHAR(10)"),
            ("exploitability", "ALTER TABLE findings ADD COLUMN exploitability FLOAT"),
            ("root_cause_id", "ALTER TABLE findings ADD COLUMN root_cause_id VARCHAR(40)"),
            ("risk", "ALTER TABLE findings ADD COLUMN risk TEXT"),
            ("example_fix", "ALTER TABLE findings ADD COLUMN example_fix TEXT"),
            ("matched_text", "ALTER TABLE findings ADD COLUMN matched_text VARCHAR(500)"),
            ("group_by_rule", "ALTER TABLE findings ADD COLUMN group_by_rule BOOLEAN"),
            # DAST evidence fields (DAST-00-040); the new dast_evidence / dast_request_audit
            # tables are created by Base.metadata.create_all, so only columns need ALTER.
            ("target", "ALTER TABLE findings ADD COLUMN target VARCHAR(300)"),
            ("param", "ALTER TABLE findings ADD COLUMN param VARCHAR(200)"),
            ("location", "ALTER TABLE findings ADD COLUMN location VARCHAR(20)"),
            ("confidence_label", "ALTER TABLE findings ADD COLUMN confidence_label VARCHAR(10)"),
            ("remediation_ref", "ALTER TABLE findings ADD COLUMN remediation_ref VARCHAR(120)"),
            ("standards", "ALTER TABLE findings ADD COLUMN standards JSON"),
            ("first_seen_scan_id", "ALTER TABLE findings ADD COLUMN first_seen_scan_id VARCHAR(36)"),
            ("last_seen_scan_id", "ALTER TABLE findings ADD COLUMN last_seen_scan_id VARCHAR(36)"),
            ("roles", "ALTER TABLE findings ADD COLUMN roles JSON"),
            ("triage_status", "ALTER TABLE findings ADD COLUMN triage_status VARCHAR(32)"),
            ("assignee", "ALTER TABLE findings ADD COLUMN assignee VARCHAR(120)"),
            ("triage_note", "ALTER TABLE findings ADD COLUMN triage_note TEXT"),
        ):
            if col_name not in finding_cols:
                with engine.begin() as conn:
                    conn.execute(text(col_sql))

        # owasp_category grew from VARCHAR(10) to VARCHAR(64) to hold full
        # "A0x:2021-Some-Category" labels instead of just the short code.
        # SQLite ignores column-width constraints entirely (nothing to alter);
        # Postgres/MySQL need an explicit widen.
        if "owasp_category" in finding_cols and engine.dialect.name != "sqlite":
            with engine.begin() as conn:
                conn.execute(text("ALTER TABLE findings ALTER COLUMN owasp_category TYPE VARCHAR(64)"))

    if "dast_evidence" in table_names:
        evidence_cols = {col["name"] for col in inspector.get_columns("dast_evidence")}
        if "reproduction" not in evidence_cols:
            with engine.begin() as conn:
                conn.execute(text("ALTER TABLE dast_evidence ADD COLUMN reproduction TEXT"))
        if "severity_source" not in evidence_cols:
            with engine.begin() as conn:
                conn.execute(text("ALTER TABLE dast_evidence ADD COLUMN severity_source VARCHAR(40)"))

    if "projects" in table_names:
        existing_cols = {col["name"] for col in inspector.get_columns("projects")}
        if "max_files_to_scan" not in existing_cols:
            with engine.begin() as conn:
                conn.execute(
                    text("ALTER TABLE projects ADD COLUMN max_files_to_scan INTEGER DEFAULT 40")
                )
        if "nvd_mode" not in existing_cols:
            with engine.begin() as conn:
                conn.execute(
                    text("ALTER TABLE projects ADD COLUMN nvd_mode VARCHAR(20) DEFAULT 'top10'")
                )
        if "reference_sources" not in existing_cols:
            with engine.begin() as conn:
                conn.execute(
                    text("ALTER TABLE projects ADD COLUMN reference_sources JSON")
                )
        if "llm_provider" not in existing_cols:
            with engine.begin() as conn:
                conn.execute(
                    text("ALTER TABLE projects ADD COLUMN llm_provider VARCHAR(20) DEFAULT 'bedrock'")
                )
        if "llm_model" not in existing_cols:
            with engine.begin() as conn:
                conn.execute(
                    text(
                        "ALTER TABLE projects ADD COLUMN llm_model VARCHAR(200) "
                        "DEFAULT 'us.anthropic.claude-haiku-4-5-20251001-v1:0'"
                    )
                )
        if "fallback_llm_provider" not in existing_cols:
            with engine.begin() as conn:
                conn.execute(
                    text(
                        "ALTER TABLE projects ADD COLUMN fallback_llm_provider "
                        "VARCHAR(20) DEFAULT 'ollama'"
                    )
                )
        if "fallback_llm_model" not in existing_cols:
            with engine.begin() as conn:
                conn.execute(
                    text(
                        "ALTER TABLE projects ADD COLUMN fallback_llm_model "
                        "VARCHAR(200) DEFAULT 'granite-code:3b-instruct'"
                    )
                )
        if "llm_base_url" not in existing_cols:
            with engine.begin() as conn:
                conn.execute(text("ALTER TABLE projects ADD COLUMN llm_base_url VARCHAR(500)"))
        if "llm_api_key" not in existing_cols:
            with engine.begin() as conn:
                conn.execute(text("ALTER TABLE projects ADD COLUMN llm_api_key VARCHAR(500)"))
        if "max_derived_regex_rules" not in existing_cols:
            with engine.begin() as conn:
                conn.execute(
                    text("ALTER TABLE projects ADD COLUMN max_derived_regex_rules INTEGER DEFAULT 50")
                )
        else:
            # One-time bump: the default has moved 20 -> 100 -> 50 as this cap
            # was tuned; no UI has ever exposed this field for editing, so any
            # row still at an old default is untouched, not a deliberate override.
            with engine.begin() as conn:
                conn.execute(
                    text(
                        "UPDATE projects SET max_derived_regex_rules = 50 "
                        "WHERE max_derived_regex_rules IN (20, 100)"
                    )
                )
        if "max_derived_semgrep_rules" not in existing_cols:
            with engine.begin() as conn:
                conn.execute(
                    text("ALTER TABLE projects ADD COLUMN max_derived_semgrep_rules INTEGER DEFAULT 20")
                )
        if "limitations_config" not in existing_cols:
            with engine.begin() as conn:
                conn.execute(
                    text("ALTER TABLE projects ADD COLUMN limitations_config JSON")
                )
        if "enable_sbom" not in existing_cols:
            with engine.begin() as conn:
                conn.execute(
                    text("ALTER TABLE projects ADD COLUMN enable_sbom BOOLEAN DEFAULT 1")
                )
        if "dast_rules_config" not in existing_cols:
            with engine.begin() as conn:
                conn.execute(text("ALTER TABLE projects ADD COLUMN dast_rules_config JSON"))
        if "gate_max_critical" not in existing_cols:
            with engine.begin() as conn:
                conn.execute(text("ALTER TABLE projects ADD COLUMN gate_max_critical INTEGER"))
        if "gate_max_high" not in existing_cols:
            with engine.begin() as conn:
                conn.execute(text("ALTER TABLE projects ADD COLUMN gate_max_high INTEGER"))
        if "training_capture_enabled" not in existing_cols:
            with engine.begin() as conn:
                conn.execute(text("ALTER TABLE projects ADD COLUMN training_capture_enabled BOOLEAN DEFAULT 0"))
        if "git_provider" not in existing_cols:
            with engine.begin() as conn:
                conn.execute(text("ALTER TABLE projects ADD COLUMN git_provider VARCHAR(20)"))
        if "git_access_token" not in existing_cols:
            with engine.begin() as conn:
                conn.execute(text("ALTER TABLE projects ADD COLUMN git_access_token VARCHAR(500)"))
        if "git_refresh_token" not in existing_cols:
            with engine.begin() as conn:
                conn.execute(text("ALTER TABLE projects ADD COLUMN git_refresh_token VARCHAR(500)"))
        if "git_token_expires_at" not in existing_cols:
            with engine.begin() as conn:
                conn.execute(
                    text("ALTER TABLE projects ADD COLUMN git_token_expires_at DATETIME")
                )

    if "dast_request_audit" in table_names:
        audit_cols = {col["name"] for col in inspector.get_columns("dast_request_audit")}
        # Redacted header maps (DAST-01-050) and size-capped bodies.
        for col_name, col_type in (
            ("request_headers", "JSON"),
            ("response_headers", "JSON"),
            ("request_body", "TEXT"),
            ("response_body", "TEXT"),
        ):
            if col_name not in audit_cols:
                with engine.begin() as conn:
                    conn.execute(text(f"ALTER TABLE dast_request_audit ADD COLUMN {col_name} {col_type}"))


def _configure_sqlite_connection(dbapi_conn, _record) -> None:
    """WAL lets readers run alongside the one writer, and busy_timeout makes a
    writer wait for the lock instead of failing at once. Both matter now that
    sign-ins and audit events write while scan threads are writing findings."""
    dbapi_conn.execute("PRAGMA foreign_keys=ON")
    dbapi_conn.execute("PRAGMA journal_mode=WAL")
    dbapi_conn.execute("PRAGMA busy_timeout=5000")


def init_db(url: str | None = None):
    global engine, SessionLocal
    db_url = url or settings.database_url
    connect_args = {}
    if db_url.startswith("sqlite"):
        connect_args["check_same_thread"] = False
    engine = create_engine(db_url, connect_args=connect_args)
    if db_url.startswith("sqlite"):
        event.listen(engine, "connect", _configure_sqlite_connection)
    Base.metadata.create_all(bind=engine)
    _run_light_migrations(engine)
    _drop_data_policy_columns(engine)
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    return SessionLocal


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
