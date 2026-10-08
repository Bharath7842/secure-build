-- Schema of backend/app/models.py as of commit 0b0c2b1, i.e. before DAST-00-040.
-- Generated once with SQLAlchemy CreateTable/CreateIndex; used by tests/test_dast_schema.py
-- to prove the light migrations upgrade a pre-change database in place.

CREATE TABLE projects (
	id VARCHAR(36) NOT NULL, 
	name VARCHAR(200) NOT NULL, 
	description TEXT, 
	languages JSON NOT NULL, 
	frameworks JSON NOT NULL, 
	build_tool VARCHAR(80), 
	default_git_url VARCHAR(500) NOT NULL, 
	default_branch VARCHAR(200) NOT NULL, 
	monorepo_path VARCHAR(300), 
	git_provider VARCHAR(20), 
	git_access_token VARCHAR(500), 
	git_refresh_token VARCHAR(500), 
	git_token_expires_at DATETIME, 
	enable_sast BOOLEAN NOT NULL, 
	enable_sca BOOLEAN NOT NULL, 
	enable_sbom BOOLEAN NOT NULL, 
	enable_secrets BOOLEAN NOT NULL, 
	scan_mode VARCHAR(20) NOT NULL, 
	max_files_to_scan INTEGER NOT NULL, 
	max_derived_regex_rules INTEGER NOT NULL, 
	max_derived_semgrep_rules INTEGER NOT NULL, 
	llm_provider VARCHAR(20) NOT NULL, 
	llm_model VARCHAR(200) NOT NULL, 
	fallback_llm_provider VARCHAR(20) NOT NULL, 
	fallback_llm_model VARCHAR(200) NOT NULL, 
	owasp_mode VARCHAR(20) NOT NULL, 
	owasp_urls JSON NOT NULL, 
	nvd_mode VARCHAR(20) NOT NULL, 
	nvd_urls JSON NOT NULL, 
	reference_sources JSON NOT NULL, 
	limitations_config JSON, 
	created_at DATETIME NOT NULL, 
	updated_at DATETIME NOT NULL, 
	PRIMARY KEY (id)
);
CREATE UNIQUE INDEX ix_projects_name ON projects (name);
CREATE TABLE file_snapshots (
	id INTEGER NOT NULL, 
	project_id VARCHAR(36) NOT NULL, 
	path VARCHAR(700) NOT NULL, 
	content_hash VARCHAR(64) NOT NULL, 
	commit_sha VARCHAR(64), 
	PRIMARY KEY (id), 
	FOREIGN KEY(project_id) REFERENCES projects (id)
);
CREATE INDEX ix_file_snapshots_project_id ON file_snapshots (project_id);
CREATE TABLE scans (
	id VARCHAR(36) NOT NULL, 
	project_id VARCHAR(36) NOT NULL, 
	git_url VARCHAR(500) NOT NULL, 
	branch VARCHAR(200) NOT NULL, 
	commit_sha VARCHAR(64), 
	status VARCHAR(20) NOT NULL, 
	scan_type VARCHAR(20) NOT NULL, 
	version INTEGER NOT NULL, 
	progress INTEGER NOT NULL, 
	message TEXT, 
	llm_provider VARCHAR(20), 
	llm_model VARCHAR(200), 
	fallback_llm_provider VARCHAR(20), 
	fallback_llm_model VARCHAR(200), 
	triggered_by VARCHAR(20), 
	metadata JSON NOT NULL, 
	created_at DATETIME NOT NULL, 
	updated_at DATETIME NOT NULL, 
	PRIMARY KEY (id), 
	FOREIGN KEY(project_id) REFERENCES projects (id)
);
CREATE INDEX ix_scans_commit_sha ON scans (commit_sha);
CREATE INDEX ix_scans_project_id ON scans (project_id);
CREATE TABLE findings (
	id VARCHAR(36) NOT NULL, 
	scan_id VARCHAR(36) NOT NULL, 
	severity VARCHAR(20) NOT NULL, 
	cvss FLOAT, 
	cwe VARCHAR(40), 
	owasp_ref VARCHAR(500), 
	rule_id VARCHAR(80), 
	title VARCHAR(500) NOT NULL, 
	file_path VARCHAR(500), 
	line INTEGER, 
	snippet TEXT, 
	ai_fix TEXT, 
	kind VARCHAR(40), 
	flow_path JSON, 
	verdict VARCHAR(40), 
	confidence FLOAT, 
	source VARCHAR(300), 
	sink VARCHAR(300), 
	data_flow TEXT, 
	verdict_reason TEXT, 
	affected_files JSON, 
	matched_text VARCHAR(500), 
	group_by_rule BOOLEAN, 
	owasp_category VARCHAR(64), 
	exploitability FLOAT, 
	root_cause_id VARCHAR(40), 
	risk TEXT, 
	example_fix TEXT, 
	PRIMARY KEY (id), 
	FOREIGN KEY(scan_id) REFERENCES scans (id)
);
CREATE INDEX ix_findings_scan_id ON findings (scan_id);

INSERT INTO projects (id, name, default_git_url, default_branch, languages, frameworks, scan_mode, max_files_to_scan, max_derived_regex_rules, max_derived_semgrep_rules, llm_provider, llm_model, fallback_llm_provider, fallback_llm_model, owasp_mode, owasp_urls, nvd_mode, nvd_urls, reference_sources, enable_sast, enable_sca, enable_sbom, enable_secrets, created_at, updated_at) VALUES ('p1','legacy','https://example.test/r.git','main','[]','[]','full',0,50,20,'bedrock','m','ollama','f','top10','[]','top10','[]','[]',1,1,1,0,'2026-01-01 00:00:00','2026-01-01 00:00:00');
INSERT INTO scans (id, project_id, git_url, branch, status, scan_type, version, progress, metadata, created_at, updated_at) VALUES ('s1','p1','https://example.test/r.git','main','success','sast',1,100,'{}','2026-01-01 00:00:00','2026-01-01 00:00:00');
INSERT INTO findings (id, scan_id, severity, title, rule_id, kind, verdict, confidence) VALUES ('f1','s1','HIGH','Legacy SAST finding','legacy-rule','llm','true_positive',0.9);
