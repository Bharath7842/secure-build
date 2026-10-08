export interface Project {
  id: string;
  name: string;
  description: string | null;
  languages: string[];
  frameworks: string[];
  build_tool: string | null;
  default_git_url: string;
  default_branch: string;
  monorepo_path: string | null;
  enable_sast: boolean;
  enable_sca: boolean;
  enable_sbom: boolean;
  enable_secrets: boolean;
  scan_mode: "full";
  max_files_to_scan: number;
  max_derived_regex_rules: number;
  max_derived_semgrep_rules: number;
  llm_provider: "bedrock" | "ollama";
  llm_model: string;
  fallback_llm_provider?: "bedrock" | "ollama" | string | null;
  fallback_llm_model?: string | null;
  owasp_mode: "top10" | "top15" | "custom";
  owasp_urls: string[];
  nvd_mode: "top10" | "top15" | "custom";
  nvd_urls: string[];
  reference_sources: ReferenceSource[];
  created_at: string;
  updated_at: string;
  limitations_config?: Record<string, boolean> | null;
  git_provider?: "github" | "gitlab" | null;
  git_connected?: boolean;
}

export interface ProjectDeleteResult {
  project_id: string;
  scans_deleted: number;
  workspace_removed: boolean;
  git_disconnected: boolean;
}

export interface ReferenceSource {
  key: string;
  name: string;
  mode: string;
  urls: string[];
}

export interface ProjectCreateInput {
  name: string;
  description?: string | null;
  languages?: string[];
  frameworks?: string[];
  build_tool?: string | null;
  // Optional: a project used only for DAST scans has no repository.
  default_git_url?: string;
  default_branch?: string;
  monorepo_path?: string | null;
  enable_sast?: boolean;
  enable_sca?: boolean;
  enable_sbom?: boolean;
  enable_secrets?: boolean;
  scan_mode?: "full";
  max_files_to_scan?: number;
  max_derived_regex_rules?: number;
  max_derived_semgrep_rules?: number;
  llm_provider?: "bedrock" | "ollama";
  llm_model?: string;
  fallback_llm_provider?: "bedrock" | "ollama";
  fallback_llm_model?: string;
  owasp_mode?: "top10" | "top15" | "custom";
  owasp_urls?: string[];
  nvd_mode?: "top10" | "top15" | "custom";
  nvd_urls?: string[];
  reference_sources?: ReferenceSource[];
  // Set when "Connect GitHub"/"Connect GitLab" was authorized on the
  // new-project form before this project existed.
  git_connection_id?: string;
}

export interface GitRepo {
  name: string;
  full_name: string;
  clone_url: string;
  default_branch: string | null;
  private: boolean;
}

export type ProjectUpdateInput = Partial<ProjectCreateInput>;

export interface Scan {
  id: string;
  project_id: string;
  git_url: string;
  branch: string;
  commit_sha: string | null;
  status: "queued" | "running" | "success" | "failed" | "cancelled" | string;
  /** "sast" (default, LLM discovery engine) | "sca" (dependency/OSV.dev lookup)
   * | "sbom" (deterministic CycloneDX/SPDX component inventory + license
   * classification) | "dast" (Playwright login + crawl of a running app;
   * `git_url` carries the target URL). */
  scan_type: "sast" | "sca" | "sbom" | "dast" | string;
  version: number;
  progress: number;
  message: string | null;
  llm_provider: "bedrock" | "ollama" | string | null;
  llm_model: string | null;
  fallback_llm_provider?: "bedrock" | "ollama" | string | null;
  fallback_llm_model?: string | null;
  triggered_by: "app" | "jenkins" | string | null;
  /** Optional subdirectory scoped for this scan. */
  repo_path?: string | null;
  /** Absolute local path of this scan's checkout (backend's workspaces_dir/<project_id>,
   *  plus repo_path scope) — only meaningful when the browser and backend share a
   *  filesystem. Used to build vscode:// / claude-cli:// deep links per finding. */
  local_root_path?: string | null;
  /** DAST scans in `GET /scans`: confirmed findings by severity plus the unverified count. */
  dast_counts?: DastCounts | null;
  created_at: string;
  updated_at: string;
}

export interface ScanCreateInput {
  project_id: string;
  git_url?: string | null;
  /** Optional subdirectory within the cloned repo to limit the scan scope. */
  repo_path?: string | null;
  branch?: string | null;
  commit_sha?: string | null;
  /** "sast" (default) | "sca" | "sbom" | "dast". Selects which engine adapter path runs. */
  scan_type?: "sast" | "sca" | "sbom" | "dast";
  /** Required when scan_type is "dast". */
  dast?: DastInput;
  metadata?: Record<string, unknown>;
  force?: boolean;
  /** When false, skip the LLM tech-stack call and use path heuristics only. */
  use_llm?: boolean;
  llm_provider?: "bedrock" | "ollama";
  llm_model?: string;
  fallback_llm_provider?: "bedrock" | "ollama";
  fallback_llm_model?: string;
}

export interface ScanTrigger {
  scan_id: string;
  status: string;
  status_url: string;
  reused: boolean;
  reused_reason: string | null;
}

export interface ScanStatus {
  scan_id: string;
  project_id: string;
  status: string;
  scan_type: "sast" | "sca" | "sbom" | "dast" | string;
  progress: number;
  message: string | null;
}

export interface ScanLogLine {
  seq: number;
  line: string;
}

export interface ScanLogs {
  scan_id: string;
  status: string;
  lines: ScanLogLine[];
  next_after: number;
}

/** Per-file result from `map_modules_and_risk` — the discovery agent's risk map. */
export interface ScanDiscoveryFile {
  path: string;
  stack: string;
  module: string;
  category: "source" | "config" | "dependency" | "test" | "build" | "other";
  risk_level: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  reason: string;
  lang?: string | null;
}

export interface ScanDiscoveryModulePlan {
  modules_by_stack: Record<string, string[]>;
  risk_counts: Record<"CRITICAL" | "HIGH" | "MEDIUM" | "LOW", number>;
  files: ScanDiscoveryFile[];
  scan_priority: ScanDiscoveryFile[];
}

export interface ScanDiscoveryScanSummary {
  root?: string;
  total_files: number;
  max_depth: number;
  top_level_entries: string[];
  extension_histogram: Record<string, number>;
  marker_files_found: string[];
}

/** One Java/Spring REST entry point found by the tree-sitter AST pass
 * (`ast_struct.analyze_java_source`). */
export interface AstEntryPoint {
  class: string;
  method: string;
  verb: string;
  path: string;
  authorized: boolean;
  file: string;
}

/** One Angular route object found by the tree-sitter AST pass
 * (`ast_struct.analyze_ts_source`). */
export interface AstRoute {
  path: string;
  guarded: boolean;
  file: string;
}

/** Per-stack aggregate from `ast_struct.build_ast_summary` — annotation/decorator
 * usage counts plus entry-point / route coverage. */
export interface AstStackSummary {
  annotations?: Record<string, number>;
  entry_points?: AstEntryPoint[];
  entry_point_count?: number;
  unauthenticated_entry_points?: number;
  decorators?: Record<string, number>;
  guard_files?: number;
  routes?: AstRoute[];
  route_count?: number;
  unguarded_route_count?: number;
}

/** Output of `ast_struct.build_ast_summary` — the tree-sitter structural pass
 * over Maven/Java and Angular sources (`discovery.llm_analysis.ast_summary`). */
export interface AstSummary {
  parsed_files: Record<string, number>;
  capped: Record<string, boolean>;
  stacks: Record<string, AstStackSummary>;
}

export interface ScanDiscoveryLlmAnalysis {
  heuristic_stacks: string[];
  llm_used: boolean;
  tech_stack: string;
  project_type: string;
  confidence: "low" | "medium" | "high" | string;
  risk_areas: string[];
  reasoning: string;
  ast_summary?: AstSummary | null;
}

/** Output of the discovery agent (`sast_scan_agent.py`) — tech stack, file
 * categorization, path-heuristic risk map, and AST-based vulnerability findings. */
export interface ScanDiscoveryAstFinding {
  rule_id: string;
  title: string;
  description: string;
  category: string;
  cwe: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  cvss?: number;
  file_path: string;
  line_number: number;
  code_snippet: string;
  requires_confirmation: boolean;
  confirmation_score?: number;
  confirmation_method?: string;
  confirmation_evidence?: string[];
  llm_verdict: "confirmed" | "false_positive";
  llm_explanation?: string;
}

export interface ScanDiscoveryAstFindings {
  raw_count: number;
  confirmed_count: number;
  discarded_count: number;
  findings: ScanDiscoveryAstFinding[];
}

/** Output of `generate_report` — aggregate TP/FP totals from the LLM-primary
 * scan of the top 100 CRITICAL/HIGH files plus the regex-gated triage of
 * MEDIUM/LOW and any CRITICAL/HIGH overflow past that cap (per-finding
 * detail lives behind `GET /scans/{id}/findings`). */
export interface ScanReport {
  files_scanned: number;
  tp_count: number;
  fp_count: number;
  /** Regex matches published without an LLM ruling (the MEDIUM/LOW tier).
   * Optional so reports persisted before this verdict existed still parse. */
  unverified_count?: number;
  by_owasp_category: Record<
    string,
    { true_positive: number; false_positive: number; unverified?: number }
  >;
}

/** One persisted `Finding` row — from `GET /scans/{id}/findings`. */
export interface Finding {
  id: string;
  scan_id: string;
  severity: string;
  cvss: number | null;
  cwe: string | null;
  owasp_category: string | null;
  rule_id: string | null;
  title: string;
  file_path: string | null;
  line: number | null;
  snippet: string | null;
  ai_fix: string | null;
  kind: string | null;
  verdict: "true_positive" | "false_positive" | "unverified" | string | null;
  confidence: number | null;
  source: string | null;
  sink: string | null;
  data_flow: string | null;
  verdict_reason: string | null;
  affected_files: string[] | null;
  /** The literal text the regex matched — findings group by rule + this. */
  matched_text: string | null;
  /** Ordered hops for kind=flow findings (file → file call-graph slice). */
  flow_path: FlowHop[] | null;
  /** DAST fields — present only on `kind=dast` findings. */
  target?: string | null;
  param?: string | null;
  location?: DastLocation | null;
  confidence_label?: DastConfidence | null;
  remediation_ref?: string | null;
  standards?: string[] | null;
  first_seen_scan_id?: string | null;
  last_seen_scan_id?: string | null;
  evidence?: DastEvidence | null;
  /** Remediation guidance text (DAST). */
  remediation?: string;
  /** Role labels involved: [owner, acting] for an authorization finding. */
  roles?: string[];
}

export interface FlowHop {
  step: number;
  file: string;
  method: string;
  line: number;
  start_line?: number;
  role: "source" | "hop" | "sink" | string;
  label: string;
  snippet: string;
}

export interface ScanFindings {
  scan_id: string;
  tp_count: number;
  fp_count: number;
  unverified_count?: number;
  /** DAST: all findings in the scan, ignoring the request's filters. */
  total_count?: number;
  files_scanned: number;
  findings: Finding[];
}

export interface ScanLimitation {
  id: string;
  enabled_by_default: boolean;
  category: "engine-cap" | "analysis-check" | "security-pattern";
  title: string;
  description: string;
  affected_scope?: string | null;
  source?: string | null;
}

/** One regex rule derived for this scan only (`derive_rules.py`) — either a
 * call-graph wrapper pattern (Pass A, no LLM) or an LLM-proposed source/sink
 * API pattern (Pass B), merged onto the static catalog. */
export interface DerivedRule {
  id: string;
  title: string;
  description: string;
  cwe: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | string;
  category: string;
  owasp: string;
  languages: string[];
  frameworks: string[];
  pattern: string;
  derived: boolean;
}

export interface DerivedRulesSummary {
  compiled: number;
  failed: number;
  failed_by_reason: Record<string, number>;
}

export interface ScanDiscovery {
  scan_summary: ScanDiscoveryScanSummary;
  llm_analysis: ScanDiscoveryLlmAnalysis;
  categorized_counts: Record<string, number>;
  module_plan: ScanDiscoveryModulePlan;
  ast_findings?: ScanDiscoveryAstFindings | null;
  derived_rules?: DerivedRule[];
  derived_rules_summary?: DerivedRulesSummary;
  report?: ScanReport | null;
}

/** Aggregate LLM token/cost totals from `usage_cost_summary` (`llm_client.py`). */
export interface UsageStepSummary {
  calls: number;
  input_tokens: number;
  output_tokens: number;
  /** DAST only: the step's own cost (hosted models are priced per provider/model). */
  cost_usd?: number;
  /** DAST only: calls that used the task's deterministic fallback / needed a repair attempt. */
  fallbacks?: number;
  repairs?: number;
}

export interface UsageSummary {
  provider: string;
  model: string;
  active_provider?: string;
  active_model?: string;
  fallback_switched?: boolean;
  cost_cutoff_usd?: number | null;
  input_tokens: number;
  output_tokens: number;
  total_tokens: number;
  cost_usd: number;
  call_count: number;
  by_step?: Record<string, UsageStepSummary>;
  /** DAST only: the same totals grouped by provider (one scan can route tasks to several). */
  by_provider?: Record<string, UsageStepSummary>;
  fallback_count?: number;
  repair_count?: number;
  /** DAST only: "provider/model" pairs that had no price configured and were costed at $0. */
  unpriced_models?: string[];
  estimated?: boolean;
  input_price_per_mtok?: number;
  output_price_per_mtok?: number;
}

export interface ScanResults {
  scan_id: string;
  status: string;
  /** For scan_type=sast this is a `ScanDiscovery`; for scan_type=sca it's a
   * `ScaDiscovery`; for scan_type=sbom it's an `SbomDiscovery` (see
   * `Scan.scan_type`). */
  discovery?: ScanDiscovery | ScaDiscovery | SbomDiscovery | DastDiscovery | null;
  usage_summary?: UsageSummary | null;
  /** DAST: the scan's frozen settings, rule-set snapshot and the checks that could not run as designed. */
  dast_effective?: Record<string, unknown> | null;
  dast_rule_set?: { packs: string[]; catalog_version: string; checks: { id: string; enabled: boolean; mode: string }[] } | null;
  dast_skipped_degraded?: DastSkippedCheck[] | null;
}

// ===========================================================================
// DAST (dynamic crawl) — backend/app/dast/runner.py
// ===========================================================================

export interface DastInput extends DastScanOptions {
  target_url: string;
  /** The original single-credential form login; use `identities` for several. */
  login_url?: string;
  username?: string;
  password?: string;
  max_depth?: number;
  max_pages?: number;
  headless?: boolean;
  /** Must be true — confirms the caller may test the target. */
  authorized: boolean;
}

export interface DastPage {
  url: string;
  depth: number;
  title: string;
  forms: Record<string, unknown>[];
  links_count: number;
  new_link_count: number;
  /** Filename of this page's crawl screenshot (e.g. "0.jpg"), served from
   * `/api/scans/{id}/screenshots/{screenshot}`; null when none was captured. */
  screenshot?: string | null;
}

export interface DastApiCall {
  method: string;
  url: string;
  status_code: number | null;
  content_type: string;
}

export type DastVerdict = "PASS" | "FAIL" | "INCONCLUSIVE" | string;

/** One security check run against one REST API during the analysis stage —
 * the leaf of the Discover → API → Check → Payload → Response → Finding →
 * Verdict drill-down. */
export interface DastApiCheck {
  check_id: string;
  check: string;
  cwe: string;
  owasp_category: string;
  target: string;
  location?: string;
  payload: string;
  expected_signal: string;
  request?: DastTraffic | null;
  response: {
    status_code: number | null;
    content_type: string;
    security_headers: Record<string, string | null>;
    evidence: string;
    error: string;
  };
  finding: string;
  severity: string;
  verdict: DastVerdict;
  confidence: string;
  evidence: string;
  /** Detector signals observed, and what the guardrail did with the model's proposal. */
  signals?: DastSignal[];
  guardrail?: { proposed: string | null; downgraded: boolean; overridden: boolean; reason: string };
  baseline?: { status_code: number | null; length: number };
  audit_ref?: string;
  source?: "model" | "fallback";
}

/** What discovery already observed for an endpoint, shown before its active tests. */
export interface DastRecorded {
  method: string;
  url: string;
  path: string;
  status_code: number | null;
  content_type: string;
  kind?: string;
  parameters: { name: string; location: string; values?: string[] }[];
}

/** The full security analysis of one discovered REST API. */
export interface DastApiAnalysis {
  method: string;
  url: string;
  path: string;
  label: string;
  checks: DastApiCheck[];
  overall_verdict: DastVerdict;
  summary: string;
  counts: { fail: number; pass: number; inconclusive: number };
  tests_sent?: number;
  dropped?: { unknown_check: number; unsafe: number; malformed: number; over_cap: number };
  used_fallback?: boolean;
  kind?: string;
  recorded?: DastRecorded;
}

export interface DastAnalysisSummary {
  apis_tested: number;
  fail: number;
  pass: number;
  inconclusive: number;
  apis_failing: number;
}

export interface DastDiscovery {
  target_url: string;
  connection_ok: boolean;
  connection_error: string;
  login_type: string;
  login_success: boolean;
  login_error: string;
  stop_reason: string;
  crawl_stop_reason: string;
  pages: DastPage[];
  api_calls: DastApiCall[];
  forms_count: number;
  skipped_duplicate_patterns: { url: string; pattern: string; reason: string }[];
  failed_urls: { url: string; error: string }[];
  warnings: { event?: string; details?: string }[];
  /** Per-REST-API security analysis (the analyze_apis stage). */
  api_analysis?: DastApiAnalysis[];
  analysis_summary?: DastAnalysisSummary;
  fingerprint?: DastFingerprint;
  inventory?: DastInventoryEntry[];
  inventory_count?: number;
  inventory_diff?: DastInventoryDiff;
  identities?: DastIdentityResult[];
  passive_analysis?: DastPassiveSummary;
  active_testing?: DastActiveSummary;
  authorization?: DastAuthorizationSummary;
  skipped_degraded?: DastSkippedCheck[];
  authentication_failed?: string;
  credentials_lost?: boolean;
}

export type DastStepStatus = "pending" | "running" | "done" | "failed" | "cancelled";

/** One step of the DAST timeline — `GET /scans/{id}/narration`. */
export interface DastNarrationStep {
  id: string;
  index: number;
  title: string;
  status: DastStepStatus;
  narration: string;
  /** Why the model concluded what it did — LLM-authored prose bullets only. */
  reasoning: string[];
  /** The model's own raw scratchpad (`[thinking]`/`[planner]` log lines), shown as its
   * own "thinking" block — never merged into `reasoning`. */
  thinking: string[];
  evidence: string[];
  /** "llm" when the model wrote it, "template" for the deterministic fallback. */
  source: "llm" | "template" | null;
  narration_pending?: boolean;
}

export interface DastNarration {
  scan_id: string;
  status: string;
  intro: string;
  intro_source?: "llm" | "template" | null;
  steps: DastNarrationStep[];
  pending: boolean;
  llm_enabled: boolean;
}

// ===========================================================================
// SCA (Software Composition Analysis) — sast_engine/pipeline/sca_scan.py
// ===========================================================================

/** One manifest-declared dependency, as collected by `sca_scan.collect_dependencies`. */
export interface ScaDependency {
  ecosystem: string;
  name: string;
  version: string | null;
  scope?: string;
  source_file?: string;
}

export interface ScaDependencySummary {
  total_dependencies: number;
  vulnerable_dependencies: number;
  manifests_parsed: string[];
  ecosystems: string[];
  severity_counts: Record<"CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "UNKNOWN", number>;
}

/** Output of `sca_scan.run_sca_scan` — `Scan.metadata_json.discovery` for
 * scan_type=sca. Per-vulnerability detail lives behind the same
 * `GET /scans/{id}/findings` endpoint SAST findings use (kind="sca"). */
export interface ScaDiscovery {
  dependency_summary: ScaDependencySummary;
  dependencies: ScaDependency[];
}

// ===========================================================================
// SBOM (Software Bill of Materials) — sast_engine/pipeline/sbom_scan.py
// ===========================================================================

export type SbomCostClassification = "fully_free" | "partially_free" | "fully_paid" | "unknown";

export interface SbomComponentLicense {
  spdx_id: string;
  name: string;
}

/** One CycloneDX-component-shaped dependency, as built by `sbom_scan.build_components`. */
export interface SbomComponent {
  "bom-ref": string;
  type: string;
  name: string;
  version: string | null;
  purl: string | null;
  group?: string | null;
  ecosystem: string;
  scope: string;
  source_file: string | null;
  licenses: SbomComponentLicense[];
  cost_classification: SbomCostClassification;
  /** Publisher/maintainer org — from the static vendor table, or filled in by
   * Bedrock Claude Haiku enrichment (`sbom_scan.llm_enrich_components`) when
   * that table has no entry. */
  vendor: string | null;
  /** "Open Source" | "Proprietary" | "Internal" — deterministic fallback from
   * license type, refined by the same LLM enrichment step. */
  origin_type: string;
  /** "Direct" | "Direct (Dev)" | "Direct (Peer)" | "Direct (Provided)" — every
   * SBOM component is a direct, manifest-declared dependency; this only
   * qualifies which manifest section it came from. */
  dependency_relationship: string;
  direct: boolean;
}

export interface SbomComponentSummary {
  total_components: number;
  ecosystems: string[];
  manifests_parsed: string[];
  license_summary: Record<SbomCostClassification, number>;
}

/** Output of `sbom_scan.run_sbom_scan` — `Scan.metadata_json.discovery` for
 * scan_type=sbom. `sbom_cyclonedx`/`sbom_spdx` are internal building blocks
 * (not a separate download surface) — SBOM export is PDF/Excel only, via the
 * same `/export.pdf`/`/export.xlsx` endpoints as SAST/SCA. */
export interface SbomDiscovery {
  component_summary: SbomComponentSummary;
  components: SbomComponent[];
  sbom_cyclonedx: Record<string, unknown> | null;
  sbom_spdx: Record<string, unknown> | null;
  llm_enrichment_usage?: Record<string, unknown> | null;
}

// ===========================================================================
// DAST contract types. Shapes mirror the backend responses
// (backend/app/routers/dast_*.py, scans.py, schemas.py); keep them in step.
// ===========================================================================

export interface DastCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  unverified: number;
}

export type DastRoleName = "admin" | "user" | "viewer" | "anonymous" | "custom";

export interface DastRole {
  name: DastRoleName;
  /** Display label; required when `name` is "custom". */
  label?: string;
}

export type DastLocation = "query" | "path" | "header" | "body" | "response";
export type DastConfidence = "HIGH" | "MEDIUM" | "LOW";
export type DastIntensity = "light" | "standard" | "deep";
export type DastMethodPolicy = "safe" | "opt_in_mutating";
export type DastAuthMethod = "form" | "token" | "preauth" | "none";

/** One identity a scan acts as. Secrets (`password`, `token`, `storage_state`) are write-only:
 *  sent once, never read back and never kept in the browser. */
export interface DastIdentityInput {
  label: string;
  /** "Admin" | "User" | "Viewer" | "Custom" (Anonymous is implied). */
  role: string;
  custom_role?: string;
  auth_method: DastAuthMethod;
  login_url?: string;
  username?: string;
  password?: string;
  token?: string;
  header_name?: string;
  scheme?: string;
  storage_state?: string;
}

export interface DastModelChoice {
  provider: DastModelProvider;
  model: string;
}

export interface DastRuleOverride {
  enabled?: boolean;
  severity?: string;
  mode?: DastCheckMode;
}

/** Options a DAST scan accepts beyond the target address (`POST /scans`, `dast`). */
export interface DastScanOptions {
  identities?: DastIdentityInput[];
  intensity?: DastIntensity;
  method_policy?: DastMethodPolicy;
  target_disposable?: boolean;
  /** Type inert markers into crawled inputs. Omit to use the configured default. */
  browser_probe_enabled?: boolean;
  /** Submit a stored-XSS marker (POST). Requires a disposable target. */
  browser_marker_posts?: boolean;
  /** Requests per second; capped by the server. */
  rate_limit_per_sec?: number;
  max_depth?: number;
  max_pages?: number;
  max_targets?: number;
  max_runtime_minutes?: number;
  /** Rule packs to run (exactly these); omitted = the project/global defaults. */
  rule_packs?: string[];
  rule_overrides?: Record<string, DastRuleOverride>;
  /** Per-task model for this scan; omitted = the configured routing. */
  model_routing?: Partial<Record<DastModelTask, DastModelChoice>>;
  schema_url?: string;
}

export interface DastSignal {
  /** Detector signal name, e.g. "db_error_surfaced", "header_absent". */
  name: string;
  detail?: string;
}

export interface DastTraffic {
  method: string;
  url: string;
  parameter?: string | null;
  location?: string | null;
  payload?: string;
  identity_label?: string | null;
  headers?: Record<string, string> | null;
  allowed?: boolean | null;
  deny_reason?: string | null;
  seq?: number | null;
  response_status?: number | null;
  response_headers?: Record<string, string> | null;
}

export interface DastEvidence {
  baseline_excerpt: string | null;
  test_excerpt: string | null;
  /** A confirmed (true_positive) finding always has at least one signal. */
  signals: DastSignal[];
  /** Sequence number of the request in the scan's audit log. */
  audit_ref: string | null;
  /** What was sent for this finding (audit log + snippet payload). */
  request?: DastTraffic | null;
}

export type DastFindingVerdict = "true_positive" | "unverified" | "false_positive";

/** Query for `GET /scans/{id}/findings` on a DAST scan. Each value may be comma separated. */
export interface DastFindingFilter {
  severity?: string;
  verdict?: string;
  /** A role label, or "owner:actor" for the pair behind one authorization-matrix cell. */
  role?: string;
  check?: string;
}

export type DastAuthzResult = "OK" | "FAIL" | "untested";

/** One cell of the authorization matrix: rows are owner roles, columns acting roles. */
export interface DastAuthzCell {
  owner: string;
  actor: string;
  result: DastAuthzResult;
  /** Findings behind a failing cell; > 0 exactly when `result` is "FAIL". */
  failures: number;
  /** Why the cell is untested (e.g. no second identity); empty otherwise. */
  reason: string;
  finding_ids: string[];
  finding_keys: string[];
}

export interface DastAuthzIdentity {
  identity_id: string;
  label: string;
  role: DastRole;
}

/** `GET /scans/{id}/authz-matrix` — derived on every request, available while the scan runs. */
export interface DastAuthzMatrix {
  scan_id: string;
  /** False until the authorization stage has run. */
  ran: boolean;
  identities: DastAuthzIdentity[];
  /** The anonymous baseline identity, always the last column. */
  baseline_identity: string;
  cells: DastAuthzCell[];
  replays: number;
  /** True when cross-role checks ran in a reduced form (e.g. only one identity). */
  degraded: boolean;
  degraded_reason: string;
}

export type DastDiffStatus = "new" | "fixed" | "still_open";

export interface DastDiffEntry {
  check_id: string;
  /** Endpoint, e.g. "POST /api/login". */
  target: string;
  param: string | null;
  status: DastDiffStatus;
  severity: string;
  verdict: string;
  roles: string[];
  finding_id: string;
  title: string;
  note: string;
}

export interface DastNotComparable {
  check_id: string;
  target: string;
  param: string | null;
  severity: string;
  reason: string;
}

/** `GET /scans/{id}/diff` — against the previous successful DAST scan of the same project and target. */
export interface DastDiff {
  scan_id: string;
  previous_scan_id: string | null;
  previous_version: number | null;
  /** False when there is no earlier scan: every finding is new. */
  baseline: boolean;
  entries: DastDiffEntry[];
  counts: Record<DastDiffStatus, number>;
  not_comparable: DastNotComparable[];
  notes: string[];
  checks_not_run_current: string[];
  checks_not_run_previous: string[];
}

export interface DastSkippedCheck {
  check_id: string;
  title: string;
  status: "skipped" | "degraded";
  dependency: string;
  effective_mode: string;
  reason: string;
}

export interface DastReportFinding {
  id: string;
  check_id: string | null;
  title: string;
  severity: string;
  verdict: DastFindingVerdict | string | null;
  confidence: string;
  target: string;
  param: string | null;
  location: string | null;
  standards: string[];
  remediation: string;
  remediation_ref: string | null;
  reason: string;
  source: string;
  roles: string[];
  affected: string[];
  review_item: boolean;
  diff_status: DastDiffStatus | "";
  evidence: {
    baseline: string;
    test: string;
    signals: DastSignal[];
    audit_ref: string;
    request?: DastTraffic | null;
    request_text?: string;
  } | null;
}

/** `GET /scans/{id}/report` — the data set the report view, the PDF and the XLSX all show. */
export interface DastReport {
  scan: { id: string; version: number; status: string; target: string; project: string; created_at: string | null; finished_at: string | null; message: string };
  summary: {
    /** Confirmed findings only. */
    severity_counts: Record<"critical" | "high" | "medium" | "low" | "info", number>;
    confirmed: number;
    unverified: number;
    review_items: number;
    dismissed: number;
    total: number;
  };
  confirmed: DastReportFinding[];
  unverified: DastReportFinding[];
  dismissed: DastReportFinding[];
  rule_packs: { id: string; title: string }[];
  catalog_version: string;
  custom_rules: { id: string; version: number }[];
  skipped_degraded: DastSkippedCheck[];
  settings: Record<string, unknown> & { identities?: { label: string; role: string; auth_method: string }[] };
  coverage: { pages: number; endpoints: number; passive: DastPassiveSummary | Record<string, never>; active: DastActiveSummary | Record<string, never>; authorization: Partial<DastAuthorizationSummary> };
  usage: Record<string, unknown>;
  diff: DastDiff;
}

/** `GET /scans/{id}/summary` — live counters, cheap enough to poll every two seconds. */
export interface DastSummary {
  scan_id: string;
  status: string;
  running: boolean;
  pages_crawled: number;
  endpoints_discovered: number;
  requests_sent: number;
  requests_denied: number;
  tests_run: number;
  replays: number;
  /** Inert markers typed into crawled pages. Absent on a scan from before browser probes existed. */
  browser_inputs?: number;
  findings: {
    /** Confirmed findings only. */
    by_severity: Record<"CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO", number>;
    by_verdict: Record<string, number>;
    total: number;
  };
  skipped_checks: number;
  model_calls: number;
  model_cost_usd: number;
  model_tokens: number;
}

export interface DastFingerprint {
  shape: string;
  auth: string;
  schema: string;
  source?: string;
  schema_url?: string;
  evidence?: string[];
}

export interface DastInventoryEntry {
  method: string;
  url: string;
  status_code: number | null;
  content_type: string;
  path_template: string;
  source: "observed" | "schema" | "both";
  state_changing: boolean;
  kind: string;
  identities: string[];
  parameters: { name: string; location: string; values: string[]; required: boolean; type: string }[];
  note: string;
}

export interface DastInventoryDiff {
  compared: boolean;
  reason: string;
  undocumented: DastInventoryEntry[];
  unexercised: DastInventoryEntry[];
}

export interface DastIdentityResult {
  identity_id: string;
  label: string;
  role: string;
  role_label: string;
  auth_method: string;
  status: string;
  failure: string;
  relogin_count: number;
}

export interface DastPassiveSummary {
  checks_run: number;
  exchanges: number;
  findings: number;
  unverified: number;
  finding_keys: string[];
  cors: { assessable: boolean | null; note: string };
}

export interface DastActiveSummary {
  targets_total: number;
  targets_tested: number;
  targets_capped: number;
  tests_sent: number;
  dropped_unknown_check: number;
  dropped_unsafe: number;
  dropped_malformed: number;
  over_cap: number;
  fallback_targets: number;
  guardrail_downgrades: number;
  guardrail_overrides: number;
  not_tested: { label: string; reason: string }[];
  cancelled: boolean;
  review_items?: number;
  ssrf?: { tests: number; confirmed: number; reason?: string };
  session_lost_reason?: string;
}

export interface DastAuthorizationSummary {
  ran: boolean;
  identities: { identity_id: string; label: string; role: string; role_label: string; auth_method: string }[];
  baseline_identity: string;
  replays: { owner: string; actor: string; replays: number; denied: number; crossed: number; owned: number; truncated: boolean; session_lost?: boolean }[];
  total_replays: number;
  findings: number;
  degraded: boolean;
  degraded_reason: string;
  cap?: number;
  cap_reached?: boolean;
}

/** One row of the per-scan request audit log (`GET /scans/{id}/requests`). */
export interface DastRequestAuditEntry {
  seq: number;
  method: string;
  url: string;
  identity_label: string | null;
  allowed: boolean;
  deny_reason: string | null;
  response_status: number | null;
  timestamp: string;
  check_id: string | null;
  /** Header maps with credential values redacted; request and response bodies are never stored. */
  request_headers?: Record<string, string> | null;
  response_headers?: Record<string, string> | null;
}

export interface DastRequestAuditPage {
  scan_id: string;
  entries: DastRequestAuditEntry[];
  /** Pass as `after` to fetch the next page; null when exhausted. */
  next_after: number | null;
}

export type DastCheckMode = "automated" | "opt-in" | "assist-only";

export interface DastCatalogPack {
  id: string;
  title: string;
  description: string;
  enabled_by_default: boolean;
  check_ids: string[];
}

export interface DastCatalogCheck {
  id: string;
  title: string;
  description: string;
  severity: string;
  mode?: string;
  passive?: boolean;
  load_generating?: boolean;
  enabled_by_default?: boolean;
}

/** `GET /dast/catalog`. */
export interface DastCatalog {
  catalog_version: string;
  packs: DastCatalogPack[];
  checks: DastCatalogCheck[];
  invalid_custom_rules: { check_id: string; errors: string[] }[];
}

export type DastCoverageStatus = "full" | "partial" | "dormant" | "none" | "not_applicable";

export interface DastCoverageCheckRef {
  id: string;
  title: string;
  severity: string;
  mode: DastCheckMode;
}

export interface DastCoverageItem {
  id: string;
  name: string;
  status: DastCoverageStatus;
  checks: DastCoverageCheckRef[];
  note: string | null;
}

export interface DastCoverageCategory {
  category: string;
  items: DastCoverageItem[];
}

/** `GET /dast/vulnerability-coverage`. */
export interface DastVulnerabilityCoverage {
  generated_from: string | null;
  categories: DastCoverageCategory[];
}

export type DastSource = "default" | "global" | "project";

export interface DastSettingValue<T> {
  value: T;
  source: DastSource;
}

export interface DastRuleSettingsPack {
  id: string;
  title: string;
  description: string;
  enabled: boolean;
  source: DastSource;
  enabled_by_default: boolean;
  check_ids: string[];
}

export interface DastRuleSettingsCheck {
  check_id: string;
  title: string;
  description: string;
  custom: boolean;
  version: number | null;
  standards: Record<string, string[]>;
  passive: boolean;
  load_generating: boolean;
  /** Dependencies, e.g. "second_identity", "oast", "schema". */
  requires: string[];
  base_severity: string;
  base_mode: DastCheckMode;
  enabled: DastSettingValue<boolean>;
  severity: DastSettingValue<string>;
  mode: DastSettingValue<DastCheckMode>;
  selected_by_pack: boolean;
  off_by_default: boolean;
  notes: string[];
}

/** `GET /dast/rule-settings[?project_id=]` — values at one level and where each comes from. */
export interface DastRuleSettings {
  level: "global" | "project";
  catalog_version: string;
  packs: DastRuleSettingsPack[];
  checks: DastRuleSettingsCheck[];
  applies_to: string;
}

/** Body of `PATCH /dast/rules` and `PATCH /projects/{id}/dast-rules`. */
export interface DastRuleConfigPatch {
  packs?: Record<string, boolean>;
  checks?: Record<string, DastRuleOverride>;
}

export interface DastEffectiveCheck {
  id: string;
  enabled: boolean;
  severity: string;
  mode: string;
  packs: string[];
  notes: string[];
  definition: { title: string; check_id?: string; requires?: string[]; passive?: boolean };
}

/** `GET /dast/rules/effective` — what a scan would run with right now. */
export interface DastEffectivePreview {
  rule_set: { packs: string[]; checks: DastEffectiveCheck[]; catalog_version: string };
  skipped_degraded: DastSkippedCheck[];
}

export interface DastCustomRule {
  id: string;
  check_id: string;
  version: number;
  enabled: boolean;
  yaml: string;
  definition: Record<string, unknown>;
  notes: string[];
  updated_at: string;
}

export interface DastRuleError {
  field: string;
  message: string;
}

export interface DastCustomRuleValidation {
  valid: boolean;
  errors: DastRuleError[];
  /** E.g. "can only surface as assist-only or unverified". */
  notes: string[];
}

export type DastModelTask =
  | "fingerprint"
  | "crawl_plan"
  | "login_selectors"
  | "construct"
  | "rule"
  | "narrate";

export type DastModelProvider = "ollama" | "bedrock" | "openai" | "anthropic";

export interface DastModelRoute {
  task: DastModelTask;
  provider: DastModelProvider;
  model: string;
  /** True when a stored override, not the environment default, decides this route. */
  overridden?: boolean;
}

export interface DastModelRouteTestResult {
  ok: boolean;
  task: string;
  latency_ms: number | null;
  error: string | null;
}

export interface DastProviderStatus {
  provider: DastModelProvider;
  /** Credentials are configured in the environment. No value is ever returned. */
  configured: boolean;
  source: string;
  detail: string;
}

export interface DastProviders {
  providers: DastProviderStatus[];
  /** Model to fill in when the operator picks a provider. Bedrock is Haiku. */
  default_models?: Partial<Record<DastModelProvider, string>>;
  storage: "environment";
  writable: false;
}

/** Effective global DAST settings (`GET/PATCH /dast/settings`). Secrets are never included. */
export interface DastSettings {
  max_runtime_minutes: number;
  max_depth: number;
  max_pages: number;
  max_per_pattern: number;
  same_domain_mode: "exact" | "root-domain";
  safe_mode_default: boolean;
  browser_probe_enabled: boolean;
  browser_marker_posts: boolean;
  browser_probe_max_inputs: number;
  rate_limit_per_sec: number;
  max_targets: number;
  max_tests_per_target: number;
  /** Whether an OAST callback address is configured (the address itself is never returned). */
  oast_configured: boolean;
  model_routing: { task: DastModelTask; provider: DastModelProvider; model: string }[];
  /** Names of the settings an edit (rather than the environment) currently decides. */
  overridden: string[];
  limits: Record<string, { min: number; max: number; label: string }>;
  /** What each intensity preset means in numbers (max_targets, max_tests_per_target, max_depth, max_pages, max_runtime_minutes, max_per_pattern). */
  presets: Record<DastIntensity, Record<string, number>>;
  applies_to: string;
}

export type DastSettingsUpdate = Partial<
  Pick<
    DastSettings,
    | "max_runtime_minutes"
    | "max_depth"
    | "max_pages"
    | "max_per_pattern"
    | "same_domain_mode"
    | "safe_mode_default"
    | "browser_probe_enabled"
    | "browser_marker_posts"
    | "browser_probe_max_inputs"
    | "rate_limit_per_sec"
    | "max_targets"
    | "max_tests_per_target"
  >
> & {
  /** Write-only. An empty string clears it. */
  oast_callback_url?: string;
  /** Required to turn the safe-mode default off. */
  confirm_unsafe?: boolean;
};
