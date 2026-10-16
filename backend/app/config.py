from pathlib import Path
from typing import Literal

from pydantic import SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = ROOT / "data"
DEFAULT_DATABASE_URL = f"sqlite:///{(DATA_DIR / 'secure_build.db').as_posix()}"

# The model-gateway tasks a DAST scan routes independently (see architecture.md,
# "Model gateway"). Each has a `dast_model_<task>_provider` / `_model` setting.
DAST_MODEL_TASKS: tuple[str, ...] = (
    "fingerprint",
    "crawl_plan",
    "login_selectors",
    "construct",
    "rule",
    "narrate",
)
DastModelProvider = Literal["ollama", "bedrock", "openai", "anthropic"]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=ROOT / ".env", extra="ignore")

    sast_api_token: str = "changeme-token"
    # In-repo engine (backend/sast_engine); no external checkout required.
    sast_framework_path: str = str(ROOT / "backend" / "sast_engine")
    aws_region: str = "us-east-1"
    bedrock_model_id: str = "us.anthropic.claude-haiku-4-5-20251001-v1:0"
    # Local Ollama server used when a project's llm_provider == "ollama"
    # (e.g. granite-code:3b-instruct). Not required when every project uses Bedrock.
    ollama_base_url: str = "http://localhost:11434"
    ollama_request_timeout: int = 600  # seconds per Ollama /api/chat call
    # Default OpenAI-compatible endpoint (vLLM, LM Studio, llama.cpp server,
    # OpenAI, ...) for projects with llm_provider == "openai_compat" that don't
    # set their own llm_base_url. Includes the version prefix, e.g. ".../v1".
    openai_compat_base_url: str = "http://localhost:8000/v1"
    openai_compat_api_key: SecretStr | None = None
    openai_compat_request_timeout: int = 600
    nvd_api_key: str | None = None
    database_url: str = DEFAULT_DATABASE_URL
    workspaces_dir: str = str(DATA_DIR / "workspaces")
    # Durable per-scan engine logs (JSONL) — surviving restarts / memory eviction
    scan_logs_dir: str = str(DATA_DIR / "scan_logs")
    # One JPEG per page visited during a DAST crawl (data/dast_screenshots/{scan_id}/{n}.jpg)
    dast_screenshots_dir: str = str(DATA_DIR / "dast_screenshots")
    use_mock_engine: bool = False  # True in unit tests
    run_live_sast: bool = True  # Real Bedrock/Ollama + git clone (set RUN_LIVE_SAST=0 to disable)
    run_reference_scan: bool = True  # OWASP Top 10 scan stage (set RUN_REFERENCE_SCAN=0 to skip)
    run_sca: bool = True  # OSV dependency CVE lookup during OWASP scan
    run_dast: bool = True  # Playwright + Ollama crawl (set RUN_DAST=0 to disable); needs playwright/ollama locally
    dast_ollama_model: str = "gpt-oss:20b"
    # Ollama host for DAST model calls. Empty = reuse `ollama_base_url`
    # (env DAST_OLLAMA_BASE_URL overrides just DAST; OLLAMA_BASE_URL moves both).
    dast_ollama_base_url: str = ""
    # Context window requested per Ollama call. The server default (often 4096) is too small once a
    # reasoning model's thinking is added to the prompt, which shows up as empty or looping replies.
    # Match it to the server's OLLAMA_CONTEXT_LENGTH so the model is not reloaded between calls.
    dast_ollama_num_ctx: int = 8192
    # Ollama models whose names start with one of these run with reasoning switched off (faster, no
    # thinking tokens). gpt-oss cannot be switched off (the server rejects it), so it is not listed.
    # phi4-mini (and gemma) return HTTP 400 if thinking is requested.
    dast_ollama_no_think_prefixes: list[str] = ["gemma", "phi4", "granite4"]
    # Context window requested per Ollama call. The server default (often 4096) is too small once a
    # reasoning model's thinking is added to the prompt, which shows up as empty or looping replies.
    # Match it to the server's OLLAMA_CONTEXT_LENGTH so the model is not reloaded between calls.
    dast_ollama_num_ctx: int = 8192

    # --- DAST crawl budgets (defaults from spec/DAST_tech_stack.md section 5) ---
    dast_max_runtime_minutes: float = 10
    dast_max_depth: int = 3
    dast_max_pages: int = 100
    dast_max_per_pattern: int = 3  # cap on crawled URLs sharing one pattern, e.g. /product?id={}
    # "exact" = same hostname only; "root-domain" = any host sharing the registrable domain.
    dast_same_domain_mode: Literal["exact", "root-domain"] = "exact"

    # --- DAST active-testing safety and limits ---
    dast_safe_mode_default: bool = True  # non-destructive methods only unless a scan opts out
    dast_rate_limit_per_sec: float = 5.0  # outbound requests per second, per scan
    dast_max_concurrent_requests: int = 4  # in-flight requests at once, per scan
    dast_max_response_body_bytes: int = 65536  # response body kept per request; the rest is dropped
    dast_max_targets: int = 15  # distinct endpoints actively tested per scan
    dast_max_tests_per_target: int = 12  # checks run per endpoint
    # Endpoints analysed at the same time (each does its own model calls). 1 = one after another.
    # Raise it only together with OLLAMA_NUM_PARALLEL on the Ollama host, or the calls just queue there.
    dast_model_parallelism: int = 1
    # Out-of-band callback host for SSRF-style checks. Unset = those checks degrade to assist-only.
    dast_oast_callback_url: str | None = None
    dast_oast_poll_url: str | None = None  # where callbacks are polled; defaults to the callback host
    dast_oast_wait_s: float = 5.0  # longest wait for a callback after each SSRF test
    # Requests a load-generating (opt-in) check may cause in one scan, baselines included.
    # Also the cap on browser marker submits (stored XSS) in one scan.
    dast_opt_in_request_ceiling: int = 30
    # Browser input probes: type inert markers into crawled pages. On by default; sends GETs only
    # unless marker posts are also on.
    dast_browser_probe_enabled: bool = True
    # Allow the browser to POST a marker (stored XSS). Off by default, and ignored unless the
    # target is marked disposable. The body must be the scan's own marker.
    dast_browser_marker_posts: bool = False
    dast_browser_probe_max_inputs: int = 4  # text inputs probed per page
    # Training-data capture (DAST-16-050): the token an operator must present (X-Training-Admin-Token) to
    # switch capture on for a project or to read captured examples. Unset = capture cannot be enabled.
    dast_training_admin_token: SecretStr | None = None
    # Plain-HTTP notifications when a DAST scan finishes. Unset = no post. Slack and Jira are the
    # same mechanism: a JSON body to a URL, with no vendor SDK.
    dast_webhook_url: str | None = None
    dast_slack_webhook_url: str | None = None
    dast_jira_webhook_url: str | None = None
    # A background thread that starts due DAST schedules. Off unless set, so tests never spawn scans.
    dast_scheduler_enabled: bool = False

    # --- DAST per-task model routing: provider + model for each gateway task ---
    # An empty model means "the provider's default": `dast_ollama_model` for ollama,
    # `bedrock_model_id` for bedrock. openai/anthropic need an explicit model.
    dast_model_fingerprint_provider: DastModelProvider = "ollama"
    dast_model_fingerprint_model: str = ""
    dast_model_crawl_plan_provider: DastModelProvider = "ollama"
    dast_model_crawl_plan_model: str = ""
    dast_model_login_selectors_provider: DastModelProvider = "ollama"
    dast_model_login_selectors_model: str = ""
    dast_model_construct_provider: DastModelProvider = "ollama"
    dast_model_construct_model: str = ""
    dast_model_rule_provider: DastModelProvider = "ollama"
    dast_model_rule_model: str = ""
    dast_model_narrate_provider: DastModelProvider = "ollama"
    dast_model_narrate_model: str = ""
    # Hosted-provider credentials, read from the environment only (never stored, logged or returned).
    anthropic_api_key: SecretStr | None = None
    openai_api_key: SecretStr | None = None
    dast_model_timeout_s: float = 120.0  # per model call, every provider
    dast_model_max_tokens: int = 1500  # reply cap when a caller does not pass one
    dast_fewshot_max_examples: int = 3  # examples included per task prompt
    # USD per million tokens, {"provider/model": [input, output]} or {"provider": [...]} as that
    # provider's default; extends the built-ins (ollama is free, bedrock priced like Haiku 4.5).
    dast_model_prices: dict[str, list[float]] = {}

    # --- DAST intensity presets (DAST-05-020) ---
    # `standard` is the budgets above (DAST_MAX_*). `light` and `deep` have the built-in values in
    # app/dast/domain/presets.py; set a JSON object to override any of their keys, e.g.
    # DAST_PRESET_LIGHT='{"max_pages": 20}'. Keys: max_targets, max_tests_per_target, max_depth,
    # max_pages, max_runtime_minutes, max_per_pattern.
    dast_preset_light: dict[str, float] = {}
    dast_preset_deep: dict[str, float] = {}
    run_sbom: bool = True  # deterministic CycloneDX/SPDX component inventory + license classification
    # Bedrock Claude Haiku best-effort supplier/license/type fill-in for whatever
    # deps.dev + the static tables in sbom_scan.py leave unresolved (SBOM_LLM_ENRICHMENT=0 to skip)
    sbom_llm_enrichment: bool = True
    # Clear per-scan verify/stack cache before each scan (0 = reuse verify cache — much faster)
    sast_refresh_cache: bool = False
    hybrid_mode: bool = False  # env HYBRID_MODE=1 enables hybrid when scan metadata omits flag
    # Joern (pipeline/joern_runner.py). Empty joern_home = use `joern` on PATH;
    # a missing install just skips the Joern stages. Heap is the main knob on
    # large repos — CPG builds for a few thousand Java files want 4-8 GB.
    joern_home: str = ""
    joern_timeout_sec: int = 900
    joern_java_opts: str = "-Xmx4g"
    # JDK used only for Joern (empty = JAVA_HOME / PATH). On Apple Silicon this
    # must be an arm64 JDK, or JS/TS CPG builds fail (jssrc2cpg looks for an
    # x86 astgen binary that an arm64 Joern install doesn't include).
    joern_java_home: str = ""
    run_semgrep: bool = True
    run_regex_scan: bool = True
    semgrep_rules: str = "p/owasp-top-ten,p/java,p/python,p/javascript"

    # "Connect GitLab" OAuth app (per-project git access,
    # used to clone private repos without a manually pasted PAT). Empty
    # client id disables the /git-auth/{provider}/authorize route.
    gitlab_oauth_client_id: str = ""
    gitlab_oauth_client_secret: str = ""
    gitlab_oauth_redirect_uri: str = "http://localhost:3000/git-auth/gitlab/callback"
    gitlab_base_url: str = "https://gitlab.com"  # override for self-hosted GitLab

    @field_validator("anthropic_api_key", "openai_api_key", "dast_training_admin_token", mode="before")
    @classmethod
    def empty_api_key_is_unset(cls, value: object) -> object:
        if isinstance(value, str) and not value.strip():
            return None
        return value

    @field_validator(
        "dast_oast_callback_url",
        "dast_oast_poll_url",
        "dast_webhook_url",
        "dast_slack_webhook_url",
        "dast_jira_webhook_url",
        mode="before",
    )
    @classmethod
    def empty_oast_url_is_unset(cls, value: object) -> object:
        # DAST_OAST_CALLBACK_URL= in .env becomes "" — treat as not configured.
        if isinstance(value, str) and not value.strip():
            return None
        return value

    @field_validator(
        "dast_max_depth",
        "dast_max_pages",
        "dast_max_per_pattern",
        "dast_max_targets",
        "dast_max_tests_per_target",
        "dast_max_concurrent_requests",
        "dast_max_response_body_bytes",
        "dast_model_parallelism",
        "dast_browser_probe_max_inputs",
    )
    @classmethod
    def dast_limit_is_positive(cls, value: int) -> int:
        if value < 1:
            raise ValueError("must be >= 1")
        return value

    @field_validator("dast_max_runtime_minutes", "dast_rate_limit_per_sec")
    @classmethod
    def dast_rate_is_positive(cls, value: float) -> float:
        if value <= 0:
            raise ValueError("must be > 0")
        return value

    def dast_effective_settings(self) -> dict:
        """JSON-safe, secret-free snapshot of the DAST settings in force right now.

        Stored on `Scan.metadata_json[DAST_SETTINGS_SNAPSHOT_KEY]` at scan start."""
        return {
            "max_runtime_minutes": self.dast_max_runtime_minutes,
            "max_depth": self.dast_max_depth,
            "max_pages": self.dast_max_pages,
            "max_per_pattern": self.dast_max_per_pattern,
            "same_domain_mode": self.dast_same_domain_mode,
            "safe_mode": self.dast_safe_mode_default,
            "rate_limit_per_sec": self.dast_rate_limit_per_sec,
            "max_concurrent_requests": self.dast_max_concurrent_requests,
            "max_response_body_bytes": self.dast_max_response_body_bytes,
            "max_targets": self.dast_max_targets,
            "max_tests_per_target": self.dast_max_tests_per_target,
            "model_parallelism": self.dast_model_parallelism,
            "oast_configured": self.dast_oast_callback_url is not None,
            "opt_in_request_ceiling": self.dast_opt_in_request_ceiling,
            "oast_wait_s": self.dast_oast_wait_s,
            "browser_probe_enabled": self.dast_browser_probe_enabled,
            "browser_marker_posts": self.dast_browser_marker_posts,
            "browser_probe_max_inputs": self.dast_browser_probe_max_inputs,
            "model_routing": {task: list(route) for task, route in self.dast_model_routing.items()},
        }

    @property
    def dast_presets(self) -> dict[str, dict[str, float]]:
        """name -> concrete budgets for every intensity preset."""
        from app.dast.domain.presets import DEFAULT_DEEP, DEFAULT_LIGHT

        return {
            "light": {**DEFAULT_LIGHT, **self.dast_preset_light},
            "standard": {
                "max_targets": self.dast_max_targets,
                "max_tests_per_target": self.dast_max_tests_per_target,
                "max_depth": self.dast_max_depth,
                "max_pages": self.dast_max_pages,
                "max_runtime_minutes": self.dast_max_runtime_minutes,
                "max_per_pattern": self.dast_max_per_pattern,
            },
            "deep": {**DEFAULT_DEEP, **self.dast_preset_deep},
        }

    @property
    def dast_ollama_url(self) -> str:
        """Effective Ollama base URL for DAST model calls."""
        return self.dast_ollama_base_url.strip() or self.ollama_base_url

    @property
    def dast_model_routing(self) -> dict[str, tuple[str, str]]:
        """task name -> (provider, model), covering every task in `DAST_MODEL_TASKS`.

        A plain mapping on purpose: the settings UI (EPIC-15) persists overrides
        in the same shape."""
        routing: dict[str, tuple[str, str]] = {}
        for task in DAST_MODEL_TASKS:
            provider = getattr(self, f"dast_model_{task}_provider")
            model = getattr(self, f"dast_model_{task}_model").strip()
            if not model:
                model = {"ollama": self.dast_ollama_model, "bedrock": self.bedrock_model_id}.get(provider, "")
            routing[task] = (provider, model)
        return routing

    @field_validator("database_url", mode="before")
    @classmethod
    def empty_database_url_uses_default(cls, value: object) -> object:
        # DATABASE_URL= in .env becomes "" and would override the default.
        if value is None or (isinstance(value, str) and not value.strip()):
            return DEFAULT_DATABASE_URL
        return value


settings = Settings()
DATA_DIR.mkdir(parents=True, exist_ok=True)
Path(settings.workspaces_dir).mkdir(parents=True, exist_ok=True)
Path(settings.scan_logs_dir).mkdir(parents=True, exist_ok=True)
Path(settings.dast_screenshots_dir).mkdir(parents=True, exist_ok=True)
