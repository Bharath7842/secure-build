# DAST — Technology Stack

Complete tech stack for the greenfield DAST engine, mapped to the architecture (§3 of `DAST_complete_design.md`). Built on your existing FastAPI/SQLAlchemy platform, with precise package recommendations per tier.

---

## 1. Tier mapping to technology

| Architecture tier | Components | Tech stack |
|---|---|---|
| **Tier 1: Interfaces** | REST API, Web UI, CLI | FastAPI, Next.js, Click |
| **Tier 2: Orchestration & Safety** | Scan lifecycle, scope guard, rate controller | FastAPI tasks, APScheduler, ratelimit |
| **Tier 3: Discovery** | Browser crawler, network recorder, schema ingester, auth manager | Playwright, httpx, pydantic-core (schema parsing) |
| **Tier 4: Analysis** | Passive analyzer, active check engine, detectors, verdict roll-up | Pure Python (detectors), LangGraph (orchestration) |
| **Tier 5: Knowledge & Data** | Check catalog (YAML), findings store, evidence store, reports | SQLAlchemy ORM, YAML, reportlab, openpyxl |
| **Cross-cutting: Model layer** | Model Gateway, per-provider adapters | langchain-core, langchain-ollama, boto3, httpx |
| **Observability** | Logging, progress, narration | structlog, in-memory buffer, SSE |

---

## 2. Backend architecture — detailed stack

### 2.1 Core infrastructure

```
backend/
├── app/
│   ├── main.py                    # FastAPI app, mount routes
│   ├── config.py                  # Pydantic Settings (env-driven)
│   ├── db.py                      # SQLAlchemy session + idempotent migrations
│   ├── models.py                  # SQLAlchemy ORM: Scan, Finding, Evidence, etc.
│   ├── schemas.py                 # Pydantic request/response models
│   ├── security.py                # Bearer token verification (bearer_scheme)
│   ├── dependencies.py            # FastAPI dependencies (get_db, verify_bearer, etc.)
│   └── logging_config.py          # structlog setup
├── requirements.txt               # See below for full list
└── README.md
```

**Key packages:**

| Package | Version | Purpose |
|---|---|---|
| `fastapi` | >=0.115 | HTTP server, dependency injection, automatic OpenAPI |
| `uvicorn[standard]` | >=0.30 | ASGI server, lifespan events for startup/shutdown |
| `pydantic` | >=2.0 | Request/response validation, Settings for env vars |
| `pydantic-settings` | latest | `BaseSettings` for config (DATABASE_URL, DAST_OLLAMA_URL, etc.) |
| `sqlalchemy` | >=2.0 | ORM, connection pooling, Core for raw migrations |
| `alembic` | *not used* | Schema migrations are hand-written idempotent SQL in `db.py` |
| `httpx` | >=0.27 | Async HTTP client for API discovery, webhook callbacks |
| `structlog` | >=24 | Structured logging (JSON output, context bindings) |
| `python-multipart` | latest | Parse `multipart/form-data` (credential upload) |

**Database:** SQLite by default (file: `data/secure_build.db`); switchable via `DATABASE_URL` env var to PostgreSQL / MySQL for production. Connection pooling: `SQLAlchemy(pool_pre_ping=True, pool_recycle=3600)`.

### 2.2 DAST engine (Tier 3 + 4) — detailed stack

```
backend/app/dast/
├── __init__.py
├── graph.py                    # LangGraph StateGraph definition, node wiring
├── runner.py                   # Entry point: run_dast_scan() → graph.invoke()
├── state.py                    # GraphState TypedDict
├── nodes/                      # One file per node
│   ├── check_connection.py
│   ├── fingerprint.py
│   ├── authenticate.py
│   ├── discover.py             # → browser_crawler.py, network_recorder.py, schema_ingester.py
│   ├── passive_analysis.py     # → passive.py
│   ├── active_testing.py       # → check_runner.py, detectors.py
│   └── verdict_rollup.py
├── browser_crawler.py          # Playwright orchestration
├── network_recorder.py         # Request/response interceptor
├── schema_ingester.py          # OpenAPI/GraphQL/SOAP parser
├── auth_manager.py             # Form, token, pre-auth state handling
├── passive.py                  # Header/cookie/CORS/leak checks
├── check_catalog.py            # Load and validate check YAML
├── check_runner.py             # Construct → execute → detect → rule loop
├── detectors.py                # Pure functions: db_error_surfaced(), input_reflected_unescaped(), etc.
├── model_gateway.py            # **[NEW]** Provider-agnostic LLM interface
├── llm_adapters/               # **[NEW]** One adapter per provider
│   ├── ollama_adapter.py
│   ├── bedrock_adapter.py
│   ├── openai_adapter.py
│   └── anthropic_adapter.py
├── llm_utils.py                # call_llm_json(), call_llm_tool_choice(), retries
├── url_utils.py                # normalize_url(), get_url_pattern(), same-domain logic
├── app.py                      # Standalone Flask UI (dev/CLI use)
└── server.py                   # CLI entry point
```

**Key packages:**

| Package | Version | Purpose | Tier |
|---|---|---|---|
| `langgraph` | >=0.1.10 | State graphs, node orchestration, conditional edges | 2 + 4 |
| `langchain-core` | >=0.3 | Base types (LLMResult, etc.) | Cross-cutting |
| `langchain-ollama` | >=0.2 | `ChatOllama` provider (default) | Cross-cutting |
| `langchain-anthropic` | latest | `ChatAnthropic` provider (for Claude) | Cross-cutting |
| `langchain-openai` | latest | `ChatOpenAI` provider (for GPT/o1-mini) | Cross-cutting |
| `boto3` | >=1.35 | AWS Bedrock (Claude Haiku) | Cross-cutting |
| `playwright` | >=1.48 | Headless Chromium, network interceptor | 3 |
| `pydantic` | >=2.0 | Validate check catalog YAML, schemas | 4 + 5 |
| `pyyaml` | >=6.0 | Parse check catalog | 5 |
| `tldextract` | >=5.0 | Same-domain / root-domain parsing | 3 |
| `python-dateutil` | latest | Relative time parsing (findings, narration) | 5 |

### 2.3 Tier 2: Orchestration & Safety

```
backend/app/services/
├── scan_runner.py              # _execute_dast_scan(): status mgmt, log capture, persist
├── engine_adapter.py           # run_dast_scan(): gate between mock and real engine
├── safety_guard.py             # **[NEW]** Scope lock, method gating, rate limiting
├── findings_writer.py          # Persist Finding rows + Evidence rows
└── dast_narration.py           # Log → narration timeline (LLM + template fallback)
```

**Key packages:**

| Package | Version | Purpose |
|---|---|---|
| `ratelimit` | >=2.2 | Per-IP / per-scan request rate limiting |
| `apscheduler` | >=3.10 | Optional: background task scheduling (cross-scan reporting) |
| `asyncio` | builtin | Async context managers, task cancellation |

**Safety guardrail flow (every request):**
```
request → Tier 2 safety_guard.py
  ├─ scope_lock: URL resolves to authorized host(s)? → 403 if not
  ├─ method_gate: POST/PUT/DELETE allowed? (safe_mode setting) → 405 if not
  ├─ rate_limit: ≤ N requests/sec? → 429 if exceeded
  └─ abort_check: scan cancelled? → abort if yes
→ execute request → return response
```

### 2.4 Tier 5: Knowledge & Data

```
backend/app/data/
├── check_catalog.yaml          # **[NEW]** All checks, each: {id, cwe, owasp, apisec, applies_to, signal[], severity}
├── remediation/                # **[NEW]** Markdown per check id (rem/sqli.md, rem/bola.md, etc.)
│   ├── sqli.md
│   ├── xss.md
│   ├── bola.md
│   ├── bfla.md
│   └── ...
└── prompts/                    # **[NEW]** System prompts per task
    ├── fingerprint.md
    ├── crawl_plan.md
    ├── construct.md
    ├── rule.md
    └── narrate.md
```

**Database schema (SQLAlchemy models):**

```python
class Scan(Base):
    id: UUID
    kind: str = "dast"  # alongside "sast", "sca", "sbom"
    git_url: str        # target URL (reused field name for simplicity)
    status: str         # queued, running, success, failed, cancelled
    progress: float     # 0-100, updated from engine log
    metadata_json: dict # {dast_input, discovery, api_analysis, dast_narration, ...}
    created_at, updated_at: datetime
    findings: Relationship[List[Finding]]

class Finding(Base):
    id: UUID
    scan_id: UUID
    kind: str = "dast"
    rule_id: str        # check id from catalog (dast-bola, dast-xss, etc.)
    severity: str       # critical, high, medium, low, info
    confidence: str     # HIGH, MEDIUM, LOW
    verdict: str        # true_positive, unverified, false_positive
    target: str         # "<METHOD> <path>" or "<METHOD> <path?param=...>"
    param: str          # injected parameter name (or null for header/whole-response findings)
    location: str       # query, path, header, body, response
    source: str         # which detector surfaced it
    sink: str           # API URL or form action
    verdict_reason: str # one-line model explanation
    evidence: Relationship[Evidence] # baseline/test/signals
    remediation_ref: str # "rem/bola.md"
    first_seen_scan: UUID
    last_seen_scan: UUID

class Evidence(Base):
    id: UUID
    finding_id: UUID
    baseline: dict      # {status, len, body_excerpt}
    test: dict          # {status, len, body_excerpt, error?}
    detector_signals: List[str]  # [db_error_surfaced, boolean_divergence, ...]
    confidence_delta: float  # numeric confidence breakdown
```

### 2.5 Model Gateway (Tier 2, cross-cutting)

**New module: `backend/app/dast/model_gateway.py`**

```python
class ModelGatewayConfig:
    # Per-task routing
    task_routes: Dict[str, ProviderConfig] = {
        "fingerprint": ProviderConfig(provider="ollama", model="gpt-oss:20b"),
        "crawl_plan": ProviderConfig(provider="ollama", model="gpt-oss:20b"),
        "construct": ProviderConfig(provider="ollama", model="gpt-oss:20b"),
        "rule": ProviderConfig(provider="ollama", model="gpt-oss:20b"),  # can swap to bedrock for higher stakes
        "narrate": ProviderConfig(provider="ollama", model="gpt-oss:20b"),
    }
    # Credentials
    ollama_base_url: str = "http://localhost:11434"
    bedrock_region: str = "us-east-1"
    bedrock_model: str = "anthropic.claude-3-5-haiku-20241022-v1:0"
    openai_api_key: SecretStr
    anthropic_api_key: SecretStr
    # Fine-tuning
    active_finetuned_model: Optional[str] = None  # e.g. "dast-tuned" for Ollama

class ModelGateway:
    """Unified LLM interface; routes per task to provider adapters."""
    
    async def call_llm(self, task: str, system: str, prompt: str, 
                       schema: Optional[Dict], max_tokens: int = 2000,
                       temperature: float = 0.1) -> Dict:
        """
        task: "fingerprint", "crawl_plan", "construct", "rule", "narrate"
        Returns: validated JSON response per schema
        """
        config = self.config.task_routes[task]
        adapter = self._get_adapter(config.provider)
        return await adapter.call(system, prompt, schema, max_tokens, temperature)
```

**Provider adapters:** Each in `backend/app/dast/llm_adapters/`

```python
# ollama_adapter.py
class OllamaAdapter:
    async def call(self, system, prompt, schema, max_tokens, temperature):
        from langchain_ollama import ChatOllama
        model = ChatOllama(base_url=self.base_url, model=self.model_id, temperature=temperature)
        # Construct messages, call, validate against schema
        
# bedrock_adapter.py
class BedrockAdapter:
    async def call(self, system, prompt, schema, max_tokens, temperature):
        from langchain_anthropic import ChatAnthropic
        model = ChatAnthropic(model_id=self.model_id, temperature=temperature)
        # ...

# openai_adapter.py
class OpenAIAdapter:
    async def call(self, system, prompt, schema, max_tokens, temperature):
        from langchain_openai import ChatOpenAI
        model = ChatOpenAI(model=self.model_id, temperature=temperature)
        # ...

# anthropic_adapter.py
class AnthropicAdapter:
    async def call(self, system, prompt, schema, max_tokens, temperature):
        from langchain_anthropic import ChatAnthropic
        model = ChatAnthropic(model=self.model_id, temperature=temperature)
        # ...
```

---

## 3. Frontend (Tier 1) — detailed stack

```
frontend/
├── app/
│   ├── layout.tsx              # App shell (rail, main, theme)
│   ├── dast/
│   │   ├── page.tsx            # Dashboard
│   │   ├── new-scan/page.tsx   # New Scan form (multi-identity)
│   │   └── [id]/
│   │       ├── page.tsx        # Scan Detail (tabs: Timeline, Discovery, Findings, Authz, Report)
│   │       └── layout.tsx
│   ├── findings/page.tsx       # Findings list + detail
│   ├── reports/page.tsx        # Scan-to-scan diff + exports
│   └── api/
│       ├── scans/
│       │   ├── route.ts        # POST (create), GET (list) — calls backend
│       │   └── [id]/
│       │       ├── route.ts    # GET (detail), PATCH (cancel), DELETE
│       │       ├── narration/route.ts   # SSE stream
│       │       └── logs/route.ts        # Polling endpoint
│       ├── findings/route.ts   # GET (list with filters)
│       └── reports/route.ts    # GET (diff, PDF/XLSX export)
├── components/
│   ├── Dast*.tsx               # DastNewScanForm, DastScanDetail, DastFindingsPanel, etc.
│   ├── DastAuthzMatrix.tsx     # Role × role heatmap
│   ├── DastNarrationTimeline.tsx
│   └── AgentArtifactCard.tsx   # Reused from SAST
├── lib/
│   ├── api.ts                  # Fetch wrapper (adds Bearer token via server routes)
│   ├── server-sast.ts          # sastFetch() — reused for DAST too
│   ├── types.ts                # TypeScript interfaces for all DAST data shapes
│   └── utils.ts                # Format severity, confidence, role badge colors, etc.
├── styles/
│   └── globals.css             # Tailwind imports
├── public/                      # Favicons, logos
└── next.config.ts
```

**Key packages:**

| Package | Version | Purpose |
|---|---|---|
| `next` | 16.2.10 | App Router, server components, route handlers |
| `react` | 19.2.4 | UI components |
| `typescript` | 5.x | Type safety |
| `tailwindcss` | 4.x | Utility CSS (color: severity + role badges) |
| `eslint` | 9.x | Linting |

**Notable components:**

- **DastNewScanForm.tsx** — Multi-identity input. One card per role, each with auth-method toggle (Form / Token / Pre-auth state). Live preview of authorization test matrix below.
- **DastAuthzMatrix.tsx** — Interactive role × role grid. Click a red cell (FAIL) to filter Findings by that role pair.
- **DastScanDetail.tsx** — Polls `/scans/{id}` every 2s. Tabs: Timeline (narration stream), Discovery (pages/endpoints/forms), Findings (master–detail), Authz (matrix), Report (diff + export).
- **DastFindingsPanel.tsx** — Master list with filters (severity, role, check, verdict). Detail pane shows evidence block (monospace baseline/test), detector signals, verdict, remediation link.

**Server routes (app/api/**/route.ts):**
- Add Bearer token from backend (never expose to browser)
- Proxy to `http://localhost:8000` (FastAPI, configurable)
- Handle CORS (allow localhost in dev, same-origin in prod)

---

## 4. Runtime topology — detailed

```
┌─────────────────────────────────────────────────────────┐
│ Browser                                                 │
│ ┌─────────────────────────────────────────────────────┐ │
│ │ React 19 (Next.js App Router)                       │ │
│ │ ├─ DastScanDetail: polling /api/scans/{id}/logs   │ │
│ │ └─ DastNarrationTimeline: SSE /api/scans/{id}/... │ │
│ └─────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────┘
                         ↓ fetch() with no Bearer
┌─────────────────────────────────────────────────────────┐
│ Next.js route handlers (app/api/**/route.ts)            │
│ ├─ Add Bearer token from env                            │
│ └─ Proxy to FastAPI                                     │
└─────────────────────────────────────────────────────────┘
                         ↓ Bearer: auth
┌─────────────────────────────────────────────────────────────────────────┐
│ FastAPI (Uvicorn, 1 process)                                            │
│ ├─ /scans (POST, GET, GET/{id}, PATCH/{id}, DELETE/{id})             │
│ ├─ /scans/{id}/narration (GET, stream)                                │
│ ├─ /findings (GET with filters)                                       │
│ ├─ /reports (GET, POST for diff)                                      │
│ ├─ /health                                                            │
│ │                                                                      │
│ ├─ services/                                                          │
│ │ ├─ scan_runner.py (_execute_dast_scan)                            │
│ │ ├─ engine_adapter.py (run_dast_scan)                              │
│ │ ├─ safety_guard.py (scope_lock, method_gate, rate_limit)         │
│ │ ├─ findings_writer.py (Finding + Evidence rows)                   │
│ │ └─ dast_narration.py (log → timeline)                             │
│ │                                                                      │
│ ├─ dast/                                                              │
│ │ ├─ graph.py (LangGraph StateGraph)                                │
│ │ ├─ nodes/ (check_connection, fingerprint, ..., verdict_rollup)   │
│ │ ├─ browser_crawler.py (Playwright)                               │
│ │ ├─ detectors.py (pure functions)                                 │
│ │ ├─ model_gateway.py (provider routing)                           │
│ │ └─ llm_adapters/ (ollama, bedrock, openai, anthropic)           │
│ │                                                                      │
│ └─ db.py (SQLAlchemy + SQLite)                                       │
│                                                                        │
│ [Background thread]                                                   │
│ ├─ LangGraph DAST pipeline                                           │
│ │ ├─ Playwright Chromium → target app                              │
│ │ ├─ Network interceptor → API calls                               │
│ │ └─ Detectors → verdict roll-up                                   │
│ │                                                                      │
│ └─ Ollama/Bedrock/OpenAI calls                                       │
│    (via model_gateway.py adapters)                                    │
│                                                                        │
└─────────────────────────────────────────────────────────────────────────┘
                         ↓
┌──────────────────────────────────────────────────────────┐
│ Target app (example: app.example.com)                   │
│ ├─ Page crawl (Playwright)                              │
│ └─ API calls (httpx, authenticated session)            │
└──────────────────────────────────────────────────────────┘
                         ↓
┌──────────────────────────────────────────────────────────┐
│ Ollama (localhost:11434, if using local model)          │
│ └─ gpt-oss:20b (or another open GGUF)                   │
└──────────────────────────────────────────────────────────┘
                         ↓ (if configured)
┌──────────────────────────────────────────────────────────┐
│ AWS Bedrock / OpenAI / Anthropic (hosted LLMs)          │
└──────────────────────────────────────────────────────────┘
```

---

## 5. Configuration (environment + code)

**Environment variables (read by Pydantic Settings):**

```bash
# Database
DATABASE_URL=sqlite:///data/secure_build.db  # or postgresql://...

# FastAPI
SAST_API_TOKEN=secret_key_here
DAST_API_TOKEN=secret_key_here_if_separate  # or reuse SAST_API_TOKEN

# DAST-specific
DAST_OLLAMA_BASE_URL=http://localhost:11434
DAST_OLLAMA_MODEL=gpt-oss:20b
USE_MOCK_ENGINE=false
RUN_DAST=true

# AWS Bedrock (if using)
AWS_REGION=us-east-1
AWS_ACCESS_KEY_ID=...
AWS_SECRET_ACCESS_KEY=...
BEDROCK_MODEL_ID=anthropic.claude-3-5-haiku-20241022-v1:0

# OpenAI (if using)
OPENAI_API_KEY=sk-...

# Anthropic (if using)
ANTHROPIC_API_KEY=sk-ant-...

# Scan defaults
DAST_MAX_RUNTIME_MINUTES=10
DAST_MAX_DEPTH=3
DAST_MAX_PAGES=100
DAST_MAX_PER_PATTERN=3
DAST_SAME_DOMAIN_MODE=exact  # or root
DAST_SAFE_MODE_DEFAULT=true

# Rate limiting
DAST_RATE_LIMIT_PER_SEC=5

# OAST callback (optional, for SSRF)
DAST_OAST_CALLBACK_URL=https://oast.your-domain.com

# Frontend
NEXT_PUBLIC_API_BASE_URL=http://localhost:8000  # dev only; prod uses relative /api
```

**Code config (`backend/app/config.py`):**

```python
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    # Database
    database_url: str = "sqlite:///data/secure_build.db"
    
    # Auth
    sast_api_token: str = Field(..., min_length=32)
    dast_api_token: Optional[str] = None  # fallback to sast_api_token
    
    # DAST engine
    use_mock_engine: bool = False
    run_dast: bool = True
    dast_ollama_base_url: str = "http://localhost:11434"
    dast_ollama_model: str = "gpt-oss:20b"
    
    # AWS Bedrock
    aws_region: str = "us-east-1"
    bedrock_model_id: str = "anthropic.claude-3-5-haiku-20241022-v1:0"
    
    # OpenAI / Anthropic (stored as SecretStr in pydantic_settings)
    openai_api_key: Optional[SecretStr] = None
    anthropic_api_key: Optional[SecretStr] = None
    
    # Scan defaults
    dast_max_runtime_minutes: int = 10
    dast_max_depth: int = 3
    dast_max_pages: int = 100
    dast_max_per_pattern: int = 3
    dast_safe_mode_default: bool = True
    dast_rate_limit_per_sec: float = 5.0
    dast_oast_callback_url: Optional[str] = None
    
    # Fine-tuning
    dast_finetuned_model: Optional[str] = None  # e.g., "dast-tuned" for Ollama
    dast_fewshot_examples_path: str = "data/dast_fewshot_examples.json"
    
    class Config:
        env_file = ".env"
        case_sensitive = True

settings = Settings()
```

---

## 6. Local development setup

### Prerequisites

```bash
# Python
python3.12 -m venv venv
source venv/bin/activate
pip install -r backend/requirements.txt

# Playwright
python -m playwright install chromium

# Ollama
ollama pull gpt-oss:20b
# Then: ollama serve  (in another terminal, runs on http://localhost:11434)

# Node
node --version  # ≥18
npm install --prefix frontend
```

### Run

```bash
# Backend (terminal 1)
cd backend
export DAST_API_TOKEN=dev_token_change_me
export USE_MOCK_ENGINE=false  # for real engine
python -m uvicorn app.main:app --reload --port 8000

# Frontend (terminal 2)
cd frontend
npm run dev  # http://localhost:3000

# Ollama (terminal 3, if not systemd service)
ollama serve
```

### Test (mock engine, no Ollama/Playwright needed)

```bash
cd backend
export USE_MOCK_ENGINE=true
pytest tests/test_dast_scan.py -v
```

---

## 7. Production deployment

### Options

**Option A: Docker compose (all-in-one)**
```yaml
version: '3.8'
services:
  backend:
    build: ./backend
    ports: ["8000:8000"]
    environment:
      DATABASE_URL: postgresql://user:pass@postgres:5432/dast
      DAST_OLLAMA_BASE_URL: http://ollama:11434
    depends_on: [postgres, ollama]
  
  frontend:
    build: ./frontend
    ports: ["3000:3000"]
    environment:
      NEXT_PUBLIC_API_BASE_URL: /api  # same-origin
  
  postgres:
    image: postgres:16-alpine
  
  ollama:
    image: ollama/ollama:latest
    volumes: [ollama-data:/root/.ollama]
```

**Option B: Kubernetes**
- FastAPI in a Deployment with replicas (stateless, can scale)
- Ollama as a Deployment or StatefulSet (stateful, needs persistent volume)
- PostgreSQL as a StatefulSet
- Next.js as a Deployment (or push to CDN for static export)
- Ingress for routing

**Option C: Managed services**
- Backend: Cloud Run, Lambda, EC2
- Database: Cloud SQL, RDS, Aurora
- Ollama: self-hosted on VM (most control) or Bedrock/OpenAI (no local model)
- Frontend: Vercel, Netlify, S3 + CloudFront

### Production checklist

- [ ] Database: PostgreSQL (not SQLite), replication, backups
- [ ] Secrets: API keys in a vault (AWS Secrets Manager, HashiCorp Vault, etc.), not `.env`
- [ ] HTTPS + TLS certificates (e.g., Let's Encrypt)
- [ ] CORS: restrict to known frontend origins
- [ ] Rate limiting: per-IP + per-user
- [ ] Logging: centralized (ELK, CloudWatch, DataDog, etc.)
- [ ] Monitoring: scan duration, LLM latency, error rates
- [ ] Backups: database snapshots, findings export
- [ ] Multi-node DAST runners: queue system (optional; threads work for <50 concurrent scans)

---

## 8. Integrations with existing engines

Your platform already has SAST, SCA, SBOM. DAST integrates cleanly:

| Aspect | Reuse | New |
|---|---|---|
| Database | `findings`, `evidence` tables (same schema) | `api_analysis` in Scan.metadata_json |
| API | Bearer token auth (same), OpenAPI endpoints | `/scans` (DAST-specific) |
| UI | Dashboard layout, findings views, export | DastNewScanForm, DastAuthzMatrix |
| LLM routing | Model Gateway pattern (can apply to SAST too) | DAST model adapters + per-task routing |
| Findings export | PDF/XLSX export already works (shared Finding row) | — |

---

## 9. Dependencies summary

**Backend requirements.txt (complete for DAST):**

```
# Core
fastapi>=0.115
uvicorn[standard]>=0.30
pydantic>=2.0
pydantic-settings
sqlalchemy>=2.0
alembic
httpx>=0.27
structlog>=24
python-multipart

# DAST
langgraph>=0.1.10
langchain-core>=0.3
langchain-ollama>=0.2
langchain-anthropic
langchain-openai
boto3>=1.35
playwright>=1.48
pyyaml>=6.0
tldextract>=5.0
python-dateutil

# Export
reportlab>=4.1
openpyxl>=3.1

# Testing
pytest>=8
pytest-asyncio

# Development
black
isort
mypy
```

**Frontend package.json (key deps):**

```json
{
  "dependencies": {
    "next": "16.2.10",
    "react": "19.2.4",
    "typescript": "5.x",
    "tailwindcss": "4.x"
  },
  "devDependencies": {
    "eslint": "9.x",
    "eslint-config-next": "16.2.10"
  }
}
```

---

## 10. Checklist: tech stack decisions to confirm

- [ ] **Model routing:** Route `rule` (highest-stakes) to Bedrock/OpenAI, others to local gpt-oss:20b?
- [ ] **Database:** SQLite for dev, PostgreSQL for production — confirm?
- [ ] **Ollama model:** Stick with gpt-oss:20b, or try a different open GGUF?
- [ ] **Rate limiting:** Per-IP or per-user or per-scan? Threshold 5 req/sec?
- [ ] **OAST callback:** Enable for SSRF testing? Use a managed service (Burp Collaborator, Interactsh, etc.)?
- [ ] **Deployment:** Docker compose, Kubernetes, or managed services (Cloud Run + Cloud SQL)?
- [ ] **Frontend static export:** Can we push Next.js to CDN (no dynamic routes)? Or keep it dynamic (easier auth)?
