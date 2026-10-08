# Secure Build P1+P2 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a pipeline-friendly FastAPI (projects + scans + Bedrock/AST agent) and an editorial Next.js UI that creates projects, runs incremental AI SAST, and reviews findings.

**Architecture:** FastAPI owns projects/scans/findings in an app SQLite DB (optional Postgres later), invokes `SAST_Framework` (LangGraph + Bedrock + symbol_indexer) via an adapter, stores per-repo `symbol_index.db` on disk. Next.js App Router + Tailwind editorial sidebar talks only to Next BFF routes that proxy to FastAPI with a server-side Bearer token.

**Tech Stack:** Python 3.11+ / FastAPI / SQLAlchemy / SQLite · existing `sast_scan_agent.py` + Bedrock · Next.js 15 App Router / React / Tailwind · TypeScript

**Spec:** `docs/superpowers/specs/2026-07-14-secure-build-sast-ui-design.md`

---

## File map

```
Secure-Build/
  .env.example
  .gitignore
  README.md
  docs/ci/
    curl-example.md
    jenkins-declarative.md
    github-actions.md
  backend/
    requirements.txt
    app/
      __init__.py
      main.py                 # FastAPI app, CORS, routers
      config.py               # env settings
      auth.py                 # Bearer verify
      db.py                   # engine, session, init
      models.py               # SQLAlchemy models
      schemas.py              # Pydantic
      routers/
        projects.py
        scans.py
      services/
        scan_runner.py        # background scan orchestration
        engine_adapter.py     # calls SAST_Framework
        incremental.py        # file hashes / changed paths
        gates.py              # gate_summary from project thresholds
      defaults/
        owasp_urls.py         # Top10 / Top15 URL presets
  data/                       # gitignored — sqlite + workspaces
  frontend/
    package.json
    next.config.ts
    tailwind.config.ts
    app/
      layout.tsx
      globals.css
      page.tsx                # redirect → /scans/new or /projects
      projects/page.tsx
      projects/new/page.tsx
      projects/[id]/page.tsx
      scans/page.tsx
      scans/new/page.tsx
      scans/[id]/page.tsx
      api/projects/route.ts
      api/projects/[id]/route.ts
      api/scans/route.ts
      api/scans/[id]/status/route.ts
      api/scans/[id]/results/route.ts
    components/
      Sidebar.tsx
      ProjectForm.tsx
      ScanForm.tsx
      ScanStatusBadge.tsx
      FindingsList.tsx
      FindingDetail.tsx
    lib/
      types.ts
      api.ts                  # browser → /api/*
      server-sast.ts          # server → FastAPI + token
```

---

### Task 1: Repository bootstrap

**Files:**
- Create: `.gitignore`, `.env.example`, `README.md`
- Create: `backend/requirements.txt`, `backend/app/__init__.py`, `backend/app/config.py`

- [ ] **Step 1: Initialize git (repo is currently uninitialized)**

```bash
cd D:/Secure-Build
git init
```

- [ ] **Step 2: Write `.gitignore`**

```gitignore
.env
.env.local
data/
__pycache__/
*.pyc
.venv/
venv/
node_modules/
frontend/.next/
frontend/out/
.superpowers/
*.db
.DS_Store
```

- [ ] **Step 3: Write `.env.example`**

```env
SAST_API_TOKEN=changeme-token
SAST_FRAMEWORK_PATH=D:\dev\SAST_Framework
AWS_REGION=us-east-1
BEDROCK_MODEL_ID=us.anthropic.claude-haiku-4-5-20251001-v1:0
NVD_API_KEY=
DATABASE_URL=sqlite:///D:/Secure-Build/data/secure_build.db
SAST_API_URL=http://localhost:8000
```

- [ ] **Step 4: Write `backend/app/config.py`**

```python
from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict

ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = ROOT / "data"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    sast_api_token: str = "changeme-token"
    sast_framework_path: str = r"D:\dev\SAST_Framework"
    aws_region: str = "us-east-1"
    bedrock_model_id: str = "us.anthropic.claude-haiku-4-5-20251001-v1:0"
    nvd_api_key: str | None = None
    database_url: str = f"sqlite:///{(DATA_DIR / 'secure_build.db').as_posix()}"
    workspaces_dir: str = str(DATA_DIR / "workspaces")
    use_mock_engine: bool = False  # True in unit tests


settings = Settings()
DATA_DIR.mkdir(parents=True, exist_ok=True)
Path(settings.workspaces_dir).mkdir(parents=True, exist_ok=True)
```

- [ ] **Step 5: Write `backend/requirements.txt`**

```text
fastapi>=0.115.0
uvicorn[standard]>=0.32.0
sqlalchemy>=2.0.36
pydantic>=2.9.0
pydantic-settings>=2.6.0
httpx>=0.27.0
pytest>=8.3.0
pytest-asyncio>=0.24.0
```

(Agent/Bedrock deps stay in `SAST_Framework/requirements.txt`; document that both venvs or a shared venv must install those when `use_mock_engine=false`.)

- [ ] **Step 6: Write a short `README.md`** with run instructions for backend (`uvicorn app.main:app`) and frontend (`npm run dev`), pointing at the spec and CI docs (to be added in Task 13).

- [ ] **Step 7: Commit**

```bash
git add .gitignore .env.example README.md backend/requirements.txt backend/app/__init__.py backend/app/config.py
git commit -m "chore: bootstrap Secure Build repo and backend config"
```

---

### Task 2: App DB models + session

**Files:**
- Create: `backend/app/db.py`, `backend/app/models.py`
- Test: `backend/tests/test_db.py`

- [ ] **Step 1: Write failing test `backend/tests/test_db.py`**

```python
from app.db import init_db, SessionLocal
from app.models import Project


def test_can_insert_project(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path}/t.db")
    # re-import or call init with overridden URL — implement so init_db() uses settings
    init_db()
    with SessionLocal() as db:
        p = Project(name="demo", default_git_url="https://github.com/org/repo.git")
        db.add(p)
        db.commit()
        assert p.id is not None
```

- [ ] **Step 2: Run test — expect fail (modules missing)**

```bash
cd D:/Secure-Build/backend
python -m venv .venv
# Windows:
.venv\Scripts\activate
pip install -r requirements.txt
pytest tests/test_db.py -v
```

Expected: FAIL import error

- [ ] **Step 3: Implement `backend/app/models.py`**

```python
import uuid
from datetime import datetime, timezone
from sqlalchemy import String, Text, Integer, Float, Boolean, DateTime, ForeignKey, JSON
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
    enable_sast: Mapped[bool] = mapped_column(Boolean, default=True)
    enable_sca: Mapped[bool] = mapped_column(Boolean, default=True)
    enable_secrets: Mapped[bool] = mapped_column(Boolean, default=False)
    scan_mode: Mapped[str] = mapped_column(String(20), default="incremental")  # full|incremental
    gate_max_critical: Mapped[int] = mapped_column(Integer, default=0)
    gate_max_high: Mapped[int | None] = mapped_column(Integer, nullable=True)
    owasp_mode: Mapped[str] = mapped_column(String(20), default="top10")  # top10|top15|custom
    owasp_urls: Mapped[list] = mapped_column(JSON, default=list)
    nvd_urls: Mapped[list] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)
    scans: Mapped[list["Scan"]] = relationship(back_populates="project")


class Scan(Base):
    __tablename__ = "scans"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id"), index=True)
    git_url: Mapped[str] = mapped_column(String(500))
    branch: Mapped[str] = mapped_column(String(200), default="main")
    commit_sha: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    status: Mapped[str] = mapped_column(String(20), default="queued")  # queued|running|success|failed
    progress: Mapped[int] = mapped_column(Integer, default=0)
    message: Mapped[str | None] = mapped_column(Text, nullable=True)
    metadata_json: Mapped[dict] = mapped_column("metadata", JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)
    project: Mapped["Project"] = relationship(back_populates="scans")
    findings: Mapped[list["Finding"]] = relationship(back_populates="scan")


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
    scan: Mapped["Scan"] = relationship(back_populates="findings")


class FileSnapshot(Base):
    __tablename__ = "file_snapshots"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id"), index=True)
    path: Mapped[str] = mapped_column(String(700))
    content_hash: Mapped[str] = mapped_column(String(64))
    commit_sha: Mapped[str | None] = mapped_column(String(64), nullable=True)
```

- [ ] **Step 4: Implement `backend/app/db.py`** with `engine`, `SessionLocal`, `init_db()` creating tables; for SQLite use `check_same_thread=False`.

- [ ] **Step 5: Fix test to reload settings after monkeypatch (or pass URL into `init_db(url)`).** Make `init_db` accept optional URL for tests.

- [ ] **Step 6: Run pytest — expect PASS**

- [ ] **Step 7: Commit** `feat(db): add SQLAlchemy models for projects scans findings`

---

### Task 3: Auth + OWASP URL defaults + Projects API

**Files:**
- Create: `backend/app/auth.py`, `backend/app/schemas.py`, `backend/app/defaults/owasp_urls.py`, `backend/app/routers/projects.py`, `backend/app/main.py`
- Test: `backend/tests/test_projects_api.py`

- [ ] **Step 1: Write `defaults/owasp_urls.py`** returning lists for `top10` and `top15` using the same OWASP Top10:2025 base URLs as in `sast_scan_agent.py` (`https://owasp.org/Top10/A01_2025-...` through A10; for top15 append five cheat-sheet URLs from `build_owasp_urls` patterns such as Injection, XSS, Auth).

- [ ] **Step 2: Write failing API test** using FastAPI `TestClient`:

```python
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)
HDR = {"Authorization": "Bearer changeme-token"}


def test_create_project_prefills_owasp_top10(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path}/p.db")
    # ensure app reinits db — call init_db in fixture
    r = client.post("/projects", headers=HDR, json={
        "name": "payments-api",
        "default_git_url": "https://github.com/org/payments.git",
        "languages": ["Java", "TypeScript"],
        "frameworks": ["Spring Boot"],
        "owasp_mode": "top10",
    })
    assert r.status_code == 201
    body = r.json()
    assert body["name"] == "payments-api"
    assert len(body["owasp_urls"]) >= 10
```

- [ ] **Step 3: Implement auth** — `verify_bearer(authorization: str | None)` raises 401 unless `Bearer {settings.sast_api_token}`.

- [ ] **Step 4: Implement Pydantic schemas** for ProjectCreate / ProjectUpdate / ProjectOut (all fields from model that the UI needs).

- [ ] **Step 5: Implement router** `POST/GET /projects`, `GET/PATCH /projects/{id}` with auth dependency. On create, if `owasp_urls` empty, set from `owasp_mode` presets.

- [ ] **Step 6: Wire `main.py`**: `init_db()` on startup, include routers, title `Secure Build SAST API`.

- [ ] **Step 7: Run pytest — PASS**

- [ ] **Step 8: Commit** `feat(api): projects CRUD with OWASP URL presets`

---

### Task 4: Scans API — create, list, status, idempotency (mock engine)

**Files:**
- Create: `backend/app/routers/scans.py`, `backend/app/services/scan_runner.py`, `backend/app/services/engine_adapter.py`, `backend/app/services/gates.py`
- Test: `backend/tests/test_scans_api.py`

- [ ] **Step 1: Write failing tests**

```python
def test_trigger_scan_idempotent(client, project_id, HDR):
    payload = {"project_id": project_id, "commit_sha": "abc123", "branch": "main"}
    r1 = client.post("/scans", headers=HDR, json=payload)
    r2 = client.post("/scans", headers=HDR, json=payload)
    assert r1.status_code == 202
    assert r2.json()["scan_id"] == r1.json()["scan_id"]


def test_force_creates_new_scan(client, project_id, HDR):
    payload = {"project_id": project_id, "commit_sha": "abc123", "force": True}
    r1 = client.post("/scans", headers=HDR, json=payload)
    r2 = client.post("/scans", headers=HDR, json=payload)
    assert r1.json()["scan_id"] != r2.json()["scan_id"]
```

- [ ] **Step 2: Implement `engine_adapter.run_scan(...)` mock path** when `settings.use_mock_engine` or env `USE_MOCK_ENGINE=true`: sleep briefly, return 1–2 fake findings with severity/snippet/ai_fix.

- [ ] **Step 3: Implement `gates.build_gate_summary(project, findings) -> dict`** comparing counts to `gate_max_critical` / `gate_max_high`.

- [ ] **Step 4: Implement `scan_runner.start_scan_background(scan_id)`** — set running, call adapter, save findings, set status `success` (engine OK) even if gate fails; store progress 0–100.

- [ ] **Step 5: Implement scans router**

- `POST /scans` body: `project_id`, optional `git_url`, `branch`, `commit_sha`, `metadata`, `force`
- Resolve git_url from project default if omitted
- Idempotency unless `force`
- Return 202 `{ scan_id, status, status_url }`
- `GET /scans`, `GET /scans/{id}/status`, `GET /scans/{id}/results` (409 if queued/running)

- [ ] **Step 6: Results include `gate_summary` + `findings[]`**

- [ ] **Step 7: Tests PASS with `USE_MOCK_ENGINE=true`**

- [ ] **Step 8: Commit** `feat(api): scans lifecycle with idempotency and gate summary`

---

### Task 5: Incremental file hashing

**Files:**
- Create: `backend/app/services/incremental.py`
- Test: `backend/tests/test_incremental.py`

- [ ] **Step 1: Write test** — given two fake file trees, `compute_changed_paths(project_id, root, commit_sha, db)` returns only modified/new paths and updates `FileSnapshot` rows.

- [ ] **Step 2: Implement** SHA-256 of file contents for extensions used by the agent (at least `.java`, `.ts`, `pom.xml`, `package.json`); skip `SKIP_DIRS` matching agent.

- [ ] **Step 3: Integrate into `scan_runner`**: after checkout (Task 6), compute `changed_paths`; if `scan_mode==full` or first scan (no snapshots), pass `changed_paths=None` meaning full index.

- [ ] **Step 4: Tests PASS · Commit** `feat(scan): incremental file snapshot hashing`

---

### Task 6: Git checkout + real engine adapter

**Files:**
- Modify: `backend/app/services/engine_adapter.py`, `backend/app/services/scan_runner.py`
- Test: `backend/tests/test_engine_adapter_mock.py` (keep CI green without Bedrock)
- Manual: document live Bedrock test

- [ ] **Step 1: Implement workspace checkout** in `scan_runner`:

```python
workspace = Path(settings.workspaces_dir) / project.id
# git clone if missing else fetch; checkout commit_sha or branch
```

Use `subprocess` for `git clone` / `git fetch` / `git checkout`. On failure set scan `status=failed`, `message=stderr`.

- [ ] **Step 2: Real adapter** — add `SAST_FRAMEWORK_PATH` to `sys.path`, import agent entrypoints. Prefer a thin function:

```python
def run_real_scan(*, workspace: Path, project_context: str, owasp_urls: list[str],
                  nvd_urls: list[str], changed_paths: list[str] | None) -> list[dict]:
    ...
```

Map agent findings into dicts matching `Finding` fields. If agent API is CLI-oriented, subprocess:

```bash
python sast_scan_agent.py --path <workspace> --context "<languages frameworks>" --out <tmp.json>
```

If HTML-only today, add a small JSON export helper **in the adapter** by calling the agent’s internal pipeline functions (import `run` graph) — prefer import over parsing HTML. If import surface is awkward, add `export_findings_json` patch file under `backend/app/services/agent_bridge.py` that duplicates only the orchestration calls needed (do not fork entire agent).

- [ ] **Step 3: Call symbol indexer** for changed files (or full tree) producing/updating `workspace/symbol_index.db` before/during scan as the agent expects.

- [ ] **Step 4: Keep mock engine default in pytest**; set `use_mock_engine=false` only when `SAST_FRAMEWORK_PATH` exists and `RUN_LIVE_SAST=1`.

- [ ] **Step 5: Manual verification checklist** in README: AWS creds, Bedrock model access, sample Spring repo.

- [ ] **Step 6: Commit** `feat(engine): checkout workspace and bridge to SAST_Framework agent`

---

### Task 7: Replace legacy sample `backend/app.py`

**Files:**
- Delete or move: `backend/app.py` (old in-memory sample)
- Ensure uvicorn entry is `uvicorn app.main:app --app-dir backend` or run from `backend/` as `uvicorn app.main:app`

- [ ] **Step 1: Remove old `backend/app.py`** to avoid confusion (logic superseded).

- [ ] **Step 2: Document start command** in README:

```bash
cd backend
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

- [ ] **Step 3: Commit** `chore: remove legacy in-memory sample API`

---

### Task 8: Next.js + Tailwind scaffold + editorial shell

**Files:**
- Create: entire `frontend/` app via `create-next-app`

- [ ] **Step 1: Scaffold**

```bash
cd D:/Secure-Build
npx create-next-app@latest frontend --typescript --tailwind --eslint --app --src-dir=false --import-alias="@/*" --use-npm
```

- [ ] **Step 2: `app/globals.css`** — soft blue-gray atmosphere, CSS variables:

```css
:root {
  --canvas: #f8fafc;
  --canvas-2: #edf3f9;
  --ink: #152238;
  --muted: #64748b;
  --accent: #2563eb;
  --sidebar: #152238;
}
body {
  background: linear-gradient(180deg, var(--canvas) 0%, var(--canvas-2) 100%);
  color: var(--ink);
  min-height: 100vh;
}
.font-display { font-family: Georgia, "Times New Roman", serif; }
```

- [ ] **Step 3: `components/Sidebar.tsx`** — brand **Secure Build**, links: Projects, New Project, New Scan, History.

- [ ] **Step 4: `app/layout.tsx`** — sidebar + main; metadata title Secure Build.

- [ ] **Step 5: Commit** `feat(ui): Next.js editorial sidebar shell`

---

### Task 9: BFF proxy routes + typed client

**Files:**
- Create: `frontend/lib/types.ts`, `frontend/lib/server-sast.ts`, `frontend/lib/api.ts`
- Create: `frontend/app/api/projects/route.ts`, `frontend/app/api/projects/[id]/route.ts`, `frontend/app/api/scans/route.ts`, `frontend/app/api/scans/[id]/status/route.ts`, `frontend/app/api/scans/[id]/results/route.ts`
- Create: `frontend/.env.local.example` with `SAST_API_URL` and `SAST_API_TOKEN` (server-only, no `NEXT_PUBLIC_` for token)

- [ ] **Step 1: `server-sast.ts`**

```typescript
const base = process.env.SAST_API_URL!;
const token = process.env.SAST_API_TOKEN!;

export async function sastFetch(path: string, init: RequestInit = {}) {
  const res = await fetch(`${base}${path}`, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${token}`,
      ...(init.headers || {}),
    },
    cache: "no-store",
  });
  return res;
}
```

- [ ] **Step 2: Proxy GET/POST projects and scans** — forward status codes and JSON bodies.

- [ ] **Step 3: Browser `api.ts`** calls `/api/projects` and `/api/scans` only.

- [ ] **Step 4: Smoke** — with backend up, `curl http://localhost:3000/api/projects` returns list.

- [ ] **Step 5: Commit** `feat(ui): BFF proxy to FastAPI with server-side token`

---

### Task 10: Projects UI (list + create wizard + detail)

**Files:**
- Create: `frontend/components/ProjectForm.tsx`, pages under `app/projects/`

- [ ] **Step 1: `ProjectForm`** fields matching schema: name, git URL, branch, languages (comma or tags), frameworks, build tool, monorepo path, toggles SAST/SCA/secrets, scan mode, gate thresholds, owasp_mode select (top10/top15/custom), editable textarea for OWASP URLs (prefilled when mode changes), NVD URLs textarea.

- [ ] **Step 2: `/projects/new`** submits POST `/api/projects` → redirect `/projects/[id]`.

- [ ] **Step 3: `/projects`** table/list of projects with link to detail and “New scan”.

- [ ] **Step 4: `/projects/[id]`** show config + PATCH form for URLs/gates + recent scans list.

- [ ] **Step 5: Manual UI check** · Commit `feat(ui): project create wizard and detail`

---

### Task 11: Scans UI (new, history, detail + polling + findings)

**Files:**
- Create: `ScanForm.tsx`, `ScanStatusBadge.tsx`, `FindingsList.tsx`, `FindingDetail.tsx`, scan pages

- [ ] **Step 1: `/scans/new`** — select project, branch, commit, force checkbox → POST `/api/scans` → `/scans/[id]`.

- [ ] **Step 2: `/scans`** — history with status badge, project name, vuln counts from status when available.

- [ ] **Step 3: `/scans/[id]`** — client component poll `/api/scans/[id]/status` every 2s while `queued|running`; then fetch results; split view: findings list (sorted critical→info) + detail panel (snippet + AI fix + OWASP/CWE links).

- [ ] **Step 4: Empty state** “No vulnerabilities found”; error banner on fetch failure; 404 message if scan missing.

- [ ] **Step 5: Manual E2E with mock engine** · Commit `feat(ui): scan flow with live status and finding review`

---

### Task 12: CI documentation (any pipeline)

**Files:**
- Create: `docs/ci/curl-example.md`, `docs/ci/jenkins-declarative.md`, `docs/ci/github-actions.md`
- Update: `README.md` links

- [ ] **Step 1: curl example** — create project once; POST scan; poll status; jq gate_summary; exit 1 if `gate_failed`.

- [ ] **Step 2: Jenkins Declarative** — `httpRequest` POST `/scans`, `waitUntil` poll `/status`, GET `/results`, fail build on `gate_failed`.

- [ ] **Step 3: GitHub Actions** — `curl` steps with secrets `SAST_API_TOKEN`, `SAST_API_URL`.

- [ ] **Step 4: Commit** `docs(ci): curl Jenkins and GitHub Actions scan gate examples`

---

### Task 13: End-to-end verification

- [ ] **Step 1: Start backend** with `USE_MOCK_ENGINE=true` — create project via UI — run scan — see findings.

- [ ] **Step 2: Optional live** — `USE_MOCK_ENGINE=false`, real repo path/git URL, AWS Bedrock configured — confirm incremental second scan logs fewer re-indexed files.

- [ ] **Step 3: Fix any blockers found** · final commit `test: verify P1+P2 happy paths`

---

## Self-review (plan vs spec)

| Spec requirement | Task |
|------------------|------|
| Create Project full tech + OWASP/NVD | 3, 10 |
| Top10/Top15 URL presets | 3 |
| REST any CI POST/poll/results | 4, 12 |
| Idempotency + force | 4 |
| gate_summary | 4 |
| Bedrock / real agent | 6 |
| AST symbol index + incremental | 5, 6 |
| Hybrid DB (app SQLite + symbol_index.db) | 2, 6 |
| Editorial sidebar UI | 8–11 |
| BFF no browser token | 9 |
| CI examples | 12 |
| Auth env token | 3, 9 |
| P3/P4 out of scope | not planned |

No TBD placeholders remain; status vs gate semantics follow the spec.

---

## Execution handoff

Plan complete and saved to `docs/superpowers/plans/2026-07-14-secure-build-p1-p2.md`.

**Two execution options:**

1. **Subagent-Driven (recommended)** — fresh subagent per task, review between tasks  
2. **Inline Execution** — execute tasks in this session with checkpoints  

Which approach?
