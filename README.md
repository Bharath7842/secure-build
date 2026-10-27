# Secure Build

Secure Build is an application-security platform with a **FastAPI** backend and a **Next.js** frontend. It runs two kinds of scans against your projects and gives you one place to review the results:

- **SAST** (static analysis). It clones a repository, maps its structure and tech stack, ranks files by risk, and uses an LLM to find vulnerabilities. Optional Joern dataflow analysis adds depth.
- **DAST** (dynamic analysis). It crawls a running web application with a browser and sends guarded test traffic. A model helps choose tests and explain evidence.
- **Reports and CI.** Findings are grouped, filterable by verdict, and exportable (PDF, XLSX, SARIF, JUnit). A small REST API plugs into Jenkins, GitHub Actions, GitLab CI or plain shell.

> Only scan code and applications you own or are explicitly authorized to test.

---

## Table of contents

1. [Features](#features)
2. [Architecture](#architecture)
3. [Accounts and access](#accounts-and-access)
4. [Repository layout](#repository-layout)
5. [Quick start (macOS / Windows)](#quick-start-macos--windows)
6. [Running on Linux](#running-on-linux)
7. [Configuration](#configuration)
8. [Using the app](#using-the-app)
9. [How a SAST scan works](#how-a-sast-scan-works)
10. [API overview](#api-overview)
11. [CI integration](#ci-integration)
12. [Testing](#testing)
13. [Troubleshooting](#troubleshooting)
14. [Further documentation](#further-documentation)

---

## Features

**SAST**

- Deterministic tech-stack detection (marker files, dependency manifests, tree-sitter) and risk ranking of every file (CRITICAL / HIGH / MEDIUM / LOW).
- LLM deep scan of the highest-risk files, guided by a regex rule catalog and per-stack "vulnerability surfaces". Remaining files get a fast regex triage tier, and every hit is then confirmed or dismissed by the LLM.
- Verdicts: `true_positive`, `false_positive`, and `unverified` (a pattern matched and nobody has reviewed it yet).
- Optional [Joern](https://joern.io) taint analysis (`reachableByFlows` from request inputs to dangerous sinks).
- Token-efficiency features: prompt caching on Bedrock, JSON-envelope outputs, batched confirmations, and a cross-scan LLM result cache. A per-scan spend cutoff (default $2) caps cost.
- Pluggable LLM providers: AWS Bedrock, the local Claude CLI (one Claude session per scan), any OpenAI-compatible endpoint (vLLM, LM Studio, llama.cpp, OpenAI), and Ollama. A per-project `local_only` data policy blocks any non-local provider.

**DAST**

- Playwright (Chromium) crawling, login handling, API/OpenAPI/GraphQL discovery and passive analysis.
- Guarded active testing: scope lock, safe mode (non-destructive methods only), rate limits and request budgets.
- Multi-identity authorization testing with a role-by-role access matrix.
- Per-task model routing (Ollama, Bedrock, OpenAI, Anthropic), custom rules, scan intensity presets (light, standard, deep) and optional schedules.
- See [DAST_IMPLEMENTATION.md](DAST_IMPLEMENTATION.md) for the technical overview.
- **The DAST pages in the frontend (`/dast`) are currently a UI mockup.** The DAST engine and APIs live in `backend/app/dast/`.

**Platform**

- Per-project settings, scan limitations (togglable checks and engine caps) and scan versioning with version-to-version diffs.
- "Scan again" reuse: if the branch head has not changed since the last successful scan, that scan is returned instead of starting a new one.
- Live engine log, exports (PDF, XLSX, SARIF, JUnit), GitHub/GitLab OAuth for private repositories.

---

## Architecture

```
 Browser ──► Next.js frontend (:3000)
               │  app/api/**/route.ts  (server-side proxy, forwards the user's session)
               ▼
            FastAPI backend (:8000)  ◄── CI systems (Bearer token)
               │
   ┌───────────┼─────────────────────────┐
   ▼           ▼                         ▼
 SQLite/     SAST engine               DAST engine
 Postgres    backend/sast_engine/      backend/app/dast/
 (data/)     LangGraph pipeline        LangGraph + Playwright
               │                         │
               └──── LLM providers: Bedrock · Claude CLI · OpenAI-compatible · Ollama
```

- People sign in with their own accounts. The session lives in an HttpOnly cookie; the frontend's server-side routes forward it to the backend as `Authorization: Session <token>`. The browser never talks to the backend directly.
- The backend checks a permission on every endpoint except `/health`, `/setup` and sign-in. Admins have full access; regular users see only the pages and actions an admin allows, and by default only their own scans. See [Accounts and access](#accounts-and-access).
- `SAST_API_TOKEN` is now the **CI** credential only (`Authorization: Bearer <SAST_API_TOKEN>`): it can create projects, start scans and read results, nothing admin.
- The SAST engine is a LangGraph agent that is loaded **by path** (`SAST_FRAMEWORK_PATH`, default `backend/sast_engine`). With `USE_MOCK_ENGINE=true` it is never imported, so the mock/test setup needs no `boto3`, `langgraph` or tree-sitter.

---

## Accounts and access

- **First admin.** Set `SETUP_TOKEN` (32+ characters) in the root `.env`, restart the backend and open `/setup`. It works only while there are no accounts and closes for good after the first one. There are no default passwords.
- **Adding people.** Admins create users under **Admin → Users** and get a one-time invite link (72 h) to send them directly; the person sets their own password. Nothing is emailed. Password resets work the same way: a 24 h link from the user's page.
- **Roles.** *Admin*: everything, including users, settings and the audit log. *User*: by default Projects, SAST/SCA/SBOM scans, History and exports, and only **their own** scans. Admins can allow or deny individual pages and actions per user (deny wins); changes apply on the user's next click.
- **Sessions.** 8 h idle and 12 h maximum, or 14 days with "Keep me signed in". Disabling a user, a password reset or removing admin signs them out everywhere.
- **Audit log.** Sign-ins (including failures), account and permission changes, and scan starts, stops and deletions, under **Admin → Audit log**. Passwords, tokens and links are never recorded.
- **Existing scans** from before accounts existed, and CI scans, have no owner: admins (and users allowed *View all scans*) see them.
- **CI** keeps using `SAST_API_TOKEN` as before (see `docs/ci/`).

| Setting (root `.env`) | Default | Purpose |
|---|---|---|
| `SETUP_TOKEN` | unset | Needed once, to create the first admin on `/setup` |
| `SESSION_IDLE_MINUTES` / `SESSION_ABSOLUTE_HOURS` / `SESSION_REMEMBER_DAYS` | 480 / 12 / 14 | Session lifetimes |
| `INVITE_TTL_HOURS` / `RESET_TTL_HOURS` | 72 / 24 | One-time link lifetimes |
| `PUBLIC_APP_URL` | `http://localhost:3000` | Base of invite and reset links |
| `FRONTEND_PROXY_SECRET` | unset | Same value in `frontend/.env.local`; lets sign-in rate limits see each browser's address |
| `AUDIT_RETENTION_DAYS` | 365 | Older audit events are deleted at startup |

Frontend (`frontend/.env.local`): `SAST_API_URL`, and optionally `FRONTEND_PROXY_SECRET`, `APP_ORIGIN` (public origin behind a reverse proxy) and `SESSION_COOKIE_SECURE=false` (only to run a production build over plain http).

---

## Repository layout

```
secure-build/
├── backend/
│   ├── app/                 FastAPI app: routers/, services/, dast/, models.py, schemas.py, db.py, config.py
│   ├── sast_engine/         SAST LangGraph agent, pipeline/, rule catalog (rules/), Joern scripts (joern/)
│   ├── tests/               pytest suite (mock engine by default)
│   └── requirements.txt
├── frontend/                Next.js App Router UI (app/, components/, lib/)
├── docs/                    CI guides (docs/ci/), "how scanning works", design plans
├── spec/                    DAST design/spec documents
├── dev/practice-targets/    Docker setup for local practice targets (Juice Shop, DVWA)
├── data/                    Runtime data (SQLite DB, workspaces, scan logs, screenshots) - git-ignored
├── CLAUDE.md                Contributor/agent guide to the architecture
└── DAST_IMPLEMENTATION.md   DAST technical overview
```

---

## Quick start (macOS / Windows)

For the fastest local trial, use the **mock engine**. It makes no network, git or LLM calls.

**Prerequisites:** Python 3.12, Node.js 20.9+ and npm. Git is also needed for live scans.

### 1. Backend

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate            # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

Create `.env` in the **repository root** (see [Configuration](#configuration) for all options):

```bash
cat > ../.env <<EOF
SAST_API_TOKEN=change-me-to-a-long-random-string
SETUP_TOKEN=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")
USE_MOCK_ENGINE=true
EOF
```

Start it:

```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

Check it: `curl http://localhost:8000/health` returns `{"status":"ok"}`.

### 2. Frontend

```bash
cd frontend
npm install
cat > .env.local <<'EOF'
SAST_API_URL=http://localhost:8000
EOF
npm run dev
```

Open http://localhost:3000/setup and create the first admin with the `SETUP_TOKEN` from the root `.env` (setup closes once an account exists). Then add people from **Admin → Users**.

### 3. Go live (real scans)

Turn the mock off and configure an LLM provider (see [Configuration](#configuration)):

```bash
# in the root .env
USE_MOCK_ENGINE=false
RUN_LIVE_SAST=1
AWS_REGION=us-east-1
BEDROCK_MODEL_ID=us.anthropic.claude-haiku-4-5-20251001-v1:0
```

Restart the backend. Real scans clone the repository into `data/workspaces/<project_id>/`.

---

## Running on Linux

These steps target Ubuntu/Debian 22.04+. Package names differ slightly on Fedora/RHEL (`dnf`), and the rest is identical.

### 1. System packages

```bash
sudo apt update
sudo apt install -y git curl jq build-essential ca-certificates \
                    python3.12 python3.12-venv python3-pip
```

If your release has no `python3.12`, install it from the deadsnakes PPA or use [pyenv](https://github.com/pyenv/pyenv) (`pyenv install 3.12`).

Node.js 20.9+ is required by Next.js 16 (Ubuntu's packaged `nodejs` is usually too old). Use NodeSource or nvm:

```bash
curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash -
sudo apt install -y nodejs
node --version    # must be >= 20.9
```

### 2. Get the code

```bash
git clone https://github.com/Bharath7842/secure-build.git
cd secure-build
```

### 3. Backend

```bash
cd backend
python3.12 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

Create the root `.env`. `SAST_API_TOKEN` is for CI; `SETUP_TOKEN` creates the first admin:

```bash
cd ..
cat > .env <<EOF
SAST_API_TOKEN=$(openssl rand -hex 32)
SETUP_TOKEN=$(openssl rand -hex 32)
USE_MOCK_ENGINE=true
EOF
grep SETUP_TOKEN .env      # you'll paste this on /setup
```

Run the API:

```bash
cd backend && source .venv/bin/activate
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Use `--host 0.0.0.0` only if other machines must reach the API directly. Otherwise keep it on loopback, since the frontend runs on the same host. Add `--reload` for development.

### 4. Frontend

```bash
cd frontend
npm install
cat > .env.local <<EOF
SAST_API_URL=http://127.0.0.1:8000
EOF
npm run dev                 # development, http://localhost:3000
```

For a production-style run:

```bash
npm run build
npm run start               # serves on :3000 (use `npm run start -- -p 8080` to change the port)
```

### 5. Enable live SAST scans

Pick **one** LLM backend:

**AWS Bedrock.** Provide credentials through the standard AWS chain (`aws configure`, an instance role, or the `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY` environment variables). The identity needs `bedrock:InvokeModel` for the model in `BEDROCK_MODEL_ID`.

**Ollama (fully local).**

```bash
curl -fsSL https://ollama.com/install.sh | sh
ollama pull granite-code:3b          # or any model you prefer
# .env
OLLAMA_BASE_URL=http://localhost:11434
```

Then select `ollama` as the project's LLM provider in the UI.

**OpenAI-compatible server (vLLM, LM Studio, llama.cpp, OpenAI).** Set `OPENAI_COMPAT_BASE_URL` (including `/v1`) and, if needed, `OPENAI_COMPAT_API_KEY`, or set the base URL and key per project in the UI. Set the project's data policy to `local_only` to guarantee code never leaves your network.

Then in `.env`:

```bash
USE_MOCK_ENGINE=false
RUN_LIVE_SAST=1
```

Restart the backend. Git must be installed, since the backend clones target repos into `data/workspaces/`.

### 6. Optional components

| Component | Needed for | Linux install |
|---|---|---|
| **Playwright Chromium** | DAST crawling | `source backend/.venv/bin/activate && python -m playwright install --with-deps chromium` |
| **ripgrep** | Regex catalog prefilter (speed only) | Already installed in the venv by the pinned `ripgrep` wheel. To use another build, set `RG_PATH=/usr/bin/rg`. |
| **Joern + JDK 17+** | Dataflow (taint) analysis | `sudo apt install -y openjdk-17-jdk`, then install Joern from https://joern.io (or `curl -L "https://github.com/joernio/joern/releases/latest/download/joern-install.sh" -o joern-install.sh && chmod +x joern-install.sh && ./joern-install.sh`). Put it on `PATH` or set `JOERN_HOME=/path/to/joern-cli`. Without Joern the Joern stages are logged no-ops. |
| **Docker** | Practice targets in `dev/practice-targets/` | `sudo apt install -y docker.io docker-compose-v2` |

### 7. Run as services (systemd, optional)

Replace `deploy`, the path and the user with your own.

`/etc/systemd/system/secure-build-api.service`

```ini
[Unit]
Description=Secure Build API
After=network.target

[Service]
User=deploy
WorkingDirectory=/opt/secure-build/backend
ExecStart=/opt/secure-build/backend/.venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8000
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

`/etc/systemd/system/secure-build-web.service`

```ini
[Unit]
Description=Secure Build Frontend
After=network.target secure-build-api.service

[Service]
User=deploy
WorkingDirectory=/opt/secure-build/frontend
ExecStart=/usr/bin/npm run start
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now secure-build-api secure-build-web
journalctl -u secure-build-api -f
```

Put a reverse proxy (nginx or Caddy) with TLS in front of port 3000 if the app is reachable beyond localhost. Keep the API port off the public internet: only the frontend and CI need it. Session cookies are Secure (HTTPS-only) in production builds.

### 8. Linux notes

- The catalog prefilter's ripgrep runs under a `ulimit -v` memory wrapper. That wrapper is **enforced on Linux**; macOS ignores it.
- Joern CPG builds on large Java repos want 4-8 GB of heap (`JOERN_JAVA_OPTS=-Xmx6g`).
- If a Playwright launch fails with missing shared libraries, re-run `python -m playwright install --with-deps chromium`.
- Port 3000 is the frontend's default. If you run the Juice Shop practice target, it is bound to 3001 for that reason.

---

## Configuration

The backend reads the **root** `.env` file (`secure-build/.env`) via `app/config.py`. Real environment variables override it. The frontend reads `frontend/.env.local`. Both files are git-ignored.

### Core

| Variable | Default | Purpose |
|---|---|---|
| `SAST_API_TOKEN` | `changeme-token` | CI bearer token (create projects, start scans, read results). **Change it.** The frontend no longer uses it. |
| `SETUP_TOKEN` | unset | Creates the first admin on `/setup`; see [Accounts and access](#accounts-and-access) for the other account settings. |
| `SAST_API_URL` | - | Used by the frontend (`frontend/.env.local`) to reach the backend, e.g. `http://localhost:8000`. |
| `DATABASE_URL` | SQLite at `data/secure_build.db` | Any SQLAlchemy URL, e.g. `postgresql+psycopg://user:pass@host/db`. |
| `USE_MOCK_ENGINE` | `false` (tests: true) | `true` returns deterministic fake results with no I/O. |
| `RUN_LIVE_SAST` | on | Second opt-in required on top of `USE_MOCK_ENGINE=false` before the real engine runs. |
| `SAST_FRAMEWORK_PATH` | `backend/sast_engine` | Location of the engine (rarely changed). |
| `WORKSPACES_DIR`, `SCAN_LOGS_DIR` | `data/...` | Where clones and durable engine logs go. |

### LLM providers

| Variable | Purpose |
|---|---|
| `AWS_REGION`, `BEDROCK_MODEL_ID` | AWS Bedrock (default model: Claude Haiku 4.5). Uses the standard AWS credential chain. |
| `BEDROCK_PROMPT_CACHE` | Set `0` to disable Bedrock prompt caching. |
| `CLAUDE_CLI_PATH`, `CLAUDE_CLI_REQUEST_TIMEOUT` | Local `claude` CLI provider (`claude_cli`); path defaults to `claude` on `PATH`. Each scan runs as one Claude session under `claude_cli_dir`. |
| `OLLAMA_BASE_URL`, `OLLAMA_REQUEST_TIMEOUT` | Local Ollama server (default `http://localhost:11434`). |
| `OPENAI_COMPAT_BASE_URL`, `OPENAI_COMPAT_API_KEY` | Default OpenAI-compatible endpoint (per-project overrides available). |
| `ANTHROPIC_API_KEY`, `OPENAI_API_KEY` | Hosted providers for DAST model routing. Read from the environment only. |

### SAST tuning

| Variable | Purpose |
|---|---|
| `JOERN_HOME`, `JOERN_JAVA_HOME`, `JOERN_JAVA_OPTS`, `JOERN_TIMEOUT_SEC` | Joern install location, JDK, heap size and timeout. |
| `RG_PATH` | Use a specific `rg` binary for the regex catalog prefilter. |
| `SAST_REFRESH_CACHE` | `1` clears the cached tech-stack fingerprint before each scan. |
| `NVD_API_KEY` | Optional NVD key for vulnerability lookups. |

### Git access for private repositories

`GITLAB_OAUTH_CLIENT_ID/SECRET/REDIRECT_URI` (plus `GITLAB_BASE_URL` for self-hosted GitLab) enable the "Connect GitLab" button. An empty client ID disables it.

### DAST

| Variable | Purpose |
|---|---|
| `RUN_DAST` | Set `0` to disable DAST. |
| `DAST_OLLAMA_MODEL`, `DAST_OLLAMA_BASE_URL`, `DAST_OLLAMA_NUM_CTX` | Default DAST model (default `gpt-oss:20b`) and context size. |
| `DAST_MODEL_<TASK>_PROVIDER` / `_MODEL` | Route `fingerprint`, `crawl_plan`, `login_selectors`, `construct`, `rule` and `narrate` independently to `ollama`, `bedrock`, `openai` or `anthropic`. |
| `DAST_MAX_PAGES`, `DAST_MAX_DEPTH`, `DAST_MAX_RUNTIME_MINUTES`, `DAST_MAX_TARGETS` | Crawl and test budgets. |
| `DAST_SAFE_MODE_DEFAULT`, `DAST_RATE_LIMIT_PER_SEC` | Safety limits (safe mode on, 5 requests per second by default). |
| `DAST_OAST_CALLBACK_URL` | Out-of-band callback host for SSRF-style checks. |
| `DAST_WEBHOOK_URL`, `DAST_SLACK_WEBHOOK_URL`, `DAST_JIRA_WEBHOOK_URL` | Notifications when a scan finishes. |
| `DAST_SCHEDULER_ENABLED` | Start due scheduled scans (off by default). |

Every setting is defined, with its default, in [backend/app/config.py](backend/app/config.py).

---

## Using the app

1. **Create a project** at `/projects/new`. Set the Git URL and branch, then pick the languages, LLM provider and model. For a private repo, use "Connect GitHub/GitLab" or provide a token.
2. **Adjust scan limitations** (optional) in the project's Settings page. These are togglable checks and engine caps, such as suppressing findings with no CWE or suppressing cleartext-HTTP findings.
3. **Start a scan** from `/scans/new`. With no commit specified, the latest commit on the branch is used, and a prior successful scan of the same commit is reused unless you tick **Force scan**.
4. **Watch it run.** The scan goes `queued → running → success/failed`, with a live Engine log (tech-stack detection, risk mapping, deep scan, triage and confirmation steps).
5. **Review results.** The Discovery panel shows tech stack and risk mapping. The Findings panel filters by severity and verdict, and identical findings are grouped into one row listing every affected file.
6. **Compare versions.** Every scan has a per-project version number. Diff any two versions into new, fixed and pending findings.
7. **Export** the report as PDF, XLSX, SARIF or JUnit.

### Running the SAST engine standalone (CLI)

```bash
cd backend/sast_engine
python sast_scan_agent.py --path /path/to/project                 # full scan
python sast_scan_agent.py --path /path/to/project --no-llm        # discovery + regex only
python sast_scan_agent.py --path /path/to/project --llm-provider ollama --llm-model granite-code:3b
python sast_scan_agent.py --path /path/to/project --no-joern
```

### Practice targets for DAST

`dev/practice-targets/` starts deliberately vulnerable apps (OWASP Juice Shop, DVWA) bound to `127.0.0.1` for authorized local testing. See [its README](dev/practice-targets/README.md).

---

## How a SAST scan works

```
scan_directory → analyze_tech_stack → categorize_files → map_modules_and_risk
  → scan_deep_files → scan_triage_files → group_triage_findings
  → confirm_triage_groups → generate_report
```

(Joern nodes run in between when enabled.)

| Stage | What happens |
|---|---|
| Tech stack | Deterministic: marker files, dependency manifests, tree-sitter. No LLM. |
| Risk mapping | Every file is classified CRITICAL / HIGH / MEDIUM / LOW, by directory and filename conventions per stack. |
| Deep scan | The top 100 CRITICAL/HIGH files (spare slots are backfilled with MEDIUM files) go to the LLM in full, with the rule catalog as guidance. Findings are written incrementally. |
| Triage | All remaining files get a local regex pass. Hits become `unverified` findings, grouped by construct. |
| Confirmation | The LLM confirms or dismisses every group, so a finished scan should not leave findings `unverified`. |
| Report | True-positive, false-positive and unverified totals plus OWASP category counts. |

Generated code and vendored or minified assets are skipped by content, not by path. A spend cutoff (default $2) bounds LLM cost.

For depth, see [docs/how-scan-works.md](docs/how-scan-works.md), [backend/sast_engine/README.md](backend/sast_engine/README.md) and [CLAUDE.md](CLAUDE.md).

---

## API overview

Every route except `GET /health`, `/setup` and `POST /auth/login` needs either a user session (`Authorization: Session <token>`, what the web app sends) or the CI token (`Authorization: Bearer <SAST_API_TOKEN>`), and each route checks a permission. New: `/auth/*` (sign-in, account), `/admin/users*` and `/admin/audit` (admins). FastAPI's Swagger UI is served at `/docs` (the page itself is not token-protected, but its API calls are).

| Area | Endpoints |
|---|---|
| Health | `GET /health` |
| Projects | `POST/GET /projects`, `GET/PATCH/DELETE /projects/{id}`, `PATCH /projects/{id}/limitations` |
| Scans | `POST/GET /scans`, `GET /scans/{id}/status`, `/results`, `/findings`, `/logs`, `/summary`, `/diff`, `/report` |
| Scan control | `POST /scans/{id}/cancel`, `/pause`, `/resume`, `/replay`, `DELETE /scans/{id}`, `GET /scans/queue` |
| Exports | `GET /scans/{id}/export.pdf`, `export.xlsx`, `export.sarif`, `export.junit` |
| Findings | `PATCH /scans/{id}/findings/{finding_id}` |
| Config | `GET /scan-limitations`, `GET /llm-presets` |
| Git auth | `GET /git-auth/{provider}/authorize`, `POST .../callback`, `GET .../repos`, `DELETE /git-auth/{project_id}/disconnect` |
| DAST | `/dast/settings`, `/dast/model-routing`, `/dast/custom-rules`, `/dast/profiles`, `/dast/schedules`, `/dast/catalog`, `/dast/compliance`, `GET /scans/{id}/authz-matrix`, `/requests`, `/narration` |

Quick example:

```bash
export SAST_API_URL=http://localhost:8000
export SAST_API_TOKEN=...

curl -sS -X POST "$SAST_API_URL/projects" \
  -H "Authorization: Bearer $SAST_API_TOKEN" -H "Content-Type: application/json" \
  -d '{"name":"my-app","default_git_url":"https://github.com/acme/my-app.git","default_branch":"main","languages":["java"]}'

curl -sS -X POST "$SAST_API_URL/scans" \
  -H "Authorization: Bearer $SAST_API_TOKEN" -H "Content-Type: application/json" \
  -d '{"project_id":"<id from above>","branch":"main"}'
```

---

## CI integration

The API works with any CI system. The pattern is always the same: **POST** a scan, **poll** `/scans/{id}/status`, then **GET** `/scans/{id}/results` and decide whether to fail the build.

| Guide | Description |
|---|---|
| [curl example](docs/ci/curl-example.md) | Generic bash script (any pipeline; needs `jq`) |
| [Jenkins Declarative](docs/ci/jenkins-declarative.md) | Jenkinsfile using the `httpRequest` plugin |
| [GitHub Actions](docs/ci/github-actions.md) | Workflow YAML with `curl` and `jq` |
| [Pipeline notes](docs/ci/pipeline.md) | Additional pipeline guidance |

`POST /scans` is idempotent for the same project and commit. Pass `"force": true` to rescan. The pass/fail gate thresholds were removed, so `gate_summary.gate_failed` is always `false`. Apply your own policy to the severity and verdict counts in the response.

---

## Testing

```bash
cd backend
source .venv/bin/activate
pytest                                    # whole suite (mock engine; no git, network or AWS)
pytest tests/test_scans_api.py            # one file
pytest tests/test_scans_api.py -k name    # one test
pytest -m live tests/test_joern.py        # opt-in: runs a real local Joern
```

```bash
cd frontend
npm run lint
npm run build
```

There is no frontend test runner. Use lint and the Next.js build.

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| Every page sends you to sign-in | No account yet: open `/setup` (needs `SETUP_TOKEN` in the root `.env`). Otherwise the session expired or the account was disabled. |
| A page says "You don't have access" | Your account doesn't include that page; an admin can allow it under **Admin → Users**. |
| Frontend cannot reach the API | Check `SAST_API_URL`, and confirm `curl $SAST_API_URL/health` works from the machine running Next.js. |
| `address already in use` on 8000 or 3000 | Find the process with `ss -ltnp \| grep -E ':(8000\|3000)'` (Linux) or `lsof -iTCP -sTCP:LISTEN -nP` (macOS), then stop it. |
| Scans return mock-looking results | `USE_MOCK_ENGINE` is still `true`. Set it to `false`, set `RUN_LIVE_SAST=1`, and restart the backend. |
| `ModuleNotFoundError: boto3` / `langgraph` during a live scan | Install the full requirements in the backend venv: `pip install -r requirements.txt`. |
| Bedrock `AccessDenied` / `ResourceNotFound` | Check the AWS credentials and region, and that the model is enabled in Bedrock for your account. |
| Scan stops with LLM budget exhausted | The $2 cutoff was reached. Remaining work is recorded as `unverified`. |
| Private repo clone fails | Connect GitHub/GitLab for the project or supply an access token. |
| Joern stages do nothing | Joern is not on `PATH`. Install it or set `JOERN_HOME`. This is non-fatal by design. |
| DAST crawl fails to start a browser | Run `python -m playwright install --with-deps chromium` in the backend venv. |
| `npm run dev` fails on Node version | Next.js 16 needs Node 20.9+. |
| Wrong DB / want a fresh start | Stop the backend and delete `data/secure_build.db`. It is recreated at startup. Schema changes are applied by idempotent migrations in `app/db.py` at startup. |

---

## Further documentation

- [CLAUDE.md](CLAUDE.md): architecture deep-dive for contributors.
- [backend/sast_engine/README.md](backend/sast_engine/README.md): engine pipeline, Joern, CLI and LLM backends.
- [backend/sast_engine/rules/README.md](backend/sast_engine/rules/README.md): rule catalog field reference.
- [docs/how-scan-works.md](docs/how-scan-works.md): scan lifecycle.
- [DAST_IMPLEMENTATION.md](DAST_IMPLEMENTATION.md) and [spec/](spec/): DAST overview and design.
- [docs/ci/](docs/ci/): CI integration guides.
