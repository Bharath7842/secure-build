# Secure Build — P1 Pipeline API + P2 Editorial UI Design

**Date:** 2026-07-14  
**Status:** Approved for implementation planning  
**Stack:** Next.js (App Router) + React + Tailwind · FastAPI · AWS Bedrock · hybrid DB · existing SAST agent

## Goal

Ship a **pipeline-friendly REST API** (works with any CI) and an **editorial sidebar UI** that:

1. Lets teams **create a project** with full tech + OWASP/NVD scan-source config  
2. Runs **AI-assisted SAST** via the existing LangGraph agent (`sast_scan_agent.py`) on **AWS Bedrock**  
3. Indexes code with **AST / symbol DB** (not sending whole files to the LLM)  
4. **Persists** projects, findings, and file hashes; **incremental** scans only re-analyze changed files  

## Locked decisions

| Topic | Choice |
|--------|--------|
| Scope | **P1 + P2** (API + UI). P3 monitoring dashboard & P4 analytics deferred |
| Project config | **All** tech details + per-project OWASP/NVD URLs (Top 10 or Top 15, editable) |
| Scan engine | Wire **real** agent at `D:\dev\SAST_Framework\sast_scan_agent.py` + `symbol_indexer.py` |
| LLM | **AWS Bedrock** (Claude Haiku inference profile; `BEDROCK_MODEL_ID` env) |
| Database | **Hybrid** — app DB (Postgres *or* SQLite for projects/scans/findings/hashes) + per-repo `symbol_index.db` |
| Auth (v1) | Env Bearer token; no login UI. Next.js BFF proxies so browser never holds the token |
| Visual | Editorial Review — serif headlines, soft blue-gray, navy sidebar |
| Shell | Sidebar navigation |

## Architecture

```
CI (Jenkins / GHA / GitLab / any) ──┐
                                   ├──► FastAPI REST + Bearer
Editorial UI ──► Next.js BFF /api/* ─┘
                         │
                         ▼
              App DB (Postgres or SQLite)
              projects · scans · findings · file_snapshots
                         │
                         ▼
              Engine adapter
                → sast_scan_agent.py (LangGraph + Bedrock)
                → symbol_indexer.py (tree-sitter AST)
                → data/workspaces/{project_id}/ + symbol_index.db
```

### Bedrock usage (only)

- Stack fingerprint  
- Summarize OWASP pages into checks  
- Derive executable scan patterns from OWASP/NVD text  
- Enrich findings (exploit / impact / fix) using **matched snippets only**  

Raw repo contents are **not** bulk-uploaded to the model. Local scan runs regex + SQLite AST rules against the symbol index.

### Agent integration

- Adapter in Secure-Build backend invokes the existing agent as a library or subprocess with project config (tech context, OWASP URL list, NVD URL list, workspace path, incremental file list).  
- Prefer importing/packaging from `SAST_Framework` via configurable `SAST_FRAMEWORK_PATH` env for v1 (path can point at `D:\dev\SAST_Framework`).  
- Outbound network required for git clone, OWASP, NVD, OSV (as in agent today).

## Create Project (required before scanning)

Project stores everything the agent needs so pipelines only pass `project_id` + git commit/branch (+ optional build metadata).

| Group | Fields |
|--------|--------|
| Identity | `name`, description |
| Languages & frameworks | e.g. Java 17, Spring Boot, TypeScript, Next.js |
| Repo & build | `default_git_url`, `default_branch`, `build_tool`, `monorepo_path` |
| Scan profile | SAST / SCA / secrets toggles; `scan_mode`: `full` \| `incremental`; gate thresholds (e.g. fail if critical > N) |
| OWASP sources | `owasp_mode`: `top10` \| `top15` \| `custom`; `owasp_urls[]` (prefilled from mode, editable) |
| NVD sources | `nvd_urls[]` / query keywords (project override) |

UI: `/projects/new` wizard. API: `POST /projects`.

## REST API (any pipeline)

Easy CI pattern (same for Jenkins `httpRequest`, GitHub Actions `curl`, etc.):

1. `POST /scans` with Bearer token → `202` + `scan_id`  
2. Poll `GET /scans/{id}/status` every 15–30s  
3. `GET /scans/{id}/results` → gate on severity counts / policy  

### Endpoints

| Method | Path | Purpose |
|--------|------|---------|
| POST | `/projects` | Create project with full config |
| GET | `/projects` | List |
| GET | `/projects/{id}` | Detail |
| PATCH | `/projects/{id}` | Update tech / URLs / gates |
| POST | `/scans` | Start scan: `{ project_id, branch?, commit_sha?, metadata?, git_url? }` |
| GET | `/scans` | List (filter by project) |
| GET | `/scans/{id}/status` | `queued` \| `running` \| `success` \| `failed` + progress |
| GET | `/scans/{id}/results` | Findings + **gate_summary** |

### Idempotency

If a scan for the same `project_id` + `commit_sha` already exists in any status (`queued` / `running` / `success` / `failed`), return that `scan_id` and do not start a duplicate. To force a re-scan, client sends `force: true` on `POST /scans`.

### Results shape (gate-friendly)

```json
{
  "scan_id": "...",
  "project_id": "...",
  "status": "failed",
  "gate_summary": {
    "vulnerabilities_found": 3,
    "by_severity": { "critical": 1, "high": 1, "medium": 1, "low": 0, "info": 0 },
    "gate_failed": true,
    "gate_reason": "critical count 1 exceeds project threshold 0"
  },
  "findings": [
    {
      "id": "f-1",
      "severity": "critical",
      "cvss": 9.8,
      "cwe": "CWE-89",
      "owasp_ref": "https://owasp.org/Top10/...",
      "rule_id": "SQLI-001",
      "title": "...",
      "file_path": "src/...",
      "line": 42,
      "snippet": "...",
      "ai_fix": "..."
    }
  ]
}
```

### CI examples (docs)

- Generic `curl` + poll loop  
- Jenkins Declarative `httpRequest` + `waitUntil`  
- GitHub Actions composite snippet  

No Jenkins plugin required in v1.

## UI (Editorial + Sidebar)

| Route | Job |
|--------|-----|
| `/projects/new` | Create Project wizard |
| `/projects` | Project list |
| `/projects/[id]` | View/edit config + recent scans |
| `/scans/new` | Start scan (select project, branch, commit) |
| `/scans` | History |
| `/scans/[id]` | Live status → findings list + snippet + AI fix |

Visual: soft blue-gray canvas, Georgia (or similar) display type, navy `#152238` sidebar, accent `#2563eb`. Severity colors only for findings.

## Data model

### App DB

- **projects** — full config JSON/columns as above  
- **scans** — project_id, git_url, branch, commit_sha, status, progress, metadata, timestamps  
- **findings** — scan_id, severity, cvss, cwe, owasp_ref, rule_id, title, file_path, line, snippet, ai_fix  
- **file_snapshots** — project_id, path, content_hash, commit_sha (incremental)

Default app DB for v1: **SQLite file** under `data/secure_build.db` with optional switch to Postgres via `DATABASE_URL`.

### On disk

- `data/workspaces/{project_id}/` — checkout  
- `symbol_index.db` — AST symbol tables for SQL/OWASP rules  

## Scan lifecycle

1. Create project (tech + OWASP/NVD URLs)  
2. `POST /scans` → queued (idempotent)  
3. Clone/fetch commit → compare `file_snapshots` hashes  
4. Re-index **changed files only** into `symbol_index.db` (full index on first scan)  
5. Fetch project OWASP/NVD URLs → Bedrock summarize/derive patterns  
6. Local scan (patterns + AST SQLite rules) → Bedrock enrich snippets  
7. Persist findings + update hashes → `success` if gate passes / zero criticals policy, else `failed` when findings breach project gates (or keep status = scan completion and expose `gate_failed` separately — **use both**: scan `status` = engine completion (`success`/`failed` on engine error); `gate_summary.gate_failed` for CI policy)  
8. UI/CI poll → results  

**Clarified status semantics:**  
- `success` / `failed` on the scan record = engine finished vs engine error.  
- CI build gate uses `gate_summary.gate_failed` (and severity counts), not merely “findings > 0”.

## Error & empty states

| Case | Behavior |
|------|----------|
| API / Bedrock / network down | Banner + retry; scan → `failed` with message |
| 401 | Check `SAST_API_TOKEN` |
| Unknown project/scan | 404 |
| Results while running | 409 — keep polling |
| Zero findings | Empty success state in UI; `gate_failed: false` |
| Form validation | Project name + default git URL required; scan needs project_id |

## Testing (v1)

- Manual: create project → run scan against a small sample repo → review findings in UI  
- Manual CI: curl POST + poll + results gate fields  
- Optional later: Playwright smoke  

## Out of scope (this build)

- P3 live heatmap / monitoring dashboard  
- P4 trends, MTTR, compliance report packs  
- Official Jenkins plugin package  
- Completion webhooks (document as future)  
- Multi-tenant SaaS auth  
- Expanding tree-sitter beyond what `SAST_Framework` already supports (extend languages as follow-ups)

## Success criteria

- Create Project captures tech + OWASP Top 10/15 (or custom) + NVD URLs  
- Any CI can drive scans with POST → poll → results without a plugin  
- Scans use Bedrock + AST index; incremental second scan skips unchanged files  
- UI supports project wizard, history, and finding review (snippet + AI fix)  
- Findings and hashes persist across process restarts (app DB)

## Env vars (minimum)

```
SAST_API_TOKEN=
SAST_FRAMEWORK_PATH=D:\dev\SAST_Framework
AWS_REGION=us-east-1
BEDROCK_MODEL_ID=us.anthropic.claude-haiku-4-5-20251001-v1:0
DATABASE_URL=          # optional; default sqlite data/secure_build.db
NVD_API_KEY=           # optional
SAST_API_URL=http://localhost:8000   # for Next BFF
```
