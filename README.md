# Secure Build

FastAPI backend and Next.js frontend for SAST scanning, findings review, and CI integration.

Design spec: [docs/superpowers/specs/2026-07-14-secure-build-sast-ui-design.md](docs/superpowers/specs/2026-07-14-secure-build-sast-ui-design.md)

## CI Integration

The Secure Build API works with **any CI system** â€” Jenkins, GitHub Actions, GitLab CI, Azure Pipelines, or a plain shell script. The pattern is always the same: **POST** a scan â†’ **poll** `/scans/{id}/status` â†’ **GET** `/scans/{id}/results` and fail the build when `gate_summary.gate_failed` is true.

| Guide | Description |
|-------|-------------|
| [curl example](docs/ci/curl-example.md) | Generic bash script (any pipeline) |
| [Jenkins Declarative](docs/ci/jenkins-declarative.md) | Jenkinsfile with `httpRequest` plugin |
| [GitHub Actions](docs/ci/github-actions.md) | Workflow YAML with `curl` + `jq` |

All requests require `Authorization: Bearer <token>`. Create a project once via `POST /projects`, then trigger scans with `POST /scans` using the project `id`.

## Backend

```bash
cd backend
python -m venv .venv
.venv\Scripts\activate   # Windows
pip install -r requirements.txt
Copy-Item ..\.env.example ..\.env   # Windows; or: cp ../.env.example ../.env
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

When `USE_MOCK_ENGINE=false`, install live-engine deps via `pip install -r requirements.txt` (includes boto3, langgraph, tree-sitter). The agent lives in-repo at `backend/sast_engine/`.

## Frontend

```bash
cd frontend
npm install
npm run dev
```

## Live SAST engine (Bedrock) — manual verification checklist

By default `pytest` and local mock runs use the **mock engine**
(`USE_MOCK_ENGINE=true`), which never touches git, the network, or AWS. The
real engine uses the in-repo agent under `backend/sast_engine/`
(`sast_scan_agent.py` graph+LLM LangGraph pipeline) and is
gated behind two separate flags so it can't be triggered by accident:

- `USE_MOCK_ENGINE=false` — turns off the deterministic mock findings
- `RUN_LIVE_SAST=1` — explicit opt-in on top of that, checked in `engine_adapter.run_scan`

To verify the real path end to end:

1. **Use the in-repo engine** (default).
   `SAST_FRAMEWORK_PATH` defaults to `backend/sast_engine` (contains
   `sast_scan_agent.py` plus `graph/`, `adapters/`, `pipeline/`). No external checkout.

2. **Install backend dependencies** (in the backend venv):

   ```bash
   pip install -r requirements.txt
   ```

   This pulls in `boto3`, `langgraph`, `networkx`, `tree-sitter` (+ java/python/typescript
   grammars), `PyYAML`, `python-dotenv`, `beautifulsoup4`.

### Dual finding sources (graph SAST + OWASP/NVD reference)

Each scan runs two complementary paths:

1. **Graph SAST (v3)** — parse → tag → flows → LLM verify → config/deep review
2. **Reference scan** — fetches project OWASP Top 10 + NVD CVE URLs (and stack-adaptive OWASP cheat sheets), LLM-summarizes them, then LLM-checks your code against those checks

Reference findings are **merged** into graph findings when they match the same file + CWE (+ nearby line). Set `RUN_REFERENCE_SCAN=0` to skip outbound OWASP/NVD fetches. The scan results UI supports **Verdict** filters (`TRUE_POSITIVE`, `NEEDS_REVIEW`, `FALSE_POSITIVE`, Unverified).

3. **Configure an LLM**:
   - **Bedrock**: AWS credentials with `bedrock:InvokeModel` and the model in `BEDROCK_MODEL_ID`
   - **Ollama**: local daemon at `OLLAMA_BASE_URL` (default `http://localhost:11434`) with the model pulled

4. **Create a project** pointing at a small public repo (Java, Python, or TypeScript)
   and trigger a scan with:

   ```bash
   $env:USE_MOCK_ENGINE = "false"
   $env:RUN_LIVE_SAST = "1"
   ```

5. **Watch the scan go `queued → running → success/failed`.** On success,
   `GET /scans/{id}/results` should return real findings with `owasp_ref`,
   `cwe`, `snippet`, and `ai_fix` populated from the agent's output; a
   `sast_report.html` and (for Java repos) `symbol_index.db` will also be
   written under `data/workspaces/<project_id>/`.

6. **Run a second scan on a later commit** of the same project and confirm
   `backend/app/services/incremental.py` recorded fewer changed files
   (visible via `FileSnapshot` rows / debug logging) than the first,
   full-tree scan.

### "Scan again" / no-change behavior

`POST /scans` with no `commit_sha` (the normal "New Scan" form flow) now
resolves the latest commit on the target branch via `git ls-remote` (no
clone) before doing anything else:

- If that commit matches an existing non-failed scan for the project, the
  endpoint returns that scan immediately (`reused: true` in the response,
  with a human-readable `reused_reason`) instead of starting a new scan —
  the UI shows a "no changes since the last scan" banner on the scan page.
- If the commit is new (or no prior scan exists), a fresh scan is queued
  with `commit_sha` pinned to that resolved commit, same as before.
- If the remote is unreachable (offline, private repo, bad URL),
  resolution silently returns `None` and the endpoint falls back to the
  original "always scan" behavior — this never blocks a scan trigger.
- A previous scan with `status="failed"` for the same commit is **not**
  reused, so a flaky/failed attempt always gets retried rather than being
  stuck behind its own failure.
- Passing an explicit `commit_sha`, or checking "Force scan" on the form
  (`force: true`), always skips this check.

### Live engine log

`GET /scans/{id}/logs?after=<seq>` returns an incremental tail of what the
engine is doing right now — every `print()` step banner the agent emits
(STEP 1 stack detection, STEP 3 fetches, STEP 5/5c scan progress, STEP 5b
enrichment batches, ...) plus a few lifecycle lines from `scan_runner.py`
itself (workspace checkout, engine start/finish, persistence). Pass back
the response's `next_after` as `after` on the next call to fetch only new
lines. The frontend scan detail page polls this on the same interval as
`/status` and renders it as a terminal-style "Engine log" panel — visible
while the scan is running and left in place afterward for review. This is
in-memory only (per-process, capped/LRU-evicted per scan), not persisted.

### Scan versioning and version diffs

Every scan gets a `version` — a per-project sequential counter (1, 2, 3, ...)
assigned when the scan is created, independent of other projects' counters.
Existing databases are migrated automatically at startup (`app/db.py`
`_run_light_migrations`): a light, idempotent `ALTER TABLE ... ADD COLUMN`
plus a backfill that assigns versions to pre-existing scans in
`created_at` order, since this project has no alembic migration chain yet.

`GET /scans/{id}/compare?against=<scan_id>` diffs one scan's findings
against another's and buckets them into:

- **new** — present in the base scan but not the comparison scan
  (newly raised since that version)
- **fixed** — present in the comparison scan but not the base scan
  (resolved since that version)
- **pending** — present in both (still unresolved)

Findings get a fresh row/id every scan, so "the same finding" across scans
is matched by a content fingerprint instead of `id` — see
`app/services/scan_diff.py` (`rule_id` or `cwe`, plus `file_path`, plus
`title`; line numbers are deliberately excluded since unrelated edits shift
them without the vulnerability moving or being fixed).

If `against` is omitted, it defaults to the most recent earlier
**successful** version of the same project (or `compare_scan_id: null` /
everything "new" if this is the first scan). The scan detail page shows
this default comparison as a "vs v(N-1): X new · Y fixed · Z pending" strip
automatically, plus a "Compare with another version…" button that opens a
modal to diff against *any* earlier version of the same project (listed by
version number and timestamp).

### Known limitations (Task 6)

- The agent's `node_prepare_repo` step always walks the *entire* checked-out
  workspace (capped by its own `MAX_FILES_TO_SCAN`); `changed_paths` from
  incremental hashing is threaded through to `agent_bridge.run_real_scan`
  but is not yet used to filter the agent's own file walk. Incremental
  hashing still gates whether `scan_mode="incremental"` re-scans are
  triggered at all — this is a scope boundary for a follow-up task, not a
  bug.
- Language adapters ship for Java, Python, and TypeScript/JavaScript; other
  languages are skipped at Stage 1 until an adapter is added.
- `cvss` on real findings is a coarse severity-bucket estimate
  (`CRITICAL=9.5 / HIGH=7.5 / MEDIUM=5.0 / LOW=3.0 / INFO=0.0`) since the
  agent itself doesn't compute a CVSS vector for local static-analysis
  findings (only for `dependency_results` via OSV, which aren't persisted
  as `Finding` rows yet).
