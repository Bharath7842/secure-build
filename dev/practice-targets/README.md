# Local practice-target environment

> **For authorized local testing only.** DVWA and Juice Shop are deliberately vulnerable. They are
> bound to `127.0.0.1` and must never be exposed to a network or the internet. Only scan targets
> you own or are explicitly authorized to test.

One place to start everything a live DAST scan needs: a local model host, a browser for the crawl,
the backend, the frontend, and two practice targets.

| Piece | Where | Notes |
|---|---|---|
| Juice Shop | http://127.0.0.1:3001 | Single-page app with a REST API (3000 is the frontend's port) |
| DVWA | http://127.0.0.1:4280 | Classic server-rendered PHP app; `admin` / `password` |
| Backend | http://127.0.0.1:8000 | FastAPI |
| Frontend | http://127.0.0.1:3000 | Next.js |
| Ollama | http://127.0.0.1:11434 | Local model host |

## 1. Prerequisites (one time)

```bash
# Model host — install Ollama (https://ollama.com), then:
ollama serve &                 # skip if it already runs as a service
ollama pull gpt-oss:20b        # the default DAST model (DAST_OLLAMA_MODEL)

# Backend: Python 3.12 venv
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python -m playwright install chromium     # one-time browser download for the crawl
cd ..

# Frontend
cd frontend && npm install && cd ..
```

`playwright install chromium` is only needed for live scans. The mock suite (`pytest -m "not live"`)
never needs a browser, a model or Docker.

## 2. Start the practice targets

```bash
cd dev/practice-targets
./reset.sh          # clean start: fresh containers, DVWA database created
```

`docker compose up -d` also works, but DVWA's database is only created by `reset.sh` (or by opening
http://127.0.0.1:4280/setup.php and clicking *Create / Reset Database*). Run `./reset.sh` again at any
time to return both targets to a known state.

## 3. Start the backend and frontend

```bash
# repo root, copy the example env once: cp .env.example .env  (set SAST_API_TOKEN)
cd backend && source .venv/bin/activate
USE_MOCK_ENGINE=false RUN_DAST=true uvicorn app.main:app --reload --port 8000

# second terminal
cd frontend && cp -n .env.local.example .env.local   # SAST_API_URL / SAST_API_TOKEN
npm run dev
```

The Ollama address defaults to `http://localhost:11434`; set `DAST_OLLAMA_BASE_URL` to point elsewhere.

## 4. Run one live scan against each target

Create a project first (UI, or `POST /projects`), then either use **DAST** in the UI
(http://127.0.0.1:3000/dast) or the API:

```bash
export TOKEN=...        # SAST_API_TOKEN
export PROJECT_ID=...

# Juice Shop (register any account on the site first, then use those credentials)
curl -s -X POST http://127.0.0.1:8000/scans -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -d '{
  "project_id": "'$PROJECT_ID'", "scan_type": "dast",
  "dast": {"target_url": "http://127.0.0.1:3001", "login_url": "http://127.0.0.1:3001/#/login",
           "username": "you@example.test", "password": "your-password", "authorized": true}}'

# DVWA
curl -s -X POST http://127.0.0.1:8000/scans -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -d '{
  "project_id": "'$PROJECT_ID'", "scan_type": "dast",
  "dast": {"target_url": "http://127.0.0.1:4280", "login_url": "http://127.0.0.1:4280/login.php",
           "username": "admin", "password": "password", "authorized": true}}'
```

Follow progress in the UI, or poll `GET /scans/{id}/status` and `GET /scans/{id}/logs?after=0`.

## Smoke checklist (run by hand after changing this folder)

- [ ] `./reset.sh` finishes with "Both targets are at their known initial state."
- [ ] `curl -I http://127.0.0.1:3001` and `curl -I http://127.0.0.1:4280/login.php` both answer.
- [ ] `docker compose ps` shows ports as `127.0.0.1:3001->3000` and `127.0.0.1:4280->80`, and no published port for `dvwa-db`.
- [ ] A scan with the mock engine off reaches `success` against one of the two targets.

## Pinned versions

| Image | Pin | Recorded |
|---|---|---|
| `bkimminich/juice-shop` | `v20.2.0` (`sha256:8739101a…526b`) | 2026-10-07 |
| `ghcr.io/digininja/dvwa` | digest `sha256:830037df…91d2` (what `latest` pointed at; the project publishes only commit-sha tags and `latest`) | 2026-10-07 |
| `mariadb` | `10.11.19` | 2026-10-07 |

To bump a pin: change the tag/digest in `docker-compose.yml`, run `./reset.sh`, tick the smoke
checklist, and update this table.
