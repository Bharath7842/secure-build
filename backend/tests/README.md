# Backend tests

Run from `backend/`:

```bash
pytest                    # everything that runs offline (live tests are skipped)
pytest -m unit            # pure logic and fixtures only
pytest -m integration     # in-process API / DB / mock engine, still offline
pytest -m live            # needs a real browser, model or practice target
pytest -m "not live"      # what CI runs
pytest tests/test_dast_layering.py   # the import-rule check on its own
```

## Markers

| Marker | Meaning | Runs by default |
|---|---|---|
| `unit` | Pure logic or fixtures only. No database, network, browser or model. | yes |
| `integration` | Exercises the API, database or mock engine in-process. Still no network. | yes |
| `live` | Needs a real browser, model host or practice target (DVWA, Juice Shop). | **no** — skipped unless `-m` names it |

`tests/conftest.py` skips `live` tests unless the `-m` expression mentions `live`. Older tests
carry no marker; mark a file with `pytestmark = pytest.mark.unit` (or `integration`) when you touch it.
The mock engine is the default for the suite, so nothing here touches git, the network or AWS.

## Shared fixtures (`tests/dast_fixtures/`, exposed via `tests/conftest.py`)

- **`fake_target`** — an in-process web target on httpx's mock transport (no sockets), so it works
  with anything that sends through an `httpx.Client`, including the guarded executor. Configurable
  pages, headers, cookies, an OpenAPI document, role-protected routes, and two users
  (`admin` / `admin-pw`, `user` / `user-pw`).
- **`fake_gateway`** — a strict fake model gateway implementing the domain `ModelGateway` contract:
  scripted replies per task, recorded calls, simulated failures and malformed output. An unscripted
  call fails the test (`FakeModelGateway(strict=False)` returns a fallback reply instead).

## One example per level

**Unit** — pure logic, fixtures only:

```python
import pytest

pytestmark = pytest.mark.unit

def test_gateway_returns_scripted_reply(fake_gateway):
    fake_gateway.script("rule", {"verdict": "FAIL"})
    reply = fake_gateway.complete("rule", "system", "prompt", {"type": "object"})
    assert reply.data == {"verdict": "FAIL"}
    assert fake_gateway.calls[0].task == "rule"
```

**Integration** — API + database + mock engine, offline:

```python
import pytest
from fastapi.testclient import TestClient
from app.config import settings
from app.db import init_db
from app.main import app

pytestmark = pytest.mark.integration
HDR = {"Authorization": f"Bearer {settings.sast_api_token}"}

def test_dast_scan_under_the_mock_engine(tmp_path, monkeypatch):
    monkeypatch.setenv("USE_MOCK_ENGINE", "true")
    settings.use_mock_engine = True
    init_db(f"sqlite:///{(tmp_path / 't.db').as_posix()}")
    client = TestClient(app)
    project = client.post("/projects", json={"name": "p", "default_git_url": "https://x.test/r.git"}, headers=HDR).json()
    resp = client.post("/scans", headers=HDR, json={
        "project_id": project["id"], "scan_type": "dast",
        "dast": {"target_url": "http://localhost:3000", "authorized": True}})
    assert resp.status_code == 202
```

**Live** — needs the practice-target environment (`dev/practice-targets/README.md`); skipped by default:

```python
import pytest

@pytest.mark.live
def test_scan_against_juice_shop():
    ...  # real browser + model + http://127.0.0.1:3001
```

## Other notes

- `tests/fixtures/pre_dast_schema.sql` is the database schema as of the commit before the DAST
  columns were added; `test_dast_schema.py` upgrades it in place to prove the migrations.
- `test_dast_layering.py` fails the build on an import that breaks the layering rules in
  `app/dast/CLAUDE.md`.
- PDF export tests read PDFs with `pypdf` (pinned in `requirements.txt`).
