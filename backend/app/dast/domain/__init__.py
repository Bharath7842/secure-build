"""DAST domain layer: pure vocabulary and rules, no I/O.

Dependency rule (enforced by `tests/test_dast_layering.py`): modules in this
package may import only the standard library and each other. No FastAPI,
SQLAlchemy, Playwright, httpx, LangChain/LLM SDKs, and nothing from the rest of
`app/`. Everything that touches the outside world is declared here as a
Protocol in `interfaces.py` and implemented elsewhere.

Contracts and type definitions live here alongside the logic that has landed so
far: scope/method policy (`policy.py`), credential redaction (`redaction.py`) and
non-destructive input validation (`validation.py`), all EPIC-01. The rest (verdict
roll-up, guardrail, dedupe, diff, detectors) lands story by story (EPIC-03, 04, 07).
"""
