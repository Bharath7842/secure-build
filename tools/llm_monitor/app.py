"""Live view of Secure Build's SAST LLM calls.

Reads the JSONL call log the engine writes when LLM_EVENTS_FILE is set
(backend/sast_engine/llm_events.py): one line per state change of a call —
queued (waiting for a concurrency slot), started (sent to the provider),
retry, then done / failed / cancelled / cache_hit.

Run from the repo root:
    tools/llm_monitor/.venv/bin/streamlit run tools/llm_monitor/app.py

LLM_EVENTS_FILE and OLLAMA_BASE_URL are read from the environment, then from
the repo's .env; the defaults are data/llm_events.jsonl and localhost:11434.
"""

from __future__ import annotations

import json
import os
import time
from datetime import datetime
from pathlib import Path

import pandas as pd
import requests
import streamlit as st

REPO_ROOT = Path(__file__).resolve().parents[2]
TERMINAL = {"done", "failed", "cancelled", "cache_hit"}
STATUS_LABEL = {
    "queued": "waiting for slot",
    "started": "in flight",
    "done": "done",
    "failed": "failed",
    "cancelled": "cancelled",
    "cache_hit": "cache hit",
    "abandoned": "abandoned (backend restarted)",
}
WINDOWS = {"15 min": 15 * 60, "1 hour": 3600, "6 hours": 6 * 3600, "24 hours": 86400, "All": None}


def _dotenv() -> dict[str, str]:
    values: dict[str, str] = {}
    try:
        for line in (REPO_ROOT / ".env").read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, _, value = line.partition("=")
                values[key.strip()] = value.strip().strip('"').strip("'")
    except OSError:
        pass
    return values


_ENV = _dotenv()
EVENTS_FILE = Path(
    os.environ.get("LLM_EVENTS_FILE") or _ENV.get("LLM_EVENTS_FILE") or REPO_ROOT / "data" / "llm_events.jsonl"
)
OLLAMA_URL = (os.environ.get("OLLAMA_BASE_URL") or _ENV.get("OLLAMA_BASE_URL") or "http://localhost:11434").rstrip("/")
# Complete prompts/responses, one file each (llm_events.store_body); the JSONL only holds previews.
BODIES_DIR = EVENTS_FILE.with_name(EVENTS_FILE.stem + "_bodies")


def _body(name: str | None) -> str | None:
    if not name:
        return None
    try:
        return (BODIES_DIR / name).read_text(encoding="utf-8")
    except OSError:
        return None


def _pid_alive(pid: object) -> bool:
    try:
        os.kill(int(pid), 0)
    except ProcessLookupError:
        return False
    except (PermissionError, TypeError, ValueError):
        return True
    return True


def _read_events() -> list[dict]:
    events: list[dict] = []
    for path in (Path(f"{EVENTS_FILE}.1"), EVENTS_FILE):  # rotated file first, then the live one
        try:
            with path.open(encoding="utf-8") as fh:
                for line in fh:
                    try:
                        events.append(json.loads(line))
                    except ValueError:
                        continue  # a line still being written
        except OSError:
            continue
    return events


def build_calls(events: list[dict]) -> dict[str, dict]:
    """One record per call id, folded from its events in file order."""
    calls: dict[str, dict] = {}
    for ev in events:
        cid = ev.get("id")
        if not cid:
            continue
        call = calls.setdefault(cid, {"id": cid, "retries": 0, "status": "queued", "retry_reasons": []})
        kind = ev.get("event")
        ts = ev.get("ts")
        call["pid"] = ev.get("pid", call.get("pid"))
        call["scan_id"] = ev.get("scan_id") or call.get("scan_id")
        if kind == "queued":
            call["queued_ts"] = ts
            for key in ("step", "provider", "model", "json_mode", "max_tokens", "system_chars", "user_chars",
                        "est_input_tokens", "context_window", "system", "user", "system_sha"):
                call[key] = ev.get(key)
        elif kind == "started":
            call["started_ts"] = call.get("started_ts") or ts
            if call["status"] not in TERMINAL:
                call["status"] = "started"
        elif kind == "retry":
            call["retries"] += 1
            call["retry_reasons"].append(ev.get("reason"))
        elif kind in TERMINAL:
            call["status"] = kind
            call["end_ts"] = ts
            for key in ("input_tokens", "output_tokens", "stop_reason", "duration_ms", "cost_usd", "response", "error"):
                if key in ev:
                    call[key] = ev[key]
    for call in calls.values():
        call.setdefault("queued_ts", call.get("started_ts") or call.get("end_ts"))
        if call["status"] not in TERMINAL and not _pid_alive(call.get("pid")):
            call["status"] = "abandoned"
    return calls


def _num(value: object) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _est_tokens(call: dict) -> int:
    """Prompt size before the answer: the engine's estimate, else chars / 4."""
    return _num(call.get("est_input_tokens")) or (_num(call.get("system_chars")) + _num(call.get("user_chars"))) // 4


def _context_used(call: dict) -> float | None:
    """Share of the model's context window this call used (or will use, while pending)."""
    window = _num(call.get("context_window"))
    if not window:
        return None
    if call.get("input_tokens") is not None:
        used = _num(call.get("input_tokens")) + _num(call.get("output_tokens"))
    else:
        used = _est_tokens(call)
    return used / window


def _fmt_pct(share: float | None) -> str:
    if share is None:
        return ""
    return f"{share:.0%}" + (" ⚠ over" if share > 1 else " ⚠" if share > 0.9 else "")


def _fmt_tokens(n: int) -> str:
    return f"{n / 1e6:.2f}M" if n >= 1_000_000 else f"{n / 1e3:.1f}k" if n >= 10_000 else f"{n:,}"


def _fmt_ts(ts: float | None) -> str:
    return datetime.fromtimestamp(ts).strftime("%H:%M:%S") if ts else ""


def _fmt_age(seconds: float | None) -> str:
    if seconds is None:
        return ""
    seconds = int(seconds)
    return f"{seconds // 60}m {seconds % 60:02d}s" if seconds >= 60 else f"{seconds}s"


def _ollama_ps() -> tuple[list[dict] | None, str | None]:
    try:
        resp = requests.get(f"{OLLAMA_URL}/api/ps", timeout=2)
        resp.raise_for_status()
        return resp.json().get("models") or [], None
    except Exception as exc:  # noqa: BLE001 - shown on the page
        return None, f"{type(exc).__name__}: {exc}"


st.set_page_config(page_title="LLM call monitor", page_icon="📡", layout="wide")
st.title("LLM call monitor")
st.caption(f"Reading `{EVENTS_FILE}` · Ollama at `{OLLAMA_URL}`")

with st.sidebar:
    window_label = st.selectbox("Time window", list(WINDOWS), index=1)
    refresh = st.select_slider("Refresh every", options=[1, 2, 5, 10, 30], value=2, format_func=lambda s: f"{s}s")
    st.caption("Only SAST scans started after LLM_EVENTS_FILE was set are logged.")


@st.fragment(run_every=refresh)
def live() -> None:
    if not EVENTS_FILE.exists():
        st.info(
            f"No call log yet at `{EVENTS_FILE}`. Set `LLM_EVENTS_FILE` in the repo's `.env`, restart the "
            "backend, and start a scan."
        )
        return
    now = time.time()
    calls = list(build_calls(_read_events()).values())

    scans = sorted({c.get("scan_id") or "(none)" for c in calls}, key=lambda s: max(
        (c.get("queued_ts") or 0) for c in calls if (c.get("scan_id") or "(none)") == s
    ), reverse=True)
    scan = st.selectbox("Scan", ["All scans", *scans], key="scan_filter")
    if scan != "All scans":
        calls = [c for c in calls if (c.get("scan_id") or "(none)") == scan]

    pending = [c for c in calls if c["status"] in ("queued", "started")]
    span = WINDOWS[window_label]
    recent = [c for c in calls if span is None or (c.get("queued_ts") or 0) >= now - span]

    sent = [c for c in recent if c.get("started_ts")]
    done = [c for c in recent if c["status"] == "done"]
    failed = [c for c in recent if c["status"] == "failed"]
    durations = [c["duration_ms"] for c in done if c.get("duration_ms") is not None]

    cols = st.columns(8)
    cols[0].metric("Waiting for slot", sum(1 for c in pending if c["status"] == "queued"), help="Queued inside the backend, not yet sent")
    cols[1].metric("In flight", sum(1 for c in pending if c["status"] == "started"), help="Sent to the provider, no answer yet")
    cols[2].metric("Sent", len(sent), help=f"Calls sent in the last {window_label.lower()}")
    cols[3].metric("Done", len(done))
    cols[4].metric("Failed", len(failed))
    cols[5].metric("Retries", sum(c["retries"] for c in recent))
    cols[6].metric("Cache hits", sum(1 for c in recent if c["status"] == "cache_hit"))
    cols[7].metric("Avg duration", f"{sum(durations) / len(durations) / 1000:.1f}s" if durations else "—")

    answered = [c for c in recent if c.get("input_tokens") is not None]
    tokens_in = sum(_num(c.get("input_tokens")) for c in answered)
    tokens_out = sum(_num(c.get("output_tokens")) for c in answered)
    pending_tokens = sum(_est_tokens(c) for c in pending)
    usage = [u for u in (_context_used(c) for c in recent + pending) if u is not None]
    cols = st.columns(8)
    cols[0].metric("Tokens sent", _fmt_tokens(tokens_in), help="Input (prompt) tokens of answered calls, as the provider reported them")
    cols[1].metric("Tokens received", _fmt_tokens(tokens_out), help="Output tokens of answered calls")
    cols[2].metric("Total tokens", _fmt_tokens(tokens_in + tokens_out))
    cols[3].metric("Avg sent / call", _fmt_tokens(tokens_in // len(answered)) if answered else "—")
    cols[4].metric("Avg received / call", _fmt_tokens(tokens_out // len(answered)) if answered else "—")
    cols[5].metric("Pending prompt tokens", _fmt_tokens(pending_tokens), help="Estimated (chars / 4) size of calls waiting or in flight")
    cols[6].metric("Max context used", _fmt_pct(max(usage)) if usage else "—",
                   help="Prompt + answer as a share of the model's context window (Ollama num_ctx). Past 100% Ollama silently truncates the prompt.")
    cols[7].metric("Over context", sum(1 for u in usage if u > 1), help="Calls whose prompt + answer exceeded the context window")

    left, right = st.columns([3, 2])
    with left:
        st.subheader(f"Pending now ({len(pending)})")
        if pending:
            rows = [{
                "state": STATUS_LABEL[c["status"]],
                "age": _fmt_age(now - (c.get("queued_ts") or now)),
                "in flight for": _fmt_age(now - c["started_ts"]) if c.get("started_ts") else "",
                "retries": c["retries"],
                "step": c.get("step"),
                "model": c.get("model"),
                "est. tokens to send": _est_tokens(c),
                "context window": c.get("context_window"),
                "context used": _fmt_pct(_context_used(c)),
                "scan": (c.get("scan_id") or "")[:8],
                "id": c["id"],
            } for c in sorted(pending, key=lambda c: c.get("queued_ts") or 0)]
            st.dataframe(pd.DataFrame(rows), hide_index=True, width="stretch")
        else:
            st.success("Nothing pending.")
    with right:
        st.subheader("Ollama")
        models, err = _ollama_ps()
        if err:
            st.warning(f"Not responding ({err})")
        elif not models:
            st.write("Running, no model loaded.")
        else:
            st.dataframe(pd.DataFrame([{
                "model": m.get("name"),
                "memory": f"{(m.get('size_vram') or m.get('size') or 0) / 1e9:.1f} GB",
                "context": m.get("context_length"),
                "unloads at": (m.get("expires_at") or "")[11:19],
            } for m in models]), hide_index=True, width="stretch")

    st.subheader("Calls per minute")
    if recent:
        frame = pd.DataFrame([{
            "minute": pd.to_datetime(int((c.get("end_ts") or c.get("queued_ts") or now) // 60 * 60), unit="s"),
            "status": STATUS_LABEL[c["status"]],
        } for c in recent])
        st.bar_chart(frame.groupby(["minute", "status"]).size().unstack(fill_value=0))
    else:
        st.caption("No calls in this window.")

    st.subheader("Tokens per minute")
    if answered:
        tok = pd.DataFrame([{
            "minute": pd.to_datetime(int((c.get("end_ts") or c.get("queued_ts") or now) // 60 * 60), unit="s"),
            "sent": _num(c.get("input_tokens")),
            "received": _num(c.get("output_tokens")),
        } for c in answered])
        st.bar_chart(tok.groupby("minute")[["sent", "received"]].sum())
    else:
        st.caption("No answered calls in this window.")

    st.subheader("Recent calls")
    ordered = sorted(recent, key=lambda c: c.get("queued_ts") or 0, reverse=True)[:300]
    if not ordered:
        st.caption("No calls in this window.")
        return
    recent_frame = pd.DataFrame([{
        "queued": _fmt_ts(c.get("queued_ts")),
        "status": STATUS_LABEL[c["status"]],
        "step": c.get("step"),
        "model": c.get("model"),
        "duration s": round(c["duration_ms"] / 1000, 1) if c.get("duration_ms") is not None else None,
        "tokens sent": c.get("input_tokens"),
        "tokens received": c.get("output_tokens"),
        "est. prompt tokens": _est_tokens(c),
        "context window": c.get("context_window"),
        "context used": _fmt_pct(_context_used(c)),
        "retries": c["retries"],
        "error": c.get("error") or "",
        "scan": (c.get("scan_id") or "")[:8],
        "id": c["id"],
    } for c in ordered])
    for column in ("tokens sent", "tokens received", "context window"):
        recent_frame[column] = pd.to_numeric(recent_frame[column], errors="coerce").astype("Int64")
    st.dataframe(recent_frame, hide_index=True, width="stretch", height=360)

    by_id = {c["id"]: c for c in ordered}
    chosen = st.selectbox(
        "Show a call's request and response",
        list(by_id),
        format_func=lambda cid: f"{_fmt_ts(by_id[cid].get('queued_ts'))} · {by_id[cid].get('step')} · "
        f"{STATUS_LABEL[by_id[cid]['status']]} · {cid}",
        key="call_detail",
    )
    call = by_id[chosen]
    meta = {k: call.get(k) for k in (
        "id", "scan_id", "step", "provider", "model", "json_mode", "max_tokens", "status", "retries",
        "duration_ms", "input_tokens", "output_tokens", "est_input_tokens", "context_window", "cost_usd",
        "stop_reason", "error",
    )}
    meta["context_used"] = _fmt_pct(_context_used(call)) or None
    meta["retry_reasons"] = call["retry_reasons"]
    st.json(meta, expanded=False)
    system = _body(f"system-{call['system_sha']}.txt" if call.get("system_sha") else None)
    user = _body(f"{chosen}.user.txt")
    response = _body(f"{chosen}.response.txt") or _body(f"{chosen}.error.txt")
    pending_call = call["status"] in ("queued", "started")

    def show(label: str, full: str | None, fallback: str | None, part: str, empty: str = "") -> None:
        text = full if full is not None else (fallback or empty)
        note = f"{len(text):,} chars" if full is not None else "preview only — full text not saved for this call"
        st.markdown(f"**{label}** ({note})")
        if full is not None:
            st.download_button("Download", full, file_name=f"{chosen}.{part}.txt", key=f"dl-{part}")
        st.code(text, language=None, wrap_lines=True)

    a, b = st.columns(2)
    with a:
        show("System prompt", system, call.get("system"), "system")
        show("User prompt", user, call.get("user"), "user")
    with b:
        if call["status"] == "done" and not (response if response is not None else call.get("response")):
            st.warning(
                "The model returned an empty answer"
                + (" because it hit its output token limit (stop reason `length`) — a reasoning model can spend "
                   "the whole budget thinking." if call.get("stop_reason") == "length" else ".")
            )
        show("Response", response, call.get("response") or call.get("error"), "response",
             "(no response yet)" if pending_call else "")
        thinking = _body(f"{chosen}.thinking.txt")
        if thinking:
            show("Model reasoning", thinking, None, "thinking")


live()
