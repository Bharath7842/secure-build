#!/usr/bin/env python3
"""
Minimal web UI backend for app.py.

Runs the existing LangGraph pipeline (check_connection -> classify_login_type -> login)
from a browser form instead of the CLI, streaming the same console output (including
LLM thinking tokens) back to the page as it happens.
"""

import json
import queue
import sys
import threading

from flask import Flask, Response, request, send_from_directory

from ..config import settings
from ..services.dast_runtime import build_standalone_runtime
from .runner import run_dast_scan

flask_app = Flask(__name__, static_folder="static", static_url_path="")


class QueueWriter:
    """File-like object that forwards every write() to a queue as a raw chunk."""

    def __init__(self, q: queue.Queue):
        self.q = q

    def write(self, chunk: str) -> None:
        if chunk:
            self.q.put(("__chunk__", chunk))

    def flush(self) -> None:
        pass


class ThreadLocalStdout:
    """Routes print() output per-thread instead of swapping sys.stdout globally.

    A plain contextlib.redirect_stdout would swap the process-wide stdout while
    a background job thread runs, which corrupts the Flask dev server's own
    request-handling thread (logging, socket I/O) since it shares that same
    global. This proxy only affects the thread that registered a writer.
    """

    def __init__(self, real_stdout):
        self._real = real_stdout
        self._local = threading.local()

    def register(self, writer) -> None:
        self._local.writer = writer

    def unregister(self) -> None:
        if hasattr(self._local, "writer"):
            del self._local.writer

    def write(self, s: str) -> None:
        writer = getattr(self._local, "writer", None)
        (writer or self._real).write(s)

    def flush(self) -> None:
        writer = getattr(self._local, "writer", None)
        (writer or self._real).flush()


_thread_stdout = ThreadLocalStdout(sys.stdout)
sys.stdout = _thread_stdout


def run_job(params: dict, q: queue.Queue) -> None:
    runtime = None
    try:
        runtime = build_standalone_runtime(
            target_url=params["url"],
            login_url=params["login_url"],
            username=params["username"],
            password=params["password"],
            headless=params["headless"],
            ollama_model=params["ollama_model"],
            ollama_base_url=settings.dast_ollama_url,
        )
        writer = QueueWriter(q)
        _thread_stdout.register(writer)
        try:
            discovery = run_dast_scan(runtime=runtime)["discovery"]
            print("\n--- Run summary ---")
            print(f"connection_ok: {discovery['connection_ok']}")
            print(f"login_type: {discovery['login_type']}")
            if discovery.get("authentication_failed"):
                print(f"authentication_failed: {discovery['authentication_failed']}")
            if discovery.get("stop_reason"):
                print(f"stop_reason: {discovery['stop_reason']}")
            if discovery["login_type"] == "simple_form":
                print(f"login_success: {discovery['login_success']}")
        finally:
            _thread_stdout.unregister()

        q.put(("__done__", {
            "connection_ok": discovery["connection_ok"],
            "login_type": discovery["login_type"],
            "login_success": discovery.get("login_success", False),
            "stop_reason": discovery.get("stop_reason", ""),
        }))
    except Exception as exc:  # noqa: BLE001
        q.put(("__chunk__", f"\nUnexpected error: {exc}\n"))
        q.put(("__done__", {"error": str(exc)}))
    finally:
        if runtime is not None:
            if runtime.credentials is not None:
                runtime.credentials.clear()
            runtime.close()


@flask_app.route("/")
def index():
    return send_from_directory("static", "index.html")


@flask_app.route("/api/run", methods=["POST"])
def api_run():
    payload = request.get_json(force=True) or {}

    required = ["url", "login_url", "username", "password"]
    missing = [f for f in required if not payload.get(f)]
    if missing:
        return {"error": f"Missing required field(s): {', '.join(missing)}"}, 400

    params = {
        "url": payload["url"],
        "login_url": payload["login_url"],
        "username": payload["username"],
        "password": payload["password"],
        "headless": bool(payload.get("headless", True)),
        "ollama_model": payload.get("ollama_model") or "gpt-oss:20b",
    }

    q: queue.Queue = queue.Queue()
    thread = threading.Thread(target=run_job, args=(params, q), daemon=True)
    thread.start()

    def generate():
        while True:
            kind, data = q.get()
            if kind == "__done__":
                yield "\x00" + json.dumps({"type": "done", "result": data})
                break
            yield "\x00" + json.dumps({"type": "chunk", "text": data})

    return Response(generate(), mimetype="text/plain")


if __name__ == "__main__":
    flask_app.run(host="127.0.0.1", port=5001, debug=False, threaded=True)
