"""llm_gate: one Ollama call at a time, one scan before the next."""

import sys
import threading
import time
from pathlib import Path

import pytest

SAST_ENGINE_DIR = Path(__file__).resolve().parents[1] / "sast_engine"
if str(SAST_ENGINE_DIR) not in sys.path:
    sys.path.insert(0, str(SAST_ENGINE_DIR))

import llm_gate  # noqa: E402


def _wait_until(predicate, timeout=5.0):
    deadline = time.monotonic() + timeout
    while not predicate():
        if time.monotonic() > deadline:
            raise AssertionError("condition not reached")
        time.sleep(0.01)


def test_one_call_at_a_time_and_the_earlier_scan_goes_first():
    gate = llm_gate.OrderedGate()
    scan_a, scan_b = {}, {}
    order, active, peak = [], [0], [0]
    lock = threading.Lock()
    release = threading.Event()

    def call(usage, label):
        with gate.slot(1, usage):
            with lock:
                active[0] += 1
                peak[0] = max(peak[0], active[0])
                order.append(label)
            if label == "a0":
                release.wait(5)
            with lock:
                active[0] -= 1

    first = threading.Thread(target=call, args=(scan_a, "a0"))
    first.start()
    _wait_until(lambda: order == ["a0"])
    # While a0 runs, a call from a later scan queues first, then two more of scan A.
    threads = [threading.Thread(target=call, args=(scan_b, "b0"))]
    threads[0].start()
    _wait_until(lambda: gate.snapshot()["waiting"] == 1)
    for label in ("a1", "a2"):
        t = threading.Thread(target=call, args=(scan_a, label))
        t.start()
        threads.append(t)
        _wait_until(lambda n=len(threads): gate.snapshot()["waiting"] == n)
    release.set()
    for t in [first, *threads]:
        t.join(5)

    assert peak[0] == 1
    assert order == ["a0", "a1", "a2", "b0"]  # scan A finishes before scan B gets the model


def test_a_cancelled_waiting_call_leaves_the_queue(monkeypatch):
    monkeypatch.setattr(llm_gate, "CANCEL_POLL_SECONDS", 0.01)
    gate = llm_gate.OrderedGate()
    holding, release = threading.Event(), threading.Event()
    cancelled = threading.Event()
    errors = []

    def hold():
        with gate.slot(1, {}):
            holding.set()
            release.wait(5)

    def abort():
        if cancelled.is_set():
            raise RuntimeError("scan was cancelled")

    def wait_then_cancel():
        try:
            with gate.slot(1, {}, abort):
                pass
        except RuntimeError as exc:
            errors.append(str(exc))

    holder = threading.Thread(target=hold)
    holder.start()
    holding.wait(5)
    waiter = threading.Thread(target=wait_then_cancel)
    waiter.start()
    _wait_until(lambda: gate.snapshot()["waiting"] == 1)
    cancelled.set()
    waiter.join(5)
    assert errors == ["scan was cancelled"]
    assert gate.snapshot() == {"active": 1, "waiting": 0}
    release.set()
    holder.join(5)
    assert gate.snapshot() == {"active": 0, "waiting": 0}


def test_ollama_calls_go_through_the_gate_and_others_do_not(monkeypatch):
    pytest.importorskip("boto3", reason="llm_client requires boto3")
    import llm_client

    used = []
    real_slot = llm_client.llm_gate.GATE.slot

    def spy(capacity, *args, **kwargs):
        used.append(capacity)
        return real_slot(capacity, *args, **kwargs)

    monkeypatch.setattr(llm_client.llm_gate.GATE, "slot", spy)
    monkeypatch.delenv("OLLAMA_NUM_PARALLEL", raising=False)
    with llm_client._call_slot({}, "ollama"):
        pass
    with llm_client._call_slot({}, "bedrock"):
        pass
    assert used == [1]  # Ollama's default: one generation at a time

    monkeypatch.setenv("OLLAMA_NUM_PARALLEL", "2")
    with llm_client._call_slot({}, "ollama"):
        pass
    assert used == [1, 2]


def test_the_limiter_survives_a_reload():
    pytest.importorskip("boto3", reason="llm_client requires boto3")
    import importlib

    import llm_client

    before = llm_client._LIMITER
    importlib.reload(llm_client)
    assert llm_client._LIMITER is before
