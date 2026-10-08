"""Endpoint analysis runs up to `model_parallelism` endpoints at once (each endpoint's own
construct -> baseline -> test -> rule sequence stays in order within its own thread); the default
of 1 keeps the walkthrough sequential, finishing one endpoint's recorded snapshot and checks before
the next starts. Log blocks from buffered_capture still must not interleave when workers>1."""

from __future__ import annotations

import json
import threading
import time

import pytest

from app.config import settings
from app.dast.domain.interfaces import ModelReply
from app.services import scan_log
from tests.dast_fixtures import FakeModelGateway, FakeTarget
from tests.test_dast_engine import BASE, Harness, default_rule_set, identities

pytestmark = pytest.mark.integration

PATHS = [f"/api/item{i}" for i in range(6)]


class SlowGateway(FakeModelGateway):
    """Every model call takes `delay` seconds; tracks how many are in flight at once."""

    def __init__(self, delay=0.15, fail_on=None):
        super().__init__(strict=False)
        self.delay, self.fail_on = delay, fail_on
        self._lock = threading.Lock()
        self.in_flight = self.max_in_flight = 0

    def complete(self, task, system, prompt, reply_schema, **kw):
        with self._lock:
            self.in_flight += 1
            self.max_in_flight = max(self.max_in_flight, self.in_flight)
        try:
            time.sleep(self.delay)
            if task == "construct":
                if self.fail_on and self.fail_on in prompt:
                    return ModelReply(data={}, fallback_used=True)  # what the real gateway returns when a call fails
                return ModelReply(data={"tests": [{"check_id": "dast-sqli", "parameter": "q", "location": "query", "input": "1'", "expected_signal": "sql error"}]})
            if task == "rule":
                # advisory FAIL with no detector signal: the model's FAIL stands as a true positive
                return ModelReply(data={"verdict": "FAIL", "finding": "possible issue", "severity": "MEDIUM", "confidence": "LOW", "evidence": "none"})
            return ModelReply(data={}, fallback_used=True)  # fingerprint, crawl_plan, ...: the heuristics decide
        finally:
            with self._lock:
                self.in_flight -= 1


def target() -> FakeTarget:
    t = FakeTarget()
    t.add_json("/", {"service": "demo"})
    t.set_openapi({"openapi": "3.0.0", "paths": {p: {"get": {}} for p in PATHS}})
    for p in PATHS:
        t.add_json(p, {"ok": True})
    return t


def run(parallelism, gateway=None, **kw):
    gateway = gateway or SlowGateway()
    harness = Harness(target(), identities(), gateway=gateway, request={"model_parallelism": parallelism}, rule_set=default_rule_set(), **kw)
    started = time.perf_counter()
    discovery = harness.run(run_analysis=True)
    return discovery, gateway, harness, time.perf_counter() - started


def view(discovery):
    return [(a["label"], a["overall_verdict"], a["counts"]) for a in discovery["api_analysis"]]


def test_serial_is_the_default_and_never_overlaps_calls():
    discovery, gateway, _, _ = run(1)
    assert gateway.max_in_flight == 1 and len(discovery["api_analysis"]) == 6


def test_discovery_is_published_after_each_endpoint():
    snaps: list[dict] = []
    gateway = SlowGateway(delay=0.02)
    harness = Harness(target(), identities(), gateway=gateway, request={"model_parallelism": 3}, rule_set=default_rule_set())
    discovery = harness.run(run_analysis=True, discovery_writer=snaps.append)
    counts = [len(s.get("api_analysis") or []) for s in snaps]
    assert counts[-1] == 6 and 1 in counts
    assert all(counts[i] <= counts[i + 1] for i in range(len(counts) - 1))
    assert all(a.get("recorded", {}).get("method") for a in discovery["api_analysis"])


def test_endpoints_run_concurrently_when_parallelism_is_raised():
    discovery, gateway, _, _ = run(3)
    assert gateway.max_in_flight > 1  # at least two endpoints' model calls overlapped
    assert len(discovery["api_analysis"]) == 6
    assert all("recorded" in a and a["recorded"]["method"] for a in discovery["api_analysis"])


def test_results_match_a_serial_run_and_stay_in_endpoint_order():
    serial, *_ = run(1)
    parallel, *_ = run(4)
    assert view(parallel) == view(serial)
    labels = [a["label"] for a in parallel["api_analysis"]]
    assert labels == sorted(labels, key=lambda l: int(l.rsplit("item", 1)[1]))


def test_findings_are_written_once_each_in_parallel_runs():
    discovery, _, harness, _ = run(4)
    written = [label for label, rows in harness.written if label != "passive analysis"]
    assert sorted(written) == sorted(a["label"] for a in discovery["api_analysis"])  # one write per endpoint


def test_one_endpoint_failing_does_not_stop_the_others():
    gateway = SlowGateway(fail_on="item2")
    discovery, _, _, _ = run(3, gateway)
    labels = [a["label"] for a in discovery["api_analysis"]]
    assert f"GET {BASE}/api/item2" not in labels and len(labels) == 5  # item2's construct fell back: no tests, no result
    assert all(w["event"] != "api_analysis_failed" for w in discovery["warnings"])  # a model failure is a fallback, not a crash


def test_a_crash_in_one_worker_is_recorded_and_the_rest_complete(monkeypatch):
    from app.dast import active

    real = active.run_target

    def flaky(tgt, steps, **kw):
        if tgt.url.endswith("item1"):
            raise ValueError("kaboom")
        return real(tgt, steps, **kw)

    monkeypatch.setattr(active, "run_target", flaky)
    discovery, *_ = run(3)
    assert len(discovery["api_analysis"]) == 5
    assert [w["details"] for w in discovery["warnings"] if w["event"] == "api_analysis_failed"] == [f"GET {BASE}/api/item1: kaboom"]


def test_cancel_stops_new_endpoints_from_starting():
    gateway = SlowGateway(delay=0.2)
    cancelled = threading.Event()
    harness = Harness(target(), identities(), gateway=gateway, request={"model_parallelism": 2}, rule_set=default_rule_set(), cancel=lambda: cancelled.is_set())
    threading.Timer(0.3, cancelled.set).start()
    discovery = harness.run(run_analysis=True, should_abort=cancelled.is_set)
    assert len(discovery["api_analysis"]) < 6


def test_the_setting_reaches_the_effective_snapshot_and_is_bounded(monkeypatch):
    from app.dast.domain.presets import build_effective_settings

    def eff(**request):
        return build_effective_settings(request=request, base=settings.dast_effective_settings(), presets=settings.dast_presets,
                                        identities=identities(), rule_set={}, model_routing=settings.dast_model_routing, oast_configured=False)

    assert eff()["model_parallelism"] == 1 and eff(model_parallelism=4)["model_parallelism"] == 4
    monkeypatch.setattr(settings, "dast_model_parallelism", 3)
    assert eff()["model_parallelism"] == 3 and eff(model_parallelism=2)["model_parallelism"] == 2
    from app.schemas import DastInput

    with pytest.raises(ValueError):
        DastInput(target_url="http://x", model_parallelism=9)


def test_log_blocks_from_parallel_tasks_never_interleave(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "scan_logs_dir", str(tmp_path))
    scan_log.reset("p1")
    barrier = threading.Barrier(4)

    def task(name):
        with scan_log.buffered_capture("p1", prefix=f"[{name}] "):
            barrier.wait()
            for n in range(5):
                print(f"line {n}")
                print("tok", end="", flush=True)  # a streamed partial line
                time.sleep(0.005)
            print()

    threads = [threading.Thread(target=task, args=(f"t{i}",)) for i in range(4)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    lines = [row["line"] for row in scan_log.get_logs("p1", 0)[0]]
    assert len(lines) == 4 * 6  # 5 lines, where each streamed partial joins the next line, plus the last
    owners = [l.split("]")[0] for l in lines]
    runs = [o for i, o in enumerate(owners) if i == 0 or owners[i - 1] != o]
    assert sorted(runs) == ["[t0", "[t1", "[t2", "[t3"]  # each task's lines form exactly one run


def test_buffered_capture_restores_the_previous_capture():
    with scan_log.capture("outer"):
        with scan_log.buffered_capture("outer", prefix="[x] "):
            print("inside")
        print("after")
    lines = [row["line"] for row in scan_log.get_logs("outer", 0)[0]]
    assert lines == ["[x] inside", "after"]
