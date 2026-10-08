"""DAST-01-020: rate limit, concurrency cap and cancellation (fake clock, real threads)."""

from __future__ import annotations

import threading
import time

import pytest

from app.config import Settings
from app.dast.domain.policy import CANCELLED, METHOD_NOT_PERMITTED, OFF_SCOPE, MethodPolicy, Scope
from app.services.safety_guard import RateLimiter, SafetyGuard, registrable_domain

pytestmark = pytest.mark.unit

URL = "http://target.test/page"


class FakeClock:
    """A clock whose `sleep` advances it, so rate tests take no wall time."""

    def __init__(self) -> None:
        self.now = 1000.0
        self.sleeps: list[float] = []
        self._lock = threading.Lock()
        self.on_sleep = None

    def __call__(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        with self._lock:
            self.sleeps.append(seconds)
            self.now += seconds
        if self.on_sleep:
            self.on_sleep()


def make_guard(*, rate=10.0, concurrent=4, clock=None, cancelled=lambda: False, policy=None) -> SafetyGuard:
    clock = clock or FakeClock()
    return SafetyGuard(
        Scope.for_target("http://target.test"),
        policy or MethodPolicy(),
        rate_limit_per_sec=rate,
        max_concurrent=concurrent,
        is_cancelled=cancelled,
        clock=clock,
        sleep=clock.sleep,
    )


# ---- rate limit -----------------------------------------------------------------------------


def test_n_requests_at_rate_r_take_at_least_the_expected_time():
    clock = FakeClock()
    guard = make_guard(rate=4.0, clock=clock)
    start = clock.now
    for _ in range(9):
        with guard.admit("GET", URL) as decision:
            assert decision.allowed
    # 9 requests at 4/s: the 9th may not start before 8 * 0.25s.
    assert clock.now - start >= 2.0 - 1e-9
    assert clock.now - start < 2.0 + 0.25  # and it does not over-wait


def test_idle_time_does_not_bank_a_burst():
    clock = FakeClock()
    limiter = RateLimiter(2.0, clock=clock, sleep=clock.sleep)
    limiter.acquire()
    clock.now += 60  # long idle
    assert limiter.acquire() == 0
    waited = limiter.acquire()
    assert waited == pytest.approx(0.5)  # back-to-back requests are still spaced


def test_rate_must_be_positive():
    with pytest.raises(ValueError):
        RateLimiter(0)
    with pytest.raises(ValueError):
        make_guard(rate=-1)


def test_a_slow_rate_spaces_a_real_wall_clock_run():
    guard = SafetyGuard(
        Scope.for_target("http://target.test"), MethodPolicy(), rate_limit_per_sec=50.0, max_concurrent=2
    )
    started = time.monotonic()
    for _ in range(6):
        with guard.admit("GET", URL):
            pass
    assert time.monotonic() - started >= 5 / 50.0 - 0.002


# ---- concurrency ----------------------------------------------------------------------------


def test_concurrency_never_exceeds_the_cap_under_parallel_callers():
    guard = SafetyGuard(
        Scope.for_target("http://target.test"), MethodPolicy(), rate_limit_per_sec=100_000.0, max_concurrent=3
    )
    lock = threading.Lock()
    current = peak = 0
    done = 0

    def worker() -> None:
        nonlocal current, peak, done
        with guard.admit("GET", URL) as decision:
            assert decision.allowed
            with lock:
                current += 1
                peak = max(peak, current)
            time.sleep(0.01)
            with lock:
                current -= 1
                done += 1

    threads = [threading.Thread(target=worker) for _ in range(24)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=20)
    assert done == 24
    assert 1 < peak <= 3  # actually concurrent, and never above the cap


def test_a_slot_is_released_when_the_caller_raises():
    guard = make_guard(concurrent=1)
    with pytest.raises(RuntimeError):
        with guard.admit("GET", URL):
            raise RuntimeError("send failed")
    with guard.admit("GET", URL) as decision:  # would deadlock if the slot leaked
        assert decision.allowed


def test_denied_requests_take_neither_a_slot_nor_a_token():
    clock = FakeClock()
    guard = make_guard(rate=1.0, concurrent=1, clock=clock)
    for _ in range(5):
        with guard.admit("GET", "http://evil.test/") as decision:
            assert decision.reason == OFF_SCOPE
    assert clock.sleeps == []
    with guard.admit("GET", URL) as decision:
        assert decision.allowed


# ---- cancellation ---------------------------------------------------------------------------


def test_request_issued_after_cancel_is_denied():
    state = {"cancelled": False}
    guard = make_guard(cancelled=lambda: state["cancelled"])
    assert guard.decide("GET", URL).allowed
    state["cancelled"] = True
    decision = guard.decide("GET", URL)
    assert not decision.allowed and decision.reason == CANCELLED
    with guard.admit("GET", URL) as admitted:
        assert admitted.reason == CANCELLED


def test_cancel_is_checked_again_after_waiting_for_a_token():
    clock = FakeClock()
    state = {"cancelled": False}
    guard = make_guard(rate=1.0, clock=clock, cancelled=lambda: state["cancelled"])
    clock.on_sleep = lambda: state.update(cancelled=True)  # cancel arrives while a caller is queued
    with guard.admit("GET", URL) as first:
        assert first.allowed  # no wait for the first token
    with guard.admit("GET", URL) as second:  # has to wait ~1s, during which the scan is cancelled
        assert not second.allowed and second.reason == CANCELLED


def test_cancel_is_reported_before_scope_or_method():
    guard = make_guard(cancelled=lambda: True)
    assert guard.decide("POST", "http://evil.test/").reason == CANCELLED


def test_an_unreadable_cancel_flag_counts_as_cancelled():
    def broken() -> bool:
        raise RuntimeError("db down")

    assert make_guard(cancelled=broken).decide("GET", URL).reason == CANCELLED


def test_guard_applies_the_domain_policy():
    guard = make_guard()
    assert guard.decide("POST", URL).reason == METHOD_NOT_PERMITTED
    assert guard.decide("GET", "http://other.test/").reason == OFF_SCOPE
    assert guard.decide_redirect(URL, "http://other.test/x", "GET").reason == OFF_SCOPE
    assert guard.decide_redirect(URL, "/x", "GET").allowed


# ---- per scan, not process-global -----------------------------------------------------------


def test_two_scans_do_not_share_budgets():
    clock = FakeClock()
    a = make_guard(rate=1.0, concurrent=1, clock=clock)
    b = make_guard(rate=1.0, concurrent=1, clock=clock)
    with a.admit("GET", URL):  # a's only slot is held ...
        with b.admit("GET", URL) as decision:  # ... b still gets its own, with no wait
            assert decision.allowed
    assert clock.sleeps == []
    with a.admit("GET", URL):
        pass
    assert clock.sleeps == [pytest.approx(1.0)]  # only a's second request waited on a's budget


def test_state_is_not_module_global():
    # Cancelling one scan's guard leaves another untouched.
    flags = {"a": False, "b": False}
    a = make_guard(cancelled=lambda: flags["a"])
    b = make_guard(cancelled=lambda: flags["b"])
    flags["a"] = True
    assert a.decide("GET", URL).reason == CANCELLED
    assert b.decide("GET", URL).allowed


# ---- built from the scan's effective settings -----------------------------------------------


def test_guard_reads_limits_from_the_effective_settings_snapshot():
    snapshot = Settings(
        dast_rate_limit_per_sec=2.5,
        dast_max_concurrent_requests=7,
        dast_same_domain_mode="root-domain",
        dast_safe_mode_default=True,
    ).dast_effective_settings()
    assert snapshot["rate_limit_per_sec"] == 2.5 and snapshot["max_concurrent_requests"] == 7

    guard = SafetyGuard.from_settings("http://app.target.com:8080/login", snapshot)
    assert guard.scope.mode == "root-domain"
    assert guard.decide("GET", "http://api.target.com/").allowed  # sibling allowed in root-domain mode
    assert guard.decide("GET", "http://target.com.evil.com/").reason == OFF_SCOPE
    assert guard.decide("POST", "http://app.target.com/").reason == METHOD_NOT_PERMITTED


def test_non_disposable_target_ignores_a_request_to_turn_safe_mode_off():
    snapshot = {"rate_limit_per_sec": 5.0, "safe_mode": False, "same_domain_mode": "exact"}
    locked = SafetyGuard.from_settings("http://target.test", snapshot, allow_state_changing=True)
    assert locked.decide("POST", URL).reason == METHOD_NOT_PERMITTED
    open_ = SafetyGuard.from_settings("http://target.test", snapshot, target_disposable=True)
    assert open_.decide("POST", URL).allowed


def test_default_settings_expose_concurrency_and_body_limits():
    snapshot = Settings().dast_effective_settings()
    assert snapshot["max_concurrent_requests"] >= 1
    assert snapshot["max_response_body_bytes"] >= 1
    with pytest.raises(ValueError):
        Settings(dast_max_concurrent_requests=0)


def test_registrable_domain():
    assert registrable_domain("app.company.co.uk") == "company.co.uk"
    assert registrable_domain("a.b.target.com") == "target.com"
    # No registrable domain: root-domain mode falls back to exact matching for these.
    for host in ("localhost", "127.0.0.1", "co.uk", "app.target.test", "intranet.corp"):
        assert registrable_domain(host) == ""
