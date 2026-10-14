"""Hunt safety primitives: atomic budget reservations and secret redaction."""

import sys
import threading
from pathlib import Path

import pytest

pytest.importorskip("boto3", reason="llm_client requires boto3")

_ENGINE_DIR = Path(__file__).resolve().parents[1] / "sast_engine"
if str(_ENGINE_DIR) not in sys.path:
    sys.path.insert(0, str(_ENGINE_DIR))

from pipeline.hunt.budget import BudgetLimits, HuntBudget  # noqa: E402
from pipeline.hunt.redact import REDACTED, redact, redact_text, redaction_aware_equal  # noqa: E402


# --- budget ---------------------------------------------------------------


def _priced_budget(**limits):
    # Bedrock Haiku pricing: $1/MTok in, $5/MTok out.
    return HuntBudget(BudgetLimits(**{
        "max_usd": None, "max_tokens": None, "max_wall_seconds": None,
        "max_llm_calls": None, "max_rg_calls": None, **limits,
    }), provider="bedrock", model="us.anthropic.claude-haiku-4-5")


def test_concurrent_reservations_never_exceed_usd_ceiling():
    # Each call reserves ~4000 prompt tokens + 1000 output = $0.009 worst case,
    # so exactly 11 fit under $0.10 no matter how 50 threads interleave.
    budget = _priced_budget(max_usd=0.10)
    prompt = "x" * 16_000
    granted = []
    lock = threading.Lock()
    start = threading.Barrier(50)

    def worker():
        start.wait()
        reservation = budget.reserve_llm(prompt, 1000)
        if reservation is not None:
            with lock:
                granted.append(reservation)

    threads = [threading.Thread(target=worker) for _ in range(50)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(granted) == 11
    assert budget.reserved_usd <= 0.10 + 1e-9
    assert budget.exhausted_reason == "usd"


def test_settle_frees_unused_headroom_for_later_calls():
    budget = _priced_budget(max_usd=0.02)
    prompt = "x" * 16_000  # worst case $0.009 per call at max_tokens=1000
    first = budget.reserve_llm(prompt, 1000)
    second = budget.reserve_llm(prompt, 1000)
    assert first and second
    assert budget.reserve_llm(prompt, 1000) is None  # 3 x 0.009 > 0.02
    # The real calls were cheap: settling returns the unused reservation.
    budget.settle(first, meta={"input_tokens": 4000, "output_tokens": 10})
    budget.settle(second, meta={"input_tokens": 4000, "output_tokens": 10})
    assert budget.reserve_llm(prompt, 1000) is not None
    assert budget.spent_usd == pytest.approx(2 * (4000 / 1e6 * 1.0 + 10 / 1e6 * 5.0))


def test_release_returns_reservation_and_settle_is_idempotent():
    budget = _priced_budget(max_usd=1.0)
    r = budget.reserve_llm("prompt", 100)
    budget.release(r)
    budget.settle(r, meta={"input_tokens": 999_999, "output_tokens": 999_999})
    assert budget.reserved_usd == pytest.approx(0.0)
    assert budget.spent_usd == 0.0


def test_settle_without_meta_estimates_from_text():
    budget = _priced_budget()
    r = budget.reserve_llm("p" * 400, 50)
    budget.settle(r, prompt_text="p" * 400, response_text="r" * 40)
    assert budget.spent_tokens == 100 + 10


def test_call_token_and_rg_ceilings():
    budget = _priced_budget(max_llm_calls=2, max_tokens=10_000, max_rg_calls=1)
    assert budget.reserve_llm("a", 10) and budget.reserve_llm("a", 10)
    assert budget.reserve_llm("a", 10) is None
    assert budget.exhausted_reason == "llm_calls"
    assert budget.reserve_rg() is True
    assert budget.reserve_rg() is False
    assert budget.snapshot()["refusals"] == {"llm_calls": 1, "rg_calls": 1}

    tokens = _priced_budget(max_tokens=1_000)
    assert tokens.reserve_llm("a", 2_000) is None
    assert tokens.exhausted_reason == "tokens"


def test_wall_clock_ceiling():
    now = [0.0]
    budget = HuntBudget(BudgetLimits(max_wall_seconds=10.0), clock=lambda: now[0])
    assert budget.reserve_rg()
    now[0] = 10.0
    assert budget.reserve_rg() is False
    assert budget.reserve_llm("a", 1) is None
    assert budget.exhausted_reason == "wall_clock"


def test_limits_default_to_share_of_remaining_cutoff():
    limits = BudgetLimits.for_scan({"cost_cutoff_usd": 2.0, "cost_usd": 1.0})
    assert limits.max_usd == pytest.approx(0.30)
    assert BudgetLimits.for_scan({"cost_cutoff_usd": None}).max_usd is None
    assert BudgetLimits.for_scan({"cost_cutoff_usd": 2.0}, max_usd=0.05).max_usd == 0.05


# --- redaction ------------------------------------------------------------


@pytest.mark.parametrize("line,kept", [
    ('String password = "hunter2-prod";', 'String password = "'),
    ('dbPassword: "s3cr3t!"', "dbPassword:"),
    ('props.getProperty("db.password", "Admin123")', 'props.getProperty("db.password", "'),
    ("spring.datasource.password=SuperSecret99", "spring.datasource.password="),
    ('conn.setRequestProperty("Authorization", "Bearer abcdefghijklmnop1234");', "Bearer "),
    ('Key k = new SecretKeySpec("0123456789abcdef".getBytes(), "AES");', "new SecretKeySpec("),
])
def test_redacts_secret_values_but_keeps_the_construct(line, kept):
    out, count = redact_text(line)
    assert count == 1
    assert REDACTED in out
    assert kept in out


def test_redacts_shaped_tokens_and_pem_blocks():
    text = (
        "aws = AKIAIOSFODNN7EXAMPLE\n"
        "jwt = eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U\n"
        "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END RSA PRIVATE KEY-----\n"
    )
    out, count = redact_text(text)
    assert count == 3
    assert "AKIAIOSFODNN7EXAMPLE" not in out
    assert "eyJhbGci" not in out
    assert "MIIEowIBAAKCAQEA" not in out


def test_redacts_high_entropy_literal_but_not_identifiers():
    assert REDACTED in redact('String k = "q8Zr2LmX9vB4nT7wYc1KdE5sHu3J";')
    assert redact('String cls = "com_example_service_impl_factory";') == (
        'String cls = "com_example_service_impl_factory";'
    )


def test_placeholders_and_lookups_are_not_redacted():
    for line in (
        "spring.datasource.password=${DB_PASSWORD}",
        'password: "${env.DB_PASSWORD}"',
        'String password = request.getParameter("password");',
    ):
        assert redact(line) == line


def test_redaction_aware_grounding():
    original = 'String password = "hunter2-prod";'
    assert redaction_aware_equal(redact(original), original)
    assert redaction_aware_equal("  String   password = \"hunter2-prod\";", original)
    assert not redaction_aware_equal('String password = "other";', original)
    assert not redaction_aware_equal("", original)


def test_redaction_never_changes_line_numbers():
    text = (
        "class K {\n"
        '  String pem = "-----BEGIN RSA PRIVATE KEY-----\n'
        "MIIEowIBAAKCAQEA\n"
        "abcdEFGH\n"
        '-----END RSA PRIVATE KEY-----";\n'
        '  String password = "hunter2-prod";\n'
        "}\n"
    )
    out = redact(text)
    assert out.count("\n") == text.count("\n")
    assert out.splitlines()[5].strip().startswith("String password")
