"""LLM02 guardrails: secret values never reach the model, stored findings or logs."""

import sys
import time
from pathlib import Path

import pytest

_ENGINE = Path(__file__).resolve().parents[1] / "sast_engine"
if str(_ENGINE) not in sys.path:
    sys.path.insert(0, str(_ENGINE))

import secret_mask  # noqa: E402

pytestmark = pytest.mark.unit

AWS = "AKIAIOSFODNN7EXAMPLE"
GH = "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"
JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk"


@pytest.mark.parametrize("secret", [
    AWS, GH, JWT, "sk_live_" + "x" * 24, "AIza" + "A" * 35, "xoxb-1234567890-abcdefghij",
])
def test_known_key_shapes_are_masked(secret):
    masked, n = secret_mask.mask_text(f'String k = "{secret}"; // use it')
    assert secret not in masked and n >= 1
    assert "«REDACTED:len=" in masked


@pytest.mark.parametrize("line, secret", [
    ('String password = "Sup3rS3cret!";', "Sup3rS3cret!"),
    ('private static final String ADMIN_PASSWORD = "hunter2hunter2";', "hunter2hunter2"),
    ('{"api_key": "abcd1234efgh5678"}', "abcd1234efgh5678"),
    ("const clientSecret = 'zzzz-yyyy-xxxx';", "zzzz-yyyy-xxxx"),
    ("spring.datasource.password=admin123", "admin123"),
    ("db_password: p@ssw0rd!", "p@ssw0rd!"),
    ("jdbc:postgresql://svc:S3cr3tPw@db:5432/app", "S3cr3tPw"),
    ("Authorization: Bearer abcdefghijklmnopqrstuvwxyz0123", "abcdefghijklmnopqrstuvwxyz0123"),
])
def test_credential_assignments_are_masked_and_the_name_is_kept(line, secret):
    masked = secret_mask.mask(line)
    assert secret not in masked
    assert "«REDACTED:len=" in masked
    assert masked.split("«")[0].strip()  # the key / surrounding code is still there


def test_the_literal_is_replaced_but_quotes_and_name_stay():
    assert secret_mask.mask('String password = "Sup3rS3cret!";') == \
        'String password = "«REDACTED:len=12»";'


@pytest.mark.parametrize("line", [
    'String sql = "select * from users where id = " + id;',
    "password: string;",
    "String password = request.getParameter(\"p\");",
    "self.password = password_hash",
    'String TOKEN_HEADER = "Authorization";',
    'String PASSWORD_PARAM = "password";',
    'String message = "Invalid password supplied";',
    'password = "${DB_PASSWORD}"',
    "spring.datasource.password=${DB_PASSWORD}",
    'token = "****"',
    "int tokenCount = 12345;",
    "log.info(\"token refreshed\");",
])
def test_code_that_is_not_a_secret_is_left_alone(line):
    assert secret_mask.mask(line) == line


def test_masking_is_idempotent():
    once = secret_mask.mask('password = "Sup3rS3cret!"\nkey=' + AWS)
    assert secret_mask.mask(once) == once


def test_line_count_is_preserved_including_a_private_key_block():
    text = (
        "10: String a = 1;\n"
        "11: -----BEGIN RSA PRIVATE KEY-----\n"
        "12: MIIEowIBAAKCAQEAxxxxxxxxxxxxxxxxxxxxxxxx\n"
        "13: yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy\n"
        "14: -----END RSA PRIVATE KEY-----\n"
        "15: String b = 2;\n"
    )
    masked, n = secret_mask.mask_text(text)
    assert masked.count("\n") == text.count("\n")
    assert "MIIEow" not in masked and "yyyyyy" not in masked
    assert n == 2
    assert [line.split(":")[0] for line in masked.splitlines()] == [str(i) for i in range(10, 16)]


def test_mask_value_walks_nested_structures_without_mutating_the_input():
    original = {"snippet": 'password = "Sup3rS3cret!"', "hops": [{"body": f"k={AWS}"}], "n": 3}
    masked = secret_mask.mask_value(original)
    assert "Sup3rS3cret" not in str(masked) and AWS not in str(masked)
    assert masked["n"] == 3
    assert "Sup3rS3cret" in original["snippet"]


@pytest.mark.parametrize("text", [
    "a" * 50_000, "password" + "-x" * 20_000, "http://" * 8_000, "=:" * 20_000, 'password="' * 5_000,
])
def test_a_pathological_input_is_fast(text):
    started = time.perf_counter()
    secret_mask.mask(text)
    assert time.perf_counter() - started < 2.0


def test_empty_and_non_string_input_never_raises():
    assert secret_mask.mask("") == ""
    assert secret_mask.mask(None) is None


# --- the prompt boundary (call_llm) -----------------------------------------------

SECRET_LINE = 'private static final String ADMIN_PASSWORD = "Sup3rS3cret!";'


@pytest.fixture()
def llm(monkeypatch):
    pytest.importorskip("boto3", reason="llm_client requires boto3")
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "test")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "test")
    import llm_client as module

    return module


class _Cache:
    def __init__(self):
        self.store, self.keys = {}, []

    def get(self, key):
        self.keys.append(key)
        return self.store.get(key)

    def put(self, key, *, step, model, text, input_tokens=0, output_tokens=0):
        self.store[key] = {"text": text, "input_tokens": input_tokens, "output_tokens": output_tokens}


def _capture(llm, monkeypatch, reply='{"findings": []}'):
    seen = []

    def fake_ollama(*a, **kw):
        seen.append((a[0], a[1]))
        return reply

    monkeypatch.setattr(llm, "_call_ollama", fake_ollama)
    return seen


def test_call_llm_masks_both_prompts_before_the_provider_sees_them(llm, monkeypatch):
    seen = _capture(llm, monkeypatch)
    usage = llm.init_usage("ollama", "m")
    llm.call_llm(f"rules {AWS}", f"Code:\n{SECRET_LINE}", usage=usage, step="t", provider="ollama", model="m")
    system, user = seen[0]
    assert AWS not in system and "Sup3rS3cret" not in user
    assert "ADMIN_PASSWORD" in user and "«REDACTED:len=12»" in user
    assert usage["_counters"]["secret_masking"] == {"values_masked": 2, "calls_with_secrets": 1}


def test_masking_happens_before_the_result_cache_key_is_computed(llm, monkeypatch):
    seen = _capture(llm, monkeypatch)
    usage = llm.init_usage("ollama", "m")
    usage[llm.RESULT_CACHE_USAGE_KEY] = _Cache()
    kwargs = dict(usage=usage, step="t", provider="ollama", model="m", json_mode=True)
    llm.call_llm("sys", 'password = "Sup3rS3cret!"', **kwargs)
    llm.call_llm("sys", 'password = "An0therSecr3"', **kwargs)  # same length, different value
    assert len(seen) == 1  # the second prompt is identical once masked: a cache hit
    cache = usage[llm.RESULT_CACHE_USAGE_KEY]
    assert len(set(cache.keys)) == 1
    assert all("Sup3rS3cret" not in value["text"] for value in cache.store.values())


def test_a_scan_can_opt_out_of_masking(llm, monkeypatch):
    seen = _capture(llm, monkeypatch)
    usage = llm.init_usage("ollama", "m", mask_secrets=False)
    llm.call_llm("sys", SECRET_LINE, usage=usage, step="t", provider="ollama", model="m")
    assert "Sup3rS3cret" in seen[0][1]
    assert "secret_masking" not in usage.get("_counters", {})


def test_a_call_without_a_usage_dict_is_masked(llm, monkeypatch):
    seen = _capture(llm, monkeypatch)
    llm.call_llm("sys", SECRET_LINE, step="t", provider="ollama", model="m")
    assert "Sup3rS3cret" not in seen[0][1]


def test_a_prompt_without_secrets_is_unchanged_and_not_counted(llm, monkeypatch):
    seen = _capture(llm, monkeypatch)
    usage = llm.init_usage("ollama", "m")
    llm.call_llm("sys", "String sql = a + b;", usage=usage, step="t", provider="ollama", model="m")
    assert seen[0] == ("sys", "String sql = a + b;")
    assert "secret_masking" not in usage.get("_counters", {})


def test_reanchor_finds_the_line_from_a_snippet_the_model_saw_masked(llm):
    pytest.importorskip("tree_sitter")
    from pipeline import llm_file_scan as lfs

    source = ["class A {", "  int x;", f"  {SECRET_LINE}", "}"]
    masked_snippet = secret_mask.mask(SECRET_LINE)
    assert lfs.reanchor_line(source, 2, masked_snippet, 1, 4) == 3  # reported line 2 is wrong


# --- what the app stores, logs and exports --------------------------------------------

def test_stored_columns_are_masked_but_the_occurrence_id_is_not_affected():
    from app.services.finding_rows import build_finding_row

    finding = {
        "rule_id": "secret-password-assign", "cwe": "CWE-798", "line": 3, "kind": "regex",
        "snippet": f"3: {SECRET_LINE}", "matched_text": SECRET_LINE, "sink": SECRET_LINE,
        "verdict_reason": f"The key {AWS} is committed",
        "facts": {"call": {"text": SECRET_LINE}}, "flow_path": [{"body": f"k={AWS}"}],
    }
    raw = build_finding_row("s1", finding, "A.java", "p1", mask_secrets=False)
    masked = build_finding_row("s1", finding, "A.java", "p1", mask_secrets=True)
    for column in (masked.snippet, masked.matched_text, masked.sink, masked.verdict_reason,
                   str(masked.facts), str(masked.flow_path)):
        assert "Sup3rS3cret" not in column and AWS not in column
    assert "Sup3rS3cret" in raw.snippet
    assert masked.occurrence_id == raw.occurrence_id
    assert finding["snippet"].endswith('"Sup3rS3cret!";')  # the input dict is untouched


def test_the_scan_log_masks_a_line_that_echoes_a_credential(tmp_path, monkeypatch):
    from app.config import settings
    from app.services import scan_log

    monkeypatch.setattr(settings, "scan_logs_dir", str(tmp_path))
    scan_log._append("scan-x", f"  matched: {SECRET_LINE} and key {AWS}")
    (line,) = [text for _seq, text in scan_log._buffers["scan-x"]]
    assert "Sup3rS3cret" not in line and AWS not in line
    assert "Sup3rS3cret" not in (tmp_path / "scan-x.log").read_text(encoding="utf-8")


def test_export_code_is_masked_for_a_scan_stored_before_masking():
    from types import SimpleNamespace

    from app.services import scan_export

    legacy = SimpleNamespace(snippet=f"3: {SECRET_LINE}")
    assert "Sup3rS3cret" not in scan_export._location_code(legacy)


def test_the_limitation_is_on_by_default_and_switchable_per_project():
    from types import SimpleNamespace

    from app.services import agent_bridge, secret_masking

    assert secret_masking.mask_enabled(None) is True
    assert secret_masking.mask_enabled(SimpleNamespace(limitations_config={"secret-masking": False})) is False
    on = agent_bridge.llm_usage_options(SimpleNamespace(limitations_config=None))
    off = agent_bridge.llm_usage_options(SimpleNamespace(limitations_config={"secret-masking": False}))
    assert on["mask_secrets"] is True and off["mask_secrets"] is False
