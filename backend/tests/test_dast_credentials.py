"""DAST-06-010: credential holder and redaction."""

from __future__ import annotations

import base64
import json
import pickle
from urllib.parse import quote

import pytest

from app.dast.domain.entities import Identity, Role, RoleName
from app.dast.domain.redaction import redact_json, redact_text, secret_variants
from app.services import scan_log
from app.services.credential_holder import CredentialHolderClosed, InMemoryCredentialHolder

pytestmark = pytest.mark.unit


def identity(label="alice"):
    return Identity(identity_id=f"id-{label}", label=label, role=Role(RoleName.USER))


def test_variants_cover_the_encodings_a_secret_can_appear_in():
    secret = "p@ss w/rd&1"
    variants = secret_variants(secret, partner="alice")
    assert secret in variants
    assert quote(secret, safe="") in variants and "p%40ss+w%2Frd%261" in variants
    # base64 is registered without padding, so the padded and unpadded spellings are both masked
    assert base64.b64encode(secret.encode()).decode().rstrip("=") in variants
    assert base64.b64encode(b"alice:" + secret.encode()).decode().rstrip("=") in variants  # HTTP Basic auth
    assert json.dumps('a"b\\c-longer')[1:-1] in secret_variants('a"b\\c-longer')
    assert variants == sorted(variants, key=len, reverse=True)  # longest first
    assert secret_variants("") == [] and secret_variants("pw") == ["pw"]  # short secrets: exact only


def test_store_registers_redaction_before_holding_the_value():
    order: list[str] = []
    holder = InMemoryCredentialHolder("s1", register=lambda sid, values: order.append(f"register:{len(values)}"))
    real_values = holder._values

    class Spy(dict):
        def __setitem__(self, k, v):
            order.append("held")
            super().__setitem__(k, v)

    holder._values = Spy(real_values)
    holder.store(identity(), {"username": "alice", "password": "hunter2hunter2"})
    assert order[0].startswith("register:") and order[-1] == "held"


def test_read_returns_a_copy_and_only_for_stored_identities():
    holder = InMemoryCredentialHolder("s2", register=lambda *_: None)
    holder.store(identity(), {"username": "alice", "password": "pw-value-123"})
    got = holder.read("id-alice")
    got["password"] = "tampered"
    assert holder.read("id-alice")["password"] == "pw-value-123"
    assert holder.read("id-nobody") is None and holder.identity_ids() == ["id-alice"]


def test_every_secret_field_is_masked_but_usernames_are_not():
    holder = InMemoryCredentialHolder("s3", register=lambda *_: None)
    holder.store(identity("svc"), {"token": "tok-abcdef123456", "username": "svc-account", "scheme": "Bearer", "header_name": "Authorization"})
    holder.store(identity("web"), {"cookie": "session=abcdefabcdef"})
    masked = holder.secrets()
    assert "tok-abcdef123456" in masked and "session=abcdefabcdef" in masked
    assert "svc-account" not in masked and "Bearer" not in masked and "Authorization" not in masked


def test_clear_drops_everything_in_every_outcome_and_closes_the_holder():
    registered: list[list[str]] = []
    holder = InMemoryCredentialHolder("s4", register=lambda sid, values: registered.append(values))
    holder.store(identity(), {"password": "pw-value-123"})
    for _ in range(2):  # idempotent: safe to call from success, failure and cancel handlers
        holder.clear()
    assert holder.is_empty() and holder.secrets() == [] and holder.read("id-alice") is None
    assert registered[-1] == []
    with pytest.raises(CredentialHolderClosed):
        holder.store(identity(), {"password": "again-again"})


def test_the_holder_cannot_be_serialized_or_printed_with_its_values():
    holder = InMemoryCredentialHolder("s5", register=lambda *_: None)
    holder.store(identity(), {"password": "hunter2hunter2"})
    with pytest.raises(TypeError):
        pickle.dumps(holder)
    assert "hunter2" not in repr(holder) and "hunter2" not in str(holder)


def test_log_lines_carry_no_registered_secret_in_any_spelling(tmp_path, monkeypatch):
    from app.config import settings

    monkeypatch.setattr(settings, "scan_logs_dir", str(tmp_path))
    scan_log.reset("s6")
    holder = InMemoryCredentialHolder("s6")
    holder.store(identity(), {"username": "alice", "password": "p@ss w/rd&1"})
    for spelling in (
        "p@ss w/rd&1", "p%40ss%20w%2Frd%261", "p%40ss+w%2Frd%261", base64.b64encode(b"alice:p@ss w/rd&1").decode(),
        json.dumps({"password": "p@ss w/rd&1"}),
    ):
        scan_log.log("s6", f"debug: {spelling}")
    lines, _ = scan_log.get_logs("s6", 0)
    text = "\n".join(entry["line"] for entry in lines)
    assert "p@ss w/rd&1" not in text and "p%40ss" not in text and "cEBzcyB3L3JkJjE" not in text
    holder.clear()
    scan_log.log("s6", "after clear: p@ss w/rd&1")  # no longer registered
    assert "p@ss w/rd&1" in scan_log.get_logs("s6", 0)[0][-1]["line"]


def test_redact_json_masks_keys_values_and_nesting():
    data = {"error": "login failed for hunter2hunter2", "nested": [{"tok": "x hunter2hunter2 y"}], "n": 3, "hunter2hunter2": 1}
    out = redact_json(data, ["hunter2hunter2"])
    assert "hunter2" not in json.dumps(out) and out["n"] == 3
    assert redact_json(data, []) is data
    assert redact_text("Authorization: Bearer abcdefghijklmnopqrstuvwxyz", []) == "Authorization: [REDACTED]"
