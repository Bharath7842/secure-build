"""The credential holder (DAST-06-010): memory-only secrets for one scan.

Implements the domain `CredentialHolder` contract. What it guarantees:

* **Registered before stored.** `store` hands every secret value (and its URL-/base64-/JSON-
  encoded spellings, plus base64 of `user:password`) to the log redactor *before* the value is
  kept, so no log line written afterwards can contain one.
* **Never persisted.** The holder has no persistence path: nothing here is written to the
  database, `metadata_json`, the narration cache or an export. A process restart empties it, and
  the scan then fails with "credentials lost" (DAST-06-050) instead of running unauthenticated.
* **Cleared at the end.** `clear` runs on success, failure and cancel; it drops the values and
  the redactor registration. After `clear` the holder is closed and refuses new secrets.
* **Tokens and cookies are secrets**, not only passwords: every value in a stored mapping is
  treated as one, except fields explicitly listed as non-secret (`NON_SECRET_FIELDS`).

`secrets()` is the live list of values to mask, passed to anything that formats text from scan
activity (the guarded executor's audit rows, error messages, engine output).
"""

from __future__ import annotations

import threading
from typing import Callable, Iterable, Mapping

from app.dast.domain.auth import storage_state_secrets
from app.dast.domain.entities import Identity
from app.dast.domain.redaction import secret_variants
from app.services import scan_log

# Fields whose values describe a credential without being one; they stay readable in logs.
NON_SECRET_FIELDS = frozenset({"username", "header_name", "scheme", "login_url"})


class CredentialHolderClosed(RuntimeError):
    """`store` was called after `clear`."""


class InMemoryCredentialHolder:
    def __init__(self, scan_id: str, *, register: Callable[[str, list[str]], None] | None = None) -> None:
        self.scan_id = scan_id
        self._register = register or scan_log.register_secrets
        self._lock = threading.Lock()
        self._values: dict[str, dict[str, str]] = {}
        self._masked: list[str] = []
        self._closed = False

    # ---- CredentialHolder contract ------------------------------------------------------------

    def store(self, identity: Identity, secret: Mapping[str, str]) -> None:
        """Keep `secret` for `identity`. Registers redaction first."""
        # Empty values are kept: an empty `scheme` means "send the token bare", which is not the default.
        cleaned = {k: str(v) for k, v in secret.items() if v is not None}
        with self._lock:
            if self._closed:
                raise CredentialHolderClosed("credentials were cleared; this scan can no longer take new ones")
            partner = cleaned.get("username")
            additions: list[str] = []
            for field, value in cleaned.items():
                if field in NON_SECRET_FIELDS:
                    continue
                additions.extend(secret_variants(value, partner=partner))
                if field == "storage_state":  # the cookies and tokens inside a saved session
                    for inner in storage_state_secrets(value):
                        additions.extend(secret_variants(inner))
            masked = list(dict.fromkeys([*self._masked, *additions]))
            self._register(self.scan_id, masked)  # before the value is held
            self._masked = masked
            self._values[identity.identity_id] = cleaned

    def read(self, identity_id: str) -> Mapping[str, str] | None:
        with self._lock:
            value = self._values.get(identity_id)
            return dict(value) if value is not None else None

    def clear(self) -> None:
        """Drop every value and the redaction registration. Idempotent."""
        with self._lock:
            self._values.clear()
            self._masked = []
            self._closed = True
            self._register(self.scan_id, [])

    # ---- helpers ------------------------------------------------------------------------------

    def secrets(self) -> list[str]:
        """Every spelling currently being masked (for audit/error redaction callbacks)."""
        with self._lock:
            return list(self._masked)

    def identity_ids(self) -> list[str]:
        with self._lock:
            return list(self._values)

    def is_empty(self) -> bool:
        with self._lock:
            return not self._values

    def __repr__(self) -> str:  # never show values, even in a debugger or a stray log line
        return f"<InMemoryCredentialHolder scan={self.scan_id} identities={len(self._values)} closed={self._closed}>"

    def __reduce__(self):  # pragma: no cover - guards against pickling secrets into a cache
        raise TypeError("a credential holder cannot be serialized")


def holder_secrets(holder: InMemoryCredentialHolder | None) -> Callable[[], Iterable[str]]:
    return holder.secrets if holder is not None else (lambda: ())
