"""Out-of-band confirmation (DAST-09-060): the collaborator contract and unique callback tokens.

SSRF is the one check whose proof arrives somewhere other than the response: the target is made to
call an address the scanner controls. A received callback is unambiguous (nothing else knows the
unique address), so it is a proving signal (`oast_callback_received`) on its own.

The service behind the interface (self-hosted or managed) is an open decision recorded in the
requirements; v1 ships one HTTP implementation (`app/services/oast.py`). The domain only fixes what
a collaborator must do: hand out an address that is unique to one test, and report which tokens it
has seen called.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Protocol, Sequence, runtime_checkable

SIGNAL = "oast_callback_received"
TOKEN_CHARS = 20


@dataclass(frozen=True)
class OastToken:
    token: str  # unique to one test; the only thing that can confirm it
    url: str  # the callback address to place in the test input
    test_key: str  # what the token was issued for (target, parameter)


@dataclass(frozen=True)
class OastCallback:
    token: str
    source: str = ""  # who called (an address), when the service says
    at: str = ""


@runtime_checkable
class OastCollaborator(Protocol):
    def new_token(self, test_key: str) -> OastToken:
        """A fresh callback address for one test. Two calls never return the same token."""

    def poll(self, token: OastToken, *, wait_s: float, interval_s: float = 1.0) -> Sequence[OastCallback]:
        """Callbacks received for exactly this token, waiting at most `wait_s` seconds in total."""


def make_token(scan_id: str, test_key: str, counter: int, nonce: str) -> str:
    """A token that is unique per (scan, test, counter) and unguessable without `nonce` (a secret
    random value held for the scan). Pure: the caller supplies the randomness."""
    digest = hashlib.sha256(f"{nonce}|{scan_id}|{test_key}|{counter}".encode()).hexdigest()
    return digest[:TOKEN_CHARS]


def confirms(token: OastToken, callbacks: Sequence[OastCallback]) -> list[OastCallback]:
    """Only a callback carrying this very token confirms this test (never another test's)."""
    return [c for c in callbacks if c.token == token.token]
