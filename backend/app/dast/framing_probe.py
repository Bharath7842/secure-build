"""One raw HTTP/1.1 connection for the framing check.

Not sent through the guarded executor: httpx normalises Content-Length and
Transfer-Encoding, so the ambiguity would never reach the server. The bytes are
built by `domain.framing.conflicting_request` and address only the host the
caller passes (the scan target). One connection, a short timeout, then close.
"""

from __future__ import annotations

import socket
import ssl

PROBE_TIMEOUT_S = 5.0


def probe_framing(host: str, port: int, payload: bytes, *, tls: bool, timeout: float = PROBE_TIMEOUT_S) -> bytes:
    """Send `payload` and return whatever came back before the peer closed or the timeout."""
    sock = socket.create_connection((host, port), timeout=timeout)
    try:
        if tls:
            context = ssl.create_default_context()
            sock = context.wrap_socket(sock, server_hostname=host)
        sock.settimeout(timeout)
        sock.sendall(payload)
        chunks = []
        while True:
            try:
                block = sock.recv(4096)
            except TimeoutError:
                break
            if not block:
                break
            chunks.append(block)
            if sum(len(c) for c in chunks) > 8192:
                break
        return b"".join(chunks)
    finally:
        try:
            sock.close()
        except Exception:  # noqa: BLE001
            pass
