"""A repository's identity, independent of how its URL was spelled.

`https://GitLab.com/Group/Repo.git`, `https://gitlab.com/group/repo/`,
`git@gitlab.com:group/repo.git` and a URL with `user:token@` in front all name
one repository. `normalize_repo_key` reduces them to `gitlab.com/group/repo`, so
CI can find the project for a repo without being told its id.

Stdlib only: `app.models` imports this, so it must not import `app`.
"""

from __future__ import annotations

import re
from urllib.parse import urlparse

_SCP_LIKE = re.compile(r"^(?:[^@/\s]+@)?(?P<host>[^:/\s]+):(?!//)(?P<path>.+)$")


def normalize_repo_key(url: str | None) -> str | None:
    """`host/path` in lower case without credentials, `.git` or trailing slashes.

    Returns None for an empty value. A value that is not a URL (a local path
    used by tests) is lower-cased and stripped the same way.
    """
    raw = (url or "").strip()
    if not raw:
        return None

    host = ""
    path = ""
    if "://" in raw:
        parsed = urlparse(raw)
        host = (parsed.hostname or "").lower()
        if parsed.port:
            host = f"{host}:{parsed.port}"
        path = parsed.path or ""
    else:
        scp = _SCP_LIKE.match(raw)
        # `C:\repo` and `/tmp/repo` are paths, not `git@host:path`.
        if scp and len(scp.group("host")) > 1:
            host = scp.group("host").lower()
            path = scp.group("path")
        else:
            path = raw

    path = path.replace("\\", "/").strip("/")
    if path.lower().endswith(".git"):
        path = path[:-4]
    path = path.strip("/").lower()
    if not path:
        return host or None
    return f"{host}/{path}" if host else path


def repo_display_name(url: str | None) -> str:
    """`group/repo` for a project name, falling back to the raw URL."""
    raw = (url or "").strip()
    if not raw:
        return "repository"
    if "://" in raw:
        path = urlparse(raw).path
    else:
        scp = _SCP_LIKE.match(raw)
        path = scp.group("path") if scp and len(scp.group("host")) > 1 else raw
    path = path.replace("\\", "/").strip("/")
    if path.lower().endswith(".git"):
        path = path[:-4]
    return path.strip("/") or raw
