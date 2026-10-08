"""Git checkout helpers for preparing a per-project scan workspace.

`ensure_workspace` clones (first run) or fetches + checks out (subsequent
runs) `settings.workspaces_dir/<project_id>` so the real SAST engine adapter
(`agent_bridge.run_real_scan`) always has a workspace on disk that matches
the requested branch/commit before the agent walks it.
"""

import base64
import re
import subprocess
from pathlib import Path
from urllib.parse import urlparse, urlunparse

from app.config import settings


_LS_REMOTE_TIMEOUT = 15
_GITHUB_SSH_RE = re.compile(r"^git@github\.com:(?P<path>[^/]+/[^/]+?)(?:\.git)?$")
_GITHUB_SSH_URL_RE = re.compile(r"^ssh://git@github\.com/(?P<path>[^/]+/[^/]+?)(?:\.git)?$")
# Windows default MAX_PATH (~260) breaks deep monorepo checkouts unless enabled.
_GIT_LONGPATHS = ["-c", "core.longpaths=true"]
# Matches credentials embedded in a URL's userinfo (scheme://user:token@...),
# for scrubbing git stderr/exceptions before they reach scan.message/scan_log
# or any other user-visible surface (a failed authenticated fetch commonly
# echoes the URL it tried back in its error output).
_URL_CREDENTIALS_RE = re.compile(r"(https?://)[^\s/@]+:[^\s/@]+@")
# Matches an HTTP Basic auth header value (base64), for the same reason —
# it appears in the `-c http.extraHeader=...` git arg on auth failures.
_AUTH_HEADER_RE = re.compile(r"(?i)(authorization:\s*basic\s+)\S+")


def normalize_git_url(git_url: str) -> str:
    """Convert GitHub SSH URLs to HTTPS so clones work without local SSH keys.

    Public repos clone anonymously over HTTPS. Private repos still need a
    credential helper or PAT — same as SSH would need a key.
    """
    url = (git_url or "").strip()
    m = _GITHUB_SSH_RE.match(url)
    if m:
        return f"https://github.com/{m.group('path')}.git"
    m = _GITHUB_SSH_URL_RE.match(url)
    if m:
        return f"https://github.com/{m.group('path')}.git"
    return url


def authenticated_clone_url(
    git_url: str, git_provider: str | None, git_access_token: str | None
) -> str:
    """Inject an OAuth token as HTTP Basic userinfo into a normalized clone URL.

    Both GitHub and GitLab accept the access token as the password half of
    the URL over HTTPS; only the conventional username differs. Falls back
    to the plain normalized URL when the project hasn't connected a provider
    (public repos clone anonymously, same as before this existed).
    """
    url = normalize_git_url(git_url)
    if not git_provider or not git_access_token:
        return url
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return url
    username = "x-access-token" if git_provider == "github" else "oauth2"
    host = parsed.hostname or ""
    if parsed.port:
        host = f"{host}:{parsed.port}"
    netloc = f"{username}:{git_access_token}@{host}"
    return urlunparse((parsed.scheme, netloc, parsed.path, parsed.params, parsed.query, parsed.fragment))


def redact_git_url(git_url: str) -> str:
    """Strip embedded credentials from a git remote URL for safe display.

    Clone URLs like ``https://oauth2:<token>@gitlab.com/org/repo.git`` must
    never appear verbatim in PDF/Excel exports or other user-visible surfaces."""
    url = (git_url or "").strip()
    if not url:
        return ""
    parsed = urlparse(url)
    if parsed.scheme and (parsed.username or parsed.password):
        host = parsed.hostname or ""
        if parsed.port:
            host = f"{host}:{parsed.port}"
        return urlunparse((
            parsed.scheme, host, parsed.path, parsed.params, parsed.query, parsed.fragment,
        ))
    return url


def _is_git_repo(path: Path) -> bool:
    return (path / ".git").exists()


def resolve_remote_head(
    git_url: str,
    branch: str,
    git_provider: str | None = None,
    git_access_token: str | None = None,
) -> str | None:
    """Best-effort `git ls-remote` for the tip commit of `branch` on `git_url`,
    with no clone/checkout. Used by the scan trigger endpoint to answer "is
    there anything new to scan?" before doing any real work.

    Never raises: any failure (unreachable remote, bad url, timeout, missing
    branch) returns None so callers fall back to "always scan" behavior
    instead of blocking a scan trigger on a flaky network call.
    """
    branch = branch or "main"
    try:
        result = subprocess.run(
            [
                "git",
                "ls-remote",
                authenticated_clone_url(git_url, git_provider, git_access_token),
                f"refs/heads/{branch}",
            ],
            capture_output=True,
            text=True,
            timeout=_LS_REMOTE_TIMEOUT,
        )
    except (subprocess.SubprocessError, OSError):
        return None

    if result.returncode != 0:
        return None

    line = result.stdout.strip().splitlines()[0] if result.stdout.strip() else ""
    sha = line.split()[0].strip() if line else ""
    return sha or None


def _git(args: list[str], cwd: Path | None = None) -> str:
    result = subprocess.run(
        ["git", *_GIT_LONGPATHS, *args],
        cwd=str(cwd) if cwd else None,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        stderr = (result.stderr or result.stdout or "").strip()
        raise RuntimeError(f"git {' '.join(args)} failed (exit {result.returncode}): {stderr}")
    return result.stdout


def _finish_partial_clone(workspace: Path) -> None:
    """Recover when `git clone` fetched objects but checkout failed (common on Windows)."""
    _git(["config", "core.longpaths", "true"], cwd=workspace)
    _git(["restore", "--source=HEAD", ":/"], cwd=workspace)


def _clone_repo(clone_url: str, workspace: Path) -> None:
    workspace.parent.mkdir(parents=True, exist_ok=True)
    result = subprocess.run(
        ["git", *_GIT_LONGPATHS, "clone", clone_url, str(workspace)],
        capture_output=True,
        text=True,
    )
    if result.returncode == 0:
        return
    stderr = (result.stderr or result.stdout or "").strip()
    if _is_git_repo(workspace):
        try:
            _finish_partial_clone(workspace)
            return
        except RuntimeError as exc:
            raise RuntimeError(
                f"git clone checkout failed even with core.longpaths=true: {stderr}; "
                f"retry restore failed: {exc}"
            ) from exc
    raise RuntimeError(f"git clone failed (exit {result.returncode}): {stderr}")


def ensure_workspace(
    project_id: str,
    git_url: str,
    branch: str,
    commit_sha: str | None,
    git_provider: str | None = None,
    git_access_token: str | None = None,
) -> Path:
    """Clone into settings.workspaces_dir/project_id if missing; else fetch.

    Checks out `commit_sha` if provided, else the tip of `branch`. Raises
    `RuntimeError` (with the underlying git stderr) on any failure so the
    caller can mark the scan `failed` with a useful message.

    `git_provider`/`git_access_token` (from a "Connect GitHub"/"Connect
    GitLab" project) let this clone/fetch private repos; omitted for public
    repos, same behavior as before either existed.
    """
    workspace = Path(settings.workspaces_dir) / project_id
    branch = branch or "main"
    clone_url = authenticated_clone_url(git_url, git_provider, git_access_token)

    if _is_git_repo(workspace):
        # Refresh the stored remote URL every run so a rotated/renewed OAuth
        # token doesn't leave `origin` pointing at a stale credential.
        _git(["remote", "set-url", "origin", clone_url], cwd=workspace)
        _git(["config", "core.longpaths", "true"], cwd=workspace)
        _git(["fetch", "origin", "--prune", "--tags"], cwd=workspace)
    else:
        if workspace.exists() and any(workspace.iterdir()):
            raise RuntimeError(
                f"Workspace path {workspace} already exists and is not a git "
                "repository; remove it manually before running a live scan."
            )
        _clone_repo(clone_url, workspace)
        _git(["fetch", "origin", "--prune", "--tags"], cwd=workspace)

    checkout_target = commit_sha or branch
    _git(["checkout", "--force", checkout_target], cwd=workspace)
    reset_target = commit_sha or f"origin/{branch}"
    _git(["reset", "--hard", reset_target], cwd=workspace)

    return workspace


def resolve_head_sha(workspace: Path) -> str | None:
    """Resolved HEAD commit SHA of the checked-out workspace — used as the
    cache-invalidation key for the persistent AST cache (a new commit means
    a new cache file; the same commit reuses the existing one). Returns None
    on any failure rather than raising, since a scan should still proceed
    even if AST caching has to fall back to a path-hash key."""
    try:
        return _git(["rev-parse", "HEAD"], cwd=workspace).strip() or None
    except RuntimeError:
        return None
