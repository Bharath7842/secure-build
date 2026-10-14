"""Keep a project's GitLab OAuth access token usable.

GitLab access tokens expire after ~2 hours. `git_auth` stores the refresh
token and expiry at connect time, but nothing used them, so every scan more
than two hours after "Connect GitLab" failed at `git fetch` with "HTTP Basic:
Access denied". `fresh_access_token` is the one place that turns a project
into a token that's safe to hand to git, refreshing and persisting it first
when it has expired (or is about to).

GitHub OAuth tokens don't expire, so GitHub projects pass straight through.
"""

import logging
import threading
from datetime import datetime, timedelta, timezone

import httpx
from sqlalchemy.orm import object_session

from app.config import settings
from app.models import Project, utcnow

logger = logging.getLogger(__name__)

# Refresh a little early so a token can't lapse between this check and the
# fetch that uses it (a large clone can run for minutes).
_EXPIRY_SKEW = timedelta(minutes=5)
_REFRESH_TIMEOUT = 15

# GitLab rotates the refresh token on every use: the old one stops working the
# moment a refresh succeeds. Two scans refreshing the same project at once
# would leave the loser with a dead token and the project disconnected, so
# refreshes are serialized and re-checked once the lock is held.
_refresh_lock = threading.Lock()


def _as_utc(value: datetime) -> datetime:
    # SQLite hands timezone-aware columns back naive; the values were written as UTC.
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def _needs_refresh(project: Project) -> bool:
    if project.git_provider != "gitlab" or not project.git_access_token:
        return False
    if project.git_token_expires_at is None:
        return False  # no expiry recorded: treat as long-lived
    return _as_utc(project.git_token_expires_at) <= utcnow() + _EXPIRY_SKEW


def _request_refresh(refresh_token: str) -> dict:
    resp = httpx.post(
        f"{settings.gitlab_base_url}/oauth/token",
        data={
            "client_id": settings.gitlab_oauth_client_id,
            "client_secret": settings.gitlab_oauth_client_secret,
            "refresh_token": refresh_token,
            "grant_type": "refresh_token",
            "redirect_uri": settings.gitlab_oauth_redirect_uri,
        },
        timeout=_REFRESH_TIMEOUT,
    )
    resp.raise_for_status()
    data = resp.json()
    if "error" in data or not data.get("access_token"):
        raise ValueError(data.get("error_description") or data.get("error") or "no access_token in response")
    return data


def fresh_access_token(project: Project) -> str | None:
    """The project's access token, refreshed first if it has expired.

    Never raises: if the refresh fails (revoked grant, GitLab unreachable, no
    refresh token stored) the stale token is returned unchanged, so the caller
    fails at git with its usual message instead of a new error path — and the
    cause is logged here. The fix for a revoked grant is to reconnect GitLab.
    """
    if not _needs_refresh(project):
        return project.git_access_token

    session = object_session(project)
    with _refresh_lock:
        if session is not None:
            # Another scan may have refreshed (and rotated the refresh token)
            # while this one waited for the lock.
            session.refresh(project)
            if not _needs_refresh(project):
                return project.git_access_token
        if not project.git_refresh_token:
            logger.warning("GitLab token for project %s expired and no refresh token is stored — reconnect GitLab", project.id)
            return project.git_access_token
        try:
            data = _request_refresh(project.git_refresh_token)
        except (httpx.HTTPError, ValueError) as exc:
            # HTTPStatusError's message carries only the status line, never the request body.
            logger.warning("GitLab token refresh failed for project %s: %s — reconnect GitLab", project.id, exc)
            return project.git_access_token

        expires_in = data.get("expires_in")
        project.git_access_token = data["access_token"]
        project.git_refresh_token = data.get("refresh_token") or project.git_refresh_token
        project.git_token_expires_at = utcnow() + timedelta(seconds=expires_in) if expires_in else None
        if session is not None:
            session.commit()
        return project.git_access_token
