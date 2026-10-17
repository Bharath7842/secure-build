"""OAuth handshake for "Connect GitLab", from either the
new-project form (no project row yet) or an existing project's edit page.

Two-step flow:
1. Frontend calls `GET /git-auth/{provider}/authorize` (with `project_id` when
   editing an existing project, omitted when still on the new-project form)
   to get the provider's authorize URL, then redirects the browser there.
2. The provider redirects back to a frontend callback page with `code` +
   `state`; the frontend POSTs those here to `/git-auth/{provider}/callback`,
   which exchanges the code for an access token.
   - `project_id` in `state` (editing an existing project): the token is
     stored on that project immediately.
   - No project yet (new-project form): the token is stashed in a short-lived
     in-memory `_PENDING_CONNECTIONS` entry keyed by a fresh `connection_id`,
     which the frontend threads through to `POST /projects` so
     `routers.projects.create_project` can attach it to the row it creates.

The stored token is only ever used server-side (see `git_workspace.py`) to
build an authenticated clone URL — it's never sent back to the client.
"""

import re
import secrets
import time
from datetime import timedelta
from urllib.parse import quote, urlencode, urlparse

import httpx
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.auth.principal import Principal, require
from app.authz.scope import can_see_project
from app.config import settings
from app.db import get_db
from app.models import Project, utcnow
from app.services import git_token

router = APIRouter(prefix="/git-auth", tags=["git-auth"])

_PROVIDERS = {"gitlab"}

# Pending connections made before a project exists (new-project form). Short
# TTL — this only needs to survive the few minutes between "Connect GitLab"
# and clicking "Create project". Process-local by design: a demo/local-scale
# concern, not meant to survive a backend restart mid-flow.
_PENDING_TTL_SECONDS = 15 * 60
_pending_connections: dict[str, dict] = {}


def _store_pending_connection(provider: str, token_fields: dict) -> str:
    _prune_pending_connections()
    connection_id = secrets.token_urlsafe(16)
    _pending_connections[connection_id] = {
        "provider": provider,
        # Bookkeeping only — distinct from token_fields["expires_at"] (the
        # OAuth token's own expiry, often None), which `**token_fields` would
        # otherwise silently overwrite this with.
        "_ttl_expires_at": time.monotonic() + _PENDING_TTL_SECONDS,
        **token_fields,
    }
    return connection_id


def consume_pending_connection(connection_id: str) -> dict | None:
    """Pop and return a pending connection's fields, or None if missing/expired.

    Called once, from `routers.projects.create_project`, to attach a
    pre-authorized token to the project row being created.
    """
    _prune_pending_connections()
    return _pending_connections.pop(connection_id, None)


def _prune_pending_connections() -> None:
    now = time.monotonic()
    expired = [cid for cid, entry in _pending_connections.items() if entry["_ttl_expires_at"] < now]
    for cid in expired:
        _pending_connections.pop(cid, None)


def _get_project_or_404(db: Session, project_id: str) -> Project:
    project = db.get(Project, project_id)
    if project is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found")
    return project


def _require_provider(provider: str) -> str:
    provider = provider.lower()
    if provider not in _PROVIDERS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported git provider '{provider}'; must be one of {sorted(_PROVIDERS)}.",
        )
    return provider


class AuthorizeUrlOut(BaseModel):
    authorize_url: str


@router.get("/{provider}/authorize", response_model=AuthorizeUrlOut)
def get_authorize_url(
    provider: str,
    project_id: str | None = None,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require("projects.manage")),
):
    provider = _require_provider(provider)

    # `state` prevents CSRF and carries just enough round-trip data through
    # the provider's redirect to know, on callback, whether this connection
    # belongs to an existing project or is still pending one.
    if project_id:
        _get_project_or_404(db, project_id)
        state = f"project:{project_id}:{secrets.token_urlsafe(16)}"
    else:
        state = f"pending:{secrets.token_urlsafe(16)}"

    if not settings.gitlab_oauth_client_id:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="GitLab OAuth is not configured on the server.",
        )
    params = {
        "client_id": settings.gitlab_oauth_client_id,
        "redirect_uri": settings.gitlab_oauth_redirect_uri,
        "response_type": "code",
        # read_api: lists projects via GET /api/v4/projects (list_repos below).
        # read_repository: git clone/pull access for the actual scan checkout.
        "scope": "read_api read_repository",
        "state": state,
    }
    authorize_url = f"{settings.gitlab_base_url}/oauth/authorize?{urlencode(params)}"

    return AuthorizeUrlOut(authorize_url=authorize_url)


class CallbackIn(BaseModel):
    code: str
    state: str


class CallbackOut(BaseModel):
    git_provider: str
    project_id: str | None = None
    connection_id: str | None = None


def _exchange_code_for_token(provider: str, code: str) -> dict:
    """Returns the token fields to store: access_token/refresh_token/expires_at."""
    try:
        resp = httpx.post(
            f"{settings.gitlab_base_url}/oauth/token",
            data={
                "client_id": settings.gitlab_oauth_client_id,
                "client_secret": settings.gitlab_oauth_client_secret,
                "code": code,
                "grant_type": "authorization_code",
                "redirect_uri": settings.gitlab_oauth_redirect_uri,
            },
            timeout=15,
        )
        resp.raise_for_status()
        token_data = resp.json()
        if "error" in token_data:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=token_data.get("error_description") or token_data["error"],
            )
        expires_in = token_data.get("expires_in")
        return {
            "access_token": token_data["access_token"],
            "refresh_token": token_data.get("refresh_token"),
            "expires_at": utcnow() + timedelta(seconds=expires_in) if expires_in else None,
        }
    except httpx.HTTPError as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Could not reach {provider} to exchange the authorization code: {exc}",
        ) from exc


@router.post("/{provider}/callback", response_model=CallbackOut)
def handle_callback(
    provider: str,
    payload: CallbackIn,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require("projects.manage")),
):
    provider = _require_provider(provider)

    parts = payload.state.split(":", 2) if payload.state else []
    if parts and parts[0] == "project" and len(parts) == 3:
        project = _get_project_or_404(db, parts[1])
        token_fields = _exchange_code_for_token(provider, payload.code)
        project.git_provider = provider
        project.git_access_token = token_fields["access_token"]
        project.git_refresh_token = token_fields["refresh_token"]
        project.git_token_expires_at = token_fields["expires_at"]
        db.commit()
        return CallbackOut(project_id=project.id, git_provider=provider)

    if parts and parts[0] == "pending":
        token_fields = _exchange_code_for_token(provider, payload.code)
        connection_id = _store_pending_connection(provider, token_fields)
        return CallbackOut(connection_id=connection_id, git_provider=provider)

    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid state.")


class RepoOut(BaseModel):
    name: str
    full_name: str
    clone_url: str
    default_branch: str | None = None
    private: bool = False


class TokenRepoIn(BaseModel):
    url: str = Field(max_length=500)
    access_token: str = Field(min_length=1, max_length=500)
    # Set when editing a saved project; omitted on the new-project form.
    project_id: str | None = None


class TokenRepoOut(RepoOut):
    # Set on the new-project form: pass it to POST /projects as git_connection_id.
    connection_id: str | None = None


@router.post("/{provider}/token", response_model=TokenRepoOut)
def check_repo_token(
    provider: str,
    body: TokenRepoIn,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require("projects.manage")),
):
    """Confirm a repository with a personal access token, then keep the token the
    same way an OAuth connection is kept: on the project when editing, or as a
    short-lived pending connection when creating. The token is never returned."""
    provider = _require_provider(provider)
    try:
        path = repo_path_from_url(provider, body.url)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    token = body.access_token.strip()
    repo = _fetch_repo(provider, path, token)

    if body.project_id:
        project = db.get(Project, body.project_id)
        if project is None or not can_see_project(principal, project):
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found")
        project.git_provider = provider
        project.git_access_token = token
        project.git_refresh_token = None
        project.git_token_expires_at = None
        db.commit()
        return TokenRepoOut(**repo.model_dump())

    connection_id = _store_pending_connection(
        provider, {"access_token": token, "refresh_token": None, "expires_at": None}
    )
    return TokenRepoOut(**repo.model_dump(), connection_id=connection_id)


def _resolve_token(
    db: Session, provider: str, connection_id: str | None, project_id: str | None
) -> str:
    """Look up the access token for either a pending (pre-project) connection
    or an already-connected project — whichever the caller has on hand."""
    if connection_id:
        _prune_pending_connections()
        entry = _pending_connections.get(connection_id)
        if entry is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Connection not found or expired — reconnect and try again.",
            )
        return entry["access_token"]
    if project_id:
        project = _get_project_or_404(db, project_id)
        if not project.git_access_token or project.git_provider != provider:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Project is not connected to {provider}.",
            )
        return git_token.fresh_access_token(project)
    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="Provide either connection_id or project_id.",
    )


_SEGMENT_RE = re.compile(r"^[A-Za-z0-9_.-]+$")


def _provider_host(provider: str) -> str:
    return (urlparse(settings.gitlab_base_url).hostname or "").lower()


def repo_path_from_url(provider: str, raw: str) -> str:
    """`owner/repo` (GitLab: `group/sub/repo`) from a pasted clone or browser URL.

    The host must be this provider's own — the lookup only ever calls the
    configured API with a path taken from the URL, so a pasted URL can never
    make the backend send the token to another server. Raises ValueError with
    a message fit to show the user.
    """
    text = raw.strip()
    if not text:
        raise ValueError("Paste the full Git URL of the repository.")
    scp = re.match(r"^[\w.-]+@([\w.-]+):(.+)$", text)  # git@host:group/repo.git
    if scp:
        host, path = scp.group(1).lower(), scp.group(2)
    else:
        parsed = urlparse(text)
        if parsed.scheme not in {"http", "https", "ssh"} or not parsed.hostname:
            raise ValueError("That doesn't look like a Git URL — use the full https:// address.")
        host, path = parsed.hostname.lower(), parsed.path

    expected = _provider_host(provider)
    if host not in {expected, f"www.{expected}"}:
        raise ValueError(
            f"That URL is on {host}, but this connection is to {expected}. "
            f"Paste a {expected} repository URL."
        )

    segments = [seg for seg in path.split("/") if seg]
    if "-" in segments:  # GitLab page URLs: group/repo/-/tree/main
        segments = segments[: segments.index("-")]
    if segments and segments[-1].endswith(".git"):
        segments[-1] = segments[-1][: -len(".git")]
    if len(segments) < 2 or not all(
        _SEGMENT_RE.match(seg) and seg not in {".", ".."} for seg in segments
    ):
        raise ValueError("The URL must point at a repository, like https://host/group/repo.git.")
    return "/".join(segments)


def _fetch_repo(provider: str, path: str, token: str) -> RepoOut:
    """Ask the provider for one repository. Raises 404 when the token can't see
    it, 502 when the provider can't be reached."""
    try:
        resp = httpx.get(
            f"{settings.gitlab_base_url}/api/v4/projects/{quote(path, safe='')}",
            headers={"Authorization": f"Bearer {token}"},
            timeout=15,
        )
        if resp.status_code == 404:
            # Same answer whether the repository doesn't exist or this account
            # can't see it, so a lookup never confirms a private repository.
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"No repository at {path} is visible to your {provider} account.",
            )
        resp.raise_for_status()
        r = resp.json()
    except httpx.HTTPError as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Could not look up the {provider} repository: {exc}",
        ) from exc

    return RepoOut(
        name=r["name"],
        full_name=r["path_with_namespace"],
        clone_url=r["http_url_to_repo"],
        default_branch=r.get("default_branch"),
        private=r.get("visibility") != "public",
    )


@router.get("/{provider}/repo", response_model=RepoOut)
def lookup_repo(
    provider: str,
    url: str,
    connection_id: str | None = None,
    project_id: str | None = None,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require("projects.manage")),
):
    """Find one repository by its Git URL using the connected account's token.

    Replaces listing every repository (one page of 100 at most): the user pastes
    the URL and we ask the provider for exactly that repository.
    """
    provider = _require_provider(provider)
    try:
        path = repo_path_from_url(provider, url)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    token = _resolve_token(db, provider, connection_id, project_id)

    return _fetch_repo(provider, path, token)


@router.delete("/{project_id}/disconnect", status_code=status.HTTP_204_NO_CONTENT)
def disconnect(
    project_id: str,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require("projects.manage")),
):
    project = _get_project_or_404(db, project_id)
    project.git_provider = None
    project.git_access_token = None
    project.git_refresh_token = None
    project.git_token_expires_at = None
    db.commit()
