"""git_workspace.ensure_workspace tests against a local (file-path) git repo.

No network access needed: the "remote" is just another folder under
tmp_path, so these run fine in CI.
"""

import subprocess
from pathlib import Path

import pytest

from app.config import settings
from app.services import git_workspace


def _git(args: list[str], cwd: Path) -> str:
    result = subprocess.run(
        ["git", *args], cwd=str(cwd), capture_output=True, text=True, check=True
    )
    return result.stdout.strip()


def _init_local_repo(path: Path) -> str:
    path.mkdir(parents=True, exist_ok=True)
    _git(["init", "-b", "main"], cwd=path)
    _git(["config", "user.email", "test@example.com"], cwd=path)
    _git(["config", "user.name", "Test"], cwd=path)
    (path / "README.md").write_text("hello", encoding="utf-8")
    _git(["add", "."], cwd=path)
    _git(["commit", "-m", "initial"], cwd=path)
    return _git(["rev-parse", "HEAD"], cwd=path)


@pytest.fixture()
def workspaces_dir(tmp_path, monkeypatch):
    root = tmp_path / "workspaces"
    monkeypatch.setattr(settings, "workspaces_dir", str(root))
    return root


def test_ensure_workspace_clones_when_missing(tmp_path, workspaces_dir):
    remote = tmp_path / "remote"
    _init_local_repo(remote)

    workspace = git_workspace.ensure_workspace("proj-clone", str(remote), "main", None)

    assert workspace == workspaces_dir / "proj-clone"
    assert (workspace / "README.md").read_text(encoding="utf-8") == "hello"


def test_ensure_workspace_fetches_branch_tip_on_second_call(tmp_path, workspaces_dir):
    remote = tmp_path / "remote"
    _init_local_repo(remote)
    git_workspace.ensure_workspace("proj-fetch", str(remote), "main", None)

    (remote / "README.md").write_text("updated", encoding="utf-8")
    _git(["add", "."], cwd=remote)
    _git(["commit", "-m", "second"], cwd=remote)

    workspace = git_workspace.ensure_workspace("proj-fetch", str(remote), "main", None)

    assert (workspace / "README.md").read_text(encoding="utf-8") == "updated"


def test_ensure_workspace_checks_out_specific_commit_sha(tmp_path, workspaces_dir):
    remote = tmp_path / "remote"
    first_sha = _init_local_repo(remote)

    (remote / "README.md").write_text("second version", encoding="utf-8")
    _git(["add", "."], cwd=remote)
    _git(["commit", "-m", "second"], cwd=remote)

    workspace = git_workspace.ensure_workspace("proj-pin", str(remote), "main", first_sha)

    assert (workspace / "README.md").read_text(encoding="utf-8") == "hello"


def test_ensure_workspace_raises_runtime_error_on_git_failure(tmp_path, workspaces_dir):
    with pytest.raises(RuntimeError):
        git_workspace.ensure_workspace(
            "proj-bad", str(tmp_path / "nonexistent-remote"), "main", None
        )


def test_ensure_workspace_raises_if_path_exists_and_is_not_a_git_repo(tmp_path, workspaces_dir):
    remote = tmp_path / "remote"
    _init_local_repo(remote)

    stray = workspaces_dir / "proj-stray"
    stray.mkdir(parents=True)
    (stray / "leftover.txt").write_text("not a git repo", encoding="utf-8")

    with pytest.raises(RuntimeError, match="not a git repository"):
        git_workspace.ensure_workspace("proj-stray", str(remote), "main", None)


def test_normalize_git_url_converts_github_ssh_to_https():
    assert (
        git_workspace.normalize_git_url("git@github.com:bharath412/mytodoapp5.git")
        == "https://github.com/bharath412/mytodoapp5.git"
    )
    assert (
        git_workspace.normalize_git_url("ssh://git@github.com/org/repo")
        == "https://github.com/org/repo.git"
    )
    assert (
        git_workspace.normalize_git_url("https://github.com/org/repo.git")
        == "https://github.com/org/repo.git"
    )


def test_redact_git_url_strips_embedded_credentials():
    assert (
        git_workspace.redact_git_url(
            "https://oauth2:glpat-secret-token-12345@gitlab.com/org/repo.git"
        )
        == "https://gitlab.com/org/repo.git"
    )
    assert (
        git_workspace.redact_git_url("https://github.com/org/repo.git")
        == "https://github.com/org/repo.git"
    )
    assert git_workspace.redact_git_url("") == ""
