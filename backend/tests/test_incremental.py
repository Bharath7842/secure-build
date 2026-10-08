from pathlib import Path

from app.db import init_db
from app.models import FileSnapshot, Project, Scan
from app.services.incremental import compute_changed_paths


def _write_tree(root: Path, files: dict[str, str]) -> None:
    for rel, content in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")


def test_compute_changed_paths_first_scan_returns_none(tmp_path):
    url = f"sqlite:///{(tmp_path / 'inc.db').as_posix()}"
    SessionLocal = init_db(url)
    root = tmp_path / "workspace"
    _write_tree(root, {"a.java": "class A {}", "b.ts": "export const x = 1;"})

    with SessionLocal() as db:
        project = Project(name="inc-demo", default_git_url="https://github.com/org/repo.git")
        db.add(project)
        db.commit()

        changed = compute_changed_paths(project.id, root, "commit1", db)
        assert changed is None
        project_id = project.id

        with SessionLocal() as other:
            assert other.query(FileSnapshot).filter_by(project_id=project_id).count() == 0

        db.commit()

    with SessionLocal() as other:
        snapshots = other.query(FileSnapshot).filter_by(project_id=project_id).all()
        assert {s.path for s in snapshots} == {"a.java", "b.ts"}
        assert all(s.commit_sha == "commit1" for s in snapshots)


def test_compute_changed_paths_second_scan_returns_only_modified(tmp_path):
    url = f"sqlite:///{(tmp_path / 'inc2.db').as_posix()}"
    SessionLocal = init_db(url)
    root = tmp_path / "workspace"
    _write_tree(root, {"a.java": "class A {}", "b.ts": "export const x = 1;"})

    with SessionLocal() as db:
        project = Project(name="inc-demo2", default_git_url="https://github.com/org/repo.git")
        db.add(project)
        db.commit()

        assert compute_changed_paths(project.id, root, "commit1", db) is None
        db.commit()

        (root / "a.java").write_text("class A { void m() {} }", encoding="utf-8")
        changed = compute_changed_paths(project.id, root, "commit2", db)

        assert changed == ["a.java"]
        assert "b.ts" not in changed
        db.commit()

        snapshots = db.query(FileSnapshot).filter_by(project_id=project.id).all()
        by_path = {s.path: s for s in snapshots}
        assert by_path["a.java"].commit_sha == "commit2"
        assert by_path["b.ts"].commit_sha == "commit1"


def test_compute_changed_paths_deletes_removed_files(tmp_path):
    url = f"sqlite:///{(tmp_path / 'inc3.db').as_posix()}"
    SessionLocal = init_db(url)
    root = tmp_path / "workspace"
    _write_tree(root, {"a.java": "class A {}", "b.ts": "export const x = 1;"})

    with SessionLocal() as db:
        project = Project(name="inc-demo3", default_git_url="https://github.com/org/repo.git")
        db.add(project)
        db.commit()

        compute_changed_paths(project.id, root, "commit1", db)
        db.commit()

        (root / "b.ts").unlink()
        changed = compute_changed_paths(project.id, root, "commit2", db)

        assert changed == ["b.ts"]
        db.commit()

        paths = {s.path for s in db.query(FileSnapshot).filter_by(project_id=project.id).all()}
        assert paths == {"a.java"}


def test_iter_scan_files_skips_excluded_dirs(tmp_path):
    from app.services.incremental import iter_scan_files

    root = tmp_path / "tree"
    _write_tree(
        root,
        {
            "src/App.ts": "export {}",
            "node_modules/pkg/index.ts": "ignored",
            ".git/config": "ignored",
            "pom.xml": "<project/>",
        },
    )

    paths = {p.relative_to(root).as_posix() for p in iter_scan_files(root)}
    assert paths == {"src/App.ts", "pom.xml"}


def test_execute_scan_failure_rolls_back_snapshots(tmp_path, monkeypatch):
    from app.config import settings
    from app.services import scan_runner

    workspaces = tmp_path / "workspaces"
    monkeypatch.setattr(settings, "workspaces_dir", str(workspaces))
    monkeypatch.setenv("USE_MOCK_ENGINE", "true")

    url = f"sqlite:///{(tmp_path / 'fail.db').as_posix()}"
    SessionLocal = init_db(url)

    with SessionLocal() as db:
        project = Project(
            name="fail-demo",
            default_git_url="https://github.com/org/repo.git",
            scan_mode="incremental",
        )
        db.add(project)
        db.commit()
        project_id = project.id

    workspace = workspaces / project_id
    _write_tree(workspace, {"a.java": "class A {}"})

    with SessionLocal() as db:
        scan = Scan(
            project_id=project_id,
            git_url="https://github.com/org/repo.git",
            branch="main",
            commit_sha="c1",
        )
        db.add(scan)
        db.commit()
        scan_id = scan.id

    def boom(*args, **kwargs):
        raise RuntimeError("engine failed")

    monkeypatch.setattr(scan_runner.engine_adapter, "run_scan", boom)
    scan_runner.execute_scan(scan_id)

    with SessionLocal() as db:
        assert db.query(FileSnapshot).filter_by(project_id=project_id).count() == 0
        scan = db.get(Scan, scan_id)
        assert scan.status == "failed"
        assert scan.message == "engine failed"
