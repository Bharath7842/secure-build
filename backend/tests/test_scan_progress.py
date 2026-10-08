"""Progress updates driven by engine log lines."""

from app.models import Project, Scan
from app.services import scan_log, scan_runner


def test_progress_hook_updates_scan_from_stage_log(tmp_path, monkeypatch):
    from app import db as db_module
    from app.config import settings
    from app.db import init_db

    db_path = tmp_path / "progress.db"
    init_db(f"sqlite:///{db_path.as_posix()}")
    monkeypatch.setattr(settings, "scan_logs_dir", str(tmp_path / "logs"))
    monkeypatch.setattr(settings, "workspaces_dir", str(tmp_path / "workspaces"))

    db = db_module.SessionLocal()
    try:
        project = Project(name="prog-test", default_git_url="https://example.com/r.git")
        db.add(project)
        db.commit()
        db.refresh(project)

        scan = Scan(
            project_id=project.id,
            git_url=project.default_git_url,
            branch="main",
            status="running",
            progress=10,
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)

        scan_log.reset(scan.id)
        last = [10]
        scan_log.register_line_hook(scan.id, scan_runner._progress_hook_factory(db, scan.id, last))
        try:
            scan_log.log(scan.id, "### Detecting the tech stack")
        finally:
            scan_log.unregister_line_hooks(scan.id)

        db.expire_all()
        updated = db.get(Scan, scan.id)
        assert updated is not None
        assert updated.progress == 50
    finally:
        db.close()
