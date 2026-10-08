from app.db import init_db
from app.models import Project


def test_can_insert_project(tmp_path):
    url = f"sqlite:///{(tmp_path / 't.db').as_posix()}"
    SessionLocal = init_db(url)
    with SessionLocal() as db:
        p = Project(name="demo", default_git_url="https://github.com/org/repo.git")
        db.add(p)
        db.commit()
        assert p.id is not None
