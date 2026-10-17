import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI

from app import db as app_db
from app.auth.principal import ApiError, api_error_handler
from app.db import init_db
from app.routers.admin_audit import router as admin_audit_router
from app.routers.admin_users import router as admin_users_router
from app.routers.auth import router as auth_router
from app.routers.dast_rules import router as dast_rules_router
from app.routers.dast_settings import router as dast_settings_router
from app.routers.dast_training import router as dast_training_router
from app.routers.feedback import router as feedback_router
from app.routers.git_auth import router as git_auth_router
from app.routers.llm_presets import router as llm_presets_router
from app.routers.model_settings import router as model_settings_router
from app.routers.projects import router as projects_router
from app.routers.scan_limitations import router as scan_limitations_router
from app.routers.scans import router as scans_router
from app.routers.setup import router as setup_router
from app.services import scan_log, scan_runner
from app.services.model_gateway import default_library

logger = logging.getLogger(__name__)


def _account_housekeeping() -> None:
    """Drop expired sessions and old audit events, and say how to create the
    first admin when there are no users yet."""
    from app.auth.sessions import purge_expired_sessions
    from app.models import User
    from app.services.audit import purge_old_events

    with app_db.SessionLocal() as db:
        purge_expired_sessions(db)
        purge_old_events(db)
        if db.query(User.id).first() is None:
            logger.warning("No users yet: open /setup in the web app to create the first admin (needs SETUP_TOKEN).")


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    _account_housekeeping()
    scan_log.install()
    scan_runner.recover_interrupted_dast_scans()  # credentials died with the old process
    from app.services.dast_schedule import start_scheduler

    start_scheduler()  # no-op unless DAST_SCHEDULER_ENABLED is set
    default_library()  # a missing or invalid DAST prompt file stops startup here, naming the file
    yield


app = FastAPI(title="Secure Build SAST API", lifespan=lifespan)
app.add_exception_handler(ApiError, api_error_handler)

app.include_router(setup_router)
app.include_router(auth_router)
app.include_router(admin_users_router)
app.include_router(admin_audit_router)
app.include_router(projects_router)
app.include_router(scans_router)
app.include_router(feedback_router)
app.include_router(llm_presets_router)
app.include_router(scan_limitations_router)
app.include_router(model_settings_router)
app.include_router(git_auth_router)
app.include_router(dast_rules_router)
app.include_router(dast_settings_router)
app.include_router(dast_training_router)


@app.get("/health")
def health():
    return {"status": "ok"}
