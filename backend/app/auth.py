from fastapi import Header, HTTPException, status

from app.config import settings


def verify_bearer(authorization: str | None = Header(default=None)) -> None:
    """FastAPI dependency that requires `Authorization: Bearer <token>`."""
    expected = f"Bearer {settings.sast_api_token}"
    if authorization != expected:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing bearer token",
        )
