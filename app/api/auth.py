import shutil
from pathlib import Path
from pydantic import BaseModel
from fastapi import APIRouter, Depends, HTTPException, Request

from app.core.config import get_settings
from app.core.security import (
    create_signed_token,
    rate_limiter,
    require_auth,
    verify_password_constant_time,
)
from app.services.notification_service import notification_service

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])


class LoginRequest(BaseModel):
    password: str = ""


@router.post("/login")
async def login(payload: LoginRequest, request: Request) -> dict:
    settings = get_settings()
    client_ip = request.client.host if request.client else "unknown"

    if not rate_limiter.check_allowed(client_ip):
        raise HTTPException(
            status_code=429,
            detail="Trop de tentatives échouées. Réessayez dans 60 secondes.",
        )

    if settings.app_password and not verify_password_constant_time(
        payload.password, settings.app_password
    ):
        rate_limiter.record_failure(client_ip)
        raise HTTPException(status_code=401, detail="Mot de passe incorrect.")

    rate_limiter.reset(client_ip)
    token = create_signed_token(subject="mobile_client")
    return {
        "ok": True,
        "token": token,
        "expires_in": settings.token_ttl_seconds,
    }


@router.get("/status")
async def system_status(_: None = Depends(require_auth)) -> dict:
    settings = get_settings()
    sdk_available = False
    try:
        import google.antigravity  # noqa: F401

        sdk_available = True
    except ImportError:
        pass

    return {
        "ok": True,
        "version": settings.version,
        "sdk_available": sdk_available,
        "cli_available": shutil.which("agy") is not None,
        "account_configured": (Path.home() / ".gemini").exists(),
        "workspace": str(settings.workspace_dir),
        "auth_protected": bool(settings.app_password),
        "notifications": notification_service.list_recent(10),
    }
