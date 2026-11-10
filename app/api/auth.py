import shutil
from pathlib import Path

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from pydantic import BaseModel

from app.core.config import get_settings
from app.core.security import (
    create_signed_token,
    extract_request_token,
    rate_limiter,
    require_auth,
    revoke_signed_token,
    ticket_store,
    verify_password_constant_time,
)
from app.services.notification_service import notification_service

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])


class LoginRequest(BaseModel):
    password: str = ""


class TicketRequest(BaseModel):
    purpose: str = "ws"


@router.post("/login")
async def login(payload: LoginRequest, request: Request) -> dict:
    settings = get_settings()
    if not settings.is_password_configured_and_strong():
        raise HTTPException(
            status_code=503,
            detail="Serveur verrouillé : APP_PASSWORD fort (min 8 caractères) doit être configuré.",
        )

    client_ip = request.client.host if request.client else "unknown"
    if not rate_limiter.check_allowed(client_ip):
        raise HTTPException(
            status_code=429,
            detail="Trop de tentatives échouées. Réessayez dans 60 secondes.",
        )

    if not verify_password_constant_time(payload.password, settings.app_password):
        rate_limiter.record_failure(client_ip)
        raise HTTPException(status_code=401, detail="Mot de passe incorrect.")

    rate_limiter.reset(client_ip)
    token = create_signed_token(subject="mobile_client")
    return {
        "ok": True,
        "token": token,
        "expires_in": settings.token_ttl_seconds,
    }


@router.post("/ticket")
async def issue_single_use_ticket(
    payload: TicketRequest,
    _: None = Depends(require_auth),
) -> dict:
    """Issues a 30-second single-use ticket for WebSocket or download requests."""
    if payload.purpose not in ("ws", "download"):
        raise HTTPException(status_code=400, detail="Purpose invalide.")
    ticket = ticket_store.issue_ticket(purpose=payload.purpose, ttl_seconds=30)
    return {"ticket": ticket, "expires_in": 30}


@router.post("/logout")
async def logout(
    authorization: str | None = Header(default=None),
    x_auth_token: str | None = Header(default=None),
    _: None = Depends(require_auth),
) -> dict:
    raw_token = extract_request_token(authorization, x_auth_token)
    revoked = revoke_signed_token(raw_token)
    return {"ok": True, "revoked": revoked}


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
        "auth_protected": settings.is_password_configured_and_strong(),
        "notifications": notification_service.list_recent(10),
    }
