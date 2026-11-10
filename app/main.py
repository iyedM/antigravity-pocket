import os
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles

from app.api import auth, files, sessions, websocket
from app.core.config import Settings, get_settings
from app.core.security import decrypt_bundle_aes_gcm, safe_extract_tar_bundle
from app.runtime.manager import AgentRuntimeManager
from app.services.session_service import SessionService
from app.services.workspace_service import WorkspaceService

STATIC_DIR = Path(__file__).parent / "static"


def restore_encrypted_bundle_if_present(dest_root: Path | None = None) -> None:
    """
    Optional Cloud helper: decrypts and safely extracts an AES-256-GCM bundle
    using strict allowlist validation (`safe_extract_tar_bundle`).
    """
    enc_bundle = os.environ.get("AGY_ENCRYPTED_BUNDLE", "").strip()
    passphrase = os.environ.get("AGY_BUNDLE_PASSPHRASE", "").strip()
    if not enc_bundle or not passphrase:
        return
    try:
        raw_tar = decrypt_bundle_aes_gcm(enc_bundle, passphrase)
        safe_extract_tar_bundle(raw_tar, dest_root or Path.home())
    except (ValueError, OSError) as exc:
        print(f"[Antigravity Pocket] Échec de restauration sécurisée : {exc}")


def create_app(custom_settings: Settings | None = None) -> FastAPI:
    restore_encrypted_bundle_if_present()
    settings = custom_settings or get_settings()
    settings.ensure_directories()

    application = FastAPI(
        title=settings.app_name,
        description="Modular Self-Hosted Mobile Companion PWA for Google Antigravity",
        version=settings.version,
    )

    session_service = SessionService(db_path=settings.db_path)
    workspace_service = WorkspaceService(
        workspace_root=settings.workspace_dir,
        max_upload_bytes=settings.max_upload_bytes,
        max_workspace_bytes=settings.max_workspace_bytes,
    )
    runtime_manager = AgentRuntimeManager(session_service=session_service)

    application.state.settings = settings
    application.state.session_service = session_service
    application.state.workspace_service = workspace_service
    application.state.runtime_manager = runtime_manager

    application.include_router(auth.router)
    application.include_router(sessions.router)
    application.include_router(files.router)
    application.include_router(websocket.router)

    application.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    @application.get("/", response_class=HTMLResponse)
    async def root_index() -> FileResponse:
        return FileResponse(STATIC_DIR / "index.html")

    @application.get("/manifest.json")
    async def pwa_manifest() -> FileResponse:
        return FileResponse(STATIC_DIR / "manifest.json")

    @application.get("/sw.js")
    async def pwa_sw() -> FileResponse:
        return FileResponse(STATIC_DIR / "sw.js", media_type="application/javascript")

    return application


app = create_app()
