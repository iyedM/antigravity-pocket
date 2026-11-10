import asyncio
import base64
import io
import json
import os
import shutil
import tarfile
from pathlib import Path
from typing import Optional

from fastapi import (
    Depends,
    FastAPI,
    File,
    Header,
    HTTPException,
    Query,
    UploadFile,
    WebSocket,
    WebSocketDisconnect,
)
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

APP_PASSWORD = os.environ.get("APP_PASSWORD", "")
WORKSPACE_DIR = Path(
    os.environ.get("AGY_WORKSPACE", str(Path.home() / "workspace"))
).resolve()
STATIC_DIR = Path(__file__).parent / "static"


def restore_auth_bundle_if_present() -> None:
    """Restores the user's ~/.gemini session & rules from AGY_AUTH_BUNDLE env secret."""
    bundle_b64 = os.environ.get("AGY_AUTH_BUNDLE", "").strip()
    if not bundle_b64:
        return
    try:
        raw_bytes = base64.b64decode(bundle_b64)
        with tarfile.open(fileobj=io.BytesIO(raw_bytes), mode="r:gz") as tar:
            tar.extractall(path=Path.home())
        print("[Antigravity Pocket] Session Google & règles restaurées avec succès.")
    except Exception as exc:
        print(f"[Antigravity Pocket] Erreur lors de la restauration AGY_AUTH_BUNDLE: {exc}")


restore_auth_bundle_if_present()
WORKSPACE_DIR.mkdir(parents=True, exist_ok=True)

app = FastAPI(
    title="Antigravity Pocket",
    description="Self-Hosted Mobile Companion PWA for Google Antigravity (iOS & Android)",
    version="1.0.0",
)

app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


def verify_token(
    x_auth_token: Optional[str] = Header(default=None),
    token: Optional[str] = Query(default=None),
) -> None:
    """Verifies optional APP_PASSWORD protection."""
    if not APP_PASSWORD:
        return
    provided = x_auth_token or token or ""
    if provided != APP_PASSWORD:
        raise HTTPException(status_code=401, detail="Mot de passe invalide ou manquant.")


@app.get("/", response_class=HTMLResponse)
async def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/manifest.json")
async def manifest() -> FileResponse:
    return FileResponse(STATIC_DIR / "manifest.json")


@app.get("/sw.js")
async def service_worker() -> FileResponse:
    return FileResponse(STATIC_DIR / "sw.js", media_type="application/javascript")


@app.get("/api/status")
async def status(_: None = Depends(verify_token)) -> JSONResponse:
    sdk_available = False
    try:
        import google.antigravity  # noqa: F401

        sdk_available = True
    except ImportError:
        pass

    cli_available = shutil.which("agy") is not None
    gemini_dir = (Path.home() / ".gemini").exists()

    return JSONResponse(
        {
            "ok": True,
            "sdk_available": sdk_available,
            "cli_available": cli_available,
            "account_configured": gemini_dir,
            "workspace": str(WORKSPACE_DIR),
            "auth_protected": bool(APP_PASSWORD),
        }
    )


@app.get("/api/files")
async def list_files(_: None = Depends(verify_token)) -> JSONResponse:
    files = []
    for item in sorted(WORKSPACE_DIR.rglob("*")):
        if item.is_file() and not any(p.startswith(".") for p in item.parts):
            rel = item.relative_to(WORKSPACE_DIR)
            stat = item.stat()
            files.append(
                {
                    "name": item.name,
                    "path": str(rel),
                    "size": stat.st_size,
                    "mtime": int(stat.st_mtime),
                }
            )
    return JSONResponse({"files": files})


@app.post("/api/upload")
async def upload_files(
    files: list[UploadFile] = File(...),
    _: None = Depends(verify_token),
) -> JSONResponse:
    saved = []
    for upload in files:
        safe_name = Path(upload.filename or "uploaded_file").name
        dest = WORKSPACE_DIR / safe_name
        with dest.open("wb") as f:
            shutil.copyfileobj(upload.file, f)
        saved.append(safe_name)
    return JSONResponse({"uploaded": saved, "workspace": str(WORKSPACE_DIR)})


@app.get("/api/files/download/{filepath:path}")
async def download_file(
    filepath: str,
    _: None = Depends(verify_token),
) -> FileResponse:
    target = (WORKSPACE_DIR / filepath).resolve()
    if not str(target).startswith(str(WORKSPACE_DIR)) or not target.is_file():
        raise HTTPException(status_code=404, detail="Fichier introuvable.")
    return FileResponse(path=target, filename=target.name)


async def stream_with_sdk(prompt: str, websocket: WebSocket) -> None:
    """Executes the prompt using the official google-antigravity Python SDK."""
    from google.antigravity import Agent, CapabilitiesConfig, LocalAgentConfig

    rules_path = Path.home() / ".gemini" / "GEMINI.md"
    system_instructions = (
        rules_path.read_text(encoding="utf-8", errors="ignore")
        if rules_path.exists()
        else "You are Antigravity Pocket, running in the user's mobile cloud workspace."
    )

    config = LocalAgentConfig(
        system_instructions=system_instructions,
        capabilities=CapabilitiesConfig(),
    )

    os.chdir(WORKSPACE_DIR)
    async with Agent(config) as agent:
        response = await agent.chat(prompt)

        async def forward_thoughts() -> None:
            try:
                async for thought in response.thoughts:
                    await websocket.send_json({"type": "thought", "content": str(thought)})
            except Exception:
                pass

        async def forward_tools() -> None:
            try:
                async for call in response.tool_calls:
                    await websocket.send_json(
                        {
                            "type": "tool_call",
                            "name": getattr(call, "name", "tool"),
                            "args": str(getattr(call, "args", "")),
                        }
                    )
            except Exception:
                pass

        thought_task = asyncio.create_task(forward_thoughts())
        tool_task = asyncio.create_task(forward_tools())

        async for token in response:
            await websocket.send_json({"type": "token", "content": str(token)})

        await asyncio.gather(thought_task, tool_task, return_exceptions=True)


async def stream_with_cli(prompt: str, websocket: WebSocket) -> None:
    """Fallback execution using the `agy` CLI binary in non-interactive print mode."""
    agy_bin = shutil.which("agy")
    if not agy_bin:
        raise RuntimeError(
            "Ni le SDK `google-antigravity` ni le binaire `agy` ne sont disponibles."
        )

    proc = await asyncio.create_subprocess_exec(
        agy_bin,
        "--print",
        "--dangerously-skip-permissions",
        "--add-dir",
        str(WORKSPACE_DIR),
        prompt,
        cwd=str(WORKSPACE_DIR),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    assert proc.stdout is not None
    while True:
        chunk = await proc.stdout.read(256)
        if not chunk:
            break
        await websocket.send_json(
            {"type": "token", "content": chunk.decode("utf-8", errors="replace")}
        )

    await proc.wait()


@app.websocket("/ws/chat")
async def chat_websocket(websocket: WebSocket) -> None:
    await websocket.accept()
    token = websocket.query_params.get("token", "")
    if APP_PASSWORD and token != APP_PASSWORD:
        await websocket.send_json(
            {"type": "error", "content": "Mot de passe invalide (APP_PASSWORD)."}
        )
        await websocket.close(code=1008)
        return

    try:
        while True:
            raw = await websocket.receive_text()
            payload = json.loads(raw)
            prompt = payload.get("prompt", "").strip()
            if not prompt:
                continue

            await websocket.send_json({"type": "start"})
            try:
                try:
                    await stream_with_sdk(prompt, websocket)
                except ImportError:
                    await stream_with_cli(prompt, websocket)
                await websocket.send_json({"type": "done"})
            except Exception as exc:
                await websocket.send_json({"type": "error", "content": str(exc)})
    except WebSocketDisconnect:
        pass
