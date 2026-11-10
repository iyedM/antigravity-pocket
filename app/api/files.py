from collections.abc import AsyncIterator
from typing import Annotated

from fastapi import APIRouter, Depends, File, HTTPException, Query, Request, UploadFile
from fastapi.responses import FileResponse

from app.core.security import require_auth, require_download_auth
from app.services.workspace_service import (
    WorkspaceCollisionError,
    WorkspaceSecurityError,
    WorkspaceService,
)

router = APIRouter(prefix="/api/v1/files", tags=["files"])


def _get_ws_service(request: Request) -> WorkspaceService:
    return request.app.state.workspace_service


async def _iter_upload_chunks(upload: UploadFile, chunk_size: int = 65536) -> AsyncIterator[bytes]:
    while True:
        chunk = await upload.read(chunk_size)
        if not chunk:
            break
        yield chunk


@router.get("")
async def list_workspace_files(
    request: Request,
    subpath: str = Query(default=""),
    _: None = Depends(require_auth),
) -> dict:
    ws = _get_ws_service(request)
    try:
        return {"files": ws.list_files(subpath), "subpath": subpath}
    except WorkspaceSecurityError as exc:
        raise HTTPException(status_code=403, detail=str(exc))
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.get("/preview")
async def preview_workspace_file(
    request: Request,
    path: str = Query(...),
    _: None = Depends(require_auth),
) -> dict:
    ws = _get_ws_service(request)
    try:
        return ws.preview_file(path)
    except WorkspaceSecurityError as exc:
        raise HTTPException(status_code=403, detail=str(exc))
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.post("/upload")
async def upload_workspace_files(
    request: Request,
    files: Annotated[list[UploadFile], File()],
    subpath: str = Query(default=""),
    overwrite: bool = Query(default=True),
    _: None = Depends(require_auth),
) -> dict:
    ws = _get_ws_service(request)
    uploaded = []
    for upload in files:
        try:
            saved = await ws.save_upload_stream(
                upload.filename or "file",
                _iter_upload_chunks(upload),
                subpath=subpath,
                overwrite=overwrite,
            )
            uploaded.append(saved)
        except WorkspaceSecurityError as exc:
            raise HTTPException(status_code=403, detail=str(exc))
        except WorkspaceCollisionError as exc:
            raise HTTPException(status_code=409, detail=str(exc))
        except ValueError as exc:
            raise HTTPException(status_code=413, detail=str(exc))
    return {"uploaded": uploaded}


@router.get("/download/{filepath:path}")
async def download_workspace_file(
    filepath: str,
    request: Request,
    _: None = Depends(require_download_auth),
) -> FileResponse:
    ws = _get_ws_service(request)
    try:
        target = ws.resolve_safe_path(filepath)
    except WorkspaceSecurityError as exc:
        raise HTTPException(status_code=403, detail=str(exc))
    if not target.is_file():
        raise HTTPException(status_code=404, detail="Fichier introuvable.")
    return FileResponse(path=target, filename=target.name)
