
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel

from app.core.permissions import PermissionMode, approval_manager
from app.core.security import require_auth

router = APIRouter(prefix="/api/v1", tags=["sessions"])


class CreateSessionRequest(BaseModel):
    title: str = "Nouvelle session"
    permission_mode: str = PermissionMode.ASSISTED.value


class UpdateSessionRequest(BaseModel):
    permission_mode: str


class ResolveApprovalRequest(BaseModel):
    approved: bool
    session_id: str | None = None


@router.get("/sessions")
async def list_sessions(
    request: Request,
    _: None = Depends(require_auth),
) -> dict:
    runtime = request.app.state.runtime_manager
    return {"sessions": runtime.session_service.list_sessions()}


@router.post("/sessions")
async def create_session(
    payload: CreateSessionRequest,
    request: Request,
    _: None = Depends(require_auth),
) -> dict:
    runtime = request.app.state.runtime_manager
    try:
        sess = runtime.session_service.create_session(
            title=payload.title,
            permission_mode=payload.permission_mode,
        )
        return {"session": sess}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.get("/sessions/{session_id}")
async def get_session_details(
    session_id: str,
    request: Request,
    after_sequence: int = Query(default=0, ge=0),
    _: None = Depends(require_auth),
) -> dict:
    runtime = request.app.state.runtime_manager
    sess = runtime.session_service.get_session(session_id)
    if not sess:
        raise HTTPException(status_code=404, detail="Session introuvable.")
    events = runtime.session_service.get_events_since(session_id, after_sequence)
    return {"session": sess, "events": events}


@router.patch("/sessions/{session_id}")
async def update_session_permission(
    session_id: str,
    payload: UpdateSessionRequest,
    request: Request,
    _: None = Depends(require_auth),
) -> dict:
    runtime = request.app.state.runtime_manager
    try:
        updated = runtime.session_service.update_permission_mode(
            session_id, payload.permission_mode
        )
    except ValueError:
        raise HTTPException(status_code=400, detail="Mode de permission invalide.")
    if not updated:
        raise HTTPException(status_code=404, detail="Session introuvable.")
    return {"session": updated}


@router.post("/sessions/{session_id}/cancel")
async def cancel_session(
    session_id: str,
    request: Request,
    _: None = Depends(require_auth),
) -> dict:
    runtime = request.app.state.runtime_manager
    cancelled = await runtime.cancel_turn(session_id)
    return {"cancelled": cancelled, "session_id": session_id}


@router.delete("/sessions/{session_id}")
async def delete_session(
    session_id: str,
    request: Request,
    _: None = Depends(require_auth),
) -> dict:
    runtime = request.app.state.runtime_manager
    deleted = runtime.session_service.delete_session(session_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Session introuvable.")
    return {"deleted": True}


@router.get("/approvals")
async def list_approvals(
    session_id: str | None = Query(default=None),
    _: None = Depends(require_auth),
) -> dict:
    return {"approvals": approval_manager.list_for_session(session_id)}


@router.post("/approvals/{approval_id}/resolve")
async def resolve_approval(
    approval_id: str,
    payload: ResolveApprovalRequest,
    _: None = Depends(require_auth),
) -> dict:
    if not payload.session_id or not payload.session_id.strip():
        raise HTTPException(
            status_code=400,
            detail="Le champ session_id est obligatoire pour vérifier l'appartenance de l'approbation.",
        )
    try:
        req = approval_manager.resolve(
            approval_id,
            approved=payload.approved,
            expected_session_id=payload.session_id.strip(),
        )
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc))
    if not req:
        raise HTTPException(
            status_code=404, detail="Demande d'approbation introuvable ou déjà résolue."
        )
    return {"approval": req.to_dict()}


@router.post("/sessions/{session_id}/approvals/{approval_id}/resolve")
async def resolve_session_approval(
    session_id: str,
    approval_id: str,
    payload: ResolveApprovalRequest,
    _: None = Depends(require_auth),
) -> dict:
    try:
        req = approval_manager.resolve(
            approval_id,
            approved=payload.approved,
            expected_session_id=session_id,
        )
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc))
    if not req:
        raise HTTPException(
            status_code=404, detail="Demande d'approbation introuvable ou déjà résolue."
        )
    return {"approval": req.to_dict()}
