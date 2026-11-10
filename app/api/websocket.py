import json
from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from app.core.events import EventEnvelope
from app.core.permissions import approval_manager
from app.core.security import verify_signed_token

router = APIRouter(tags=["websocket"])


@router.websocket("/ws/sessions/{session_id}")
async def session_websocket(websocket: WebSocket, session_id: str) -> None:
    await websocket.accept()
    token = websocket.query_params.get("token", "")
    last_seq = int(websocket.query_params.get("last_seq", "0") or "0")

    if not verify_signed_token(token):
        await websocket.send_json(
            {"type": "session_error", "payload": {"error": "Non autorisé : jeton invalide."}}
        )
        await websocket.close(code=1008)
        return

    runtime = websocket.app.state.runtime_manager
    session = runtime.session_service.get_session(session_id)
    if not session:
        await websocket.send_json(
            {"type": "session_error", "payload": {"error": f"Session {session_id} introuvable."}}
        )
        await websocket.close(code=1008)
        return

    # 1. Replay missed events since `last_seq`
    missed_events = runtime.session_service.get_events_since(session_id, last_seq)
    for ev in missed_events:
        await websocket.send_json(ev)

    # 2. Subscribe to live events for this session
    async def _on_live_event(envelope: EventEnvelope) -> None:
        await websocket.send_json(envelope.to_dict())

    runtime.subscribe(session_id, _on_live_event)

    try:
        while True:
            raw = await websocket.receive_text()
            data = json.loads(raw)
            msg_type = data.get("type", "prompt")

            if msg_type == "prompt":
                prompt = data.get("prompt", "").strip()
                if prompt:
                    runtime.start_background_turn(session_id, prompt)
            elif msg_type == "cancel":
                await runtime.cancel_turn(session_id)
            elif msg_type == "approval":
                approval_id = data.get("approval_id", "")
                approved = bool(data.get("approved", False))
                approval_manager.resolve(approval_id, approved=approved)
    except WebSocketDisconnect:
        pass
    finally:
        runtime.unsubscribe(session_id, _on_live_event)
