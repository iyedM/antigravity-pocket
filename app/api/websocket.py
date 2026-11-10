import asyncio
import json

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from app.core.events import EventEnvelope
from app.core.permissions import approval_manager
from app.core.security import ticket_store, verify_signed_token

router = APIRouter(tags=["websocket"])


@router.websocket("/ws/sessions/{session_id}")
async def session_websocket(websocket: WebSocket, session_id: str) -> None:
    """
    Gapless WebSocket event stream authenticated via single-use ephemeral `ticket`
    (or Authorization header) so Bearer tokens never appear in URL query strings.
    """
    await websocket.accept()
    ticket = websocket.query_params.get("ticket", "").strip()
    auth_header = websocket.headers.get("authorization", "")
    bearer_token = (
        auth_header[7:].strip()
        if auth_header.lower().startswith("bearer ")
        else ""
    )

    try:
        last_seq = max(0, int(websocket.query_params.get("last_seq", "0") or "0"))
    except ValueError:
        last_seq = 0

    authenticated = False
    if ticket and ticket_store.consume_ticket(ticket, expected_purpose="ws") or bearer_token and verify_signed_token(bearer_token):
        authenticated = True

    if not authenticated:
        await websocket.send_json(
            {
                "type": "session_error",
                "payload": {
                    "error": "Non autorisé : ticket éphémère invalide ou expiré."
                },
            }
        )
        await websocket.close(code=1008)
        return

    runtime = websocket.app.state.runtime_manager
    session = runtime.session_service.get_session(session_id)
    if not session:
        await websocket.send_json(
            {
                "type": "session_error",
                "payload": {"error": f"Session {session_id} introuvable."},
            }
        )
        await websocket.close(code=1008)
        return

    live_queue: asyncio.Queue[dict] = asyncio.Queue()

    async def _on_live_event(envelope: EventEnvelope) -> None:
        await live_queue.put(envelope.to_dict())

    # Step 1: Subscribe BEFORE fetching replay events so zero events can fall in a gap
    runtime.subscribe(session_id, _on_live_event)
    high_water_seq = last_seq

    try:
        # Step 2: Replay missed events from SQLite
        missed_events = runtime.session_service.get_events_since(session_id, last_seq)
        for ev in missed_events:
            seq = int(ev.get("sequence", 0))
            if seq > high_water_seq:
                await websocket.send_json(ev)
                high_water_seq = seq

        # Step 3: Background task forwarding live events with sequence deduplication
        async def _forward_live_queue() -> None:
            nonlocal high_water_seq
            while True:
                ev = await live_queue.get()
                seq = int(ev.get("sequence", 0))
                if seq > high_water_seq:
                    high_water_seq = seq
                    await websocket.send_json(ev)

        sender_task = asyncio.create_task(_forward_live_queue())

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
                    approval_id = str(data.get("approval_id", ""))
                    approved = bool(data.get("approved", False))
                    approval_manager.resolve(approval_id, approved=approved)
        finally:
            sender_task.cancel()
            await asyncio.gather(sender_task, return_exceptions=True)
    except WebSocketDisconnect:
        pass
    finally:
        runtime.unsubscribe(session_id, _on_live_event)
