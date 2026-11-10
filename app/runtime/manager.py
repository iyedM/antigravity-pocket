import asyncio
from typing import Any, Callable, Coroutine, Dict, Optional, Set

from app.core.events import EventEnvelope, EventType
from app.core.permissions import PermissionMode
from app.runtime.adapters.cli import CLIAdapter
from app.runtime.adapters.sdk import SDKAdapter
from app.runtime.base import AgentAdapter
from app.services.notification_service import notification_service
from app.services.session_service import SessionService

SubscriberCallback = Callable[[EventEnvelope], Coroutine[Any, Any, None]]


class AgentRuntimeManager:
    """
    Central orchestrator managing session lifecycle, adapter selection,
    event persistence (SQLite), WebSocket fan-out, and serialized per-session turns.
    """

    def __init__(
        self,
        session_service: Optional[SessionService] = None,
        adapter: Optional[AgentAdapter] = None,
    ) -> None:
        self.session_service = session_service or SessionService()
        self.adapter = adapter or self._select_default_adapter()
        self._subscribers: Dict[str, Set[SubscriberCallback]] = {}
        self._running_tasks: Dict[str, asyncio.Task] = {}
        self._session_locks: Dict[str, asyncio.Lock] = {}

    @staticmethod
    def _select_default_adapter() -> AgentAdapter:
        try:
            import google.antigravity  # noqa: F401

            return SDKAdapter()
        except ImportError:
            return CLIAdapter()

    def _get_lock(self, session_id: str) -> asyncio.Lock:
        if session_id not in self._session_locks:
            self._session_locks[session_id] = asyncio.Lock()
        return self._session_locks[session_id]

    def subscribe(self, session_id: str, callback: SubscriberCallback) -> None:
        self._subscribers.setdefault(session_id, set()).add(callback)

    def unsubscribe(self, session_id: str, callback: SubscriberCallback) -> None:
        if session_id in self._subscribers:
            self._subscribers[session_id].discard(callback)

    async def emit_event(
        self, session_id: str, event_type: EventType, payload: Dict[str, Any]
    ) -> EventEnvelope:
        envelope = self.session_service.append_event(session_id, event_type, payload)
        for sub in list(self._subscribers.get(session_id, set())):
            try:
                await sub(envelope)
            except Exception:
                pass
        return envelope

    async def run_turn(self, session_id: str, prompt: str) -> None:
        lock = self._get_lock(session_id)
        async with lock:
            session = self.session_service.get_session(session_id)
            if not session:
                raise ValueError(f"Session introuvable : {session_id}")

            permission_mode = PermissionMode(session["permission_mode"])
            workspace = session["workspace"]

            self.session_service.update_session_status(session_id, "running")
            await self.emit_event(
                session_id,
                EventType.SESSION_STARTED,
                {"permission_mode": permission_mode.value},
            )
            await self.emit_event(session_id, EventType.USER_MESSAGE, {"text": prompt})

            async def _adapter_emit(ev_type: EventType, data: Dict[str, Any]) -> None:
                if ev_type == EventType.APPROVAL_REQUIRED:
                    self.session_service.update_session_status(
                        session_id, "waiting_approval"
                    )
                    notification_service.push(
                        title="Approbation requise",
                        body=data.get(
                            "risk_description", "Action en attente de validation"
                        ),
                        level="warning",
                        session_id=session_id,
                    )
                elif ev_type == EventType.APPROVAL_RESOLVED:
                    self.session_service.update_session_status(session_id, "running")
                await self.emit_event(session_id, ev_type, data)

            try:
                await self.adapter.start_session(
                    session_id, workspace, permission_mode
                )
                await self.adapter.send_message(
                    session_id=session_id,
                    message=prompt,
                    workspace=workspace,
                    permission_mode=permission_mode,
                    emit=_adapter_emit,
                )
                current = self.session_service.get_session(session_id)
                if current and current["status"] != "error":
                    self.session_service.update_session_status(session_id, "completed")
                    await self.emit_event(
                        session_id,
                        EventType.SESSION_COMPLETED,
                        {"status": "completed"},
                    )
                    notification_service.push(
                        title="Tâche terminée",
                        body=f"Session '{session['title']}' complétée.",
                        level="success",
                        session_id=session_id,
                    )
            except asyncio.CancelledError:
                self.session_service.update_session_status(session_id, "cancelled")
                await self.emit_event(
                    session_id,
                    EventType.SESSION_ERROR,
                    {"error": "Tâche interrompue à la demande de l'utilisateur."},
                )
            except Exception as exc:
                self.session_service.update_session_status(session_id, "error")
                await self.emit_event(
                    session_id, EventType.SESSION_ERROR, {"error": str(exc)}
                )

    def start_background_turn(self, session_id: str, prompt: str) -> asyncio.Task:
        existing = self._running_tasks.get(session_id)

        async def _serialized_runner() -> None:
            if existing and not existing.done():
                await self.cancel_turn(session_id)
                await asyncio.gather(existing, return_exceptions=True)
            await self.run_turn(session_id, prompt)

        task = asyncio.create_task(_serialized_runner())
        self._running_tasks[session_id] = task
        return task

    async def cancel_turn(self, session_id: str) -> bool:
        await self.adapter.cancel(session_id)
        task = self._running_tasks.get(session_id)
        if task and not task.done():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
            return True
        self.session_service.update_session_status(session_id, "cancelled")
        return False
