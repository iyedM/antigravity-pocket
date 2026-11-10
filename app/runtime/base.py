from abc import ABC, abstractmethod
from collections.abc import Awaitable, Callable
from typing import Any

from app.core.events import EventType
from app.core.permissions import PermissionMode

EventEmitter = Callable[[EventType, dict[str, Any]], Awaitable[None]]


class AgentAdapter(ABC):
    """Unified adapter interface isolating the backend from SDK/CLI internals."""

    @abstractmethod
    async def start_session(
        self,
        session_id: str,
        workspace: str,
        permission_mode: PermissionMode,
    ) -> None:
        """Initializes resources for a session."""

    @abstractmethod
    async def send_message(
        self,
        session_id: str,
        message: str,
        workspace: str,
        permission_mode: PermissionMode,
        emit: EventEmitter,
    ) -> None:
        """Executes a user turn and streams standardized events via `emit`."""

    @abstractmethod
    async def cancel(self, session_id: str) -> bool:
        """Cancels an in-flight turn for the given session."""

    @abstractmethod
    async def close_session(self, session_id: str) -> None:
        """Releases resources associated with a session."""
