import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict


class EventType(str, Enum):
    """Standardized real-time timeline event types."""

    SESSION_STARTED = "session_started"
    USER_MESSAGE = "user_message"
    THOUGHT_DELTA = "thought_delta"
    ASSISTANT_MESSAGE = "assistant_message"
    TOOL_STARTED = "tool_started"
    TOOL_COMPLETED = "tool_completed"
    APPROVAL_REQUIRED = "approval_required"
    APPROVAL_RESOLVED = "approval_resolved"
    FILE_CHANGED = "file_changed"
    SESSION_ERROR = "session_error"
    SESSION_COMPLETED = "session_completed"


@dataclass
class EventEnvelope:
    """Standardized numbered event envelope supporting WebSocket replay."""

    session_id: str
    sequence: int
    type: EventType
    payload: Dict[str, Any]
    event_id: str = field(default_factory=lambda: f"evt_{uuid.uuid4().hex[:12]}")
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "session_id": self.session_id,
            "sequence": self.sequence,
            "type": self.type.value if isinstance(self.type, EventType) else str(self.type),
            "timestamp": self.timestamp,
            "payload": self.payload,
        }
