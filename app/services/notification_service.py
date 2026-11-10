from collections import deque
from datetime import UTC, datetime
from typing import Any


class NotificationService:
    """In-memory ring buffer for mobile push/badge notifications."""

    def __init__(self, maxlen: int = 100) -> None:
        self._notifications: deque[dict[str, Any]] = deque(maxlen=maxlen)

    def push(self, title: str, body: str, level: str = "info", session_id: str = "") -> dict[str, Any]:
        item = {
            "title": title,
            "body": body,
            "level": level,
            "session_id": session_id,
            "timestamp": datetime.now(UTC).isoformat(),
        }
        self._notifications.appendleft(item)
        return item

    def list_recent(self, limit: int = 20) -> list[dict[str, Any]]:
        return list(self._notifications)[:limit]


notification_service = NotificationService()
