from collections import deque
from datetime import datetime, timezone
from typing import Any, Deque, Dict, List


class NotificationService:
    """In-memory ring buffer for mobile push/badge notifications."""

    def __init__(self, maxlen: int = 100) -> None:
        self._notifications: Deque[Dict[str, Any]] = deque(maxlen=maxlen)

    def push(self, title: str, body: str, level: str = "info", session_id: str = "") -> Dict[str, Any]:
        item = {
            "title": title,
            "body": body,
            "level": level,
            "session_id": session_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        self._notifications.appendleft(item)
        return item

    def list_recent(self, limit: int = 20) -> List[Dict[str, Any]]:
        return list(self._notifications)[:limit]


notification_service = NotificationService()
