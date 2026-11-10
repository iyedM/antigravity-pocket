import json
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from app.core.config import get_settings
from app.core.events import EventEnvelope, EventType
from app.core.permissions import PermissionMode


class SessionService:
    """SQLite-backed multi-session and numbered event timeline store."""

    def __init__(self, db_path: Optional[Path] = None) -> None:
        self.db_path = db_path or get_settings().db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA foreign_keys=ON;")
        return conn

    def _init_db(self) -> None:
        with self._lock, self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS sessions (
                    session_id TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    workspace TEXT NOT NULL,
                    permission_mode TEXT NOT NULL DEFAULT 'assisted',
                    status TEXT NOT NULL DEFAULT 'idle',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS events (
                    event_id TEXT PRIMARY KEY,
                    session_id TEXT NOT NULL,
                    sequence INTEGER NOT NULL,
                    type TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    FOREIGN KEY(session_id) REFERENCES sessions(session_id) ON DELETE CASCADE,
                    UNIQUE(session_id, sequence)
                );

                CREATE INDEX IF NOT EXISTS idx_events_session_seq
                ON events(session_id, sequence);
                """
            )

    def create_session(
        self,
        title: str = "Nouvelle session",
        workspace: Optional[str] = None,
        permission_mode: str = PermissionMode.ASSISTED.value,
    ) -> Dict[str, Any]:
        settings = get_settings()
        ws = workspace or str(settings.workspace_dir)
        mode = PermissionMode(permission_mode).value
        session_id = f"sess_{uuid.uuid4().hex[:10]}"
        now = datetime.now(timezone.utc).isoformat()

        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO sessions (session_id, title, workspace, permission_mode, status, created_at, updated_at)
                VALUES (?, ?, ?, ?, 'idle', ?, ?)
                """,
                (session_id, title.strip() or "Session", ws, mode, now, now),
            )
        return self.get_session(session_id)  # type: ignore[return-value]

    def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM sessions WHERE session_id = ?", (session_id,)
            ).fetchone()
            return dict(row) if row else None

    def list_sessions(self) -> List[Dict[str, Any]]:
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM sessions ORDER BY updated_at DESC"
            ).fetchall()
            return [dict(r) for r in rows]

    def update_session_status(self, session_id: str, status: str) -> Optional[Dict[str, Any]]:
        now = datetime.now(timezone.utc).isoformat()
        with self._lock, self._connect() as conn:
            conn.execute(
                "UPDATE sessions SET status = ?, updated_at = ? WHERE session_id = ?",
                (status, now, session_id),
            )
        return self.get_session(session_id)

    def update_permission_mode(
        self, session_id: str, permission_mode: str
    ) -> Optional[Dict[str, Any]]:
        mode = PermissionMode(permission_mode).value
        now = datetime.now(timezone.utc).isoformat()
        with self._lock, self._connect() as conn:
            conn.execute(
                "UPDATE sessions SET permission_mode = ?, updated_at = ? WHERE session_id = ?",
                (mode, now, session_id),
            )
        return self.get_session(session_id)

    def delete_session(self, session_id: str) -> bool:
        with self._lock, self._connect() as conn:
            cur = conn.execute(
                "DELETE FROM sessions WHERE session_id = ?", (session_id,)
            )
            return cur.rowcount > 0

    def append_event(
        self,
        session_id: str,
        event_type: EventType,
        payload: Dict[str, Any],
    ) -> EventEnvelope:
        now = datetime.now(timezone.utc).isoformat()
        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT COALESCE(MAX(sequence), 0) AS max_seq FROM events WHERE session_id = ?",
                (session_id,),
            ).fetchone()
            next_seq = int(row["max_seq"]) + 1 if row else 1
            envelope = EventEnvelope(
                session_id=session_id,
                sequence=next_seq,
                type=event_type,
                payload=payload,
                timestamp=now,
            )
            conn.execute(
                """
                INSERT INTO events (event_id, session_id, sequence, type, timestamp, payload_json)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    envelope.event_id,
                    envelope.session_id,
                    envelope.sequence,
                    envelope.type.value,
                    envelope.timestamp,
                    json.dumps(envelope.payload, ensure_ascii=False),
                ),
            )
            conn.execute(
                "UPDATE sessions SET updated_at = ? WHERE session_id = ?",
                (now, session_id),
            )
        return envelope

    def get_events_since(
        self, session_id: str, after_sequence: int = 0
    ) -> List[Dict[str, Any]]:
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                """
                SELECT event_id, session_id, sequence, type, timestamp, payload_json
                FROM events
                WHERE session_id = ? AND sequence > ?
                ORDER BY sequence ASC
                """,
                (session_id, after_sequence),
            ).fetchall()
            result = []
            for r in rows:
                result.append(
                    {
                        "event_id": r["event_id"],
                        "session_id": r["session_id"],
                        "sequence": r["sequence"],
                        "type": r["type"],
                        "timestamp": r["timestamp"],
                        "payload": json.loads(r["payload_json"]),
                    }
                )
            return result
