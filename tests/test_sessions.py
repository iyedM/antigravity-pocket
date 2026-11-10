from pathlib import Path

from app.core.events import EventType
from app.core.permissions import PermissionMode
from app.services.session_service import SessionService


def test_session_crud_and_event_sequence_replay(tmp_path: Path) -> None:
    db_file = tmp_path / "test_pocket.db"
    service = SessionService(db_path=db_file)

    s1 = service.create_session(
        title="Refactoring API",
        workspace=str(tmp_path),
        permission_mode=PermissionMode.ASSISTED.value,
    )
    assert s1["title"] == "Refactoring API"
    assert s1["permission_mode"] == "assisted"

    s2 = service.create_session(
        title="Audit Sécurité",
        workspace=str(tmp_path),
        permission_mode=PermissionMode.READ_ONLY.value,
    )
    sessions = service.list_sessions()
    assert len(sessions) == 2

    # Append 3 events to s1 and verify monotonic sequence numbering
    e1 = service.append_event(s1["session_id"], EventType.SESSION_STARTED, {"info": "start"})
    e2 = service.append_event(s1["session_id"], EventType.TOOL_STARTED, {"tool": "read_file"})
    e3 = service.append_event(s1["session_id"], EventType.SESSION_COMPLETED, {"ok": True})

    assert e1.sequence == 1
    assert e2.sequence == 2
    assert e3.sequence == 3

    # Replay only events after sequence 1 (simulating mobile WebSocket reconnect)
    missed = service.get_events_since(s1["session_id"], after_sequence=1)
    assert len(missed) == 2
    assert missed[0]["sequence"] == 2
    assert missed[1]["sequence"] == 3

    # Update permission mode & delete
    updated = service.update_permission_mode(s1["session_id"], PermissionMode.AUTONOMOUS.value)
    assert updated is not None and updated["permission_mode"] == "autonomous"

    assert service.delete_session(s2["session_id"]) is True
    assert service.get_session(s2["session_id"]) is None
