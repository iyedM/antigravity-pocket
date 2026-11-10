from pathlib import Path
from fastapi.testclient import TestClient

from app.core.config import Settings
from app.core.events import EventType
from app.main import create_app


def test_end_to_end_api_and_websocket_replay(tmp_path: Path) -> None:
    settings = Settings(
        app_password="TestPassword2026!",
        secret_key="0123456789abcdef0123456789abcdef",
        workspace_dir=tmp_path / "ws",
        db_path=tmp_path / "pocket.db",
    )
    app = create_app(custom_settings=settings)
    client = TestClient(app)

    # 1. Unauthenticated request without password should fail if APP_PASSWORD is set
    import os
    os.environ["APP_PASSWORD"] = "TestPassword2026!"
    os.environ["APP_SECRET_KEY"] = "0123456789abcdef0123456789abcdef"
    try:
        unauth = client.get("/api/v1/sessions")
        assert unauth.status_code == 401

        # 2. Login and obtain signed token
        login_res = client.post(
            "/api/v1/auth/login", json={"password": "TestPassword2026!"}
        )
        assert login_res.status_code == 200
        token = login_res.json()["token"]
        headers = {"Authorization": f"Bearer {token}"}

        # 3. Create session
        create_res = client.post(
            "/api/v1/sessions",
            headers=headers,
            json={"title": "Session Mobile iOS", "permission_mode": "read_only"},
        )
        assert create_res.status_code == 200
        session_id = create_res.json()["session"]["session_id"]

        # 4. Pre-populate 2 events in the session
        session_svc = app.state.session_service
        session_svc.append_event(session_id, EventType.SESSION_STARTED, {"ok": True})
        session_svc.append_event(
            session_id, EventType.ASSISTANT_MESSAGE, {"delta": "Premier message"}
        )

        # 5. Connect WebSocket with last_seq=1 and verify it replays sequence 2
        with client.websocket_connect(
            f"/ws/sessions/{session_id}?token={token}&last_seq=1"
        ) as ws:
            replayed = ws.receive_json()
            assert replayed["sequence"] == 2
            assert replayed["type"] == "assistant_message"
            assert replayed["payload"]["delta"] == "Premier message"
    finally:
        os.environ.pop("APP_PASSWORD", None)
        os.environ.pop("APP_SECRET_KEY", None)
