from pathlib import Path

from fastapi.testclient import TestClient

from app.core.config import Settings
from app.core.events import EventType
from app.main import create_app


def test_end_to_end_api_and_single_use_ticket_websocket(tmp_path: Path) -> None:
    strong_secret = "9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3b2a1f0e9d8c7b6a5f4e3d2c1b0a9f8e"
    settings = Settings(
        app_password="StrongPassword#2026!",
        secret_key=strong_secret,
        workspace_dir=tmp_path / "ws",
        db_path=tmp_path / "pocket.db",
    )
    app = create_app(custom_settings=settings)
    client = TestClient(app)

    import os
    os.environ["APP_PASSWORD"] = "StrongPassword#2026!"
    os.environ["APP_SECRET_KEY"] = strong_secret
    os.environ["AGY_DB_PATH"] = str(tmp_path / "pocket.db")
    try:
        # 1. All protected endpoints must reject unauthenticated requests
        for endpoint in [
            "/api/v1/sessions",
            "/api/v1/files",
            "/api/v1/approvals",
            "/api/v1/auth/status",
        ]:
            assert client.get(endpoint).status_code == 401

        # 2. Login and obtain signed Bearer token
        login_res = client.post(
            "/api/v1/auth/login", json={"password": "StrongPassword#2026!"}
        )
        assert login_res.status_code == 200
        token = login_res.json()["token"]
        headers = {"Authorization": f"Bearer {token}"}

        # 3. Create session
        create_res = client.post(
            "/api/v1/sessions",
            headers=headers,
            json={"title": "<script>alert(1)</script>", "permission_mode": "read_only"},
        )
        assert create_res.status_code == 200
        session_id = create_res.json()["session"]["session_id"]

        # 4. Pre-populate 2 events in the session
        session_svc = app.state.session_service
        session_svc.append_event(session_id, EventType.SESSION_STARTED, {"ok": True})
        session_svc.append_event(
            session_id, EventType.ASSISTANT_MESSAGE, {"delta": "Premier message"}
        )

        # 5. Request a single-use ephemeral WebSocket ticket (no Bearer token in URL)
        tkt_res = client.post(
            "/api/v1/auth/ticket", headers=headers, json={"purpose": "ws"}
        )
        assert tkt_res.status_code == 200
        ws_ticket = tkt_res.json()["ticket"]

        # 6. Connect WebSocket with single-use ticket and last_seq=1
        with client.websocket_connect(
            f"/ws/sessions/{session_id}?ticket={ws_ticket}&last_seq=1"
        ) as ws:
            replayed = ws.receive_json()
            assert replayed["sequence"] == 2
            assert replayed["type"] == "assistant_message"
            assert replayed["payload"]["delta"] == "Premier message"

        # 7. Reusing the same single-use ticket must fail
        with client.websocket_connect(
            f"/ws/sessions/{session_id}?ticket={ws_ticket}&last_seq=1"
        ) as ws2:
            err_msg = ws2.receive_json()
            assert err_msg["type"] == "session_error"

        # 8. Logout revokes the Bearer token in SQLite
        logout_res = client.post("/api/v1/auth/logout", headers=headers)
        assert logout_res.status_code == 200
        assert client.get("/api/v1/sessions", headers=headers).status_code == 401
    finally:
        os.environ.pop("APP_PASSWORD", None)
        os.environ.pop("APP_SECRET_KEY", None)
        os.environ.pop("AGY_DB_PATH", None)


def test_frontend_contains_no_unsafe_innerhtml_or_url_tokens() -> None:
    """Static security audit verifying index.html has zero innerHTML and zero '?token=' URLs."""
    html_path = Path(__file__).resolve().parent.parent / "app" / "static" / "index.html"
    content = html_path.read_text(encoding="utf-8")
    assert ".innerHTML" not in content
    assert "thought_delta" not in content
    assert "?token=" not in content
