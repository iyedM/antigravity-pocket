import asyncio
import pytest

from app.core.permissions import (
    ApprovalManager,
    PermissionMode,
    classify_operation,
    is_forbidden_command,
)
from app.runtime.adapters.cli import CLIAdapter
from app.runtime.manager import AgentRuntimeManager
from app.services.session_service import SessionService


def test_classify_operations() -> None:
    sensitive, _ = classify_operation("read_file", "/workspace/main.py")
    assert sensitive is False

    sensitive_write, _ = classify_operation("write_file", "/workspace/main.py")
    assert sensitive_write is True

    sensitive_cmd, _ = classify_operation("run_command", "pytest -q")
    assert sensitive_cmd is True


def test_forbidden_system_commands_blocked() -> None:
    assert is_forbidden_command("rm -rf /") is True
    assert is_forbidden_command("shutdown -h now") is True
    assert is_forbidden_command("python3 -m pytest") is False


def test_approval_manager_async_workflow() -> None:
    async def _run() -> None:
        manager = ApprovalManager()
        req = manager.create_request(
            session_id="sess_1",
            tool_name="run_command",
            command_or_target="git status",
            workspace="/home/user/workspace",
            risk_description="Exécution d'une commande Git",
        )
        assert req.status == "pending"

        async def _approve_shortly() -> None:
            await asyncio.sleep(0.02)
            manager.resolve(req.approval_id, approved=True)

        asyncio.create_task(_approve_shortly())
        decision = await manager.wait_for_decision(req.approval_id, timeout=1.0)
        assert decision is True
        assert req.status == "approved"

    asyncio.run(_run())


def test_cli_adapter_never_uses_dangerously_skip_permissions() -> None:
    for mode, expected_flag in [
        (PermissionMode.READ_ONLY, "plan"),
        (PermissionMode.ASSISTED, "accept-edits"),
        (PermissionMode.AUTONOMOUS, "auto"),
    ]:
        args = CLIAdapter.build_cli_args("/usr/bin/agy", "/tmp/ws", mode, "test prompt")
        assert "--dangerously-skip-permissions" not in args
        assert "--sandbox" in args
        assert expected_flag in args


def test_runtime_manager_persists_timeline_events(tmp_path) -> None:
    async def _run() -> None:
        session_svc = SessionService(db_path=tmp_path / "rt.db")
        manager = AgentRuntimeManager(session_service=session_svc, adapter=CLIAdapter())
        sess = session_svc.create_session(
            title="Test Runtime",
            workspace=str(tmp_path),
            permission_mode=PermissionMode.READ_ONLY.value,
        )
        # Force diagnostic fallback by hiding 'agy' in PATH temporarily if needed
        import shutil
        orig_which = shutil.which
        shutil.which = lambda _: None
        try:
            await manager.run_turn(sess["session_id"], "Bonjour agent")
        finally:
            shutil.which = orig_which

        events = session_svc.get_events_since(sess["session_id"], 0)
        event_types = [e["type"] for e in events]
        assert "session_started" in event_types
        assert "user_message" in event_types
        assert "assistant_message" in event_types
        assert "session_completed" in event_types

    asyncio.run(_run())
