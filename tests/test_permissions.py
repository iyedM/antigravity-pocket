import asyncio
import pytest

from app.core.permissions import (
    ApprovalManager,
    PermissionMode,
    classify_operation,
    is_forbidden_command,
)


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
