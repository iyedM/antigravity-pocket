import asyncio
import os
from pathlib import Path

import pytest

from app.core.events import EventType
from app.core.permissions import (
    ApprovalManager,
    PermissionMode,
    approval_manager,
    classify_operation,
    is_forbidden_command,
)
from app.runtime.adapters.cli import CLIAdapter
from app.runtime.adapters.sdk import SDKAdapter
from app.runtime.base import AgentAdapter, EventEmitter
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


def test_real_google_antigravity_sdk_config_policies(tmp_path: Path) -> None:
    """Validates SDKAdapter.build_real_sdk_config against the real google-antigravity SDK."""
    from google.antigravity import BuiltinTools

    async def _dummy_handler(tc, reason=""):
        return True

    ro_cfg = SDKAdapter.build_real_sdk_config(
        workspace=str(tmp_path),
        permission_mode=PermissionMode.READ_ONLY,
        system_instructions="Test RO",
        ask_user_handler=_dummy_handler,
    )
    assert ro_cfg.workspaces == [str(tmp_path)]
    assert set(ro_cfg.capabilities.enabled_tools) == set(BuiltinTools.read_only())
    assert BuiltinTools.RUN_COMMAND not in ro_cfg.capabilities.enabled_tools
    assert BuiltinTools.EDIT_FILE not in ro_cfg.capabilities.enabled_tools

    assisted_cfg = SDKAdapter.build_real_sdk_config(
        workspace=str(tmp_path),
        permission_mode=PermissionMode.ASSISTED,
        system_instructions="Test Assisted",
        ask_user_handler=_dummy_handler,
    )
    assert assisted_cfg.workspaces == [str(tmp_path)]
    assert len(assisted_cfg.policies) > 0


def test_sdk_adapter_pre_execution_gate_and_real_task_cancellation(
    tmp_path: Path,
) -> None:
    """Proves SDKAdapter blocks rejected turns and truly cancels an active slow SDK turn."""

    class _SlowResponse:
        def __aiter__(self):
            return self._tokens()

        async def _tokens(self):
            yield "Début..."
            await asyncio.sleep(10.0)
            yield "Fin jamais atteinte"

    class _FakeAgentCM:
        def __init__(self, cfg: dict, tracker: list) -> None:
            self.cfg = cfg
            self.tracker = tracker
            self.exited = False

        async def __aenter__(self):
            self.tracker.append(self)
            return self

        async def __aexit__(self, exc_type, exc, tb):
            self.exited = True
            return False

        async def chat(self, msg: str):
            return _SlowResponse()

    async def _run() -> None:
        spawned: list = []
        adapter = SDKAdapter(sdk_factory=lambda cfg: _FakeAgentCM(cfg, spawned))
        emitted: list = []

        async def _emit(ev_type: EventType, payload: dict) -> None:
            emitted.append((ev_type, payload))
            if ev_type == EventType.APPROVAL_REQUIRED:
                approval_manager.resolve(payload["approval_id"], approved=False)

        cwd_before = os.getcwd()
        await adapter.send_message(
            session_id="s_reject",
            message="Modifie main.py",
            workspace=str(tmp_path),
            permission_mode=PermissionMode.ASSISTED,
            emit=_emit,
        )
        assert os.getcwd() == cwd_before
        assert len(spawned) == 0

        # Now start a slow READ_ONLY turn and cancel it mid-flight
        turn_task = asyncio.create_task(
            adapter.send_message(
                session_id="s_cancel",
                message="Longue analyse",
                workspace=str(tmp_path),
                permission_mode=PermissionMode.READ_ONLY,
                emit=_emit,
            )
        )
        await asyncio.sleep(0.05)
        assert len(spawned) == 1
        cancelled = await adapter.cancel("s_cancel")
        assert cancelled is True
        await asyncio.gather(turn_task, return_exceptions=True)
        # Context manager __aexit__ must have been called upon cancellation
        assert spawned[0].exited is True

    asyncio.run(_run())


def test_replace_running_task_cancels_old_and_completes_new(tmp_path: Path) -> None:
    """Proves Point D fix: replacing an active turn cancels ONLY the old turn and completes the new turn."""

    class _ControllableAdapter(AgentAdapter):
        def __init__(self) -> None:
            self.completed_prompts: list[str] = []

        async def start_session(self, session_id: str, workspace: str, permission_mode: PermissionMode) -> None:
            pass

        async def send_message(
            self,
            session_id: str,
            message: str,
            workspace: str,
            permission_mode: PermissionMode,
            emit: EventEmitter,
        ) -> None:
            if message == "SLOW_FIRST_TURN":
                await asyncio.sleep(10.0)
            await emit(EventType.ASSISTANT_MESSAGE, {"delta": f"Done:{message}"})
            self.completed_prompts.append(message)

        async def cancel(self, session_id: str) -> bool:
            return True

        async def close_session(self, session_id: str) -> None:
            pass

    async def _run() -> None:
        session_svc = SessionService(db_path=tmp_path / "replace.db")
        adapter = _ControllableAdapter()
        manager = AgentRuntimeManager(session_service=session_svc, adapter=adapter)
        sess = session_svc.create_session(
            title="Test Replace",
            workspace=str(tmp_path),
            permission_mode=PermissionMode.READ_ONLY.value,
        )
        sid = sess["session_id"]

        # Start slow first turn
        t1 = manager.start_background_turn(sid, "SLOW_FIRST_TURN")
        await asyncio.sleep(0.05)
        assert not t1.done()

        # Replace with fast second turn while t1 is running
        t2 = manager.start_background_turn(sid, "FAST_SECOND_TURN")
        await asyncio.wait_for(t2, timeout=2.0)

        assert t1.done()
        assert adapter.completed_prompts == ["FAST_SECOND_TURN"]
        final_session = session_svc.get_session(sid)
        assert final_session is not None and final_session["status"] == "completed"

    asyncio.run(_run())


def test_cli_adapter_consumes_stderr_and_reports_nonzero_exit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake_agy = tmp_path / "fake_agy.sh"
    fake_agy.write_text(
        "#!/usr/bin/env bash\n"
        "python3 -c 'import sys; sys.stderr.write(\"E\" * 70000 + \"\\n\"); sys.exit(2)'\n",
        encoding="utf-8",
    )
    fake_agy.chmod(0o755)
    monkeypatch.setattr("shutil.which", lambda _: str(fake_agy))

    async def _run() -> None:
        adapter = CLIAdapter(timeout_seconds=5.0)
        events: list = []

        async def _emit(ev_type: EventType, payload: dict) -> None:
            events.append((ev_type, payload))

        with pytest.raises(RuntimeError, match="code 2"):
            await adapter.send_message(
                session_id="s_cli_err",
                message="run",
                workspace=str(tmp_path),
                permission_mode=PermissionMode.READ_ONLY,
                emit=_emit,
            )

    asyncio.run(_run())
