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


def test_sdk_adapter_pre_execution_approval_gate_and_no_chdir(tmp_path: Path) -> None:
    """Proves SDKAdapter blocks execution BEFORE spawning the agent if rejected in ASSISTED mode."""

    class _FakeResponse:
        def __init__(self) -> None:
            self.tool_calls = self._empty_tools()

        async def _empty_tools(self):
            if False:
                yield None

        def __aiter__(self):
            return self._tokens()

        async def _tokens(self):
            yield "Réponse SDK simulée"

    class _FakeAgentCM:
        def __init__(self, cfg: dict, tracker: list) -> None:
            self.cfg = cfg
            self.tracker = tracker

        async def __aenter__(self):
            self.tracker.append(self.cfg)
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def chat(self, msg: str):
            return _FakeResponse()

    async def _run() -> None:
        spawned_configs: list = []
        adapter = SDKAdapter(sdk_factory=lambda cfg: _FakeAgentCM(cfg, spawned_configs))
        emitted: list = []

        async def _emit(ev_type: EventType, payload: dict) -> None:
            emitted.append((ev_type, payload))
            if ev_type == EventType.APPROVAL_REQUIRED:
                # Simulate user REJECTING the operation on mobile
                approval_manager.resolve(payload["approval_id"], approved=False)

        cwd_before = os.getcwd()
        await adapter.send_message(
            session_id="s_reject",
            message="Modifie le fichier main.py",
            workspace=str(tmp_path),
            permission_mode=PermissionMode.ASSISTED,
            emit=_emit,
        )
        assert os.getcwd() == cwd_before
        # Agent must NEVER have been spawned because pre-execution approval was rejected
        assert len(spawned_configs) == 0

        # Now test READ_ONLY mode: spawns with write_enabled=False without asking approval
        await adapter.send_message(
            session_id="s_ro",
            message="Analyse le code",
            workspace=str(tmp_path),
            permission_mode=PermissionMode.READ_ONLY,
            emit=_emit,
        )
        assert len(spawned_configs) == 1
        assert spawned_configs[0]["write_enabled"] is False

    asyncio.run(_run())


def test_cli_adapter_consumes_stderr_and_reports_nonzero_exit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Proves CLIAdapter does not deadlock on large stderr and fails on exit code != 0."""
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


def test_runtime_manager_persists_timeline_events(tmp_path: Path) -> None:
    async def _run() -> None:
        session_svc = SessionService(db_path=tmp_path / "rt.db")
        manager = AgentRuntimeManager(session_service=session_svc, adapter=CLIAdapter())
        sess = session_svc.create_session(
            title="Test Runtime",
            workspace=str(tmp_path),
            permission_mode=PermissionMode.READ_ONLY.value,
        )
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
