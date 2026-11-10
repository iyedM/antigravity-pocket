import asyncio
import shutil
from typing import Dict

from app.core.events import EventType
from app.core.permissions import (
    PermissionMode,
    approval_manager,
     is_forbidden_command,
)
from app.runtime.base import AgentAdapter, EventEmitter


class CLIAdapter(AgentAdapter):
    """
    Adapter for the `agy` CLI binary.
    Never uses `--dangerously-skip-permissions`.
    Enforces `--sandbox` and maps PermissionMode to `--mode (plan|accept-edits|auto)`.
    """

    def __init__(self) -> None:
        self._processes: Dict[str, asyncio.subprocess.Process] = {}

    @staticmethod
    def build_cli_args(
        agy_bin: str,
        workspace: str,
        permission_mode: PermissionMode,
        prompt: str,
    ) -> list[str]:
        mode_map = {
            PermissionMode.READ_ONLY: "plan",
            PermissionMode.ASSISTED: "accept-edits",
            PermissionMode.AUTONOMOUS: "auto",
        }
        cli_mode = mode_map.get(permission_mode, "plan")
        return [
            agy_bin,
            "--print",
            "--sandbox",
            "--mode",
            cli_mode,
            "--add-dir",
            workspace,
            prompt,
        ]

    async def start_session(
        self,
        session_id: str,
        workspace: str,
        permission_mode: PermissionMode,
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
        if is_forbidden_command(message):
            await emit(
                EventType.SESSION_ERROR,
                {"error": "Instruction bloquée par la politique de sécurité."},
            )
            return

        # In ASSISTED mode, ask mobile confirmation before running write/exec CLI mode
        if permission_mode == PermissionMode.ASSISTED:
            req = approval_manager.create_request(
                session_id=session_id,
                tool_name="agy_cli_turn",
                command_or_target=message[:200],
                workspace=workspace,
                risk_description="Exécution assistée dans le sandbox du workspace.",
            )
            await emit(EventType.APPROVAL_REQUIRED, req.to_dict())
            approved = await approval_manager.wait_for_decision(req.approval_id)
            await emit(
                EventType.APPROVAL_RESOLVED,
                {"approval_id": req.approval_id, "approved": approved},
            )
            if not approved:
                await emit(
                    EventType.SESSION_ERROR,
                    {"error": "Exécution annulée par l'utilisateur depuis le mobile."},
                )
                return

        agy_bin = shutil.which("agy")
        if not agy_bin:
            # Diagnostic fallback if neither SDK nor CLI binary is installed in test environment
            await emit(
                EventType.TOOL_STARTED,
                {"tool": "workspace_diagnostic", "status": "running"},
            )
            await emit(
                EventType.TOOL_COMPLETED,
                {"tool": "workspace_diagnostic", "status": "completed"},
            )
            await emit(
                EventType.ASSISTANT_MESSAGE,
                {
                    "delta": (
                        f"[Mode Diagnostic ({permission_mode.value})] "
                        f"Message reçu dans `{workspace}` : {message}"
                    )
                },
            )
            return

        cmd = self.build_cli_args(agy_bin, workspace, permission_mode, message)
        await emit(
            EventType.TOOL_STARTED,
            {"tool": "agy_cli", "mode": permission_mode.value, "status": "running"},
        )

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            cwd=workspace,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        self._processes[session_id] = proc

        try:
            assert proc.stdout is not None
            while True:
                chunk = await proc.stdout.read(256)
                if not chunk:
                    break
                await emit(
                    EventType.ASSISTANT_MESSAGE,
                    {"delta": chunk.decode("utf-8", errors="replace")},
                )
            await proc.wait()
            await emit(
                EventType.TOOL_COMPLETED,
                {"tool": "agy_cli", "exit_code": proc.returncode, "status": "completed"},
            )
        finally:
            self._processes.pop(session_id, None)

    async def cancel(self, session_id: str) -> bool:
        proc = self._processes.get(session_id)
        if proc and proc.returncode is None:
            proc.terminate()
            return True
        return False

    async def close_session(self, session_id: str) -> None:
        await self.cancel(session_id)
