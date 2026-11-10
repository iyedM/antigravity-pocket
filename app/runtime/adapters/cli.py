import asyncio
import os
import shutil
import signal
from typing import Dict, Optional

from app.core.config import get_settings
from app.core.events import EventType
from app.core.permissions import (
    PermissionMode,
    approval_manager,
    is_forbidden_command,
)
from app.runtime.base import AgentAdapter, EventEmitter

MAX_CLI_OUTPUT_BYTES = 512 * 1024  # 512 KB output cap per turn


class CLIAdapter(AgentAdapter):
    """
    Adapter for the `agy` CLI binary.
    - Never uses `--dangerously-skip-permissions`.
    - Enforces pre-execution approval gate in ASSISTED mode.
    - Reads stdout and stderr concurrently to prevent pipe deadlocks.
    - Enforces process group termination (`os.killpg`), timeout, and exit code check.
    """

    def __init__(self, timeout_seconds: Optional[float] = None) -> None:
        self._processes: Dict[str, asyncio.subprocess.Process] = {}
        self._timeout = timeout_seconds

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

        # Pre-execution approval gate in ASSISTED mode before spawning subprocess
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
            start_new_session=True,
        )
        self._processes[session_id] = proc
        stderr_chunks: list[bytes] = []
        total_bytes = 0

        async def _consume_stdout() -> None:
            nonlocal total_bytes
            assert proc.stdout is not None
            while True:
                chunk = await proc.stdout.read(512)
                if not chunk:
                    break
                total_bytes += len(chunk)
                if total_bytes <= MAX_CLI_OUTPUT_BYTES:
                    await emit(
                        EventType.ASSISTANT_MESSAGE,
                        {"delta": chunk.decode("utf-8", errors="replace")},
                    )

        async def _consume_stderr() -> None:
            assert proc.stderr is not None
            while True:
                chunk = await proc.stderr.read(512)
                if not chunk:
                    break
                if sum(len(c) for c in stderr_chunks) < 32768:
                    stderr_chunks.append(chunk)

        timeout = (
            self._timeout
            if self._timeout is not None
            else get_settings().cli_timeout_seconds
        )

        try:
            await asyncio.wait_for(
                asyncio.gather(_consume_stdout(), _consume_stderr(), proc.wait()),
                timeout=timeout,
            )
        except asyncio.TimeoutError:
            await self.cancel(session_id)
            raise RuntimeError(
                f"Délai d'exécution CLI dépassé ({timeout}s). Processus arrêté."
            )
        finally:
            self._processes.pop(session_id, None)

        if proc.returncode != 0:
            err_text = b"".join(stderr_chunks).decode("utf-8", errors="replace").strip()
            await emit(
                EventType.TOOL_COMPLETED,
                {"tool": "agy_cli", "exit_code": proc.returncode, "status": "failed"},
            )
            raise RuntimeError(
                f"Le processus CLI s'est terminé avec le code {proc.returncode}"
                + (f" : {err_text[:300]}" if err_text else ".")
            )

        await emit(
            EventType.TOOL_COMPLETED,
            {"tool": "agy_cli", "exit_code": 0, "status": "completed"},
        )

    async def cancel(self, session_id: str) -> bool:
        proc = self._processes.get(session_id)
        if not proc or proc.returncode is not None:
            return False
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        except ProcessLookupError:
            return False
        except Exception:
            proc.terminate()
        try:
            await asyncio.wait_for(proc.wait(), timeout=2.0)
        except asyncio.TimeoutError:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except Exception:
                proc.kill()
        return True

    async def close_session(self, session_id: str) -> None:
        await self.cancel(session_id)
