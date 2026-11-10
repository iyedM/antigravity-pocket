import asyncio
from pathlib import Path
from typing import Any, Callable, Dict, Optional

from app.core.events import EventType
from app.core.permissions import (
    PermissionMode,
    approval_manager,
    is_forbidden_command,
)
from app.runtime.base import AgentAdapter, EventEmitter


class SDKAdapter(AgentAdapter):
    """
    Adapter for the official `google-antigravity` Python SDK.
    - Never calls `os.chdir()` (safe for concurrent multi-session execution).
    - Enforces a true pre-execution approval gate in ASSISTED mode before
      enabling write/execution capabilities (`CapabilitiesConfig`).
    - Supports dependency injection (`sdk_factory`) for deterministic testing.
    """

    def __init__(self, sdk_factory: Optional[Callable[[Any], Any]] = None) -> None:
        self._cancelled: Dict[str, bool] = {}
        self._sdk_factory = sdk_factory

    async def start_session(
        self,
        session_id: str,
        workspace: str,
        permission_mode: PermissionMode,
    ) -> None:
        self._cancelled[session_id] = False

    async def send_message(
        self,
        session_id: str,
        message: str,
        workspace: str,
        permission_mode: PermissionMode,
        emit: EventEmitter,
    ) -> None:
        self._cancelled[session_id] = False

        if is_forbidden_command(message):
            await emit(
                EventType.SESSION_ERROR,
                {"error": "Opération refusée par la politique de sécurité globale."},
            )
            return

        # Pre-execution gate in ASSISTED mode BEFORE granting CapabilitiesConfig()
        write_capabilities_enabled = False
        if permission_mode == PermissionMode.READ_ONLY:
            write_capabilities_enabled = False
        elif permission_mode == PermissionMode.ASSISTED:
            req = approval_manager.create_request(
                session_id=session_id,
                tool_name="sdk_workspace_execution",
                command_or_target=message[:200],
                workspace=workspace,
                risk_description=(
                    "Autoriser l'agent SDK à modifier des fichiers ou exécuter "
                    f"des outils dans le workspace `{workspace}` ?"
                ),
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
                    {"error": "Exécution refusée par l'utilisateur avant lancement."},
                )
                return
            write_capabilities_enabled = True
        elif permission_mode == PermissionMode.AUTONOMOUS:
            write_capabilities_enabled = True

        rules_path = Path.home() / ".gemini" / "GEMINI.md"
        base_instructions = (
            rules_path.read_text(encoding="utf-8", errors="ignore")
            if rules_path.exists()
            else "You are Antigravity Pocket."
        )
        scoped_instructions = (
            f"{base_instructions}\n"
            f"IMPORTANT: Operate strictly inside workspace directory: {workspace}\n"
            f"Permission mode: {permission_mode.value}"
        )

        if self._sdk_factory is not None:
            agent_cm = self._sdk_factory(
                {
                    "system_instructions": scoped_instructions,
                    "write_enabled": write_capabilities_enabled,
                    "workspace": workspace,
                }
            )
        else:
            from google.antigravity import Agent, CapabilitiesConfig, LocalAgentConfig

            if write_capabilities_enabled:
                config = LocalAgentConfig(
                    system_instructions=scoped_instructions,
                    capabilities=CapabilitiesConfig(),
                )
            else:
                config = LocalAgentConfig(system_instructions=scoped_instructions)
            agent_cm = Agent(config)

        async with agent_cm as agent:
            response = await agent.chat(message)

            async def _stream_tools() -> None:
                if not hasattr(response, "tool_calls"):
                    return
                try:
                    async for call in response.tool_calls:
                        if self._cancelled.get(session_id):
                            break
                        tool_name = getattr(call, "name", "tool")
                        tool_args = str(getattr(call, "args", ""))
                        await emit(
                            EventType.TOOL_STARTED,
                            {"tool": tool_name, "args": tool_args[:200], "status": "running"},
                        )
                        await emit(
                            EventType.TOOL_COMPLETED,
                            {"tool": tool_name, "status": "completed"},
                        )
                except Exception:
                    pass

            tool_task = asyncio.create_task(_stream_tools())

            async for token in response:
                if self._cancelled.get(session_id):
                    break
                await emit(EventType.ASSISTANT_MESSAGE, {"delta": str(token)})

            await asyncio.gather(tool_task, return_exceptions=True)

    async def cancel(self, session_id: str) -> bool:
        self._cancelled[session_id] = True
        return True

    async def close_session(self, session_id: str) -> None:
        self._cancelled.pop(session_id, None)
