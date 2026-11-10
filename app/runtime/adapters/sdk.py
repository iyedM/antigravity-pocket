import asyncio
import os
from pathlib import Path
from typing import Dict

from app.core.events import EventType
from app.core.permissions import (
    PermissionMode,
    approval_manager,
    classify_operation,
    is_forbidden_command,
)
from app.runtime.base import AgentAdapter, EventEmitter


class SDKAdapter(AgentAdapter):
    """Adapter for the official `google-antigravity` Python SDK."""

    def __init__(self) -> None:
        self._cancelled: Dict[str, bool] = {}

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
        from google.antigravity import Agent, CapabilitiesConfig, LocalAgentConfig

        self._cancelled[session_id] = False

        if is_forbidden_command(message):
            await emit(
                EventType.SESSION_ERROR,
                {"error": "Opération refusée par la politique de sécurité globale."},
            )
            return

        rules_path = Path.home() / ".gemini" / "GEMINI.md"
        system_instructions = (
            rules_path.read_text(encoding="utf-8", errors="ignore")
            if rules_path.exists()
            else "You are Antigravity Pocket, running inside the user's isolated workspace."
        )

        # In READ_ONLY mode, omit CapabilitiesConfig() so write/exec tools stay disabled
        if permission_mode == PermissionMode.READ_ONLY:
            config = LocalAgentConfig(system_instructions=system_instructions)
        else:
            config = LocalAgentConfig(
                system_instructions=system_instructions,
                capabilities=CapabilitiesConfig(),
            )

        os.chdir(workspace)
        async with Agent(config) as agent:
            response = await agent.chat(message)

            async def _stream_thoughts() -> None:
                if not hasattr(response, "thoughts"):
                    return
                try:
                    async for thought in response.thoughts:
                        if self._cancelled.get(session_id):
                            break
                        await emit(EventType.THOUGHT_DELTA, {"text": str(thought)})
                except Exception:
                    pass

            async def _stream_tools() -> None:
                if not hasattr(response, "tool_calls"):
                    return
                try:
                    async for call in response.tool_calls:
                        if self._cancelled.get(session_id):
                            break
                        tool_name = getattr(call, "name", "tool")
                        tool_args = str(getattr(call, "args", ""))
                        sensitive, risk = classify_operation(tool_name, tool_args)

                        if sensitive and permission_mode == PermissionMode.ASSISTED:
                            req = approval_manager.create_request(
                                session_id=session_id,
                                tool_name=tool_name,
                                command_or_target=tool_args,
                                workspace=workspace,
                                risk_description=risk,
                            )
                            await emit(EventType.APPROVAL_REQUIRED, req.to_dict())
                            approved = await approval_manager.wait_for_decision(req.approval_id)
                            await emit(
                                EventType.APPROVAL_RESOLVED,
                                {"approval_id": req.approval_id, "approved": approved},
                            )
                            if not approved:
                                self._cancelled[session_id] = True
                                await emit(
                                    EventType.SESSION_ERROR,
                                    {"error": f"Action '{tool_name}' refusée par l'utilisateur."},
                                )
                                break

                        await emit(
                            EventType.TOOL_STARTED,
                            {"tool": tool_name, "args": tool_args, "status": "running"},
                        )
                        await emit(
                            EventType.TOOL_COMPLETED,
                            {"tool": tool_name, "status": "completed"},
                        )
                except Exception:
                    pass

            thought_task = asyncio.create_task(_stream_thoughts())
            tool_task = asyncio.create_task(_stream_tools())

            async for token in response:
                if self._cancelled.get(session_id):
                    break
                await emit(EventType.ASSISTANT_MESSAGE, {"delta": str(token)})

            await asyncio.gather(thought_task, tool_task, return_exceptions=True)

    async def cancel(self, session_id: str) -> bool:
        self._cancelled[session_id] = True
        return True

    async def close_session(self, session_id: str) -> None:
        self._cancelled.pop(session_id, None)
