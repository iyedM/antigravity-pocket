import asyncio
from collections.abc import Callable
from pathlib import Path
from typing import Any

from app.core.events import EventType
from app.core.permissions import (
    PermissionMode,
    approval_manager,
    is_forbidden_command,
)
from app.runtime.base import AgentAdapter, EventEmitter


class SDKAdapter(AgentAdapter):
    """
    Adapter for the official `google-antigravity` Python SDK (v0.1.23+).
    - Uses `LocalAgentConfig(workspaces=[workspace], capabilities=..., policies=...)`.
    - In READ_ONLY mode: restricts `enabled_tools` to `BuiltinTools.read_only()` and
      enforces `policy.deny_all()` + explicit read-only allowlist.
    - In ASSISTED mode: enforces both a pre-turn gate and granular per-tool
      `policy.safe_defaults(handler=...)` + `policy.workspace_only([workspace])`.
    - Supports true task cancellation via `self._active_sdk_tasks[session_id].cancel()`,
      which unwinds the `async with Agent(config)` context manager immediately.
    """

    def __init__(self, sdk_factory: Callable[[Any], Any] | None = None) -> None:
        self._active_sdk_tasks: dict[str, asyncio.Task] = {}
        self._sdk_factory = sdk_factory

    @staticmethod
    def build_real_sdk_config(
        workspace: str,
        permission_mode: PermissionMode,
        system_instructions: str,
        ask_user_handler: Callable[..., Any],
    ) -> Any:
        from google.antigravity import (
            BuiltinTools,
            CapabilitiesConfig,
            LocalAgentConfig,
            types,
        )
        from google.antigravity.hooks import policy

        ws_root = Path(workspace).resolve()
        known_path_keys = (
            "path",
            "Path",
            "file_path",
            "TargetFile",
            "DirectoryPath",
            "SearchPath",
            "SearchDirectory",
            "Directory",
            "File",
            "Source",
            "Destination",
        )

        def _check_path_invalid(raw_path: str) -> bool:
            if not raw_path or not raw_path.strip() or "\x00" in raw_path:
                return True
            try:
                candidate = (ws_root / raw_path).resolve()
                return not candidate.is_relative_to(ws_root)
            except (OSError, ValueError):
                return True

        def _is_outside_workspace_file_tool(args: dict[str, Any]) -> bool:
            """
            Fail-closed validator for filesystem tools:
            - Denies if `args` is not a non-empty dict or contains no recognized path argument.
            - Denies if any recognized path argument or path-like string resolves outside `ws_root`
              (including indirect symlink escapes or `..` traversal).
            """
            if not isinstance(args, dict) or not args:
                return True
            found_valid_key = False
            for key in known_path_keys:
                if key in args:
                    val = args[key]
                    if not isinstance(val, str) or _check_path_invalid(val):
                        return True
                    found_valid_key = True
            return not found_valid_key

        def _is_outside_workspace_any_tool(args: dict[str, Any]) -> bool:
            if not isinstance(args, dict):
                return False
            for key in known_path_keys:
                if key in args:
                    val = args[key]
                    if not isinstance(val, str) or _check_path_invalid(val):
                        return True
            return False

        guarded_file_tools = sorted(
            {
                *(t.value for t in BuiltinTools.file_tools()),
                "list_directory",
                "search_directory",
                "find_file",
                "write_file",
                "create_file",
                "delete_file",
            }
        )
        file_containment_guards = [
            *(
                policy.deny(
                    tool_name,
                    when=_is_outside_workspace_file_tool,
                    name="enforce_workspace_boundary",
                    reason="Path outside configured workspace or malformed file arguments denied.",
                )
                for tool_name in guarded_file_tools
            ),
            policy.deny(
                "*",
                when=_is_outside_workspace_any_tool,
                name="enforce_workspace_boundary_wildcard",
                reason="Path outside configured workspace is strictly denied.",
            ),
        ]
        forbidden_cmd_guard = policy.deny(
            BuiltinTools.RUN_COMMAND.value,
            when=lambda args: is_forbidden_command(str(args), workspace=workspace),
            name="block_forbidden_command",
            reason="Forbidden destructive or out-of-workspace command blocked by policy.",
        )
        sandboxed_cmd_config = types.RunCommandConfig(
            enable_sandbox=True,
            enable_daemons=False,
            timeout_seconds=120.0,
        )

        if permission_mode == PermissionMode.READ_ONLY:
            ro_tools = BuiltinTools.read_only()
            return LocalAgentConfig(
                system_instructions=system_instructions,
                workspaces=[workspace],
                capabilities=CapabilitiesConfig(enabled_tools=ro_tools),
                policies=[
                    *file_containment_guards,
                    policy.deny_all(),
                    *[policy.allow(t.value) for t in ro_tools],
                ],
            )

        if permission_mode == PermissionMode.ASSISTED:
            return LocalAgentConfig(
                system_instructions=system_instructions,
                workspaces=[workspace],
                capabilities=CapabilitiesConfig(
                    run_command_config=sandboxed_cmd_config
                ),
                policies=[
                    *file_containment_guards,
                    forbidden_cmd_guard,
                    *policy.safe_defaults(handler=ask_user_handler),
                    *policy.workspace_only([workspace]),
                ],
            )

        # PermissionMode.AUTONOMOUS (OS exebox sandbox enabled + workspace containment)
        return LocalAgentConfig(
            system_instructions=system_instructions,
            workspaces=[workspace],
            capabilities=CapabilitiesConfig(
                run_command_config=sandboxed_cmd_config
            ),
            policies=[
                *file_containment_guards,
                forbidden_cmd_guard,
                policy.allow_all(),
                *policy.workspace_only([workspace]),
            ],
        )

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
        if is_forbidden_command(message, workspace=workspace):
            await emit(
                EventType.SESSION_ERROR,
                {"error": "Opération refusée par la politique de sécurité globale."},
            )
            return

        async def _ask_mobile_user_for_tool(
            tool_call: Any, reason: str | None = None
        ) -> bool:
            tool_name = getattr(tool_call, "name", "sdk_tool")
            tool_args = str(getattr(tool_call, "args", ""))
            req = approval_manager.create_request(
                session_id=session_id,
                tool_name=tool_name,
                command_or_target=tool_args[:200],
                workspace=workspace,
                risk_description=reason
                or f"Validation pré-exécution de l'outil SDK '{tool_name}'.",
            )
            await emit(EventType.APPROVAL_REQUIRED, req.to_dict())
            approved = await approval_manager.wait_for_decision(req.approval_id)
            await emit(
                EventType.APPROVAL_RESOLVED,
                {"approval_id": req.approval_id, "approved": approved},
            )
            return approved

        # Pre-turn confirmation in ASSISTED mode before initializing write-capable session
        if permission_mode == PermissionMode.ASSISTED:
            req = approval_manager.create_request(
                session_id=session_id,
                tool_name="sdk_session_turn",
                command_or_target=message[:200],
                workspace=workspace,
                risk_description=(
                    f"Autoriser le lancement de ce tour assisté dans `{workspace}` ?"
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

        async def _execute_sdk_turn() -> None:
            from google.antigravity import Agent
            from google.antigravity.hooks import policy

            config = self.build_real_sdk_config(
                workspace=workspace,
                permission_mode=permission_mode,
                system_instructions=scoped_instructions,
                ask_user_handler=_ask_mobile_user_for_tool,
            )
            policy_hook = policy.enforce(config.policies)

            if self._sdk_factory is not None:
                agent_cm = self._sdk_factory(
                    {
                        "system_instructions": scoped_instructions,
                        "write_enabled": permission_mode != PermissionMode.READ_ONLY,
                        "workspace": workspace,
                        "permission_mode": permission_mode.value,
                        "sdk_config": config,
                        "policy_hook": policy_hook,
                    }
                )
            else:
                agent_cm = Agent(config)

            async with agent_cm as agent:
                response = await agent.chat(message)

                async def _stream_tools() -> None:
                    if not hasattr(response, "tool_calls"):
                        return
                    try:
                        async for call in response.tool_calls:
                            tool_name = getattr(call, "name", "tool")
                            tool_args = str(getattr(call, "args", ""))
                            await emit(
                                EventType.TOOL_STARTED,
                                {
                                    "tool": tool_name,
                                    "args": tool_args[:200],
                                    "status": "running",
                                },
                            )
                            await emit(
                                EventType.TOOL_COMPLETED,
                                {"tool": tool_name, "status": "completed"},
                            )
                    except asyncio.CancelledError:
                        raise
                    except RuntimeError:
                        return

                tool_task = asyncio.create_task(_stream_tools())
                try:
                    async for token in response:
                        await emit(EventType.ASSISTANT_MESSAGE, {"delta": str(token)})
                    await asyncio.gather(tool_task, return_exceptions=True)
                finally:
                    if not tool_task.done():
                        tool_task.cancel()
                        await asyncio.gather(tool_task, return_exceptions=True)

        sdk_task = asyncio.create_task(_execute_sdk_turn())
        self._active_sdk_tasks[session_id] = sdk_task
        try:
            await sdk_task
        finally:
            if self._active_sdk_tasks.get(session_id) is sdk_task:
                self._active_sdk_tasks.pop(session_id, None)

    async def cancel(self, session_id: str) -> bool:
        # Also reject any pending approval request for this session so it unblocks
        for item in approval_manager.list_for_session(session_id):
            if item.get("status") == "pending":
                approval_manager.resolve(item["approval_id"], approved=False)

        sdk_task = self._active_sdk_tasks.get(session_id)
        if sdk_task and not sdk_task.done():
            sdk_task.cancel()
            await asyncio.gather(sdk_task, return_exceptions=True)
            return True
        return False

    async def close_session(self, session_id: str) -> None:
        await self.cancel(session_id)
