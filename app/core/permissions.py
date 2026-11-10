import asyncio
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum


class PermissionMode(str, Enum):
    """Three-tier permission model for remote agent control."""

    READ_ONLY = "read_only"
    ASSISTED = "assisted"
    AUTONOMOUS = "autonomous"


FORBIDDEN_PATTERNS = (
    "rm -rf /",
    "mkfs",
    "shutdown",
    "reboot",
    ":(){ :|:& };:",
    "dd if=",
    "> /dev/sd",
)

WRITE_OR_EXEC_TOOLS = {
    "run_command",
    "write_file",
    "edit_file",
    "delete_file",
    "bash",
    "shell",
    "execute",
}


def is_forbidden_command(command_or_args: str) -> bool:
    lowered = command_or_args.lower()
    return any(pat in lowered for pat in FORBIDDEN_PATTERNS)


def classify_operation(tool_name: str, args_summary: str) -> tuple[bool, str]:
    """
    Returns (is_sensitive, risk_description).
    Read-only tools (read_file, list_files, search) are non-sensitive.
    Write/execution tools are sensitive and require policy evaluation.
    """
    if is_forbidden_command(args_summary):
        return True, "Commande système critique bloquée par la politique de sécurité."

    normalized = tool_name.lower()
    if normalized in WRITE_OR_EXEC_TOOLS or "write" in normalized or "exec" in normalized or "cmd" in normalized:
        return True, f"Exécution de l'opération '{tool_name}' sur le workspace ({args_summary[:120]})"

    return False, "Opération de lecture ou diagnostic sans modification."


@dataclass
class ApprovalRequest:
    approval_id: str
    session_id: str
    tool_name: str
    command_or_target: str
    workspace: str
    risk_description: str
    status: str = "pending"  # pending | approved | rejected
    created_at: str = field(
        default_factory=lambda: datetime.now(UTC).isoformat()
    )
    resolved_at: str | None = None
    _event: asyncio.Event = field(default_factory=asyncio.Event, repr=False)

    def to_dict(self) -> dict:
        return {
            "approval_id": self.approval_id,
            "session_id": self.session_id,
            "tool_name": self.tool_name,
            "command_or_target": self.command_or_target,
            "workspace": self.workspace,
            "risk_description": self.risk_description,
            "status": self.status,
            "created_at": self.created_at,
            "resolved_at": self.resolved_at,
        }


class ApprovalManager:
    """Manages pending mobile approval cards and policy checks per session."""

    def __init__(self) -> None:
        self._pending: dict[str, ApprovalRequest] = {}

    def create_request(
        self,
        session_id: str,
        tool_name: str,
        command_or_target: str,
        workspace: str,
        risk_description: str,
    ) -> ApprovalRequest:
        req = ApprovalRequest(
            approval_id=f"apr_{uuid.uuid4().hex[:10]}",
            session_id=session_id,
            tool_name=tool_name,
            command_or_target=command_or_target,
            workspace=workspace,
            risk_description=risk_description,
        )
        self._pending[req.approval_id] = req
        return req

    def resolve(self, approval_id: str, approved: bool) -> ApprovalRequest | None:
        req = self._pending.get(approval_id)
        if not req:
            return None
        req.status = "approved" if approved else "rejected"
        req.resolved_at = datetime.now(UTC).isoformat()
        req._event.set()
        return req

    async def wait_for_decision(self, approval_id: str, timeout: float = 300.0) -> bool:
        req = self._pending.get(approval_id)
        if not req:
            return False
        try:
            await asyncio.wait_for(req._event.wait(), timeout=timeout)
            return req.status == "approved"
        except TimeoutError:
            req.status = "rejected"
            req.resolved_at = datetime.now(UTC).isoformat()
            return False

    def list_for_session(self, session_id: str | None = None) -> list[dict]:
        items = list(self._pending.values())
        if session_id:
            items = [r for r in items if r.session_id == session_id]
        return [r.to_dict() for r in items]


approval_manager = ApprovalManager()
