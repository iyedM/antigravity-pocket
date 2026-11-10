import asyncio
import re
import shlex
import threading
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path


class PermissionMode(str, Enum):
    """Three-tier permission model for remote agent control."""

    READ_ONLY = "read_only"
    ASSISTED = "assisted"
    AUTONOMOUS = "autonomous"


FORBIDDEN_PATTERNS = (
    "rm -rf /",
    "rm -fr /",
    "--no-preserve-root",
    "mkfs",
    "shutdown",
    "reboot",
    ":(){ :|:& };:",
    "dd if=",
    "> /dev/sd",
    "> /dev/nvme",
    "/etc/shadow",
    "/etc/passwd",
    "/.ssh/",
    "~/.ssh",
)

FORBIDDEN_REGEXES = (
    re.compile(r"\brm\s+(-[a-zA-Z]*[rf][a-zA-Z]*\s+)+/(\*|\s|$)", re.IGNORECASE),
    re.compile(r"\b(curl|wget)\b.*\|\s*(ba)?sh\b", re.IGNORECASE),
    re.compile(r"\bchmod\s+(-r\s+)?777\s+/(\*|\s|$)", re.IGNORECASE),
    re.compile(r"\bfind\s+/\s+.*-delete\b", re.IGNORECASE),
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


def is_forbidden_command(
    command_or_args: str, workspace: str | None = None
) -> bool:
    """
    Evaluates a command or serialized tool argument string against:
    1. Known destructive command signatures and regexes (flag permutations, pipe-to-shell).
    2. Workspace path containment (blocks `..` traversal or absolute paths outside `workspace`).
    """
    lowered = command_or_args.lower()
    if any(pat in lowered for pat in FORBIDDEN_PATTERNS):
        return True
    if any(rx.search(lowered) for rx in FORBIDDEN_REGEXES):
        return True

    if workspace:
        ws_root = Path(workspace).resolve()
        try:
            tokens = shlex.split(command_or_args, posix=True)
        except ValueError:
            tokens = command_or_args.split()

        for tok in tokens:
            cleaned = tok.strip("\"',;()[]{}")
            if not cleaned or cleaned.startswith("-"):
                continue
            if ".." in Path(cleaned).parts:
                candidate = (ws_root / cleaned).resolve()
                if not candidate.is_relative_to(ws_root):
                    return True
            elif cleaned.startswith("/") and len(cleaned) > 1:
                # Allow standard read-only system binary prefixes (/usr/bin, /bin, /dev/null)
                if cleaned.startswith(("/usr/bin/", "/bin/", "/usr/local/bin/", "/dev/null")):
                    continue
                candidate = Path(cleaned).resolve()
                if not candidate.is_relative_to(ws_root):
                    return True

    return False


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
    """Thread-safe, atomic approval state machine bounded against memory exhaustion."""

    MAX_TRACKED_APPROVALS = 1024

    def __init__(self) -> None:
        self._pending: dict[str, ApprovalRequest] = {}
        self._lock = threading.Lock()

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
        with self._lock:
            if len(self._pending) >= self.MAX_TRACKED_APPROVALS:
                # Evict oldest already-resolved entry first, else oldest entry
                resolved_keys = [
                    k for k, v in self._pending.items() if v.status != "pending"
                ]
                victim = (
                    resolved_keys[0]
                    if resolved_keys
                    else next(iter(self._pending))
                )
                self._pending.pop(victim, None)
            self._pending[req.approval_id] = req
        return req

    def resolve(
        self,
        approval_id: str,
        approved: bool,
        expected_session_id: str | None = None,
    ) -> ApprovalRequest | None:
        with self._lock:
            req = self._pending.get(approval_id)
            if not req:
                return None
            if expected_session_id is not None and req.session_id != expected_session_id:
                raise PermissionError(
                    f"Accès refusé : l'approbation {approval_id} appartient à une autre session."
                )
            if req.status != "pending":
                return None
            req.status = "approved" if approved else "rejected"
            req.resolved_at = datetime.now(UTC).isoformat()
            req._event.set()
            return req

    async def wait_for_decision(self, approval_id: str, timeout: float = 300.0) -> bool:
        with self._lock:
            req = self._pending.get(approval_id)
        if not req:
            return False
        try:
            await asyncio.wait_for(req._event.wait(), timeout=timeout)
        except TimeoutError:
            pass
        with self._lock:
            if req.status == "pending":
                req.status = "rejected"
                req.resolved_at = datetime.now(UTC).isoformat()
            return req.status == "approved"

    def list_for_session(self, session_id: str | None = None) -> list[dict]:
        with self._lock:
            items = list(self._pending.values())
            if session_id:
                items = [r for r in items if r.session_id == session_id]
            return [r.to_dict() for r in items]


approval_manager = ApprovalManager()
