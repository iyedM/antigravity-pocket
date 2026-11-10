import mimetypes
from pathlib import Path
from typing import Any, Dict, List, Optional

from app.core.config import get_settings

PREVIEWABLE_EXTENSIONS = {
    ".py",
    ".js",
    ".ts",
    ".tsx",
    ".jsx",
    ".json",
    ".md",
    ".txt",
    ".sh",
    ".yml",
    ".yaml",
    ".toml",
    ".html",
    ".css",
    ".sql",
    ".csv",
    ".log",
    ".xml",
}


class WorkspaceSecurityError(PermissionError):
    """Raised when a path violates workspace isolation or symlink rules."""


class WorkspaceService:
    """Secure bidirectional workspace file manager with anti-traversal & symlink guards."""

    def __init__(
        self,
        workspace_root: Optional[Path] = None,
        max_upload_bytes: Optional[int] = None,
        max_workspace_bytes: Optional[int] = None,
    ) -> None:
        settings = get_settings()
        self.root = (workspace_root or settings.workspace_dir).resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self.max_upload_bytes = (
            max_upload_bytes if max_upload_bytes is not None else settings.max_upload_bytes
        )
        self.max_workspace_bytes = (
            max_workspace_bytes
            if max_workspace_bytes is not None
            else settings.max_workspace_bytes
        )

    def resolve_safe_path(self, relative_path: str = "") -> Path:
        """
        Resolves a relative path inside the workspace while strictly blocking:
        - Path traversal ('..', absolute paths outside root)
        - Symbolic links anywhere along the path
        """
        clean_rel = relative_path.strip().lstrip("/")
        candidate = self.root / clean_rel

        # Check every component from root to candidate for symlinks before resolving
        current = self.root
        if clean_rel:
            for part in Path(clean_rel).parts:
                if part in ("..", "."):
                    raise WorkspaceSecurityError("Navigation '..' interdite dans le workspace.")
                current = current / part
                if current.is_symlink():
                    raise WorkspaceSecurityError("Les liens symboliques (symlinks) sont interdits.")

        resolved = candidate.resolve()
        if not resolved.is_relative_to(self.root):
            raise WorkspaceSecurityError("Tentative d'accès hors du workspace bloquée (Path Traversal).")

        return resolved

    def list_files(self, subpath: str = "") -> List[Dict[str, Any]]:
        target_dir = self.resolve_safe_path(subpath)
        if not target_dir.exists() or not target_dir.is_dir():
            raise FileNotFoundError("Dossier introuvable dans le workspace.")

        items: List[Dict[str, Any]] = []
        for entry in sorted(target_dir.iterdir(), key=lambda p: (not p.is_dir(), p.name.lower())):
            if entry.name.startswith(".") or entry.is_symlink():
                continue
            rel = entry.relative_to(self.root)
            stat = entry.stat()
            ext = entry.suffix.lower()
            items.append(
                {
                    "name": entry.name,
                    "path": str(rel),
                    "is_dir": entry.is_dir(),
                    "size": 0 if entry.is_dir() else stat.st_size,
                    "mtime": int(stat.st_mtime),
                    "previewable": (not entry.is_dir()) and (ext in PREVIEWABLE_EXTENSIONS),
                    "mime": mimetypes.guess_type(entry.name)[0] or "application/octet-stream",
                }
            )
        return items

    def save_upload(self, filename: str, content: bytes, subpath: str = "") -> Dict[str, Any]:
        if len(content) > self.max_upload_bytes:
            raise ValueError(
                f"Fichier trop volumineux ({len(content)} octets). Maximum autorisé : {self.max_upload_bytes} octets."
            )
        safe_name = Path(filename).name
        if not safe_name or safe_name.startswith(".") or safe_name in (".", ".."):
            raise WorkspaceSecurityError("Nom de fichier invalide ou interdit.")

        target_dir = self.resolve_safe_path(subpath)
        target_dir.mkdir(parents=True, exist_ok=True)
        dest = self.resolve_safe_path(str(Path(subpath) / safe_name) if subpath else safe_name)

        dest.write_bytes(content)
        return {
            "name": safe_name,
            "path": str(dest.relative_to(self.root)),
            "size": len(content),
        }

    def preview_file(self, relative_path: str, max_bytes: int = 65536) -> Dict[str, Any]:
        target = self.resolve_safe_path(relative_path)
        if not target.is_file():
            raise FileNotFoundError("Fichier introuvable.")

        ext = target.suffix.lower()
        size = target.stat().st_size
        mime = mimetypes.guess_type(target.name)[0] or "application/octet-stream"

        if ext not in PREVIEWABLE_EXTENSIONS and not mime.startswith("text/"):
            return {
                "name": target.name,
                "path": str(target.relative_to(self.root)),
                "size": size,
                "mime": mime,
                "previewable": False,
                "content": None,
                "truncated": False,
            }

        raw = target.read_bytes()[:max_bytes]
        text = raw.decode("utf-8", errors="replace")
        return {
            "name": target.name,
            "path": str(target.relative_to(self.root)),
            "size": size,
            "mime": mime,
            "previewable": True,
            "content": text,
            "truncated": size > max_bytes,
        }
