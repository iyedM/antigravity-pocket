import errno
import mimetypes
import os
import stat as stat_mod
import tempfile
from collections.abc import AsyncIterator, Iterator
from pathlib import Path
from typing import Any

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


class WorkspaceCollisionError(FileExistsError):
    """Raised when an upload collides with an existing file and overwrite=False."""


class WorkspaceService:
    """
    Secure bidirectional workspace file manager with:
    - Canonical path resolution & anti-traversal
    - Strict symlink rejection & TOCTOU O_NOFOLLOW verification
    - Atomic file writing via temporary file + `os.replace`
    - Chunked streaming upload & total workspace storage quota
    - Explicit overwrite collision policy
    """

    def __init__(
        self,
        workspace_root: Path | None = None,
        max_upload_bytes: int | None = None,
        max_workspace_bytes: int | None = None,
    ) -> None:
        settings = get_settings()
        self.root = (workspace_root or settings.workspace_dir).resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self.max_upload_bytes = (
            max_upload_bytes
            if max_upload_bytes is not None
            else settings.max_upload_bytes
        )
        self.max_workspace_bytes = (
            max_workspace_bytes
            if max_workspace_bytes is not None
            else settings.max_workspace_bytes
        )

    def get_total_workspace_usage(self) -> int:
        total = 0
        for entry in self.root.rglob("*"):
            if not entry.is_symlink() and entry.is_file():
                try:
                    total += entry.stat().st_size
                except OSError:
                    pass
        return total

    def resolve_safe_path(self, relative_path: str = "") -> Path:
        """
        Resolves a relative path inside the workspace while strictly blocking:
        - Path traversal ('..', absolute paths outside root)
        - Symbolic links anywhere along the path
        """
        clean_rel = relative_path.strip().lstrip("/")
        candidate = self.root / clean_rel

        current = self.root
        if clean_rel:
            for part in Path(clean_rel).parts:
                if part in ("..", "."):
                    raise WorkspaceSecurityError(
                        "Navigation '..' interdite dans le workspace."
                    )
                current = current / part
                if current.is_symlink():
                    raise WorkspaceSecurityError(
                        "Les liens symboliques (symlinks) sont interdits."
                    )

        resolved = candidate.resolve()
        if not resolved.is_relative_to(self.root):
            raise WorkspaceSecurityError(
                "Tentative d'accès hors du workspace bloquée (Path Traversal)."
            )

        return resolved

    def list_files(self, subpath: str = "") -> list[dict[str, Any]]:
        target_dir = self.resolve_safe_path(subpath)
        if not target_dir.exists() or not target_dir.is_dir():
            raise FileNotFoundError("Dossier introuvable dans le workspace.")

        items: list[dict[str, Any]] = []
        for entry in sorted(
            target_dir.iterdir(), key=lambda p: (not p.is_dir(), p.name.lower())
        ):
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
                    "previewable": (not entry.is_dir())
                    and (ext in PREVIEWABLE_EXTENSIONS),
                    "mime": mimetypes.guess_type(entry.name)[0]
                    or "application/octet-stream",
                }
            )
        return items

    def _prepare_upload_destination(
        self, filename: str, subpath: str, overwrite: bool
    ) -> tuple[Path, Path, str]:
        safe_name = Path(filename).name
        if not safe_name or safe_name.startswith(".") or safe_name in (".", ".."):
            raise WorkspaceSecurityError("Nom de fichier invalide ou interdit.")

        target_dir = self.resolve_safe_path(subpath)
        target_dir.mkdir(parents=True, exist_ok=True)
        dest = self.resolve_safe_path(
            str(Path(subpath) / safe_name) if subpath else safe_name
        )

        if dest.exists() or dest.is_symlink():
            if dest.is_symlink():
                raise WorkspaceSecurityError(
                    "Écriture sur un lien symbolique interdite."
                )
            if not overwrite:
                raise WorkspaceCollisionError(
                    f"Le fichier '{safe_name}' existe déjà (utilisez overwrite=true pour remplacer)."
                )
        return target_dir, dest, safe_name

    def save_upload(
        self,
        filename: str,
        content: bytes,
        subpath: str = "",
        overwrite: bool = True,
    ) -> dict[str, Any]:
        if len(content) > self.max_upload_bytes:
            raise ValueError(
                f"Fichier trop volumineux ({len(content)} octets). Maximum : {self.max_upload_bytes} octets."
            )
        if self.get_total_workspace_usage() + len(content) > self.max_workspace_bytes:
            raise ValueError("Quota global de stockage du workspace dépassé.")

        target_dir, dest, safe_name = self._prepare_upload_destination(
            filename, subpath, overwrite
        )

        # Atomic write in the same directory with TOCTOU symlink verification
        fd, tmp_path_str = tempfile.mkstemp(
            dir=str(target_dir), prefix=".upload_", suffix=".tmp"
        )
        tmp_path = Path(tmp_path_str)
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(content)
                f.flush()
                os.fsync(f.fileno())
            os.chmod(tmp_path, 0o600)
            if dest.is_symlink():
                raise WorkspaceSecurityError("Détection TOCTOU : lien symbolique détecté.")
            os.replace(tmp_path, dest)
        except Exception:
            tmp_path.unlink(missing_ok=True)
            raise

        return {
            "name": safe_name,
            "path": str(dest.relative_to(self.root)),
            "size": len(content),
        }

    async def save_upload_stream(
        self,
        filename: str,
        chunks: AsyncIterator[bytes],
        subpath: str = "",
        overwrite: bool = True,
    ) -> dict[str, Any]:
        """Streams upload chunks directly to a temporary file before atomic replace."""
        target_dir, dest, safe_name = self._prepare_upload_destination(
            filename, subpath, overwrite
        )
        current_usage = self.get_total_workspace_usage()

        fd, tmp_path_str = tempfile.mkstemp(
            dir=str(target_dir), prefix=".upload_", suffix=".tmp"
        )
        tmp_path = Path(tmp_path_str)
        written = 0
        try:
            with os.fdopen(fd, "wb") as f:
                async for chunk in chunks:
                    written += len(chunk)
                    if written > self.max_upload_bytes:
                        raise ValueError("Taille maximale par fichier dépassée.")
                    if current_usage + written > self.max_workspace_bytes:
                        raise ValueError("Quota global du workspace dépassé.")
                    f.write(chunk)
                f.flush()
                os.fsync(f.fileno())
            os.chmod(tmp_path, 0o600)
            if dest.is_symlink():
                raise WorkspaceSecurityError("Détection TOCTOU : lien symbolique détecté.")
            os.replace(tmp_path, dest)
        except Exception:
            tmp_path.unlink(missing_ok=True)
            raise

        return {
            "name": safe_name,
            "path": str(dest.relative_to(self.root)),
            "size": written,
        }

    def _open_safe_file_fd(
        self, relative_path: str
    ) -> tuple[int, str, str, os.stat_result]:
        """
        Atomically opens a regular file inside `self.root` by walking directory
        file descriptors (`dir_fd` + `O_DIRECTORY | O_NOFOLLOW`) component by component,
        eliminating any TOCTOU symlink-swap window on intermediate directories or the target file.
        """
        clean_rel = relative_path.strip().lstrip("/")
        if not clean_rel:
            raise FileNotFoundError("Chemin de fichier vide.")
        parts = Path(clean_rel).parts
        for part in parts:
            if part in ("", ".", ".."):
                raise WorkspaceSecurityError(
                    "Navigation '..' interdite dans le workspace."
                )

        o_nofollow = getattr(os, "O_NOFOLLOW", 0)
        o_directory = getattr(os, "O_DIRECTORY", 0)
        dir_fd = os.open(str(self.root), os.O_RDONLY | o_directory | o_nofollow)
        try:
            for comp in parts[:-1]:
                try:
                    next_fd = os.open(
                        comp,
                        os.O_RDONLY | o_directory | o_nofollow,
                        dir_fd=dir_fd,
                    )
                except OSError as exc:
                    if exc.errno in (errno.ELOOP, errno.ENOTDIR, errno.EACCES):
                        raise WorkspaceSecurityError(
                            "Les liens symboliques (symlinks) sont interdits."
                        ) from exc
                    if exc.errno == errno.ENOENT:
                        raise FileNotFoundError("Dossier introuvable.") from exc
                    raise
                os.close(dir_fd)
                dir_fd = next_fd

            leaf = parts[-1]
            try:
                file_fd = os.open(leaf, os.O_RDONLY | o_nofollow, dir_fd=dir_fd)
            except OSError as exc:
                if exc.errno in (errno.ELOOP, errno.EACCES):
                    raise WorkspaceSecurityError(
                        "Les liens symboliques (symlinks) sont interdits."
                    ) from exc
                if exc.errno in (errno.ENOENT, errno.EISDIR):
                    raise FileNotFoundError("Fichier introuvable.") from exc
                raise

            st = os.fstat(file_fd)
            if not stat_mod.S_ISREG(st.st_mode):
                os.close(file_fd)
                raise FileNotFoundError("La cible n'est pas un fichier régulier.")

            return file_fd, leaf, "/".join(parts), st
        finally:
            os.close(dir_fd)

    def open_download_stream(
        self, relative_path: str, chunk_size: int = 65536
    ) -> tuple[Iterator[bytes], str, str, int]:
        """Returns `(byte_iterator, filename, media_type, file_size)` backed by an already-opened safe `fd`."""
        file_fd, leaf_name, _norm_rel, st = self._open_safe_file_fd(relative_path)
        mime = mimetypes.guess_type(leaf_name)[0] or "application/octet-stream"

        def _stream() -> Iterator[bytes]:
            try:
                while True:
                    chunk = os.read(file_fd, chunk_size)
                    if not chunk:
                        break
                    yield chunk
            finally:
                os.close(file_fd)

        return _stream(), leaf_name, mime, st.st_size

    def preview_file(self, relative_path: str, max_bytes: int = 65536) -> dict[str, Any]:
        fd, leaf_name, norm_rel, st = self._open_safe_file_fd(relative_path)
        try:
            size = st.st_size
            ext = Path(leaf_name).suffix.lower()
            mime = mimetypes.guess_type(leaf_name)[0] or "application/octet-stream"

            if ext not in PREVIEWABLE_EXTENSIONS and not mime.startswith("text/"):
                return {
                    "name": leaf_name,
                    "path": norm_rel,
                    "size": size,
                    "mime": mime,
                    "previewable": False,
                    "content": None,
                    "truncated": False,
                }

            raw = os.read(fd, max_bytes)
        finally:
            os.close(fd)

        text = raw.decode("utf-8", errors="replace")
        return {
            "name": leaf_name,
            "path": norm_rel,
            "size": size,
            "mime": mime,
            "previewable": True,
            "content": text,
            "truncated": size > max_bytes,
        }
