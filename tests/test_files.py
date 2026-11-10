import os
from pathlib import Path

import pytest

from app.services.workspace_service import (
    WorkspaceCollisionError,
    WorkspaceSecurityError,
    WorkspaceService,
)


def test_workspace_upload_list_and_preview(tmp_path: Path) -> None:
    ws = WorkspaceService(workspace_root=tmp_path, max_upload_bytes=1024)

    saved = ws.save_upload("hello.py", b"print('Hello Antigravity')\n")
    assert saved["name"] == "hello.py"

    files = ws.list_files()
    assert len(files) == 1
    assert files[0]["previewable"] is True

    preview = ws.preview_file("hello.py")
    assert preview["previewable"] is True
    assert "Hello Antigravity" in preview["content"]


def test_workspace_blocks_path_traversal(tmp_path: Path) -> None:
    ws = WorkspaceService(workspace_root=tmp_path)
    with pytest.raises(WorkspaceSecurityError):
        ws.resolve_safe_path("../../etc/passwd")

    with pytest.raises(WorkspaceSecurityError):
        ws.preview_file("../secret.txt")


def test_workspace_blocks_symlinks(tmp_path: Path) -> None:
    ws = WorkspaceService(workspace_root=tmp_path)
    outside_file = tmp_path.parent / "outside_secret.txt"
    outside_file.write_text("top-secret", encoding="utf-8")

    symlink_path = tmp_path / "evil_link.txt"
    os.symlink(outside_file, symlink_path)

    with pytest.raises(WorkspaceSecurityError):
        ws.resolve_safe_path("evil_link.txt")


def test_workspace_enforces_upload_size_and_global_quota(tmp_path: Path) -> None:
    ws = WorkspaceService(
        workspace_root=tmp_path, max_upload_bytes=10, max_workspace_bytes=15
    )
    with pytest.raises(ValueError):
        ws.save_upload("huge.bin", b"0123456789ABCDEF")

    ws.save_upload("part1.bin", b"0123456789")
    # Second file exceeds global workspace quota of 15 bytes
    with pytest.raises(ValueError, match="Quota global"):
        ws.save_upload("part2.bin", b"01234567")


def test_workspace_collision_policy(tmp_path: Path) -> None:
    ws = WorkspaceService(workspace_root=tmp_path)
    ws.save_upload("doc.txt", b"v1", overwrite=False)

    with pytest.raises(WorkspaceCollisionError):
        ws.save_upload("doc.txt", b"v2", overwrite=False)

    ws.save_upload("doc.txt", b"v2", overwrite=True)
    assert ws.preview_file("doc.txt")["content"] == "v2"
