import os
import secrets
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Settings:
    """Centralized application settings loaded from environment variables."""

    app_name: str = "Antigravity Pocket"
    version: str = "2.0.0"
    app_password: str = field(default_factory=lambda: os.environ.get("APP_PASSWORD", ""))
    secret_key: str = field(
        default_factory=lambda: os.environ.get("APP_SECRET_KEY", secrets.token_hex(32))
    )
    workspace_dir: Path = field(
        default_factory=lambda: Path(
            os.environ.get("AGY_WORKSPACE", str(Path.home() / "workspace"))
        ).resolve()
    )
    db_path: Path = field(
        default_factory=lambda: Path(
            os.environ.get(
                "AGY_DB_PATH",
                str(Path.home() / ".gemini" / "antigravity_pocket.db"),
            )
        ).resolve()
    )
    default_permission_mode: str = field(
        default_factory=lambda: os.environ.get("AGY_DEFAULT_PERMISSION_MODE", "assisted")
    )
    max_upload_bytes: int = field(
        default_factory=lambda: int(os.environ.get("AGY_MAX_UPLOAD_MB", "50")) * 1024 * 1024
    )
    token_ttl_seconds: int = field(
        default_factory=lambda: int(os.environ.get("AGY_TOKEN_TTL_SECONDS", "86400"))
    )
    rate_limit_max_failures: int = 10
    rate_limit_window_seconds: int = 60

    def ensure_directories(self) -> None:
        self.workspace_dir.mkdir(parents=True, exist_ok=True)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)


def get_settings() -> Settings:
    settings = Settings()
    settings.ensure_directories()
    return settings
