import os
import secrets
from dataclasses import dataclass, field
from pathlib import Path

WEAK_SECRETS = frozenset(
    {
        "",
        "changemenow!",
        "changemewithastrongpassword2026!",
        "replace_with_random_64_hex_secret",
        "0123456789abcdef0123456789abcdef",
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "password",
        "admin",
        "123456",
    }
)

_PROCESS_SECRET_KEY = secrets.token_hex(32)


def is_strong_secret_value(val: str, min_len: int = 8) -> bool:
    cleaned = val.strip()
    if len(cleaned) < min_len:
        return False
    if cleaned.lower() in WEAK_SECRETS:
        return False
    if "0123456789abcdef" in cleaned.lower():
        return False
    return len(set(cleaned.lower())) >= 5


def _load_or_create_secret_key() -> str:
    env_key = os.environ.get("APP_SECRET_KEY", "").strip()
    if is_strong_secret_value(env_key, min_len=32):
        return env_key
    return _PROCESS_SECRET_KEY


@dataclass
class Settings:
    """Centralized application settings with mandatory fail-closed authentication."""

    app_name: str = "Antigravity Pocket"
    version: str = "2.2.0"
    app_password: str = field(
        default_factory=lambda: os.environ.get("APP_PASSWORD", "").strip()
    )
    secret_key: str = field(default_factory=_load_or_create_secret_key)
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
        default_factory=lambda: int(os.environ.get("AGY_MAX_UPLOAD_MB", "50"))
        * 1024
        * 1024
    )
    max_workspace_bytes: int = field(
        default_factory=lambda: int(os.environ.get("AGY_MAX_WORKSPACE_MB", "500"))
        * 1024
        * 1024
    )
    token_ttl_seconds: int = field(
        default_factory=lambda: int(os.environ.get("AGY_TOKEN_TTL_SECONDS", "86400"))
    )
    cli_timeout_seconds: float = field(
        default_factory=lambda: float(os.environ.get("AGY_CLI_TIMEOUT_SECONDS", "180"))
    )

    def is_password_configured_and_strong(self) -> bool:
        return is_strong_secret_value(self.app_password, min_len=8)

    def ensure_directories(self) -> None:
        self.workspace_dir.mkdir(parents=True, exist_ok=True)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)


def get_settings() -> Settings:
    settings = Settings()
    settings.ensure_directories()
    return settings
