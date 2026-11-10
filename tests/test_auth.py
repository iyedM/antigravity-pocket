import io
import os
import stat
import tarfile
from pathlib import Path

import pytest

from app.core.config import get_settings, is_strong_secret_value
from app.core.security import (
    PersistentRevocationStore,
    RateLimiter,
    create_signed_token,
    decrypt_bundle_aes_gcm,
    encrypt_bundle_aes_gcm,
    revoke_signed_token,
    safe_extract_tar_bundle,
    ticket_store,
    verify_password_constant_time,
    verify_signed_token,
)


def test_constant_time_password_verification() -> None:
    assert verify_password_constant_time("secret123", "secret123") is True
    assert verify_password_constant_time("wrong", "secret123") is False
    assert verify_password_constant_time("", "") is False


def test_rejects_predictable_example_secrets() -> None:
    assert (
        is_strong_secret_value(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            min_len=32,
        )
        is False
    )
    assert is_strong_secret_value("ChangeMeWithAStrongPassword2026!", min_len=8) is False
    assert is_strong_secret_value("a" * 64, min_len=32) is False
    assert is_strong_secret_value("K9#mP2$vL8@qR5!xZ1&wN4", min_len=8) is True


def test_persistent_secret_key_when_env_unset(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("APP_SECRET_KEY", raising=False)
    monkeypatch.setenv("APP_PASSWORD", "StrongPass#2026_XyZ")
    monkeypatch.setenv("AGY_DB_PATH", str(tmp_path / "auth.db"))
    s1 = get_settings()
    s2 = get_settings()
    assert s1.secret_key == s2.secret_key
    token = create_signed_token(subject="iphone15")
    assert verify_signed_token(token) is True


def test_fail_closed_always_requires_strong_password(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("APP_PASSWORD", raising=False)
    monkeypatch.setenv("AGY_ALLOW_UNAUTHENTICATED_LOCAL", "true")
    # Even if AGY_ALLOW_UNAUTHENTICATED_LOCAL is set in env, auth must remain fail-closed
    assert verify_signed_token("any_token") is False

    monkeypatch.setenv("APP_PASSWORD", "ChangeMeNow!")
    assert verify_signed_token("ChangeMeNow!") is False


def test_signed_token_sqlite_persistent_revocation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db_file = tmp_path / "revocation.db"
    monkeypatch.setenv("AGY_DB_PATH", str(db_file))
    monkeypatch.setenv("APP_PASSWORD", "MyStrongPass#2026!")
    monkeypatch.setenv(
        "APP_SECRET_KEY",
        "9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3b2a1f0e9d8c7b6a5f4e3d2c1b0a9f8e",
    )

    token = create_signed_token(subject="iphone15", ttl_seconds=300)
    assert verify_signed_token(token) is True

    # Revoke token in SQLite and verify a brand new store instance still sees it as revoked
    assert revoke_signed_token(token) is True
    assert verify_signed_token(token) is False

    fresh_store = PersistentRevocationStore()
    from app.core.security import decode_and_verify_signed_token

    assert decode_and_verify_signed_token(token) is None
    assert fresh_store.is_revoked("non_existent", db_path=db_file) is False


def test_single_use_ephemeral_ticket_store() -> None:
    tkt = ticket_store.issue_ticket(purpose="ws", ttl_seconds=30)
    # Wrong purpose must fail and consume the ticket
    assert ticket_store.consume_ticket(tkt, expected_purpose="download") is False

    tkt2 = ticket_store.issue_ticket(purpose="ws", ttl_seconds=30)
    assert ticket_store.consume_ticket(tkt2, expected_purpose="ws") is True
    # Replay of same ticket must fail (single-use)
    assert ticket_store.consume_ticket(tkt2, expected_purpose="ws") is False


def test_rate_limiter_blocks_brute_force() -> None:
    limiter = RateLimiter(max_failures=3, window_seconds=60)
    client = "192.168.1.50"
    assert limiter.check_allowed(client) is True
    for _ in range(3):
        limiter.record_failure(client)
    assert limiter.check_allowed(client) is False
    limiter.reset(client)
    assert limiter.check_allowed(client) is True


def test_aes_256_gcm_bundle_encryption() -> None:
    secret_data = b'{"account":"user@example.com","state":"authenticated"}'
    passphrase = "CorrectHorseBatteryStaple!"

    encrypted = encrypt_bundle_aes_gcm(secret_data, passphrase)
    assert encrypted != secret_data.decode()

    decrypted = decrypt_bundle_aes_gcm(encrypted, passphrase)
    assert decrypted == secret_data

    from cryptography.exceptions import InvalidTag

    with pytest.raises(InvalidTag):
        decrypt_bundle_aes_gcm(encrypted, "WrongPassphrase123")


def test_safe_extract_tar_bundle_blocks_tarslip_and_unallowed_files(
    tmp_path: Path,
) -> None:
    valid_buf = io.BytesIO()
    with tarfile.open(fileobj=valid_buf, mode="w:gz") as tar:
        data = b"# Rules"
        info = tarfile.TarInfo(name=".gemini/GEMINI.md")
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))

    extracted = safe_extract_tar_bundle(valid_buf.getvalue(), tmp_path)
    assert extracted == [".gemini/GEMINI.md"]
    extracted_file = tmp_path / ".gemini" / "GEMINI.md"
    assert extracted_file.read_bytes() == b"# Rules"
    assert stat.S_IMODE(os.stat(extracted_file).st_mode) == 0o600

    evil_buf = io.BytesIO()
    with tarfile.open(fileobj=evil_buf, mode="w:gz") as tar:
        info = tarfile.TarInfo(name="../../evil.sh")
        info.size = 4
        tar.addfile(info, io.BytesIO(b"echo"))

    with pytest.raises(ValueError):
        safe_extract_tar_bundle(evil_buf.getvalue(), tmp_path)
