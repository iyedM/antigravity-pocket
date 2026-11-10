import io
import os
import stat
import tarfile
from pathlib import Path
import pytest

from app.core.config import get_settings
from app.core.security import (
    RateLimiter,
    create_signed_token,
    decrypt_bundle_aes_gcm,
    encrypt_bundle_aes_gcm,
    revoke_signed_token,
    safe_extract_tar_bundle,
    verify_password_constant_time,
    verify_signed_token,
)


def test_constant_time_password_verification() -> None:
    assert verify_password_constant_time("secret123", "secret123") is True
    assert verify_password_constant_time("wrong", "secret123") is False
    # Empty password must NEVER return True
    assert verify_password_constant_time("", "") is False


def test_persistent_secret_key_when_env_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("APP_SECRET_KEY", raising=False)
    monkeypatch.setenv("APP_PASSWORD", "StrongPassword2026!")
    s1 = get_settings()
    s2 = get_settings()
    assert s1.secret_key == s2.secret_key
    token = create_signed_token(subject="iphone15")
    assert verify_signed_token(token) is True


def test_fail_closed_when_password_missing_or_weak(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("APP_PASSWORD", raising=False)
    monkeypatch.delenv("AGY_ALLOW_UNAUTHENTICATED_LOCAL", raising=False)
    assert verify_signed_token("any_token") is False

    monkeypatch.setenv("APP_PASSWORD", "ChangeMeNow!")
    assert verify_signed_token("ChangeMeNow!") is False


def test_signed_token_lifecycle_and_revocation(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("APP_PASSWORD", "MyStrongPass2026!")
    monkeypatch.setenv("APP_SECRET_KEY", "a" * 64)

    token = create_signed_token(subject="iphone15", ttl_seconds=300)
    assert verify_signed_token(token) is True
    assert verify_signed_token(token + "tampered") is False

    # Revoke token and verify it is immediately rejected
    assert revoke_signed_token(token) is True
    assert verify_signed_token(token) is False

    expired_token = create_signed_token(subject="iphone15", ttl_seconds=-10)
    assert verify_signed_token(expired_token) is False


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

    with pytest.raises(Exception):
        decrypt_bundle_aes_gcm(encrypted, "WrongPassphrase123")


def test_safe_extract_tar_bundle_blocks_tarslip_and_unallowed_files(tmp_path: Path) -> None:
    # 1. Valid allowlisted file (.gemini/GEMINI.md)
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

    # 2. Malicious Tar Slip ('../../evil.sh') must be rejected
    evil_buf = io.BytesIO()
    with tarfile.open(fileobj=evil_buf, mode="w:gz") as tar:
        info = tarfile.TarInfo(name="../../evil.sh")
        info.size = 4
        tar.addfile(info, io.BytesIO(b"echo"))

    with pytest.raises(ValueError):
        safe_extract_tar_bundle(evil_buf.getvalue(), tmp_path)

    # 3. Non-allowlisted file ('.bashrc') must be rejected
    unallowed_buf = io.BytesIO()
    with tarfile.open(fileobj=unallowed_buf, mode="w:gz") as tar:
        info = tarfile.TarInfo(name=".bashrc")
        info.size = 4
        tar.addfile(info, io.BytesIO(b"echo"))

    with pytest.raises(ValueError):
        safe_extract_tar_bundle(unallowed_buf.getvalue(), tmp_path)
