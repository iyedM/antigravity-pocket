import os
import pytest

from app.core.security import (
    RateLimiter,
    create_signed_token,
    decrypt_bundle_aes_gcm,
    encrypt_bundle_aes_gcm,
    verify_password_constant_time,
    verify_signed_token,
)


def test_constant_time_password_verification() -> None:
    assert verify_password_constant_time("secret123", "secret123") is True
    assert verify_password_constant_time("wrong", "secret123") is False


def test_signed_token_lifecycle(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("APP_PASSWORD", "MyStrongPass!")
    monkeypatch.setenv("APP_SECRET_KEY", "a" * 64)

    token = create_signed_token(subject="iphone15", ttl_seconds=300)
    assert verify_signed_token(token) is True
    assert verify_signed_token(token + "tampered") is False

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
