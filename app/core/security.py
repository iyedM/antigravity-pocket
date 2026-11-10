import base64
import hashlib
import hmac
import json
import os
import time
from typing import Dict, List, Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi import Header, HTTPException, Query, Request

from app.core.config import get_settings


class RateLimiter:
    """In-memory sliding window rate limiter against brute-force authentication."""

    def __init__(self, max_failures: int = 10, window_seconds: int = 60) -> None:
        self.max_failures = max_failures
        self.window_seconds = window_seconds
        self._failures: Dict[str, List[float]] = {}

    def check_allowed(self, client_id: str) -> bool:
        now = time.time()
        window_start = now - self.window_seconds
        attempts = [t for t in self._failures.get(client_id, []) if t >= window_start]
        self._failures[client_id] = attempts
        return len(attempts) < self.max_failures

    def record_failure(self, client_id: str) -> None:
        now = time.time()
        self._failures.setdefault(client_id, []).append(now)

    def reset(self, client_id: str) -> None:
        self._failures.pop(client_id, None)


rate_limiter = RateLimiter()


def verify_password_constant_time(provided: str, expected: str) -> bool:
    """Constant-time password comparison to prevent timing attacks."""
    if not expected:
        return True
    return hmac.compare_digest(provided.encode("utf-8"), expected.encode("utf-8"))


def create_signed_token(subject: str = "mobile_user", ttl_seconds: Optional[int] = None) -> str:
    """Creates an HMAC-SHA256 signed session token with expiration."""
    settings = get_settings()
    ttl = ttl_seconds if ttl_seconds is not None else settings.token_ttl_seconds
    payload = {
        "sub": subject,
        "iat": int(time.time()),
        "exp": int(time.time()) + ttl,
    }
    payload_b64 = base64.urlsafe_b64encode(
        json.dumps(payload, separators=(",", ":")).encode("utf-8")
    ).decode("ascii")
    sig = hmac.new(
        settings.secret_key.encode("utf-8"),
        payload_b64.encode("ascii"),
        hashlib.sha256,
    ).hexdigest()
    return f"{payload_b64}.{sig}"


def verify_signed_token(token: str) -> bool:
    """Verifies an HMAC-SHA256 signed session token or direct APP_PASSWORD."""
    settings = get_settings()
    if not settings.app_password:
        return True
    if not token:
        return False

    # Allow signed token verification
    if "." in token:
        parts = token.split(".", 1)
        if len(parts) == 2:
            payload_b64, sig = parts
            expected_sig = hmac.new(
                settings.secret_key.encode("utf-8"),
                payload_b64.encode("ascii"),
                hashlib.sha256,
            ).hexdigest()
            if hmac.compare_digest(sig, expected_sig):
                try:
                    raw = base64.urlsafe_b64decode(payload_b64.encode("ascii"))
                    data = json.loads(raw.decode("utf-8"))
                    if int(data.get("exp", 0)) >= int(time.time()):
                        return True
                except Exception:
                    return False

    # Fallback: constant-time check against APP_PASSWORD
    return verify_password_constant_time(token, settings.app_password)


def require_auth(
    request: Request,
    authorization: Optional[str] = Header(default=None),
    x_auth_token: Optional[str] = Header(default=None),
    token: Optional[str] = Query(default=None),
) -> None:
    """FastAPI dependency enforcing authentication and brute-force rate limiting."""
    settings = get_settings()
    if not settings.app_password:
        return

    client_ip = request.client.host if request.client else "unknown"
    if not rate_limiter.check_allowed(client_ip):
        raise HTTPException(
            status_code=429,
            detail="Trop de tentatives d'authentification échouées. Réessayez dans 1 minute.",
        )

    extracted = ""
    if authorization and authorization.lower().startswith("bearer "):
        extracted = authorization[7:].strip()
    elif x_auth_token:
        extracted = x_auth_token.strip()
    elif token:
        extracted = token.strip()

    if not verify_signed_token(extracted):
        rate_limiter.record_failure(client_ip)
        raise HTTPException(status_code=401, detail="Non autorisé : jeton ou mot de passe invalide.")

    rate_limiter.reset(client_ip)


def encrypt_bundle_aes_gcm(plaintext_bytes: bytes, passphrase: str) -> str:
    """Encrypts bytes with AES-256-GCM using PBKDF2-HMAC-SHA256 key derivation."""
    if len(passphrase) < 8:
        raise ValueError("La phrase secrète de chiffrement doit contenir au moins 8 caractères.")
    salt = os.urandom(16)
    nonce = os.urandom(12)
    key = hashlib.pbkdf2_hmac("sha256", passphrase.encode("utf-8"), salt, 200_000, dklen=32)
    aesgcm = AESGCM(key)
    ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext_bytes, None)
    envelope = salt + nonce + ciphertext_with_tag
    return base64.b64encode(envelope).decode("ascii")


def decrypt_bundle_aes_gcm(encoded_bundle: str, passphrase: str) -> bytes:
    """Decrypts and verifies an AES-256-GCM encrypted bundle."""
    raw = base64.b64decode(encoded_bundle.encode("ascii"))
    if len(raw) < 44:
        raise ValueError("Archive chiffrée invalide ou tronquée.")
    salt = raw[:16]
    nonce = raw[16:28]
    ciphertext_with_tag = raw[28:]
    key = hashlib.pbkdf2_hmac("sha256", passphrase.encode("utf-8"), salt, 200_000, dklen=32)
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext_with_tag, None)
