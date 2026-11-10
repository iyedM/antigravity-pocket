import base64
import hashlib
import hmac
import io
import json
import os
import tarfile
import time
import uuid
from pathlib import Path
from typing import Dict, List, Optional, Set

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi import Header, HTTPException, Query, Request

from app.core.config import get_settings

ALLOWED_BUNDLE_FILES = frozenset(
    {
        ".gemini/GEMINI.md",
        ".gemini/antigravity/antigravity_state.pbtxt",
        ".gemini/antigravity/installation_id",
        ".gemini/antigravity-cli/jetski_state.pbtxt",
        ".gemini/antigravity-cli/settings.json",
        ".gemini/antigravity-cli/installation_id",
    }
)
MAX_BUNDLE_FILE_BYTES = 1 * 1024 * 1024  # 1 MB per config file max
MAX_BUNDLE_MEMBERS = 10


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
        self._failures.setdefault(client_id, []).append(time.time())

    def reset(self, client_id: str) -> None:
        self._failures.pop(client_id, None)


class TokenRevocationStore:
    """Tracks revoked token JTIs to support explicit logout and revocation."""

    def __init__(self) -> None:
        self._revoked_jtis: Set[str] = set()

    def revoke_jti(self, jti: str) -> None:
        if jti:
            self._revoked_jtis.add(jti)

    def is_revoked(self, jti: str) -> bool:
        return jti in self._revoked_jtis

    def clear(self) -> None:
        self._revoked_jtis.clear()


rate_limiter = RateLimiter()
revocation_store = TokenRevocationStore()


def verify_password_constant_time(provided: str, expected: str) -> bool:
    """Constant-time password comparison; never returns True for empty expected."""
    if not expected or not provided:
        return False
    return hmac.compare_digest(provided.encode("utf-8"), expected.encode("utf-8"))


def create_signed_token(
    subject: str = "mobile_user", ttl_seconds: Optional[int] = None
) -> str:
    """Creates an HMAC-SHA256 signed session token with unique JTI and expiration."""
    settings = get_settings()
    ttl = ttl_seconds if ttl_seconds is not None else settings.token_ttl_seconds
    now = int(time.time())
    payload = {
        "sub": subject,
        "jti": uuid.uuid4().hex[:16],
        "iat": now,
        "exp": now + ttl,
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


def decode_and_verify_signed_token(token: str) -> Optional[dict]:
    """Decodes and verifies an HMAC-SHA256 signed token, checking expiration & revocation."""
    if not token or "." not in token:
        return None
    settings = get_settings()
    parts = token.split(".", 1)
    if len(parts) != 2:
        return None
    payload_b64, sig = parts
    expected_sig = hmac.new(
        settings.secret_key.encode("utf-8"),
        payload_b64.encode("ascii"),
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(sig, expected_sig):
        return None
    try:
        raw = base64.urlsafe_b64decode(payload_b64.encode("ascii"))
        data = json.loads(raw.decode("utf-8"))
        if int(data.get("exp", 0)) < int(time.time()):
            return None
        jti = str(data.get("jti", ""))
        if jti and revocation_store.is_revoked(jti):
            return None
        return data
    except Exception:
        return None


def revoke_signed_token(token: str) -> bool:
    """Revokes a valid signed token by its JTI."""
    data = decode_and_verify_signed_token(token)
    if not data or "jti" not in data:
        return False
    revocation_store.revoke_jti(str(data["jti"]))
    return True


def verify_signed_token(token: str) -> bool:
    """
    Fail-closed token verification:
    - If APP_PASSWORD is missing/weak and AGY_ALLOW_UNAUTHENTICATED_LOCAL is False -> False.
    - Accepts valid non-revoked HMAC token or constant-time APP_PASSWORD match.
    """
    settings = get_settings()
    if not settings.is_password_configured_and_strong():
        return settings.allow_unauthenticated_local

    if not token:
        return False

    if decode_and_verify_signed_token(token) is not None:
        return True

    return verify_password_constant_time(token, settings.app_password)


def extract_request_token(
    authorization: Optional[str] = None,
    x_auth_token: Optional[str] = None,
    token: Optional[str] = None,
) -> str:
    if authorization and authorization.lower().startswith("bearer "):
        return authorization[7:].strip()
    if x_auth_token:
        return x_auth_token.strip()
    if token:
        return token.strip()
    return ""


def require_auth(
    request: Request,
    authorization: Optional[str] = Header(default=None),
    x_auth_token: Optional[str] = Header(default=None),
    token: Optional[str] = Query(default=None),
) -> None:
    """FastAPI dependency enforcing fail-closed authentication and brute-force rate limiting."""
    settings = get_settings()
    if not settings.is_password_configured_and_strong():
        if settings.allow_unauthenticated_local:
            return
        raise HTTPException(
            status_code=503,
            detail="Serveur verrouillé : APP_PASSWORD (min 8 caractères) doit être configuré.",
        )

    client_ip = request.client.host if request.client else "unknown"
    if not rate_limiter.check_allowed(client_ip):
        raise HTTPException(
            status_code=429,
            detail="Trop de tentatives d'authentification échouées. Réessayez dans 1 minute.",
        )

    extracted = extract_request_token(authorization, x_auth_token, token)
    if not verify_signed_token(extracted):
        rate_limiter.record_failure(client_ip)
        raise HTTPException(
            status_code=401, detail="Non autorisé : jeton ou mot de passe invalide."
        )

    rate_limiter.reset(client_ip)


def encrypt_bundle_aes_gcm(plaintext_bytes: bytes, passphrase: str) -> str:
    """Encrypts bytes with AES-256-GCM using PBKDF2-HMAC-SHA256 key derivation."""
    if len(passphrase) < 8:
        raise ValueError(
            "La phrase secrète de chiffrement doit contenir au moins 8 caractères."
        )
    salt = os.urandom(16)
    nonce = os.urandom(12)
    key = hashlib.pbkdf2_hmac(
        "sha256", passphrase.encode("utf-8"), salt, 200_000, dklen=32
    )
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
    key = hashlib.pbkdf2_hmac(
        "sha256", passphrase.encode("utf-8"), salt, 200_000, dklen=32
    )
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext_with_tag, None)


def safe_extract_tar_bundle(raw_tar_bytes: bytes, dest_root: Path) -> List[str]:
    """
    Safely extracts a decrypted tar.gz bundle into `dest_root` without `extractall()`.
    Enforces:
    - Strict allowlist (`ALLOWED_BUNDLE_FILES`)
    - No symlinks, hardlinks, devices, or FIFOs
    - No path traversal ('..', leading '/')
    - Maximum file count and per-file size limit
    - 0o600 permissions on extracted files
    """
    dest_resolved = dest_root.resolve()
    extracted: List[str] = []

    with tarfile.open(fileobj=io.BytesIO(raw_tar_bytes), mode="r:gz") as tar:
        members = tar.getmembers()
        if len(members) > MAX_BUNDLE_MEMBERS:
            raise ValueError("Archive rejetée : trop d'entrées dans l'archive.")

        for member in members:
            raw_name = member.name.strip()
            if raw_name.startswith("/") or ".." in Path(raw_name).parts:
                raise ValueError(f"Entrée d'archive dangereuse rejetée : {member.name}")
            norm_name = raw_name.removeprefix("./")
            if (
                not member.isfile()
                or member.issym()
                or member.islnk()
            ):
                raise ValueError(f"Entrée d'archive dangereuse rejetée : {member.name}")

            if norm_name not in ALLOWED_BUNDLE_FILES:
                raise ValueError(
                    f"Fichier non autorisé dans l'archive : {norm_name}"
                )

            if member.size > MAX_BUNDLE_FILE_BYTES:
                raise ValueError(f"Fichier trop volumineux dans l'archive : {norm_name}")

            target_path = (dest_resolved / norm_name).resolve()
            if not target_path.is_relative_to(dest_resolved):
                raise ValueError("Violation d'isolation lors de l'extraction.")

            file_obj = tar.extractfile(member)
            if file_obj is None:
                continue
            data = file_obj.read(MAX_BUNDLE_FILE_BYTES + 1)
            if len(data) > MAX_BUNDLE_FILE_BYTES:
                raise ValueError("Taille réelle supérieure à la limite autorisée.")

            target_path.parent.mkdir(parents=True, exist_ok=True)
            target_path.write_bytes(data)
            os.chmod(target_path, 0o600)
            extracted.append(norm_name)

    return extracted
