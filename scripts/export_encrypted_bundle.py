#!/usr/bin/env python3
"""
Phase 2 Cloud Helper : Chiffre les fichiers d'état ~/.gemini avec AES-256-GCM
(PBKDF2-HMAC-SHA256, 200 000 itérations) avant tout stockage dans un gestionnaire
de secrets Cloud (AGY_ENCRYPTED_BUNDLE + AGY_BUNDLE_PASSPHRASE).
"""
import getpass
import io
import sys
import tarfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from app.core.security import encrypt_bundle_aes_gcm  # noqa: E402

FILES_TO_INCLUDE = [
    ".gemini/GEMINI.md",
    ".gemini/antigravity/antigravity_state.pbtxt",
    ".gemini/antigravity/installation_id",
    ".gemini/antigravity-cli/jetski_state.pbtxt",
    ".gemini/antigravity-cli/settings.json",
    ".gemini/antigravity-cli/installation_id",
]


def main() -> None:
    home = Path.home()
    buf = io.BytesIO()
    included = []

    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for rel in FILES_TO_INCLUDE:
            p = home / rel
            if p.exists() and p.is_file():
                tar.add(str(p), arcname=rel)
                included.append(rel)

    if not included:
        print("❌ Aucun fichier trouvé dans ~/.gemini/.")
        return

    passphrase = getpass.getpass("🔑 Entrez une phrase secrète de chiffrement AES-256-GCM (min 8 car.) : ")
    encrypted_b64 = encrypt_bundle_aes_gcm(buf.getvalue(), passphrase)

    out_path = Path(__file__).resolve().parent.parent / ".agy_bundle.aes256.enc"
    out_path.write_text(encrypted_b64, encoding="utf-8")
    print(f"✅ Archive chiffrée AES-256-GCM générée dans : {out_path}")
    print("👉 Configurez AGY_ENCRYPTED_BUNDLE et AGY_BUNDLE_PASSPHRASE dans votre conteneur Cloud.")


if __name__ == "__main__":
    main()
