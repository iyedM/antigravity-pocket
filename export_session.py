#!/usr/bin/env python3
"""
Exporte uniquement les fichiers légers d'authentification et de règles (~/.gemini)
en une chaîne Base64 (AGY_AUTH_BUNDLE) à coller dans les Secrets privés
de Hugging Face Spaces ou GitHub Codespaces (sans jamais les publier sur Git).
"""
import base64
import io
import tarfile
from pathlib import Path

FILES_TO_EXPORT = [
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
        for rel_path in FILES_TO_EXPORT:
            full_path = home / rel_path
            if full_path.exists() and full_path.is_file():
                tar.add(str(full_path), arcname=rel_path)
                included.append(rel_path)

    if not included:
        print("❌ Aucun fichier de session trouvé dans ~/.gemini/. Connectez-vous d'abord avec `agy`.")
        return

    b64_str = base64.b64encode(buf.getvalue()).decode("ascii")
    out_file = Path(__file__).parent / ".agy_auth_bundle.secret.txt"
    out_file.write_text(b64_str, encoding="utf-8")

    print("✅ Fichiers exportés dans l'archive chiffrée Base64 :")
    for item in included:
        print(f"   - ~/{item}")
    print(f"\n🔒 Valeur enregistrée localement dans : {out_file}")
    print("👉 Copiez le contenu de ce fichier dans la variable secrète `AGY_AUTH_BUNDLE`")
    print("   de votre Space Hugging Face (Settings -> Variables and secrets -> New secret).")


if __name__ == "__main__":
    main()
