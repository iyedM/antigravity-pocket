#!/usr/bin/env bash
# Installation locale sécurisée d'Antigravity Pocket v2.1.0
set -e

echo "🚀 Installation d'Antigravity Pocket v2.1.0..."

python3 -m venv .venv
.venv/bin/pip install --upgrade pip
.venv/bin/pip install -r requirements.txt

GENERATED_SECRET=$(python3 -c "import secrets; print(secrets.token_hex(32))")

echo "✅ Installation terminée !"
echo ""
echo "🔒 Configuration obligatoire avant le démarrage :"
echo "   export APP_PASSWORD='ChoisissezUnMotDePasseFortMin8Caracteres'"
echo "   export APP_SECRET_KEY='${GENERATED_SECRET}'"
echo ""
echo "▶️  Démarrage local sécurisé (127.0.0.1) :"
echo "   .venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 7860"
