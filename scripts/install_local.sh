#!/usr/bin/env bash
# Installation locale (Linux PC, Raspberry Pi, ou Android Termux Ubuntu ARM64 aarch64)
set -e

echo "🚀 Installation d'Antigravity Pocket v2.0..."

if command -v pkg >/dev/null 2>&1 && [ -n "$TERMUX_VERSION" ]; then
  echo "📱 Environnement Android Termux détecté (ARM64)."
  pkg update -y && pkg install -y proot-distro git curl
  if ! proot-distro list | grep -q "ubuntu.*installed"; then
    proot-distro install ubuntu
  fi
  echo "👉 Connectez-vous avec : proot-distro login ubuntu"
  exit 0
fi

python3 -m venv .venv
.venv/bin/pip install --upgrade pip
.venv/bin/pip install -r requirements.txt

echo "✅ Installation terminée !"
echo "🔒 Définissez votre mot de passe : export APP_PASSWORD='VotreMotDePasseFort'"
echo "▶️  Lancez le serveur : .venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 7860"
