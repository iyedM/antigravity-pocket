#!/usr/bin/env bash
# Installation automatique pour Android (Samsung A52, etc.) via Termux + Ubuntu ARM64
set -e

echo "🚀 Installation d'Antigravity Pocket sur Android (Termux)..."
pkg update -y && pkg install -y proot-distro git curl

if ! proot-distro list | grep -q "ubuntu.*installed"; then
  proot-distro install ubuntu
fi

proot-distro login ubuntu -- bash -c "
  apt-get update && apt-get install -y python3 python3-pip git curl
  pip3 install --break-system-packages -r requirements.txt
  echo '✅ Installation terminée ! Lancez : python3 -m uvicorn app.main:app --host 0.0.0.0 --port 7860'
"
