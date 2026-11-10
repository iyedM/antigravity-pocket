# 🚀 Antigravity Pocket v2.0

> **Compagnon Mobile Open-Source (iOS & Android PWA) pour contrôler vos agents Google Antigravity à distance en toute sécurité.**
> *Note : Antigravity Pocket est un projet communautaire indépendant et n'est pas affilié officiellement à Google.*

---

## ✨ Fonctionnalités Clés (v2.0)

- **🛡️ Architecture Security-First (3 niveaux de permissions)** :
  - `read_only` : Consultation et diagnostic uniquement.
  - `assisted` *(par défaut)* : Cartes d'approbation interactives sur votre téléphone (`[✅ Approuver]` / `[❌ Refuser]`) avant toute opération sensible.
  - `autonomous` : Exécution autonome confinée dans le sandbox (`--sandbox`) du workspace.
  - *Aucune utilisation de `--dangerously-skip-permissions`.*
- **🗂️ Multi-Sessions & Persistance SQLite** : Créez plusieurs sessions, basculez d'une tâche à l'autre, annulez une tâche en cours (`⏹ Stop`) depuis votre téléphone.
- **⏱️ Timeline d'Événements Numérotés (`sequence`) & Reconnexion WebSocket** : En cas de coupure réseau mobile (passage Wi-Fi ↔ 4G/5G ou verrouillage d'écran iOS), le WebSocket rejoue automatiquement tous les événements manqués (`last_seq`).
- **📁 Workspace File Manager Sécurisé** : Explorateur bidirectionnel (envoi de photos/fichiers, aperçu de code/Markdown intégré, téléchargement en 1 tap) protégé contre le *Path Traversal* et les liens symboliques (*symlinks*).
- **🔌 Moteur Hybride Basé sur Adapters (`AgentAdapter`)** : Supporte nativement le SDK Python `google-antigravity` (`SDKAdapter`) et le CLI `agy` (`CLIAdapter`).

---

## 🏗️ Architecture Modulaire

```text
antigravity-pocket/
├── app/
│   ├── main.py                      # Point d'entrée FastAPI & initialisation des services
│   ├── api/
│   │   ├── auth.py                  # Login HMAC-SHA256, Rate Limiting & Statut système
│   │   ├── sessions.py              # CRUD Multi-Sessions, Permissions & Approbations
│   │   ├── files.py                 # Explorateur Workspace, Upload, Preview & Download
│   │   └── websocket.py             # Streaming temps réel & Replay d'événements (last_seq)
│   ├── core/
│   │   ├── config.py                # Configuration centralisée par variables d'environnement
│   │   ├── security.py              # Jetons HMAC, RateLimiter & Chiffrement AES-256-GCM
│   │   ├── permissions.py           # Politique Read-Only / Assisted / Autonomous & ApprovalManager
│   │   └── events.py                # Protocole standardisé EventEnvelope (sequence)
│   ├── runtime/
│   │   ├── base.py                  # Interface abstraite AgentAdapter
│   │   ├── manager.py               # Orchestrateur de sessions, annulation & diffusion
│   │   └── adapters/
│   │       ├── sdk.py               # Adapter officiel google-antigravity SDK
│   │       └── cli.py               # Adapter CLI agy (--sandbox --mode plan|accept-edits|auto)
│   ├── services/
│   │   ├── session_service.py       # Persistance SQLite (sessions & timeline d'événements)
│   │   ├── workspace_service.py     # Isolation stricte du workspace (anti-traversal & symlinks)
│   │   └── notification_service.py  # Fil de notifications mobiles
│   └── static/
│       ├── index.html               # Interface Mobile PWA v2 (4 onglets + thème sombre/clair)
│       ├── manifest.json            # Manifeste PWA iOS / Android
│       └── sw.js                    # Service Worker
├── tests/                           # Suite complète de tests unitaires & d'intégration (Pytest)
├── scripts/
│   ├── install_local.sh             # Installation Linux PC / Raspberry Pi / Android Termux ARM64
│   └── export_encrypted_bundle.py   # Chiffrement AES-256-GCM optionnel pour déploiement Cloud
├── Dockerfile
├── docker-compose.yml
├── .env.example
├── SECURITY.md
└── LICENSE
```

---

## 🚀 Les 3 Modes de Déploiement (Pour iPhone & Android)

### Mode 1 — Local Companion (PC allumé + Tailscale / Cloudflare Tunnel)
Idéal lorsque votre PC est allumé : **aucun identifiant ne quitte votre PC**.
```bash
./scripts/install_local.sh
export APP_PASSWORD="VotreMotDePasseFort"
.venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 7860
```

### Mode 2 — Home Pocket Server (PC ÉTEINT • Serveur sur votre Samsung A52 Android ARM64 ou Raspberry Pi)
Vous voulez utiliser Antigravity sur votre **iPhone 15 quand votre PC est éteint**, **gratuitement (0 €)**, **sans carte bancaire** et **sans envoyer vos identifiants sur un Cloud tiers** ?
- Le SDK `google-antigravity` fournit une roue officielle compilée pour **Linux ARM64 (`aarch64`)**.
- Laissez votre téléphone Android secondaire (ex: **Samsung Galaxy A52** sous *Termux + proot-distro Ubuntu*) ou un Raspberry Pi branché chez vous en Wi-Fi :
```bash
./scripts/install_local.sh
```
- Connectez votre **iPhone 15** dessus via Wi-Fi local ou **Tailscale** (gratuit, chiffré de bout en bout, sans carte bancaire) !

### Mode 3 — Remote Cloud Container (PC ÉTEINT • Docker / Cloud distant)
Pour héberger l'agent dans un conteneur Docker distant avec vos secrets chiffrés en **AES-256-GCM** :
1. Chiffrez votre configuration localement avec une phrase secrète forte :
   ```bash
   python3 scripts/export_encrypted_bundle.py
   ```
2. Configurez `APP_PASSWORD`, `AGY_ENCRYPTED_BUNDLE` et `AGY_BUNDLE_PASSPHRASE` dans votre conteneur Docker (`docker compose up -d`).

---

## 🧪 Exécuter les Tests Automatisés & l'Audit

```bash
.venv/bin/pytest tests/ -v
```

---

## 📄 Licence
Distribué sous licence **MIT**. Voir [LICENSE](LICENSE) et [SECURITY.md](SECURITY.md).
