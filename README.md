# 🚀 Antigravity Pocket v2.1.0

> **Compagnon Mobile Open-Source (iOS & Android PWA) pour superviser et contrôler vos agents Google Antigravity.**
> *Avis : Antigravity Pocket est un projet communautaire indépendant et n'est pas un produit officiel de Google.*

---

## 🎯 Vision & Garanties (v2.1.0)

**Antigravity Pocket v2.1.0** se concentre sur cinq fonctionnalités fiables, auditées et couvertes par des tests automatisés :

1. **Supervision Multi-Sessions (SQLite)** : Créez, reprenez, isolez et annulez (`⏹ Stop`) vos sessions d'agents avec sérialisation par verrou (`asyncio.Lock`) et sans mutation globale du répertoire courant.
2. **Contrôle d'Exécution à 3 Niveaux (`read_only`, `assisted`, `autonomous`)** :
   - En mode `assisted`, une **porte d'approbation pré-exécution** bloque le lancement de l'agent tant que vous n'avez pas validé l'opération depuis votre téléphone (`✅ Approuver` / `❌ Refuser`).
   - En mode CLI, `agy` est toujours exécuté avec `--sandbox` et `--mode (plan|accept-edits|auto)` (jamais `--dangerously-skip-permissions`).
3. **Synchronisation WebSocket Sans Perte (`Subscribe-First Replay`)** : Lorsqu'un téléphone (iPhone / Android) se reconnecte après une coupure réseau, le serveur met en file d'attente le flux temps réel *avant* de rejouer les événements manqués (`last_seq`), puis déduplique par `sequence`.
4. **Explorateur de Fichiers Sécurisé (Anti-TOCTOU & Écriture Atomique)** : Upload en streaming par chunks, quotas par fichier et global, politique de collision explicite (`409 Conflict`), aperçu avec `O_NOFOLLOW` et blocage des liens symboliques.
5. **Interface Mobile de Supervision Anti-XSS (6 Onglets)** : *Dashboard*, *Activity & Chat* (résumés d'outils sans exposition des pensées internes `thought_delta`), *Sessions*, *Workspace*, *Approvals* et *Settings* (connexion/déconnexion avec révocation de jeton `JTI`), construite exclusivement avec l'API DOM (`textContent`, zéro `.innerHTML`).

---

## 📊 État des Fonctionnalités (Transparence v2.1.0)

| Fonctionnalité | État dans v2.1.0 |
| :--- | :--- |
| Authentification HMAC-SHA256 Fail-Closed + Révocation JTI + Rate Limiting | ✅ Garanti & Testé |
| Porte d'approbation pré-exécution (`read_only` / `assisted` / `autonomous`) | ✅ Garanti & Testé |
| Multi-sessions SQLite + Sérialisation des tâches + Annulation groupe de processus (`killpg`) | ✅ Garanti & Testé |
| Reconnexion WebSocket sans perte ni doublon (`Subscribe-First` + `sequence`) | ✅ Garanti & Testé |
| File Manager atomique (Chunks, Quotas, Anti-Traversal, Anti-Symlink, `O_NOFOLLOW`) | ✅ Garanti & Testé |
| Frontend PWA 6 onglets 100 % sans `.innerHTML` (Protection XSS) | ✅ Garanti & Testé |
| Notifications Push Web natives (APNs / WebPush hors-ligne) | 🚧 Prévu pour v2.2 (fil d'activité local en v2.1) |

---

## 🏗️ Architecture du Dépôt

```text
antigravity-pocket/
├── app/
│   ├── main.py                      # Application FastAPI & initialisation des services
│   ├── api/
│   │   ├── auth.py                  # Login, Logout (révocation JTI) & Statut
│   │   ├── sessions.py              # CRUD Sessions, Permissions & Approbations
│   │   ├── files.py                 # Streaming Upload, Preview, List & Download
│   │   └── websocket.py             # Subscribe-First Replay & Streaming temps réel
│   ├── core/
│   │   ├── config.py                # Configuration fail-closed & clé secrète persistante
│   │   ├── security.py              # Jetons HMAC, JTI Revocation, RateLimiter & Safe Tar Extract
│   │   ├── permissions.py           # Politique Read-Only / Assisted / Autonomous & ApprovalManager
│   │   └── events.py                # Protocole standardisé EventEnvelope (sequence)
│   ├── runtime/
│   │   ├── base.py                  # Interface abstraite AgentAdapter
│   │   ├── manager.py               # Orchestrateur de sessions avec verrous asyncio.Lock
│   │   └── adapters/
│   │       ├── sdk.py               # Adapter google-antigravity SDK (sans os.chdir)
│   │       └── cli.py               # Adapter CLI agy (stdout+stderr concurrents, timeout, killpg)
│   ├── services/
│   │   ├── session_service.py       # Persistance SQLite WAL
│   │   ├── workspace_service.py     # Isolation workspace, écriture atomique & quotas
│   │   └── notification_service.py  # Journal d'activité
│   └── static/
│       ├── index.html               # Interface PWA de supervision à 6 onglets (zéro innerHTML)
│       ├── manifest.json            # Manifeste PWA
│       └── sw.js                    # Service Worker
├── tests/                           # 22 tests unitaires, sécurité & intégration (Pytest)
├── scripts/
│   ├── install_local.sh             # Installation locale sécurisée
│   └── export_encrypted_bundle.py   # Chiffrement AES-256-GCM optionnel
├── Dockerfile
├── docker-compose.yml               # Écoute locale 127.0.0.1 par défaut, secrets obligatoires
├── .env.example
├── SECURITY.md
└── LICENSE
```

---

## 🚀 Installation & Démarrage Rapide (Local-First Recommandé)

```bash
# 1. Installer l'environnement virtuel et les dépendances
./scripts/install_local.sh

# 2. Configurer obligatoirement votre mot de passe fort et votre clé secrète HMAC
export APP_PASSWORD="VotreMotDePasseFort2026!"
export APP_SECRET_KEY="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"

# 3. Lancer le serveur (écoute locale par défaut, exposez via Tailscale / Cloudflare Tunnel avec TLS)
.venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 7860
```

---

## 🧪 Exécuter la Suite de Tests (22 Tests)

```bash
.venv/bin/pytest tests/ -v
```

---

## 📄 Licence
Distribué sous licence **MIT**. Voir [LICENSE](LICENSE) et [SECURITY.md](SECURITY.md).
