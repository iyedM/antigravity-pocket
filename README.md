# 🚀 Antigravity Pocket v2.3.0-rc1 (Release Candidate)

> **Compagnon Mobile Open-Source (iOS & Android PWA) pour superviser et contrôler vos agents Google Antigravity.**
> *Avis : Antigravity Pocket est un projet communautaire indépendant et n'est pas un produit officiel de Google.*

---

## ✨ Garanties Techniques Vérifiées (v2.3.0-rc1 — 44/44 Tests Pytest)

1. **Authentification Fail-Closed, Séparation des Privilèges, Révocation SQLite & Tickets à Usage Unique** :
   - Authentification obligatoire dans tous les modes (`APP_PASSWORD` accepté uniquement sur `POST /api/v1/auth/login`, rejeté comme jeton Bearer API/WebSocket).
   - Révocation persistante des jetons (`jti`) dans SQLite (`revoked_tokens`) et persistance `0600` de `secret.key`.
   - Échange de **tickets éphémères à usage unique (30s)** (`POST /api/v1/auth/ticket`, isolés entre `ws` et `download`).
2. **Intégration Réelle des Politiques du SDK `google-antigravity` (`v0.1.23+`) & Vérification Fail-Closed de `sandbox_status`** :
   - **Avec `SDKAdapter`** : Utilise `LocalAgentConfig` avec `RunCommandConfig(enable_sandbox=True, enable_daemons=False, timeout_seconds=120.0)` et vérifie **à l'exécution** `agent.sandbox_status` avant `agent.chat()` (refus fail-closed immédiat si `sandbox_status.available == False` ou non confirmé en mode `autonomous`).
   - **Avec `CLIAdapter`** : Utilise `agy --print --sandbox --mode (plan|accept-edits|auto)` avec validation préalable du lancement du tour en mode `assisted`.
3. **Atomicité des Approbations Inter-Sessions, Remplacement de Tâche & Annulation Réelle** :
   - Machine à états atomique protégée par verrou (`threading.Lock`) dans `ApprovalManager`, liaison stricte `approval_id` ↔ `session_id` (`session_id` obligatoire, `403 Forbidden` inter-session) et anti-rejeu.
   - Séparation explicite entre `previous_task` et `new_task` dans `AgentRuntimeManager`, `sdk_task.cancel()` et `os.killpg`.
4. **Synchronisation WebSocket Sans Perte (`Subscribe-First Replay` + Backpressure + Reconnexion Mobile)** :
   - File bornée (`MAX_WS_QUEUE_SIZE = 256`) avec rattrapage SQLite automatique, compteur de génération `wsGeneration` et reconnexion exponentielle automatique sur mobile (`visibilitychange` / `online` avec `last_seq`).
5. **Explorateur de Fichiers sans TOCTOU (`openat` / `dir_fd` + `O_NOFOLLOW`) & PWA Anti-XSS** :
   - Traversée de descripteurs noyau composant par composant (`os.open(..., dir_fd=..., flags=O_DIRECTORY | O_NOFOLLOW)`), streaming direct depuis le descripteur ouvert (`StreamingResponse`), écriture atomique et `0` `.innerHTML`.

---

## 📊 Transparence : Périmètre Exact des Contrôles (v2.3.0-rc1)

| Mécanisme | Comportement garanti dans v2.3.0-rc1 |
| :--- | :--- |
| **Mode `read_only` (SDK)** | Restreint `enabled_tools` à `BuiltinTools.read_only()` et applique `policy.deny_all()` + liste blanche lecture + confinement fail-closed `enforce_workspace_boundary`. |
| **Mode `assisted` (SDK)** | Validation préalable du tour + interception outil par outil via `policy.safe_defaults(handler=...)`, confinement fail-closed sur les 8 outils fichiers et refus fail-closed si `agent.sandbox_status.available == False`. |
| **Mode `autonomous` *(Risque élevé)*** | Exige à la fois `RunCommandConfig(enable_sandbox=True)` **et** la confirmation effective `agent.sandbox_status.available == True` à l'ouverture de session avant tout `agent.chat()` (sinon arrêt fail-closed immédiat). |
| **Atomicité & Isolation `approval_id`** | Transition `pending -> approved/rejected` atomique sous `threading.Lock` + liaison `session_id` obligatoire (`403` inter-session, `404` double résolution). |
| **Mode `assisted` (CLI `agy`)** | Validation préalable avant le lancement du sous-processus `agy --sandbox --mode accept-edits` (le CLI en mode `--print` ne supporte pas l'interception interactive outil par outil). |
| **Séparation Mot de Passe / Jetons API** | `APP_PASSWORD` est accepté **uniquement** sur `POST /api/v1/auth/login`. Toutes les routes API exigent un jeton HMAC-SHA256 signé non révoqué. |
| **Authentification WebSocket / Download** | Ticket éphémère à usage unique (`tkt_...`, validité 30s) isolé par finalité (`ws` vs `download`), aucun jeton Bearer dans les query parameters. |
| **File WebSocket Bornée & Rattrapage SQLite** | File mémoire bornée (`MAX_WS_QUEUE_SIZE = 256`) avec éviction sans blocage en cas de backpressure et rattrapage automatique des séquences manquantes depuis SQLite (`last_seq`). |
| **Modèle d'exécution Uvicorn (`--workers 1`)** | Les files pub/sub temps réel et les tickets éphémères résident en mémoire de processus : déployez toujours avec un seul worker asynchrone (`uvicorn --workers 1`). |

---

## 🚀 Installation & Démarrage Rapide

```bash
# 1. Installer l'environnement virtuel et les dépendances
./scripts/install_local.sh

# 2. Générer et exporter vos secrets aléatoires obligatoires
export APP_PASSWORD="$(python3 -c 'import secrets; print(secrets.token_urlsafe(18))')"
export APP_SECRET_KEY="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
echo "Votre mot de passe mobile : $APP_PASSWORD"

# 3. Démarrer le serveur en écoute locale (127.0.0.1)
.venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 7860
```

---

## 🧪 Exécuter l'Analyse Statique (`Ruff`) & la Suite de Tests (`Pytest`)

```bash
.venv/bin/ruff check app/ tests/
.venv/bin/pytest tests/ -v
```

---

## 📄 Licence
Distribué sous licence **MIT**. Voir [LICENSE](LICENSE) et [SECURITY.md](SECURITY.md).
