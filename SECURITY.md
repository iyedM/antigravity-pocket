# Politique de Sécurité (Security Policy) — Antigravity Pocket v2.3.0-rc1

**Antigravity Pocket** est un compagnon mobile communautaire indépendant conçu selon une architecture **Local-First & Fail-Closed Security**.

---

## 1. Garanties de Sécurité Implémentées et Testées (v2.3.0-rc1 — 44/44 Tests Pytest)

1. **Authentification Fail-Closed & Séparation des Privilèges (`app/core/security.py`, `app/core/config.py`)** :
   - Aucune option de désactivation de l'authentification n'existe dans le code : le serveur refuse toute requête (`HTTP 503`) tant que `APP_PASSWORD` (minimum 8 caractères, hors liste noire et motifs répétitifs/séquentiels) n'est pas configuré.
   - **Séparation stricte Mot de Passe / Jetons API** : `APP_PASSWORD` n'est accepté **que** sur `POST /api/v1/auth/login`. Il est rejeté comme jeton Bearer sur toutes les routes API et WebSocket (`verify_signed_token` exige un jeton HMAC-SHA256 signé, non expiré et non révoqué).
   - **Gestion de `APP_SECRET_KEY`** : Rejet automatique des clés d'exemple connues (`0123456789abcdef...`) par `is_strong_secret_value()`. Si `APP_SECRET_KEY` n'est pas définie dans l'environnement, une clé aléatoire de 256 bits (`secrets.token_hex(32)`) est générée une seule fois et persistée avec les permissions `0600` dans `~/.gemini/antigravity-pocket/secret.key` afin de garantir la stabilité des signatures au redémarrage.
   - **Révocation Persistante SQLite (`PersistentRevocationStore`)** : Les identifiants `jti` des jetons révoqués via `POST /api/v1/auth/logout` sont enregistrés dans la table SQLite `revoked_tokens` et survivent aux redémarrages du serveur.
   - **Tickets Éphémères à Usage Unique & Isolation par Finalité (`EphemeralTicketStore`)** : Les connexions WebSocket (`purpose="ws"`) et les téléchargements de fichiers (`purpose="download"` via `require_download_auth`) utilisent un ticket temporaire (30 secondes, usage unique `tkt_...`) obtenu via `POST /api/v1/auth/ticket`, garantissant que le jeton principal Bearer n'apparaît **jamais** dans les paramètres d'URL (`?token=...`). Les routes REST générales (`require_auth`) n'acceptent que l'en-tête `Authorization: Bearer` et rejettent tout ticket en paramètre d'URL.
   - **Protection Anti-DoS par Bornage Mémoire** : `RateLimiter` (`MAX_TRACKED_CLIENTS = 4096`), `EphemeralTicketStore` (`MAX_ACTIVE_TICKETS = 256`) et les files WebSocket (`MAX_WS_QUEUE_SIZE = 256`) bornent strictement leur empreinte mémoire face aux attaques par inondation (flood) ou aux clients lents.
   - **En-têtes HTTP de Sécurité (`app/main.py`)** : Toutes les réponses HTTP incluent `Content-Security-Policy` (`default-src 'self'`, `frame-ancestors 'none'`), `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, ainsi que `Cache-Control: no-store` sur toutes les routes `/api/`.

2. **Contrôle des Permissions, Atomicité des Approbations & Sandbox OS (`app/runtime/adapters/sdk.py`, `app/core/permissions.py`)** :
   - **Atomicité & Isolation Inter-Sessions (`ApprovalManager`)** : Toutes les transitions d'état (`pending -> approved/rejected`) sont sérialisées par un verrou `threading.Lock` (`MAX_TRACKED_APPROVALS = 1024`), empêchant toute course critique entre requêtes concurrentes ou expiration de délai. Chaque résolution exige la correspondance stricte `expected_session_id` (`403 Forbidden` en cas de tentative inter-session, `404` sur double résolution).
   - **SDK Python (`google-antigravity` v0.1.23+)** :
     - Validation fail-closed des schémas sur les 8 outils fichiers (`view_file`, `create_file`, `edit_file`, `list_directory`, `search_directory`, `find_file`, `write_file`, `delete_file`), rejetant tout champ inconnu, octet nul `\x00` ou lien symbolique indirect pointant hors du workspace.
     - Activation explicite de `RunCommandConfig(enable_sandbox=True, enable_daemons=False, timeout_seconds=120.0)` **et vérification à l'exécution** de `agent.sandbox_status` dès l'entrée dans `async with Agent(config)` avant tout appel `agent.chat()` : si `sandbox_status.available == False` (ou si `sandbox_status` est non confirmé en mode `autonomous`), la session échoue proprement en mode fail-closed (`SESSION_ERROR`).
   - **CLI (`agy` v1.5.3+)** :
     - Invoqué avec `--sandbox` et `--mode (plan | accept-edits | auto)`. En mode `assisted`, la validation mobile agit comme une validation préalable du lancement du tour CLI.

3. **Cycle de Vie des Tâches, Statuts d'Erreur & Annulation Réelle (`app/runtime/manager.py`, `app/runtime/adapters/sdk.py`)** :
   - Toute émission de `SESSION_ERROR` ou refus d'approbation marque immédiatement la session en statut non terminé (`error`/`rejected`) et empêche toute émission ultérieure de `SESSION_COMPLETED`.
   - En cas de nouveau prompt sur une session déjà active, `start_background_turn` capture `previous_task` explicitement et attend son arrêt complet avant de lancer `new_task`.
   - Annulation réelle de tâche dans `SDKAdapter` (`_active_sdk_tasks[session_id].cancel()`) et terminaison du groupe de processus (`os.killpg`) dans `CLIAdapter`.

4. **Isolation du Workspace sans Fenêtre TOCTOU (`openat` / `dir_fd` + `O_NOFOLLOW` dans `app/services/workspace_service.py`)** :
   - Lecture d'aperçu (`preview_file`) et téléchargement (`open_download_stream` + `StreamingResponse`) par traversée atomique de descripteurs de répertoires (`os.open(..., dir_fd=..., flags=O_DIRECTORY | O_NOFOLLOW)`), éliminant toute fenêtre de course (TOCTOU) sur les dossiers intermédiaires comme sur le fichier cible, sans réouverture par chemin.
   - Upload en streaming par chunks (`save_upload_stream`), quotas par fichier et global, écriture atomique (`tempfile.mkstemp` + `os.replace`) et politique explicite de collision (`409 Conflict`).

5. **Protection XSS Frontend & Synchronisation WebSocket Mobile (`app/static/index.html`, `app/api/websocket.py`)** :
   - **Zéro `.innerHTML`**, **zéro `eval()`** et **zéro `?token=`** dans le frontend (vérifié par test statique et syntaxique AST `node --check`).
   - **Subscribe-First Replay + Backpressure + Reconnexion Mobile** : File bornée (`MAX_WS_QUEUE_SIZE = 256`) avec rattrapage SQLite automatique, compteur de génération `wsGeneration` anti-course et reconnexion automatique exponentielle sur reprise réseau (`visibilitychange` / `online` avec `last_seq`).

---

## 2. Signaler une Vulnérabilité

Merci de ne pas publier de faille de sécurité dans une Issue publique. Utilisez l'onglet **Security → Report a vulnerability** du dépôt GitHub.
