# Politique de Sécurité (Security Policy) — Antigravity Pocket v2.2.0

**Antigravity Pocket** est un compagnon mobile communautaire indépendant conçu selon une architecture **Local-First & Fail-Closed Security**.

---

## 1. Garanties de Sécurité Implémentées et Testées (v2.2.0)

1. **Authentification Fail-Closed & Séparation des Privilèges (`app/core/security.py`, `app/core/config.py`)** :
   - Aucune option de désactivation de l'authentification n'existe dans le code : le serveur refuse toute requête (`HTTP 503`) tant que `APP_PASSWORD` (minimum 8 caractères, hors liste noire et motifs répétitifs/séquentiels) n'est pas configuré.
   - **Séparation stricte Mot de Passe / Jetons API** : `APP_PASSWORD` n'est accepté **que** sur `POST /api/v1/auth/login`. Il est rejeté comme jeton Bearer sur toutes les routes API et WebSocket (`verify_signed_token` exige un jeton HMAC-SHA256 signé, non expiré et non révoqué).
   - **Gestion de `APP_SECRET_KEY`** : Rejet automatique des clés d'exemple connues (`0123456789abcdef...`) par `is_strong_secret_value()`. Si `APP_SECRET_KEY` n'est pas définie dans l'environnement, une clé aléatoire de 256 bits (`secrets.token_hex(32)`) est générée une seule fois et persistée avec les permissions `0600` dans `~/.gemini/antigravity-pocket/secret.key` afin de garantir la stabilité des signatures au redémarrage.
   - **Révocation Persistante SQLite (`PersistentRevocationStore`)** : Les identifiants `jti` des jetons révoqués via `POST /api/v1/auth/logout` sont enregistrés dans la table SQLite `revoked_tokens` et survivent aux redémarrages du serveur.
   - **Tickets Éphémères à Usage Unique & Isolation par Finalité (`EphemeralTicketStore`)** : Les connexions WebSocket (`purpose="ws"`) et les téléchargements de fichiers (`purpose="download"` via `require_download_auth`) utilisent un ticket temporaire (30 secondes, usage unique `tkt_...`) obtenu via `POST /api/v1/auth/ticket`, garantissant que le jeton principal Bearer n'apparaît **jamais** dans les paramètres d'URL (`?token=...`). Les routes REST générales (`require_auth`) n'acceptent que l'en-tête `Authorization: Bearer` et rejettent tout ticket en paramètre d'URL.
   - **Protection Anti-DoS par Bornage Mémoire** : `RateLimiter` (`MAX_TRACKED_CLIENTS = 4096`), `EphemeralTicketStore` (`MAX_ACTIVE_TICKETS = 256`) et les files WebSocket (`MAX_WS_QUEUE_SIZE = 256`) bornent strictement leur empreinte mémoire face aux attaques par inondation (flood) ou aux clients lents.
   - **En-têtes HTTP de Sécurité (`app/main.py`)** : Toutes les réponses HTTP incluent `Content-Security-Policy` (`default-src 'self'`, `frame-ancestors 'none'`), `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, ainsi que `Cache-Control: no-store` sur toutes les routes `/api/`.

2. **Contrôle des Permissions via `google.antigravity.hooks.policy` & Validation Préalable (`app/runtime/adapters/sdk.py`, `app/runtime/adapters/cli.py`)** :
   - **SDK Python (`google-antigravity` v0.1.23+)** :
     - Prédicats dynamiques en mémoire (`enforce_workspace_boundary` sur les outils fichiers et `block_forbidden_command` avec analyse `shlex`/regex et vérification de confinement au workspace sur `run_command`) combinés aux politiques natives du SDK (`policy.workspace_only([workspace])`, `policy.safe_defaults(handler=...)`, `policy.deny_all()`).
     - Mode `read_only` : Restreint `CapabilitiesConfig(enabled_tools=BuiltinTools.read_only())` et applique `policy.deny_all()` avec liste blanche explicite des outils de lecture.
     - Mode `assisted` *(par défaut)* : Combine une validation préalable du tour de session et les politiques natives du SDK `policy.workspace_only([workspace])` + `policy.safe_defaults(handler=...)` (qui interceptent chaque outil d'écriture ou d'exécution via `PreToolCallDecideHook`).
     - Mode `autonomous` *(Mode à risque élevé)* : Applique les gardes de confinement `enforce_workspace_boundary` + `block_forbidden_command` + `policy.workspace_only([workspace])` + `policy.allow_all()`. **Avertissement de sécurité** : un filtrage lexical/heuristique de commandes shell ne remplace pas une isolation système (kernel namespace/cgroups). N'activez le mode `autonomous` que lorsque le serveur tourne dans un conteneur Docker isolé ou via `agy --sandbox`.
   - **CLI (`agy` v1.5.3+)** :
     - Invoqué avec `--sandbox` et `--mode (plan | accept-edits | auto)`.
     - En mode CLI `assisted`, la validation mobile agit comme une **validation préalable du lancement du tour CLI** (et non outil par outil à l'intérieur du processus CLI).

3. **Cycle de Vie des Tâches, Remplacement & Annulation Réelle (`app/runtime/manager.py`, `app/runtime/adapters/sdk.py`)** :
   - En cas de nouveau prompt sur une session déjà active, `start_background_turn` capture la référence exacte de `previous_task` et attend son arrêt complet avant de lancer la nouvelle tâche (évitant toute auto-annulation).
   - Dans `SDKAdapter`, l'exécution est encapsulée dans une `asyncio.Task` dédiée (`_active_sdk_tasks`) : `cancel()` annule la tâche active et débloque immédiatement toute demande d'approbation en attente, provoquant la sortie propre du gestionnaire de contexte `async with Agent(config)`.
   - Dans `CLIAdapter`, `os.killpg` termine l'arbre complet du groupe de processus (`start_new_session=True`), tandis que `stdout` et `stderr` sont consommés simultanément.

4. **Isolation du Workspace, Écriture Atomique & Protection TOCTOU (`app/services/workspace_service.py`)** :
   - Résolution canonique (`is_relative_to`), rejet des liens symboliques (`is_symlink()` + `O_NOFOLLOW` à la lecture).
   - Upload en streaming par chunks (`save_upload_stream`), quotas par fichier et global, écriture atomique (`tempfile.mkstemp` + `os.replace`) et politique explicite de collision (`409 Conflict`).

5. **Protection XSS Frontend & Synchronisation WebSocket Sans Perte (`app/static/index.html`, `app/api/websocket.py`)** :
   - **Zéro `.innerHTML`** et **zéro `?token=`** dans le frontend (vérifié par test statique automatisé).
   - **Subscribe-First Replay** : Abonnement à la file temps réel *avant* la lecture SQLite (`last_seq`), suivi d'une déduplication stricte par `sequence`.

---

## 2. Signaler une Vulnérabilité

Merci de ne pas publier de faille de sécurité dans une Issue publique. Utilisez l'onglet **Security → Report a vulnerability** du dépôt GitHub.
