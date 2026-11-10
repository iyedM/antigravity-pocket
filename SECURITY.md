# Politique de Sécurité (Security Policy) — Antigravity Pocket v2.2.0

**Antigravity Pocket** est un compagnon mobile communautaire indépendant conçu selon une architecture **Local-First & Fail-Closed Security**.

---

## 1. Garanties de Sécurité Implémentées et Testées (v2.2.0)

1. **Authentification Fail-Closed Sans Exception (`app/core/security.py`, `app/core/config.py`)** :
   - Aucune option de désactivation de l'authentification n'existe dans le code : le serveur refuse toute requête (`HTTP 503`) tant que `APP_PASSWORD` (minimum 8 caractères, hors liste noire et motifs répétitifs/séquentiels) n'est pas configuré.
   - Rejet automatique des clés d'exemple connues (`0123456789abcdef...`) par `is_strong_secret_value()`.
   - **Révocation Persistante SQLite (`PersistentRevocationStore`)** : Les identifiants `jti` des jetons révoqués via `POST /api/v1/auth/logout` sont enregistrés dans la table SQLite `revoked_tokens` et survivent aux redémarrages du serveur.
   - **Tickets Éphémères à Usage Unique (`EphemeralTicketStore`)** : Les connexions WebSocket et les téléchargements de fichiers utilisent un ticket temporaire (30 secondes, usage unique `tkt_...`) obtenu via `POST /api/v1/auth/ticket`, garantissant que le jeton principal Bearer n'apparaît **jamais** dans les paramètres d'URL (`?token=...`).

2. **Contrôle des Permissions via `google.antigravity.hooks.policy` & Validation Préalable (`app/runtime/adapters/sdk.py`, `app/runtime/adapters/cli.py`)** :
   - **SDK Python (`google-antigravity` v0.1.23+)** :
     - Mode `read_only` : Restreint `CapabilitiesConfig(enabled_tools=BuiltinTools.read_only())` et applique `policy.deny_all()` avec liste blanche explicite des outils de lecture.
     - Mode `assisted` *(par défaut)* : Combine une validation préalable du tour de session et les politiques natives du SDK `policy.workspace_only([workspace])` + `policy.safe_defaults(handler=...)` (qui interceptent chaque outil d'écriture ou d'exécution via `PreToolCallDecideHook`).
     - Mode `autonomous` : Applique `policy.workspace_only([workspace])` + `policy.allow_all()`.
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
