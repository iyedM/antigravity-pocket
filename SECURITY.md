# Politique de Sécurité (Security Policy) — Antigravity Pocket v2.1.0

**Antigravity Pocket** est un compagnon mobile communautaire indépendant conçu selon une architecture **Local-First & Fail-Closed Security**.

---

## 1. Garanties de Sécurité Implémentées et Testées (v2.1.0)

1. **Authentification Fail-Closed & Révocation (`app/core/security.py`, `app/core/config.py`)** :
   - Le serveur refuse toute requête (`HTTP 503`) si `APP_PASSWORD` (minimum 8 caractères, hors liste noire de mots de passe faibles) n'est pas configuré, sauf activation explicite de `AGY_ALLOW_UNAUTHENTICATED_LOCAL=true` pour les tests locaux.
   - Clé secrète HMAC-SHA256 persistante sur toute la durée de vie du serveur (`APP_SECRET_KEY`).
   - Jetons de session signés HMAC-SHA256 incluant un identifiant unique `jti` et une liste de révocation immédiate (`POST /api/v1/auth/logout`).
   - Comparaison en temps constant (`hmac.compare_digest`) et limitation de débit (`RateLimiter` : blocage `HTTP 429` après 10 échecs).

2. **Porte d'Approbation Pré-Exécution Réelle (`app/runtime/adapters/sdk.py`, `app/runtime/adapters/cli.py`)** :
   - En mode `read_only` : `CapabilitiesConfig()` n'est jamais transmis au SDK et le CLI `agy` s'exécute en `--sandbox --mode plan`.
   - En mode `assisted` *(par défaut)* : L'approbation mobile est demandée et attendue **avant** l'instanciation de l'agent avec capacités d'écriture ou le lancement du sous-processus CLI. Si l'utilisateur refuse ou si le délai expire, le moteur n'est jamais exécuté.
   - Aucun appel global à `os.chdir()` (isolation propre entre sessions concurrentes).
   - Aucune utilisation de `--dangerously-skip-permissions`.

3. **Gestion Robuste des Processus CLI (`app/runtime/adapters/cli.py`)** :
   - Consommation simultanée de `stdout` et `stderr` avec plafond mémoire (`MAX_CLI_OUTPUT_BYTES`) évitant tout blocage de pipe OS.
   - Isolation en groupe de processus (`start_new_session=True`) permettant l'arrêt complet de l'arbre de processus (`os.killpg` `SIGTERM` puis `SIGKILL`) en cas d'annulation ou de dépassement de délai (`cli_timeout_seconds`).
   - Vérification stricte du code de retour (`proc.returncode != 0` déclenche une erreur explicite).

4. **Isolation du Workspace, Écriture Atomique & Protection TOCTOU (`app/services/workspace_service.py`)** :
   - Résolution canonique (`is_relative_to`) et rejet de tout lien symbolique (`is_symlink()` + `O_NOFOLLOW` à la lecture).
   - Upload en streaming par chunks (`save_upload_stream`), quota par fichier (`max_upload_bytes`) et quota global de workspace (`max_workspace_bytes`).
   - Écriture atomique via fichier temporaire dans le même système de fichiers (`tempfile.mkstemp` + `os.replace`) et politique explicite de collision (`overwrite` / `HTTP 409`).

5. **Protection XSS Frontend & Synchronisation WebSocket Sans Perte (`app/static/index.html`, `app/api/websocket.py`)** :
   - **Zéro `.innerHTML`** dans le frontend : toutes les données dynamiques sont insérées via `document.createElement` et `textContent` (vérifié par test statique automatisé).
   - **Subscribe-First Replay** : Le WebSocket s'abonne aux événements temps réel dans une file tampon *avant* de rejouer l'historique SQLite (`last_seq`), puis déduplique par numéro de `sequence` (`high_water_seq`), éliminant toute perte d'événement à la reconnexion.

6. **Extraction d'Archive Contrôlée (`safe_extract_tar_bundle`)** :
   - Liste blanche stricte de fichiers (`ALLOWED_BUNDLE_FILES`), rejet des symlinks/hardlinks/traversal, taille maximale de 1 Mo par fichier et permissions `0600`.

---

## 2. Signaler une Vulnérabilité

Merci de ne pas publier de faille de sécurité dans une Issue publique. Utilisez l'onglet **Security → Report a vulnerability** du dépôt GitHub.
