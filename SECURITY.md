# Politique de Sécurité (Security Policy) — Antigravity Pocket

**Antigravity Pocket** est un compagnon mobile communautaire indépendant conçu avec une architecture **Security-First**.

---

## 1. Modèle de Menace & Principes de Sécurité

Contrôler un agent de développement depuis un appareil mobile implique des risques spécifiques que l'architecture mitige à cinq niveaux :

1. **Suppression totale de `--dangerously-skip-permissions`** :
   - Le binaire `agy` est systématiquement invoqué avec `--sandbox` et un `--mode` explicite (`plan`, `accept-edits` ou `auto`).
   - Le SDK `google-antigravity` n'active `CapabilitiesConfig()` que lorsque le mode de la session l'autorise.

2. **Modèle de Permissions à 3 Niveaux (`PermissionMode`)** :
   - `read_only` : Consultation et diagnostic uniquement (aucune écriture ni exécution).
   - `assisted` *(par défaut)* : Toute opération sensible génère une carte d'approbation temps réel (`approval_required`) sur le téléphone avec blocage asynchrone jusqu'à validation explicite (`[Approuver]` / `[Refuser]`).
   - `autonomous` : Opérations autorisées à l'intérieur du sandbox du workspace, tout en bloquant les commandes système destructrices (`FORBIDDEN_PATTERNS`).

3. **Authentification & Protection Anti-Brute-Force** :
   - Comparaison des mots de passe en temps constant (`hmac.compare_digest`).
   - Émission de jetons de session signés **HMAC-SHA256** avec expiration (`AGY_TOKEN_TTL_SECONDS`).
   - Limitation de débit en mémoire (`RateLimiter`) bloquant les adresses IP après 10 échecs en 60 secondes (`HTTP 429`).

4. **Isolation Stricte du Workspace (`WorkspaceService`)** :
   - Vérification canonique `Path.resolve().is_relative_to(workspace_root)` contre toute attaque *Path Traversal* (`../`).
   - Rejet systématique des liens symboliques (`is_symlink()`) sur chaque segment du chemin.
   - Quotas stricts sur la taille maximale des fichiers envoyés (`AGY_MAX_UPLOAD_MB`).

5. **Protection des Identifiants (Local-First & AES-256-GCM)** :
   - En **Mode 1 (PC Local)** et **Mode 2 (Home Pocket Server Android ARM64 / Raspberry Pi)**, les identifiants `~/.gemini` ne quittent jamais votre réseau privé.
   - En **Mode 3 (Conteneur Cloud)**, tout export optionnel via `scripts/export_encrypted_bundle.py` est chiffré avec **AES-256-GCM** et dérivation de clé **PBKDF2-HMAC-SHA256 (200 000 itérations)** — jamais en simple Base64.

---

## 2. Signaler une Vulnérabilité

Ne publiez pas de faille de sécurité dans une Issue publique. Ouvrez un signalement privé via l'onglet **Security → Report a vulnerability** du dépôt GitHub.
