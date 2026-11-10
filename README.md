# 🚀 Antigravity Pocket v2.2.0 (Release Candidate)

> **Compagnon Mobile Open-Source (iOS & Android PWA) pour superviser et contrôler vos agents Google Antigravity.**
> *Avis : Antigravity Pocket est un projet communautaire indépendant et n'est pas un produit officiel de Google.*

---

## ✨ Garanties Techniques Vérifiées (v2.2.0)

1. **Authentification Fail-Closed, Révocation SQLite & Tickets à Usage Unique** :
   - Authentification obligatoire dans tous les modes (aucun contournement local non authentifié, rejet des secrets faibles ou séquentiels).
   - Révocation persistante des jetons (`jti`) stockée dans SQLite (`revoked_tokens`).
   - Échange de **tickets éphémères à usage unique (30s)** (`POST /api/v1/auth/ticket`) pour l'ouverture du WebSocket et le téléchargement de fichiers : le jeton Bearer principal n'est **jamais** exposé dans les URL.
2. **Intégration Réelle des Politiques du SDK `google-antigravity` (`v0.1.23+`) & du CLI `agy` (`v1.5.3+`)** :
   - **Avec `SDKAdapter`** : Utilise `LocalAgentConfig(workspaces=[workspace], capabilities=..., policies=...)` avec `BuiltinTools.read_only()`, `policy.workspace_only([workspace])` et `policy.safe_defaults(handler=...)` (`PreToolCallDecideHook`).
   - **Avec `CLIAdapter`** : Utilise `agy --print --sandbox --mode (plan|accept-edits|auto)` avec validation préalable du lancement du tour en mode `assisted`.
3. **Remplacement de Tâche Sans Conflit & Annulation Réelle** :
   - Séparation explicite entre `previous_task` et `new_task` dans `AgentRuntimeManager`.
   - Annulation réelle de la tâche asyncio du SDK (`sdk_task.cancel()`) et terminaison du groupe de processus CLI (`os.killpg`).
4. **Synchronisation WebSocket Sans Perte (`Subscribe-First Replay`)** :
   - Abonnement à la file d'événements en direct *avant* la relecture SQLite (`last_seq`) et déduplication par `sequence`.
5. **Explorateur de Fichiers Atomique & Interface Mobile 6 Onglets Anti-XSS** :
   - Streaming par chunks, écriture atomique (`tempfile` + `os.replace`), lecture `O_NOFOLLOW`, quotas et 0 utilisation de `.innerHTML`.

---

## 📊 Transparence : Périmètre Exact des Contrôles (v2.2.0)

| Mécanisme | Comportement garanti dans v2.2.0 |
| :--- | :--- |
| **Mode `read_only` (SDK)** | Restreint `enabled_tools` à `BuiltinTools.read_only()` et applique `policy.deny_all()` + liste blanche lecture. |
| **Mode `assisted` (SDK)** | Validation préalable du tour + interception outil par outil via `policy.safe_defaults(handler=...)` et `policy.workspace_only()`. |
| **Mode `assisted` (CLI `agy`)** | Validation préalable avant le lancement du sous-processus `agy --sandbox --mode accept-edits` (le CLI en mode `--print` ne supporte pas l'interception interactive outil par outil). |
| **Authentification WebSocket / Download** | Ticket éphémère à usage unique (`tkt_...`, validité 30s), aucun jeton Bearer dans les query parameters. |
| **Révocation de session (`Logout`)** | Persistée sur disque dans la table SQLite `revoked_tokens` (survit aux redémarrages). |

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
