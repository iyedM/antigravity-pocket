---
title: Antigravity Pocket
emoji: 🚀
colorFrom: blue
colorTo: purple
sdk: docker
app_port: 7860
pinned: false
---

# 🚀 Antigravity Pocket — Open-Source Mobile Companion (iPhone & Android)

**Antigravity Pocket** est une application Web Mobile Progressive (PWA) auto-hébergeable qui vous permet d'utiliser **Google Antigravity** sur votre **iPhone (iOS)** ou **Android** avec **votre propre compte Google**, même lorsque **votre PC est éteint**.

---

## 📱 Guide Étape par Étape : Utiliser sur iPhone 15 (100% Gratuit & SANS Carte Bancaire)

La plupart des hébergeurs Cloud demandent une carte bancaire. Pour héberger votre agent Antigravity **gratuitement (0 €) et sans aucune carte bancaire**, nous utilisons **Hugging Face Spaces (Docker)** qui offre gratuitement un serveur Linux avec **2 vCPU et 16 Go de RAM** allumé dans le Cloud.

### Étape 1 : Exporter votre session Google Antigravity depuis votre PC (1 seule fois)
Sur votre PC (où vous êtes déjà connecté à Antigravity), ouvrez un terminal dans ce dossier et lancez :
```bash
python3 export_session.py
```
Ce script génère un fichier local `.agy_auth_bundle.secret.txt` (ignoré par Git) qui contient votre session Google et vos règles `~/.gemini/GEMINI.md`.

### Étape 2 : Créer votre serveur Cloud gratuit sans carte bancaire
1. Créez un compte gratuit sur **[huggingface.co](https://huggingface.co/join)** (juste un email, **aucune carte bancaire**).
2. Cliquez sur votre profil en haut à droite $\rightarrow$ **New Space** :
   - **Space name** : `antigravity-pocket`
   - **Select the Space SDK** : choisissez **Docker** (puis *Blank*)
   - **Space Hardware** : laissez **CPU basic • 2 vCPU • 16 GB • FREE**
   - Cliquez sur **Create Space**.
3. Allez dans l'onglet **Settings** de votre Space $\rightarrow$ section **Variables and secrets** $\rightarrow$ cliquez sur **New secret** :
   - Secret 1 : Nom = `AGY_AUTH_BUNDLE` | Valeur = collez le contenu du fichier `.agy_auth_bundle.secret.txt`.
   - Secret 2 : Nom = `APP_PASSWORD` | Valeur = choisissez un mot de passe personnel (ex: `MonMotDePasse123`).
4. Uploadez les fichiers de ce projet dans votre Space (via *Files* $\rightarrow$ *Add file* $\rightarrow$ *Upload files* ou `git push`).

### Étape 3 : Installer l'application sur l'écran d'accueil de votre iPhone 15
1. Une fois le Space démarré (*Running*), ouvrez l'URL directe de votre Space dans **Safari** sur votre **iPhone 15** :
   `https://<votre-pseudo>-antigravity-pocket.hf.space`
2. Appuyez sur le bouton **🔑 Accès** en haut à droite et entrez votre `APP_PASSWORD`.
3. Dans Safari sur l'iPhone 15, appuyez sur l'icône **Partager** (en bas au centre) $\rightarrow$ **Sur l'écran d'accueil** $\rightarrow$ **Ajouter**.
4. Vous avez maintenant l'application **Antigravity** sur votre iPhone 15 en plein écran (compatible *Dynamic Island*), utilisable **même quand votre PC est éteint** !

---

## 🤖 Alternative : Utiliser votre Samsung A52 comme serveur local (0 €)

Si vous souhaitez faire tourner le serveur directement sur votre téléphone Android (**Samsung A52** en ARM64 `aarch64`) :
1. Installez **Termux** sur le Samsung A52.
2. Lancez `./install_android_termux.sh`.
3. Vous pouvez y accéder directement sur le Samsung A52 (`http://localhost:7860`) ou depuis votre **iPhone 15** en Wi-Fi / partage de connexion !

---

## 🌍 Pour la Communauté Open Source (GitHub)

### Fonctionnalités
- **SDK Officiel [`google-antigravity`](https://pypi.org/project/google-antigravity/) + Fallback CLI `agy`**
- **Streaming WebSocket Temps Réel** : Affiche les pensées de l'agent (`thoughts`), les outils exécutés (`tool_calls`) et la réponse en direct.
- **Upload & Download de fichiers** : Prenez une photo d'énoncé avec l'appareil photo de l'iPhone ou envoyez un fichier, puis téléchargez les fichiers générés depuis le tiroir **📁 Fichiers**.
- **Zéro fuite de données** : Les identifiants de session ne sont jamais stockés dans le code mais injectés via la variable d'environnement secrète `AGY_AUTH_BUNDLE`.

### Licence
Distribué sous licence MIT — Libre d'utilisation et de partage pour toute la communauté Antigravity.
