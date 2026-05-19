# 👁 Pixel Tracker Detector

> Extension Chrome (Manifest V3) de détection des pixels trackers, requêtes réseau suspectes et techniques de fingerprinting.  
> **Projet de portfolio – Cybersécurité / Développement logiciel**

![Version](https://img.shields.io/badge/version-1.0.0-blue)
![MV3](https://img.shields.io/badge/Manifest-V3-green)
![License](https://img.shields.io/badge/license-MIT-orange)

---

## 📸 Aperçu

L'extension analyse en temps réel chaque page visitée et fournit :
- Un **score de tracking 0–100** avec classification Faible / Moyen / Élevé
- La liste des **images pixel** (1×1 px, cachées CSS)
- Les **domaines trackers connus** (Google Analytics, Facebook Pixel, Criteo…)
- Les **requêtes réseau suspectes** (fetch, XHR, img src)
- Les **signaux de fingerprinting** (Canvas, WebGL, Audio API)

---

## 🗂 Architecture du projet

```
pixel-tracker-detector/
├── manifest.json                    # Configuration Chrome MV3
├── icons/                           # Icônes 16 / 48 / 128 px
├── src/
│   ├── shared/
│   │   ├── constants.js             # Domaines, patterns, poids scoring
│   │   └── scoring.js               # Moteur de calcul du score
│   ├── content/
│   │   └── content.js               # Analyse DOM + monkey-patch réseau
│   ├── background/
│   │   └── service-worker.js        # Interception webRequest + scoring
│   └── popup/
│       ├── popup.html               # Interface utilisateur
│       ├── popup.css                # Thème dark terminal
│       └── popup.js                 # Contrôleur popup
├── generate_icons.py                # Générateur d'icônes
└── README.md
```

### Rôle de chaque composant

| Fichier | Rôle |
|---|---|
| `content.js` | Injecté dans chaque page. Analyse le DOM, monkey-patche fetch/XHR, détecte le fingerprinting via les scripts inline. |
| `service-worker.js` | Écoute `chrome.webRequest.onCompleted` (lecture seule). Agrège les trackers réseau par onglet. Orchestre le scoring final. |
| `popup.js` | Demande le rapport complet au service worker, rend l'UI dynamiquement. |
| `constants.js` | Source de vérité : liste noire de 40+ domaines, patterns regex, poids de scoring. |
| `scoring.js` | Calcul pur du score 0–100 à partir des données brutes. Testable unitairement. |

---

## 🔬 Comment fonctionne la détection

### V0 — Détection DOM

```
document.querySelectorAll("img")
  → width ≤ 1 ET height ≤ 1           → pixel image
  → display:none / opacity:0           → image cachée
  → src correspond à SUSPICIOUS_PATTERNS → URL suspecte
  → domaine dans KNOWN_TRACKER_DOMAINS → tracker connu
```

### V1 — Communication popup

```
popup.js → chrome.runtime.sendMessage(GET_FULL_REPORT)
         → service-worker.js
         → chrome.tabs.sendMessage(GET_RESULTS) → content.js
         → retour DOM + réseau + score
```

### V2 — Interception réseau (deux couches)

**Couche 1 — Content Script (monkey-patching)**
```javascript
// Remplace window.fetch par un wrapper transparent
window.fetch = function(...args) {
  analyzeNetworkRequest(url, "fetch");
  return originalFetch(...args);   // non bloquant
};
```

**Couche 2 — Service Worker (webRequest API)**
```javascript
chrome.webRequest.onCompleted.addListener(
  (details) => { /* analyse url, initiator, tabId */ },
  { urls: ["<all_urls>"] }
);
```

### V3 — Score de tracking

```
Score = Σ(nombre_occurrences × poids_catégorie), plafonné à 100

Catégorie          Poids    Plafond
────────────────────────────────────
Image pixel          ×15     30 pts
URL suspecte         ×10     25 pts
Tracker connu        ×20     40 pts
Requête tierce       × 5     15 pts
Fingerprinting       ×25     50 pts
iFrame cachée        ×15     20 pts
```

### V4 — Fingerprinting

Détection par analyse des scripts inline via regex :

| Signal | Technique |
|---|---|
| `canvas.toDataURL()` | Canvas fingerprint |
| `getImageData()` | Lecture pixels canvas |
| `getParameter(RENDERER)` | Fuite GPU WebGL |
| `AudioContext + createOscillator` | Audio fingerprint |
| `navigator.plugins` | Énumération plugins |
| `Intl.DateTimeFormat` | Fuite timezone |

---

## ⚠️ Limites et faux positifs

### Limites techniques

- **Monkey-patching** : ne capture pas les requêtes dans les Web Workers ou les Service Workers tiers.
- **Scripts inline** : la détection fingerprinting est basée sur des regex, pas sur l'exécution réelle. Un obfuscateur contourne cette méthode.
- **webRequest MV3** : lecture seule uniquement. Le blocage actif nécessite `declarativeNetRequest` avec des règles statiques.
- **Images lazy-loaded** : les images chargées après scroll peuvent être manquées si l'utilisateur n'a pas scrollé avant d'ouvrir la popup.
- **SPA (React/Vue)** : le MutationObserver recouvre la plupart des cas, mais pas tous les frameworks.

### Faux positifs possibles

| Cas | Explication |
|---|---|
| Images décoratives 1×1 | Un espaceur CSS peut déclencher la détection pixel |
| CDN propres | Un site hébergeant ses propres analytics sur son domaine échappe à la liste noire |
| Canvas pour jeux | Un canvas de jeu vidéo peut ressembler à du fingerprinting |
| `analytics` dans l'URL | Des endpoints légitimes contiennent ce mot |

---

## 🚀 Installation (développement)

```bash
# 1. Cloner le repo
git clone https://github.com/votre-pseudo/pixel-tracker-detector.git
cd pixel-tracker-detector

# 2. Générer les icônes
pip install Pillow
python3 generate_icons.py

# 3. Charger l'extension dans Chrome
#    → chrome://extensions/
#    → Activer "Mode développeur"
#    → "Charger l'extension non empaquetée"
#    → Sélectionner ce dossier
```

---

## 🏗 Évolutions possibles (niveau portfolio avancé)

### Technique
- [ ] **Bundler (esbuild/Rollup)** : permettre les vrais imports ES modules entre content/background
- [ ] **TypeScript** : typage fort, meilleure maintenabilité
- [ ] **Tests unitaires (Vitest)** : tester `scoring.js` et `constants.js` isolément
- [ ] **declarativeNetRequest** : bloquer les requêtes tracker (nécessite règles statiques JSON)
- [ ] **IndexedDB** : historique multi-session des sites analysés
- [ ] **Export JSON/CSV** : rapport téléchargeable

### Détection avancée
- [ ] **Liste EasyPrivacy/uBlock** : intégration des listes de filtres standard
- [ ] **Analyse TLS/headers** : détecter les trackers via les en-têtes HTTP (Set-Cookie tiers, etc.)
- [ ] **Machine Learning (TensorFlow.js)** : classification des URLs par modèle entraîné
- [ ] **Détection comportementale** : fréquence des requêtes, timing

### UX
- [ ] **Badge sur l'icône** : afficher le score directement sur l'icône Chrome
- [ ] **Notifications** : alerter si score > 80
- [ ] **Dashboard multi-sites** : comparaison entre pages visitées
- [ ] **Mode sombre/clair** : toggle thème

---

## 📚 Ressources et références

- [Chrome Extensions MV3 – Migration Guide](https://developer.chrome.com/docs/extensions/mv3/intro/)
- [webRequest API](https://developer.chrome.com/docs/extensions/reference/webRequest/)
- [Browser Fingerprinting – EFF](https://coveryourtracks.eff.org/)
- [Tracking Pixels Explained – MDN](https://developer.mozilla.org/en-US/docs/Web/Performance/Tracking_pixel)
- [EasyPrivacy Filter List](https://easylist.to/easylist/easyprivacy.txt)

---

## 👤 Auteur

Projet de portfolio – Cybersécurité / IoT / Développement logiciel  
Licence MIT — libre d'utilisation et de modification.
