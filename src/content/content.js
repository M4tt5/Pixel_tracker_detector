/**
 * content/content.js
 * ─────────────────────────────────────────────────────────────
 * Content Script — injecté dans chaque page visitée.
 *
 * Responsabilités :
 *   V0 – Détection DOM (images pixel, iframes cachées)
 *   V1 – Communication avec la popup via chrome.runtime
 *   V2 – Interception fetch/XHR (monkey-patching sécurisé)
 *   V4 – Détection fingerprinting via analyse des scripts inline
 * ─────────────────────────────────────────────────────────────
 */

// Note : les imports ES modules ne fonctionnent pas directement
// dans les content scripts MV3 → on intègre les constantes ici.
// En production, utiliser un bundler (Rollup/esbuild).

// ─────────────────────── CONSTANTES ──────────────────────────

const KNOWN_TRACKER_DOMAINS = new Set([
  "google-analytics.com", "analytics.google.com", "googletagmanager.com",
  "googletagservices.com", "doubleclick.net", "googlesyndication.com",
  "facebook.com", "connect.facebook.net", "graph.facebook.com",
  "adnxs.com", "ads.yahoo.com", "advertising.com", "adform.net",
  "rubiconproject.com", "openx.net", "pubmatic.com", "criteo.com",
  "criteo.net", "amazon-adsystem.com", "adsrvr.org",
  "hotjar.com", "mixpanel.com", "segment.com", "segment.io",
  "amplitude.com", "heap.io", "fullstory.com", "logrocket.com",
  "clarity.ms", "mouseflow.com",
  "platform.twitter.com", "analytics.twitter.com",
  "linkedin.com", "snap.com", "tiktok.com",
  "scorecard.research.com", "imrworldwide.com", "quantserve.com",
  "scorecardresearch.com", "comscore.com", "taboola.com",
  "outbrain.com", "moatads.com",
]);

const SUSPICIOUS_URL_PATTERNS = [
  /[?&/]pixel[?&/=]/i, /[?&/]track(er|ing)?[?&/=]/i,
  /[?&/]beacon[?&/=]/i, /[?&/]collect[?&/=]/i,
  /[?&/]ping[?&/=]/i, /[?&/]analytics[?&/=]/i,
  /\/collect(\?|$)/i, /\/pixel\.(gif|png)/i,
  /\/b\.gif/i, /\/t\.gif/i, /\/beacon\.gif/i,
  /\/1x1\.(gif|png)/i, /\/clear\.gif/i, /\/spacer\.gif/i,
  /google-analytics\.com\/collect/i,
  /facebook\.com\/tr/i, /fingerprint/i,
];

const FINGERPRINT_PATTERNS = [
  { pattern: /canvas.*?toDataURL/,        label: "Canvas fingerprint" },
  { pattern: /getImageData/,              label: "Canvas pixel read" },
  { pattern: /getParameter.*?RENDERER/,   label: "WebGL renderer" },
  { pattern: /getSupportedExtensions/,    label: "WebGL extensions" },
  { pattern: /AudioContext|OfflineAudioContext/, label: "Audio fingerprint" },
  { pattern: /createOscillator/,          label: "AudioContext oscillator" },
  { pattern: /navigator\.plugins/,        label: "Plugin enumeration" },
  { pattern: /screen\.colorDepth/,        label: "Screen color depth" },
  { pattern: /Intl\.DateTimeFormat/,      label: "Timezone fingerprint" },
  { pattern: /measureText/,              label: "Font fingerprint" },
];

// ─────────────────────── ÉTAT LOCAL ──────────────────────────

const state = {
  pixelImages:        [],   // Images 1x1 ou cachées
  hiddenIframes:      [],   // iFrames invisibles
  suspiciousRequests: [],   // URLs suspectes (fetch/XHR/img src)
  knownTrackers:      [],   // Domaines tracker connus
  thirdPartyRequests: [],   // Requêtes vers domaines tiers
  fingerprintSignals: [],   // Signaux de fingerprinting JS
  initialized:        false,
};

// ─────────────────────── UTILITAIRES ─────────────────────────

function extractDomain(url) {
  try { return new URL(url).hostname.replace(/^www\./, ""); }
  catch { return null; }
}

function isThirdParty(domain) {
  if (!domain) return false;
  const pageBase = location.hostname.replace(/^www\./, "").split(".").slice(-2).join(".");
  const trkBase  = domain.split(".").slice(-2).join(".");
  return pageBase !== trkBase;
}

function isTrackerDomain(domain) {
  if (!domain) return false;
  // Vérification exacte + suffixe (ex: sub.criteo.com → criteo.com)
  if (KNOWN_TRACKER_DOMAINS.has(domain)) return true;
  const parts = domain.split(".");
  for (let i = 1; i < parts.length - 1; i++) {
    if (KNOWN_TRACKER_DOMAINS.has(parts.slice(i).join("."))) return true;
  }
  return false;
}

function isSuspiciousUrl(url) {
  return SUSPICIOUS_URL_PATTERNS.some(p => p.test(url));
}

function addUniqueByUrl(arr, item) {
  if (!arr.some(i => i.url === item.url)) arr.push(item);
}

// ─────────────────────── V0 : ANALYSE DOM ────────────────────

/**
 * Analyse toutes les balises <img> de la page.
 * Détecte :
 *  - Images dont width ou height ≤ 1 (pixels invisibles)
 *  - Images avec display:none / visibility:hidden / opacity:0
 *  - Images dont le src correspond à un pattern suspect
 */
function analyzeImages() {
  const images = document.querySelectorAll("img");

  images.forEach(img => {
    const src = img.src || img.getAttribute("src") || "";
    if (!src || src.startsWith("data:")) return;

    const style    = window.getComputedStyle(img);
    const w        = img.naturalWidth  || parseInt(img.getAttribute("width")  || "0");
    const h        = img.naturalHeight || parseInt(img.getAttribute("height") || "0");
    const isHidden = style.display === "none"
                  || style.visibility === "hidden"
                  || parseFloat(style.opacity) === 0;
    const isPixel  = (w <= 1 && h <= 1 && w !== 0 && h !== 0)
                  || (img.width <= 1 && img.height <= 1);
    const isSusp   = isSuspiciousUrl(src);
    const domain   = extractDomain(src);
    const isTrack  = isTrackerDomain(domain);

    if (isPixel || isHidden || isSusp || isTrack) {
      const entry = {
        url:    src,
        domain,
        width:  w,
        height: h,
        hidden: isHidden,
        pixel:  isPixel,
        suspicious: isSusp,
        knownTracker: isTrack,
        reason: isPixel ? "Image 1×1 px" :
                isHidden ? "Image cachée (CSS)" :
                isSusp   ? "URL suspecte" : "Domaine tracker",
      };

      addUniqueByUrl(state.pixelImages, entry);

      if (isTrack && !state.knownTrackers.some(k => k.domain === domain)) {
        state.knownTrackers.push({ domain, source: "img_tag", url: src });
      }
      if (isThirdParty(domain)) {
        addUniqueByUrl(state.thirdPartyRequests, { url: src, domain, source: "img_tag" });
      }

      // V0 : log console
      console.group(`[PixelTracker] 🎯 Image suspecte détectée`);
      console.log("URL     :", src);
      console.log("Raison  :", entry.reason);
      console.log("Domaine :", domain);
      console.groupEnd();
    }
  });
}

/**
 * Analyse les balises <iframe>.
 * Détecte les iframes cachées souvent utilisées pour le tracking.
 */
function analyzeIframes() {
  const iframes = document.querySelectorAll("iframe");

  iframes.forEach(frame => {
    const src   = frame.src || "";
    const style = window.getComputedStyle(frame);
    const w     = frame.offsetWidth;
    const h     = frame.offsetHeight;

    const isHidden = style.display === "none"
                  || style.visibility === "hidden"
                  || w === 0 || h === 0
                  || parseFloat(style.opacity) === 0;

    if (!isHidden) return;

    const domain   = extractDomain(src);
    const isTrack  = isTrackerDomain(domain);
    const isSusp   = isSuspiciousUrl(src);

    if (isHidden && (isTrack || isSusp || isThirdParty(domain))) {
      addUniqueByUrl(state.hiddenIframes, { url: src, domain, reason: "iFrame cachée" });
      console.warn(`[PixelTracker] 🖼️ iFrame cachée : ${src}`);
    }
  });
}

/**
 * Analyse les balises <script> pour détecter du fingerprinting.
 * Inspecte le contenu inline des scripts.
 */
function analyzeScripts() {
  const scripts = document.querySelectorAll("script:not([src])");

  scripts.forEach(script => {
    const code = script.textContent || "";
    if (!code.trim()) return;

    FINGERPRINT_PATTERNS.forEach(({ pattern, label }) => {
      if (pattern.test(code)) {
        if (!state.fingerprintSignals.some(s => s.label === label)) {
          state.fingerprintSignals.push({ label, source: "inline_script" });
          console.warn(`[PixelTracker] 🔍 Fingerprinting détecté : ${label}`);
        }
      }
    });
  });

  // Scripts externes : vérifier le domaine
  const externalScripts = document.querySelectorAll("script[src]");
  externalScripts.forEach(script => {
    const src    = script.src;
    const domain = extractDomain(src);
    if (!domain) return;

    if (isTrackerDomain(domain)) {
      if (!state.knownTrackers.some(k => k.domain === domain)) {
        state.knownTrackers.push({ domain, source: "script_tag", url: src });
      }
      if (isThirdParty(domain)) {
        addUniqueByUrl(state.thirdPartyRequests, { url: src, domain, source: "script_tag" });
      }
      if (isSuspiciousUrl(src)) {
        addUniqueByUrl(state.suspiciousRequests, { url: src, domain, source: "script_tag" });
      }
    }
  });
}

// ─────────────── V2 : INTERCEPTION RÉSEAU ────────────────────

/**
 * Monkey-patch de fetch() pour intercepter les requêtes XHR/Fetch.
 * Technique : on remplace window.fetch par notre wrapper, puis
 * on appelle l'original. Non bloquant, non intrusif.
 *
 * ⚠️  Limites : ne capture pas les requêtes faites dans des Workers
 *     ni les prefetch/preconnect du navigateur.
 */
function patchFetch() {
  const originalFetch = window.fetch.bind(window);

  window.fetch = function (...args) {
    const url = typeof args[0] === "string" ? args[0] : args[0]?.url || "";
    analyzeNetworkRequest(url, "fetch");
    return originalFetch(...args);
  };
}

/**
 * Monkey-patch de XMLHttpRequest.open().
 */
function patchXHR() {
  const OriginalXHR  = window.XMLHttpRequest;
  const originalOpen = OriginalXHR.prototype.open;

  OriginalXHR.prototype.open = function (method, url, ...rest) {
    analyzeNetworkRequest(String(url), "xhr");
    return originalOpen.call(this, method, url, ...rest);
  };
}

/**
 * Analyse une URL de requête réseau (fetch ou XHR).
 */
function analyzeNetworkRequest(url, source) {
  if (!url || url.startsWith("data:") || url.startsWith("blob:")) return;

  const domain   = extractDomain(url);
  const isTrack  = isTrackerDomain(domain);
  const isSusp   = isSuspiciousUrl(url);
  const isTP     = isThirdParty(domain);

  if (isTrack && !state.knownTrackers.some(k => k.domain === domain)) {
    state.knownTrackers.push({ domain, source, url });
    console.warn(`[PixelTracker] 🌐 Tracker réseau (${source}) : ${domain}`);
  }

  if (isSusp) {
    addUniqueByUrl(state.suspiciousRequests, { url, domain, source });
    console.warn(`[PixelTracker] ⚠️  URL suspecte (${source}) : ${url}`);
  }

  if (isTP) {
    addUniqueByUrl(state.thirdPartyRequests, { url, domain, source });
  }
}

// ─────────────────── INITIALISATION ──────────────────────────

function runAnalysis() {
  if (state.initialized) return;
  state.initialized = true;

  // Patch réseau AVANT l'analyse DOM (pour capturer les requêtes lazy)
  try { patchFetch(); } catch (e) { console.warn("[PixelTracker] fetch patch failed", e); }
  try { patchXHR();   } catch (e) { console.warn("[PixelTracker] XHR patch failed", e);   }

  // Analyse DOM
  analyzeImages();
  analyzeIframes();
  analyzeScripts();

  // Résumé console (V0)
  console.group("[PixelTracker] 📊 Résumé d'analyse");
  console.log("Images pixel/cachées :", state.pixelImages.length);
  console.log("iFrames cachées      :", state.hiddenIframes.length);
  console.log("URLs suspectes       :", state.suspiciousRequests.length);
  console.log("Trackers connus      :", state.knownTrackers.length);
  console.log("Requêtes tierces     :", state.thirdPartyRequests.length);
  console.log("Fingerprinting       :", state.fingerprintSignals.length);
  console.groupEnd();
}

// ─────────── COMMUNICATION AVEC LA POPUP (V1) ────────────────

/**
 * Écoute les messages de la popup.
 * La popup envoie { action: "GET_RESULTS" }
 * On répond avec l'état complet.
 */
chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message.action === "GET_RESULTS") {
    // Re-scan rapide au moment où la popup est ouverte
    analyzeImages();
    analyzeIframes();
    analyzeScripts();

    sendResponse({
      success: true,
      data: {
        pixelImages:        state.pixelImages,
        hiddenIframes:      state.hiddenIframes,
        suspiciousRequests: state.suspiciousRequests,
        knownTrackers:      state.knownTrackers,
        thirdPartyRequests: state.thirdPartyRequests,
        fingerprintSignals: state.fingerprintSignals,
        pageUrl:            location.href,
        pageDomain:         location.hostname,
        timestamp:          Date.now(),
      },
    });
    return true; // Réponse asynchrone
  }
});

// ─────────────────────── LANCEMENT ───────────────────────────

// Lancer après chargement du DOM
if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", runAnalysis);
} else {
  runAnalysis();
}

// Observer les mutations DOM (SPA, chargements dynamiques)
const observer = new MutationObserver(() => {
  // Re-analyser uniquement si de nouveaux noeuds sont ajoutés
  analyzeImages();
  analyzeIframes();
});

observer.observe(document.body || document.documentElement, {
  childList: true,
  subtree:   true,
});
