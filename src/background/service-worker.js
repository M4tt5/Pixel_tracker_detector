/**
 * background/service-worker.js
 * ─────────────────────────────────────────────────────────────
 * Service Worker MV3 — traitement en arrière-plan.
 *
 * Responsabilités :
 *   V2 – Interception des requêtes réseau via chrome.webRequest
 *        (lecture seule, non bloquant — conforme MV3)
 *   V3 – Agrégation des données par onglet
 *        Calcul du score de tracking
 *        Stockage dans chrome.storage.session
 * ─────────────────────────────────────────────────────────────
 *
 * ⚠️  Note MV3 : chrome.declarativeNetRequest remplace le
 *     webRequest bloquant. On utilise ici webRequest en lecture
 *     seule (onCompleted / onBeforeSendHeaders) pour l'analyse.
 * ─────────────────────────────────────────────────────────────
 */

// ─────────────────── CONSTANTES (dupliquées) ─────────────────
// Les service workers MV3 ne supportent pas les imports de
// modules locaux non-bundlés dans tous les contextes.
// Solution propre : utiliser un bundler (esbuild/rollup).

const KNOWN_TRACKER_DOMAINS = new Set([
  "google-analytics.com", "analytics.google.com", "googletagmanager.com",
  "googletagservices.com", "doubleclick.net", "googlesyndication.com",
  "facebook.com", "connect.facebook.net",
  "adnxs.com", "ads.yahoo.com", "advertising.com", "adform.net",
  "rubiconproject.com", "openx.net", "pubmatic.com", "criteo.com",
  "criteo.net", "amazon-adsystem.com", "adsrvr.org",
  "hotjar.com", "mixpanel.com", "segment.com", "segment.io",
  "amplitude.com", "heap.io", "fullstory.com", "logrocket.com",
  "clarity.ms", "mouseflow.com",
  "platform.twitter.com", "analytics.twitter.com",
  "linkedin.com", "tiktok.com",
  "scorecardresearch.com", "comscore.com", "taboola.com",
  "outbrain.com",
]);

const SUSPICIOUS_URL_PATTERNS = [
  /[?&/]pixel[?&/=]/i, /[?&/]track(er|ing)?[?&/=]/i,
  /[?&/]beacon[?&/=]/i, /[?&/]collect[?&/=]/i,
  /\/collect(\?|$)/i, /\/pixel\.(gif|png)/i,
  /\/1x1\.(gif|png)/i, /\/b\.gif/i, /\/clear\.gif/i,
  /google-analytics\.com\/collect/i, /facebook\.com\/tr/i,
];

const SCORING_WEIGHTS = {
  pixelImage: 15, suspiciousUrl: 10,
  knownTrackerDomain: 20, thirdPartyRequest: 5,
  fingerprintScript: 25, hiddenIframe: 15,
};

const SCORE_THRESHOLDS = {
  LOW:    { max: 30,  label: "Faible",  color: "#22c55e", emoji: "🟢" },
  MEDIUM: { max: 65,  label: "Moyen",   color: "#f59e0b", emoji: "🟡" },
  HIGH:   { max: 100, label: "Élevé",   color: "#ef4444", emoji: "🔴" },
};

// ─────────────── CACHE EN MÉMOIRE PAR ONGLET ─────────────────
// Map<tabId, { networkTrackers: Set, suspiciousUrls: Set, ... }>
const tabData = new Map();

function getTabState(tabId) {
  if (!tabData.has(tabId)) {
    tabData.set(tabId, {
      networkTrackers:  new Set(),
      suspiciousUrls:   new Set(),
      thirdPartyDomains: new Set(),
      pageDomain:       null,
      requestCount:     0,
    });
  }
  return tabData.get(tabId);
}

// ─────────────────── UTILITAIRES ─────────────────────────────

function extractDomain(url) {
  try { return new URL(url).hostname.replace(/^www\./, ""); }
  catch { return null; }
}

function isTrackerDomain(domain) {
  if (!domain) return false;
  if (KNOWN_TRACKER_DOMAINS.has(domain)) return true;
  const parts = domain.split(".");
  for (let i = 1; i < parts.length - 1; i++) {
    if (KNOWN_TRACKER_DOMAINS.has(parts.slice(i).join("."))) return true;
  }
  return false;
}

function isThirdParty(trackerDomain, pageDomain) {
  if (!trackerDomain || !pageDomain) return false;
  const base = d => d.split(".").slice(-2).join(".");
  return base(trackerDomain) !== base(pageDomain);
}

function isSuspicious(url) {
  return SUSPICIOUS_URL_PATTERNS.some(p => p.test(url));
}

// ─────────────── V3 : CALCUL DU SCORE ────────────────────────

function computeScore(domData, netData) {
  let raw = 0;
  const reasons = [];

  // Depuis le content script (DOM)
  const px = domData?.pixelImages?.length || 0;
  if (px > 0) {
    const pts = Math.min(px * SCORING_WEIGHTS.pixelImage, 30);
    raw += pts;
    reasons.push({ label: `${px} image(s) pixel`, points: pts, severity: "high" });
  }

  const sr = domData?.suspiciousRequests?.length || 0;
  if (sr > 0) {
    const pts = Math.min(sr * SCORING_WEIGHTS.suspiciousUrl, 20);
    raw += pts;
    reasons.push({ label: `${sr} URL(s) suspecte(s)`, points: pts, severity: "medium" });
  }

  const fp = domData?.fingerprintSignals?.length || 0;
  if (fp > 0) {
    const pts = Math.min(fp * SCORING_WEIGHTS.fingerprintScript, 50);
    raw += pts;
    reasons.push({ label: `${fp} signal(s) fingerprinting`, points: pts, severity: "critical" });
  }

  const hi = domData?.hiddenIframes?.length || 0;
  if (hi > 0) {
    const pts = Math.min(hi * SCORING_WEIGHTS.hiddenIframe, 20);
    raw += pts;
    reasons.push({ label: `${hi} iFrame(s) cachée(s)`, points: pts, severity: "medium" });
  }

  // Depuis le service worker (réseau)
  const nt = netData?.networkTrackers?.size || 0;
  if (nt > 0) {
    const pts = Math.min(nt * SCORING_WEIGHTS.knownTrackerDomain, 40);
    raw += pts;
    reasons.push({ label: `${nt} tracker(s) réseau connu(s)`, points: pts, severity: "high" });
  }

  const su = netData?.suspiciousUrls?.size || 0;
  if (su > 0) {
    const pts = Math.min(su * SCORING_WEIGHTS.suspiciousUrl, 20);
    raw += pts;
    reasons.push({ label: `${su} URL réseau suspecte(s)`, points: pts, severity: "medium" });
  }

  const tp = netData?.thirdPartyDomains?.size || 0;
  if (tp > 0) {
    const pts = Math.min(tp * SCORING_WEIGHTS.thirdPartyRequest, 15);
    raw += pts;
    reasons.push({ label: `${tp} domaine(s) tiers`, points: pts, severity: "low" });
  }

  const score = Math.min(Math.round(raw), 100);

  let level;
  if      (score <= SCORE_THRESHOLDS.LOW.max)    level = { ...SCORE_THRESHOLDS.LOW,    key: "LOW"    };
  else if (score <= SCORE_THRESHOLDS.MEDIUM.max) level = { ...SCORE_THRESHOLDS.MEDIUM, key: "MEDIUM" };
  else                                            level = { ...SCORE_THRESHOLDS.HIGH,   key: "HIGH"   };

  return { score, level, reasons };
}

// ────────────── ÉCOUTE DES REQUÊTES RÉSEAU ───────────────────

/**
 * chrome.webRequest.onCompleted — déclenché après chaque requête.
 * Non bloquant, lecture seule.
 */
chrome.webRequest.onCompleted.addListener(
  (details) => {
    const { tabId, url, initiator } = details;
    if (tabId < 0 || !url) return;

    const domain   = extractDomain(url);
    const initDom  = initiator ? extractDomain(initiator) : null;
    const tab      = getTabState(tabId);

    // Stocker le domaine de la page
    if (initDom && !tab.pageDomain) tab.pageDomain = initDom;

    tab.requestCount++;

    if (isTrackerDomain(domain)) {
      tab.networkTrackers.add(domain);
    }

    if (isSuspicious(url)) {
      tab.suspiciousUrls.add(domain || url);
    }

    if (domain && initDom && isThirdParty(domain, initDom)) {
      tab.thirdPartyDomains.add(domain);
    }
  },
  { urls: ["<all_urls>"] }
);

// ─────────────── NETTOYAGE QUAND ON CHANGE D'ONGLET ──────────

chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
  if (changeInfo.status === "loading") {
    // Réinitialiser les données réseau à chaque nouvelle navigation
    tabData.delete(tabId);
  }
});

chrome.tabs.onRemoved.addListener((tabId) => {
  tabData.delete(tabId);
});

// ───────────── COMMUNICATION AVEC LA POPUP ───────────────────

/**
 * La popup envoie { action: "GET_FULL_REPORT", tabId }
 * On demande les données DOM au content script, on les fusionne
 * avec nos données réseau, et on calcule le score.
 */
chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message.action !== "GET_FULL_REPORT") return;

  const tabId = message.tabId;

  // Récupérer les données DOM via le content script
  chrome.tabs.sendMessage(tabId, { action: "GET_RESULTS" }, (domResponse) => {
    const domData = domResponse?.data || {};
    const netData = getTabState(tabId);

    // Convertir les Sets en Arrays pour la sérialisation
    const networkData = {
      networkTrackers:  [...netData.networkTrackers],
      suspiciousUrls:   [...netData.suspiciousUrls],
      thirdPartyDomains:[...netData.thirdPartyDomains],
      requestCount:     netData.requestCount,
    };

    const scoreResult = computeScore(domData, netData);

    sendResponse({
      success: true,
      dom:     domData,
      network: networkData,
      score:   scoreResult,
      meta: {
        tabId,
        timestamp: Date.now(),
        pageUrl:   domData.pageUrl || "",
        pageDomain:domData.pageDomain || netData.pageDomain || "",
      },
    });
  });

  return true; // Réponse asynchrone
});
