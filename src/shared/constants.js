/**
 * shared/constants.js
 * ─────────────────────────────────────────────────────────────
 * Base de connaissances centrale du projet.
 * Contient tous les patterns, domaines et règles de scoring.
 * Importé par le content script ET le service worker.
 * ─────────────────────────────────────────────────────────────
 */

// ─── Domaines de tracking connus ────────────────────────────
export const KNOWN_TRACKER_DOMAINS = new Set([
  // Analytics
  "google-analytics.com", "analytics.google.com", "googletagmanager.com",
  "googletagservices.com", "doubleclick.net", "googlesyndication.com",
  // Facebook / Meta
  "facebook.com", "connect.facebook.net", "graph.facebook.com",
  "pixel.facebook.com",
  // Publicité display
  "adnxs.com", "ads.yahoo.com", "advertising.com", "adform.net",
  "rubiconproject.com", "openx.net", "pubmatic.com", "criteo.com",
  "criteo.net", "amazon-adsystem.com", "adsrvr.org",
  // Analytics tiers
  "hotjar.com", "mixpanel.com", "segment.com", "segment.io",
  "amplitude.com", "heap.io", "fullstory.com", "logrocket.com",
  "clarity.ms", "mouseflow.com",
  // Réseaux sociaux
  "platform.twitter.com", "analytics.twitter.com",
  "linkedin.com", "snap.com", "pinterest.com", "tiktok.com",
  // Autres trackers
  "scorecard.research.com", "imrworldwide.com", "quantserve.com",
  "scorecardresearch.com", "comscore.com", "taboola.com",
  "outbrain.com", "moatads.com",
]);

// ─── Patterns d'URL suspects (regex) ────────────────────────
export const SUSPICIOUS_URL_PATTERNS = [
  // Mots-clés classiques des pixels
  /[?&/]pixel[?&/=]/i,
  /[?&/]track(er|ing)?[?&/=]/i,
  /[?&/]beacon[?&/=]/i,
  /[?&/]collect[?&/=]/i,
  /[?&/]event[?&/=]/i,
  /[?&/]ping[?&/=]/i,
  /[?&/]log[?&/=]/i,
  /[?&/]hit[?&/=]/i,
  /[?&/]analytics[?&/=]/i,
  /[?&/]impression[?&/=]/i,
  /[?&/]view[?&/=]/i,

  // Endpoints typiques
  /\/collect(\?|$)/i,
  /\/pixel\.gif/i,
  /\/pixel\.png/i,
  /\/b\.gif/i,
  /\/t\.gif/i,
  /\/beacon\.gif/i,
  /\/1x1\.gif/i,
  /\/clear\.gif/i,
  /\/spacer\.gif/i,

  // Google Analytics / GTM
  /google-analytics\.com\/collect/i,
  /google-analytics\.com\/r\/collect/i,
  /googletagmanager\.com\/gtm\.js/i,
  /googletagmanager\.com\/gtag\/js/i,

  // Facebook
  /facebook\.com\/tr/i,

  // Fingerprinting-like
  /fingerprint/i,
  /fp\.js/i,
  /device_id/i,
];

// ─── Patterns de fingerprinting JS ──────────────────────────
export const FINGERPRINT_PATTERNS = [
  // Canvas fingerprint
  { pattern: /canvas.*?toDataURL/i,        label: "Canvas fingerprint" },
  { pattern: /getImageData/i,              label: "Canvas pixel read" },
  // WebGL
  { pattern: /getParameter.*?RENDERER/i,   label: "WebGL renderer leak" },
  { pattern: /getSupportedExtensions/i,    label: "WebGL extensions" },
  // Audio
  { pattern: /AudioContext|OfflineAudioContext/i, label: "Audio fingerprint" },
  { pattern: /createOscillator/i,          label: "AudioContext oscillator" },
  // Navigateur
  { pattern: /navigator\.plugins/i,        label: "Plugin enumeration" },
  { pattern: /navigator\.languages/i,      label: "Language leak" },
  { pattern: /screen\.colorDepth/i,        label: "Screen color depth" },
  { pattern: /Intl\.DateTimeFormat/i,      label: "Timezone fingerprint" },
  // Font detection
  { pattern: /measureText/i,               label: "Font fingerprint" },
];

// ─── Scoring : poids par catégorie ──────────────────────────
export const SCORING_WEIGHTS = {
  pixelImage:          15,   // Image 1x1 ou invisible
  suspiciousUrl:       10,   // URL avec mot-clé suspect
  knownTrackerDomain:  20,   // Domaine dans la liste noire
  thirdPartyRequest:    5,   // Requête vers domaine tiers
  fingerprintScript:   25,   // Tentative de fingerprinting
  analyticsScript:     10,   // Script analytics détecté
  hiddenIframe:        15,   // iFrame cachée
};

// ─── Seuils du score final ───────────────────────────────────
export const SCORE_THRESHOLDS = {
  LOW:    { max: 30,  label: "Faible",  color: "#22c55e", emoji: "🟢" },
  MEDIUM: { max: 65,  label: "Moyen",   color: "#f59e0b", emoji: "🟡" },
  HIGH:   { max: 100, label: "Élevé",   color: "#ef4444", emoji: "🔴" },
};

// ─── Utilitaire : extraire le domaine d'une URL ──────────────
export function extractDomain(url) {
  try {
    return new URL(url).hostname.replace(/^www\./, "");
  } catch {
    return null;
  }
}

// ─── Utilitaire : comparer deux domaines (tiers ou premier) ─
export function isThirdParty(trackerDomain, pageDomain) {
  if (!trackerDomain || !pageDomain) return false;
  const base = (d) => d.split(".").slice(-2).join(".");
  return base(trackerDomain) !== base(pageDomain);
}
