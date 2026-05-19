/**
 * shared/scoring.js
 * ─────────────────────────────────────────────────────────────
 * Moteur de scoring : calcule un score 0–100 de tracking
 * à partir des données collectées par le content script
 * et le service worker.
 * ─────────────────────────────────────────────────────────────
 */

import { SCORING_WEIGHTS, SCORE_THRESHOLDS } from "./constants.js";

/**
 * Calcule le score de tracking global.
 *
 * @param {Object} data - Données brutes agrégées
 * @param {Array}  data.pixelImages        - Images 1x1 / cachées
 * @param {Array}  data.suspiciousRequests - Requêtes URL suspectes
 * @param {Array}  data.knownTrackers      - Domaines dans la liste noire
 * @param {Array}  data.thirdPartyRequests - Requêtes vers domaines tiers
 * @param {Array}  data.fingerprintSignals - Signaux de fingerprinting
 * @param {Array}  data.hiddenIframes      - iFrames cachées
 * @returns {Object} score, level, reasons
 */
export function computeScore(data) {
  const reasons = [];
  let raw = 0;

  // ── Pixels images ──────────────────────────────────────────
  if (data.pixelImages?.length > 0) {
    const pts = Math.min(data.pixelImages.length * SCORING_WEIGHTS.pixelImage, 30);
    raw += pts;
    reasons.push({
      category: "pixel_image",
      label: `${data.pixelImages.length} image(s) pixel détectée(s)`,
      points: pts,
      severity: "high",
      items: data.pixelImages,
    });
  }

  // ── URLs suspectes ─────────────────────────────────────────
  if (data.suspiciousRequests?.length > 0) {
    const pts = Math.min(data.suspiciousRequests.length * SCORING_WEIGHTS.suspiciousUrl, 25);
    raw += pts;
    reasons.push({
      category: "suspicious_url",
      label: `${data.suspiciousRequests.length} URL(s) suspecte(s)`,
      points: pts,
      severity: "medium",
      items: data.suspiciousRequests,
    });
  }

  // ── Domaines tracker connus ────────────────────────────────
  if (data.knownTrackers?.length > 0) {
    const pts = Math.min(data.knownTrackers.length * SCORING_WEIGHTS.knownTrackerDomain, 40);
    raw += pts;
    reasons.push({
      category: "known_tracker",
      label: `${data.knownTrackers.length} domaine(s) tracker connu(s)`,
      points: pts,
      severity: "high",
      items: data.knownTrackers,
    });
  }

  // ── Requêtes tierces ───────────────────────────────────────
  if (data.thirdPartyRequests?.length > 0) {
    const pts = Math.min(data.thirdPartyRequests.length * SCORING_WEIGHTS.thirdPartyRequest, 15);
    raw += pts;
    reasons.push({
      category: "third_party",
      label: `${data.thirdPartyRequests.length} requête(s) vers domaine(s) tiers`,
      points: pts,
      severity: "low",
      items: data.thirdPartyRequests,
    });
  }

  // ── Fingerprinting ─────────────────────────────────────────
  if (data.fingerprintSignals?.length > 0) {
    const pts = Math.min(data.fingerprintSignals.length * SCORING_WEIGHTS.fingerprintScript, 50);
    raw += pts;
    reasons.push({
      category: "fingerprint",
      label: `${data.fingerprintSignals.length} signal(s) de fingerprinting`,
      points: pts,
      severity: "critical",
      items: data.fingerprintSignals,
    });
  }

  // ── iFrames cachées ────────────────────────────────────────
  if (data.hiddenIframes?.length > 0) {
    const pts = Math.min(data.hiddenIframes.length * SCORING_WEIGHTS.hiddenIframe, 20);
    raw += pts;
    reasons.push({
      category: "hidden_iframe",
      label: `${data.hiddenIframes.length} iFrame(s) cachée(s)`,
      points: pts,
      severity: "medium",
      items: data.hiddenIframes,
    });
  }

  // ── Normalisation 0–100 ────────────────────────────────────
  const score = Math.min(Math.round(raw), 100);

  // ── Détermination du niveau ────────────────────────────────
  let level;
  if (score <= SCORE_THRESHOLDS.LOW.max) {
    level = { ...SCORE_THRESHOLDS.LOW, key: "LOW" };
  } else if (score <= SCORE_THRESHOLDS.MEDIUM.max) {
    level = { ...SCORE_THRESHOLDS.MEDIUM, key: "MEDIUM" };
  } else {
    level = { ...SCORE_THRESHOLDS.HIGH, key: "HIGH" };
  }

  return { score, level, reasons };
}
