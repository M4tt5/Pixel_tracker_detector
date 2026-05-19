/**
 * popup/popup.js
 * ─────────────────────────────────────────────────────────────
 * Contrôleur de la popup Chrome.
 *
 * Flux :
 *   1. Récupère l'onglet actif
 *   2. Envoie GET_FULL_REPORT au service worker
 *   3. Reçoit { dom, network, score, meta }
 *   4. Rend l'interface
 * ─────────────────────────────────────────────────────────────
 */

// ─────────────────── ÉTAT LOCAL ──────────────────────────────

let currentReport = null;

// ─────────────────── UTILITAIRES DOM ─────────────────────────

const $ = (id) => document.getElementById(id);

function show(id)  { $(id).classList.remove("hidden"); }
function hide(id)  { $(id).classList.add("hidden"); }

function setState(state) {
  hide("state-loading");
  hide("state-error");
  hide("main-content");
  show(`state-${state}`);
}

// ─────────────────── RÉCUPÉRATION DES DONNÉES ────────────────

async function fetchReport() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab?.id) throw new Error("Aucun onglet actif.");

  // Vérifier que la page est analysable (pas chrome://, about:, etc.)
  if (!tab.url?.startsWith("http")) {
    throw new Error("Cette page ne peut pas être analysée.\n(pages internes Chrome non supportées)");
  }

  return new Promise((resolve, reject) => {
    chrome.runtime.sendMessage(
      { action: "GET_FULL_REPORT", tabId: tab.id },
      (response) => {
        if (chrome.runtime.lastError) {
          reject(new Error(chrome.runtime.lastError.message));
          return;
        }
        if (!response?.success) {
          reject(new Error("Analyse échouée. Rechargez la page et réessayez."));
          return;
        }
        resolve(response);
      }
    );
  });
}

// ─────────────────── RENDU : SCORE ───────────────────────────

function renderScore(score, level, meta) {
  // Valeur numérique
  $("score-value").textContent = score;

  // Arc SVG — circumference = 2π × 42 ≈ 264
  const circ   = 264;
  const offset = circ - (score / 100) * circ;
  const ring   = $("ring-fill");
  ring.style.strokeDashoffset = offset;
  ring.style.stroke           = level.color;

  // Badge
  const badge = $("score-badge");
  badge.textContent = `${level.emoji} ${level.label}`;
  badge.className   = "score-badge " + level.key.toLowerCase();

  // Domaine
  if (meta?.pageDomain) {
    $("score-domain").textContent = meta.pageDomain;
  }
}

// ─────────────────── RENDU : RAISONS ─────────────────────────

function renderReasons(reasons) {
  const container = $("reasons-list");
  container.innerHTML = "";

  if (!reasons?.length) {
    container.innerHTML = `<p style="color:var(--text-muted);font-size:11px;">Aucun signal détecté</p>`;
    return;
  }

  reasons.forEach(r => {
    const div = document.createElement("div");
    div.className = `reason-item severity-${r.severity || "low"}`;
    div.innerHTML = `
      <span class="reason-label">${escHtml(r.label)}</span>
      <span class="reason-pts">+${r.points} pts</span>
    `;
    container.appendChild(div);
  });
}

// ─────────────────── RENDU : PANELS ──────────────────────────

function renderPixels(items) {
  const list  = $("list-pixels");
  const empty = $("empty-pixels");
  $("tab-count-pixels").textContent = items.length;
  list.innerHTML = "";

  if (!items.length) { show("empty-pixels"); return; }
  hide("empty-pixels");

  items.forEach(item => {
    const severity = item.knownTracker ? "high" :
                     item.pixel        ? "medium" : "low";
    list.appendChild(createCard({
      domain:    item.domain || "inconnu",
      url:       item.url,
      badge:     item.pixel ? "1×1 pixel" :
                 item.hidden ? "Cachée CSS" : "Suspecte",
      badgeType: severity,
      tags: [
        item.width  ? `${item.width}×${item.height}px` : null,
        item.hidden ? "display:none"                   : null,
        item.knownTracker ? "Tracker connu"            : null,
      ].filter(Boolean),
    }));
  });
}

function renderTrackers(domTrackers, netTrackers) {
  const list  = $("list-trackers");
  const empty = $("empty-trackers");
  list.innerHTML = "";

  // Fusionner DOM + réseau
  const seen    = new Set();
  const all     = [];

  (domTrackers || []).forEach(t => {
    if (!seen.has(t.domain)) { seen.add(t.domain); all.push({ ...t, source: t.source || "DOM" }); }
  });
  (netTrackers || []).forEach(domain => {
    if (!seen.has(domain)) { seen.add(domain); all.push({ domain, source: "Réseau" }); }
  });

  $("tab-count-trackers").textContent = all.length;

  if (!all.length) { show("empty-trackers"); return; }
  hide("empty-trackers");

  all.forEach(item => {
    list.appendChild(createCard({
      domain:    item.domain,
      url:       item.url || "—",
      badge:     "Tracker connu",
      badgeType: "critical",
      tags:      [item.source],
    }));
  });
}

function renderNetwork(suspiciousReqs, suspiciousUrls, thirdParty, requestCount) {
  const list  = $("list-network");
  const empty = $("empty-network");
  list.innerHTML = "";

  const all = [
    ...(suspiciousReqs || []).map(r => ({ ...r, badge: "URL suspecte", badgeType: "high" })),
    ...(suspiciousUrls || []).map(u => ({ domain: u, url: u, badge: "Réseau suspect", badgeType: "medium" })),
    ...(thirdParty     || []).map(d => ({ domain: d, url: d, badge: "Tiers",          badgeType: "low"    })),
  ];

  // Déduplique par URL
  const seen = new Set();
  const dedup = all.filter(item => {
    const key = item.url || item.domain;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });

  $("tab-count-network").textContent = dedup.length;
  const totalLabel = requestCount ? `${requestCount} req. totales` : null;

  if (!dedup.length) { show("empty-network"); return; }
  hide("empty-network");

  dedup.forEach(item => {
    list.appendChild(createCard({
      domain:    item.domain || "—",
      url:       item.url || "—",
      badge:     item.badge,
      badgeType: item.badgeType,
      tags:      [item.source, totalLabel].filter(Boolean),
    }));
  });
}

function renderFingerprint(signals) {
  const list  = $("list-fingerprint");
  const empty = $("empty-fingerprint");
  list.innerHTML = "";
  $("tab-count-fingerprint").textContent = (signals || []).length;

  if (!signals?.length) { show("empty-fingerprint"); return; }
  hide("empty-fingerprint");

  signals.forEach(sig => {
    const div = document.createElement("div");
    div.className = "item-card";
    div.innerHTML = `
      <div class="item-card-header">
        <span class="item-badge badge-critical">Fingerprint</span>
        <span class="item-domain">${escHtml(sig.label)}</span>
      </div>
      <div class="item-meta">
        <span class="item-tag">${escHtml(sig.source || "script")}</span>
        <span class="item-tag">Tracking comportemental</span>
      </div>
    `;
    list.appendChild(div);
  });
}

// ─────────────────── FACTORY : CARTE ITEM ────────────────────

function createCard({ domain, url, badge, badgeType, tags = [] }) {
  const div = document.createElement("div");
  div.className = "item-card";
  div.innerHTML = `
    <div class="item-card-header">
      <span class="item-badge badge-${badgeType}">${escHtml(badge)}</span>
      <span class="item-domain" title="${escHtml(domain)}">${escHtml(domain)}</span>
    </div>
    <div class="item-url" title="${escHtml(url)}">${escHtml(truncate(url, 52))}</div>
    ${tags.length ? `<div class="item-meta">${tags.map(t => `<span class="item-tag">${escHtml(t)}</span>`).join("")}</div>` : ""}
  `;
  return div;
}

// ─────────────────── RENDU GLOBAL ────────────────────────────

function renderReport(report) {
  const { dom, network, score: sc, meta } = report;

  renderScore(sc.score, sc.level, meta);
  renderReasons(sc.reasons);

  renderPixels([
    ...(dom?.pixelImages   || []),
    ...(dom?.hiddenIframes || []),
  ]);

  renderTrackers(dom?.knownTrackers, network?.networkTrackers);

  renderNetwork(
    dom?.suspiciousRequests,
    network?.suspiciousUrls,
    network?.thirdPartyDomains,
    network?.requestCount,
  );

  renderFingerprint(dom?.fingerprintSignals);

  // Mettre à jour le titre de la fenêtre
  document.title = `[${sc.score}/100] Pixel Tracker Detector`;
}

// ─────────────────── TABS ────────────────────────────────────

function initTabs() {
  const tabs   = document.querySelectorAll(".tab");
  const panels = document.querySelectorAll(".tab-panel");

  tabs.forEach(tab => {
    tab.addEventListener("click", () => {
      const target = tab.dataset.tab;

      tabs.forEach(t   => t.classList.remove("active"));
      panels.forEach(p => p.classList.remove("active"));

      tab.classList.add("active");
      const panel = document.getElementById(`panel-${target}`);
      if (panel) panel.classList.add("active");
    });
  });
}

// ─────────────────── MAIN ────────────────────────────────────

async function main() {
  setState("loading");

  try {
    const report    = await fetchReport();
    currentReport  = report;

    setState("main-content");
    show("main-content");
    renderReport(report);
  } catch (err) {
    setState("error");
    $("error-message").textContent = err.message || "Erreur inconnue.";
    console.error("[PixelTracker Popup]", err);
  }
}

// ── Bouton re-scan ────────────────────────────────────────────
document.getElementById("btn-scan").addEventListener("click", async () => {
  const btn  = document.getElementById("btn-scan");
  btn.classList.add("spinning");
  await main();
  btn.classList.remove("spinning");
});

// ── Helpers ───────────────────────────────────────────────────
function escHtml(str) {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function truncate(str, max) {
  if (!str) return "";
  return str.length > max ? str.slice(0, max) + "…" : str;
}

// ── Init ──────────────────────────────────────────────────────
initTabs();
main();
