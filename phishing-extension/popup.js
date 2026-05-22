/**
 * popup.js — PhishGuard Popup Controller
 * Retrieves the latest scan result from the background service worker
 * and renders it into the popup UI.
 */

const API_BASE = "http://localhost:8000";

// ── DOM refs ──────────────────────────────────────────────────────────────────
const $ = id => document.getElementById(id);

// ── state helpers ─────────────────────────────────────────────────────────────
function showState(name) {
  ["scanning", "error", "result"].forEach(s => {
    $(`state-${s}`).style.display = s === name ? "block" : "none";
  });
}

// ── colour maps ───────────────────────────────────────────────────────────────
const GAUGE_COLORS = {
  Low:      "var(--safe)",
  Medium:   "var(--warn)",
  High:     "var(--danger)",
  Critical: "#cc0033",
};

// ── render functions ──────────────────────────────────────────────────────────

function renderResult(data) {
  showState("result");
  const { result, cached } = data;
  const isPhish = result.prediction === "phishing";
  const level   = result.risk_level;
  const score   = result.risk_score;

  // verdict strip
  const strip = $("verdict-strip");
  strip.className = `verdict-strip ${isPhish ? "phishing" : "legitimate"}`;
  $("verdict-emoji").textContent  = isPhish ? "🚨" : "✅";
  $("verdict-title").textContent  = isPhish ? `PHISHING` : "Legitimate";
  $("verdict-title").style.color  = isPhish ? "var(--danger)" : "var(--safe)";
  $("verdict-sub").textContent    = `${level} Risk · ${(result.confidence * 100).toFixed(1)}% confidence`;
  $("score-num").textContent      = `${score}%`;
  $("score-num").style.color      = isPhish ? "var(--danger)" : "var(--safe)";

  // gauge
  $("gauge-fill").style.width      = `${score}%`;
  $("gauge-fill").style.background = GAUGE_COLORS[level] || "var(--accent)";
  $("gauge-label").textContent     = level;

  // features
  const feats = result.features || {};
  const SHOW = [
    { key: "is_https",          label: "HTTPS",           fmt: v => v ? ["Yes", "ok"] : ["No", "bad"] },
    { key: "has_ip",            label: "IP as Host",      fmt: v => v ? ["Yes ⚠", "bad"] : ["No", "ok"] },
    { key: "suspicious_tld",    label: "Suspicious TLD",  fmt: v => v ? ["Yes ⚠", "bad"] : ["No", "ok"] },
    { key: "suspicious_keywords",label:"Phish Keywords",  fmt: v => [v, v > 0 ? "warn" : "ok"] },
    { key: "num_subdomains",    label: "Subdomains",      fmt: v => [v, v >= 3 ? "warn" : "ok"] },
    { key: "url_length",        label: "URL Length",      fmt: v => [v, v > 75 ? "warn" : "ok"] },
    { key: "domain_entropy",    label: "Domain Entropy",  fmt: v => [v.toFixed(2), v > 3.5 ? "warn" : "ok"] },
    { key: "domain_age_days",   label: "Domain Age",
      fmt: v => v === -1 ? ["N/A", ""] : [v + " days", v < 30 ? "bad" : "ok"] },
  ];

  const list = $("feat-list");
  list.innerHTML = "";
  for (const { key, label, fmt } of SHOW) {
    if (!(key in feats)) continue;
    const [display, cls] = fmt(feats[key]);
    const isFlagged = cls === "bad" || cls === "warn";
    const row = document.createElement("div");
    row.className = `feat-row${isFlagged ? " flagged" : ""}`;
    row.innerHTML = `
      <span class="feat-name">${label}</span>
      <span class="feat-val ${cls}">${display}</span>`;
    list.appendChild(row);
  }

  // footer meta
  $("latency-note").textContent =
    `⚡ ${result.latency_ms}ms · PhishGuard ML`;
  if (cached) $("cached-badge").style.display = "inline";
}

function renderError(msg, cmd) {
  showState("error");
  $("err-msg").textContent = msg;
  $("err-cmd").textContent = cmd || "";
}

function renderScanning() {
  showState("scanning");
}

// ── API health check ──────────────────────────────────────────────────────────

async function checkAPI() {
  try {
    const r = await fetch(`${API_BASE}/health`, { signal: AbortSignal.timeout(3000) });
    const d = await r.json();
    $("api-dot").className = "api-dot online";
    $("api-status").textContent = "API online";
    $("model-info").textContent = d.model_loaded
      ? `${d.features} features`
      : "model not loaded";
  } catch {
    $("api-dot").className = "api-dot offline";
    $("api-status").textContent = "API offline";
  }
}

// ── main ──────────────────────────────────────────────────────────────────────

async function init() {
  checkAPI();

  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab) return;

  // display current URL
  const url = tab.url || "";
  $("url-bar").textContent = url.length > 55 ? url.slice(0, 55) + "…" : url;
  $("url-bar").title = url;

  // ask background for cached result
  chrome.runtime.sendMessage(
    { type: "GET_TAB_RESULT", tabId: tab.id },
    (data) => {
      if (!data) {
        renderScanning();
        return;
      }
      if (data.status === "scanning") { renderScanning(); return; }
      if (data.status === "error") {
        renderError(
          data.error,
          data.error.includes("offline")
            ? "uvicorn src.api:app --port 8000"
            : ""
        );
        return;
      }
      if (data.status === "done") { renderResult(data); return; }
    }
  );

  // re-scan button
  $("rescan-btn").addEventListener("click", () => {
    renderScanning();
    chrome.runtime.sendMessage({ type: "RESCAN", tabId: tab.id });
  });

  // live updates pushed from background
  chrome.runtime.onMessage.addListener((msg) => {
    if (msg.tabId !== tab.id) return;
    if (msg.type === "SCAN_START")  renderScanning();
    if (msg.type === "SCAN_DONE")   renderResult({ result: msg.result, cached: false });
    if (msg.type === "SCAN_ERROR")  renderError(msg.error);
  });
}

document.addEventListener("DOMContentLoaded", init);
