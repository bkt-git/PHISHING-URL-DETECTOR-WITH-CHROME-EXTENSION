/**
 * background.js — PhishGuard Service Worker
 * ─────────────────────────────────────────────────────────────────────────────
 * Runs in the background at all times.
 * - Intercepts every tab navigation
 * - Calls the PhishGuard API to classify the URL
 * - Caches results in chrome.storage.session (cleared on browser restart)
 * - Sets badge colour: 🔴 phishing / 🟢 safe / ⏳ scanning / ⚪ idle
 * - Sends a Chrome notification for Critical/High risk pages
 * - Relays results to the popup and content script via messaging
 */

const API_BASE   = "http://localhost:8000";
const CACHE_TTL  = 10 * 60 * 1000;   // 10 minutes in ms

// ── badge helpers ─────────────────────────────────────────────────────────────

function setBadge(tabId, { text, color }) {
  chrome.action.setBadgeText({ tabId, text });
  chrome.action.setBadgeBackgroundColor({ tabId, color });
}

const BADGES = {
  scanning:   { text: "…",  color: "#5a6a88" },
  safe:       { text: "OK", color: "#00c87a" },
  low:        { text: "OK", color: "#00c87a" },
  medium:     { text: "!",  color: "#e6a817" },
  high:       { text: "!!",  color: "#ff3c5c" },
  critical:   { text: "!!!",color: "#cc0033" },
  error:      { text: "?",  color: "#5a6a88" },
  idle:       { text: "",   color: "#5a6a88" },
};

// ── cache helpers ─────────────────────────────────────────────────────────────

async function getCached(url) {
  const key  = "cache_" + btoa(url).slice(0, 80);
  const data = await chrome.storage.session.get(key);
  const entry = data[key];
  if (!entry) return null;
  if (Date.now() - entry.timestamp > CACHE_TTL) return null;
  return entry.result;
}

async function setCache(url, result) {
  const key = "cache_" + btoa(url).slice(0, 80);
  await chrome.storage.session.set({ [key]: { result, timestamp: Date.now() } });
}

// ── URL filter — skip internal / extension / browser pages ───────────────────

function shouldScan(url) {
  if (!url) return false;
  try {
    const u = new URL(url);
    const skip = ["chrome:", "chrome-extension:", "about:", "edge:", "moz-extension:", "data:", "file:"];
    return !skip.includes(u.protocol);
  } catch { return false; }
}

// ── API call ──────────────────────────────────────────────────────────────────

async function analyzeURL(url) {
  const cached = await getCached(url);
  if (cached) return { ...cached, cached: true };

  const res = await fetch(`${API_BASE}/predict`, {
    method:  "POST",
    headers: { "Content-Type": "application/json" },
    body:    JSON.stringify({ url, use_whois: false }),
    signal:  AbortSignal.timeout(8000),
  });

  if (!res.ok) throw new Error(`API error ${res.status}`);
  const result = await res.json();
  await setCache(url, result);
  return result;
}

// ── notification ──────────────────────────────────────────────────────────────

function maybeNotify(result, tabId) {
  if (!["High", "Critical"].includes(result.risk_level)) return;
  chrome.notifications.create(`phish-${tabId}-${Date.now()}`, {
    type:     "basic",
    iconUrl:  "icons/icon128.png",
    title:    `⚠️ PhishGuard — ${result.risk_level} Risk Detected`,
    message:  `${result.risk_score}% phishing probability on this page. Be careful!`,
    priority: 2,
  });
}

// ── core scan function ────────────────────────────────────────────────────────

async function scanTab(tabId, url) {
  if (!shouldScan(url)) {
    setBadge(tabId, BADGES.idle);
    return;
  }

  // store "scanning" state
  await chrome.storage.session.set({ [`tab_${tabId}`]: { status: "scanning", url } });
  setBadge(tabId, BADGES.scanning);

  // notify popup that scan started
  chrome.runtime.sendMessage({ type: "SCAN_START", tabId, url }).catch(() => {});

  try {
    const result = await analyzeURL(url);

    // store result keyed by tabId for popup to read
    await chrome.storage.session.set({
      [`tab_${tabId}`]: { status: "done", url, result, ts: Date.now() }
    });

    const level = result.risk_level.toLowerCase();
    setBadge(tabId, BADGES[level] || BADGES.safe);
    maybeNotify(result, tabId);

    // relay to popup
    chrome.runtime.sendMessage({ type: "SCAN_DONE", tabId, result }).catch(() => {});

    // relay to content script for warning banner
    if (["High", "Critical"].includes(result.risk_level)) {
      chrome.tabs.sendMessage(tabId, { type: "SHOW_WARNING", result }).catch(() => {});
    }

  } catch (err) {
    const isOffline = err.message.includes("Failed to fetch") ||
                      err.message.includes("timeout");
    await chrome.storage.session.set({
      [`tab_${tabId}`]: {
        status: "error",
        url,
        error: isOffline ? "API offline — start api.py" : err.message
      }
    });
    setBadge(tabId, BADGES.error);
    chrome.runtime.sendMessage({
      type: "SCAN_ERROR", tabId,
      error: isOffline ? "API offline — run: uvicorn src.api:app --port 8000" : err.message
    }).catch(() => {});
  }
}

// ── listeners ─────────────────────────────────────────────────────────────────

// Fires when a tab completes loading a new URL
chrome.webNavigation.onCompleted.addListener(({ tabId, url, frameId }) => {
  if (frameId !== 0) return;   // only main frame
  scanTab(tabId, url);
});

// Fires when tab URL changes (SPA navigation, redirects)
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === "complete" && tab.url) {
    scanTab(tabId, tab.url);
  }
});

// Clean up session data when a tab closes
chrome.tabs.onRemoved.addListener((tabId) => {
  chrome.storage.session.remove([`tab_${tabId}`]);
});

// Popup / content script asks for latest result for a given tab
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === "GET_TAB_RESULT") {
    chrome.storage.session.get(`tab_${msg.tabId}`).then(data => {
      sendResponse(data[`tab_${msg.tabId}`] || null);
    });
    return true;   // keep channel open for async response
  }

  if (msg.type === "RESCAN") {
    // popup requested a fresh scan (bypass cache)
    chrome.tabs.get(msg.tabId).then(tab => {
      scanTab(tab.id, tab.url);
      sendResponse({ ok: true });
    });
    return true;
  }
});
