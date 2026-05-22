/**
 * content.js — PhishGuard Content Script
 * Injected into every page. Listens for a SHOW_WARNING message from the
 * background service worker and renders a dismissible warning banner at
 * the top of the page for High / Critical risk detections.
 */

(function () {
  "use strict";

  // Only inject one banner per page
  let bannerInjected = false;

  function injectBanner(result) {
    if (bannerInjected) return;
    bannerInjected = true;

    const isCritical = result.risk_level === "Critical";

    const banner = document.createElement("div");
    banner.id = "__phishguard_banner__";
    banner.style.cssText = `
      all: initial;
      position: fixed;
      top: 0; left: 0; right: 0;
      z-index: 2147483647;
      font-family: 'JetBrains Mono', 'Courier New', monospace;
      font-size: 13px;
      display: flex;
      align-items: center;
      gap: 12px;
      padding: 10px 16px;
      background: ${isCritical ? "#1a0008" : "#1a0d00"};
      border-bottom: 2px solid ${isCritical ? "#ff3c5c" : "#ffb830"};
      color: ${isCritical ? "#ff7090" : "#ffcc70"};
      box-shadow: 0 4px 24px rgba(0,0,0,.6);
      animation: __pg_slide 0.3s ease-out;
    `;

    const style = document.createElement("style");
    style.textContent = `
      @keyframes __pg_slide {
        from { transform: translateY(-100%); }
        to   { transform: translateY(0); }
      }
    `;
    document.head?.appendChild(style);

    const icon  = isCritical ? "🚨" : "⚠️";
    const label = isCritical ? "CRITICAL PHISHING RISK" : "HIGH PHISHING RISK";

    banner.innerHTML = `
      <span style="font-size:18px;flex-shrink:0;">${icon}</span>
      <div style="flex:1;min-width:0;">
        <strong style="color:${isCritical ? "#ff3c5c" : "#ffb830"};letter-spacing:.5px;">
          PhishGuard: ${label}
        </strong>
        <span style="color:#888;margin-left:8px;">
          ${result.risk_score}% phishing probability detected on this page.
        </span>
      </div>
      <a href="${result.url}" target="_blank"
         style="color:#888;text-decoration:none;font-size:11px;flex-shrink:0;">
        More info
      </a>
      <button id="__pg_dismiss__"
        style="all:unset;cursor:pointer;color:#666;font-size:18px;
               line-height:1;padding:0 4px;flex-shrink:0;">
        ×
      </button>
    `;

    document.documentElement.prepend(banner);

    document.getElementById("__pg_dismiss__")?.addEventListener("click", () => {
      banner.style.transition = "opacity .2s";
      banner.style.opacity = "0";
      setTimeout(() => banner.remove(), 200);
    });

    // push page content down so banner doesn't overlap
    document.body && (document.body.style.marginTop =
      Math.max(parseInt(document.body.style.marginTop) || 0, 44) + "px");
  }

  // Listen for warning message from background
  chrome.runtime.onMessage.addListener((msg) => {
    if (msg.type === "SHOW_WARNING" && msg.result) {
      injectBanner(msg.result);
    }
  });
})();
