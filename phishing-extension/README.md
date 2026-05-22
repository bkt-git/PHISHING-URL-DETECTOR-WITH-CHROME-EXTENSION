# 🛡️ PhishGuard Chrome Extension

Real-time phishing and scam website detection built on top of the PhishGuard Python API.

---

## 📁 File Structure

```
phishing-extension/
├── manifest.json       ← Extension config (Manifest V3)
├── background.js       ← Service worker: auto-scans every URL
├── popup.html          ← UI shown when you click the extension icon
├── popup.js            ← Popup controller
├── content.js          ← Injects warning banner on dangerous pages
└── icons/
    ├── icon16.png
    ├── icon48.png
    └── icon128.png
```

---

## ⚙️ Prerequisites

Your PhishGuard API must be running before using the extension:

```bash
# From your phishing-detector project folder:
uvicorn src.api:app --reload --port 8000
```

Train the model first if you haven't:
```bash
python src/train_model.py
```

---

## 🚀 How to Install in Chrome

1. Open Chrome and go to: `chrome://extensions/`
2. Enable **Developer Mode** (toggle in top-right corner)
3. Click **"Load unpacked"**
4. Select the `phishing-extension/` folder
5. The PhishGuard shield icon will appear in your toolbar

> Pin it for easy access: click the puzzle piece icon → pin PhishGuard

---

## 🔍 How It Works

```
Tab loads a URL
      │
      ▼
background.js (Service Worker)
  ├── Checks session cache (10-min TTL)
  ├── Calls POST http://localhost:8000/predict
  └── Gets: prediction, risk_score, risk_level, features
      │
      ├── Sets badge on icon:
      │     OK  (green)  = Legitimate / Low
      │      !  (yellow) = Medium risk
      │      !! (red)    = High risk
      │     !!! (dark)   = Critical risk
      │
      ├── Sends result to popup.js (if open)
      │
      └── For High/Critical:
            ├── Chrome notification popup
            └── content.js → Warning banner on the page
```

---

## 🎯 Features

| Feature | Description |
|---|---|
| **Auto-scan** | Every URL you visit is automatically analyzed |
| **Badge indicator** | Colour-coded risk level on extension icon |
| **Popup details** | Click icon for full feature breakdown |
| **Warning banner** | Red/yellow banner injected on dangerous pages |
| **Notifications** | Chrome notification for Critical/High risk |
| **10-min cache** | Results cached to avoid redundant API calls |
| **Rescan button** | Force re-analyze any page |

---

## 🚦 Badge Color Guide

| Badge | Meaning |
|---|---|
| `OK` 🟢 | Safe / Low risk |
| `!` 🟡 | Medium risk — proceed with caution |
| `!!` 🔴 | High risk — likely phishing |
| `!!!` 🔴 | Critical — almost certainly phishing |
| `?` ⚪ | API unreachable |

---

## ⚠️ Known Limitations

- Extension calls `localhost:8000` — the API must be running locally
- WHOIS lookups are disabled by default for speed (can enable in API call)
- Does not work on `chrome://` or `chrome-extension://` pages (by design)

---

## 🔧 Customizing the API URL

Edit the top of `background.js` and `popup.js`:
```js
const API_BASE = "http://localhost:8000";
// Change to your hosted URL, e.g.:
// const API_BASE = "https://your-api.onrender.com";
```

---

## 🚀 Deploy the API (Optional)

To use without keeping the terminal open, deploy the API to Railway or Render:

```bash
# Install Railway CLI
npm install -g @railway/cli
railway login
railway init
railway up
```

Then update `API_BASE` in the extension files to your deployed URL.
