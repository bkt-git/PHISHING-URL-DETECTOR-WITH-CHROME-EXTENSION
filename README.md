# 🛡️ PhishGuard — ML Phishing & Scam Website Detector

A machine-learning system that classifies URLs as **phishing** or **legitimate**
using URL lexical features and WHOIS/domain-age signals — no browser required.

---

## 📁 Project Structure

```
phishing-detector/
├── src/
│   ├── feature_extractor.py   ← URL + WHOIS feature engineering
│   ├── train_model.py         ← Dataset loading, training, evaluation
│   └── api.py                 ← FastAPI inference server
├── frontend/
│   └── index.html             ← Web dashboard (open in browser)
├── data/                      ← Put your datasets here
│   └── README_datasets.md
├── models/                    ← Auto-created when training runs
│   ├── model.pkl
│   ├── scaler.pkl
│   └── feature_names.pkl
└── requirements.txt
```

---
## https://phishing-detector-api-84il.onrender.com
## ⚡ Quick Start

### 1. Install dependencies
```bash
pip install -r requirements.txt
```

### 2. Train the model

**Demo mode** (no datasets needed — runs immediately):
```bash
python src/train_model.py
```

**With real datasets** (recommended for workshop):
```bash
# Download PhishTank CSV from https://phishtank.org/developer_info.php
# Download Tranco list from https://tranco-list.eu/
python src/train_model.py \
  --phishtank data/verified_online.csv \
  --tranco    data/tranco_1M.csv \
  --max-rows  10000
```

Add `--whois` to enable WHOIS lookups during training (slow but more accurate):
```bash
python src/train_model.py --phishtank ... --tranco ... --whois
```

### 3. Start the API
```bash
uvicorn src.api:app --reload --port 8000
```
API docs auto-generated at: `http://localhost:8000/docs`

### 4. Open the dashboard
Open `frontend/index.html` in your browser — no server needed for the frontend.

---

## 📊 Features Extracted

### URL Lexical (instant, no network)
| Feature | Why it matters |
|---|---|
| `url_length` | Phishing URLs are often very long |
| `num_dots` | Extra subdomains = suspicious |
| `has_ip` | IP as hostname instead of domain name |
| `is_https` | Many phishing sites skip HTTPS |
| `suspicious_tld` | `.tk`, `.ml`, `.ga`, `.xyz` etc. are abused |
| `suspicious_keywords` | "login", "verify", "paypal" in URL |
| `domain_entropy` | High entropy → randomly generated domain |
| `digit_ratio_domain` | Lots of numbers in domain = suspicious |
| `num_hyphens` | `paypal-secure-login.com` pattern |
| `hex_encoding` | `%XX` obfuscation attempts |

### WHOIS / Domain (requires network)
| Feature | Why it matters |
|---|---|
| `domain_age_days` | New domains (<30 days) are high risk |
| `days_until_expiry` | Short expiry = throwaway domain |
| `whois_available` | No WHOIS data = suspicious |

---

## 🔌 API Endpoints

### `POST /predict`
```json
// Request
{ "url": "http://paypal-login.tk/verify?token=abc", "use_whois": false }

// Response
{
  "url": "http://paypal-login.tk/verify?token=abc",
  "prediction": "phishing",
  "confidence": 0.94,
  "risk_score": 94.0,
  "risk_level": "Critical",
  "features": { "url_length": 43, "suspicious_tld": 1, ... },
  "latency_ms": 12.5
}
```

### `POST /predict/batch`
```json
{ "urls": ["https://google.com", "http://phish.tk/login"], "use_whois": false }
```

### `GET /health`
```json
{ "status": "ok", "model_loaded": true, "features": 24 }
```

### `GET /model/info`
Returns feature list, model type, number of estimators.

---

## 📈 Expected Accuracy

With real PhishTank + Tranco data (10K each):

| Metric | Expected |
|---|---|
| Accuracy | 95–97% |
| Precision | 94–96% |
| Recall | 95–97% |
| ROC-AUC | 0.97–0.99 |

With demo data (50 URLs each side), accuracy will be lower but the full
pipeline works end-to-end.

---

## 🗂️ Dataset Download Instructions

### PhishTank
1. Go to https://phishtank.org/developer_info.php
2. Register a free account
3. Download `verified_online.csv`
4. Place in `data/` folder

### Tranco
1. Go to https://tranco-list.eu/
2. Download latest list → CSV format
3. Place as `data/tranco_1M.csv`

---

## 🏗️ Architecture

```
                     ┌─────────────────────────────────┐
                     │         FastAPI Backend          │
 User enters URL ──► │  feature_extractor.py            │
                     │    ├── URL lexical features      │
                     │    └── WHOIS / domain age        │
                     │  RandomForestClassifier.predict() │
                     │  → Phishing | Legitimate + score │
                     └─────────────────┬───────────────┘
                                       │ JSON
                     ┌─────────────────▼───────────────┐
                     │     HTML Dashboard (frontend)    │
                     │  Risk gauge, feature cards,      │
                     │  scan history, confidence badge  │
                     └─────────────────────────────────┘
```

---

## 🔬 Workshop Demo Script

1. **Show the dashboard** — explain the 3-layer architecture
2. **Scan a safe site**: `https://www.google.com` → Green, Low Risk
3. **Scan a phishing-style URL**: `http://paypal-secure-verify.tk/login?token=abc`
   → Red, Critical Risk
4. **Point to the feature cards**: explain *why* the model flagged it
   (suspicious TLD, keyword "paypal", no HTTPS, high entropy)
5. **Show `/docs`** (FastAPI Swagger UI) — explain REST API design
6. **Show `feature_importance.png`** — explain which features the model relied on most

---

## 🚀 Extensions (post-workshop ideas)
- Add a **browser extension** that calls the API on every page load
- Add **VirusTotal API** integration as a third signal source
- Train with **content-based features** (HTML parsing with BeautifulSoup)
- Deploy the API to **Railway / Render** and the frontend to **GitHub Pages**
- Add **LIME / SHAP** for per-prediction explainability

---

*Built with Python · scikit-learn · FastAPI · Tailwind-inspired CSS*
