"""
api.py
─────────────────────────────────────────────────────────────────────────────
FastAPI backend that loads the trained model and exposes:

  POST /predict          — predict a single URL
  POST /predict/batch    — predict up to 50 URLs at once
  GET  /health           — liveness check
  GET  /model/info       — feature list + model metadata

Run with:
    uvicorn api:app --reload --port 8000
"""

import pickle
import time
from pathlib import Path
from typing import Optional
import sys

import numpy as np
import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, HttpUrl, field_validator

# ─── paths ───────────────────────────────────────────────────────────────────

BASE_DIR   = Path(__file__).resolve().parent.parent
MODELS_DIR = BASE_DIR / "models"
sys.path.insert(0, str(Path(__file__).resolve().parent))

from feature_extractor import extract_url_features, extract_whois_features

# ─── load model artefacts ────────────────────────────────────────────────────

def _load(name):
    p = MODELS_DIR / name
    if not p.exists():
        raise FileNotFoundError(
            f"Model file '{p}' not found. "
            "Run `python src/train_model.py` first."
        )
    with open(p, "rb") as f:
        return pickle.load(f)

try:
    MODEL         = _load("model.pkl")
    SCALER        = _load("scaler.pkl")
    FEATURE_NAMES = _load("feature_names.pkl")
    WHOIS_PRESENT = "domain_age_days" in FEATURE_NAMES
    print(f"[INFO] Model loaded — {len(FEATURE_NAMES)} features, "
          f"WHOIS={'yes' if WHOIS_PRESENT else 'no'}")
except FileNotFoundError as e:
    print(f"[WARN] {e}")
    MODEL = SCALER = FEATURE_NAMES = None
    WHOIS_PRESENT = False

# ─── FastAPI app ──────────────────────────────────────────────────────────────

app = FastAPI(
    title="Phishing Detector API",
    description="ML-based phishing and scam website detection using URL + WHOIS features.",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],      # tighten for production
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─── request / response schemas ──────────────────────────────────────────────

class PredictRequest(BaseModel):
    url: str
    use_whois: bool = False   # set True for better accuracy, slower response

    @field_validator("url")
    @classmethod
    def clean_url(cls, v: str) -> str:
        v = v.strip()
        if not v.startswith(("http://", "https://")):
            v = "http://" + v
        return v


class PredictResponse(BaseModel):
    url:        str
    prediction: str          # "phishing" | "legitimate"
    confidence: float        # 0.0 – 1.0
    risk_score: float        # 0–100 (easier to display)
    risk_level: str          # "Low" | "Medium" | "High" | "Critical"
    features:   dict         # raw feature values (for explainability)
    latency_ms: float


class BatchRequest(BaseModel):
    urls:      list[str]
    use_whois: bool = False

    @field_validator("urls")
    @classmethod
    def limit_size(cls, v):
        if len(v) > 50:
            raise ValueError("Batch size cannot exceed 50 URLs.")
        return v


# ─── helpers ─────────────────────────────────────────────────────────────────

def _risk_level(score: float) -> str:
    if score < 25:   return "Low"
    if score < 50:   return "Medium"
    if score < 75:   return "High"
    return "Critical"


def _predict_one(url: str, use_whois: bool) -> PredictResponse:
    t0 = time.perf_counter()

    # extract features
    feats = extract_url_features(url)
    if use_whois and WHOIS_PRESENT:
        feats.update(extract_whois_features(url))
    elif WHOIS_PRESENT:
        # model was trained with WHOIS features — supply -1 sentinels
        feats.setdefault("domain_age_days",   -1)
        feats.setdefault("days_until_expiry",  -1)
        feats.setdefault("whois_available",     0)

    # align to training feature order
    row = np.array([feats.get(f, 0) for f in FEATURE_NAMES], dtype=float).reshape(1, -1)
    row_scaled = SCALER.transform(row)

    proba      = MODEL.predict_proba(row_scaled)[0]
    phish_prob = float(proba[1])
    prediction = "phishing" if phish_prob >= 0.5 else "legitimate"
    risk_score = round(phish_prob * 100, 1)

    latency_ms = round((time.perf_counter() - t0) * 1000, 2)

    return PredictResponse(
        url=url,
        prediction=prediction,
        confidence=round(phish_prob if prediction == "phishing" else 1 - phish_prob, 4),
        risk_score=risk_score,
        risk_level=_risk_level(risk_score),
        features=feats,
        latency_ms=latency_ms,
    )


# ─── routes ──────────────────────────────────────────────────────────────────

@app.get("/health")
def health():
    return {
        "status": "ok",
        "model_loaded": MODEL is not None,
        "features": len(FEATURE_NAMES) if FEATURE_NAMES else 0,
    }


@app.get("/model/info")
def model_info():
    if not MODEL:
        raise HTTPException(503, "Model not loaded. Run train_model.py first.")
    return {
        "model_type":    type(MODEL).__name__,
        "n_features":    len(FEATURE_NAMES),
        "feature_names": FEATURE_NAMES,
        "whois_enabled": WHOIS_PRESENT,
        "n_estimators":  getattr(MODEL, "n_estimators", "N/A"),
    }


@app.post("/predict", response_model=PredictResponse)
def predict(req: PredictRequest):
    if not MODEL:
        raise HTTPException(503, "Model not loaded. Run train_model.py first.")
    try:
        return _predict_one(req.url, req.use_whois)
    except Exception as e:
        raise HTTPException(500, f"Prediction failed: {e}")


@app.post("/predict/batch")
def predict_batch(req: BatchRequest):
    if not MODEL:
        raise HTTPException(503, "Model not loaded. Run train_model.py first.")
    results = []
    for url in req.urls:
        try:
            url_clean = url.strip()
            if not url_clean.startswith(("http://", "https://")):
                url_clean = "http://" + url_clean
            result = _predict_one(url_clean, req.use_whois)
            results.append(result.model_dump())
        except Exception as e:
            results.append({"url": url, "error": str(e)})
    return {"results": results, "count": len(results)}


# ─── main ────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    uvicorn.run("api:app", host="0.0.0.0", port=8000, reload=True)
