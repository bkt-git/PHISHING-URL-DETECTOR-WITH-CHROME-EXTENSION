"""
api.py
─────────────────────────────────────────────────────────────────────────────
Production-ready FastAPI backend that loads the trained model from sister directory.
"""

import os
import pickle
import time
from pathlib import Path
from typing import Optional
import sys

import numpy as np
import uvicorn
import joblib  # Fallback mechanism for loading model binaries cleanly
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, HttpUrl, field_validator

# ─── Paths Configuration ───────────────────────────────────────────────────

BASE_DIR   = Path(__file__).resolve().parent.parent
MODELS_DIR = BASE_DIR / "models"
sys.path.insert(0, str(Path(__file__).resolve().parent))

try:
    from feature_extractor import extract_url_features, extract_whois_features
except ImportError as e:
    print(f"[CRITICAL] Failed to import feature_extractor.py: {e}")
    print(f"Current Sys Path: {sys.path}")
    raise e

# ─── Robust Model Loader ───────────────────────────────────────────────────

def _load(name):
    p = MODELS_DIR / name
    if not p.exists():
        raise FileNotFoundError(
            f"Model file '{p}' not found. Verify it is pushed to your models/ directory."
        )
    
    # Try loading with joblib first (handles scikit-learn large arrays better), fallback to pickle
    try:
        return joblib.load(p)
    except Exception:
        with open(p, "rb") as f:
            return pickle.load(f)

# Crash loudly during initialization if files are missing so Render logs can show it
try:
    MODEL         = _load("model.pkl")
    SCALER        = _load("scaler.pkl")
    FEATURE_NAMES = _load("feature_names.pkl")
    WHOIS_PRESENT = "domain_age_days" in FEATURE_NAMES
    print(f"[INFO] Model loaded successfully — {len(FEATURE_NAMES)} features, "
          f"WHOIS={'yes' if WHOIS_PRESENT else 'no'}")
except Exception as e:
    print(f"[CRITICAL] Model loading pipeline failed: {e}")
    # Force process exit so Render captures the exact stack trace
    sys.exit(1)

# ─── FastAPI app ──────────────────────────────────────────────────────────────

app = FastAPI(
    title="Phishing Detector API",
    description="ML-based phishing and scam website detection using URL + WHOIS features.",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],      
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─── Request / Response Schemas ──────────────────────────────────────────────

class PredictRequest(BaseModel):
    url: str
    use_whois: bool = False   

    @field_validator("url")
    @classmethod
    def clean_url(cls, v: str) -> str:
        v = v.strip()
        if not v.startswith(("http://", "https://")):
            v = "http://" + v
        return v


class PredictResponse(BaseModel):
    url:        str
    prediction: str          
    confidence: float        
    risk_score: float        
    risk_level: str          
    features:   dict         
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


# ─── Core Inference Engine ───────────────────────────────────────────────────

def _risk_level(score: float) -> str:
    if score < 25:   return "Low"
    if score < 50:   return "Medium"
    if score < 75:   return "High"
    return "Critical"


def _predict_one(url: str, use_whois: bool) -> PredictResponse:
    t0 = time.perf_counter()

    # Extract features
    feats = extract_url_features(url)
    if use_whois and WHOIS_PRESENT:
        feats.update(extract_whois_features(url))
    elif WHOIS_PRESENT:
        feats.setdefault("domain_age_days",   -1)
        feats.setdefault("days_until_expiry",  -1)
        feats.setdefault("whois_available",     0)

    # Align to training feature array layout
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


# ─── API Routes ──────────────────────────────────────────────────────────────

@app.get("/health")
def health():
    return {
        "status": "ok",
        "model_loaded": MODEL is not None,
        "features": len(FEATURE_NAMES) if FEATURE_NAMES else 0,
    }


@app.get("/model/info")
def model_info():
    return {
        "model_type":    type(MODEL).__name__,
        "n_features":    len(FEATURE_NAMES),
        "feature_names": FEATURE_NAMES,
        "whois_enabled": WHOIS_PRESENT,
        "n_estimators":  getattr(MODEL, "n_estimators", "N/A"),
    }


@app.post("/predict", response_model=PredictResponse)
def predict(req: PredictRequest):
    try:
        return _predict_one(req.url, req.use_whois)
    except Exception as e:
        raise HTTPException(500, f"Prediction failed: {e}")


@app.post("/predict/batch")
def predict_batch(req: BatchRequest):
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


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run("api:app", host="0.0.0.0", port=port, reload=False)