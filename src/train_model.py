"""
train_model.py
─────────────────────────────────────────────────────────────────────────────
Loads PhishTank + Tranco datasets, extracts features, trains a Random Forest
classifier, evaluates it, saves the model + feature list.

Usage:
    python train_model.py

Outputs (saved to ../models/):
    model.pkl          — trained RandomForestClassifier
    feature_names.pkl  — list of feature column names (must match at inference)
    scaler.pkl         — StandardScaler fitted on training data
    label_encoder.pkl  — LabelEncoder (0=legit, 1=phishing)
"""

import os
import sys
import pickle
import warnings
import argparse
import pandas as pd
import numpy as np
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    classification_report, confusion_matrix,
    roc_auc_score, RocCurveDisplay
)
import matplotlib
matplotlib.use("Agg")   # non-interactive backend (saves to file)
import matplotlib.pyplot as plt

warnings.filterwarnings("ignore")

# ─────────────────────────── paths ────────────────────────────────────────────

BASE_DIR   = Path(__file__).resolve().parent.parent
DATA_DIR   = BASE_DIR / "data"
MODELS_DIR = BASE_DIR / "models"
MODELS_DIR.mkdir(exist_ok=True)

sys.path.insert(0, str(Path(__file__).resolve().parent))
from feature_extractor import extract_url_features, extract_whois_features

# ──────────────────────────── data loading ────────────────────────────────────

def load_phishtank(path: Path, max_rows: int = 10_000) -> pd.DataFrame:
    """
    PhishTank CSV columns: phish_id, url, phish_detail_url, submission_time,
    verified, verification_time, online, target
    Download: https://phishtank.org/developer_info.php  (verified_online.csv)
    """
    df = pd.read_csv(path, usecols=["url"], nrows=max_rows)
    df = df.dropna(subset=["url"])
    df["label"] = 1   # 1 = phishing
    return df[["url", "label"]]


def load_tranco(path: Path, max_rows: int = 10_000) -> pd.DataFrame:
    """
    Tranco list format: rank,domain  (no header)
    Download: https://tranco-list.eu/
    We prepend https:// to make them proper URLs.
    """
    df = pd.read_csv(path, header=None, names=["rank", "domain"], nrows=max_rows)
    df = df.dropna(subset=["domain"])
    df["url"] = "https://" + df["domain"]
    df["label"] = 0   # 0 = legitimate
    return df[["url", "label"]]


def load_demo_data() -> pd.DataFrame:
    """
    Fallback: built-in mini dataset so you can run train_model.py right away
    without downloading anything.  Results won't be production-grade, but
    the full pipeline will run and the model will be saved.
    """
    print("[INFO] Using built-in demo dataset (100 URLs). "
          "Download real datasets for production-quality accuracy.")

    phishing = [
        "http://paypal-login.secure-verify.tk/account/confirm?token=abc123",
        "http://192.168.1.1/admin/login.php",
        "http://amazon-account-update.xyz/secure/verify?user=bhavya",
        "http://apple-id-locked.ml/recovery/login",
        "http://login.microsoftonline-secure.tk/auth",
        "http://ebay.payment-required.ga/item/confirm",
        "http://bankofamerica-secure.cf/signin/verify",
        "http://netflix-billing-update.gq/account/payment",
        "http://instagram-verify-account.xyz/login?next=/",
        "http://dhl-shipment-track.online/parcel/ABC1234",
        "http://216.58.220.110/phish",
        "http://faceb00k-login.tk/",
        "http://secure-payp4l.com/us/signin/",
        "http://update-account.amazon-aws.pw/login",
        "http://wellsfargo-secure.work/signin.html",
        "http://dropbox-share.click/d/1234567890abcdef",
        "http://verify-support.apple.com.apple-id-locked.xyz/",
        "http://go0gle-security.top/verify-account",
        "http://steamcommunity-trade.link/tradeoffer/new/",
        "http://bitcoin-wallet-secure.site/claim",
        "http://irs-tax-refund.online/claim-refund?id=9999",
        "http://covid-relief-fund.xyz/apply?ssn=required",
        "http://fedex-delivery-update.club/track-package",
        "http://support-helpdesk-microsoft.biz/tech-support",
        "http://login-chase-bank-secure.pw/online",
        "http://free-iphone14-giveaway.tk/claim",
        "http://zelle-payment-pending.ml/verify",
        "http://citibank-alert-security.ga/update",
        "http://usps-package-delivery.cf/notify",
        "http://whatsapp-verify-number.gq/code",
        "http://googledocs-shared-doc.site/view?id=xyz",
        "http://office365-login-secure.online/auth",
        "http://crypto-wallet-metamask.xyz/connect",
        "http://nft-airdrop-claim.top/mint-free",
        "http://discord-nitro-free.click/claim",
        "http://steam-gift-card.link/redeem?code=abc",
        "http://binance-kyc-verify.work/submit",
        "http://coinbase-wallet-secure.club/login",
        "http://robinhood-support-verify.pw/account",
        "http://venmo-money-request.site/pay?req=xyz",
        "http://phishing-test.ml/login?redirect=bank",
        "http://fake-antivirus-alert.xyz/download-now",
        "http://lottery-winner-notification.top/claim",
        "http://cra-canada-tax-refund.online/apply",
        "http://hmrc-tax-rebate.click/claim?ref=123",
        "http://ato-gov-refund.link/tax-return",
        "http://sbi-net-banking-secure.tk/login",
        "http://hdfc-bank-alert.ml/update-kyc",
        "http://icici-secure-login.ga/netbanking",
        "http://paytm-kyc-update.cf/verify-account",
    ]

    legitimate = [
        "https://www.google.com",
        "https://www.github.com",
        "https://www.microsoft.com",
        "https://www.apple.com",
        "https://www.amazon.com",
        "https://www.wikipedia.org",
        "https://www.stackoverflow.com",
        "https://www.reddit.com",
        "https://www.linkedin.com",
        "https://www.twitter.com",
        "https://www.facebook.com",
        "https://www.instagram.com",
        "https://www.youtube.com",
        "https://www.netflix.com",
        "https://www.spotify.com",
        "https://www.dropbox.com",
        "https://www.salesforce.com",
        "https://www.adobe.com",
        "https://www.cloudflare.com",
        "https://www.stripe.com",
        "https://www.paypal.com",
        "https://www.ebay.com",
        "https://www.walmart.com",
        "https://www.bestbuy.com",
        "https://www.cnn.com",
        "https://www.bbc.com",
        "https://www.nytimes.com",
        "https://www.reuters.com",
        "https://www.medium.com",
        "https://www.notion.so",
        "https://www.slack.com",
        "https://www.zoom.us",
        "https://www.atlassian.com",
        "https://www.shopify.com",
        "https://www.hubspot.com",
        "https://www.twilio.com",
        "https://www.heroku.com",
        "https://www.mongodb.com",
        "https://www.postgresql.org",
        "https://www.docker.com",
        "https://www.kubernetes.io",
        "https://www.tensorflow.org",
        "https://www.pytorch.org",
        "https://www.anaconda.com",
        "https://www.kaggle.com",
        "https://www.coursera.org",
        "https://www.udemy.com",
        "https://www.edx.org",
        "https://www.mit.edu",
        "https://www.stanford.edu",
    ]

    df_phish = pd.DataFrame({"url": phishing, "label": 1})
    df_legit  = pd.DataFrame({"url": legitimate,  "label": 0})
    return pd.concat([df_phish, df_legit], ignore_index=True)


# ────────────────────────── feature extraction ────────────────────────────────

def extract_features_parallel(urls: list[str], use_whois: bool = False,
                               max_workers: int = 20) -> pd.DataFrame:
    """Extract features for a list of URLs with a thread pool."""
    results = []

    def _extract(url):
        try:
            feats = extract_url_features(url)
            if use_whois:
                feats.update(extract_whois_features(url))
            feats["url"] = url
            return feats
        except Exception as e:
            print(f"[WARN] Feature extraction failed for {url}: {e}")
            return None

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(_extract, u): u for u in urls}
        for i, future in enumerate(as_completed(futures), 1):
            result = future.result()
            if result:
                results.append(result)
            if i % 500 == 0:
                print(f"  [{i}/{len(urls)}] extracted …")

    return pd.DataFrame(results)


# ──────────────────────────── training ────────────────────────────────────────

def train(args):
    # 1. Load data ─────────────────────────────────────────────────────────────
    use_demo = False
    if args.phishtank and args.tranco:
        phish_path  = Path(args.phishtank)
        tranco_path = Path(args.tranco)
        if not phish_path.exists() or not tranco_path.exists():
            print("[WARN] One or both dataset files not found. Falling back to demo data.")
            use_demo = True
        else:
            df_phish = load_phishtank(phish_path, args.max_rows)
            df_legit  = load_tranco(tranco_path, args.max_rows)
            df        = pd.concat([df_phish, df_legit], ignore_index=True)
    else:
        use_demo = True

    if use_demo:
        df = load_demo_data()

    df = df.sample(frac=1, random_state=42).reset_index(drop=True)
    print(f"[INFO] Dataset: {len(df)} URLs  "
          f"({df['label'].sum()} phishing, {(df['label']==0).sum()} legitimate)")

    # 2. Feature extraction ────────────────────────────────────────────────────
    print("[INFO] Extracting features …")
    feat_df = extract_features_parallel(df["url"].tolist(),
                                        use_whois=args.whois,
                                        max_workers=args.workers)
    feat_df = feat_df.merge(df[["url", "label"]], on="url", how="left")
    feat_df = feat_df.drop(columns=["url"])
    feat_df = feat_df.dropna()

    X = feat_df.drop(columns=["label"])
    y = feat_df["label"]

    feature_names = X.columns.tolist()
    print(f"[INFO] Feature count: {len(feature_names)}")

    # 3. Train/test split ──────────────────────────────────────────────────────
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y)

    # 4. Scale ─────────────────────────────────────────────────────────────────
    scaler  = StandardScaler()
    X_train_s = scaler.fit_transform(X_train)
    X_test_s  = scaler.transform(X_test)

    # 5. Train model ───────────────────────────────────────────────────────────
    print("[INFO] Training Random Forest …")
    clf = RandomForestClassifier(
        n_estimators=200,
        max_depth=None,
        min_samples_split=4,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1,
    )
    clf.fit(X_train_s, y_train)

    # 6. Evaluate ──────────────────────────────────────────────────────────────
    y_pred   = clf.predict(X_test_s)
    y_proba  = clf.predict_proba(X_test_s)[:, 1]

    print("\n" + "═" * 55)
    print("CLASSIFICATION REPORT")
    print("═" * 55)
    print(classification_report(y_test, y_pred,
          target_names=["Legitimate", "Phishing"]))

    cm  = confusion_matrix(y_test, y_pred)
    auc = roc_auc_score(y_test, y_proba)
    print(f"Confusion Matrix:\n{cm}")
    print(f"ROC-AUC Score   : {auc:.4f}")

    cv_scores = cross_val_score(clf, scaler.transform(X), y, cv=5, scoring="f1")
    print(f"5-Fold CV F1    : {cv_scores.mean():.4f} ± {cv_scores.std():.4f}")
    print("═" * 55 + "\n")

    # 7. Feature importance plot ───────────────────────────────────────────────
    importances = pd.Series(clf.feature_importances_, index=feature_names)
    top20 = importances.nlargest(20)

    fig, ax = plt.subplots(figsize=(10, 6))
    top20.sort_values().plot(kind="barh", ax=ax, color="#e74c3c")
    ax.set_title("Top 20 Feature Importances — Phishing Detector", fontsize=14)
    ax.set_xlabel("Importance")
    plt.tight_layout()
    plot_path = MODELS_DIR / "feature_importance.png"
    fig.savefig(plot_path, dpi=150)
    print(f"[INFO] Feature importance plot saved → {plot_path}")

    # ROC curve
    fig2, ax2 = plt.subplots(figsize=(7, 5))
    RocCurveDisplay.from_predictions(y_test, y_proba, ax=ax2,
                                     name="Random Forest")
    ax2.set_title("ROC Curve — Phishing Detector")
    plt.tight_layout()
    roc_path = MODELS_DIR / "roc_curve.png"
    fig2.savefig(roc_path, dpi=150)
    print(f"[INFO] ROC curve saved → {roc_path}")

    # 8. Save model artefacts ──────────────────────────────────────────────────
    for obj, fname in [
        (clf,           "model.pkl"),
        (scaler,        "scaler.pkl"),
        (feature_names, "feature_names.pkl"),
    ]:
        p = MODELS_DIR / fname
        with open(p, "wb") as f:
            pickle.dump(obj, f)
        print(f"[INFO] Saved → {p}")

    print("\n✅  Training complete. Model is ready for inference via api.py")


# ──────────────────────────────── CLI ─────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train phishing detection model")
    parser.add_argument("--phishtank", default=None,
                        help="Path to PhishTank verified_online.csv")
    parser.add_argument("--tranco",    default=None,
                        help="Path to Tranco top-1M list CSV")
    parser.add_argument("--max-rows",  type=int, default=10_000,
                        help="Max rows to load from each dataset (default 10000)")
    parser.add_argument("--whois",     action="store_true",
                        help="Include WHOIS lookup features (slow but more accurate)")
    parser.add_argument("--workers",   type=int, default=20,
                        help="Thread pool size for parallel extraction (default 20)")
    args = parser.parse_args()

    train(args)
