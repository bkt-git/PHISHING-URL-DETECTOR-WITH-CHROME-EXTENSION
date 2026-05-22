"""
feature_extractor.py
Extracts URL lexical features + WHOIS/domain-age features from a given URL.
Returns a flat dict (or pandas Series) ready for ML training / inference.
"""

import re
import math
import socket
import urllib.parse
from datetime import datetime, timezone
from typing import Optional

import tldextract
import whois  # python-whois

# ─────────────────────────── suspicious signals ───────────────────────────────

SUSPICIOUS_KEYWORDS = [
    "login", "signin", "sign-in", "secure", "verify", "update",
    "confirm", "account", "banking", "password", "credential",
    "paypal", "ebay", "amazon", "apple", "microsoft", "google",
    "support", "alert", "access", "auth", "validate",
]

SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq",   # free Freenom TLDs heavily abused
    "xyz", "top", "work", "click", "link", "online", "site",
    "info", "biz", "club", "pw",
}

# ──────────────────────────── helper functions ─────────────────────────────────

def _has_ip_address(url: str) -> int:
    """Return 1 if the host part of the URL looks like a raw IPv4/IPv6 address."""
    try:
        host = urllib.parse.urlparse(url).netloc.split(":")[0]
        socket.inet_aton(host)   # throws if not IPv4
        return 1
    except Exception:
        # try IPv6 brackets
        if re.match(r"^\[[\da-fA-F:]+\]$", host):
            return 1
        return 0


def _shannon_entropy(s: str) -> float:
    """Shannon entropy of a string (higher → more random-looking)."""
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((f / n) * math.log2(f / n) for f in freq.values())


def _count_keywords(text: str) -> int:
    text_lower = text.lower()
    return sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in text_lower)


def _digit_ratio(s: str) -> float:
    if not s:
        return 0.0
    return sum(c.isdigit() for c in s) / len(s)


# ────────────────────────── URL feature extraction ────────────────────────────

def extract_url_features(url: str) -> dict:
    """
    Extract lexical features from a URL string.
    No network calls — instant, always available.
    """
    # ensure scheme is present for urlparse
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    parsed   = urllib.parse.urlparse(url)
    ext      = tldextract.extract(url)

    domain   = ext.domain or ""
    suffix   = ext.suffix or ""
    subdomain = ext.subdomain or ""
    path     = parsed.path or ""
    query    = parsed.query or ""
    netloc   = parsed.netloc or ""
    full_url = url

    num_subdomains = len(subdomain.split(".")) if subdomain else 0

    features = {
        # --- length signals ---
        "url_length":       len(full_url),
        "domain_length":    len(domain),
        "path_length":      len(path),
        "query_length":     len(query),

        # --- character counts ---
        "num_dots":         full_url.count("."),
        "num_hyphens":      full_url.count("-"),
        "num_underscores":  full_url.count("_"),
        "num_slashes":      full_url.count("/"),
        "num_question":     full_url.count("?"),
        "num_equals":       full_url.count("="),
        "num_ampersand":    full_url.count("&"),
        "num_at":           full_url.count("@"),
        "num_percent":      full_url.count("%"),
        "num_digits":       sum(c.isdigit() for c in full_url),
        "num_special":      sum(not c.isalnum() for c in full_url),

        # --- structural signals ---
        "has_ip":           _has_ip_address(url),
        "has_port":         int(bool(parsed.port)),
        "is_https":         int(parsed.scheme == "https"),
        "num_subdomains":   num_subdomains,

        # --- domain signals ---
        "digit_ratio_domain":   _digit_ratio(domain),
        "digit_ratio_url":      _digit_ratio(full_url),
        "domain_entropy":       _shannon_entropy(domain),
        "url_entropy":          _shannon_entropy(full_url),
        "suspicious_keywords":  _count_keywords(full_url),
        "suspicious_tld":       int(suffix.lower() in SUSPICIOUS_TLDS),

        # --- path signals ---
        "path_depth":       len([p for p in path.split("/") if p]),
        "has_double_slash": int("//" in path),
        "hex_encoding":     len(re.findall(r"%[0-9a-fA-F]{2}", full_url)),
    }

    return features


# ─────────────────────────── WHOIS feature extraction ─────────────────────────

def extract_whois_features(url: str, timeout: int = 10) -> dict:
    """
    Query WHOIS for domain age and expiry.
    Falls back to -1 sentinel values if lookup fails (common for many TLDs).
    """
    defaults = {
        "domain_age_days":    -1,
        "days_until_expiry":  -1,
        "whois_available":    0,
    }

    ext = tldextract.extract(url)
    domain_str = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain
    if not domain_str:
        return defaults

    try:
        w = whois.whois(domain_str)

        now = datetime.now(timezone.utc)

        # creation date
        created = w.creation_date
        if isinstance(created, list):
            created = created[0]
        if created:
            if created.tzinfo is None:
                created = created.replace(tzinfo=timezone.utc)
            age_days = (now - created).days
        else:
            age_days = -1

        # expiry date
        expiry = w.expiration_date
        if isinstance(expiry, list):
            expiry = expiry[0]
        if expiry:
            if expiry.tzinfo is None:
                expiry = expiry.replace(tzinfo=timezone.utc)
            expiry_days = (expiry - now).days
        else:
            expiry_days = -1

        return {
            "domain_age_days":   age_days,
            "days_until_expiry": expiry_days,
            "whois_available":   1,
        }

    except Exception:
        return defaults


# ──────────────────────────── combined extractor ──────────────────────────────

def extract_all_features(url: str, use_whois: bool = True) -> dict:
    """
    Master function: returns a single flat dict of all features.
    Set use_whois=False for fast batch offline extraction.
    """
    features = extract_url_features(url)
    if use_whois:
        features.update(extract_whois_features(url))
    return features


# ─────────────────────────────── quick test ───────────────────────────────────

if __name__ == "__main__":
    test_urls = [
        "https://www.google.com",
        "http://paypal-secure-login.tk/verify?user=123&token=abc",
        "http://192.168.1.1/admin/login.php",
        "https://amazon-account-update.xyz/secure/confirm",
    ]
    for u in test_urls:
        f = extract_all_features(u, use_whois=False)   # skip WHOIS for quick test
        print(f"\n[URL] {u}")
        for k, v in f.items():
            print(f"  {k:30s} = {v}")
