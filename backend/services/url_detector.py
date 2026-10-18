"""
URL Phishing Detector combining trained XGBoost model and heuristic verification.
"""
from __future__ import annotations

import sys
from pathlib import Path
import json
import joblib
import pandas as pd
from xgboost import XGBClassifier

# Add repo root to sys.path so mlservices is importable
REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from mlservices.src.url.feature_extractor import extract_features
from backend.services.heuristics import evaluate_heuristics

MODELS_DIR = Path(__file__).resolve().parent.parent / "models"
TUNED_MODEL_BACKEND = MODELS_DIR / "url_xgboost_tuned.json"
TUNED_FEATURES_BACKEND = MODELS_DIR / "url_xgboost_tuned_features.json"
TUNED_MODEL_MLSERVICES = REPO_ROOT / "mlservices" / "models" / "url_xgboost_tuned.json"
TUNED_FEATURES_MLSERVICES = REPO_ROOT / "mlservices" / "models" / "url_xgboost_tuned_features.json"
LEGACY_MODEL_PATH = MODELS_DIR / "url_model.joblib"

_MODEL_CACHE = None
_FEATURE_NAMES = None


def load_model():
    """Load and cache the trained XGBoost model artifact (preferring tuned JSON)."""
    global _MODEL_CACHE, _FEATURE_NAMES
    if _MODEL_CACHE is not None:
        return _MODEL_CACHE, _FEATURE_NAMES

    # 1. Prefer tuned XGBoost JSON model
    for model_path, feat_path in [
        (TUNED_MODEL_BACKEND, TUNED_FEATURES_BACKEND),
        (TUNED_MODEL_MLSERVICES, TUNED_FEATURES_MLSERVICES),
    ]:
        if model_path.exists() and feat_path.exists():
            with open(feat_path, "r", encoding="utf-8") as f:
                feature_names = json.load(f)
            model = XGBClassifier()
            model.load_model(str(model_path))
            _MODEL_CACHE = model
            _FEATURE_NAMES = feature_names
            return _MODEL_CACHE, _FEATURE_NAMES

    # 2. Fallback to legacy joblib artifact
    if LEGACY_MODEL_PATH.exists():
        artifact = joblib.load(LEGACY_MODEL_PATH)
        _MODEL_CACHE = artifact["model"]
        _FEATURE_NAMES = artifact["features"]
        return _MODEL_CACHE, _FEATURE_NAMES

    raise FileNotFoundError(
        f"No model artifact found. Checked: {TUNED_MODEL_BACKEND}, {TUNED_MODEL_MLSERVICES}, {LEGACY_MODEL_PATH}"
    )


KNOWN_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "ow.ly", "is.gd",
    "buff.ly", "cutt.ly", "rb.gy", "goo.gl", "rebrand.ly",
    "t.ly", "s.id", "shorturl.at", "tiny.cc", "clck.ru"
}


def unmask_shortened_url(url: str, timeout: float = 1.5) -> tuple[str, bool, str | None]:
    """
    Resolve shortened URLs (e.g. bit.ly, tinyurl) to uncover the final destination.
    Returns (resolved_url, is_shortened, original_short_url).
    """
    raw = url.strip()
    parse_target = raw if "://" in raw else "http://" + raw
    try:
        from urllib.parse import urlparse
        parsed = urlparse(parse_target)
        hostname = (parsed.hostname or "").lower()

        is_shortener = any(hostname == s or hostname.endswith("." + s) for s in KNOWN_SHORTENERS)
        if not is_shortener:
            return raw, False, None

        import urllib.request
        req = urllib.request.Request(
            parse_target,
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) PhishGuard/1.1"}
        )
        opener = urllib.request.build_opener()
        with opener.open(req, timeout=timeout) as response:
            final_url = response.geturl()
            if final_url and final_url.lower().rstrip("/") != parse_target.lower().rstrip("/"):
                return final_url, True, raw
    except Exception:
        pass

    return raw, False, None


def unwrap_redirect_wrapper(raw_url: str) -> str:
    """Unwrap search engine / mail redirect wrappers (e.g. google.com/url?q=...)."""
    try:
        from urllib.parse import urlparse, parse_qs
        parsed = urlparse(raw_url if "://" in raw_url else "http://" + raw_url)
        host = (parsed.hostname or "").lower()
        if host == "google.com" or host.endswith(".google.com"):
            if parsed.path.rstrip("/") == "/url":
                qs = parse_qs(parsed.query)
                if "q" in qs and qs["q"]:
                    return qs["q"][0]
                if "url" in qs and qs["url"]:
                    return qs["url"][0]
    except Exception:
        pass
    return raw_url


def detect_url_phishing(url: str) -> dict[str, any]:
    """
    Analyze a URL and return threat score (0-100), verdict, and explanation flags.
    """
    model, feature_names = load_model()

    # 0. Unwrap mail/search redirect wrappers and unmask shortened URLs
    clean_input_url = unwrap_redirect_wrapper(url)
    target_url, is_shortened, original_short_url = unmask_shortened_url(clean_input_url)

    # 1. Feature extraction on target URL
    features = extract_features(target_url)
    input_data = pd.DataFrame(
        [[features[name] for name in feature_names]],
        columns=feature_names,
    )

    # 2. ML model prediction
    probabilities = model.predict_proba(input_data)[0]
    # Class 1 is phishing, Class 0 is legitimate
    ml_phishing_prob = float(probabilities[1])
    ml_score = round(ml_phishing_prob * 100.0, 1)

    # 3. Heuristic evaluation on target URL
    heuristics = evaluate_heuristics(target_url)
    penalty_score = heuristics["penalty_score"]
    flags = list(heuristics["flags"])

    if is_shortened:
        flags.insert(0, f"Shortened link unmasked: leads to {target_url}")

    # 4. Explanations & feature insights
    has_suspicious_keywords = False
    if features.get("suspicious_keyword_count", 0) > 0:
        kw_list = []
        for kw in ["login", "verify", "account", "password"]:
            if features.get(f"has_{kw}", 0) == 1:
                kw_list.append(kw)
        if kw_list:
            has_suspicious_keywords = True
            flags.append(f"Contains security-sensitive keyword(s): {', '.join(kw_list)}")

    if features.get("url_length", 0) > 120 and not heuristics.get("is_trusted_domain"):
        flags.append(f"Abnormally long URL ({features['url_length']} characters)")

    # 5. Composite score calculation
    if heuristics.get("is_trusted_domain"):
        composite_score = 0.0
        ml_phishing_prob = 0.0
        flags.append("Verified high-reputation domain")
    elif penalty_score >= 40.0:
        # High heuristic penalty indicates corroborated threat signals (e.g. typosquatting, raw IP, new domain)
        composite_score = max(ml_score, penalty_score)
    elif penalty_score > 0.0 or has_suspicious_keywords:
        # Moderate risk indicators present
        composite_score = (0.50 * ml_score) + (0.50 * penalty_score)
        if has_suspicious_keywords and composite_score < 40.0:
            composite_score = 40.0
    else:
        # Zero heuristic penalties and zero suspicious keywords detected.
        # Cap uncorroborated ML score to prevent false alarms on benign URLs with paths/queries.
        composite_score = min(ml_score * 0.25, 25.0)

    composite_score = round(min(max(composite_score, 0.0), 100.0), 1)

    # 6. Final verdict
    if composite_score >= 70.0:
        verdict = "phishing"
        risk_level = "HIGH"
    elif composite_score >= 40.0:
        verdict = "suspicious"
        risk_level = "MEDIUM"
    else:
        verdict = "safe"
        risk_level = "LOW"

    return {
        "url": url,
        "resolved_url": target_url if (is_shortened or target_url != url) else None,
        "is_shortened": is_shortened,
        "threat_score": composite_score,
        "verdict": verdict,
        "risk_level": risk_level,
        "ml_probability": ml_phishing_prob,
        "reasons": flags,
        "features": features
    }

