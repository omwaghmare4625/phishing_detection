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


def calculate_bayesian_threat_score(
    ml_prob: float,
    penalty_score: float,
    is_trusted_domain: bool,
    has_suspicious_keywords: bool
) -> tuple[float, dict[str, any]]:
    """
    Bayesian and Adaptive Evidence Fusion engine for phishing threat scoring.
    Combines domain prior beliefs, ML likelihood, and structural attack indicators.
    """
    ml_score = round(ml_prob * 100.0, 1)

    if is_trusted_domain:
        breakdown = {
            "engine": "bayesian_adaptive",
            "domain_trust": "verified_top_domain",
            "base_prior_probability": 0.005,
            "ml_score": ml_score,
            "heuristic_penalty": 0.0,
            "weight_ml": 0.10,
            "weight_heuristic": 0.90,
            "final_threat_score": 0.0
        }
        return 0.0, breakdown

    # 1. Base Prior Odds P0 based on heuristic severity
    if penalty_score >= 50.0:
        base_prior = 0.65
        w_heur = 0.80
        w_ml = 0.20
    elif penalty_score >= 20.0 or has_suspicious_keywords:
        base_prior = 0.35
        w_heur = 0.60
        w_ml = 0.40
    else:
        base_prior = 0.12
        w_heur = 0.50
        w_ml = 0.50

    prior_odds = base_prior / (1.0 - base_prior)

    # 2. ML Likelihood Ratio
    clamped_ml = min(max(ml_prob, 0.02), 0.98)
    l_ml = clamped_ml / (1.0 - clamped_ml)

    # 3. Heuristic Likelihood Ratio
    if penalty_score >= 50.0:
        l_heur = 12.0
    elif penalty_score >= 35.0:
        l_heur = 6.0
    elif penalty_score >= 20.0:
        l_heur = 3.0
    elif penalty_score >= 10.0 or has_suspicious_keywords:
        l_heur = 1.8
    else:
        l_heur = 0.25

    # 4. Bayesian Posterior Odds & Probability
    posterior_odds = prior_odds * (l_ml ** w_ml) * (l_heur ** w_heur)
    posterior_prob = posterior_odds / (1.0 + posterior_odds)
    score = posterior_prob * 100.0

    # 5. Guardrails & Safety Caps
    if penalty_score >= 50.0:
        score = max(score, 75.0, penalty_score)
    elif ml_prob >= 0.85 and (penalty_score >= 15.0 or has_suspicious_keywords):
        score = max(score, 75.0)
    elif penalty_score == 0.0 and not has_suspicious_keywords:
        score = min(score, 25.0)

    final_score = round(min(max(score, 0.0), 100.0), 1)

    breakdown = {
        "engine": "bayesian_adaptive",
        "domain_trust": "unverified",
        "base_prior_probability": round(base_prior, 2),
        "ml_score": ml_score,
        "heuristic_penalty": penalty_score,
        "weight_ml": round(w_ml, 2),
        "weight_heuristic": round(w_heur, 2),
        "final_threat_score": final_score
    }

    return final_score, breakdown


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

    # 5. Bayesian & Dynamic Score Calculation
    is_trusted = bool(heuristics.get("is_trusted_domain"))
    if is_trusted:
        flags.append("Verified high-reputation domain")

    composite_score, scoring_breakdown = calculate_bayesian_threat_score(
        ml_prob=ml_phishing_prob,
        penalty_score=penalty_score,
        is_trusted_domain=is_trusted,
        has_suspicious_keywords=has_suspicious_keywords
    )

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
        "features": features,
        "scoring_breakdown": scoring_breakdown
    }

