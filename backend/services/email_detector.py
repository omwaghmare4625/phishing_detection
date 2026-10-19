"""
Email phishing and Business Email Compromise (BEC) detector.
Analyzes sender spoofing, urgency/fear triggers in body text, and embedded links.
"""
from __future__ import annotations

import re
import base64
import io
import urllib.request
from pathlib import Path
from functools import lru_cache
from urllib.parse import urlparse
import joblib

try:
    import cv2
    import numpy as np
    from PIL import Image
    _CV2_QR_DETECTOR = cv2.QRCodeDetector()
except Exception:
    _CV2_QR_DETECTOR = None

from backend.services.url_detector import detect_url_phishing
from backend.services.heuristics import POPULAR_BRANDS, AUTHENTIC_BRAND_DOMAINS

FREE_EMAIL_PROVIDERS = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com",
    "aol.com", "icloud.com", "mail.com", "proton.me", "protonmail.com"
}

@lru_cache(maxsize=1)
def load_email_nlp_model():
    """Load the trained email NLP classifier pipeline."""
    model_path = Path(__file__).resolve().parent.parent / "models" / "email_model.joblib"
    if model_path.exists():
        try:
            return joblib.load(model_path)
        except Exception:
            return None
    return None


def predict_email_nlp(subject: str, body: str) -> dict[str, any]:
    """Run NLP model to detect phishing probability in subject + body text."""
    model = load_email_nlp_model()
    combined_text = f"{subject} {body}".strip()
    if not model or not combined_text:
        return {
            "model_loaded": model is not None,
            "phishing_probability": 0.0,
            "is_phishing_text": False
        }

    try:
        proba = model.predict_proba([combined_text])[0][1]
        pct = round(float(proba) * 100, 1)
        return {
            "model_loaded": True,
            "phishing_probability": pct,
            "is_phishing_text": pct >= 50.0
        }
    except Exception:
        return {
            "model_loaded": False,
            "phishing_probability": 0.0,
            "is_phishing_text": False
        }


HOMOGLYPH_MAP = {
    # Cyrillic lookalikes
    "а": "a", "с": "c", "е": "e", "о": "o", "р": "p", "ѕ": "s", "х": "x", "у": "y",
    "і": "i", "ј": "j", "ԁ": "d", "ԛ": "q", "ԝ": "w", "А": "A", "В": "B", "Е": "E",
    "К": "K", "М": "M", "Н": "H", "О": "O", "Р": "P", "С": "C", "Т": "T", "Х": "X",
    "Ү": "Y", "І": "I", "Ј": "J",
    # Greek lookalikes
    "α": "a", "ο": "o", "ν": "v", "ρ": "p", "τ": "t", "υ": "u", "χ": "x",
    # Fullwidth Latin
    "ａ": "a", "ｂ": "b", "ｃ": "c", "ｄ": "d", "ｅ": "e", "ｆ": "f", "ｇ": "g",
    "ｈ": "h", "ｉ": "i", "ｊ": "j", "ｋ": "k", "ｌ": "l", "ｍ": "m", "ｎ": "n",
    "ｏ": "o", "ｐ": "p", "ｑ": "q", "ｒ": "r", "ｓ": "s", "ｔ": "t", "ｕ": "u",
    "ｖ": "v", "ｗ": "w", "ｘ": "x", "ｙ": "y", "ｚ": "z",
}


def strip_zero_width_and_homoglyphs(text: str) -> str:
    """
    Strip zero-width spaces, joiners, non-printable unicode characters,
    and normalize homoglyphs used to evade security keyword filters.
    """
    if not text:
        return ""
    # Strip zero-width spaces, joiners, non-break spaces, soft hyphens, and byte order marks
    cleaned = re.sub(
        r"[\u200B-\u200D\uFEFF\u2060\u180E\u00AD\u00A0\u200E\u200F\u202A-\u202E\u2066-\u2069]",
        "",
        text
    )
    # Map homoglyphs to standard Latin ASCII
    return "".join(HOMOGLYPH_MAP.get(ch, ch) for ch in cleaned)


URGENT_PHRASES = [
    "immediate action required",
    "account suspended",
    "account has been locked",
    "unauthorized login attempt",
    "verify your identity",
    "suspended within 24 hours",
    "confirm your password",
    "update payment method",
    "security alert",
    "final warning",
    "urgent notification",
    "wire transfer",
    "gift card",
    "crypto wallet compromised",
    "tax refund pending",
    "unusual activity detected"
]

SCAM_FINANCIAL_LURES = [
    "free money",
    "claim your prize",
    "claim prize",
    "claim reward",
    "cash prize",
    "giveaway",
    "lottery winner",
    "crypto giveaway",
    "bitcoin giveaway",
    "congratulations you won",
    "you have won",
    "get rich",
    "earn $",
    "claim bonus",
    "unclaimed funds",
    "free gift card",
    "double your investment",
    "risk-free return",
    "inheritance notification",
    "easy money",
    "free crypto",
    "click to claim",
]

BEC_PHRASES = [
    # Primary CEO & Payroll diversion triggers
    "update direct deposit",
    "change bank details for payroll",
    "are you at your desk",
    "wire instructions",
    "keep this confidential",
    # Extended BEC & wire fraud indicators
    "payroll direct deposit",
    "change direct deposit",
    "wire transfer instructions",
    "urgent wire",
    "strictly confidential transaction",
    "quick favor",
    "purchase apple gift cards",
    "purchase gift cards",
    "send voucher codes to my personal",
    "send card codes to my email",
    "new bank account for payment",
    "updated invoice payment details",
    "payroll change request",
    "direct deposit routing",
    "urgent payment authorization",
    "are you in the office",
    "process this wire"
]


def detect_qr_codes_in_images(image_sources: list[str]) -> tuple[float, list[str], list[dict]]:
    """
    Scan email images (data URIs or remote image URLs) for embedded QR codes (Quishing).
    Decodes payload and evaluates threat level of decoded destinations.
    """
    if not image_sources or _CV2_QR_DETECTOR is None:
        return 0.0, [], []

    max_score = 0.0
    reasons: list[str] = []
    qr_findings: list[dict] = []

    for src in image_sources[:6]:  # Limit to first 6 images for fast response
        src = src.strip()
        if not src:
            continue

        raw_bytes = None
        try:
            if src.startswith("data:image/") and ";base64," in src:
                b64_part = src.split(";base64,")[1]
                raw_bytes = base64.b64decode(b64_part)
            elif src.startswith("http://") or src.startswith("https://"):
                req = urllib.request.Request(
                    src,
                    headers={"User-Agent": "PhishGuard-QR-Scanner/1.0"}
                )
                with urllib.request.urlopen(req, timeout=1.2) as resp:
                    raw_bytes = resp.read()
        except Exception:
            continue

        if not raw_bytes:
            continue

        try:
            pil_img = Image.open(io.BytesIO(raw_bytes)).convert("RGB")
            np_img = np.array(pil_img)
            cv_img = cv2.cvtColor(np_img, cv2.COLOR_RGB2BGR)

            decoded_text, points, _ = _CV2_QR_DETECTOR.detectAndDecode(cv_img)
            if decoded_text and decoded_text.strip():
                payload = decoded_text.strip()
                finding = {
                    "source": src[:50] + "..." if len(src) > 50 else src,
                    "payload": payload,
                    "is_url": False,
                    "destination_threat_score": 0.0,
                    "verdict": "unknown"
                }

                # If QR code encodes a destination URL, inspect with URL detector
                if re.match(r"^https?://", payload, re.IGNORECASE) or ("." in payload and " " not in payload):
                    finding["is_url"] = True
                    url_report = detect_url_phishing(payload)
                    dest_score = url_report.get("threat_score", 0.0)
                    finding["destination_threat_score"] = dest_score
                    finding["verdict"] = url_report.get("verdict", "safe")

                    if dest_score >= 70.0:
                        max_score = max(max_score, 88.0)
                        reasons.append(
                            f"Quishing (QR Code Phishing) detected: Embedded QR code redirects to malicious destination: '{payload}'"
                        )
                    elif dest_score >= 40.0:
                        max_score = max(max_score, 65.0)
                        reasons.append(
                            f"Suspicious QR Code detected: Embedded QR points to suspicious URL: '{payload}'"
                        )
                    else:
                        max_score = max(max_score, 25.0)
                        reasons.append(
                            f"Scannable QR code detected linking to external URL: '{payload}'"
                        )
                else:
                    max_score = max(max_score, 20.0)
                    reasons.append(
                        f"Embedded QR code detected with payload: '{payload[:40]}'"
                    )

                qr_findings.append(finding)
        except Exception:
            continue

    return max_score, reasons, qr_findings


def check_quishing_and_schemes(links: list[str], image_sources: list[str] | None = None) -> tuple[float, list[str], list[dict]]:
    """Check for suspicious data: URIs, blob: links, QR/quishing links, and embedded image QR codes."""
    score = 0.0
    reasons: list[str] = []

    # 1. Inspect hyperlink schemes & quishing keywords
    for link in links:
        link_lower = link.lower().strip()
        if link_lower.startswith("data:text/html") or link_lower.startswith("data:image/svg+xml"):
            score = max(score, 85.0)
            reasons.append("Embedded data URI payload detected (obfuscated HTML/SVG phishing)")
        elif link_lower.startswith("blob:") or link_lower.startswith("javascript:"):
            score = max(score, 80.0)
            reasons.append("High-risk execution URI detected (blob/javascript scheme)")
        elif "quishing" in link_lower or ("qr" in link_lower and any(kw in link_lower for kw in ["login", "auth", "verify", "scan"])):
            score = max(score, 75.0)
            reasons.append("Quishing / QR-authentication capture link pattern flagged")

    # 2. Inspect embedded email images for QR codes
    qr_score, qr_reasons, qr_findings = detect_qr_codes_in_images(image_sources or [])
    score = max(score, qr_score)
    reasons.extend(qr_reasons)

    return score, reasons, qr_findings


def check_sender_spoofing(sender_name: str, sender_email: str) -> list[str]:
    """Check for display name spoofing and brand impersonation in sender headers."""
    reasons: list[str] = []
    name_lower = sender_name.lower().strip()
    email_lower = sender_email.lower().strip()

    email_domain = email_lower.split("@")[-1] if "@" in email_lower else ""
    local_part = email_lower.split("@")[0] if "@" in email_lower else ""

    # 1. Check if a known brand is claimed in the sender's display name
    for brand in POPULAR_BRANDS:
        auth_domains = AUTHENTIC_BRAND_DOMAINS.get(brand, {f"{brand}.com", f"{brand}.org"})
        is_valid_brand_domain = any(
            email_domain == d or email_domain.endswith(f".{d}")
            for d in auth_domains
        )

        if re.search(r"\b" + re.escape(brand) + r"\b", name_lower):
            if not is_valid_brand_domain:
                reasons.append(
                    f"Sender claims brand '{brand.title()}' in display name, but email domain is '{email_domain}'"
                )
                if email_domain in FREE_EMAIL_PROVIDERS:
                    reasons.append(
                        f"Sender uses free public email service (@{email_domain}) while claiming to be '{brand.title()}'"
                    )
        elif not is_valid_brand_domain and email_domain:
            # 2. Check if brand is in the sender domain or local-part of free email provider
            domain_core = email_domain.split(".")[0]
            if brand in domain_core or (email_domain in FREE_EMAIL_PROVIDERS and brand in local_part):
                reasons.append(
                    f"Sender address '{sender_email}' appears to impersonate brand '{brand.title()}'"
                )

    return reasons


def check_body_urgency(subject: str, body: str) -> tuple[float, list[str]]:
    """Check for high-pressure language, credential theft triggers, BEC, and financial scam lures."""
    reasons: list[str] = []
    combined_raw = f"{subject} {body}"
    clean_text = strip_zero_width_and_homoglyphs(combined_raw).lower()
    score = 0.0

    matched_bec = [p for p in BEC_PHRASES if p in clean_text]
    if matched_bec:
        score += 45.0
        reasons.append(
            f"Business Email Compromise (BEC) / executive fraud pattern detected: {', '.join(matched_bec[:2])}"
        )

    matched_urgency = [p for p in URGENT_PHRASES if p in clean_text]
    if matched_urgency:
        score += min(len(matched_urgency) * 15.0, 30.0)
        reasons.append(
            f"High-urgency fear/coercion language detected: {', '.join(matched_urgency[:3])}"
        )

    matched_lures = [l for l in SCAM_FINANCIAL_LURES if l in clean_text]
    if matched_lures:
        score += min(len(matched_lures) * 20.0, 35.0)
        reasons.append(
            f"Financial bait / scam lure language detected: {', '.join(matched_lures[:3])}"
        )

    # Check for credential request keywords
    if ("password" in clean_text or "credentials" in clean_text) and (
        "click" in clean_text or "link" in clean_text or "log in" in clean_text
    ):
        score += 25.0
        reasons.append("Email solicits credential verification via link")

    return min(score, 60.0), reasons


def calculate_email_dual_engine_score(
    nlp_prob: float,
    sender_penalty: float,
    content_penalty: float,
    link_threat_score: float,
    quishing_score: float
) -> tuple[float, dict[str, any]]:
    """
    Unified Dual-Engine Scoring (ML + Heuristic Evidence Fusion).
    Explicitly combines Machine Learning text classifier probability
    with objective structural heuristic penalties.
    """
    ml_score = round(nlp_prob, 1)
    heuristic_raw = sender_penalty + content_penalty + (link_threat_score * 0.9) + quishing_score
    heuristic_score = round(min(max(heuristic_raw, 0.0), 100.0), 1)

    # 1. Calibrate dynamic weights
    if link_threat_score >= 70.0 or sender_penalty >= 45.0 or quishing_score >= 70.0:
        w_heur = 0.75
        w_ml = 0.25
        combined = (w_ml * ml_score) + (w_heur * heuristic_score)
        combined = max(combined, link_threat_score, sender_penalty, quishing_score)
    elif ml_score >= 75.0:
        w_ml = 0.60
        w_heur = 0.40
        combined = (w_ml * ml_score) + (w_heur * heuristic_score)
    else:
        w_ml = 0.50
        w_heur = 0.50
        combined = (w_ml * ml_score) + (w_heur * heuristic_score)

    # Safety caps & minimum barriers
    if link_threat_score >= 70.0:
        combined = max(combined, link_threat_score)
    if ml_score >= 75.0 and heuristic_score >= 20.0:
        combined = max(combined, 72.0)
    elif heuristic_score >= 50.0:
        combined = max(combined, 70.0)

    final_score = round(min(max(combined, 0.0), 100.0), 1)

    breakdown = {
        "engine": "dual_ml_heuristic",
        "ml_score": ml_score,
        "heuristic_score": heuristic_score,
        "weight_ml": round(w_ml, 2),
        "weight_heuristic": round(w_heur, 2),
        "final_threat_score": final_score
    }
    return final_score, breakdown


def detect_email_phishing(
    sender_name: str,
    sender_email: str,
    subject: str,
    body_text: str,
    links: list[str] | None = None,
    image_urls: list[str] | None = None
) -> dict[str, any]:
    """
    Analyze an email for phishing and return threat score (0-100), verdict, and findings
    via unified ML + Heuristic dual-engine evaluation.
    """
    links = links or []
    image_urls = image_urls or []
    reasons: list[str] = []

    # Clean zero-width obfuscation across inputs
    clean_subject = strip_zero_width_and_homoglyphs(subject)
    clean_body = strip_zero_width_and_homoglyphs(body_text)

    # 1. Inspect sender
    sender_flags = check_sender_spoofing(sender_name, sender_email)
    sender_penalty = 45.0 if sender_flags else 0.0
    if sender_flags:
        reasons.extend(sender_flags)

    # 2. Inspect content via NLP Classifier & Keyword Heuristics
    nlp_report = predict_email_nlp(clean_subject, clean_body)
    nlp_prob = nlp_report.get("phishing_probability", 0.0)

    if nlp_prob >= 75.0:
        reasons.append(f"NLP Classifier flagged high-confidence phishing language ({nlp_prob}%)")
    elif nlp_prob >= 50.0:
        reasons.append(f"NLP Classifier flagged social engineering / urgency patterns ({nlp_prob}%)")

    content_penalty, urgency_flags = check_body_urgency(clean_subject, clean_body)
    if urgency_flags:
        reasons.extend(urgency_flags)

    # 3. Quishing & Deceptive Scheme link and QR image inspection
    quishing_score, quishing_flags, qr_findings = check_quishing_and_schemes(links, image_urls)
    if quishing_flags:
        reasons.extend(quishing_flags)

    # 4. Inspect embedded links
    link_results = []
    max_link_score = 0.0

    for link in links:
        clean_link = link.strip()
        if not clean_link or clean_link.startswith("#"):
            continue
        url_report = detect_url_phishing(clean_link)
        link_results.append({
            "url": clean_link,
            "threat_score": url_report["threat_score"],
            "verdict": url_report["verdict"],
            "reasons": url_report["reasons"]
        })
        if url_report["threat_score"] > max_link_score:
            max_link_score = url_report["threat_score"]

    if max_link_score >= 70.0:
        reasons.append(f"Email contains high-risk phishing URL ({max_link_score}/100)")
    elif max_link_score >= 40.0:
        reasons.append(f"Email contains suspicious URL ({max_link_score}/100)")

    # 5. Dual-Engine Evidence Fusion (ML + Heuristic)
    threat_score, scoring_breakdown = calculate_email_dual_engine_score(
        nlp_prob=nlp_prob,
        sender_penalty=sender_penalty,
        content_penalty=content_penalty,
        link_threat_score=max_link_score,
        quishing_score=quishing_score
    )

    if threat_score >= 70.0:
        verdict = "phishing"
        risk_level = "HIGH"
    elif threat_score >= 40.0:
        verdict = "suspicious"
        risk_level = "MEDIUM"
    else:
        verdict = "safe"
        risk_level = "LOW"

    return {
        "threat_score": threat_score,
        "verdict": verdict,
        "risk_level": risk_level,
        "sender": {
            "name": sender_name,
            "email": sender_email
        },
        "subject": subject,
        "reasons": reasons,
        "link_count": len(links),
        "analyzed_links": link_results,
        "nlp_analysis": nlp_report,
        "quishing_findings": qr_findings,
        "scoring_breakdown": scoring_breakdown
    }
