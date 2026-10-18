"""
Email phishing and Business Email Compromise (BEC) detector.
Analyzes sender spoofing, urgency/fear triggers in body text, and embedded links.
"""
from __future__ import annotations

import re
from urllib.parse import urlparse
from backend.services.url_detector import detect_url_phishing
from backend.services.heuristics import POPULAR_BRANDS, AUTHENTIC_BRAND_DOMAINS

FREE_EMAIL_PROVIDERS = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com",
    "aol.com", "icloud.com", "mail.com", "proton.me", "protonmail.com"
}

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


def check_sender_spoofing(sender_name: str, sender_email: str) -> list[str]:
    """Check for display name spoofing and brand impersonation."""
    reasons: list[str] = []
    name_lower = sender_name.lower().strip()
    email_lower = sender_email.lower().strip()

    email_domain = email_lower.split("@")[-1] if "@" in email_lower else ""

    # Check if a known brand is claimed in the sender's display name
    for brand in POPULAR_BRANDS:
        # Match brand name as distinct word
        if re.search(r"\b" + re.escape(brand) + r"\b", name_lower):
            auth_domains = AUTHENTIC_BRAND_DOMAINS.get(brand, {f"{brand}.com", f"{brand}.org"})
            is_valid_brand_domain = any(
                email_domain == d or email_domain.endswith(f".{d}")
                for d in auth_domains
            )
            if not is_valid_brand_domain:
                reasons.append(
                    f"Sender claims brand '{brand.title()}' in display name, but email domain is '{email_domain}'"
                )
                if email_domain in FREE_EMAIL_PROVIDERS:
                    reasons.append(
                        f"Sender uses free public email service (@{email_domain}) while claiming to be '{brand.title()}'"
                    )

    return reasons



def check_body_urgency(subject: str, body: str) -> list[str]:
    """Check for high-pressure language and credential theft triggers."""
    reasons: list[str] = []
    combined_text = f"{subject} {body}".lower()

    matched_phrases = []
    for phrase in URGENT_PHRASES:
        if phrase in combined_text:
            matched_phrases.append(phrase)

    if matched_phrases:
        reasons.append(
            f"High-urgency fear/coercion language detected: {', '.join(matched_phrases[:3])}"
        )

    # Check for credential request keywords
    if ("password" in combined_text or "credentials" in combined_text) and (
        "click" in combined_text or "link" in combined_text or "log in" in combined_text
    ):
        reasons.append("Email solicits credential verification via link")

    return reasons


def detect_email_phishing(
    sender_name: str,
    sender_email: str,
    subject: str,
    body_text: str,
    links: list[str] | None = None
) -> dict[str, any]:
    """
    Analyze an email for phishing and return threat score (0-100), verdict, and findings.
    """
    links = links or []
    reasons: list[str] = []
    threat_score = 0.0

    # 1. Inspect sender
    sender_flags = check_sender_spoofing(sender_name, sender_email)
    if sender_flags:
        threat_score += 45.0
        reasons.extend(sender_flags)

    # 2. Inspect content urgency
    urgency_flags = check_body_urgency(subject, body_text)
    if urgency_flags:
        threat_score += min(len(urgency_flags) * 20.0, 40.0)
        reasons.extend(urgency_flags)

    # 3. Inspect embedded links
    link_results = []
    max_link_score = 0.0

    for link in links:
        clean_link = link.strip()
        if not clean_link or clean_link.startswith("#") or clean_link.startswith("javascript:"):
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
        threat_score = max(threat_score + 35.0, max_link_score)
        reasons.append(f"Email contains high-risk phishing URL ({max_link_score}/100)")
    elif max_link_score >= 40.0:
        threat_score += 25.0
        reasons.append(f"Email contains suspicious URL ({max_link_score}/100)")

    threat_score = round(min(max(threat_score, 0.0), 100.0), 1)

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
        "analyzed_links": link_results
    }
