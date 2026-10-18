"""
Unit tests for v1.1 Heuristic features:
- Pure Python Levenshtein distance & typosquatting detection
- RDAP domain age checking
"""
import pytest
from backend.services.heuristics import (
    levenshtein_distance,
    check_brand_typosquatting,
    check_domain_age_risk,
    evaluate_heuristics
)


def test_levenshtein_distance_exact_and_mutations():
    assert levenshtein_distance("paypal", "paypal") == 0
    assert levenshtein_distance("paypal", "paypa1") == 1
    assert levenshtein_distance("amazon", "arnazon") == 2  # 2 edits: 'm' -> 'r','n'
    assert levenshtein_distance("apple", "appl3") == 1
    assert levenshtein_distance("google", "gooogle") == 1



def test_typosquatting_detection():
    # Subtle typo mutations
    is_squat, brand = check_brand_typosquatting("paypa1.com")
    assert is_squat is True
    assert brand == "paypal"

    is_squat, brand = check_brand_typosquatting("arnazon.shop")
    assert is_squat is True
    assert brand == "amazon"

    is_squat, brand = check_brand_typosquatting("g00gle-security.com")
    assert is_squat is True
    assert brand == "google"

    # Legitimate domains should not trigger typosquatting
    is_squat, brand = check_brand_typosquatting("paypal.com")
    assert is_squat is False

    is_squat, brand = check_brand_typosquatting("api.paypal.com")
    assert is_squat is False


def test_domain_age_risk_evaluation(monkeypatch):
    # Mock RDAP response with fresh domain (< 30 days old)
    def mock_fetch_domain_created(domain):
        return 12  # 12 days old

    monkeypatch.setattr(
        "backend.services.heuristics.get_domain_age_days",
        mock_fetch_domain_created
    )

    is_fresh, days, flag = check_domain_age_risk("brand-new-scam-site.xyz")
    assert is_fresh is True
    assert days == 12
    assert "Newly registered domain" in flag


def test_evaluate_heuristics_incorporates_v11_signals(monkeypatch):
    def mock_fetch_domain_created(domain):
        return 5

    monkeypatch.setattr(
        "backend.services.heuristics.get_domain_age_days",
        mock_fetch_domain_created
    )

    result = evaluate_heuristics("http://paypa1-update.xyz/login")
    assert result["penalty_score"] >= 70.0
    reasons_text = " ".join(result["flags"])
    assert "impersonates known brand" in reasons_text.lower() or "typosquatting" in reasons_text.lower()


def test_dynamic_top_domains_loader():
    from backend.services.heuristics import load_trusted_domains, evaluate_heuristics
    trusted = load_trusted_domains()
    assert len(trusted) >= 1000
    assert "google.com" in trusted
    assert "zoom.us" in trusted
    assert "notion.so" in trusted

    # Test root domain coverage: deep subdomain of a top domain is recognized as trusted
    res = evaluate_heuristics("https://deep.nested.subdomain.zoom.us/webinar")
    assert res["is_trusted_domain"] is True
    assert res["penalty_score"] == 0.0

