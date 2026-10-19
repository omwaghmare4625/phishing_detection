"""
Unit and integration tests for URL Phishing Detector.
"""
import pytest
from backend.services.url_detector import detect_url_phishing


def test_benign_url_classification():
    result = detect_url_phishing("https://google.com")
    assert result["threat_score"] < 40.0
    assert result["verdict"] == "safe"
    assert result["risk_level"] == "LOW"


def test_github_benign():
    result = detect_url_phishing("https://github.com/torvalds/linux")
    assert result["threat_score"] < 40.0
    assert result["verdict"] == "safe"


def test_ip_address_phishing_url():
    result = detect_url_phishing("http://192.168.1.1/login")
    assert result["threat_score"] >= 40.0
    assert any("IP address" in reason for reason in result["reasons"])


def test_brand_typosquatting_phishing_url():
    result = detect_url_phishing("http://paypa1-account-verification.xyz/login")
    assert result["threat_score"] >= 70.0
    assert result["verdict"] == "phishing"
    assert any("impersonates" in reason.lower() for reason in result["reasons"])


def test_punycode_homograph_detection():
    result = detect_url_phishing("https://xn--pple-43d.com/signin")
    assert result["threat_score"] >= 40.0
    assert any("Punycode" in reason for reason in result["reasons"])


def test_tuned_xgboost_model_loaded():
    from backend.services.url_detector import load_model
    model, features = load_model()
    assert model is not None
    assert len(features) == 21
    assert "suspicious_keyword_count" in features
    assert "has_https" in features


def test_shortener_unmasking_detection():
    from backend.services.url_detector import unmask_shortened_url, KNOWN_SHORTENERS
    assert "bit.ly" in KNOWN_SHORTENERS
    assert "tinyurl.com" in KNOWN_SHORTENERS

    # Test non-shortener doesn't trigger network
    url, is_short, original = unmask_shortened_url("https://google.com")
    assert not is_short
    assert url == "https://google.com"
    assert original is None


def test_benign_popular_platforms():
    for test_url in [
        "https://zoom.us/j/123456789",
        "https://notion.so/myworkspace/page-123",
        "https://canva.com/design/DAF123/view",
        "https://drive.google.com/file/d/123456/view",
        "https://raw.githubusercontent.com/user/repo/main/file.png",
        "https://medium.com/@username/my-awesome-post"
    ]:
        report = detect_url_phishing(test_url)
        assert report["verdict"] == "safe", f"Expected {test_url} to be safe, got {report['verdict']}"
        assert report["threat_score"] < 40.0


def test_unwrap_google_redirect():
    from backend.services.url_detector import unwrap_redirect_wrapper
    wrapped = "https://www.google.com/url?q=https://zoom.us/j/999&source=gmail"
    unwrapped = unwrap_redirect_wrapper(wrapped)
    assert unwrapped == "https://zoom.us/j/999"

    # Ensure phishing target inside Google wrapper is caught
    evil_wrapped = "https://www.google.com/url?q=http://paypa1-account-verification.xyz/login"
    report = detect_url_phishing(evil_wrapped)
    assert report["threat_score"] >= 70.0
    assert report["verdict"] == "phishing"


def test_bayesian_threat_scoring_engine():
    from backend.services.url_detector import calculate_bayesian_threat_score

    # Trusted domain case
    score_trusted, b_trusted = calculate_bayesian_threat_score(
        ml_prob=0.99, penalty_score=0.0, is_trusted_domain=True, has_suspicious_keywords=False
    )
    assert score_trusted == 0.0
    assert b_trusted["engine"] == "bayesian_adaptive"
    assert b_trusted["domain_trust"] == "verified_top_domain"

    # Severe typosquatting attack
    score_severe, b_severe = calculate_bayesian_threat_score(
        ml_prob=0.85, penalty_score=55.0, is_trusted_domain=False, has_suspicious_keywords=True
    )
    assert score_severe >= 75.0
    assert b_severe["weight_heuristic"] == 0.80

    # Clean unknown URL with zero heuristic flags
    score_clean, b_clean = calculate_bayesian_threat_score(
        ml_prob=0.70, penalty_score=0.0, is_trusted_domain=False, has_suspicious_keywords=False
    )
    assert score_clean <= 25.0


def test_scoring_breakdown_in_detect_url():
    report = detect_url_phishing("https://google.com")
    assert "scoring_breakdown" in report
    assert report["scoring_breakdown"]["engine"] == "bayesian_adaptive"
    assert report["scoring_breakdown"]["final_threat_score"] == 0.0


def test_multi_tenant_subdomain_phishing():
    report = detect_url_phishing("http://www.meridian-x.pages.dev/")
    assert report["threat_score"] >= 70.0
    assert report["verdict"] == "phishing"
    assert any("pages.dev" in r for r in report["reasons"])




