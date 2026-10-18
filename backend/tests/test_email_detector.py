"""
Unit and integration tests for Email Phishing Detector.
"""
import pytest
from backend.services.email_detector import detect_email_phishing


def test_benign_corporate_email():
    report = detect_email_phishing(
        sender_name="Google Accounts",
        sender_email="no-reply@accounts.google.com",
        subject="Security checkup completed",
        body_text="Your monthly security checkup completed normally. No action required.",
        links=["https://myaccount.google.com/security"]
    )
    assert report["threat_score"] < 40.0
    assert report["verdict"] == "safe"


def test_spoofed_brand_free_email():
    report = detect_email_phishing(
        sender_name="PayPal Support Team",
        sender_email="paypal-helpdesk12@gmail.com",
        subject="Urgent: Your account is suspended!",
        body_text="Your account has been locked due to suspicious activity. Verify your identity within 24 hours.",
        links=["http://paypa1-account-verification.xyz/login"]
    )
    assert report["threat_score"] >= 70.0
    assert report["verdict"] == "phishing"
    assert report["risk_level"] == "HIGH"
    assert any("claims brand 'Paypal'" in r or "Paypal" in r for r in report["reasons"])
    assert any("fear/coercion" in r.lower() or "action" in r.lower() for r in report["reasons"])


def test_urgent_credential_harvesting_body():
    report = detect_email_phishing(
        sender_name="IT Desk",
        sender_email="it@company.org",
        subject="Mandatory: Confirm your password",
        body_text="Click link below to update credentials or account suspended immediately.",
        links=["http://192.168.1.1/login"]
    )
    assert report["threat_score"] >= 40.0
    assert report["verdict"] in ("suspicious", "phishing")


def test_benign_email_with_attached_links():
    report = detect_email_phishing(
        sender_name="Alice Smith",
        sender_email="alice.smith@gmail.com",
        subject="Project meeting agenda & notes",
        body_text="Hi team, here is the Zoom link for our sync and the Notion notes.",
        links=[
            "https://zoom.us/j/9876543210",
            "https://notion.so/workspace/project-notes",
            "https://canva.com/design/DAF123/view"
        ]
    )
    assert report["verdict"] == "safe"
    assert report["threat_score"] < 40.0
    assert len(report["reasons"]) == 0


def test_google_service_email_not_spoofed():
    report = detect_email_phishing(
        sender_name="Google Calendar",
        sender_email="calendar-notification@google.com",
        subject="Invitation: Sprint Planning @ Mon Oct 20",
        body_text="You have been invited to Sprint Planning. See details in your calendar.",
        links=["https://calendar.google.com/calendar/event?eid=123"]
    )
    assert report["verdict"] == "safe"
    assert report["threat_score"] < 40.0


def test_email_nlp_classifier_direct():
    from backend.services.email_detector import predict_email_nlp, load_email_nlp_model
    model = load_email_nlp_model()
    assert model is not None

    # Test phishing prompt
    phish_res = predict_email_nlp(
        subject="Urgent: Verify your password immediately",
        body="Your account will be suspended within 24 hours. Click here to confirm credentials."
    )
    assert phish_res["model_loaded"] is True
    assert phish_res["phishing_probability"] >= 50.0
    assert phish_res["is_phishing_text"] is True

    # Test benign prompt
    benign_res = predict_email_nlp(
        subject="Sprint 42 retrospective follow-up",
        body="Thanks for participating in yesterday's retro. I updated the Jira board."
    )
    assert benign_res["model_loaded"] is True
    assert benign_res["phishing_probability"] < 50.0
    assert benign_res["is_phishing_text"] is False


def test_email_nlp_in_detection_report():
    report = detect_email_phishing(
        sender_name="Security Alert",
        sender_email="sec-alert@unknown-domain.xyz",
        subject="Critical Security Alert: Unauthorized login attempt detected",
        body_text="Someone attempted to log into your account. Review activity and verify your credentials now.",
        links=[]
    )
    assert "nlp_analysis" in report
    assert report["nlp_analysis"]["model_loaded"] is True
    assert report["threat_score"] >= 40.0
    assert any("NLP Classifier" in r for r in report["reasons"])


