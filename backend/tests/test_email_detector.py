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


def test_financial_lure_and_multi_tenant_link():
    report = detect_email_phishing(
        sender_name="Promo Bot",
        sender_email="promo@unknown-service.com",
        subject="Check this out!",
        body_text="Yo This link gives u free money check it out http://www.meridian-x.pages.dev/",
        links=["http://www.meridian-x.pages.dev/"]
    )
    assert report["threat_score"] >= 70.0
    assert report["verdict"] == "phishing"
    assert any("Financial bait" in r or "free money" in r for r in report["reasons"])
    assert any("high-risk phishing URL" in r or "pages.dev" in str(report["analyzed_links"]) for r in report["reasons"])


def test_sender_email_domain_impersonation():
    report = detect_email_phishing(
        sender_name="Customer Service",
        sender_email="billing@paypal-support.net",
        subject="Notice regarding your account",
        body_text="Please check your records.",
        links=[]
    )
    assert report["threat_score"] >= 40.0
    assert any("impersonate brand 'Paypal'" in r for r in report["reasons"])


def test_bec_payroll_fraud_lexicon():
    """Verify triggers for CEO / Payroll diversion and wire fraud."""
    bec_samples = [
        ("Urgent Request", "Please update direct deposit to my new routing number.", "update direct deposit"),
        ("Payroll update", "Need to change bank details for payroll before 5pm.", "change bank details for payroll"),
        ("Quick check", "Are you at your desk? Need urgent wire transfer.", "are you at your desk"),
        ("Confidential Transaction", "Wire instructions for acquisition attached. Keep this confidential.", "wire instructions"),
    ]
    for subj, body, expected_match in bec_samples:
        report = detect_email_phishing(
            sender_name="Executive Office",
            sender_email="ceo@executive-internal.com",
            subject=subj,
            body_text=body,
            links=[]
        )
        assert report["threat_score"] >= 40.0
        assert any("Business Email Compromise" in r or "BEC" in r for r in report["reasons"])
        assert any(expected_match.lower() in r.lower() for r in report["reasons"])


def test_zero_width_and_homoglyphs_stripping():
    """Verify that zero-width spaces and Cyrillic homoglyphs are stripped/normalized."""
    from backend.services.email_detector import strip_zero_width_and_homoglyphs

    # Evasion attempt with zero-width spaces (\u200B) inside "password"
    evasive_text = "p\u200Ba\u200Bs\u200Bs\u200Bw\u200Bo\u200Br\u200Bd"
    assert strip_zero_width_and_homoglyphs(evasive_text) == "password"

    # Evasion with Cyrillic lookalikes: а (U+0430), о (U+043E), е (U+0435)
    cyrillic_text = "ch\u0430ng\u0435 b\u0430nk d\u0435t\u0430ils f\u043Er p\u0430yr\u043Ell"  # change bank details for payroll
    assert "change bank details for payroll" in strip_zero_width_and_homoglyphs(cyrillic_text)

    # End to end: Email using zero-width spaces in BEC phrase is still caught
    report = detect_email_phishing(
        sender_name="HR Director",
        sender_email="hr@corp-portal.com",
        subject="Important",
        body_text="Please u\u200Bp\u200Bd\u200Ba\u200Bt\u200Be d\u200Bi\u200Br\u200Be\u200Bc\u200Bt d\u200Be\u200Bp\u200Bo\u200Bs\u200Bi\u200Bt immediately.",
        links=[]
    )
    assert any("Business Email Compromise" in r for r in report["reasons"])


def test_quishing_image_qr_code_detection():
    """Verify embedded QR code detection from base64 image."""
    import cv2
    import base64
    import numpy as np

    encoder = cv2.QRCodeEncoder_create()
    qr_matrix = encoder.encode("http://paypa1-account-verify.xyz/login")
    qr_img = cv2.resize(qr_matrix, (200, 200), interpolation=cv2.INTER_NEAREST)
    # Convert to 3-channel BGR
    qr_bgr = cv2.cvtColor(qr_img, cv2.COLOR_GRAY2BGR)
    _, buf = cv2.imencode(".png", qr_bgr)
    b64_qr = "data:image/png;base64," + base64.b64encode(buf).decode("utf-8")

    report = detect_email_phishing(
        sender_name="Authentication Team",
        sender_email="auth@secure-mail.com",
        subject="Scan QR code to access your portal",
        body_text="Use your phone to scan the QR code below to verify your login credentials.",
        links=[],
        image_urls=[b64_qr]
    )

    assert report["threat_score"] >= 70.0
    assert report["verdict"] == "phishing"
    assert any("Quishing" in r or "QR" in r for r in report["reasons"])
    assert len(report.get("quishing_findings", [])) > 0


def test_email_dual_engine_scoring_breakdown():
    """Verify transparent dual-engine ML + Heuristic scoring breakdown."""
    report = detect_email_phishing(
        sender_name="PayPal Security",
        sender_email="support@paypa1-update.com",
        subject="Immediate action required: Confirm your password",
        body_text="Your account suspended within 24 hours. Wire transfer instructions enclosed.",
        links=["http://paypa1-update.com/login"]
    )
    assert "scoring_breakdown" in report
    breakdown = report["scoring_breakdown"]
    assert breakdown["engine"] == "dual_ml_heuristic"
    assert "ml_score" in breakdown
    assert "heuristic_score" in breakdown
    assert "weight_ml" in breakdown
    assert "weight_heuristic" in breakdown
    assert "final_threat_score" in breakdown
    assert breakdown["final_threat_score"] == report["threat_score"]


