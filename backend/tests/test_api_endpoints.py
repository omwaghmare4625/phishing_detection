"""
Integration tests for FastAPI endpoints (/api/health, /api/check-url, /api/check-email).
"""
import pytest
from starlette.testclient import TestClient
from backend.main import app

client = TestClient(app)


def test_health_endpoint():
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "popular_brands" in data
    assert "google" in data["popular_brands"]
    assert "paypal" in data["popular_brands"]



def test_check_url_api_benign():
    response = client.post("/api/check-url", json={"url": "https://google.com"})
    assert response.status_code == 200
    data = response.json()
    assert data["verdict"] == "safe"
    assert data["threat_score"] < 40.0


def test_check_url_api_phishing():
    response = client.post(
        "/api/check-url",
        json={"url": "http://paypa1-account-verification.xyz/login"}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["verdict"] == "phishing"
    assert data["threat_score"] >= 70.0


def test_check_email_api():
    payload = {
        "sender_name": "PayPal Support",
        "sender_email": "security-alert@gmail.com",
        "subject": "Urgent: Account locked",
        "body_text": "Immediate action required: verify your password now.",
        "links": ["http://paypa1-account-verification.xyz/login"]
    }
    response = client.post("/api/check-email", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["verdict"] == "phishing"
    assert data["threat_score"] >= 70.0
    assert len(data["reasons"]) > 0


def test_check_urls_batch_api():
    payload = {
        "urls": [
            "https://google.com",
            "http://paypa1-account-verification.xyz/login",
            "https://github.com"
        ]
    }
    response = client.post("/api/check-urls", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 3
    assert data["phishing_count"] >= 1
    assert len(data["results"]) == 3
    assert data["results"][0]["verdict"] == "safe"
    assert data["results"][1]["verdict"] == "phishing"

