import sys
from pathlib import Path
import pytest

URL_DIR = Path(__file__).resolve().parent
if str(URL_DIR) not in sys.path:
    sys.path.insert(0, str(URL_DIR))

try:
    from feature_extractor import extract_features
except ImportError:
    from mlservices.src.url.feature_extractor import extract_features


def test_extract_features_structure():
    test_urls = [
        "https://google.com",
        "https://login-secure-account.com/verify",
        "http://192.168.1.1/login"
    ]
    for url in test_urls:
        features = extract_features(url)
        assert isinstance(features, dict)
        assert "url_length" in features
        assert "num_dots" in features
        assert "suspicious_keyword_count" in features

    ip_features = extract_features("http://192.168.1.1/login")
    assert ip_features["has_ip"] == 1
    assert ip_features["has_login"] == 1