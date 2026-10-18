import json
import sys
from pathlib import Path
from urllib.parse import urlparse

import pandas as pd
from xgboost import XGBClassifier

try:
    from .feature_extractor import extract_features
except ImportError:
    from feature_extractor import extract_features


# Resolve paths relative to the mlservices directory
BASE_DIR = Path(__file__).resolve().parents[2]
MODEL_PATH = BASE_DIR / "models" / "url_xgboost_tuned.json"
FEATURES_PATH = BASE_DIR / "models" / "url_xgboost_tuned_features.json"

# Current model decision threshold
THRESHOLD = 0.50


def load_model():
    """Load the saved model and its expected feature order."""
    if not MODEL_PATH.exists():
        raise FileNotFoundError(f"Model not found: {MODEL_PATH}")

    if not FEATURES_PATH.exists():
        raise FileNotFoundError(f"Feature list not found: {FEATURES_PATH}")

    with open(FEATURES_PATH, "r", encoding="utf-8") as file:
        feature_names = json.load(file)

    model = XGBClassifier()
    model.load_model(str(MODEL_PATH))

    if model.n_features_in_ != len(feature_names):
        raise ValueError(
            f"Model expects {model.n_features_in_} features, "
            f"but the feature list contains {len(feature_names)}."
        )

    return model, feature_names


def validate_url(url):
    """Accept HTTP(S) URLs or bare domain names; reject random text."""
    if not isinstance(url, str):
        return False

    url = url.strip()

    if not url or any(char.isspace() for char in url):
        return False

    # Reject malformed URLs with no hostname after a scheme.
    candidate = url if "://" in url else f"https://{url}"

    try:
        parsed = urlparse(candidate)
        hostname = parsed.hostname

        if parsed.scheme not in ("http", "https"):
            return False

        if not hostname or "." not in hostname:
            return False

        # Reject invalid ports such as example.com:abc
        try:
            parsed.port
        except ValueError:
            return False

        labels = hostname.rstrip(".").split(".")

        if any(
            not label
            or len(label) > 63
            or label.startswith("-")
            or label.endswith("-")
            or not all(c.isalnum() or c == "-" for c in label)
            for label in labels
        ):
            return False

        # Require a plausible domain suffix.
        if len(labels[-1]) < 2 or not labels[-1].isalnum():
            return False

        return True

    except (ValueError, UnicodeError):
        return False


def predict_url(url, model, feature_names):
    """Validate a URL and predict its phishing probability."""
    if not isinstance(url, str):
        raise ValueError("URL must be provided as text.")

    url = url.strip()

    if not validate_url(url):
        raise ValueError(
            "Invalid URL. Enter a domain or URL, "
            "such as google.com or https://google.com."
        )

    # Add HTTPS to bare domains.
    if "://" not in url:
        url = "https://" + url

    features = extract_features(url)

    missing = set(feature_names) - set(features)
    if missing:
        raise ValueError(
            f"Feature extractor is missing: {sorted(missing)}"
        )

    # Preserve the exact feature order used during training.
    input_data = pd.DataFrame(
        [[features[name] for name in feature_names]],
        columns=feature_names,
    )

    phishing_probability = float(
        model.predict_proba(input_data)[0][1]
    )

    is_phishing = phishing_probability >= THRESHOLD

    return {
        "url": url,
        "prediction": "PHISHING" if is_phishing else "LEGITIMATE",
        "phishing_probability": round(
            phishing_probability * 100, 2
        ),
        "threshold": THRESHOLD,
        "risk_level": (
            "HIGH"
            if is_phishing
            else "LOWER MODEL-ESTIMATED RISK"
        ),
    }


def main():
    try:
        model, feature_names = load_model()

        if len(sys.argv) > 1:
            url = " ".join(sys.argv[1:])
        else:
            url = input("Enter URL to check: ")

        result = predict_url(url, model, feature_names)

        print("\n=== PHISHING URL DETECTION ===")
        print(f"URL: {result['url']}")
        print(f"Prediction: {result['prediction']}")
        print(
            f"Phishing probability: "
            f"{result['phishing_probability']:.2f}%"
        )
        print(f"Threshold: {result['threshold']}")
        print(f"Risk indicator: {result['risk_level']}")
        print(
            "\nNote: This is a model prediction based on URL "
            "features, not a guarantee that the website is safe "
            "or malicious."
        )

    except (FileNotFoundError, ValueError, TypeError) as error:
        print(f"Error: {error}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
