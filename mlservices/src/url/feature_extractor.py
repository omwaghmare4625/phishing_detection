import re
from urllib.parse import urlparse


# Suspicious keywords commonly associated with phishing URLs
SUSPICIOUS_KEYWORDS = [
    "login",
    "signin",
    "verify",
    "verification",
    "account",
    "update",
    "secure",
    "security",
    "confirm",
    "password",
    "bank",
    "paypal",
    "wallet",
    "payment",
    "recover",
    "authenticate"
]


def extract_features(url):
    """
    Extract numerical features from a URL.
    """

    raw_url = url.strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", raw_url):
        parse_target = "http://" + raw_url
    else:
        parse_target = raw_url

    parsed = urlparse(parse_target)

    hostname = parsed.hostname or ""
    path = parsed.path or ""
    query = parsed.query or ""

    # -----------------------------------
    # Basic URL features
    # -----------------------------------

    url_length = len(url)
    hostname_length = len(hostname)
    path_length = len(path)
    query_length = len(query)

    # -----------------------------------
    # Character-based features
    # -----------------------------------

    num_dots = url.count(".")
    num_hyphens = url.count("-")
    num_underscores = url.count("_")
    num_slashes = url.count("/")
    num_question_marks = url.count("?")
    num_equals = url.count("=")
    num_ampersands = url.count("&")

    num_digits = sum(c.isdigit() for c in url)

    num_special_chars = sum(
        not c.isalnum() for c in url
    )

    # -----------------------------------
    # Suspicious character features
    # -----------------------------------

    has_at = int("@" in url)

    has_double_slash = int("//" in path)

    # -----------------------------------
    # HTTPS
    # -----------------------------------

    has_https = int(raw_url.lower().startswith("https://"))

    # -----------------------------------
    # IP address detection
    # -----------------------------------

    ip_pattern = r"^(?:\d{1,3}\.){3}\d{1,3}$"

    has_ip = int(
        bool(re.match(ip_pattern, hostname))
    )

    # -----------------------------------
    # Subdomain count
    # -----------------------------------

    if has_ip:
        num_subdomains = 0
    else:
        hostname_parts = hostname.split(".")

        if len(hostname_parts) > 2:
            num_subdomains = len(hostname_parts) - 2
        else:
            num_subdomains = 0

    # -----------------------------------
    # Suspicious keyword features
    # -----------------------------------

    url_lower = url.lower()

    suspicious_keyword_count = sum(
        keyword in url_lower
        for keyword in SUSPICIOUS_KEYWORDS
    )

    # -----------------------------------
    # Specific keyword indicators
    # -----------------------------------

    has_login = int(
        "login" in url_lower or
        "signin" in url_lower
    )

    has_verify = int(
        "verify" in url_lower or
        "verification" in url_lower
    )

    has_account = int(
        "account" in url_lower
    )

    has_password = int(
        "password" in url_lower
    )

    # -----------------------------------
    # Feature dictionary
    # -----------------------------------

    features = {
        "url_length": url_length,
        "hostname_length": hostname_length,
        "path_length": path_length,
        "query_length": query_length,

        "num_dots": num_dots,
        "num_hyphens": num_hyphens,
        "num_underscores": num_underscores,
        "num_slashes": num_slashes,
        "num_question_marks": num_question_marks,
        "num_equals": num_equals,
        "num_ampersands": num_ampersands,

        "num_digits": num_digits,
        "num_special_chars": num_special_chars,

        "has_at": has_at,
        "has_double_slash": has_double_slash,
        "has_https": has_https,
        "has_ip": has_ip,

        "num_subdomains": num_subdomains,

        "suspicious_keyword_count": suspicious_keyword_count,

        "has_login": has_login,
        "has_verify": has_verify,
        "has_account": has_account,
        "has_password": has_password
    }

    return features