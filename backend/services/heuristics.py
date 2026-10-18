from __future__ import annotations

import re
from functools import lru_cache
from pathlib import Path
from urllib.parse import urlparse
try:
    import tldextract  # type: ignore
    _TLD_EXTRACTOR = tldextract.TLDExtract(cache_dir=None)
except Exception:
    _TLD_EXTRACTOR = None


@lru_cache(maxsize=2048)
def get_registered_domain(domain: str) -> str:
    """Extract registered domain (e.g. sub.bank.co.uk -> bank.co.uk)."""
    if _TLD_EXTRACTOR is not None:
        try:
            ext = _TLD_EXTRACTOR(domain.lower())
            domain_suffix = getattr(ext, "top_domain_under_public_suffix", "")
            if not domain_suffix and ext.suffix:
                domain_suffix = f"{ext.domain}.{ext.suffix}"
            if domain_suffix:
                return domain_suffix
        except Exception:
            pass

    # Fallback if tldextract unavailable
    parts = domain.lower().split(".")
    if len(parts) >= 2:
        return f"{parts[-2]}.{parts[-1]}"
    return domain.lower()

HIGH_RISK_TLDS = {
    "xyz", "top", "tk", "ml", "ga", "cf", "gq",
    "buzz", "cam", "fit", "work", "click", "loan", "zip", "mov"
}

TOP_DOMAINS_FILE = Path(__file__).resolve().parent.parent / "data" / "top_domains.txt"

_FALLBACK_TOP_DOMAINS = frozenset({
    "google.com", "gmail.com", "googleusercontent.com", "gstatic.com", "youtube.com",
    "github.com", "github.io", "githubusercontent.com", "githubassets.com",
    "microsoft.com", "office.com", "live.com", "azure.com", "outlook.com", "bing.com",
    "apple.com", "icloud.com", "amazon.com", "aws.amazon.com", "media-amazon.com", "amzn.to",
    "wikipedia.org", "wikimedia.org", "twitter.com", "x.com", "linkedin.com", "facebook.com",
    "instagram.com", "netflix.com", "cloudflare.com", "mozilla.org", "reddit.com", "stackoverflow.com",
    "paypal.com", "chase.com", "bankofamerica.com", "wellsfargo.com", "yahoo.com",
    "zoom.us", "zoomgov.com", "notion.so", "notion.site", "canva.com", "slack.com",
    "dropbox.com", "figma.com", "atlassian.com", "atlassian.net", "spotify.com", "medium.com",
    "adobe.com", "salesforce.com", "whatsapp.com", "telegram.org", "discord.com"
})


@lru_cache(maxsize=1)
def load_trusted_domains() -> frozenset[str]:
    """Load high-reputation domains from Tranco top domains dataset with in-memory caching."""
    if TOP_DOMAINS_FILE.exists():
        try:
            with open(TOP_DOMAINS_FILE, "r", encoding="utf-8") as f:
                domains = {line.strip().lower() for line in f if line.strip() and not line.startswith("#")}
            if len(domains) > 100:
                return frozenset(domains)
        except Exception:
            pass
    return _FALLBACK_TOP_DOMAINS


# Retained for backward compatibility
TRUSTED_TOP_DOMAINS = load_trusted_domains()


AUTHENTIC_BRAND_DOMAINS = {
    "google": {"google.com", "gmail.com", "googlemail.com", "googleusercontent.com", "gstatic.com", "youtube.com", "1e100.net"},
    "github": {"github.com", "github.io", "githubusercontent.com", "githubassets.com"},
    "microsoft": {"microsoft.com", "office.com", "live.com", "azure.com", "outlook.com", "windows.net", "bing.com", "microsoftonline.com"},
    "apple": {"apple.com", "icloud.com", "mzstatic.com"},
    "amazon": {"amazon.com", "media-amazon.com", "amzn.to", "aws.amazon.com"},
    "netflix": {"netflix.com", "nflxext.com", "nflxvideo.net"},
    "facebook": {"facebook.com", "fb.com", "fbcdn.net"},
    "instagram": {"instagram.com", "cdninstagram.com"},
    "paypal": {"paypal.com", "paypal-communication.com"},
    "chase": {"chase.com"},
    "wellsfargo": {"wellsfargo.com"},
    "bankofamerica": {"bankofamerica.com", "bofa.com"},
    "binance": {"binance.com"},
    "coinbase": {"coinbase.com"},
    "metamask": {"metamask.io"},
    "steam": {"steampowered.com", "steamcommunity.com", "steamstatic.com"},
    "twitter": {"twitter.com", "x.com", "twimg.com", "t.co"},
    "yahoo": {"yahoo.com", "yimg.com"},
    "outlook": {"outlook.com", "office.com", "live.com", "microsoft.com"},
    "dropbox": {"dropbox.com", "dropboxstatic.com"}
}

POPULAR_BRANDS = [
    "google", "microsoft", "apple", "amazon", "netflix",
    "facebook", "instagram", "paypal", "chase", "wellsfargo",
    "bankofamerica", "binance", "coinbase", "metamask", "steam",
    "twitter", "yahoo", "outlook", "dropbox", "github"
]

SUSPICIOUS_LEET_SUBS = {
    "0": "o",
    "1": "l",
    "3": "e",
    "4": "a",
    "5": "s",
    "7": "t",
    "@": "a",
    "vv": "w"
}




def levenshtein_distance(s1: str, s2: str) -> int:
    """Compute classic Levenshtein edit distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)

    previous_row = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]


def normalize_target_url(raw_url: str) -> str:
    """Normalize schemeless or stripped URLs."""
    url = raw_url.strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        return "http://" + url
    return url


def check_homograph_and_punycode(hostname: str) -> bool:
    """Check if domain uses Punycode / IDN encoding."""
    return "xn--" in hostname.lower()


def check_ip_hostname(hostname: str) -> bool:
    """Check if hostname is raw IP address."""
    ip_pattern = r"^(?:\d{1,3}\.){3}\d{1,3}$"
    return bool(re.match(ip_pattern, hostname))


def check_brand_typosquatting(hostname: str) -> tuple[bool, str | None]:
    """Detect visual leetspeak, character mutations, and Levenshtein typosquatting."""
    cleaned = hostname.lower()

    # 1. Check if it's an authentic domain for any known brand
    for brand, auth_domains in AUTHENTIC_BRAND_DOMAINS.items():
        for auth in auth_domains:
            if cleaned == auth or cleaned.endswith("." + auth):
                return False, None

    # Check common TLDs for brand
    for brand in POPULAR_BRANDS:
        if (
            cleaned == f"{brand}.com" or
            cleaned.endswith(f".{brand}.com") or
            cleaned == f"{brand}.org" or
            cleaned.endswith(f".{brand}.org") or
            cleaned == f"{brand}.net" or
            cleaned.endswith(f".{brand}.net")
        ):
            return False, None

    # 2. Leetspeak substitution & Levenshtein edit distance check on sub-tokens
    sub_tokens = re.split(r"[-_.]", cleaned)
    for token in sub_tokens:
        if len(token) < 4:
            continue

        normalized_token = token
        for leet, char in SUSPICIOUS_LEET_SUBS.items():
            normalized_token = normalized_token.replace(leet, char)

        for brand in POPULAR_BRANDS:
            # If token transformed into brand via leetspeak (e.g. paypa1 -> paypal, g00gle -> google)
            if normalized_token == brand and token != brand:
                return True, brand

            # Collapsed visual homoglyphs (e.g. rn -> m, vv -> w)
            collapsed_token = token.replace("rn", "m").replace("vv", "w")
            if collapsed_token == brand and token != brand:
                return True, brand

            dist = min(
                levenshtein_distance(token, brand),
                levenshtein_distance(collapsed_token, brand)
            )
            # Distance 1 mutation (or distance 2 for long brands >= 6 chars)
            threshold = 2 if len(brand) >= 6 and abs(len(token) - len(brand)) <= 1 else 1
            if 0 < dist <= threshold:
                return True, brand

    return False, None



@lru_cache(maxsize=2048)
def get_domain_age_days(domain: str) -> int | None:
    """Fetch domain registration age in days via public RDAP service (LRU cached)."""
    root_domain = get_registered_domain(domain)

    if check_ip_hostname(root_domain) or root_domain in {"localhost", "127.0.0.1"}:
        return None

    try:
        import urllib.request
        import json
        from datetime import datetime, timezone

        req = urllib.request.Request(
            f"https://rdap.org/domain/{root_domain}",
            headers={"User-Agent": "PhishGuard-Validator/1.1", "Accept": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=1.2) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            events = data.get("events", [])
            reg_date = None
            for event in events:
                if event.get("eventAction") in ("registration", "created"):
                    reg_date = event.get("eventDate")
                    break
            if reg_date:
                clean_date = reg_date.replace("Z", "+00:00")
                created_dt = datetime.fromisoformat(clean_date)
                now_dt = datetime.now(timezone.utc)
                age_days = max(0, (now_dt - created_dt).days)
                return age_days
    except Exception:
        pass

    return None


def check_domain_age_risk(hostname: str) -> tuple[bool, int | None, str | None]:
    """Check if domain is freshly registered (< 30 days old)."""
    age_days = get_domain_age_days(hostname)
    if age_days is not None and age_days < 30:
        return True, age_days, f"Newly registered domain ({age_days} days old, high phishing risk)"
    return False, age_days, None


def evaluate_heuristics(url: str) -> dict[str, any]:
    """
    Evaluate structural, lexical, and heuristic risk signals on a URL.
    Returns penalty score and list of triggered flags.
    """
    normalized_url = normalize_target_url(url)
    parsed = urlparse(normalized_url)
    hostname = (parsed.hostname or "").lower()
    path = parsed.path or ""

    flags: list[str] = []
    penalty_score = 0.0

    # 1. IP address hostname
    if check_ip_hostname(hostname):
        flags.append("Host is a raw IP address instead of domain name")
        penalty_score += 45.0

    # 2. Punycode / IDN homograph attack
    if check_homograph_and_punycode(hostname):
        flags.append("Domain uses Punycode (IDN homograph attack indicator)")
        penalty_score += 40.0

    # 3. Brand typosquatting / spoofing & Levenshtein mutation
    is_squatting, brand = check_brand_typosquatting(hostname)
    if is_squatting and brand:
        flags.append(f"Domain impersonates known brand via typosquatting: '{brand}'")
        penalty_score += 50.0

    # 4. Domain age check via RDAP
    is_fresh, days, age_flag = check_domain_age_risk(hostname)
    if is_fresh and age_flag:
        flags.append(age_flag)
        penalty_score += 35.0

    # 5. High-risk TLD
    tld = hostname.split(".")[-1] if "." in hostname else ""
    if tld in HIGH_RISK_TLDS:
        flags.append(f"Suspicious top-level domain: '.{tld}'")
        penalty_score += 25.0

    # 6. Excessive subdomains
    parts = hostname.split(".")
    if len(parts) > 4:
        flags.append(f"Excessive subdomain depth ({len(parts) - 2} subdomains)")
        penalty_score += 20.0

    # 7. Credentials / @ sign in URL authority (credential masking e.g. http://user:pass@evil.com)
    if "@" in (parsed.netloc or ""):
        flags.append("URL contains embedded '@' symbol in authority (credential masking)")
        penalty_score += 35.0

    # 8. Double slashes in path
    if "//" in path:
        flags.append("URL path contains double slash redirect trick")
        penalty_score += 25.0

    # Cap heuristic penalty at 95
    penalty_score = min(penalty_score, 95.0)

    is_trusted = False
    if not check_homograph_and_punycode(hostname) and "@" not in (parsed.netloc or ""):
        trusted_set = load_trusted_domains()
        root_domain = get_registered_domain(hostname)
        if hostname in trusted_set or root_domain in trusted_set:
            is_trusted = True
        else:
            for fallback in _FALLBACK_TOP_DOMAINS:
                if hostname == fallback or hostname.endswith("." + fallback):
                    is_trusted = True
                    break


    if is_trusted:
        penalty_score = 0.0

    return {
        "penalty_score": penalty_score,
        "flags": flags,
        "hostname": hostname,
        "tld": tld,
        "is_trusted_domain": is_trusted
    }

