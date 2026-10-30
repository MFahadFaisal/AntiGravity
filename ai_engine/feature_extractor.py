import math
import re
from urllib.parse import urlparse, parse_qs
from collections import Counter

# High-profile brands frequently targeted by phishing campaigns
TARGET_BRANDS = [
    "paypal", "google", "apple", "netflix", "amazon", "microsoft",
    "chase", "meta", "instagram", "facebook", "whatsapp", "binance",
    "coinbase", "metamask", "wellsfargo", "bankofamerica", "steam",
    "allegro", "outlook", "yahoo", "icloud", "dropbox", "spotify",
    "twitter", "x.com", "linkedin", "tiktok", "adobe", "telegram"
]

# Legitimate parent domains for the above brands
LEGIT_BRAND_DOMAINS = {
    "paypal": ["paypal.com", "paypal-communication.com"],
    "google": ["google.com", "google.co.uk", "google.de", "google.fr", "google.com.tr", "gstatic.com", "googleapis.com"],
    "apple": ["apple.com", "icloud.com"],
    "netflix": ["netflix.com"],
    "amazon": ["amazon.com", "amazon.co.uk", "amazon.de", "amazon.com.tr", "aws.amazon.com"],
    "microsoft": ["microsoft.com", "live.com", "office.com", "outlook.com", "office365.com", "azure.com"],
    "chase": ["chase.com"],
    "meta": ["meta.com", "facebook.com", "instagram.com", "whatsapp.com"],
    "instagram": ["instagram.com"],
    "facebook": ["facebook.com", "fb.com"],
    "whatsapp": ["whatsapp.com"],
    "binance": ["binance.com"],
    "coinbase": ["coinbase.com"],
    "metamask": ["metamask.io"],
    "wellsfargo": ["wellsfargo.com"],
    "bankofamerica": ["bankofamerica.com", "bofa.com"],
    "steam": ["steampowered.com", "steamcommunity.com"],
    "allegro": ["allegro.pl", "allegrolokalnie.pl"],
    "outlook": ["outlook.com", "live.com", "office.com"],
    "yahoo": ["yahoo.com"],
    "icloud": ["icloud.com"],
    "dropbox": ["dropbox.com"],
    "spotify": ["spotify.com"],
    "twitter": ["twitter.com", "x.com"],
    "linkedin": ["linkedin.com"],
    "tiktok": ["tiktok.com"],
    "adobe": ["adobe.com"],
    "telegram": ["telegram.org", "t.me"]
}

SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".tk", ".ml", ".cf", ".gq", ".site", ".online",
    ".club", ".buzz", ".icu", ".cam", ".vip", ".work", ".rest",
    ".cfd", ".sbs", ".monster", ".fit", ".gdn", ".kim", ".fun",
    ".space", ".website", ".cyou", ".live"
}

KNOWN_SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "is.gd", "cutt.ly",
    "ow.ly", "rebrand.ly", "buff.ly", "bl.ink", "tiny.cc", "t.ly"
}

FREE_HOSTING_PATTERNS = [
    "web.app", "firebaseapp.com", "pages.dev", "vercel.app", "netlify.app",
    "ngrok-free.app", "ngrok.io", "github.io", "glitch.me", "herokuapp.com",
    "000webhostapp.com", "wixsite.com", "weebly.com", "surge.sh", "render.com",
    "fly.dev", "railway.app", "onrender.com"
]

PHISHING_KEYWORDS = [
    "login", "verify", "account", "banking", "secure", "update", "signin",
    "wallet", "support", "confirm", "auth", "password", "service",
    "security", "portal", "admin", "recover", "validation", "authenticate",
    "billing", "invoice", "suspended", "unusual", "activity", "kyc"
]

FEATURE_NAMES = [
    "url_length",
    "domain_length",
    "path_length",
    "num_digits",
    "num_letters",
    "digit_ratio",
    "num_subdomains",
    "num_hyphens",
    "num_dots",
    "num_underscores",
    "num_slashes",
    "num_special_chars",
    "has_ip_address",
    "has_punycode",
    "has_shortener",
    "is_https",
    "shannon_entropy",
    "suspicious_tld",
    "suspicious_keywords_count",
    "num_query_params",
    "free_hosting_provider",
    "brand_spoofing"
]

def calculate_shannon_entropy(text: str) -> float:
    """Computes Shannon entropy of character frequencies."""
    if not text:
        return 0.0
    length = len(text)
    counts = Counter(text)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 4)

def check_punycode(domain: str) -> int:
    """Returns 1 if internationalized domain spoofing (Punycode xn--) is detected."""
    d = (domain or "").lower()
    return 1 if "xn--" in d else 0

def check_ip_address(domain: str) -> int:
    """Detects raw IPv4 or IPv6 address in hostname."""
    d = (domain or "").split(":")[0]
    ipv4_pattern = r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    if re.match(ipv4_pattern, d):
        return 1
    if ":" in d and not d.startswith("http"):
        return 1
    return 0

def check_brand_spoofing(url: str, domain: str) -> int:
    """
    Detects if a high-profile brand is mentioned in the subdomain or path,
    while the actual host domain is NOT that brand's legitimate domain.
    """
    d = (domain or "").lower()
    u = (url or "").lower()

    for brand in TARGET_BRANDS:
        if brand in u:
            # Check if current domain is an authorized domain for this brand
            authorized_domains = LEGIT_BRAND_DOMAINS.get(brand, [])
            is_legit = any(d == auth or d.endswith("." + auth) for auth in authorized_domains)
            if not is_legit:
                # Brand is present in URL or subdomain on an unauthorized domain!
                return 1
    return 0

def check_free_hosting(domain: str) -> int:
    """Checks if site is hosted on a free/shared application hosting service."""
    d = (domain or "").lower()
    for provider in FREE_HOSTING_PATTERNS:
        if d == provider or d.endswith("." + provider):
            return 1
    return 0

def extract_features_dict(url: str) -> dict:
    """Extracts 22 engineered lexical and structural features from a URL."""
    u = (url or "").strip()
    if not u:
        return {name: 0 for name in FEATURE_NAMES}

    if "://" not in u:
        u_parsed_prep = "http://" + u
    else:
        u_parsed_prep = u

    try:
        parsed = urlparse(u_parsed_prep)
    except Exception:
        parsed = urlparse("")

    domain = (parsed.netloc or "").split("@")[-1].split(":")[0].lower()
    path = parsed.path or ""
    query = parsed.query or ""

    url_length = len(u)
    domain_length = len(domain)
    path_length = len(path)

    num_digits = sum(c.isdigit() for c in u)
    num_letters = sum(c.isalpha() for c in u)
    digit_ratio = round(num_digits / max(1, url_length), 4)

    dot_count = domain.count(".")
    num_subdomains = max(0, dot_count - 1) if not check_ip_address(domain) else 0

    num_hyphens = u.count("-")
    num_dots = u.count(".")
    num_underscores = u.count("_")
    num_slashes = u.count("/")
    num_special_chars = sum(u.count(c) for c in "@?=&%+~!;$,*")

    has_ip = check_ip_address(domain)
    has_punycode = check_punycode(domain)
    has_shortener = 1 if any(short in domain for short in KNOWN_SHORTENERS) else 0
    is_https = 1 if u.lower().startswith("https://") else 0

    entropy = calculate_shannon_entropy(u)

    suspicious_tld = 1 if any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS) else 0

    u_lower = u.lower()
    keywords_count = sum(1 for kw in PHISHING_KEYWORDS if kw in u_lower)

    try:
        query_params = len(parse_qs(query))
    except Exception:
        query_params = 0

    free_host = check_free_hosting(domain)
    brand_spoofed = check_brand_spoofing(u, domain)

    return {
        "url_length": url_length,
        "domain_length": domain_length,
        "path_length": path_length,
        "num_digits": num_digits,
        "num_letters": num_letters,
        "digit_ratio": digit_ratio,
        "num_subdomains": num_subdomains,
        "num_hyphens": num_hyphens,
        "num_dots": num_dots,
        "num_underscores": num_underscores,
        "num_slashes": num_slashes,
        "num_special_chars": num_special_chars,
        "has_ip_address": has_ip,
        "has_punycode": has_punycode,
        "has_shortener": has_shortener,
        "is_https": is_https,
        "shannon_entropy": entropy,
        "suspicious_tld": suspicious_tld,
        "suspicious_keywords_count": keywords_count,
        "num_query_params": query_params,
        "free_hosting_provider": free_host,
        "brand_spoofing": brand_spoofed,
    }

def extract_features_vector(url: str) -> list:
    """Returns features as an ordered list matching FEATURE_NAMES."""
    f_dict = extract_features_dict(url)
    return [f_dict[k] for k in FEATURE_NAMES]
