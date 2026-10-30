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
    "paypal": ["paypal.com", "paypal-communication.com", "paypalobjects.com"],
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

HIGH_RISK_TLDS = {
    ".xyz", ".top", ".tk", ".ml", ".cf", ".gq", ".buzz", ".icu",
    ".cam", ".vip", ".work", ".rest", ".cfd", ".sbs", ".monster",
    ".fit", ".gdn", ".kim", ".fun", ".cyou", ".live"
}

MODERATE_RISK_TLDS = {
    ".site", ".online", ".club", ".space", ".website", ".info",
    ".biz", ".cc", ".to", ".pro"
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

SENSITIVE_DIRECTORIES = {
    "admin", "login", "auth", "oauth", "wp-admin", "wp-content",
    "cgi-bin", ".well-known", "secure", "banking", "verification",
    "signin", "includes", "runtime"
}

# Master List of 32 Dimensional Feature Space
FEATURE_NAMES = [
    # 1. Classical Lexical Dimensions (1-12)
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

    # 2. Network & Protocol Signals (13-16)
    "has_ip_address",
    "has_punycode",
    "has_shortener",
    "is_https",

    # 3. Statistical & Heuristic Metrics (17-22)
    "shannon_entropy",
    "suspicious_tld",
    "suspicious_keywords_count",
    "num_query_params",
    "free_hosting_provider",
    "brand_spoofing",

    # 4. Enterprise Advanced Zero-Day Dimensions (23-32)
    "min_brand_edit_dist",
    "consonant_vowel_ratio",
    "sensitive_directory_depth",
    "ip_obfuscation_type",
    "max_char_repeat_count",
    "query_entropy",
    "tld_risk_tier",
    "has_double_extension",
    "is_non_standard_port",
    "fragment_entropy"
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

def levenshtein_distance(s1: str, s2: str) -> int:
    """Computes minimal Levenshtein character edit distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)
    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]

def calculate_min_brand_edit_dist(domain: str) -> int:
    """Calculates min edit distance to target brands for typosquatting detection."""
    d = (domain or "").lower()
    labels = d.split(".")
    min_dist = 10

    for label in labels:
        if len(label) < 3 or len(label) > 16:
            continue
        for brand in TARGET_BRANDS:
            # Skip if legitimate parent domain
            if d == brand + ".com" or d.endswith("." + brand + ".com"):
                return 10
            dist = levenshtein_distance(label, brand)
            if dist < min_dist:
                min_dist = dist
    return min_dist

def calculate_consonant_vowel_ratio(domain: str) -> float:
    """Detects DGA (Domain Generation Algorithm) / random character strings."""
    vowels = set("aeiou")
    consonants = set("bcdfghjklmnpqrstvwxyz")
    v_count = sum(1 for c in domain.lower() if c in vowels)
    c_count = sum(1 for c in domain.lower() if c in consonants)
    if v_count == 0:
        return 5.0 if c_count > 0 else 1.0
    return round(min(10.0, c_count / v_count), 2)

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

def check_ip_obfuscation(domain: str) -> int:
    """Detects integer / decimal / hex IP obfuscation evasions (e.g. http://2130706433)."""
    d = (domain or "").split(":")[0]
    # Pure integer decimal IP
    if d.isdigit() and len(d) >= 8:
        return 1
    # Hex or octal notation
    if d.startswith("0x") or ".0x" in d:
        return 1
    return check_ip_address(d)

def check_brand_spoofing(url: str, domain: str) -> int:
    """Detects unauthorized brand keyword appearance across domain or path."""
    d = (domain or "").lower()
    u = (url or "").lower()

    for brand in TARGET_BRANDS:
        if brand in u:
            authorized_domains = LEGIT_BRAND_DOMAINS.get(brand, [])
            is_legit = any(d == auth or d.endswith("." + auth) for auth in authorized_domains)
            if not is_legit:
                return 1
    return 0

def check_free_hosting(domain: str) -> int:
    """Checks if site is hosted on a free/shared application hosting service."""
    d = (domain or "").lower()
    for provider in FREE_HOSTING_PATTERNS:
        if d == provider or d.endswith("." + provider):
            return 1
    return 0

def check_double_extension(path: str) -> int:
    """Detects double file extensions commonly used to mask executables/payloads."""
    p = (path or "").lower()
    double_ext_re = r"\.(html?|php|asp|jsp|pdf|doc|docx|xls|xlsx|zip)\.(php|exe|sh|bat|txt|js|html?)$"
    return 1 if re.search(double_ext_re, p) else 0

def calculate_max_char_repeat(text: str) -> int:
    """Finds maximum consecutive repeated character count in text."""
    if not text:
        return 0
    max_rep = 1
    cur_rep = 1
    for i in range(1, len(text)):
        if text[i] == text[i - 1]:
            cur_rep += 1
            if cur_rep > max_rep:
                max_rep = cur_rep
        else:
            cur_rep = 1
    return min(15, max_rep)

def calculate_tld_risk(domain: str) -> float:
    """Calculates granular risk weight from 0.0 (benign) to 1.0 (high abuse)."""
    d = (domain or "").lower()
    for tld in HIGH_RISK_TLDS:
        if d.endswith(tld):
            return 0.95
    for tld in MODERATE_RISK_TLDS:
        if d.endswith(tld):
            return 0.50
    if d.endswith(".gov") or d.endswith(".edu") or d.endswith(".mil"):
        return 0.0
    return 0.10

def extract_features_dict(url: str) -> dict:
    """Extracts 32 engineered lexical, structural, and zero-day features from a URL."""
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
    port = parsed.port
    path = parsed.path or ""
    query = parsed.query or ""
    fragment = parsed.fragment or ""

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
    suspicious_tld = 1 if any(domain.endswith(tld) for tld in HIGH_RISK_TLDS) else 0

    u_lower = u.lower()
    keywords_count = sum(1 for kw in PHISHING_KEYWORDS if kw in u_lower)

    try:
        query_params = len(parse_qs(query))
    except Exception:
        query_params = 0

    free_host = check_free_hosting(domain)
    brand_spoofed = check_brand_spoofing(u, domain)

    # Advanced 10 Enterprise Dimensions
    min_brand_dist = calculate_min_brand_edit_dist(domain)
    cv_ratio = calculate_consonant_vowel_ratio(domain)

    path_segments = [s.strip().lower() for s in path.split("/") if s.strip()]
    sensitive_depth = sum(1 for seg in path_segments if seg in SENSITIVE_DIRECTORIES)

    ip_obf = check_ip_obfuscation(domain)
    max_repeat = calculate_max_char_repeat(u)
    q_entropy = calculate_shannon_entropy(query)
    tld_risk = calculate_tld_risk(domain)
    double_ext = check_double_extension(path)

    is_non_std_port = 0
    if port and port not in (80, 443, 8000, 8001, 8080):
        is_non_std_port = 1

    frag_entropy = calculate_shannon_entropy(fragment)

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
        "min_brand_edit_dist": min_brand_dist,
        "consonant_vowel_ratio": cv_ratio,
        "sensitive_directory_depth": sensitive_depth,
        "ip_obfuscation_type": ip_obf,
        "max_char_repeat_count": max_repeat,
        "query_entropy": q_entropy,
        "tld_risk_tier": tld_risk,
        "has_double_extension": double_ext,
        "is_non_standard_port": is_non_std_port,
        "fragment_entropy": frag_entropy
    }

def extract_features_vector(url: str) -> list:
    """Returns features as an ordered 32-element list matching FEATURE_NAMES."""
    f_dict = extract_features_dict(url)
    return [f_dict[k] for k in FEATURE_NAMES]
