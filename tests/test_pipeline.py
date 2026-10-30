import sys
import os
import pytest
from PIL import Image
from fastapi.testclient import TestClient

# Ensure ai_engine is in sys.path
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
AI_ENGINE_DIR = os.path.join(ROOT_DIR, "ai_engine")
if AI_ENGINE_DIR not in sys.path:
    sys.path.insert(0, AI_ENGINE_DIR)

from feature_extractor import (
    extract_features_vector,
    extract_features_dict,
    check_punycode,
    check_brand_spoofing,
    check_free_hosting,
    FEATURE_NAMES
)
from visual_detector import compute_dhash, hamming_distance, check_visual_spoofing, AUTHORIZED_BRAND_DOMAINS
from threat_feed_manager import normalize_domain, is_known_threat, get_feed_statistics, THREAT_DOMAINS_SET, THREAT_CACHE
from siem_exporter import format_cef_event, format_rfc5424_syslog
from takedown_generator import generate_takedown_notice, defang_url
from main import app, DB_FILE

client = TestClient(app)

# ----------------------------------------------------------------------
# 1. FEATURE EXTRACTOR TESTS
# ----------------------------------------------------------------------
def test_feature_vector_dimension():
    """Verify feature extractor outputs exactly 32 named features."""
    url = "https://secure.bank-update.xyz/login.php?session=928374"
    vec = extract_features_vector(url)
    assert len(vec) == 32, f"Expected 32 features, got {len(vec)}"
    assert len(FEATURE_NAMES) == 32

def test_feature_dictionary_keys():
    """Verify feature dictionary keys and reasonable values."""
    url = "http://192.168.1.1/admin"
    fdict = extract_features_dict(url)
    assert "url_length" in fdict
    assert "has_ip_address" in fdict
    assert fdict["has_ip_address"] == 1
    assert fdict["is_https"] == 0

def test_punycode_homograph_detection():
    """Verify detection of internationalized homograph attack domains."""
    legit = "apple.com"
    spoofed = "xn--pple-43d.com"
    assert bool(check_punycode(legit)) is False
    assert bool(check_punycode(spoofed)) is True

def test_brand_spoofing_detection():
    """Verify spoofed brands on unauthorized domains are flagged."""
    spoofed_url = "https://paypal-security-verification.xyz/restore"
    spoofed_domain = "paypal-security-verification.xyz"
    assert bool(check_brand_spoofing(spoofed_url, spoofed_domain)) is True

    legit_url = "https://www.paypal.com/signin"
    legit_domain = "paypal.com"
    assert bool(check_brand_spoofing(legit_url, legit_domain)) is False

def test_free_hosting_detection():
    """Verify cloud/free hosting platforms used for phishing forms are identified."""
    assert bool(check_free_hosting("login-portal.pages.dev")) is True
    assert bool(check_free_hosting("verify-bank.firebaseapp.com")) is True
    assert bool(check_free_hosting("corporate-secure.bank.com")) is False

# ----------------------------------------------------------------------
# 2. VISUAL PERCEPTUAL HASHING TESTS
# ----------------------------------------------------------------------
def test_dhash_computation():
    """Verify dHash generates deterministic 16-hex char perceptual signatures."""
    img = Image.new("RGB", (32, 32), color="blue")
    h = compute_dhash(img)
    assert len(h) == 16
    assert isinstance(h, str)

def test_hamming_distance_exact_and_different():
    """Verify hamming distance calculation for identical vs inverted hashes."""
    h1 = "ffff0000ffff0000"
    h2 = "ffff0000ffff0000"
    assert hamming_distance(h1, h2) == 0

    h_inv = "0000ffff0000ffff"
    assert hamming_distance(h1, h_inv) == 64

def test_visual_spoofing_whitelist_bypass():
    """Verify that legitimate brand domains are never flagged by visual detector."""
    res = check_visual_spoofing("https://www.paypal.com/favicon.ico", "paypal.com")
    assert res.get("is_visual_spoof") is False
    assert res.get("is_authorized") is True

def test_expanded_brand_coverage():
    """Verify expanded brand catalog contains >= 30 global brands."""
    assert len(AUTHORIZED_BRAND_DOMAINS) >= 30
    assert "chase" in AUTHORIZED_BRAND_DOMAINS
    assert "binance" in AUTHORIZED_BRAND_DOMAINS
    assert "steam" in AUTHORIZED_BRAND_DOMAINS
    assert "dhl" in AUTHORIZED_BRAND_DOMAINS

# ----------------------------------------------------------------------
# 3. THREAT FEED & INTEL TESTS
# ----------------------------------------------------------------------
def test_threat_feed_normalization():
    """Verify URL and domain normalization for threat intel ingestion."""
    assert normalize_domain("https://www.Evil-Phish.xyz/login?id=1") == "evil-phish.xyz"
    assert normalize_domain("http://sub.domain.corp.com/") == "sub.domain.corp.com"

def test_threat_intel_in_memory_lookup():
    """Verify O(1) in-memory lookup detects added threat domains."""
    test_dom = "test-simulated-malware-feed.xyz"
    THREAT_DOMAINS_SET.add(test_dom)
    THREAT_CACHE[test_dom] = "URLhaus Mock"

    res = is_known_threat(test_dom)
    assert res["is_threat"] is True
    assert "URLhaus" in res["source"]

    # Clean up
    THREAT_DOMAINS_SET.discard(test_dom)
    THREAT_CACHE.pop(test_dom, None)

# ----------------------------------------------------------------------
# 4. SIEM & TAKEDOWN TESTS
# ----------------------------------------------------------------------
def test_cef_format_generation():
    """Verify standard ArcSight CEF:0 header and extension syntax."""
    entry = {
        "action": "BLOCK",
        "url_score": 99,
        "detector": "T1566.002",
        "reason": "Brand Impersonation Phishing",
        "url": "http://evil-brand-spoof.com/auth",
        "domain": "evil-brand-spoof.com",
        "timestamp": "2026-10-30 16:00:00"
    }
    cef = format_cef_event(entry)
    assert cef.startswith("CEF:0|AntiGravity|Zero-Trust SOC Engine|2.1.0|")
    assert "act=BLOCK" in cef
    assert "dst=evil-brand-spoof.com" in cef
    assert "cn1=99" in cef

def test_rfc5424_syslog_generation():
    """Verify RFC 5424 syslog envelope wrapping CEF message."""
    entry = {
        "action": "BLOCK",
        "url_score": 95,
        "domain": "test-phish.xyz",
        "reason": "Test Alert"
    }
    syslog = format_rfc5424_syslog(entry)
    assert syslog.startswith("<33>1")
    assert "antigravity-soc" in syslog
    assert "CEF:0" in syslog

def test_takedown_notice_content():
    """Verify automated abuse complaint and defanged formatting."""
    entry = {
        "id": 42,
        "url": "http://malicious-login-portal.top/signin.php",
        "domain": "malicious-login-portal.top",
        "detector": "T1056: Input Capture",
        "url_score": 100,
        "reason": "Credential Harvesting",
        "timestamp": "2026-10-30 16:00:00"
    }
    notice = generate_takedown_notice(entry)
    assert "target_domain" in notice
    assert "malicious-login-portal[.]top" in notice["target_domain"]
    assert "hxxp://" in notice["defanged_url"]
    assert len(notice["evidence_sha256"]) == 64
    assert "ICANN" in notice["plain_text"]

# ----------------------------------------------------------------------
# 5. SOC REST API ENDPOINTS INTEGRATION TESTS
# ----------------------------------------------------------------------
def test_health_endpoint():
    """Verify /health endpoint returns 200 and healthy status."""
    res = client.get("/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "healthy"
    assert "version" in data

def test_stats_endpoint():
    """Verify /api/stats endpoint returns valid integer metrics."""
    res = client.get("/api/stats")
    assert res.status_code == 200
    data = res.json()
    assert "total" in data
    assert "safe" in data
    assert "blocked" in data
    assert data["total"] >= 0

def test_analyze_legitimate_url():
    """Verify known safe infrastructure URL is permitted."""
    payload = {
        "url": "https://www.google.com/search?q=cybersecurity",
        "domain": "google.com"
    }
    res = client.post("/analyze", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["action"] == "ALLOW"
    assert data["is_fake"] is False

def test_analyze_brand_phishing_block():
    """Verify malicious brand impersonation URL is blocked."""
    payload = {
        "url": "http://paypal-verification-account.xyz/login.php",
        "domain": "paypal-verification-account.xyz",
        "has_password_field": True
    }
    res = client.post("/analyze", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["action"] == "BLOCK"
    assert data["is_fake"] is True
    assert data["url_score"] >= 90

def test_siem_settings_flow():
    """Verify SIEM configuration persistence and test endpoint."""
    get_res = client.get("/api/settings/siem")
    assert get_res.status_code == 200

    update_payload = {
        "siem_syslog_host": "127.0.0.1",
        "siem_syslog_port": "514",
        "siem_syslog_proto": "UDP",
        "siem_enabled": True
    }
    post_res = client.post("/api/settings/siem", json=update_payload)
    assert post_res.status_code == 200
    assert post_res.json()["status"] == "success"

    verify_res = client.get("/api/settings/siem")
    assert verify_res.json()["siem_syslog_host"] == "127.0.0.1"

    # Test SIEM test endpoint
    test_res = client.post("/api/test-siem")
    assert test_res.status_code == 200

    # Clean up test setting
    client.post("/api/settings/siem", json={"siem_syslog_host": "", "siem_syslog_port": "514", "siem_syslog_proto": "UDP", "siem_enabled": False})

def test_threat_intel_stats_endpoint():
    """Verify /api/threat-intel/stats endpoint."""
    res = client.get("/api/threat-intel/stats")
    assert res.status_code == 200
    data = res.json()
    assert "total_indicators" in data
