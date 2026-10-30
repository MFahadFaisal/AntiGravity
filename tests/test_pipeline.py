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
from visual_detector import compute_dhash, hamming_distance, check_visual_spoofing
from main import app

client = TestClient(app)

# ----------------------------------------------------------------------
# 1. FEATURE EXTRACTOR TESTS
# ----------------------------------------------------------------------
def test_feature_vector_dimension():
    """Verify feature extractor outputs exactly 22 named features."""
    url = "https://secure.bank-update.xyz/login.php?session=928374"
    vec = extract_features_vector(url)
    assert len(vec) == 22, f"Expected 22 features, got {len(vec)}"
    assert len(FEATURE_NAMES) == 22

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

# ----------------------------------------------------------------------
# 3. SOC REST API ENDPOINTS INTEGRATION TESTS
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

def test_webhook_settings_flow():
    """Verify webhook configuration retrieval and persistence."""
    get_res = client.get("/api/settings/webhooks")
    assert get_res.status_code == 200

    update_payload = {
        "discord_webhook_url": "https://discord.com/api/webhooks/test/123",
        "slack_webhook_url": "",
        "telegram_bot_token": "",
        "telegram_chat_id": ""
    }
    post_res = client.post("/api/settings/webhooks", json=update_payload)
    assert post_res.status_code == 200
    assert post_res.json()["status"] == "success"

    verify_res = client.get("/api/settings/webhooks")
    assert verify_res.json()["discord_webhook_url"] == update_payload["discord_webhook_url"]

    # Clean up test setting
    client.post("/api/settings/webhooks", json={"discord_webhook_url": "", "slack_webhook_url": "", "telegram_bot_token": "", "telegram_chat_id": ""})
