import time
import json
import requests

SERVER_URL = "http://127.0.0.1:8001"

TEST_SCENARIOS = [
    {
        "id": "THREAT-001",
        "name": "IDN Homograph Homoglyph Attack",
        "category": "Spearphishing / Homograph",
        "mitre": "T1566.002",
        "payload": {
            "url": "https://xn--pple-43d.com/login/auth.php",
            "domain": "xn--pple-43d.com",
            "page_title": "Apple ID - Sign In",
            "has_password_field": True
        },
        "expected_action": "BLOCK"
    },
    {
        "id": "THREAT-002",
        "name": "Credential Harvester on Free Cloud Hosting",
        "category": "Credential Access / Cloud Trap",
        "mitre": "T1056",
        "payload": {
            "url": "https://chase-bank-verify-account.pages.dev/login.html",
            "domain": "chase-bank-verify-account.pages.dev",
            "page_title": "Chase Online - Sign In",
            "has_password_field": True,
            "has_credit_card_field": True
        },
        "expected_action": "BLOCK"
    },
    {
        "id": "THREAT-003",
        "name": "Brand Spoofing & Impersonation on High-Risk TLD",
        "category": "Spearphishing Link",
        "mitre": "T1566.002",
        "payload": {
            "url": "http://paypal-security-verification-center.xyz/update-billing.php?id=83749",
            "domain": "paypal-security-verification-center.xyz",
            "page_title": "PayPal: Account Resolution",
            "has_password_field": True
        },
        "expected_action": "BLOCK"
    },
    {
        "id": "THREAT-004",
        "name": "High-Entropy Lexical Zero-Day Phishing",
        "category": "Machine Learning Detection",
        "mitre": "T1566.002",
        "payload": {
            "url": "http://secure-banking-portal-auth-reset-kyc-validation.top/confirm?token=a8f9c0e1234",
            "domain": "secure-banking-portal-auth-reset-kyc-validation.top",
            "page_title": "Banking Security Alert",
            "has_password_field": True
        },
        "expected_action": "BLOCK"
    },
    {
        "id": "THREAT-005",
        "name": "Illegal Gambling Vector Policy Enforcement",
        "category": "Policy Violation",
        "mitre": "Policy: Gambling",
        "payload": {
            "url": "http://super-casino-slot-bahis-jackpot.com/play",
            "domain": "super-casino-slot-bahis-jackpot.com",
            "page_title": "Canlı Casino ve Slot Bahis",
            "page_text": "kumar slot bonusu kazan ve iddaa oyna",
            "has_password_field": False
        },
        "expected_action": "BLOCK"
    },
    {
        "id": "BENIGN-001",
        "name": "Legitimate Search Engine Query (SERP Awareness)",
        "category": "Benign Navigation",
        "mitre": "None",
        "payload": {
            "url": "https://www.google.com/search?q=cybersecurity+defense+frameworks",
            "domain": "google.com",
            "page_title": "Google Search",
            "has_password_field": False
        },
        "expected_action": "ALLOW"
    },
    {
        "id": "BENIGN-002",
        "name": "Legitimate Developer Infrastructure",
        "category": "Benign Navigation",
        "mitre": "None",
        "payload": {
            "url": "https://github.com/MFahadFaisal/AntiGravity",
            "domain": "github.com",
            "page_title": "GitHub - MFahadFaisal/AntiGravity",
            "has_password_field": False
        },
        "expected_action": "ALLOW"
    }
]

def run_simulation():
    print("=" * 75)
    print("🛡️  ANTIGRAVITY SOC DEFENSE EVALUATION & THREAT SIMULATION RUNNER")
    print("=" * 75)
    print(f"[*] Target Endpoint: {SERVER_URL}/analyze")
    print(f"[*] Total Test Scenarios: {len(TEST_SCENARIOS)}\n")

    results = []

    for test in TEST_SCENARIOS:
        print(f"[{test['id']}] Executing: {test['name']} ({test['category']})...")
        t0 = time.perf_counter()
        try:
            resp = requests.post(f"{SERVER_URL}/analyze", json=test["payload"], timeout=4.0)
            latency_ms = (time.perf_counter() - t0) * 1000
            if resp.status_code == 200:
                data = resp.json()
                action = data.get("action", "UNKNOWN")
                score = data.get("url_score", 0)
                mitre_tag = data.get("mitre_tag", "None")
                reason = data.get("reason", "N/A")
                success = (action == test["expected_action"])

                results.append({
                    "id": test["id"],
                    "name": test["name"],
                    "category": test["category"],
                    "target_url": test["payload"]["url"],
                    "expected": test["expected_action"],
                    "actual": action,
                    "score": score,
                    "mitre": mitre_tag,
                    "reason": reason,
                    "latency_ms": round(latency_ms, 2),
                    "success": success
                })
                symbol = "✓ PASS" if success else "✗ FAIL"
                print(f"   └─ Verdict: [{action}] | Score: %{score} | Latency: {latency_ms:.2f}ms | {symbol}")
                print(f"      Reason: {reason[:80]}...")
            else:
                print(f"   └─ HTTP Error: {resp.status_code}")
        except Exception as e:
            print(f"   └─ Connection Exception: {e}")

        time.sleep(0.15)

    print("\n" + "=" * 75)
    print("📊 FETCHING FORENSIC DOSSIER & SYSTEM METRICS")
    print("=" * 75)

    # 1. Fetch system statistics
    stats_resp = requests.get(f"{SERVER_URL}/api/stats").json()
    print(f"[*] Telemetry Ingestion Stats: Total={stats_resp.get('total')}, Benign={stats_resp.get('safe')}, Blocked={stats_resp.get('blocked')}, Threat Ratio={stats_resp.get('threat_ratio')}%")

    # 2. Fetch export report with cryptographic digest
    report_resp = requests.get(f"{SERVER_URL}/api/export-report").json()
    digest = report_resp.get("butunluk", {}).get("deger", "N/A")
    print(f"[*] Cryptographic Forensic Digest (SHA-256): {digest}")
    print(f"[*] Total Archived Incident Logs: {len(report_resp.get('kayitlar', []))}")

    # Output JSON summary for processing
    output_summary = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "stats": stats_resp,
        "crypto_digest_sha256": digest,
        "results": results
    }
    with open("ai_engine/simulation_report.json", "w", encoding="utf-8") as f:
        json.dump(output_summary, f, indent=2, ensure_ascii=False)

    print("\n[✓] Threat simulation finished. Detailed report saved to 'ai_engine/simulation_report.json'.")

if __name__ == "__main__":
    run_simulation()
