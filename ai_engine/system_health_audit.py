#!/usr/bin/env python3
"""
AntiGravity SOC End-to-End System Health & Deep Diagnostic Auditor
==================================================================
Runs comprehensive automated verification across all 9 architectural layers:
1. Environment & Dependencies
2. Model & Feature Engineering (32-D, ONNX, PKL)
3. Threat Intel Feed Ledger (25k+ Indicators)
4. Computer Vision Visual Engine (dHash & Hamming Distance)
5. Backend REST & WebSocket API (Port 8001)
6. RFC 1035 UDP DNS Sinkhole Gateway (Port 5300)
7. Client-Side JavaScript Engine (Manifest V3 Edge Inference)
8. Browser Extension Bundle Integrity
9. Legal Forensics & Cryptographic Signatures
"""

import os
import sys
import json
import time
import socket
import struct
import subprocess
import requests

SERVER_URL = "http://127.0.0.1:8001"
DNS_PORT = 5300
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(PROJECT_ROOT, "ai_engine"))

class AntiGravityAuditor:
    def __init__(self):
        self.results = []
        self.start_time = time.time()

    def record(self, layer: str, test_name: str, passed: bool, message: str, latency_ms: float = 0.0):
        self.results.append({
            "layer": layer,
            "test": test_name,
            "passed": passed,
            "message": message,
            "latency_ms": round(latency_ms, 2)
        })
        icon = "✅" if passed else "❌"
        lat_str = f"({round(latency_ms, 2)}ms)" if latency_ms > 0 else ""
        print(f" {icon} [{layer.upper()}] {test_name}: {message} {lat_str}")

    def audit_environment(self):
        print("\n--- 1. ENVIRONMENT & DEPENDENCY AUDIT ---")
        try:
            import torch
            import onnx
            import onnxruntime
            import sklearn
            import fastapi
            import pandas
            import PIL
            self.record("env", "Core Libraries", True, f"PyTorch {torch.__version__}, ONNX {onnx.__version__}, Sklearn {sklearn.__version__}, FastAPI {fastapi.__version__}")
        except Exception as e:
            self.record("env", "Core Libraries", False, f"Missing dependency: {e}")

    def audit_model_and_features(self):
        print("\n--- 2. MACHINE LEARNING & FEATURE PIPELINE AUDIT ---")
        # 1. Feature Extractor
        t0 = time.time()
        try:
            from feature_extractor import extract_features_vector, extract_features_dict, FEATURE_NAMES
            test_url = "https://paypal-security-verification-center.xyz/secure/login.php?auth=1"
            vec = extract_features_vector(test_url)
            fdict = extract_features_dict(test_url)
            lat = (time.time() - t0) * 1000
            if len(vec) == 32 and len(FEATURE_NAMES) == 32:
                self.record("ml", "32-D Feature Extractor", True, f"Extracted 32 features accurately ({len(fdict)} dict keys)", lat)
            else:
                self.record("ml", "32-D Feature Extractor", False, f"Feature dimension mismatch: {len(vec)} != 32", lat)
        except Exception as e:
            self.record("ml", "32-D Feature Extractor", False, str(e))

        # 2. PKL Model
        t0 = time.time()
        try:
            import joblib
            import pandas as pd
            model_path = os.path.join(PROJECT_ROOT, "ai_engine", "antigravity_url_model.pkl")
            pkg = joblib.load(model_path)
            model = pkg["model"]
            acc = pkg.get("accuracy", 0.0)
            roc = pkg.get("roc_auc", 0.0)
            df = pd.DataFrame([vec], columns=FEATURE_NAMES)
            prob = float(model.predict_proba(df)[0][1])
            lat = (time.time() - t0) * 1000
            self.record("ml", "PKL Random Forest Model", True, f"Accuracy: {acc*100:.2f}%, ROC-AUC: {roc:.4f}, Test Inference Prob: {prob*100:.1f}%", lat)
        except Exception as e:
            self.record("ml", "PKL Random Forest Model", False, str(e))

        # 3. ONNX Model
        t0 = time.time()
        try:
            import onnxruntime as ort
            import numpy as np
            onnx_path = os.path.join(PROJECT_ROOT, "ai_engine", "antigravity_url_model.onnx")
            sess = ort.InferenceSession(onnx_path)
            inp_name = sess.get_inputs()[0].name
            dummy_x = np.array([vec], dtype=np.float32)
            outs = sess.run(None, {inp_name: dummy_x})
            lat = (time.time() - t0) * 1000
            self.record("ml", "ONNX Model Runtime", True, f"Loaded ONNX session ({os.path.getsize(onnx_path)/1024:.1f} KB), Outputs: {len(outs)}", lat)
        except Exception as e:
            self.record("ml", "ONNX Model Runtime", False, str(e))

        # 4. Dataset
        csv_path = os.path.join(PROJECT_ROOT, "ai_engine", "datasets", "modern_phishing_dataset_2026.csv")
        if os.path.exists(csv_path):
            size_mb = os.path.getsize(csv_path) / (1024 * 1024)
            self.record("ml", "Modern Phishing Dataset 2026", True, f"CSV exists ({size_mb:.2f} MB)")
        else:
            self.record("ml", "Modern Phishing Dataset 2026", False, "CSV not found")

    def audit_threat_intelligence(self):
        print("\n--- 3. THREAT INTELLIGENCE & INDICATOR AUDIT ---")
        t0 = time.time()
        try:
            from threat_feed_manager import is_known_threat, get_feed_statistics, load_threat_cache_from_db
            db_path = os.path.join(PROJECT_ROOT, "ai_engine", "antigravity_logs.db")
            stats = get_feed_statistics(db_path)
            total = stats.get("total_indicators", 0)
            lat = (time.time() - t0) * 1000
            if total >= 20_000:
                self.record("threat_intel", "Threat Feed Ingestion", True, f"{total:,} active indicators loaded across feeds", lat)
            else:
                self.record("threat_intel", "Threat Feed Ingestion", False, f"Indicator count too low: {total}", lat)
        except Exception as e:
            self.record("threat_intel", "Threat Feed Ingestion", False, str(e))

        # Threat CLI validation
        try:
            cli_res = subprocess.run([sys.executable, "ai_engine/threat_sync_cli.py", "--validate"], cwd=PROJECT_ROOT, capture_output=True, text=True)
            output_text = (cli_res.stdout or "") + " " + (cli_res.stderr or "")
            if cli_res.returncode == 0 and "PASSED" in output_text:
                self.record("threat_intel", "Threat Sync CLI Tool", True, "Integrity check and schema validation passed")
            else:
                self.record("threat_intel", "Threat Sync CLI Tool", False, output_text)
        except Exception as e:
            self.record("threat_intel", "Threat Sync CLI Tool", False, str(e))

    def audit_computer_vision(self):
        print("\n--- 4. COMPUTER VISION & PERCEPTUAL DHASH AUDIT ---")
        t0 = time.time()
        try:
            from PIL import Image
            from visual_detector import compute_dhash, hamming_distance, BRAND_SIGNATURES, check_visual_spoofing
            img1 = Image.new("RGB", (64, 64), color=(255, 0, 0))
            img2 = Image.new("RGB", (64, 64), color=(255, 0, 0))
            h1 = compute_dhash(img1)
            h2 = compute_dhash(img2)
            dist = hamming_distance(h1, h2)
            lat = (time.time() - t0) * 1000
            if dist == 0 and len(BRAND_SIGNATURES) >= 30:
                self.record("cv", "Perceptual dHash Engine", True, f"Identical image distance = 0, {len(BRAND_SIGNATURES)} brand signatures loaded", lat)
            else:
                self.record("cv", "Perceptual dHash Engine", False, f"Invalid distance {dist} or signatures count {len(BRAND_SIGNATURES)}", lat)
        except Exception as e:
            self.record("cv", "Perceptual dHash Engine", False, str(e))

    def audit_backend_api(self):
        print("\n--- 5. BACKEND REST & WEBSOCKET API AUDIT ---")
        endpoints = [
            ("GET", "/health", 200, "Health check"),
            ("GET", "/api/stats", 200, "SOC telemetry statistics"),
            ("GET", "/api/logs", 200, "Audit logs"),
            ("GET", "/api/threat-intel/stats", 200, "Threat intelligence summary"),
            ("GET", "/api/whitelist", 200, "Whitelist management"),
            ("GET", "/api/dns/stats", 200, "DNS Sinkhole statistics"),
            ("GET", "/api/dns/queries", 200, "DNS query ledger"),
            ("GET", "/api/model/weights", 200, "Client tree weights JSON"),
            ("GET", "/api/model/onnx", 200, "ONNX model download binary"),
            ("GET", "/api/export-report", 200, "Forensic dossier report")
        ]

        for method, ep, exp_code, desc in endpoints:
            t0 = time.time()
            try:
                resp = requests.get(f"{SERVER_URL}{ep}", timeout=3.0)
                lat = (time.time() - t0) * 1000
                if resp.status_code == exp_code:
                    self.record("api", f"{method} {ep}", True, f"{desc} responded HTTP {resp.status_code}", lat)
                else:
                    self.record("api", f"{method} {ep}", False, f"Expected {exp_code}, got {resp.status_code}", lat)
            except Exception as e:
                self.record("api", f"{method} {ep}", False, f"Request failed: {e}")

        # Core Zero-Trust Evaluation API Test
        t0 = time.time()
        try:
            payload = {
                "url": "http://paypal-verification-center.xyz/auth.php",
                "page_text": "Please enter your PayPal credentials",
                "html_source": "<html><form><input type='password'></form></html>",
                "has_password_field": True,
                "has_credit_card_field": False
            }
            res = requests.post(f"{SERVER_URL}/analyze", json=payload, timeout=3.0)
            lat = (time.time() - t0) * 1000
            data = res.json()
            if data.get("is_fake") is True and data.get("url_score", 0) >= 80:
                self.record("api", "POST /analyze (Phishing Block)", True, f"Threat blocked with score {data.get('url_score')}% ({data.get('details', '')[:40]}...)", lat)
            else:
                self.record("api", "POST /analyze (Phishing Block)", False, f"Phishing not blocked: {data}", lat)
        except Exception as e:
            self.record("api", "POST /analyze (Phishing Block)", False, str(e))

        # Legitimate URL Test
        t0 = time.time()
        try:
            benign_payload = {
                "url": "https://www.google.com/search?q=cybersecurity",
                "page_text": "Google Search results",
                "html_source": "<html><body>Google Search</body></html>",
                "has_password_field": False,
                "has_credit_card_field": False
            }
            res = requests.post(f"{SERVER_URL}/analyze", json=benign_payload, timeout=3.0)
            lat = (time.time() - t0) * 1000
            data = res.json()
            if data.get("is_fake") is False and data.get("url_score", 100) <= 20:
                self.record("api", "POST /analyze (Benign Allow)", True, f"Legitimate search allowed with score {data.get('url_score')}%", lat)
            else:
                self.record("api", "POST /analyze (Benign Allow)", False, f"Benign incorrectly flagged: {data}", lat)
        except Exception as e:
            self.record("api", "POST /analyze (Benign Allow)", False, str(e))

    def audit_dns_sinkhole(self):
        print("\n--- 6. RFC 1035 UDP DNS SINKHOLE GATEWAY AUDIT ---")
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(3.0)

        # 1. Test Malicious Domain Sinkholing
        t0 = time.time()
        try:
            query = struct.pack("!HHHHHH", 0x1111, 0x0100, 1, 0, 0, 0)
            for part in "paypal-security-update-center.com".split("."):
                p = part.encode("ascii")
                query += bytes([len(p)]) + p
            query += b"\x00" + struct.pack("!HH", 1, 1)

            sock.sendto(query, ("127.0.0.1", DNS_PORT))
            data, _ = sock.recvfrom(1024)
            lat = (time.time() - t0) * 1000
            tx, _, _, ancount, _, _ = struct.unpack("!HHHHHH", data[:12])
            ip = socket.inet_ntoa(data[-4:]) if ancount > 0 else ""
            if ip == "0.0.0.0":
                self.record("dns", "Malicious Domain Sinkholing", True, f"paypal-security-update-center.com sinkholed to 0.0.0.0", lat)
            else:
                self.record("dns", "Malicious Domain Sinkholing", False, f"Expected 0.0.0.0, got {ip}", lat)
        except Exception as e:
            self.record("dns", "Malicious Domain Sinkholing", False, str(e))

        # 2. Test Benign Domain Recursive Forwarding
        t0 = time.time()
        try:
            query = struct.pack("!HHHHHH", 0x2222, 0x0100, 1, 0, 0, 0)
            for part in "apple.com".split("."):
                p = part.encode("ascii")
                query += bytes([len(p)]) + p
            query += b"\x00" + struct.pack("!HH", 1, 1)

            sock.sendto(query, ("127.0.0.1", DNS_PORT))
            data, _ = sock.recvfrom(1024)
            lat = (time.time() - t0) * 1000
            tx, _, _, ancount, _, _ = struct.unpack("!HHHHHH", data[:12])
            ip = socket.inet_ntoa(data[-4:]) if ancount > 0 else ""
            if ancount > 0 and ip != "0.0.0.0":
                self.record("dns", "Benign Recursive Resolution", True, f"apple.com resolved upstream to {ip}", lat)
            else:
                self.record("dns", "Benign Recursive Resolution", False, f"Failed resolving upstream: ip={ip}", lat)
        except Exception as e:
            self.record("dns", "Benign Recursive Resolution", False, str(e))
        finally:
            sock.close()

    def audit_client_engine(self):
        print("\n--- 7. CLIENT-SIDE JAVASCRIPT ENGINE AUDIT ---")
        js_engine_path = os.path.join(PROJECT_ROOT, "browser_agent", "antigravity_client_engine.js")
        t0 = time.time()
        try:
            node_script = f"""
            const Engine = require('{js_engine_path}');
            const test1 = Engine.predict('https://google.com/search?q=test');
            const test2 = Engine.predict('http://paypal-security-update-center.com/login.php?verify=1');
            const vec = Engine.extractFeaturesVector('https://test.com');
            console.log(JSON.stringify({{
                version: Engine.version,
                numFeatures: Engine.numFeatures,
                vecLen: vec.length,
                test1_status: test1.status,
                test2_status: test2.status,
                test2_score: test2.url_score
            }}));
            """
            res = subprocess.run(["node", "-e", node_script], capture_output=True, text=True, check=True)
            lat = (time.time() - t0) * 1000
            out = json.loads(res.stdout)
            if out["numFeatures"] == 32 and out["test1_status"] == "safe" and out["test2_status"] == "block":
                self.record("js_engine", "Offline Edge Model (Node.js)", True, f"V{out['version']} (32 features), Google=safe, Phish=block ({out['test2_score']}%)", lat)
            else:
                self.record("js_engine", "Offline Edge Model (Node.js)", False, f"Unexpected output: {out}", lat)
        except Exception as e:
            self.record("js_engine", "Offline Edge Model (Node.js)", False, str(e))

    def audit_extension_bundle(self):
        print("\n--- 8. CHROME EXTENSION BUNDLE INTEGRITY AUDIT ---")
        manifest_path = os.path.join(PROJECT_ROOT, "browser_agent", "manifest.json")
        try:
            with open(manifest_path, "r") as f:
                manifest = json.load(f)
            v = manifest.get("manifest_version")
            name = manifest.get("name")
            ver = manifest.get("version")
            sw = manifest.get("background", {}).get("service_worker")
            if v == 3 and sw == "background.js":
                self.record("extension", "Manifest V3 Compliance", True, f"'{name}' v{ver}, Service Worker: {sw}")
            else:
                self.record("extension", "Manifest V3 Compliance", False, f"Manifest mismatch: v={v}, sw={sw}")
        except Exception as e:
            self.record("extension", "Manifest V3 Compliance", False, str(e))

        required_files = [
            "browser_agent/background.js",
            "browser_agent/content.js",
            "browser_agent/antigravity_client_engine.js",
            "browser_agent/antigravity_model_weights.json",
            "browser_agent/popup.html",
            "browser_agent/popup.js",
            "browser_agent/options.html",
            "browser_agent/options.js",
            "browser_agent/icon128.png"
        ]
        all_present = True
        missing = []
        for rf in required_files:
            fp = os.path.join(PROJECT_ROOT, rf)
            if not os.path.exists(fp):
                all_present = False
                missing.append(rf)

        if all_present:
            self.record("extension", "Extension Assets Presence", True, f"All {len(required_files)} extension assets verified")
        else:
            self.record("extension", "Extension Assets Presence", False, f"Missing files: {missing}")

    def audit_forensics(self):
        print("\n--- 9. LEGAL FORENSICS & CRYPTOGRAPHIC DIGESTS ---")
        t0 = time.time()
        try:
            res = requests.get(f"{SERVER_URL}/api/export-report", timeout=3.0)
            lat = (time.time() - t0) * 1000
            data = res.json()
            digest = data.get("report_sha256_digest") or data.get("butunluk", {}).get("deger", "")
            incident_count = data.get("total_incidents") or data.get("ozet", {}).get("total", 0)
            if len(digest) == 64:
                self.record("forensics", "SHA-256 Chain of Custody", True, f"Valid SHA-256 digest ({digest[:16]}...), Records: {incident_count}", lat)
            else:
                self.record("forensics", "SHA-256 Chain of Custody", False, f"Invalid hash digest: {digest}", lat)
        except Exception as e:
            self.record("forensics", "SHA-256 Chain of Custody", False, str(e))

    def run_all(self):
        print("===========================================================================")
        print("🛡️  ANTIGRAVITY SOC END-TO-END SYSTEM HEALTH AUDITOR")
        print("===========================================================================")
        self.audit_environment()
        self.audit_model_and_features()
        self.audit_threat_intelligence()
        self.audit_computer_vision()
        self.audit_backend_api()
        self.audit_dns_sinkhole()
        self.audit_client_engine()
        self.audit_extension_bundle()
        self.audit_forensics()

        total = len(self.results)
        passed = sum(1 for r in self.results if r["passed"])
        failed = total - passed
        duration = round(time.time() - self.start_time, 2)

        print("\n===========================================================================")
        print(f"📊 DIAGNOSTIC AUDIT SUMMARY: {passed}/{total} CHECKS PASSED ({duration}s)")
        print("===========================================================================")

        if failed == 0:
            print("🌟 VERDICT: ALL SYSTEMS FULLY OPERATIONAL WITH ZERO DEFECTS.")
        else:
            print(f"⚠️ VERDICT: {failed} FAILURES DETECTED.")
            for r in self.results:
                if not r["passed"]:
                    print(f"   └─ [{r['layer']}] {r['test']}: {r['message']}")

        # Save audit report to JSON
        report_file = os.path.join(PROJECT_ROOT, "ai_engine", "system_health_audit_report.json")
        with open(report_file, "w") as f:
            json.dump({
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "total_checks": total,
                "passed_checks": passed,
                "failed_checks": failed,
                "duration_seconds": duration,
                "results": self.results
            }, f, indent=2)
        print(f"[*] Audit record saved to: {report_file}")
        return failed == 0

if __name__ == "__main__":
    auditor = AntiGravityAuditor()
    success = auditor.run_all()
    sys.exit(0 if success else 1)
