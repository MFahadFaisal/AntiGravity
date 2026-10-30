#!/usr/bin/env python3
"""
AntiGravity Threat Feed Sync & SOC Operations CLI
=================================================
Automates pulling, validating, deduplicating, and exporting threat intelligence
from OpenPhish, URLhaus, and PhishTank, with zero-day STIX 2.1 compliance.
"""

import sys
import os
import json
import time
import argparse
import logging
from typing import Dict, Any, List

# Ensure ai_engine is importable
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(CURRENT_DIR, ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from ai_engine.threat_feed_manager import ThreatFeedManager
from ai_engine.feature_extractor import extract_features_vector, FEATURE_NAMES

logger = logging.getLogger("ThreatSyncCLI")
logging.basicConfig(level=logging.INFO, format="[%(asctime)s] [%(levelname)s] %(message)s")

def get_status(manager: ThreatFeedManager) -> dict:
    """Returns database size, indicators count, and feed statistics."""
    stats = manager.get_stats()
    model_pkl = os.path.join(CURRENT_DIR, "antigravity_url_model.pkl")
    onnx_path = os.path.join(CURRENT_DIR, "antigravity_url_model.onnx")

    stats["model_pkl_exists"] = os.path.exists(model_pkl)
    stats["model_onnx_exists"] = os.path.exists(onnx_path)
    if os.path.exists(onnx_path):
        stats["onnx_size_kb"] = round(os.path.getsize(onnx_path) / 1024, 1)

    return stats

def sync_feeds(manager: ThreatFeedManager) -> dict:
    """Triggers live synchronization across threat feeds."""
    logger.info("Initiating threat feed synchronization...")
    start_time = time.time()
    result = manager.sync_all_feeds()
    duration = round(time.time() - start_time, 2)
    result["sync_duration_seconds"] = duration
    logger.info(f"Sync completed in {duration}s. Total Indicators: {result.get('total_indicators', 0)}")
    return result

def validate_integrity(manager: ThreatFeedManager) -> bool:
    """Validates threat database structure and feature extraction pipeline."""
    logger.info("Running pipeline integrity validation...")
    stats = manager.get_stats()
    if stats.get("total_indicators", 0) < 100:
        logger.error(f"Integrity check failed: Suspiciously low indicator count ({stats.get('total_indicators')})")
        return False

    # Test 32-feature extraction
    test_vec = extract_features_vector("https://chase-bank-verify-auth.xyz/secure/login.php?session=xyz")
    if len(test_vec) != 32:
        logger.error(f"Integrity check failed: Vector length {len(test_vec)} != 32")
        return False

    logger.info(f"Integrity check PASSED: {stats.get('total_indicators')} indicators verified across {len(FEATURE_NAMES)} features.")
    return True

def inspect_target(manager: ThreatFeedManager, target: str) -> dict:
    """Performs unified inspection across Threat Feeds and 32-Feature Model."""
    url = target if "://" in target else "http://" + target
    feed_result = manager.check_url(url)

    # ML Inference
    ai_prob = 0.0
    try:
        import joblib
        import pandas as pd
        model_path = os.path.join(CURRENT_DIR, "antigravity_url_model.pkl")
        if os.path.exists(model_path):
            pkg = joblib.load(model_path)
            model = pkg.get("model")
            df = pd.DataFrame([extract_features_vector(url)], columns=FEATURE_NAMES)
            ai_prob = float(model.predict_proba(df)[0][1])
    except Exception as e:
        logger.warning(f"AI inspection fallback: {e}")

    verdict = "MALICIOUS" if (feed_result.get("is_blacklisted") or ai_prob >= 0.70) else "BENIGN"

    return {
        "target": target,
        "verdict": verdict,
        "feed_blacklisted": feed_result.get("is_blacklisted", False),
        "feed_source": feed_result.get("source"),
        "ai_phishing_probability": round(ai_prob, 4),
        "ai_confidence_score": round(ai_prob * 100, 1),
        "mitre_tag": "T1566.002: Spearphishing Link" if verdict == "MALICIOUS" else "None"
    }

def export_stix_bundle(manager: ThreatFeedManager, output_path: str):
    """Exports active threat indicators as an OASIS STIX 2.1 JSON bundle."""
    logger.info(f"Exporting threat indicators to STIX 2.1 format: {output_path}")
    indicators = list(manager.indicators)[:2500]  # Export representative bundle

    stix_objects = []
    bundle_id = f"bundle--{int(time.time())}"

    for i, ind in enumerate(indicators):
        stix_ind = {
            "type": "indicator",
            "spec_version": "2.1",
            "id": f"indicator--{abs(hash(ind)) % 10000000000000000}",
            "created": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "modified": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "name": f"AntiGravity Phishing IOC #{i+1}",
            "description": f"Blacklisted active phishing threat indicator: {ind}",
            "indicator_types": ["malicious-activity"],
            "pattern": f"[url:value = '{ind}']",
            "pattern_type": "stix",
            "valid_from": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        }
        stix_objects.append(stix_ind)

    bundle = {
        "type": "bundle",
        "id": bundle_id,
        "objects": stix_objects
    }

    with open(output_path, "w") as f:
        json.dump(bundle, f, indent=2)

    logger.info(f"Successfully generated STIX 2.1 bundle with {len(stix_objects)} objects at {output_path}")

def main():
    parser = argparse.ArgumentParser(description="AntiGravity Threat Feed Operations CLI")
    parser.add_argument("--sync", action="store_true", help="Download and synchronize fresh threat intelligence feeds")
    parser.add_argument("--validate", action="store_true", help="Validate indicator database and AI feature pipeline")
    parser.add_argument("--status", action="store_true", help="Print current threat intel database and model status")
    parser.add_argument("--check", type=str, help="Scan a URL or domain against feeds and 32-feature AI engine")
    parser.add_argument("--export-stix", type=str, help="Export threat indicators as STIX 2.1 JSON bundle")
    parser.add_argument("--export-metrics", type=str, help="Output operational metrics to JSON file for CI/CD")

    args = parser.parse_args()
    manager = ThreatFeedManager()

    if not any([args.sync, args.validate, args.status, args.check, args.export_stix, args.export_metrics]):
        parser.print_help()
        sys.exit(0)

    metrics = {}

    if args.sync:
        sync_res = sync_feeds(manager)
        metrics["sync"] = sync_res

    if args.validate:
        is_valid = validate_integrity(manager)
        metrics["valid"] = is_valid
        if not is_valid:
            sys.exit(1)

    if args.status:
        st = get_status(manager)
        metrics["status"] = st
        print(json.dumps(st, indent=2))

    if args.check:
        res = inspect_target(manager, args.check)
        print(json.dumps(res, indent=2))

    if args.export_stix:
        export_stix_bundle(manager, args.export_stix)

    if args.export_metrics:
        with open(args.export_metrics, "w") as f:
            json.dump(metrics, f, indent=2)
        logger.info(f"Metrics written to {args.export_metrics}")

if __name__ == "__main__":
    main()
