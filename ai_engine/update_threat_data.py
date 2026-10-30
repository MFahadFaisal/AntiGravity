import os
import sys
import argparse
import sqlite3
import datetime
import requests
import pandas as pd
import numpy as np
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, roc_auc_score

# Ensure feature_extractor can be imported
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from feature_extractor import extract_features_vector, FEATURE_NAMES

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_FILE = os.path.join(BASE_DIR, "antigravity_logs.db")
DATASET_FILE = os.path.join(BASE_DIR, "datasets", "modern_phishing_dataset_2026.csv")
MODEL_FILE = os.path.join(BASE_DIR, "antigravity_url_model.pkl")

def fetch_external_threats():
    """
    Pulls recent active phishing feeds from PhishTank & URLhaus.
    Returns a list of newly discovered malicious URLs.
    """
    discovered_urls = []
    print("[*] Contacting global threat intelligence feeds...")

    # 1. PhishTank Feed
    try:
        url = "http://data.phishtank.com/data/online-valid.json"
        headers = {"User-Agent": "anti-gravity-soc-agent-v2"}
        res = requests.get(url, headers=headers, timeout=8)
        if res.status_code == 200:
            entries = res.json()
            for item in entries[:500]:
                u = item.get("url")
                if u:
                    discovered_urls.append(u)
            print(f"[✓] PhishTank Feed: Fetched {len(discovered_urls)} verified active threats.")
    except Exception as e:
        print(f"[!] PhishTank connection skipped: {e}")

    # 2. Local Threat Intel Database
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute("SELECT domain FROM threat_intel ORDER BY id DESC LIMIT 500")
        rows = cursor.fetchall()
        conn.close()
        for r in rows:
            discovered_urls.append(f"http://{r[0]}")
        print(f"[✓] Local SQLite Cache: Loaded {len(rows)} verified threat domains.")
    except Exception as e:
        print(f"[!] Local database query error: {e}")

    return list(set(discovered_urls))

def update_dataset_and_retrain(retrain=True):
    print("=" * 65)
    print("   ANTIGRAVITY AUTOMATED THREAT INGESTION & DATASET UPDATER")
    print("=" * 65)

    if not os.path.exists(DATASET_FILE):
        print(f"[!] Primary dataset not found at: {DATASET_FILE}")
        return

    # Load existing dataset
    existing_df = pd.read_csv(DATASET_FILE)
    print(f"[*] Current Dataset Size: {len(existing_df):,} samples ({sum(existing_df['is_phishing'] == 1):,} phishing, {sum(existing_df['is_phishing'] == 0):,} safe)")
    existing_urls = set(existing_df["url"].astype(str).str.lower().str.strip())

    # Fetch new threats
    candidate_urls = fetch_external_threats()
    new_urls = [u for u in candidate_urls if u.lower().strip() not in existing_urls]

    print(f"[*] New unique malicious URLs discovered: {len(new_urls):,}")

    if new_urls:
        print(f"[*] Extracting 22 real-time features for {len(new_urls)} new threats...")
        new_rows = []
        for u in new_urls:
            vec = extract_features_vector(u)
            new_rows.append(vec)

        new_features_df = pd.DataFrame(new_rows, columns=FEATURE_NAMES)
        new_features_df.insert(0, "url", new_urls)
        new_features_df["is_phishing"] = 1

        # Append to master dataset and save
        updated_df = pd.concat([existing_df, new_features_df], ignore_index=True)
        updated_df.to_csv(DATASET_FILE, index=False)
        print(f"[✓] Dataset successfully updated! New total: {len(updated_df):,} samples.")
    else:
        print("[✓] All candidate threats are already up to date in the master dataset.")
        updated_df = existing_df

    # Retrain model if requested
    if retrain:
        print("\n[*] Retraining Random Forest Classifier on updated data...")
        X = updated_df[FEATURE_NAMES]
        y = updated_df["is_phishing"].values

        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.20, random_state=42, stratify=y
        )

        clf = RandomForestClassifier(
            n_estimators=150,
            max_depth=16,
            min_samples_split=6,
            min_samples_leaf=2,
            class_weight="balanced",
            random_state=42,
            n_jobs=1
        )
        clf.fit(X_train, y_train)

        y_pred = clf.predict(X_test)
        y_prob = clf.predict_proba(X_test)[:, 1]
        acc = accuracy_score(y_test, y_pred)
        roc = roc_auc_score(y_test, y_prob)

        package = {
            "model": clf,
            "feature_names": FEATURE_NAMES,
            "version": f"2.0-auto-updated-{datetime.date.today()}",
            "accuracy": acc,
            "roc_auc": roc,
            "sample_count": len(updated_df)
        }
        joblib.dump(package, MODEL_FILE)
        print(f"[✓] Model retrained & updated in-place: Accuracy = {acc * 100:.2f}%, ROC-AUC = {roc:.4f}")

    print("=" * 65)
    print("   AUTOMATED THREAT INGESTION COMPLETE")
    print("=" * 65)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AntiGravity Automated Threat Dataset Updater")
    parser.add_argument("--no-retrain", action="store_true", help="Append new threats without retraining the model")
    args = parser.parse_args()

    update_dataset_and_retrain(retrain=not args.no_retrain)
