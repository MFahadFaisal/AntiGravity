import os
import sys
import time
import sqlite3
import random
import pandas as pd
import numpy as np
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, roc_auc_score, classification_report

# Ensure local imports work
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from feature_extractor import extract_features_vector, FEATURE_NAMES
from adversarial_generator import generate_adversarial_phishing_urls

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_FILE = os.path.join(BASE_DIR, "antigravity_logs.db")
DATASET_FILE = os.path.join(BASE_DIR, "datasets", "modern_phishing_dataset_2026.csv")
MODEL_FILE = os.path.join(BASE_DIR, "antigravity_url_model.pkl")

# Diverse real-world benign URL templates (CDNs, API endpoints, web assets, deep articles)
BENIGN_EXTENSIONS = [
    "https://github.com/torvalds/linux/commit/8f9c0e12345a",
    "https://en.wikipedia.org/wiki/Zero_trust_security_model",
    "https://stackoverflow.com/questions/59828472/python-multiprocessing-pool",
    "https://docs.python.org/3/library/multiprocessing.html#module-multiprocessing",
    "https://developer.mozilla.org/en-US/docs/Web/API/MutationObserver",
    "https://fastapi.tiangolo.com/tutorial/security/oauth2-jwt/",
    "https://aws.amazon.com/s3/pricing/?nc2=h_ql_pr_s3",
    "https://cloud.google.com/kubernetes-engine/docs/concepts/cluster-architecture",
    "https://learn.microsoft.com/en-us/azure/security/fundamentals/zero-trust",
    "https://hub.docker.com/_/python/tags?page=1&name=3.11",
    "https://pypi.org/project/scikit-learn/#history",
    "https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css",
    "https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap",
    "https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css",
    "https://www.youtube.com/watch?v=dQw4w9WgXcQ&t=42s",
    "https://news.ycombinator.com/item?id=38492019",
    "https://tranco-list.eu/list/K2N9/1000000",
    "https://www.w3.org/Protocols/rfc2616/rfc2616-sec10.html",
    "https://archive.org/web/web.php",
    "https://www.nature.com/articles/s41586-023-06747-5"
]

BENIGN_TOP_DOMAINS = [
    "google.com", "youtube.com", "facebook.com", "baidu.com", "wikipedia.org",
    "yahoo.com", "amazon.com", "zoom.us", "live.com", "reddit.com",
    "netflix.com", "microsoft.com", "instagram.com", "linkedin.com", "apple.com",
    "bing.com", "twitter.com", "twitch.tv", "adobe.com", "spotify.com",
    "github.com", "aliexpress.com", "dropbox.com", "slack.com", "salesforce.com",
    "cnn.com", "bbc.co.uk", "nytimes.com", "theguardian.com", "reuters.com",
    "forbes.com", "bloomberg.com", "huffpost.com", "espn.com", "imdb.com",
    "cloudflare.com", "akamai.com", "fastly.net", "aws.amazon.com", "azure.com"
]

def generate_deep_benign_urls(count: int = 15000) -> list[str]:
    """Generates realistic deep-path benign enterprise URLs with natural language parameters."""
    paths = [
        "articles/tech/cybersecurity-overview",
        "docs/v2/api/reference/get-user-profile",
        "assets/images/hero-banner-2026.png",
        "category/business/finance/markets-today",
        "products/hardware/enterprise-switches/catalog",
        "search/results.html",
        "download/client/installer-win64.msi",
        "releases/tag/v2.1.0-rc3",
        "blog/engineering/scaling-distributed-systems"
    ]
    query_templates = [
        "page={}&sort=desc&filter=verified",
        "id={}&lang=en&theme=dark&client_id=web",
        "query=machine+learning+security&page={}&limit=50",
        "v=3.4.1&cache_bust={}&format=json",
        "session_token=valid_token_{}&ref=homepage"
    ]

    benign_urls = list(BENIGN_EXTENSIONS)

    while len(benign_urls) < count:
        dom = random.choice(BENIGN_TOP_DOMAINS)
        path = random.choice(paths)
        num = random.randint(100, 999999)
        q = random.choice(query_templates).format(num)
        scheme = "https://" if random.random() < 0.9 else "http://"
        url = f"{scheme}www.{dom}/{path}?{q}"
        benign_urls.append(url)

    return benign_urls[:count]

def build_enterprise_dataset_and_train():
    print("=" * 75)
    print("🚀 ANTIGRAVITY ENTERPRISE DATASET BUILDER & 32-FEATURE MODEL TRAINER")
    print("=" * 75)

    urls_pool = []
    labels_pool = []

    # 1. Ingest existing dataset (if present)
    if os.path.exists(DATASET_FILE):
        print(f"[*] Reading base samples from: {DATASET_FILE}")
        old_df = pd.read_csv(DATASET_FILE)
        if "url" in old_df.columns and "is_phishing" in old_df.columns:
            for _, row in old_df.iterrows():
                u = str(row["url"]).strip()
                l = int(row["is_phishing"])
                if u and len(u) > 6:
                    urls_pool.append(u)
                    labels_pool.append(l)
            print(f"[✓] Base dataset loaded: {len(urls_pool):,} samples.")

    # 2. Ingest verified threat intelligence indicators from local SQLite cache
    threat_intel_urls = []
    if os.path.exists(DB_FILE):
        try:
            conn = sqlite3.connect(DB_FILE)
            cur = conn.cursor()
            cur.execute("SELECT domain FROM threat_intel LIMIT 10000")
            rows = cur.fetchall()
            conn.close()
            for r in rows:
                if r[0]:
                    threat_intel_urls.append(f"http://{r[0]}/login/auth")
            print(f"[✓] Threat Intel Feed: Loaded {len(threat_intel_urls):,} verified malicious domains.")
        except Exception as e:
            print(f"[!] SQLite threat read skipped: {e}")

    for u in threat_intel_urls:
        urls_pool.append(u)
        labels_pool.append(1)

    # 3. Ingest synthetic adversarial evasion zero-days
    print("[*] Generating 6,000 synthetic adversarial zero-day phishing samples...")
    adv_urls = generate_adversarial_phishing_urls(count=6000)
    for u in adv_urls:
        urls_pool.append(u)
        labels_pool.append(1)
    print(f"[✓] Adversarial samples added: {len(adv_urls):,}")

    # 4. Generate deep-path benign samples to balance class distribution
    phish_count = sum(labels_pool)
    needed_benign = max(18000, int(phish_count * 1.5))
    print(f"[*] Generating {needed_benign:,} deep-path enterprise benign URLs...")
    benign_samples = generate_deep_benign_urls(count=needed_benign)
    for u in benign_samples:
        urls_pool.append(u)
        labels_pool.append(0)

    # 5. Deduplicate dataset
    df_raw = pd.DataFrame({"url": urls_pool, "is_phishing": labels_pool})
    df_raw = df_raw.drop_duplicates(subset=["url"]).reset_index(drop=True)

    total_samples = len(df_raw)
    benign_total = sum(df_raw["is_phishing"] == 0)
    phish_total = sum(df_raw["is_phishing"] == 1)
    print(f"\n[✓] Unified Clean Dataset: {total_samples:,} samples")
    print(f"    ├─ Benign (0):   {benign_total:,} ({benign_total/total_samples*100:.1f}%)")
    print(f"    └─ Phishing (1): {phish_total:,} ({phish_total/total_samples*100:.1f}%)\n")

    # 6. Extract 32 features across all samples
    print(f"[*] Extracting 32-dimensional feature matrix across {total_samples:,} URLs...")
    t0 = time.time()
    feature_matrix = []
    for idx, u in enumerate(df_raw["url"]):
        feature_matrix.append(extract_features_vector(u))
        if (idx + 1) % 10000 == 0 or (idx + 1) == total_samples:
            elapsed = time.time() - t0
            print(f"    └─ Processed {idx + 1:,} / {total_samples:,} URLs ({elapsed:.1f}s)")

    feat_df = pd.DataFrame(feature_matrix, columns=FEATURE_NAMES)
    feat_df["url"] = df_raw["url"]
    feat_df["is_phishing"] = df_raw["is_phishing"]

    # Reorder so url and is_phishing are first
    cols = ["url", "is_phishing"] + FEATURE_NAMES
    feat_df = feat_df[cols]

    # Save to CSV
    os.makedirs(os.path.dirname(DATASET_FILE), exist_ok=True)
    feat_df.to_csv(DATASET_FILE, index=False)
    print(f"[✓] Saved expanded dataset to: {DATASET_FILE} ({os.path.getsize(DATASET_FILE)/(1024*1024):.2f} MB)")

    # 7. Model Training & Benchmarking
    print("\n" + "=" * 75)
    print("🧠 TRAINING ENTERPRISE 32-FEATURE RANDOM FOREST CLASSIFIER")
    print("=" * 75)

    X = feat_df[FEATURE_NAMES]
    y = feat_df["is_phishing"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )

    print(f"[*] Training Set: {len(X_train):,} samples | Test Set: {len(X_test):,} samples")
    print("[*] Optimizing Random Forest (100 estimators, max_depth=22, class_weight='balanced')...")

    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=22,
        min_samples_split=4,
        class_weight="balanced",
        random_state=42,
        n_jobs=1  # Safe on Python 3.14 macOS
    )

    t_train = time.time()
    model.fit(X_train, y_train)
    train_duration = time.time() - t_train
    print(f"[✓] Training Completed in {train_duration:.2f} seconds.")

    # 8. Evaluation Metrics
    y_pred = model.predict(X_test)
    y_prob = model.predict_proba(X_test)[:, 1]

    acc = accuracy_score(y_test, y_pred)
    auc = roc_auc_score(y_test, y_prob)

    print("\n" + "-" * 75)
    print(f"🎯 BENCHMARK RESULTS (32 FEATURES):")
    print(f"   Accuracy Score:  {acc * 100:.2f}%")
    print(f"   ROC-AUC Score:   {auc:.4f}")
    print("-" * 75)
    print(classification_report(y_test, y_pred, target_names=["Safe (0)", "Phishing (1)"]))

    # 9. Top Feature Importances
    importances = model.feature_importances_
    ranked_indices = np.argsort(importances)[::-1]
    print("📊 TOP 10 MOST INFLUENTIAL FEATURES:")
    for rank, idx in enumerate(ranked_indices[:10], start=1):
        print(f"   {rank:2d}. {FEATURE_NAMES[idx]:<28} : {importances[idx]*100:.2f}%")

    # 10. Save Model Package
    package = {
        "model": model,
        "feature_names": FEATURE_NAMES,
        "num_features": len(FEATURE_NAMES),
        "accuracy": acc,
        "roc_auc": auc,
        "trained_date": time.strftime("%Y-%m-%d %H:%M:%S"),
        "total_samples": total_samples
    }
    joblib.dump(package, MODEL_FILE)
    print(f"\n[✓] Saved production model package to: {MODEL_FILE}")
    print("[✓] Enterprise pipeline ready for live deployment.")

if __name__ == "__main__":
    build_enterprise_dataset_and_train()
