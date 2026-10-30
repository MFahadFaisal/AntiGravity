import os
import sys
import sqlite3
import random
import pandas as pd
import numpy as np
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix, roc_auc_score

# Ensure feature_extractor can be imported
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from feature_extractor import extract_features_vector, FEATURE_NAMES

# High-reputation legitimate base domains (sample of top web properties)
TOP_LEGIT_DOMAINS = [
    "google.com", "youtube.com", "facebook.com", "wikipedia.org", "yahoo.com",
    "amazon.com", "reddit.com", "netflix.com", "microsoft.com", "instagram.com",
    "twitter.com", "linkedin.com", "apple.com", "github.com", "ebay.com",
    "pinterest.com", "wordpress.org", "tumblr.com", "imdb.com", "bing.com",
    "nytimes.com", "cnn.com", "bbc.co.uk", "theguardian.com", "forbes.com",
    "bloomberg.com", "reuters.com", "espn.com", "walmart.com", "target.com",
    "stackoverflow.com", "medium.com", "quora.com", "craigslist.org", "yelp.com",
    "dropbox.com", "spotify.com", "paypal.com", "chase.com", "bankofamerica.com",
    "wellsfargo.com", "adobe.com", "salesforce.com", "shopify.com", "slack.com",
    "zoom.us", "twitch.tv", "hulu.com", "disneyplus.com", "weather.com",
    "nih.gov", "cdc.gov", "nasa.gov", "harvard.edu", "mit.edu", "stanford.edu",
    "berkeley.edu", "ox.ac.uk", "cam.ac.uk", "nature.com", "sciencedirect.com",
    "cloudflare.com", "digitalocean.com", "gitlab.com", "bitbucket.org", "docker.com",
    "kernel.org", "python.org", "mozilla.org", "apache.org", "w3schools.com",
    "freecodecamp.org", "geeksforgeeks.org", "khanacademy.org", "coursera.org", "edx.org",
    "aliexpress.com", "booking.com", "tripadvisor.com", "airbnb.com", "uber.com",
    "lyft.com", "doordash.com", "instacart.com", "etsy.com", "ikea.com",
    "homedepot.com", "bestbuy.com", "costco.com", "steamcommunity.com", "steampowered.com",
    "roblox.com", "epicgames.com", "playstation.com", "xbox.com", "nintendo.com"
]

BENIGN_PATHS = [
    "", "/", "/about", "/contact", "/privacy-policy", "/terms", "/help",
    "/faq", "/search?q=technology", "/search?q=cybersecurity", "/explore",
    "/news/article-2026", "/blog/how-to-guide", "/products/item-38291",
    "/docs/v1/getting-started", "/category/science-and-nature",
    "/profile/user_981", "/feed?page=2", "/api/v2/status", "/support/knowledge-base"
]

def generate_legitimate_urls(target_count=12000):
    """Generates realistic legitimate URL variations from verified domains."""
    urls = []
    schemes = ["https://", "https://www.", "http://www."]
    
    while len(urls) < target_count:
        domain = random.choice(TOP_LEGIT_DOMAINS)
        scheme = random.choice(schemes)
        path = random.choice(BENIGN_PATHS)
        
        # Add random query params occasionally
        if random.random() < 0.25 and "?" not in path:
            param = f"?ref=nav&page={random.randint(1, 10)}&lang=en"
            path += param
            
        url = f"{scheme}{domain}{path}"
        urls.append(url)
    return urls

def load_phishing_urls_from_db(db_path, limit=12000):
    """Loads verified phishing domains/URLs from the SQLite threat intelligence table."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT domain FROM threat_intel ORDER BY RANDOM() LIMIT ?", (limit,))
    rows = cursor.fetchall()
    conn.close()

    phish_urls = []
    schemes = ["http://", "https://"]
    for row in rows:
        domain = row[0]
        scheme = random.choice(schemes)
        # Some have paths, some are domain roots
        if random.random() < 0.4:
            path = random.choice([
                "/login", "/verify", "/account/update", "/signin.php",
                "/auth/session", "/secure/validation", "/wallet/confirm",
                "/webscr?cmd=_login-run", "/service/billing"
            ])
        else:
            path = ""
        phish_urls.append(f"{scheme}{domain}{path}")
    return phish_urls

def train_and_export_modern_model():
    print("[*] Starting AntiGravity Modern Feature-Engineered ML Pipeline...")
    base_dir = os.path.dirname(os.path.abspath(__file__))
    db_path = os.path.join(base_dir, "antigravity_logs.db")
    model_output_path = os.path.join(base_dir, "antigravity_url_model.pkl")

    # 1. Gather Real Phishing URLs
    print("[*] Querying verified phishing threat feeds from SQLite...")
    phish_urls = load_phishing_urls_from_db(db_path, limit=12000)
    print(f"[✓] Retrieved {len(phish_urls)} phishing URLs from PhishTank threat intel.")

    # 2. Generate Legitimate URLs
    print("[*] Generating legitimate URL samples across top web properties...")
    legit_urls = generate_legitimate_urls(target_count=len(phish_urls))
    print(f"[✓] Generated {len(legit_urls)} legitimate baseline URLs.")

    # 3. Extract 22 Features for every URL (Zero Dummy Padding!)
    print(f"[*] Extracting 22 lexical & structural features for all {len(phish_urls) + len(legit_urls)} URLs...")
    X_rows = []
    y_labels = []
    all_urls = []

    for url in legit_urls:
        X_rows.append(extract_features_vector(url))
        y_labels.append(0)  # 0: Legitimate / Safe
        all_urls.append(url)

    for url in phish_urls:
        X_rows.append(extract_features_vector(url))
        y_labels.append(1)  # 1: Phishing / Malicious
        all_urls.append(url)

    df = pd.DataFrame(X_rows, columns=FEATURE_NAMES)
    y = np.array(y_labels)

    # Persist modern dataset for data scientists, audits & research
    dataset_export_df = df.copy()
    dataset_export_df.insert(0, "url", all_urls)
    dataset_export_df["is_phishing"] = y_labels
    datasets_dir = os.path.join(base_dir, "datasets")
    os.makedirs(datasets_dir, exist_ok=True)
    export_csv_path = os.path.join(datasets_dir, "modern_phishing_dataset_2026.csv")
    dataset_export_df.to_csv(export_csv_path, index=False)
    print(f"[✓] Exported modern dataset ({len(dataset_export_df)} samples) to: {export_csv_path}")

    print(f"[✓] Feature matrix built: shape {df.shape}")
    print(f"[*] Class Distribution:\n  - Safe (0): {sum(y == 0)}\n  - Phishing (1): {sum(y == 1)}")

    # 4. Train/Test Split
    X_train, X_test, y_train, y_test = train_test_split(
        df, y, test_size=0.20, random_state=42, stratify=y
    )

    # 5. Train Random Forest Classifier
    print("[*] Training calibrated Random Forest Classifier (150 trees, max_depth=16)...")
    clf = RandomForestClassifier(
        n_estimators=150,
        max_depth=16,
        min_samples_split=6,
        min_samples_leaf=2,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1
    )
    clf.fit(X_train, y_train)

    # 6. Evaluate
    y_pred = clf.predict(X_test)
    y_prob = clf.predict_proba(X_test)[:, 1]
    acc = accuracy_score(y_test, y_pred)
    roc = roc_auc_score(y_test, y_prob)
    cm = confusion_matrix(y_test, y_pred)

    print("\n" + "=" * 60)
    print("      ANTIGRAVITY MODERN ML CLASSIFIER EVALUATION")
    print("=" * 60)
    print(f"Accuracy:  {acc * 100:.2f}%")
    print(f"ROC-AUC:   {roc:.4f}")
    print("\nConfusion Matrix:")
    print(f"  True Negatives (Safe):      {cm[0][0]}")
    print(f"  False Positives (Alarm):    {cm[0][1]}")
    print(f"  False Negatives (Missed):   {cm[1][0]}")
    print(f"  True Positives (Blocked):   {cm[1][1]}")
    print("\nDetailed Classification Report:")
    print(classification_report(y_test, y_pred, target_names=["Safe (0)", "Phishing (1)"]))
    print("=" * 60)

    # Feature Importances
    importances = pd.Series(clf.feature_importances_, index=FEATURE_NAMES).sort_values(ascending=False)
    print("\nTop 10 Most Important Features:")
    for feat, imp in importances.head(10).items():
        print(f"  {feat:<28}: {imp:.4f}")

    # 7. Save Model & Feature Schema
    package = {
        "model": clf,
        "feature_names": FEATURE_NAMES,
        "version": "2.0-lexical-realtime",
        "accuracy": acc,
        "roc_auc": roc
    }
    joblib.dump(package, model_output_path)
    print(f"\n[✓] Modern model successfully saved to: {model_output_path}")

if __name__ == "__main__":
    train_and_export_modern_model()
