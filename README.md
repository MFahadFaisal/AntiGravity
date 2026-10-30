# 🛡️ AntiGravity v2.0: Zero-Trust AI Web Security & Phishing Defense Platform

[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-009688?style=for-the-badge&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![Chrome Extension](https://img.shields.io/badge/Chrome_Extension-MV3-4285F4?style=for-the-badge&logo=google-chrome&logoColor=white)](https://developer.chrome.com/docs/extensions/)
[![Scikit-Learn](https://img.shields.io/badge/Scikit--Learn-F7931E?style=for-the-badge&logo=scikit-learn&logoColor=white)](https://scikit-learn.org/)
[![WebSocket](https://img.shields.io/badge/WebSocket-Real--Time-010101?style=for-the-badge&logo=socketdotio&logoColor=white)](https://fastapi.tiangolo.com/advanced/websockets/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](https://opensource.org/licenses/MIT)

**AntiGravity** is an enterprise-grade, real-time **Zero-Trust Web Security, Phishing Detection, and Digital Forensics** platform. It pairs an active **Google Chrome Manifest V3 Browser Agent** (featuring an interactive toolbar popup and Shadow DOM blocking overlay) with a high-throughput **FastAPI Machine Learning Backend** and an integrated **SOC (Security Operations Center)** dashboard connected via **WebSockets** to shield users from fraudulent portals, brand impersonations, credential harvesting traps, and zero-day threats in real time.

---

## 📑 Table of Contents
- [Architecture Overview](#-architecture-overview)
- [Key Features](#-key-features)
  - [1. Chrome Agent (Manifest V3) with Toolbar Popup](#1-chrome-agent-manifest-v3-with-toolbar-popup)
  - [2. Multi-Layered AI Engine & Zero-Day Traps](#2-multi-layered-ai-engine--zero-day-traps)
  - [3. SOC & Digital Forensics Suite with WebSockets](#3-soc--digital-forensics-suite-with-websockets)
- [Zero-Day Detection Pipeline](#-zero-day-detection-pipeline)
- [🧬 Dataset Engineering & Evolution](#-dataset-engineering--evolution)
  - [The Flaws of Legacy Datasets](#the-flaws-of-legacy-datasets)
  - [The v2.0 Modern Dataset (modern_phishing_dataset_2026.csv)](#the-v20-modern-dataset-modern_phishing_dataset_2026csv)
  - [Dataset Inventory & Roles](#dataset-inventory--roles)
- [Feature Engineering (22 Lexical & Structural Metrics)](#-feature-engineering-22-lexical--structural-metrics)
- [Repository Structure](#-repository-structure)
- [Quick Start Guide](#-quick-start-guide)
  - [Prerequisites](#prerequisites)
  - [1. Backend Setup](#1-backend-setup)
  - [2. Chrome Extension Setup](#2-chrome-extension-setup)
- [API Reference](#-api-reference)
- [Machine Learning Benchmark (98.75% Accuracy)](#-machine-learning-benchmark-9875-accuracy)
- [Forensic Evidence & Integrity Verification](#-forensic-evidence--integrity-verification)
- [License](#-license)

---

## 🚀 Architecture Overview

```
                          +------------------------------------------+
                          |           CLIENT ENVIRONMENT             |
                          |                                          |
                          |      [ popup.html (Toolbar UI) ]         |
                          |       - Live risk meter & engine status  |
                          |       - 1-click Whitelist & Phish Report |
                          |                                          |
                          |      [ content.js (Content Script) ]     |
                          |       - Telemetry & DOM feature scrape   |
                          |       - Credential form trap on cloud    |
                          |       - MutationObserver ad/script trap  |
                          |       - Click interception on anchors    |
                          |       - Isolated Shadow DOM Shield       |
                          +--------------------+---------------------+
                                               |
                                     (chrome.runtime msg)
                                               v
                          +------------------------------------------+
                          |    [ background.js (Service Worker) ]    |
                          |       - CORS-free proxy bridge           |
                          |       - Native Chrome OS notifications   |
                          +--------------------+---------------------+
                                               |
                                   (HTTP POST 127.0.0.1:8001)
                                               v
+-----------------------------------------------------------------------------------------+
|                          FASTAPI AI ENGINE & DETECTION SERVER                           |
|                                                                                         |
|  [Layer 1: System Domain Guard]  -> Pass-through for Google, OpenAI, GitHub, etc.      |
|  [Layer 2: Custom Whitelist]     -> SQLite-backed operator domain bypass                |
|  [Layer 3: Punycode / IDN Trap]  -> Blocks internationalized lookalikes (xn--...)       |
|  [Layer 4: Credential Trap]      -> Blocks password inputs on free cloud hosts (Vercel) |
|  [Layer 5: Brand Spoofing Trap]  -> Blocks brand names in subdomains on foreign hosts   |
|  [Layer 6: Threat Intelligence]  -> Active PhishTank database lookup (25,000+ entries)  |
|  [Layer 7: Machine Learning]     -> 22-Feature Random Forest (98.75% Accuracy, No Pad)  |
|  [Layer 8: OSINT Web Scraper]    -> Live multi-engine reputation check (DDG, Bing)      |
|  [Layer 9: Evidence Logger]      -> Quarantined HTML capture in SQLite database          |
+--------------------------------------------+--------------------------------------------+
                                             | (WebSocket /ws/logs)
                                             v
                          +------------------------------------------+
                          |          SOC FORENSIC DASHBOARD          |
                          |               (/dashboard)               |
                          |  - Real-time WebSocket streaming         |
                          |  - Defanged URLs (hxxp://...[.]...)      |
                          |  - Sandboxed HTML evidence downloader    |
                          |  - SHA-256 cryptographically signed logs |
                          |  - MITRE ATT&CK taxonomy tags            |
                          +------------------------------------------+
```

---

## ✨ Key Features

### 1. Chrome Agent (Manifest V3) with Toolbar Popup
* **Interactive Extension Popup (`popup.html` & `popup.js`)**: An operator toolbar interface displaying the real-time AI engine connection status, the active tab's risk score (0-100%), 1-click domain whitelisting, 1-click phishing reporting, and a shortcut to the SOC Console.
* **Credential Form Trap**: Detects `<input type="password">` and credit card fields hosted on unverified or free cloud application providers (e.g. Vercel, Netlify, Firebase, ngrok, GitHub Pages) and alerts the AI Engine immediately.
* **Dynamic Injection Defense**: Uses a live `MutationObserver` to monitor DOM changes, proactively destroying dynamically injected ad or malicious `<script>` and `<iframe>` elements before execution.
* **Search-Engine-Aware Non-Blocking Alerts**: Differentiates search engine result pages (Google, Bing, DuckDuckGo) from target landing pages. Rather than locking down the search engine when phishing hits are found in search snippets, it displays a non-intrusive warning toast and arms **Link Click Interception**.
* **Link Interception Engine**: Inspects anchor clicks prior to browser navigation, validating destination URLs against the AI Engine before the page is requested.
* **Tamper-Proof Shadow DOM Overlay**: When a hard block is enforced, renders a zero-dependency full-screen shield within a closed **Shadow Root** (`#antigravity-shield`). Malicious website stylesheets or scripts cannot hide, bypass, or tamper with the shield.

### 2. Multi-Layered AI Engine & Zero-Day Traps
* **Punycode / IDN Homograph Defense**: Automatically unmasks and blocks Cyrillic/Greek lookalike domain spoofing (`xn--...`).
* **Brand Impersonation in Subdomains**: Flags domains where high-profile brands (e.g. PayPal, Apple, Binance, Microsoft, Google) appear in subdomains or paths on unauthorized hosts (e.g., `paypal-verify.security-update.xyz`).
* **Real-Time 22-Feature ML Model**: Powered by a calibrated Random Forest classifier trained directly on real-world PhishTank data and top web properties with **zero dummy padding**.
* **Active PhishTank Threat Intel Feed**: A background thread asynchronously synchronizes verified active malicious URLs directly from PhishTank into the local SQLite database cache (25,000+ cached threats).
* **Real-Time OSINT Reputation Scraper**: Performs automated web intelligence scraping across DuckDuckGo, Bing, and Yahoo to aggregate threat signals, user complaints, and fraudulent domain disclosures.

### 3. SOC & Digital Forensics Suite with WebSockets
* **Live WebSocket Streaming (`/ws/logs`)**: High-performance real-time telemetry streaming pushes new alerts to connected analysts without HTTP polling delay.
* **MITRE ATT&CK Tagging**: Categorizes incidents using standard cyber threat intelligence taxonomies (e.g. `T1566.002: Spearphishing Link`, `T1056: Input Capture`, `T1566.002: Homograph Phishing`).
* **Defanged URL Safety**: Defangs all displayed indicators of compromise (`http://bad.com` $\to$ `hxxp://bad[.]com`) to protect security operations personnel from accidental navigation.
* **HTML Evidence Quarantine**: Captures up to 150KB of sanitized HTML source code at the moment of compromise and archives it for forensic review.
* **Cryptographic Tamper-Proof Reporting**: Exports complete forensic incident reports with a verifiable **SHA-256 digital signature** ensuring chain-of-custody validity.

---

## 🔍 Zero-Day Detection Pipeline

```
[ Incoming Request (/analyze) ]
               │
               ▼
   [ Is System Safe Domain? ] ───( YES )───► ALLOW (Clean Traffic)
               │ (NO)
               ▼
   [ Is In Custom Whitelist? ] ──( YES )───► ALLOW (Whitelisted)
               │ (NO)
               ▼
   [ IDN Punycode Spoofing? ] ───( YES )───► BLOCK (T1566.002: Homograph Phishing)
               │ (NO)
               ▼
   [ Password on Free Host? ] ───( YES )───► BLOCK (T1056: Credential Harvesting)
               │ (NO)
               ▼
   [ Brand Spoofing in Subdomain? ] ──► BLOCK (T1566.002: Brand Impersonation)
               │ (NO)
               ▼
   [ Explicit / Adult Regex? ] ──( YES )───► BLOCK (Policy Violation)
               │ (NO)
               ▼
   [ In PhishTank Local DB? ] ───( YES )───► BLOCK / SUSPICIOUS (Confirmed Intel)
               │ (NO)
               ▼
   [ Random Forest (22 Feats) ] ─( YES )───► BLOCK / SUSPICIOUS (ML Phishing Pattern)
               │ (NO)
               ▼
   [ OSINT Scam Score >= 3? ] ───( YES )───► BLOCK / SUSPICIOUS (OSINT Threat Alert)
               │ (NO)
               ▼
   [ Illegal Gambling Regex? ] ──( YES )───► BLOCK / SUSPICIOUS (Gambling Policy)
               │ (NO)
               ▼
         ALLOW (Clean Traffic)
```

---

## 🧬 Dataset Engineering & Evolution

A critical breakthrough in AntiGravity v2.0 is resolving the **dataset mismatch and staleness problem** found in early academic phishing projects.

### The Flaws of Legacy Datasets
1. **The 2015 UCI Dataset (`dataset.csv`)**: Contains 30 handcrafted features from 2015. Over 85% of modern phishing campaigns now use valid SSL certificates via Let's Encrypt / Cloudflare, making UCI's reliance on `SSLfinal_State` obsolete.
2. **The Dummy Padding Flaw**: The original backend only calculated 8 real URL features at runtime and filled the remaining 21 features with hardcoded `-1` dummy values, forcing the model to guess with 70% missing data.
3. **Email vs Web Mismatch**: Legacy files like `Nazario.csv`, `SpamAssasin.csv`, and `CEAS_08.csv` were raw email text collections, completely unused by real-time web URL classifiers.

### The v2.0 Modern Dataset (`modern_phishing_dataset_2026.csv`)
AntiGravity v2.0 includes a newly extracted, fully persistent dataset built for reproducible research:
* **24,000 Real-World Samples:** Balanced 50/50 split between 12,000 verified malicious URLs from active PhishTank feeds and 12,000 legitimate URLs from Tranco/Alexa top web properties.
* **Zero Dummy Padding:** Every single one of the 22 lexical, structural, and social engineering features is genuinely calculated.
* **Persisted in CSV:** Located at [ai_engine/datasets/modern_phishing_dataset_2026.csv](file:///Users/fahadfaisal/Downloads/AntiGravity/ai_engine/datasets/modern_phishing_dataset_2026.csv) (2.3 MB) for instant inspection in Excel, Pandas, or Jupyter Notebooks.

### Dataset Inventory & Roles

| File | Type | Sample Count | Status / Role in v2.0 |
| :--- | :--- | :--- | :--- |
| `modern_phishing_dataset_2026.csv` | Lexical & Structural URL | **24,000** | **Primary Modern Training Dataset** (22 Features, 0 Padding) |
| `dataset.csv` | Tabular Academic | 11,055 | Retained as 2015 UCI baseline benchmark |
| `uci-ml-phishing-dataset.csv` | Tabular Academic | 11,055 | UCI mirror dataset |
| `Nazario.csv` | Email Phishing Corpus | ~2,500 emails | Archived NLP email corpus |
| `SpamAssasin.csv` | Email Spam Corpus | ~6,000 emails | Archived NLP email corpus |
| `spam.csv` | SMS Spam Corpus | ~5,500 messages| Archived NLP text corpus |

---

## 📊 Feature Engineering (22 Lexical & Structural Metrics)

AntiGravity v2.0 inspects URLs across 22 engineered features computed in $<0.5\text{ms}$ with zero dummy padding:

| Feature Name | Description | Phishing Indicator |
| :--- | :--- | :--- |
| `domain_length` | Hostname character count | Exceptionally long randomized hostnames |
| `path_length` | URL path length | Deep nested paths masking true destinations |
| `suspicious_keywords_count` | Count of `login`, `verify`, `banking`, `wallet`, etc. | Aggressive social engineering triggers |
| `num_slashes` | Directory depth | Complex obfuscated redirects |
| `free_hosting_provider` | Hosted on Vercel, Firebase, Netlify, ngrok, etc. | Disposable, free phishing infrastructure |
| `brand_spoofing` | Brand name in subdomain on foreign registered domain | Classic brand impersonation |
| `has_punycode` | Presence of `xn--` in hostname | Lookalike visual Unicode deception |
| `has_ip_address` | Raw IPv4/IPv6 used as host | Direct server connection evading DNS |
| `has_shortener` | Bit.ly, TinyURL, t.co, is.gd, etc. | Destination masking |
| `shannon_entropy` | Character distribution randomness ($H(X)$) | Algorithmic / DGA domain generation |
| `suspicious_tld` | High-risk TLDs (`.xyz`, `.top`, `.cfd`, `.icu`, etc.) | Cheap, disposable malicious TLD registration |
| `digit_ratio` | Ratio of digits to total URL length | Randomized tracking hashes |
| `num_subdomains` | Dot count minus 1 in hostname | Multi-level subdomain masquerading |
| `num_hyphens` | Hyphen character count | Fake brand hyphenation (`paypal-login-portal`) |
| `num_special_chars` | Special characters (`@`, `?`, `=`, `&`, `%`, `+`) | Query obfuscation & basic auth injection |

---

## 📁 Repository Structure

```
AntiGravity/
├── README.md                          # Comprehensive documentation
├── .gitignore                         # Git ignore configuration
│
├── browser_agent/                     # Chrome Extension (Manifest V3)
│   ├── manifest.json                  # Extension permissions & entry points (v2.0)
│   ├── icon16.png, icon32.png...      # High-DPI custom shield branding icons
│   ├── popup.html                     # Toolbar popup user interface
│   ├── popup.js                       # Popup controller & status monitor
│   ├── background.js                  # Service worker & proxy bridge
│   └── content.js                     # Content script, DOM observer & Shadow DOM shield
│
└── ai_engine/                         # Backend Engine, ML & SOC Dashboard
    ├── main.py                        # FastAPI application & real-time engine
    ├── feature_extractor.py           # 22-Feature engineering module
    ├── train_modern_url_model.py      # Modern training pipeline (PhishTank + Tranco)
    ├── update_threat_data.py          # Automated threat ingestion & retraining pipeline
    ├── dashboard.html                 # WebSocket-enabled SOC & Forensics console
    ├── antigravity_url_model.pkl      # Calibrated Random Forest model (98.65%+ Acc)
    ├── antigravity_logs.db            # SQLite operational database (25k+ threat intel)
    └── datasets/                      # Phishing benchmark datasets
        ├── modern_phishing_dataset_2026.csv # 24,400+ sample modern dataset (Primary)
        ├── dataset.csv                # UCI tabular phishing features (Baseline)
        ├── uci-ml-phishing-dataset.csv# UCI dataset mirror
        └── legacy_email_archive/      # Archived raw email spam corpora (Nazario, SpamAssassin)
```

---

## 🛠️ Quick Start Guide

### Prerequisites
* **Operating System**: macOS, Linux, or Windows
* **Python**: Version `3.10` or higher
* **Google Chrome**: Version 100+ (or any Chromium-based browser supporting MV3)

---

### 1. Backend Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/MFahadFaisal/AntiGravity.git
   cd AntiGravity
   ```

2. **Install required dependencies:**
   ```bash
   pip3 install fastapi uvicorn requests beautifulsoup4 scikit-learn pandas joblib websockets
   ```

3. **Start the AI Engine:**
   ```bash
   python3 ai_engine/main.py
   ```
   *The server starts on `http://127.0.0.1:8001`.*

4. **Verify the SOC Dashboard:**
   Open [http://127.0.0.1:8001/dashboard](http://127.0.0.1:8001/dashboard) in your web browser. You will see the live WebSocket beacon (`CANLI (WS)`).

---

### 2. Chrome Extension Setup

1. Open **Google Chrome** and navigate to:
   ```
   chrome://extensions/
   ```
2. Enable the **Developer mode** toggle in the top-right corner.
3. Click the **Load unpacked** (*Paketlenmemiş öğe yükle*) button in the top-left corner.
4. Select the `browser_agent` folder from this repository:
   ```
   AntiGravity/browser_agent
   ```
5. Click the extension icon in your browser toolbar to open the **AntiGravity Security Popup**!

---

## 📡 API Reference

The FastAPI backend exposes the following REST & WebSocket endpoints:

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/analyze` | Primary analysis endpoint used by the Chrome Agent. |
| `WS`   | `/ws/logs` | Real-time WebSocket stream pushing new security events to the SOC. |
| `POST` | `/api/report-phish`| Submits user-reported phishing links into threat intelligence. |
| `GET`  | `/api/logs` | Returns aggregated scan statistics and the latest 500 log events. |
| `GET`  | `/api/details/{log_id}` | Retrieves full diagnostic metadata for a specific incident. |
| `GET`  | `/api/evidence/{log_id}` | Downloads sandboxed raw HTML evidence for an incident. |
| `GET`  | `/api/export-report` | Generates a JSON forensic audit report with SHA-256 integrity hash. |
| `GET`  | `/api/whitelist` | Lists all operator-configured whitelisted domains. |
| `POST` | `/api/whitelist/add` | Adds a domain to the permanent whitelist. |
| `POST` | `/api/whitelist/remove` | Removes a domain from the whitelist. |
| `DELETE`| `/api/logs` | Clears all operational logs from the SQLite database. |
| `GET`  | `/dashboard` | Serves the interactive SOC Operations Center web interface. |

---

## 🧠 Machine Learning Benchmark (98.75% Accuracy)

The model is trained using `train_modern_url_model.py` on 24,000 real-world samples (12,000 active PhishTank malicious URLs + 12,000 top web properties):

```bash
python3 ai_engine/train_modern_url_model.py
```

### Evaluation Benchmark
* **Accuracy:** `98.75%`
* **ROC-AUC Score:** `0.9996`
* **Precision (Phishing):** `0.98`
* **Recall (Phishing):** `0.99`

```
Confusion Matrix:
  True Negatives (Safe):      2354
  False Positives (Alarm):    46
  False Negatives (Missed):   14
  True Positives (Blocked):   2386
```

### 🔄 Automated Self-Updating Threat Ingestion Pipeline
Phishing campaigns frequently rotate domain infrastructure every 48–72 hours. AntiGravity includes a continuous threat ingestion and model refresher script:

```bash
# Ingest fresh threats from threat intelligence and retrain in seconds
python3 ai_engine/update_threat_data.py

# Or append newly discovered threats without retraining
python3 ai_engine/update_threat_data.py --no-retrain
```
* **Deduplication:** Automatically queries the database cache and external feeds, deduplicates incoming URLs against `modern_phishing_dataset_2026.csv`.
* **Zero-Downtime Retraining:** Recalculates the 22 feature vectors and updates `antigravity_url_model.pkl` in-place.

---

## 🔒 Forensic Evidence & Integrity Verification

To support digital forensics investigations, AntiGravity implements chain-of-custody controls:
1. **Quarantine Isolation**: Downloaded HTML evidence is served with strict `X-Content-Type-Options: nosniff` and `Content-Security-Policy: sandbox` headers to prevent stored XSS or script execution during analysis.
2. **Cryptographic Integrity (SHA-256)**: Exported JSON audit reports calculate a canonical SHA-256 digest over the entire incident record array:
   $$\text{Digest} = \text{SHA256}(\text{JSON}(\text{Records}))$$
   Any post-export modification or tampering invalidates the hash.

---

## 📄 License

This project is licensed under the **MIT License**. See the `LICENSE` file for details.
