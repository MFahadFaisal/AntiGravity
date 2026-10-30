# 🛡️ AntiGravity: Zero-Trust AI Web Security & Phishing Defense Platform

[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-009688?style=for-the-badge&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![Chrome Extension](https://img.shields.io/badge/Chrome_Extension-MV3-4285F4?style=for-the-badge&logo=google-chrome&logoColor=white)](https://developer.chrome.com/docs/extensions/)
[![Scikit-Learn](https://img.shields.io/badge/Scikit--Learn-F7931E?style=for-the-badge&logo=scikit-learn&logoColor=white)](https://scikit-learn.org/)
[![SQLite](https://img.shields.io/badge/SQLite-003B57?style=for-the-badge&logo=sqlite&logoColor=white)](https://www.sqlite.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](https://opensource.org/licenses/MIT)

**AntiGravity** is an enterprise-grade, real-time **Zero-Trust Web Security, Phishing Detection, and Digital Forensics** platform. It pairs an active **Google Chrome Manifest V3 Browser Agent** with a high-throughput **FastAPI Machine Learning Backend** and an integrated **SOC (Security Operations Center)** dashboard to shield users from fraudulent portals, malicious scripts, illegal gambling, and credential harvesting in real time.

---

## 📑 Table of Contents
- [Architecture Overview](#-architecture-overview)
- [Key Features](#-key-features)
  - [1. Chrome Agent (Manifest V3)](#1-chrome-agent-manifest-v3)
  - [2. Multi-Layered AI Engine](#2-multi-layered-ai-engine)
  - [3. SOC & Digital Forensics Suite](#3-soc--digital-forensics-suite)
- [Detection Pipeline](#-detection-pipeline)
- [Repository Structure](#-repository-structure)
- [Quick Start Guide](#-quick-start-guide)
  - [Prerequisites](#prerequisites)
  - [1. Backend Setup](#1-backend-setup)
  - [2. Chrome Extension Setup](#2-chrome-extension-setup)
- [API Reference](#-api-reference)
- [Machine Learning & Model Training](#-machine-learning--model-training)
- [Forensic Evidence & Integrity Verification](#-forensic-evidence--integrity-verification)
- [License](#-license)

---

## 🚀 Architecture Overview

```
                          +------------------------------------------+
                          |           CLIENT ENVIRONMENT             |
                          |                                          |
                          |      [ content.js (Content Script) ]     |
                          |       - Telemetry & DOM feature scrape   |
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
|                               FASTAPI AI ENGINE & SERVER                                |
|                                                                                         |
|  [Layer 1: System Domain Guard]  -> Pass-through for Google, OpenAI, GitHub, etc.      |
|  [Layer 2: Custom Whitelist]     -> SQLite-backed operator domain bypass                |
|  [Layer 3: Heuristic Filters]    -> Fast-path regex checks for explicit & gambling hits |
|  [Layer 4: Threat Intelligence]  -> Active PhishTank database lookup (25,000+ entries)  |
|  [Layer 5: Machine Learning]     -> Random Forest Classifier (30+ structural features)  |
|  [Layer 6: OSINT Scraper]        -> Live multi-engine reputation check (DDG, Bing)      |
|  [Layer 7: Evidence Logger]      -> Quarantined HTML capture in SQLite database          |
+--------------------------------------------+--------------------------------------------+
                                             |
                                             v
                          +------------------------------------------+
                          |          SOC FORENSIC DASHBOARD          |
                          |               (/dashboard)               |
                          |  - Real-time event ledger & ticker tape  |
                          |  - Defanged URLs (hxxp://...[.]...)      |
                          |  - Sandboxed HTML evidence downloader    |
                          |  - SHA-256 cryptographically signed logs |
                          +------------------------------------------+
```

---

## ✨ Key Features

### 1. Chrome Agent (Manifest V3)
* **Zero Overhead Sensor (`content.js`)**: Gathers lightweight page telemetry (URL, title, 1,500 characters of inner text, and raw HTML document structure) on window load.
* **Dynamic Injection Defense**: Uses a live `MutationObserver` to monitor DOM tree changes, proactively destroying dynamically injected ad or malicious `<script>` and `<iframe>` elements before execution.
* **Search-Engine-Aware Non-Blocking Alerts**: Differentiates search engine result pages (Google, Bing, DuckDuckGo) from target landing pages. Rather than locking down the search engine when phishing hits are found in search snippets, it displays a non-intrusive warning toast and arms **Link Click Interception**.
* **Link Interception Engine**: Inspects anchor clicks prior to browser navigation, validating destination URLs against the AI Engine before the page is requested.
* **Tamper-Proof Shadow DOM Overlay**: When a hard block is enforced, renders a zero-dependency full-screen shield within a closed **Shadow Root** (`#antigravity-shield`). Malicious website stylesheets or scripts cannot hide, bypass, or tamper with the shield.

### 2. Multi-Layered AI Engine
* **Pre-Emptive Whitelist & System Domain Guard**: Guarantees zero false positives on essential developer and productivity platforms (Google Workspace, GitHub, OpenAI, etc.).
* **Active PhishTank Threat Intel Feed**: A background thread asynchronously synchronizes verified active malicious URLs directly from PhishTank into the local SQLite database cache.
* **Random Forest ML Classification**: Inspects URLs using 30+ engineered attributes, including IP-based addresses, length thresholds, shortener detection (`bit.ly`, `tinyurl`), abnormal subdomains, and high-risk top-level domains (`.xyz`, `.top`, `.tk`, `.ml`, `.site`, `.online`, etc.).
* **Real-Time OSINT Reputation Scraper**: Performs automated web intelligence scraping across DuckDuckGo, Bing, and Yahoo to aggregate threat signals, user complaints, and fraudulent domain disclosures.

### 3. SOC & Digital Forensics Suite
* **Real-Time Analyst Console (`/dashboard`)**: Dark forensic user interface with live telemetry, event volume counters, risk distributions, and recent scan tickers.
* **Defanged URL Safety**: Defangs all displayed indicators of compromise (`http://bad.com` $\to$ `hxxp://bad[.]com`) to protect security operations personnel from accidental navigation.
* **HTML Evidence Quarantine**: Captures up to 150KB of sanitized HTML source code at the moment of compromise and archives it for forensic review.
* **Cryptographic Tamper-Proof Reporting**: Exports complete forensic incident reports with a verifiable **SHA-256 digital signature** ensuring chain-of-custody validity.

---

## 🔍 Detection Pipeline

When a page navigation occurs, AntiGravity follows an orchestrated decision cascade:

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
   [ Explicit / Adult Regex? ] ──( YES )───► BLOCK (Explicit Content Policy)
               │ (NO)
               ▼
   [ In PhishTank Local DB? ] ───( YES )───► BLOCK / SUSPICIOUS (Confirmed Threat Intel)
               │ (NO)
               ▼
   [ Random Forest Predicts? ] ──( YES )───► BLOCK / SUSPICIOUS (Phishing URL Pattern)
               │ (NO)
               ▼
   [ OSINT Scam Score >= 3? ] ───( YES )───► BLOCK / SUSPICIOUS (OSINT Reputation Alert)
               │ (NO)
               ▼
   [ Illegal Gambling Regex? ] ──( YES )───► BLOCK / SUSPICIOUS (Gambling Policy)
               │ (NO)
               ▼
         ALLOW (Clean Traffic)
```

---

## 📁 Repository Structure

```
AntiGravity/
├── README.md                          # Project documentation and guide
├── .gitignore                         # Git ignore configuration
│
├── browser_agent/                     # Chrome Extension (Manifest V3)
│   ├── manifest.json                  # Extension permissions & entry points
│   ├── background.js                  # Service worker & network relay
│   └── content.js                     # Content script, DOM observer & Shadow DOM shield
│
└── ai_engine/                         # Backend Engine, ML & SOC Dashboard
    ├── main.py                        # FastAPI application & detection engine
    ├── dashboard.html                 # SOC & Forensics analyst interface
    ├── train_models.py                # Model training & dataset pipeline
    ├── antigravity_url_model.pkl      # Serialized Random Forest classifier
    ├── antigravity_text_model.pkl     # Pre-trained NLP text classifier
    ├── antigravity_vectorizer.pkl     # Pre-trained TF-IDF vectorizer
    ├── antigravity_logs.db            # SQLite operational database (logs, threats, whitelist)
    └── datasets/                      # Phishing, spam, and legitimate training datasets
        ├── dataset.csv                # UCI tabular phishing features (11,000+ samples)
        ├── uci-ml-phishing-dataset.csv# UCI dataset mirror
        ├── Nazario.csv                # Phishing email corpus
        ├── SpamAssasin.csv            # SpamAssassin benchmark corpus
        ├── CEAS_08.csv                # CEAS 2008 phishing corpus
        └── spam.csv                   # SMS/Message spam dataset
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
   pip3 install fastapi uvicorn requests beautifulsoup4 scikit-learn pandas joblib
   ```

3. **Start the AI Engine:**
   ```bash
   python3 ai_engine/main.py
   ```
   *The server will start on `http://127.0.0.1:8001`.*

4. **Verify the SOC Dashboard:**
   Open [http://127.0.0.1:8001/dashboard](http://127.0.0.1:8001/dashboard) in your web browser. You should see the live status indicator (`CANLI`).

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
5. AntiGravity is now active! As you browse, navigation events are analyzed in real time.

---

## 📡 API Reference

The FastAPI backend exposes the following endpoints:

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/analyze` | Primary analysis endpoint used by the Chrome Agent. |
| `GET` | `/api/logs` | Returns aggregated scan statistics and the latest 500 log events. |
| `GET` | `/api/details/{log_id}` | Retrieves full diagnostic metadata for a specific incident. |
| `GET` | `/api/evidence/{log_id}` | Downloads sandboxed raw HTML evidence for an incident. |
| `GET` | `/api/export-report` | Generates a JSON forensic audit report with SHA-256 integrity hash. |
| `GET` | `/api/whitelist` | Lists all operator-configured whitelisted domains. |
| `POST` | `/api/whitelist/add` | Adds a domain to the permanent whitelist. |
| `POST` | `/api/whitelist/remove` | Removes a domain from the whitelist. |
| `DELETE`| `/api/logs` | Clears all operational logs from the SQLite database. |
| `GET` | `/dashboard` | Serves the interactive SOC Operations Center web interface. |

---

## 🧠 Machine Learning & Model Training

The URL classification model is trained via `train_models.py` using standard supervised learning techniques on lexical and structural domain features:

```bash
python3 ai_engine/train_models.py
```

### Feature Engineering
The model inspects URLs across key indicators:
* **IP Address in URL**: Flags raw IP address hostnames (e.g. `http://192.168.1.1/login`).
* **URL Length Thresholds**: Standardizes character length anomalies.
* **URL Shorteners**: Detects redirection services (`bit.ly`, `tinyurl`, `goo.gl`, etc.).
* **Lexical Markers**: Flags `@` symbol credentials and double-slash `//` redirect patterns.
* **Domain Structure**: Counts subdomain depth and detects hyphens in domains (`-`).
* **TLD Reputation**: Scores high-risk top-level domains (`.xyz`, `.top`, `.tk`, `.ml`, `.site`, etc.).

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
