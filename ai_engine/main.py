import os
import re
import json
import sqlite3
import hashlib
import datetime
import threading
import asyncio
from contextlib import contextmanager
from urllib.parse import urlparse, parse_qs

import requests
from bs4 import BeautifulSoup
import joblib
import pandas as pd
from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, Response
from pydantic import BaseModel

# Import our custom feature engineering & zero-day detection engine
from feature_extractor import (
    extract_features_vector,
    extract_features_dict,
    check_punycode,
    check_brand_spoofing,
    check_free_hosting,
    FEATURE_NAMES
)

app = FastAPI(title="AntiGravity SOC - Real-Time Zero-Trust AI Engine", version="2.0.0")

ALLOWED_ORIGIN_RE = re.compile(r"^(chrome-extension://[a-z]{32}|https?://(127\.0\.0\.1|localhost)(:\d+)?)$")

app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=ALLOWED_ORIGIN_RE.pattern,
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.middleware("http")
async def origin_guard(request: Request, call_next):
    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        origin = request.headers.get("origin")
        if origin and not ALLOWED_ORIGIN_RE.match(origin):
            return JSONResponse(status_code=403, content={"status": "error", "message": "İzin verilmeyen kaynak."})
    return await call_next(request)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_FILE = os.path.join(BASE_DIR, "antigravity_logs.db")
MODEL_FILE = os.path.join(BASE_DIR, "antigravity_url_model.pkl")
EVIDENCE_LIMIT = 150_000

# ------------------------------------------------------------------
# WEBSOCKET REAL-TIME BROADCAST MANAGER
# ------------------------------------------------------------------
class ConnectionManager:
    def __init__(self):
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        for connection in list(self.active_connections):
            try:
                await connection.send_json(message)
            except Exception:
                self.disconnect(connection)

ws_manager = ConnectionManager()

# ------------------------------------------------------------------
# VERİTABANI VE TEHDİT İSTİHBARATI
# ------------------------------------------------------------------
@contextmanager
def db():
    conn = sqlite3.connect(DB_FILE, timeout=10)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()

def init_db():
    with db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                time TEXT,
                date TEXT,
                url TEXT,
                domain TEXT,
                action TEXT,
                reason TEXT,
                target_url TEXT,
                details TEXT,
                detector TEXT,
                created_at TEXT,
                source TEXT,
                url_score INTEGER,
                text_score INTEGER,
                status TEXT
            )
        """)
        cols = [row["name"] for row in conn.execute("PRAGMA table_info(logs)").fetchall()]
        if "evidence" not in cols:
            conn.execute("ALTER TABLE logs ADD COLUMN evidence TEXT")

        conn.execute("""
            CREATE TABLE IF NOT EXISTS whitelist (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT UNIQUE NOT NULL,
                created_at TEXT
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS threat_intel (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT UNIQUE NOT NULL,
                source TEXT,
                added_at TEXT
            )
        """)

init_db()

LOG_COLUMNS = (
    "id, timestamp, time, date, url, domain, action, reason, target_url, details, detector, "
    "created_at, source, url_score, text_score, status, "
    "(evidence IS NOT NULL AND evidence != '') AS has_evidence"
)

def save_log_to_db(log: dict) -> int:
    with db() as conn:
        cursor = conn.execute("""
            INSERT INTO logs (
                timestamp, time, date, url, domain, action, reason,
                target_url, details, detector, created_at, source, url_score, text_score, status, evidence
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            log["timestamp"], log["time"], log["date"], log["url"], log["domain"],
            log["action"], log["reason"], log["target_url"], log["details"],
            log["detector"], log["created_at"], log["source"], log["url_score"],
            log["text_score"], log["status"], log.get("evidence")
        ))
        log_id = cursor.lastrowid
    return log_id

def get_logs_from_db(limit: int = 500):
    with db() as conn:
        rows = conn.execute(f"SELECT {LOG_COLUMNS} FROM logs ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    return [dict(row) for row in rows]

def get_stats_from_db():
    with db() as conn:
        total = conn.execute("SELECT COUNT(*) FROM logs").fetchone()[0]
        blocked = conn.execute("SELECT COUNT(*) FROM logs WHERE UPPER(action) = 'BLOCK'").fetchone()[0]
    return total, total - blocked, blocked

# ------------------------------------------------------------------
# MODEL YÜKLEME (Modern 22-Özellikli Random Forest)
# ------------------------------------------------------------------
print("[*] AntiGravity 2.0 AI Motoru Başlatılıyor...")
url_model = None
try:
    if os.path.exists(MODEL_FILE):
        pkg = joblib.load(MODEL_FILE)
        if isinstance(pkg, dict) and "model" in pkg:
            url_model = pkg["model"]
            print(f"[✓] Modern URL Modeli Başarıyla Yüklendi. (Doğruluk: %{pkg.get('accuracy', 0)*100:.2f})")
        else:
            url_model = pkg
            print("[✓] URL Yapay Zeka Modeli Başarıyla Yüklendi.")
    else:
        print("[!] UYARI: Model dosyası bulunamadı. Lütfen train_modern_url_model.py çalıştırın.")
except Exception as e:
    print(f"[!] HATA: Model yüklenemedi! {e}")
    url_model = None

class TrafficData(BaseModel):
    url: str = ""
    domain: str = ""
    page_title: str = ""
    page_text: str = ""
    search_query: str = ""
    html_source: str = ""
    has_password_field: bool = False
    has_credit_card_field: bool = False

class DomainBody(BaseModel):
    domain: str = ""

class ReportPhishBody(BaseModel):
    url: str = ""
    reason: str = "Kullanıcı Bildirimi"

# ------------------------------------------------------------------
# ANAHTAR KELİMELER, OSINT / PHISHTANK FEED & SİSTEM KORUMASI
# ------------------------------------------------------------------
OSINT_CACHE = {}

SYSTEM_SAFE_DOMAINS = (
    "google.com", "gemini.google.com", "youtube.com", "gstatic.com",
    "googleapis.com", "openai.com", "chatgpt.com", "github.com",
    "microsoft.com", "apple.com", "127.0.0.1", "localhost"
)

def is_system_safe(domain: str) -> bool:
    clean = (domain or "").replace("www.", "").lower()
    return any(clean == d or clean.endswith("." + d) for d in SYSTEM_SAFE_DOMAINS)

def shorten_url_for_display(url: str, max_len: int = 40) -> str:
    clean = url.replace("https://", "").replace("http://", "").replace("www.", "")
    if len(clean) > max_len:
        return clean[:max_len-3] + "..."
    return clean

EXPLICIT_URL_RE = re.compile(
    r"porn|xxx|escort|cinsel|ifşa|ifsa|(?<![a-z])sex|(?<![a-z])nude", re.IGNORECASE
)
EXPLICIT_TEXT_RE = re.compile(
    r"(?<!\w)(?:porn\w*|xxx+|escort|cinsel\w*|ifşa\w*|nude|sex|sexy|sexual|seks|adult|anal|ero)(?!\w)",
    re.IGNORECASE,
)
GAMBLING_RE = re.compile(r"kumar|bahis|casino|iddaa|slot|rulet|poker|jackpot", re.IGNORECASE)

LINK_CHECK_MARKER = "<div>Tıklanan Link Analizi</div>"
SEARCH_ENGINE_HOSTS = ("google.", "bing.com", "yahoo.com", "duckduckgo.com", "yandex.", "ecosia.org", "search.brave.com")
SEARCH_QUERY_KEYS = ("q", "query", "p", "text", "search_query", "wd")

def is_search_host(host: str) -> bool:
    host = (host or "").lower()
    return any(part in host for part in SEARCH_ENGINE_HOSTS)

def extract_search_query(url: str) -> str:
    try:
        params = parse_qs(urlparse(url).query)
        for key in SEARCH_QUERY_KEYS:
            if key in params and params[key]:
                return params[key][0]
    except Exception:
        pass
    return ""

def is_search_page(url: str) -> bool:
    return is_search_host(urlparse(url).hostname or "") and bool(extract_search_query(url))

def update_phishtank_feed():
    try:
        url = "http://data.phishtank.com/data/online-valid.json"
        headers = {"User-Agent": "anti-gravity-soc-agent"}
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            data = response.json()
            now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            with db() as conn:
                for entry in data:
                    phish_url = entry.get("url", "")
                    domain = normalize_domain(phish_url)
                    if domain:
                        conn.execute(
                            "INSERT OR IGNORE INTO threat_intel (domain, source, added_at) VALUES (?, ?, ?)",
                            (domain, "PhishTank", now_str)
                        )
            print("[✓] PhishTank Feed Güncellendi: Veritabanına yeni tehditler eklendi.")
    except Exception as e:
        print(f"[!] PhishTank Feed Güncelleme Hatası: {e}")

threading.Thread(target=update_phishtank_feed, daemon=True).start()

def check_local_threat_intel(domain: str):
    clean_domain = domain.replace("www.", "").lower()
    if is_system_safe(clean_domain):
        return {"is_scam": False}

    with db() as conn:
        row = conn.execute("SELECT source FROM threat_intel WHERE domain = ?", (clean_domain,)).fetchone()
    if row:
        return {"is_scam": True, "details": f"Tehdit İstihbaratı ({row['source']}): Veritabanında onaylanmış sahte/zararlı site!"}
    return {"is_scam": False}

def check_domain_reputation(domain: str):
    clean_domain = domain.replace("www.", "").lower()
    if clean_domain in OSINT_CACHE:
        return OSINT_CACHE[clean_domain]

    risk_keywords = ["şikayet", "dolandırıcı", "sahte", "paramı vermedi", "uzak durun", "güvenilmez", "mağdur", "yasadışı", "phishing", "scam"]
    query = f'"{clean_domain}" şikayet OR dolandırıcı OR scam'

    search_engines = [
        f"https://html.duckduckgo.com/html/?q={query}",
        f"https://www.bing.com/search?q={query}",
        f"https://search.yahoo.com/search?p={query}"
    ]

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36"
    }

    combined_text = ""
    success_count = 0

    for search_url in search_engines:
        try:
            response = requests.get(search_url, headers=headers, timeout=2)
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                combined_text += " " + soup.get_text(separator=' ').lower()
                success_count += 1
        except Exception:
            pass

    if success_count == 0:
        return {"is_scam": False, "details": "İstihbarat: Arama motorlarına erişilemedi"}

    risk_count = sum(1 for word in risk_keywords if word in combined_text)
    if risk_count >= 3:
        result = {"is_scam": True, "details": f"OSINT Tespiti: Çoklu kaynakta {risk_count} şikayet/dolandırıcılık bulgusu!"}
    else:
        result = {"is_scam": False, "details": "OSINT Tespiti: Temiz"}

    OSINT_CACHE[clean_domain] = result
    return result

# ------------------------------------------------------------------
# BEYAZ LİSTE YARDIMCILARI
# ------------------------------------------------------------------
DOMAIN_RE = re.compile(r"^(?=.{4,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$")

def normalize_domain(value: str) -> str:
    v = (value or "").strip().lower()
    if not v:
        return ""
    if "://" not in v:
        v = "http://" + v
    try:
        host = urlparse(v).hostname or ""
    except ValueError:
        return ""
    host = host.rstrip(".")
    if host.startswith("www."):
        host = host[4:]
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError:
        return ""
    if re.fullmatch(r"[\d.]+", host):
        return ""
    return host if DOMAIN_RE.match(host) else ""

def find_whitelisted(host: str):
    host = (host or "").lower().rstrip(".")
    if host.startswith("www."):
        host = host[4:]
    if not host:
        return None
    with db() as conn:
        rows = conn.execute("SELECT domain FROM whitelist").fetchall()
    for row in rows:
        d = row["domain"]
        if host == d or host.endswith("." + d):
            return d
    return None

# ------------------------------------------------------------------
# 1. EKLENTİNİN BEKLEDİĞİ KARAR KAPISI (/analyze)
# ------------------------------------------------------------------
@app.post("/analyze")
async def gatekeeper_decision(data: TrafficData):
    url = data.url or ""
    parsed = urlparse(url)
    domain = data.domain or parsed.netloc
    query = data.search_query or extract_search_query(url)
    url_target = f"{parsed.netloc}{parsed.path}"
    is_link_check = data.html_source.strip() == LINK_CHECK_MARKER
    search_page = is_search_page(url)
    whitelisted = find_whitelisted(parsed.hostname or "")

    short_url = shorten_url_for_display(url)

    # 1. Heuristic Pattern Matching (Adult / Gambling)
    explicit_found = bool(
        EXPLICIT_URL_RE.search(url_target)
        or EXPLICIT_URL_RE.search(query)
        or EXPLICIT_TEXT_RE.search(data.page_text or "")
        or EXPLICIT_TEXT_RE.search(data.page_title or "")
    )
    gambling_found = bool(
        GAMBLING_RE.search(url_target)
        or GAMBLING_RE.search(query)
        or (is_link_check and GAMBLING_RE.search(data.page_text or ""))
    )

    # 2. Advanced Zero-Day Feature Engineering
    features_vec = extract_features_vector(url)
    features_df = pd.DataFrame([features_vec], columns=FEATURE_NAMES)
    features_dict = extract_features_dict(url)

    punycode_found = bool(check_punycode(domain))
    brand_spoof_found = bool(check_brand_spoofing(url, domain))
    free_host_found = bool(check_free_hosting(domain))
    credential_trap = bool(data.has_password_field and free_host_found)

    local_threat = {"is_scam": False}
    osint_result = {"is_scam": False, "details": ""}
    phishing_found = False
    ai_confidence = 0.0

    # 3. Model Prediction (Trained on Modern 22 Lexical Features)
    if is_system_safe(domain):
        phishing_found = False
    else:
        if not whitelisted:
            local_threat = check_local_threat_intel(domain)

        if url_model:
            try:
                preds = url_model.predict(features_df)
                probs = url_model.predict_proba(features_df)[0]
                ai_confidence = float(probs[1]) if len(probs) > 1 else (1.0 if preds[0] == 1 else 0.0)
                phishing_found = (preds[0] == 1 and ai_confidence >= 0.60) or (features_dict["suspicious_tld"] == 1 and ai_confidence >= 0.40)
            except Exception:
                phishing_found = features_dict["suspicious_tld"] == 1 or brand_spoof_found

    action = "ALLOW"
    reason = "AI Model: Temiz ve Güvenli Trafik"
    is_hard_block = False
    show_toast = False
    url_score = int(ai_confidence * 100)
    text_score = 0
    mitre_tag = "None"

    if not whitelisted and not local_threat["is_scam"] and not is_system_safe(domain):
        osint_result = check_domain_reputation(domain)

    # --------------------------------------------------------------
    # KARAR AĞACI (DECISION HIERARCHY)
    # --------------------------------------------------------------
    if whitelisted:
        reason = f"Beyaz Liste: {whitelisted} güvenli olarak işaretlendi"

    elif is_system_safe(domain):
        reason = "Sistem Dokunulmaz Servisi: Güvenli Altyapı"

    elif punycode_found:
        action = "BLOCK"
        is_hard_block = True
        reason = f"Adli Güvenlik Tespiti: '{short_url}' Uluslararası Karakter Sahtekarlığı (IDN/Punycode Homograph Saldırısı)!"
        url_score = 100
        mitre_tag = "T1566.002: Homograph Phishing"

    elif credential_trap:
        action = "BLOCK"
        is_hard_block = True
        reason = f"Kimlik Avı Koruması: '{short_url}' Ücretsiz bulut altyapısında yetkisiz şifre toplama formu tespit edildi!"
        url_score = 100
        text_score = 100
        mitre_tag = "T1056: Input Capture (Credential Harvesting)"

    elif brand_spoof_found:
        action = "BLOCK"
        is_hard_block = True
        reason = f"AI Model Tespiti: '{short_url}' Sahte Marka Taklidi (Brand Impersonation / Spoofing)!"
        url_score = 99
        mitre_tag = "T1566.002: Spearphishing Link"

    elif explicit_found:
        action = "BLOCK"
        is_hard_block = True
        reason = f"AI Model Koruması: '{short_url}' adresinde Cinsel / Yasaklı İçerik Tespit Edildi!"
        text_score = 100
        mitre_tag = "Policy: Explicit Content Violation"

    elif local_threat["is_scam"]:
        url_score = 100
        mitre_tag = "T1566.002: Verified Phishing Feed"
        if search_page:
            action = "SUSPICIOUS"
            show_toast = True
            reason = "Arama Motoru Uyarısı: Sonuçlarda onaylı sahte site (PhishTank) bağlantısı mevcut."
        else:
            action = "BLOCK"
            is_hard_block = True
            reason = f"PhishTank İstihbaratı: '{short_url}' onaylanmış sahte site!"

    elif phishing_found:
        url_score = max(url_score, 95)
        mitre_tag = "T1566.002: Machine Learning Phishing Detection"
        if search_page:
            action = "SUSPICIOUS"
            show_toast = True
            reason = "Arama Motoru Uyarısı: Sonuçlarda oltalama (Phishing) riskli bağlantılar var."
        else:
            action = "BLOCK"
            is_hard_block = True
            reason = f"AI Model Tespiti: '{short_url}' Sahte/Oltalama URL Yapısı (%{url_score} Risk)!"

    elif osint_result["is_scam"]:
        url_score = 98
        mitre_tag = "OSINT: Fraudulent Domain Signals"
        if search_page:
            action = "SUSPICIOUS"
            show_toast = True
            reason = "Arama Motoru Uyarısı: Sonuçlardaki siteler hakkında dolandırıcılık şikayetleri mevcut."
        else:
            action = "BLOCK"
            is_hard_block = True
            reason = f"OSINT Tespiti: '{short_url}' hakkında çoklu dolandırıcılık/şikayet bulgusu!"

    elif gambling_found:
        url_score = 90
        text_score = 80
        mitre_tag = "Policy: Illegal Gambling"
        if is_link_check:
            action = "BLOCK"
            is_hard_block = True
            reason = f"AI Model Koruması: Tıkladığınız '{short_url}' bağlantısı Bahis/Kumar içeriyor!"
        elif search_page:
            action = "SUSPICIOUS"
            show_toast = True
            reason = "Arama Motoru Uyarısı: Bahis/Kumar içerikli sonuçlar tespit edildi."
        else:
            action = "BLOCK"
            is_hard_block = True
            reason = f"AI Model Koruması: '{short_url}' Bahis/Kumar Sitesi (Erişim Engellendi)"

    blocked = action == "BLOCK"
    now = datetime.datetime.now()
    now_timestamp = now.strftime("%Y-%m-%d %H:%M:%S")

    evidence = None
    if blocked and not is_link_check and data.html_source.strip():
        evidence = data.html_source[:EVIDENCE_LIMIT]

    log_entry = {
        "timestamp": now_timestamp,
        "time": now.strftime("%H:%M"),
        "date": now.strftime("%Y-%m-%d"),
        "url": url,
        "domain": domain,
        "action": action,
        "reason": reason,
        "target_url": url,
        "details": reason,
        "detector": f"AntiGravity AI Engine (v2.0 - {mitre_tag})",
        "created_at": now_timestamp,
        "source": "AI / OSINT / Intel / Heuristics",
        "url_score": url_score,
        "text_score": text_score,
        "status": action,
        "evidence": evidence,
    }
    log_id = save_log_to_db(log_entry)
    log_entry["id"] = log_id
    log_entry["has_evidence"] = bool(evidence)

    # Broadcast instantaneously to all connected SOC analysts over WebSocket
    formatted = format_log(log_entry)
    asyncio.create_task(ws_manager.broadcast(formatted))

    return {
        "is_fake": blocked,
        "is_hard_block": blocked and is_hard_block,
        "show_toast": show_toast,
        "details": reason,
        "action": action,
        "status": action.lower(),
        "block": blocked,
        "is_blocked": blocked,
        "reason": reason,
        "url_score": url_score,
        "text_score": text_score,
        "mitre_tag": mitre_tag,
    }

# ------------------------------------------------------------------
# 2. WEBSOCKET ENDPOINT
# ------------------------------------------------------------------
@app.websocket("/ws/logs")
async def websocket_logs_endpoint(websocket: WebSocket):
    await ws_manager.connect(websocket)
    try:
        while True:
            # Keep socket alive and respond to client pings
            msg = await websocket.receive_text()
            if msg == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
    except Exception:
        ws_manager.disconnect(websocket)

# ------------------------------------------------------------------
# 3. DASHBOARD API
# ------------------------------------------------------------------
def format_log(log: dict) -> dict:
    act = (log.get("action") or "ALLOW").upper()
    blocked = act == "BLOCK"
    suspicious = act == "SUSPICIOUS"
    reason = log.get("reason") or log.get("details") or ""

    if blocked:
        durum = "Engellendi"
    elif suspicious:
        durum = "Şüpheli"
    else:
        durum = "Güvenli"

    return {
        **log,
        "action": act,
        "status": act,
        "badge_status": act,
        "durum": durum,
        "is_fake": blocked,
        "is_blocked": blocked,
        "is_hard_block": blocked,
        "reason": reason,
        "details": log.get("details") or reason,
        "url_score": log.get("url_score") or 0,
        "text_score": log.get("text_score") or 0,
        "has_evidence": bool(log.get("has_evidence")),
        "zaman": log.get("timestamp"),
        "hedef_url": log.get("url"),
        "hedefUrl": log.get("url"),
        "targetUrl": log.get("url"),
        "sebep": reason,
        "tespit_eden": log.get("detector"),
        "tespitEden": log.get("detector"),
    }

@app.get("/api/logs")
def get_logs():
    total_scans, safe_scans, blocked_scans = get_stats_from_db()
    return {
        "logs": [format_log(log) for log in get_logs_from_db()],
        "total": total_scans,
        "safe": safe_scans,
        "blocked": blocked_scans,
        "stats": {"total": total_scans, "safe": safe_scans, "blocked": blocked_scans},
        "total_scans": total_scans,
        "safe_scans": safe_scans,
        "blocked_scans": blocked_scans,
    }

@app.get("/api/details/{log_id}")
def get_details(log_id: int):
    with db() as conn:
        row = conn.execute(f"SELECT {LOG_COLUMNS} FROM logs WHERE id = ?", (log_id,)).fetchone()
    if not row:
        return JSONResponse(status_code=404, content={"status": "error", "message": "Kayıt bulunamadı."})
    return format_log(dict(row))

def _clear_logs():
    with db() as conn:
        conn.execute("DELETE FROM logs")
    return {"status": "success", "message": "Tüm veritabanı kayıtları temizlendi."}

@app.post("/api/clear-logs")
def clear_logs_post():
    return _clear_logs()

@app.delete("/api/logs")
def clear_logs():
    return _clear_logs()

# ------------------------------------------------------------------
# 4. KULLANICI ŞÜPHELİ URL BİLDİRİMİ (REPORT PHISHING)
# ------------------------------------------------------------------
@app.post("/api/report-phish")
def report_phish(body: ReportPhishBody):
    domain = normalize_domain(body.url)
    if not domain:
        return JSONResponse(status_code=400, content={"status": "error", "message": "Geçerli bir web adresi girin."})
    now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with db() as conn:
        conn.execute(
            "INSERT OR IGNORE INTO threat_intel (domain, source, added_at) VALUES (?, ?, ?)",
            (domain, f"User Report: {body.reason}", now_str)
        )
    return {"status": "success", "message": f"'{domain}' adresi tehdit istihbarat havuzuna eklendi."}

# ------------------------------------------------------------------
# 5. ADLİ RAPOR VE KANIT İNDİRME
# ------------------------------------------------------------------
@app.get("/api/export-report")
def export_report():
    with db() as conn:
        rows = conn.execute(f"SELECT {LOG_COLUMNS} FROM logs ORDER BY id DESC").fetchall()
    records = []
    for row in rows:
        rec = dict(row)
        rec["has_evidence"] = bool(rec.get("has_evidence"))
        records.append(rec)

    total = len(records)
    blocked = sum(1 for r in records if (r.get("action") or "").upper() == "BLOCK")

    canonical = json.dumps(records, ensure_ascii=False, sort_keys=True)
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    now = datetime.datetime.now()
    report = {
        "olusturulma": now.isoformat(timespec="seconds"),
        "ozet": {"total": total, "safe": total - blocked, "blocked": blocked},
        "butunluk": {
            "algoritma": "SHA-256",
            "aciklama": "kayitlar alaninin json.dumps(kayitlar, ensure_ascii=False, sort_keys=True) ciktisinin ozeti",
            "deger": digest,
        },
        "kayitlar": records,
    }
    filename = f"adli-rapor-{now.strftime('%Y%m%d-%H%M')}.json"
    return JSONResponse(content=report, headers={"Content-Disposition": f'attachment; filename="{filename}"'})

@app.get("/api/evidence/{log_id}")
def get_evidence(log_id: int):
    with db() as conn:
        row = conn.execute(
            "SELECT url, timestamp, evidence FROM logs WHERE id = ?", (log_id,)
        ).fetchone()
    if not row or not row["evidence"]:
        return JSONResponse(status_code=404, content={"status": "error", "message": "Bu kayıt için kanıt bulunamadı."})

    safe_url = (row["url"] or "").replace("--", "- -")
    header = f"<!-- AntiGravity kanıt kaydı | ID: {log_id} | Zaman: {row['timestamp']} | URL: {safe_url} -->\n"
    return Response(
        content=header + row["evidence"],
        media_type="text/plain; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="kanit-{log_id}.html.txt"',
            "X-Content-Type-Options": "nosniff",
            "Content-Security-Policy": "sandbox",
        },
    )

# ------------------------------------------------------------------
# 6. BEYAZ LİSTE YÖNETİMİ
# ------------------------------------------------------------------
@app.get("/api/whitelist")
def list_whitelist():
    with db() as conn:
        rows = conn.execute("SELECT id, domain, created_at FROM whitelist ORDER BY id DESC").fetchall()
    return [dict(r) for r in rows]

@app.post("/api/whitelist/add")
def add_whitelist(body: DomainBody):
    domain = normalize_domain(body.domain)
    if not domain:
        return JSONResponse(status_code=400, content={"status": "error", "message": "Geçerli bir alan adı girin (örn. ornek.com)."})
    if is_search_host(domain):
        return JSONResponse(status_code=400, content={"status": "error", "message": "Arama motorları beyaz listeye eklenemez."})

    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with db() as conn:
        cur = conn.execute("INSERT OR IGNORE INTO whitelist (domain, created_at) VALUES (?, ?)", (domain, now))
        added = cur.rowcount > 0
    if not added:
        return {"status": "exists", "message": f"{domain} zaten beyaz listede."}
    return {"status": "success", "message": f"{domain} beyaz listeye eklendi."}

@app.post("/api/whitelist/remove")
def remove_whitelist(body: DomainBody):
    domain = normalize_domain(body.domain)
    if not domain:
        return JSONResponse(status_code=400, content={"status": "error", "message": "Geçerli bir alan adı girin."})
    with db() as conn:
        cur = conn.execute("DELETE FROM whitelist WHERE domain = ?", (domain,))
        removed = cur.rowcount > 0
    if not removed:
        return JSONResponse(status_code=404, content={"status": "error", "message": f"{domain} beyaz listede bulunamadı."})
    return {"status": "success", "message": f"{domain} beyaz listeden çıkarıldı."}

# ------------------------------------------------------------------
# 7. DASHBOARD ARAYÜZÜ
# ------------------------------------------------------------------
@app.get("/")
@app.get("/dashboard")
def serve_dashboard():
    for name in ("dashboard.html", "index.html"):
        path = os.path.join(BASE_DIR, name)
        if os.path.exists(path):
            return FileResponse(path)
    return JSONResponse(status_code=404, content={"message": "Dashboard dosyası bulunamadı!"})

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8001)
