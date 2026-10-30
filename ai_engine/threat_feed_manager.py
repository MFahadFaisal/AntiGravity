import os
import re
import csv
import io
import time
import sqlite3
import datetime
import requests
from urllib.parse import urlparse

# In-memory domain cache for sub-millisecond lookup
THREAT_CACHE = {}
THREAT_DOMAINS_SET = set()

# High-frequency public feeds
FEED_CONFIGS = {
    "urlhaus": {
        "name": "abuse.ch URLhaus",
        "url": "https://urlhaus.abuse.ch/downloads/csv_recent/",
        "type": "csv"
    },
    "openphish": {
        "name": "OpenPhish Community Feed",
        "url": "https://openphish.com/feed.txt",
        "type": "text"
    },
    "phishtank": {
        "name": "PhishTank Verified Database",
        "url": "http://data.phishtank.com/data/online-valid.json",
        "type": "json"
    }
}

def normalize_domain(url_or_domain: str) -> str:
    """Extracts and normalizes clean lowercase hostname."""
    if not url_or_domain:
        return ""
    text = url_or_domain.strip().lower()
    if not (text.startswith("http://") or text.startswith("https://")):
        text = "http://" + text
    try:
        parsed = urlparse(text)
        host = (parsed.hostname or "").rstrip(".")
        if host.startswith("www."):
            host = host[4:]
        return host
    except Exception:
        return ""

def load_threat_cache_from_db(db_path: str):
    """Loads all known malicious domains from SQLite into in-memory set."""
    global THREAT_DOMAINS_SET, THREAT_CACHE
    if not os.path.exists(db_path):
        return 0

    try:
        conn = sqlite3.connect(db_path, timeout=10)
        cursor = conn.cursor()
        cursor.execute("SELECT domain, source FROM threat_intel")
        rows = cursor.fetchall()
        conn.close()

        for domain, source in rows:
            if domain:
                clean = domain.lower().strip()
                THREAT_DOMAINS_SET.add(clean)
                THREAT_CACHE[clean] = source or "Verified Threat Intel"
        return len(THREAT_DOMAINS_SET)
    except Exception as e:
        print(f"[!] Failed to load threat cache: {e}")
        return 0

def is_known_threat(domain: str) -> dict:
    """Instantaneous O(1) in-memory check for verified malicious domains."""
    if not domain:
        return {"is_threat": False, "source": ""}

    clean = normalize_domain(domain)
    if clean in THREAT_DOMAINS_SET:
        return {"is_threat": True, "source": THREAT_CACHE.get(clean, "Threat Feed Indicator")}

    # Also check parent domain if subdomain
    parts = clean.split(".")
    if len(parts) > 2:
        parent = ".".join(parts[-2:])
        if parent in THREAT_DOMAINS_SET:
            return {"is_threat": True, "source": THREAT_CACHE.get(parent, "Threat Feed Indicator")}

    return {"is_threat": False, "source": ""}

def fetch_feed_urls(feed_key: str, timeout: float = 3.5) -> list[str]:
    """Fetches candidate threat URLs from external threat intel feed."""
    cfg = FEED_CONFIGS.get(feed_key)
    if not cfg:
        return []

    urls = []
    headers = {"User-Agent": "AntiGravity-ThreatFeed-Sync/2.1"}

    try:
        resp = requests.get(cfg["url"], headers=headers, timeout=timeout)
        if resp.status_code != 200:
            return []

        if cfg["type"] == "text":
            # Plain text URLs line by line (OpenPhish)
            for line in resp.text.splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    urls.append(line)

        elif cfg["type"] == "csv":
            # CSV with header comments (URLhaus)
            lines = [l for l in resp.text.splitlines() if l and not l.startswith("#")]
            if lines:
                reader = csv.reader(io.StringIO("\n".join(lines)))
                for row in reader:
                    # URLhaus CSV column 2 is typically the malicious URL
                    if len(row) > 2 and row[2].startswith("http"):
                        urls.append(row[2])

        elif cfg["type"] == "json":
            # JSON array of entries (PhishTank)
            entries = resp.json()
            if isinstance(entries, list):
                for item in entries[:1000]:
                    u = item.get("url")
                    if u:
                        urls.append(u)

    except Exception:
        # Graceful degradation on network timeout or air-gapped environments
        pass

    return urls

def sync_all_feeds(db_path: str, max_per_feed: int = 1500) -> dict:
    """
    Downloads and ingests latest indicators from URLhaus, OpenPhish, and PhishTank.
    Persists unique domains to SQLite with batch insertion.
    """
    stats = {}
    now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    total_added = 0

    conn = sqlite3.connect(db_path, timeout=15)
    cursor = conn.cursor()

    # Ensure table & indices
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS threat_intel (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT UNIQUE NOT NULL,
            source TEXT,
            added_at TEXT
        )
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_threat_intel_domain ON threat_intel(domain)")

    for key, cfg in FEED_CONFIGS.items():
        candidate_urls = fetch_feed_urls(key)
        domains = set()
        for u in candidate_urls[:max_per_feed]:
            d = normalize_domain(u)
            if d and "." in d and len(d) > 3:
                domains.add(d)

        feed_added = 0
        if domains:
            source_label = cfg["name"]
            records = [(d, source_label, now_str) for d in domains]
            cursor.executemany("INSERT OR IGNORE INTO threat_intel (domain, source, added_at) VALUES (?, ?, ?)", records)
            feed_added = cursor.rowcount
            total_added += feed_added

            # Update in-memory set immediately
            for d in domains:
                THREAT_DOMAINS_SET.add(d)
                THREAT_CACHE[d] = source_label

        stats[key] = {
            "name": cfg["name"],
            "fetched_urls": len(candidate_urls),
            "unique_domains": len(domains),
            "new_inserted": feed_added
        }

    conn.commit()
    conn.close()

    stats["total_new_domains_added"] = total_added
    stats["total_cached_domains"] = len(THREAT_DOMAINS_SET)
    stats["last_sync_time"] = now_str
    return stats

def get_feed_statistics(db_path: str) -> dict:
    """Returns database summary of all active threat intel records."""
    if not os.path.exists(db_path):
        return {"total_indicators": 0, "sources": {}}

    try:
        conn = sqlite3.connect(db_path, timeout=10)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM threat_intel")
        total = cursor.fetchone()[0]

        cursor.execute("SELECT source, COUNT(*) FROM threat_intel GROUP BY source ORDER BY COUNT(*) DESC")
        sources = dict(cursor.fetchall())
        conn.close()

        return {
            "total_indicators": total,
            "in_memory_cached": len(THREAT_DOMAINS_SET),
            "sources": sources
        }
    except Exception as e:
        return {"total_indicators": 0, "error": str(e)}
