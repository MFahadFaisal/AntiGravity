#!/usr/bin/env python3
"""
AntiGravity DNS Sinkhole & Enterprise Gateway Daemon (RFC 1035)
==============================================================
Provides real-time network-wide DNS interception, zero-trust domain threat
evaluation via the 32-feature machine learning model and 25k+ threat feeds,
and automatic sinkholing (0.0.0.0 / redirect) of malicious domains.
"""

import socket
import struct
import threading
import time
import logging
from typing import Dict, List, Optional, Tuple, Any
from collections import deque
from urllib.parse import urlparse
import sqlite3
import os

logger = logging.getLogger("AntiGravity-DNS")
logger.setLevel(logging.INFO)
if not logger.handlers:
    ch = logging.StreamHandler()
    ch.setFormatter(logging.Formatter("[%(asctime)s] [DNS-SINKHOLE] [%(levelname)s] %(message)s"))
    logger.addHandler(ch)

DB_PATH = os.path.join(os.path.dirname(__file__), "antigravity_logs.db")

class DNSQueryPacket:
    """Parses RFC 1035 DNS Question and Header fields."""
    def __init__(self, raw_data: bytes):
        self.raw_data = raw_data
        self.transaction_id = 0
        self.flags = 0
        self.qdcount = 0
        self.ancount = 0
        self.domain = ""
        self.qtype = 1  # 1 = A, 28 = AAAA
        self.qclass = 1  # 1 = IN
        self.is_valid = False
        self._parse()

    def _parse(self):
        if len(self.raw_data) < 12:
            return
        try:
            self.transaction_id, self.flags, self.qdcount, self.ancount, _, _ = struct.unpack(
                "!HHHHHH", self.raw_data[:12]
            )
            offset = 12
            labels = []
            while offset < len(self.raw_data):
                length = self.raw_data[offset]
                if length == 0:
                    offset += 1
                    break
                # RFC 1035 pointer compression check
                if (length & 0xC0) == 0xC0:
                    offset += 2
                    break
                offset += 1
                labels.append(self.raw_data[offset:offset + length].decode("ascii", errors="ignore"))
                offset += length

            if labels:
                self.domain = ".".join(labels).lower()

            if offset + 4 <= len(self.raw_data):
                self.qtype, self.qclass = struct.unpack("!HH", self.raw_data[offset:offset + 4])
                self.is_valid = True
        except Exception as e:
            self.is_valid = False

class DNSSinkholeServer:
    """Multithreaded UDP DNS Sinkhole Daemon with AI Zero-Trust Evaluation."""

    def __init__(
        self,
        bind_host: str = "0.0.0.0",
        bind_port: int = 5300,
        upstream_dns: str = "1.1.1.1",
        upstream_port: int = 53,
        sinkhole_ip: str = "0.0.0.0",
        ai_threshold: float = 0.70
    ):
        self.bind_host = bind_host
        self.bind_port = bind_port
        self.upstream_dns = upstream_dns
        self.upstream_port = upstream_port
        self.sinkhole_ip = sinkhole_ip
        self.ai_threshold = ai_threshold

        self.running = False
        self.sock: Optional[socket.socket] = None
        self.thread: Optional[threading.Thread] = None
        self.lock = threading.Lock()

        # Telemetry & Metrics
        self.stats = {
            "total_queries": 0,
            "blocked_queries": 0,
            "benign_queries": 0,
            "ai_evaluated": 0,
            "feed_blocked": 0,
            "start_time": None,
            "upstream_dns": self.upstream_dns,
            "port": self.bind_port,
            "status": "STOPPED"
        }
        self.recent_queries = deque(maxlen=250)
        self.dns_cache: Dict[str, Tuple[bytes, float]] = {}  # key -> (response_bytes, expire_timestamp)

        # Lazy references to AI model and feeds
        self._model = None
        self._feature_extractor = None
        self._threat_feed_manager = None
        self._init_models()

    def _init_models(self):
        """Loads machine learning model and threat intelligence feeds."""
        try:
            import joblib
            model_path = os.path.join(os.path.dirname(__file__), "antigravity_url_model.pkl")
            if os.path.exists(model_path):
                pkg = joblib.load(model_path)
                self._model = pkg.get("model")
                logger.info("DNS Sinkhole loaded 32-feature AI Model successfully.")
        except Exception as e:
            logger.warning(f"Could not load AI model in DNS Sinkhole: {e}")

        try:
            try:
                from ai_engine.threat_feed_manager import ThreatFeedManager
            except ImportError:
                from threat_feed_manager import ThreatFeedManager
            self._threat_feed_manager = ThreatFeedManager()
            logger.info("DNS Sinkhole linked to Threat Feed Manager.")
        except Exception as e:
            logger.warning(f"Could not load Threat Feed Manager: {e}")

        try:
            try:
                from ai_engine.feature_extractor import extract_features_vector
            except ImportError:
                from feature_extractor import extract_features_vector
            self._feature_extractor = extract_features_vector
        except Exception as e:
            logger.warning(f"Could not load feature extractor: {e}")

    def evaluate_domain(self, domain: str) -> Tuple[bool, str, float]:
        """
        Evaluates domain against Threat Feeds and the 32-feature Zero-Day AI model.
        Returns: (is_blocked, reason, confidence)
        """
        d = (domain or "").strip().lower().rstrip(".")
        if not d:
            return False, "Empty domain", 0.0

        # 1. Whitelist common core services & local network
        if d in ("localhost", "local", "127.0.0.1") or d.endswith((".internal", ".lan", ".home")):
            return False, "Local Network", 0.0

        # 2. Official Brand Infrastructure Immunity
        try:
            try:
                from ai_engine.feature_extractor import LEGIT_BRAND_DOMAINS
            except ImportError:
                from feature_extractor import LEGIT_BRAND_DOMAINS
            for b, auth_list in LEGIT_BRAND_DOMAINS.items():
                if d in auth_list or any(d.endswith("." + a) for a in auth_list):
                    return False, f"Official Brand Infrastructure ({b})", 0.0
        except Exception:
            pass

        # 3. Check Local Database Whitelist
        try:
            conn = sqlite3.connect(DB_PATH, timeout=1)
            c = conn.cursor()
            c.execute("SELECT 1 FROM whitelist WHERE domain = ?", (d,))
            if c.fetchone():
                conn.close()
                return False, "Operator Whitelisted Domain", 0.0
            conn.close()
        except Exception:
            pass

        # 4. Threat Feed Indicator Lookup (Exact & Suffix)
        if self._threat_feed_manager:
            feed_match = self._threat_feed_manager.check_url("https://" + d)
            if feed_match.get("is_blacklisted"):
                return True, f"Threat Feed Indicator: {feed_match.get('source', 'Blacklist')}", 1.0

        # 5. Fast Heuristic Checks (Punycode / IDN Homograph)
        if "xn--" in d:
            return True, "IDN Homograph Punycode Attack", 0.99

        # 6. Zero-Day 32-Feature AI Engine Inference
        if self._model and self._feature_extractor:
            try:
                import pandas as pd
                try:
                    from ai_engine.feature_extractor import FEATURE_NAMES
                except ImportError:
                    from feature_extractor import FEATURE_NAMES
                features = [self._feature_extractor("https://" + d)]
                df = pd.DataFrame(features, columns=FEATURE_NAMES)
                prob = float(self._model.predict_proba(df)[0][1])
                with self.lock:
                    self.stats["ai_evaluated"] += 1
                # Higher threshold for raw DNS interception to ensure zero false positives
                threshold = max(0.85, self.ai_threshold)
                if prob >= threshold:
                    return True, f"AI Zero-Day Classifier (Confidence: {round(prob * 100, 1)}%)", prob
                return False, f"AI Classified Benign ({round((1 - prob) * 100, 1)}%)", prob
            except Exception as e:
                logger.error(f"Error during AI DNS evaluation for {domain}: {e}")

        return False, "Passed Inspection", 0.0

    def craft_sinkhole_response(self, query: DNSQueryPacket) -> bytes:
        """Constructs an RFC 1035 A record DNS answer pointing to sinkhole IP."""
        raw = query.raw_data
        # Flags: QR=1 (response), AA=1, RD=1, RA=1, RCODE=0 -> 0x8180
        header = struct.pack("!HHHHHH", query.transaction_id, 0x8180, 1, 1, 0, 0)

        # Question section from original query
        offset = 12
        while offset < len(raw) and raw[offset] != 0:
            if (raw[offset] & 0xC0) == 0xC0:
                offset += 2
                break
            offset += 1 + raw[offset]
        if offset < len(raw) and raw[offset] == 0:
            offset += 1
        q_section = raw[12:offset + 4]

        # Answer Section: Compression pointer to domain name in question (0xC00C)
        # Type: A (1), Class: IN (1), TTL: 60 seconds, RDLENGTH: 4 bytes
        ans_prefix = struct.pack("!HHIH", 1, 1, 60, 4)
        sinkhole_bytes = socket.inet_aton(self.sinkhole_ip)

        return header + q_section + b"\xc0\x0c" + ans_prefix + sinkhole_bytes

    def query_upstream(self, raw_data: bytes) -> bytes:
        """Forwards standard DNS query to recursive upstream resolver (1.1.1.1 / 8.8.8.8)."""
        upstream_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        upstream_sock.settimeout(2.5)
        try:
            upstream_sock.sendto(raw_data, (self.upstream_dns, self.upstream_port))
            resp, _ = upstream_sock.recvfrom(4096)
            return resp
        except Exception as e:
            logger.debug(f"Upstream DNS resolution error: {e}")
            return b""
        finally:
            upstream_sock.close()

    def handle_request(self, raw_data: bytes, client_addr: Tuple[str, int]):
        """Processes a single incoming UDP DNS packet."""
        t_start = time.time()
        query = DNSQueryPacket(raw_data)
        if not query.is_valid or not query.domain:
            return

        with self.lock:
            self.stats["total_queries"] += 1

        is_blocked, reason, conf = self.evaluate_domain(query.domain)
        latency_ms = round((time.time() - t_start) * 1000, 2)

        record = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "client_ip": client_addr[0],
            "domain": query.domain,
            "qtype": "A" if query.qtype == 1 else f"TYPE{query.qtype}",
            "verdict": "BLOCKED" if is_blocked else "RESOLVED",
            "reason": reason,
            "confidence": conf,
            "latency_ms": latency_ms
        }

        if is_blocked:
            with self.lock:
                self.stats["blocked_queries"] += 1
                if "Threat Feed" in reason:
                    self.stats["feed_blocked"] += 1
                self.recent_queries.append(record)

            logger.warning(f"🚫 SINKHOLED: {query.domain} -> {self.sinkhole_ip} ({reason})")
            sink_resp = self.craft_sinkhole_response(query)
            try:
                self.sock.sendto(sink_resp, client_addr)
            except Exception as e:
                logger.error(f"Failed to send sinkhole response: {e}")

            self._log_to_db(record)
        else:
            with self.lock:
                self.stats["benign_queries"] += 1
                self.recent_queries.append(record)

            # Check cache
            now = time.time()
            cached_resp = self.dns_cache.get(query.domain)
            if cached_resp and cached_resp[1] > now:
                # Update transaction ID in cached packet
                resp_data = bytearray(cached_resp[0])
                if len(resp_data) >= 2:
                    struct.pack_into("!H", resp_data, 0, query.transaction_id)
                self.sock.sendto(bytes(resp_data), client_addr)
                return

            # Forward upstream
            resp = self.query_upstream(raw_data)
            if resp:
                self.dns_cache[query.domain] = (resp, now + 120)  # 2 minute cache
                try:
                    self.sock.sendto(resp, client_addr)
                except Exception as e:
                    logger.error(f"Failed forwarding upstream DNS reply: {e}")

    def _log_to_db(self, record: dict):
        """Persists sinkhole events to the local SQLite audit log."""
        try:
            conn = sqlite3.connect(DB_PATH, timeout=2)
            c = conn.cursor()
            c.execute("""
                INSERT INTO threat_logs (
                    url, is_fake, url_score, visual_score, final_score,
                    status, details, mitre_tag, verified_brand
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                "dns://" + record["domain"],
                1,
                int(record["confidence"] * 100),
                0,
                int(record["confidence"] * 100),
                "sinkholed",
                f"DNS Sinkhole Block: {record['reason']} (Client: {record['client_ip']})",
                "T1566.002: Malicious Domain Resolution",
                "DNS Gateway"
            ))
            conn.commit()
            conn.close()
        except Exception:
            pass

    def _serve_loop(self):
        """Background socket loop."""
        logger.info(f"DNS Sinkhole server listening on UDP {self.bind_host}:{self.bind_port}...")
        while self.running and self.sock:
            try:
                data, addr = self.sock.recvfrom(4096)
                if data:
                    t = threading.Thread(target=self.handle_request, args=(data, addr), daemon=True)
                    t.start()
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    logger.debug(f"Socket loop exception: {e}")
                break

    def start(self) -> bool:
        """Starts the DNS Sinkhole in a background thread."""
        with self.lock:
            if self.running:
                return True
            try:
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                self.sock.bind((self.bind_host, self.bind_port))
                self.sock.settimeout(1.0)
                self.running = True
                self.stats["status"] = "RUNNING"
                self.stats["start_time"] = time.strftime("%Y-%m-%d %H:%M:%S")
            except Exception as e:
                logger.error(f"Failed to bind DNS Sinkhole on port {self.bind_port}: {e}")
                self.stats["status"] = f"ERROR: {e}"
                return False

        self.thread = threading.Thread(target=self._serve_loop, daemon=True)
        self.thread.start()
        return True

    def stop(self):
        """Stops the DNS Sinkhole service."""
        with self.lock:
            self.running = False
            self.stats["status"] = "STOPPED"
            if self.sock:
                try:
                    self.sock.close()
                except Exception:
                    pass
                self.sock = None
        if self.thread:
            self.thread.join(timeout=1.5)
        logger.info("DNS Sinkhole server stopped.")

    def get_stats(self) -> dict:
        """Returns current operational statistics."""
        with self.lock:
            st = dict(self.stats)
            st["cached_domains"] = len(self.dns_cache)
            return st

    def get_recent_queries(self) -> List[dict]:
        """Returns recent DNS query records."""
        with self.lock:
            return list(self.recent_queries)

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="AntiGravity DNS Sinkhole Daemon")
    parser.add_argument("--port", type=int, default=5353, help="Port to listen on (default: 5353)")
    parser.add_argument("--upstream", type=str, default="1.1.1.1", help="Upstream DNS resolver")
    parser.add_argument("--sinkhole-ip", type=str, default="0.0.0.0", help="IP returned for blocked queries")
    args = parser.parse_args()

    server = DNSSinkholeServer(bind_port=args.port, upstream_dns=args.upstream, sinkhole_ip=args.sinkhole_ip)
    if server.start():
        print(f"[*] AntiGravity DNS Sinkhole active on UDP port {args.port}")
        print(f"[*] Upstream Resolver: {args.upstream} | Sinkhole Destination: {args.sinkhole_ip}")
        print("[*] Press Ctrl+C to terminate.")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            server.stop()
            print("\n[*] Server shutdown cleanly.")
