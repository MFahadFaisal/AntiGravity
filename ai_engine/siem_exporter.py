import os
import re
import socket
import datetime
import asyncio

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SIEM_LOG_FILE = os.path.join(BASE_DIR, "antigravity_siem.log")

def escape_cef_value(val) -> str:
    """Escapes special CEF characters according to ArcSight specification."""
    if val is None:
        return ""
    s = str(val)
    return s.replace("\\", "\\\\").replace("|", "\\|").replace("=", "\\=")

def format_cef_event(log_entry: dict) -> str:
    """
    Formats a threat event into standard Common Event Format (CEF:0).
    Format: CEF:Version|Device Vendor|Device Product|Device Version|Device Event Class ID|Name|Severity|[Extension]
    """
    vendor = "AntiGravity"
    product = "Zero-Trust SOC Engine"
    version = "2.1.0"

    action = (log_entry.get("action") or "ALLOW").upper()
    score = int(log_entry.get("url_score") or 0)
    mitre_tag = log_entry.get("detector") or log_entry.get("mitre_tag") or "T1566.002"

    # Severity scale (0 - 10)
    if action == "BLOCK":
        severity = 10 if score >= 90 else 8
    elif action == "SUSPICIOUS":
        severity = 5
    else:
        severity = 1

    event_class = "THREAT_INTERCEPTED" if action == "BLOCK" else "TRAFFIC_INSPECTED"
    event_name = log_entry.get("reason") or "Web Threat Activity"
    # Truncate and clean for CEF header
    clean_name = re.sub(r"[\r\n]+", " ", event_name)[:120]

    url = log_entry.get("url") or ""
    domain = log_entry.get("domain") or ""
    timestamp = log_entry.get("timestamp") or datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Extension dictionary
    ext = [
        f"act={escape_cef_value(action)}",
        f"dst={escape_cef_value(domain)}",
        f"request={escape_cef_value(url)}",
        f"msg={escape_cef_value(clean_name)}",
        f"cn1={score}",
        f"cn1Label=ThreatRiskScore",
        f"cs1={escape_cef_value(mitre_tag)}",
        f"cs1Label=MITRE_Taxonomy",
        f"rt={escape_cef_value(timestamp)}"
    ]

    header = f"CEF:0|{vendor}|{product}|{version}|{event_class}|{clean_name}|{severity}|{' '.join(ext)}"
    return header

def format_rfc5424_syslog(log_entry: dict) -> str:
    """Formats event into RFC 5424 syslog message containing the CEF payload."""
    now = datetime.datetime.now(datetime.timezone.utc)
    timestamp = now.isoformat(timespec="milliseconds")
    hostname = socket.gethostname() or "antigravity-node"
    app_name = "antigravity-soc"
    proc_id = str(os.getpid())
    msg_id = "SEC_INCIDENT"

    cef_msg = format_cef_event(log_entry)
    # Facility: security/authorization (4) or local0 (16), Severity: Alert (1) or Notice (5)
    action = (log_entry.get("action") or "").upper()
    pri = 33 if action == "BLOCK" else 133  # Facility 4 / Severity 1 or Facility 16 / Severity 5

    return f"<{pri}>1 {timestamp} {hostname} {app_name} {proc_id} {msg_id} - {cef_msg}"

def write_to_local_siem_file(cef_message: str):
    """Appends CEF event to local log file for ingestion by Splunk/Elastic forwarders."""
    try:
        with open(SIEM_LOG_FILE, "a", encoding="utf-8") as f:
            f.write(cef_message + "\n")
    except Exception as e:
        print(f"[!] SIEM local log write error: {e}")

async def dispatch_siem_event(log_entry: dict, host: str = "", port: int = 514, protocol: str = "UDP"):
    """
    Dispatches CEF event to local SIEM file and external Syslog host (Splunk/Elastic) if configured.
    """
    cef_line = format_cef_event(log_entry)
    syslog_msg = format_rfc5424_syslog(log_entry)

    # 1. Always record to local SIEM file for agent-based ingestion
    write_to_local_siem_file(cef_line)

    # 2. Forward to external Syslog receiver over network if configured
    if host and port:
        try:
            proto = protocol.upper()
            if proto == "UDP":
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(1.5)
                sock.sendto(syslog_msg.encode("utf-8"), (host, int(port)))
                sock.close()
            elif proto == "TCP":
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1.5)
                sock.connect((host, int(port)))
                sock.sendall((syslog_msg + "\n").encode("utf-8"))
                sock.close()
        except Exception as e:
            # Non-blocking, network timeout or unreachable SIEM receiver
            pass
