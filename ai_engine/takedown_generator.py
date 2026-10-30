import re
import hashlib
import datetime

def defang_url(url: str) -> str:
    """Defangs a malicious URL to prevent accidental execution."""
    if not url:
        return ""
    clean = url.replace("http://", "hxxp://").replace("https://", "hxxps://")
    return clean.replace(".", "[.]")

def generate_takedown_notice(log_entry: dict) -> dict:
    """
    Generates an RFC-compliant abuse complaint and domain takedown request
    for domain registrars, hosting providers, and CSIRT response teams.
    """
    raw_url = log_entry.get("url") or ""
    defanged = defang_url(raw_url)
    domain = (log_entry.get("domain") or "").replace(".", "[.]")
    timestamp = log_entry.get("timestamp") or datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
    mitre = log_entry.get("detector") or log_entry.get("mitre_tag") or "T1566.002: Spearphishing Link"
    score = log_entry.get("url_score") or 100
    reason = log_entry.get("reason") or "Malicious phishing activity detected"
    log_id = log_entry.get("id") or "N/A"

    evidence = log_entry.get("evidence") or ""
    evidence_hash = ""
    if evidence:
        evidence_hash = hashlib.sha256(evidence.encode("utf-8")).hexdigest()
    else:
        evidence_hash = hashlib.sha256(f"{raw_url}:{timestamp}".encode("utf-8")).hexdigest()

    subject = f"[URGENT ABUSE COMPLAINT] Phishing / Malicious Infrastructure Takedown: {domain}"

    plain_body = f"""To: Abuse Team / Registrar Security Operations
Subject: {subject}
Date: {timestamp}
Incident ID: AG-INC-{log_id}

Dear Security Team,

We are writing from the AntiGravity Zero-Trust Security Operations Center (SOC) to report an active, confirmed malicious phishing attack hosted on your network/registry:

INCIDENT TELEMETRY:
===================
- Target Malicious Domain: {domain}
- Defanged Malicious URL: {defanged}
- Incident Timestamp: {timestamp}
- Attack Vector: {mitre}
- Threat Severity Index: %{score}
- Detection Summary: {reason}
- Evidence SHA-256 Digest: {evidence_hash}

ANALYSIS & EVIDENCE:
====================
The URL above was intercepted while attempting to harvest credentials and impersonate protected services. This activity directly violates standard Terms of Service and ICANN Registrar Accreditation Agreement (RAA) provisions regarding malicious domain abuse.

REQUESTED ACTION:
=================
In accordance with standard incident response guidelines and ICANN abuse mitigation procedures, we urgently request that you:
1. Immediately suspend or revoke DNS resolution for the abusive domain '{domain}'.
2. Null-route / terminate the hosting service hosting this credential harvester.
3. Preserve server logs and registrant telemetry for law enforcement / CSIRT review.

Please confirm receipt of this notice and provide an update on remediation actions taken.

Sincerely,
AntiGravity SOC Automated Incident Response
Digital Forensics & Zero-Trust Defense Unit
Email: abuse-report@antigravity-defense.local
"""

    return {
        "subject": subject,
        "target_domain": domain,
        "defanged_url": defanged,
        "evidence_sha256": evidence_hash,
        "timestamp": timestamp,
        "plain_text": plain_body
    }
