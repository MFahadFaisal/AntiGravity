import sys
import os
import pytest
import struct
import socket

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
AI_ENGINE_DIR = os.path.join(ROOT_DIR, "ai_engine")
if AI_ENGINE_DIR not in sys.path:
    sys.path.insert(0, AI_ENGINE_DIR)

from dns_sinkhole import DNSQueryPacket, DNSSinkholeServer

def create_sample_dns_query(domain: str, transaction_id: int = 0x1337) -> bytes:
    """Helper to construct raw RFC 1035 DNS Question packet."""
    header = struct.pack("!HHHHHH", transaction_id, 0x0100, 1, 0, 0, 0)
    qname_parts = domain.split(".")
    qname_bytes = b""
    for part in qname_parts:
        part_bytes = part.encode("ascii")
        qname_bytes += bytes([len(part_bytes)]) + part_bytes
    qname_bytes += b"\x00"
    q_suffix = struct.pack("!HH", 1, 1)  # TYPE=A, CLASS=IN
    return header + qname_bytes + q_suffix

def test_dns_packet_parsing():
    raw_packet = create_sample_dns_query("paypal-update.xyz", 0xABCD)
    pkt = DNSQueryPacket(raw_packet)

    assert pkt.is_valid is True
    assert pkt.transaction_id == 0xABCD
    assert pkt.domain == "paypal-update.xyz"
    assert pkt.qtype == 1
    assert pkt.qclass == 1

def test_dns_sinkhole_evaluation_benign():
    server = DNSSinkholeServer(bind_port=5354)
    is_blocked, reason, conf = server.evaluate_domain("google.com")
    assert is_blocked is False
    assert conf < 0.50

def test_dns_sinkhole_evaluation_punycode():
    server = DNSSinkholeServer(bind_port=5354)
    is_blocked, reason, conf = server.evaluate_domain("xn--paypa-update-38a.com")
    assert is_blocked is True
    assert "Homograph" in reason or "Punycode" in reason
    assert conf >= 0.90

def test_dns_sinkhole_response_crafting():
    server = DNSSinkholeServer(bind_port=5354, sinkhole_ip="0.0.0.0")
    raw_query = create_sample_dns_query("malicious-test-phish.xyz", 0x4444)
    query_pkt = DNSQueryPacket(raw_query)

    response_bytes = server.craft_sinkhole_response(query_pkt)
    assert len(response_bytes) > len(raw_query)

    # Validate header in crafted answer
    tx_id, flags, qdcount, ancount, _, _ = struct.unpack("!HHHHHH", response_bytes[:12])
    assert tx_id == 0x4444
    assert flags == 0x8180  # Standard query response, No error
    assert ancount == 1     # 1 Answer record

    # Validate sinkhole IP payload is 0.0.0.0
    assert response_bytes[-4:] == socket.inet_aton("0.0.0.0")

def test_dns_server_stats_lifecycle():
    server = DNSSinkholeServer(bind_port=5355)
    stats = server.get_stats()
    assert "total_queries" in stats
    assert "blocked_queries" in stats
    assert "benign_queries" in stats
    assert stats["status"] == "STOPPED"
