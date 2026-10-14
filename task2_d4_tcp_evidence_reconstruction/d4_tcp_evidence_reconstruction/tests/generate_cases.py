#!/usr/bin/env python3
"""
Generate 24 deterministic, randomized PCAP test cases for TCP Evidence Reconstruction.
Covers:
  - In-order and out-of-order packet reassembly
  - Identical retransmissions (confirmed)
  - Conflicting retransmissions (indeterminate '?' markers)
  - Intermittent sequence gaps
  - Sequence number wrap-around near 2^32 - 1
  - SYN flag ISN consumption (payload starts at ISN + 1)
  - SYN-less stream reconstruction
  - FIN flag sequence consumption
  - Same 4-tuple multi-generation connection lifecycles (FIN/RST teardown)
  - Ethernet minimum 64-byte link padding stripping (IP total_length vs frame size)
  - Variable TCP data offsets (TCP options: MSS, SACK, Timestamp, NOP)
  - Variable IPv4 header lengths (IHL with IP options)
  - Combined stress scenarios (wrapping + conflicts + padding)
"""

import struct
import os
import random
from datetime import datetime, timedelta

PCAP_MAGIC = 0xa1b2c3d4
LINKTYPE_ETHERNET = 1

def build_raw_packet(src_ip: str, dst_ip: str, sport: int, dport: int,
                     seq: int, ack: int, flags: int, payload: bytes,
                     tcp_options: bytes = b"", ip_options: bytes = b"",
                     link_padding_len: int = 0) -> bytes:
    """Build a complete Ethernet + IPv4 + TCP raw frame with optional padding and options."""
    src_mac = b"\x00\x11\x22\x33\x44\x55"
    dst_mac = b"\xaa\xbb\xcc\xdd\xee\xff"
    eth_type = struct.pack(">H", 0x0800)  # IPv4

    # TCP header
    tcp_hdr_len = 20 + len(tcp_options)
    # TCP data offset is in 32-bit words
    data_offset_words = tcp_hdr_len // 4
    data_offset_and_reserved = (data_offset_words << 4) & 0xF0

    tcp_hdr = struct.pack(">HHIIBBHHH",
                          sport, dport,
                          seq & 0xFFFFFFFF,
                          ack & 0xFFFFFFFF,
                          data_offset_and_reserved,
                          flags,
                          65535,  # window size
                          0,      # checksum (0 for synthetic)
                          0)      # urgent pointer
    tcp_packet = tcp_hdr + tcp_options + payload

    # IPv4 header
    ip_hdr_len = 20 + len(ip_options)
    ihl_words = ip_hdr_len // 4
    ver_and_ihl = (4 << 4) | (ihl_words & 0x0F)
    ip_total_len = ip_hdr_len + len(tcp_packet)

    src_bytes = bytes(int(x) for x in src_ip.split("."))
    dst_bytes = bytes(int(x) for x in dst_ip.split("."))

    ip_hdr = struct.pack(">BBHHHBBH",
                         ver_and_ihl,
                         0,              # DSCP/ECN
                         ip_total_len,
                         0x1234,         # Identification
                         0x4000,         # Flags: Don't Fragment
                         64,             # TTL
                         6,              # Protocol: TCP
                         0)              # Checksum
    ip_packet = ip_hdr + src_bytes + dst_bytes + ip_options + tcp_packet

    # Ethernet frame + link padding
    frame = src_mac + dst_mac + eth_type + ip_packet
    if link_padding_len > 0:
        frame += b"\x00" * link_padding_len
    elif len(frame) < 60:
        frame += b"\x00" * (60 - len(frame))

    return frame


def write_pcap_file(filepath: str, packets_with_ts: list):
    """Write packet list [(datetime, raw_bytes), ...] to a standard PCAP file."""
    with open(filepath, "wb") as f:
        # PCAP global header
        global_header = struct.pack("<IHHiIII",
                                    PCAP_MAGIC,
                                    2, 4,
                                    0, 0,
                                    65535,
                                    LINKTYPE_ETHERNET)
        f.write(global_header)
        for ts, raw_pkt in packets_with_ts:
            ts_sec = int(ts.timestamp())
            ts_usec = int((ts.timestamp() - ts_sec) * 1_000_000)
            pkt_len = len(raw_pkt)
            f.write(struct.pack("<IIII", ts_sec, ts_usec, pkt_len, pkt_len))
            f.write(raw_pkt)


def seq_diff(s1: int, s2: int) -> int:
    """Signed difference (s1 - s2) in modulo 2^32 sequence space."""
    diff = (s1 - s2) & 0xFFFFFFFF
    if diff >= 0x80000000:
        diff -= 0x100000000
    return diff


# TCP Flags
FLAG_FIN = 0x01
FLAG_SYN = 0x02
FLAG_RST = 0x04
FLAG_PSH = 0x08
FLAG_ACK = 0x10


def generate_all_cases(output_dir: str):
    """Generate all 24 PCAP test fixtures and ground-truth expectations."""
    os.makedirs(output_dir, exist_ok=True)
    rng = random.Random(0xD47EC9)

    cases = []
    base_ts = datetime(2024, 2, 1, 10, 0, 0)

    # Helper to generate common test cases
    def make_case(case_num: int, title: str, packets: list, expected_evidence: list):
        pcap_name = f"case_{case_num:02d}_{title}.pcap"
        pcap_path = os.path.join(output_dir, pcap_name)
        write_pcap_file(pcap_path, packets)
        cases.append({
            "case_id": case_num,
            "title": title,
            "pcap_file": pcap_name,
            "expected_evidence": expected_evidence
        })

    # ==========================================
    # CASE 01: Baseline Contiguous Stream with Handshake
    # ==========================================
    c1_src, c1_sport, c1_dst, c1_dport = "10.0.0.1", 50001, "10.0.0.2", 80
    c1_isn = 1000
    t0 = base_ts
    p1 = [
        (t0, build_raw_packet(c1_src, c1_dst, c1_sport, c1_dport, c1_isn, 0, FLAG_SYN, b"")),
        (t0 + timedelta(milliseconds=10), build_raw_packet(c1_src, c1_dst, c1_sport, c1_dport, c1_isn + 1, 1, FLAG_ACK | FLAG_PSH, b"HELLOWORLD")),
        (t0 + timedelta(milliseconds=20), build_raw_packet(c1_src, c1_dst, c1_sport, c1_dport, c1_isn + 11, 1, FLAG_FIN | FLAG_ACK, b"")),
    ]
    e1 = [{
        "connection": {"src_ip": c1_src, "sport": c1_sport, "dst_ip": c1_dst, "dport": c1_dport},
        "generation": 0,
        "confirmed": "HELLOWORLD",
        "gaps": [],
        "conflicts": [],
        "total_observed_bytes": 10,
        "unambiguous_bytes": 10
    }]
    make_case(1, "baseline_contiguous_handshake", p1, e1)

    # ==========================================
    # CASE 02: Out-of-Order Packet Delivery Reassembly
    # ==========================================
    c2_src, c2_sport, c2_dst, c2_dport = "10.0.0.1", 50002, "10.0.0.2", 80
    c2_isn = 2000
    t0 = base_ts + timedelta(seconds=1)
    # Packets arrived in reverse: Segment 3, Segment 1, Segment 2
    p2 = [
        (t0, build_raw_packet(c2_src, c2_dst, c2_sport, c2_dport, c2_isn, 0, FLAG_SYN, b"")),
        (t0 + timedelta(milliseconds=10), build_raw_packet(c2_src, c2_dst, c2_sport, c2_dport, c2_isn + 9, 1, FLAG_ACK, b"THREE")),
        (t0 + timedelta(milliseconds=20), build_raw_packet(c2_src, c2_dst, c2_sport, c2_dport, c2_isn + 1, 1, FLAG_ACK, b"ONE_")),
        (t0 + timedelta(milliseconds=30), build_raw_packet(c2_src, c2_dst, c2_sport, c2_dport, c2_isn + 5, 1, FLAG_ACK, b"TWO_")),
        (t0 + timedelta(milliseconds=40), build_raw_packet(c2_src, c2_dst, c2_sport, c2_dport, c2_isn + 14, 1, FLAG_FIN, b"")),
    ]
    e2 = [{
        "connection": {"src_ip": c2_src, "sport": c2_sport, "dst_ip": c2_dst, "dport": c2_dport},
        "generation": 0,
        "confirmed": "ONE_TWO_THREE",
        "gaps": [],
        "conflicts": [],
        "total_observed_bytes": 13,
        "unambiguous_bytes": 13
    }]
    make_case(2, "out_of_order_reassembly", p2, e2)

    # ==========================================
    # CASE 03: Identical Retransmission (Agreement, No Conflict)
    # ==========================================
    c3_src, c3_sport, c3_dst, c3_dport = "10.0.0.1", 50003, "10.0.0.2", 80
    c3_isn = 3000
    t0 = base_ts + timedelta(seconds=2)
    p3 = [
        (t0, build_raw_packet(c3_src, c3_dst, c3_sport, c3_dport, c3_isn, 0, FLAG_SYN, b"")),
        (t0 + timedelta(milliseconds=10), build_raw_packet(c3_src, c3_dst, c3_sport, c3_dport, c3_isn + 1, 1, FLAG_ACK, b"ALPHA_BETA")),
        (t0 + timedelta(milliseconds=20), build_raw_packet(c3_src, c3_dst, c3_sport, c3_dport, c3_isn + 1, 1, FLAG_ACK, b"ALPHA_BETA")),  # Exact duplicate
        (t0 + timedelta(milliseconds=30), build_raw_packet(c3_src, c3_dst, c3_sport, c3_dport, c3_isn + 7, 1, FLAG_ACK, b"BETA")),        # Sub-span duplicate
    ]
    e3 = [{
        "connection": {"src_ip": c3_src, "sport": c3_sport, "dst_ip": c3_dst, "dport": c3_dport},
        "generation": 0,
        "confirmed": "ALPHA_BETA",
        "gaps": [],
        "conflicts": [],
        "total_observed_bytes": 10,
        "unambiguous_bytes": 10
    }]
    make_case(3, "identical_retransmission_no_conflict", p3, e3)

    # ==========================================
    # CASE 04: Single-Byte Retransmission Conflict
    # ABCDEF vs ABCXEF -> ABC?EF
    # ==========================================
    c4_src, c4_sport, c4_dst, c4_dport = "10.0.0.1", 50004, "10.0.0.2", 80
    c4_isn = 4000
    t0 = base_ts + timedelta(seconds=3)
    p4 = [
        (t0, build_raw_packet(c4_src, c4_dst, c4_sport, c4_dport, c4_isn, 0, FLAG_SYN, b"")),
        (t0 + timedelta(milliseconds=10), build_raw_packet(c4_src, c4_dst, c4_sport, c4_dport, c4_isn + 1, 1, FLAG_ACK, b"ABCDEF")),
        (t0 + timedelta(milliseconds=20), build_raw_packet(c4_src, c4_dst, c4_sport, c4_dport, c4_isn + 1, 1, FLAG_ACK, b"ABCXEF")),
        (t0 + timedelta(milliseconds=30), build_raw_packet(c4_src, c4_dst, c4_sport, c4_dport, c4_isn + 1, 1, FLAG_ACK, b"ABCXEF")),  # Majority vote trap (2 'X' vs 1 'D')
    ]
    e4 = [{
        "connection": {"src_ip": c4_src, "sport": c4_sport, "dst_ip": c4_dst, "dport": c4_dport},
        "generation": 0,
        "confirmed": "ABC?EF",
        "gaps": [],
        "conflicts": [{"offset": 3, "observed": ["D", "X"]}],
        "total_observed_bytes": 6,
        "unambiguous_bytes": 5
    }]
    make_case(4, "single_byte_conflict_no_majority_vote", p4, e4)

    # ==========================================
    # CASE 05: Multi-Byte Overlapping Retransmission Conflict
    # ==========================================
    c5_src, c5_sport, c5_dst, c5_dport = "10.0.0.1", 50005, "10.0.0.2", 80
    c5_isn = 5000
    t0 = base_ts + timedelta(seconds=4)
    # Packet 1: 0..8 "COMMAND_A"
    # Packet 2: 4..12 "AND_B123" -> offset 8: 'A' vs '1'
    # Packet 3: 8..15 "C234567" -> offset 8 has 'A', '1', 'C'
    p5 = [
        (t0, build_raw_packet(c5_src, c5_dst, c5_sport, c5_dport, c5_isn, 0, FLAG_SYN, b"")),
        (t0 + timedelta(milliseconds=10), build_raw_packet(c5_src, c5_dst, c5_sport, c5_dport, c5_isn + 1, 1, FLAG_ACK, b"COMMAND_A")),
        (t0 + timedelta(milliseconds=20), build_raw_packet(c5_src, c5_dst, c5_sport, c5_dport, c5_isn + 5, 1, FLAG_ACK, b"AND_B123")),
        (t0 + timedelta(milliseconds=30), build_raw_packet(c5_src, c5_dst, c5_sport, c5_dport, c5_isn + 9, 1, FLAG_ACK, b"C234567")),
    ]
    # Analysis:
    # 0..3: "COMM"
    # 4..7: "AND_"
    # 8: P1='A', P2='B', P3='C' -> conflict '?'
    # 9: P2='1', P3='2' -> conflict '?'
    # 10: P2='2', P3='3' -> conflict '?'
    # 11: P2='3', P3='4' -> conflict '?'
    # 12: P3='5'
    # 13: P3='6'
    # 14: P3='7'
    e5 = [{
        "connection": {"src_ip": c5_src, "sport": c5_sport, "dst_ip": c5_dst, "dport": c5_dport},
        "generation": 0,
        "confirmed": "COMM_AND_????567".replace("_", "AND_"[0:0]),  # "COMMAND_????567"
        "gaps": [],
        "conflicts": [
            {"offset": 8, "observed": ["A", "B", "C"]},
            {"offset": 9, "observed": ["1", "2"]},
            {"offset": 10, "observed": ["2", "3"]},
            {"offset": 11, "observed": ["3", "4"]},
        ],
        "total_observed_bytes": 15,
        "unambiguous_bytes": 11
    }]
    # Fix confirmed string explicitly:
    # 0:C, 1:O, 2:M, 3:M, 4:A, 5:N, 6:D, 7:_, 8:?, 9:?, 10:?, 11:?, 12:5, 13:6, 14:7
    e5[0]["confirmed"] = "COMMAND_????567"
    make_case(5, "multibyte_overlapping_conflict", p5, e5)

    # ==========================================
    # CASE 06: Missing Packets with Sequence Gaps
    # ==========================================
    c6_src, c6_sport, c6_dst, c6_dport = "10.0.0.1", 50006, "10.0.0.2", 80
    c6_isn = 6000
    t0 = base_ts + timedelta(seconds=5)
    # Head: 0..4 "HEAD", Gap: 4..10, Mid: 10..15 "MIDLE", Gap: 15..20, Tail: 20..24 "TAIL"
    p6 = [
        (t0, build_raw_packet(c6_src, c6_dst, c6_sport, c6_dport, c6_isn, 0, FLAG_SYN, b"")),
        (t0 + timedelta(milliseconds=10), build_raw_packet(c6_src, c6_dst, c6_sport, c6_dport, c6_isn + 1, 1, FLAG_ACK, b"HEAD")),
        (t0 + timedelta(milliseconds=20), build_raw_packet(c6_src, c6_dst, c6_sport, c6_dport, c6_isn + 11, 1, FLAG_ACK, b"MIDLE")),
        (t0 + timedelta(milliseconds=30), build_raw_packet(c6_src, c6_dst, c6_sport, c6_dport, c6_isn + 21, 1, FLAG_ACK, b"TAIL")),
    ]
    e6 = [{
        "connection": {"src_ip": c6_src, "sport": c6_sport, "dst_ip": c6_dst, "dport": c6_dport},
        "generation": 0,
        "confirmed": "HEAD??????MIDLE?????TAIL",
        "gaps": [[4, 10], [15, 20]],
        "conflicts": [],
        "total_observed_bytes": 24,
        "unambiguous_bytes": 13
    }]
    make_case(6, "unobserved_sequence_gaps", p6, e6)

    # ==========================================
    # CASE 07: 32-bit Sequence Wrap-Around Across 2^32 Boundary
    # ISN = 0xFFFFFFF8 (-8 relative to wrap)
    # ==========================================
    c7_src, c7_sport, c7_dst, c7_dport = "10.0.0.1", 50007, "10.0.0.2", 80
    c7_isn = 0xFFFFFFF0
    t0 = base_ts + timedelta(seconds=6)
    # SYN consumes 0xFFFFFFF0
    # Data starts at 0xFFFFFFF1
    # Seg 1: 0xFFFFFFF1 .. 0xFFFFFFFF (15 bytes: "WRAP_BEFORE_")
    # Seg 2: 0x00000000 .. 0x0000000F (16 bytes: "WRAP_AFTER_ZERO!")
    seg1_data = b"WRAP_BEFORE_123"  # 15 bytes -> seq ends at 0xFFFFFFFF
    seg2_data = b"WRAP_AFTER_ZERO!"  # 16 bytes -> seq starts at 0x00000000
    p7 = [
        (t0, build_raw_packet(c7_src, c7_dst, c7_sport, c7_dport, c7_isn, 0, FLAG_SYN, b"")),
        (t0 + timedelta(milliseconds=10), build_raw_packet(c7_src, c7_dst, c7_sport, c7_dport, c7_isn + 1, 1, FLAG_ACK, seg1_data)),
        (t0 + timedelta(milliseconds=20), build_raw_packet(c7_src, c7_dst, c7_sport, c7_dport, 0, 1, FLAG_ACK, seg2_data)),
    ]
    e7 = [{
        "connection": {"src_ip": c7_src, "sport": c7_sport, "dst_ip": c7_dst, "dport": c7_dport},
        "generation": 0,
        "confirmed": (seg1_data + seg2_data).decode("ascii"),
        "gaps": [],
        "conflicts": [],
        "total_observed_bytes": 31,
        "unambiguous_bytes": 31
    }]
    make_case(7, "sequence_wrap_around_boundary", p7, e7)

    # ==========================================
    # CASE 08: Wrap-Around with Out-of-Order Delivery
    # Post-wrap packet arrives before pre-wrap packet
    # ==========================================
    c8_src, c8_sport, c8_dst, c8_dport = "10.0.0.1", 50008, "10.0.0.2", 80
    c8_isn = 0xFFFFFFF5
    t0 = base_ts + timedelta(seconds=7)
    seg1 = b"PRE_WRAP"   # 8 bytes: 0xFFFFFFF6 .. 0xFFFFFFFD
    seg2 = b"WRAP_ZERO"  # 9 bytes: 0xFFFFFFFE .. 0x00000006
    seg3 = b"POST_ZERO"  # 9 bytes: 0x00000007 .. 0x0000000F
    p8 = [
        (t0, build_raw_packet(c8_src, c8_dst, c8_sport, c8_dport, c8_isn, 0, FLAG_SYN, b"")),
        (t0 + timedelta(milliseconds=10), build_raw_packet(c8_src, c8_dst, c8_sport, c8_dport, 7, 1, FLAG_ACK, seg3)),          # Arrives 1st
        (t0 + timedelta(milliseconds=20), build_raw_packet(c8_src, c8_dst, c8_sport, c8_dport, 0xFFFFFFF6, 1, FLAG_ACK, seg1)), # Arrives 2nd
        (t0 + timedelta(milliseconds=30), build_raw_packet(c8_src, c8_dst, c8_sport, c8_dport, 0xFFFFFFFE, 1, FLAG_ACK, seg2)), # Arrives 3rd
    ]
    e8 = [{
        "connection": {"src_ip": c8_src, "sport": c8_sport, "dst_ip": c8_dst, "dport": c8_dport},
        "generation": 0,
        "confirmed": (seg1 + seg2 + seg3).decode("ascii"),
        "gaps": [],
        "conflicts": [],
        "total_observed_bytes": 26,
        "unambiguous_bytes": 26
    }]
    make_case(8, "wrap_around_out_of_order", p8, e8)

    # ==========================================
    # CASE 09: Wrap-Around with Conflicting Retransmission
    # ==========================================
    c9_src, c9_sport, c9_dst, c9_dport = "10.0.0.1", 50009, "10.0.0.2", 80
    c9_isn = 0xFFFFFFFE
    t0 = base_ts + timedelta(seconds=8)
    # ISN: 0xFFFFFFFE
    # Data start: 0xFFFFFFFF (offset 0)
    # Seg A: seq 0xFFFFFFFF: "X123" (0xFFFFFFFF .. 0x00000002)
    # Seg B: seq 0xFFFFFFFF: "Y123" -> conflict at offset 0 ('X' vs 'Y')
    p9 = [
        (t0, build_raw_packet(c9_src, c9_dst, c9_sport, c9_dport, c9_isn, 0, FLAG_SYN, b"")),
        (t0 + timedelta(milliseconds=10), build_raw_packet(c9_src, c9_dst, c9_sport, c9_dport, 0xFFFFFFFF, 1, FLAG_ACK, b"X123")),
        (t0 + timedelta(milliseconds=20), build_raw_packet(c9_src, c9_dst, c9_sport, c9_dport, 0xFFFFFFFF, 1, FLAG_ACK, b"Y123")),
    ]
    e9 = [{
        "connection": {"src_ip": c9_src, "sport": c9_sport, "dst_ip": c9_dst, "dport": c9_dport},
        "generation": 0,
        "confirmed": "?123",
        "gaps": [],
        "conflicts": [{"offset": 0, "observed": ["X", "Y"]}],
        "total_observed_bytes": 4,
        "unambiguous_bytes": 3
    }]
    make_case(9, "wrap_around_with_conflict", p9, e9)

    # ==========================================
    # CASE 10: SYN-less Mid-Stream Capture
    # Capture starts without SYN handshake packet
    # Earliest sequence becomes logical offset 0
    # ==========================================
    c10_src, c10_sport, c10_dst, c10_dport = "10.0.0.1", 50010, "10.0.0.2", 80
    t0 = base_ts + timedelta(seconds=9)
    p10 = [
        (t0, build_raw_packet(c10_src, c10_dst, c10_sport, c10_dport, 55000, 100, FLAG_ACK, b"MIDSTREAM_DATA")),
        (t0 + timedelta(milliseconds=10), build_raw_packet(c10_src, c10_dst, c10_sport, c10_dport, 55014, 100, FLAG_ACK, b"_CONTINUATION")),
    ]
    e10 = [{
        "connection": {"src_ip": c10_src, "sport": c10_sport, "dst_ip": c10_dst, "dport": c10_dport},
        "generation": 0,
        "confirmed": "MIDSTREAM_DATA_CONTINUATION",
        "gaps": [],
        "conflicts": [],
        "total_observed_bytes": 27,
        "unambiguous_bytes": 27
    }]
    make_case(10, "syn_less_midstream_capture", p10, e10)

    # ==========================================
    # CASE 11: FIN Sequence Space Consumption
    # FIN consumes 1 sequence number
    # ==========================================
    c11_src, c11_sport, c11_dst, c11_dport = "10.0.0.1", 50011, "10.0.0.2", 80
    c11_isn = 11000
    t0 = base_ts + timedelta(seconds=10)
    p11 = [
        (t0, build_raw_packet(c11_src, c11_dst, c11_sport, c11_dport, c11_isn, 0, FLAG_SYN, b"")),
        (t0 + timedelta(milliseconds=10), build_raw_packet(c11_src, c11_dst, c11_sport, c11_dport, c11_isn + 1, 1, FLAG_ACK, b"DATA_BEFORE_FIN")),
        # FIN packet carries no payload but consumes sequence number c11_isn + 17
        (t0 + timedelta(milliseconds=20), build_raw_packet(c11_src, c11_dst, c11_sport, c11_dport, c11_isn + 17, 1, FLAG_FIN | FLAG_ACK, b"")),
    ]
    e11 = [{
        "connection": {"src_ip": c11_src, "sport": c11_sport, "dst_ip": c11_dst, "dport": c11_dport},
        "generation": 0,
        "confirmed": "DATA_BEFORE_FIN",
        "gaps": [],
        "conflicts": [],
        "total_observed_bytes": 15,
        "unambiguous_bytes": 15
    }]
    make_case(11, "fin_sequence_consumption", p11, e11)

    # ==========================================
    # CASE 12: Same 4-Tuple Multiple Generations (FIN/ACK Teardown)
    # Connection 1: SYN -> Data1 -> FIN
    # Connection 2: New SYN -> Data2 -> FIN on identical (src_ip, sport, dst_ip, dport)
    # ==========================================
    c12_src, c12_sport, c12_dst, c12_dport = "10.0.0.1", 50012, "10.0.0.2", 80
    isn_gen0 = 12000
    isn_gen1 = 88000
    t0 = base_ts + timedelta(seconds=11)
    p12 = [
        # Generation 0
        (t0, build_raw_packet(c12_src, c12_dst, c12_sport, c12_dport, isn_gen0, 0, FLAG_SYN, b"")),
        (t0 + timedelta(milliseconds=10), build_raw_packet(c12_src, c12_dst, c12_sport, c12_dport, isn_gen0 + 1, 1, FLAG_ACK, b"SESSION_ZERO")),
        (t0 + timedelta(milliseconds=20), build_raw_packet(c12_src, c12_dst, c12_sport, c12_dport, isn_gen0 + 13, 1, FLAG_FIN | FLAG_ACK, b"")),
        # Generation 1 (new connection on same 4-tuple)
        (t0 + timedelta(seconds=1), build_raw_packet(c12_src, c12_dst, c12_sport, c12_dport, isn_gen1, 0, FLAG_SYN, b"")),
        (t0 + timedelta(seconds=1, milliseconds=10), build_raw_packet(c12_src, c12_dst, c12_sport, c12_dport, isn_gen1 + 1, 1, FLAG_ACK, b"SESSION_ONE")),
        (t0 + timedelta(seconds=1, milliseconds=20), build_raw_packet(c12_src, c12_dst, c12_sport, c12_dport, isn_gen1 + 12, 1, FLAG_FIN | FLAG_ACK, b"")),
    ]
    e12 = [
        {
            "connection": {"src_ip": c12_src, "sport": c12_sport, "dst_ip": c12_dst, "dport": c12_dport},
            "generation": 0,
            "confirmed": "SESSION_ZERO",
            "gaps": [],
            "conflicts": [],
            "total_observed_bytes": 12,
            "unambiguous_bytes": 12
        },
        {
            "connection": {"src_ip": c12_src, "sport": c12_sport, "dst_ip": c12_dst, "dport": c12_dport},
            "generation": 1,
            "confirmed": "SESSION_ONE",
            "gaps": [],
            "conflicts": [],
            "total_observed_bytes": 11,
            "unambiguous_bytes": 11
        }
    ]
    make_case(12, "same_4tuple_multi_generation_fin", p12, e12)

    # ==========================================
    # CASE 13: Same 4-Tuple Multiple Generations (RST Teardown)
    # RST immediately terminates generation 0
    # ==========================================
    c13_src, c13_sport, c13_dst, c13_dport = "10.0.0.1", 50013, "10.0.0.2", 80
    isn13_0 = 13000
    isn13_1 = 93000
    t0 = base_ts + timedelta(seconds=13)
    p13 = [
        # Gen 0 aborted with RST
        (t0, build_raw_packet(c13_src, c13_dst, c13_sport, c13_dport, isn13_0, 0, FLAG_SYN, b"")),
        (t0 + timedelta(milliseconds=10), build_raw_packet(c13_src, c13_dst, c13_sport, c13_dport, isn13_0 + 1, 1, FLAG_ACK, b"ABORTED_")),
        (t0 + timedelta(milliseconds=20), build_raw_packet(c13_src, c13_dst, c13_sport, c13_dport, isn13_0 + 9, 1, FLAG_RST, b"")),
        # Gen 1 established
        (t0 + timedelta(seconds=1), build_raw_packet(c13_src, c13_dst, c13_sport, c13_dport, isn13_1, 0, FLAG_SYN, b"")),
        (t0 + timedelta(seconds=1, milliseconds=10), build_raw_packet(c13_src, c13_dst, c13_sport, c13_dport, isn13_1 + 1, 1, FLAG_ACK, b"NEW_RECOVERY")),
    ]
    e13 = [
        {
            "connection": {"src_ip": c13_src, "sport": c13_sport, "dst_ip": c13_dst, "dport": c13_dport},
            "generation": 0,
            "confirmed": "ABORTED_",
            "gaps": [],
            "conflicts": [],
            "total_observed_bytes": 8,
            "unambiguous_bytes": 8
        },
        {
            "connection": {"src_ip": c13_src, "sport": c13_sport, "dst_ip": c13_dst, "dport": c13_dport},
            "generation": 1,
            "confirmed": "NEW_RECOVERY",
            "gaps": [],
            "conflicts": [],
            "total_observed_bytes": 12,
            "unambiguous_bytes": 12
        }
    ]
    make_case(13, "same_4tuple_multi_generation_rst", p13, e13)

    # ==========================================
    # CASE 14: Ethernet Link Padding Stripping
    # Frame is padded to 64 bytes (Ethernet minimum)
    # Trailing null bytes must NOT be included in TCP confirmed stream
    # ==========================================
    c14_src, c14_sport, c14_dst, c14_dport = "10.0.0.1", 50014, "10.0.0.2", 80
    c14_isn = 14000
    t0 = base_ts + timedelta(seconds=15)
    # Payload is 5 bytes "PING\n"
    # Total IP len = 20 + 20 + 5 = 45 bytes.
    # Ethernet minimum payload = 46 bytes (+14 eth header = 60 bytes).
    # Link padding = 15 bytes of 0x00.
    p14 = [
        (t0, build_raw_packet(c14_src, c14_dst, c14_sport, c14_dport, c14_isn, 0, FLAG_SYN, b"")),
        (t0 + timedelta(milliseconds=10), build_raw_packet(c14_src, c14_dst, c14_sport, c14_dport, c14_isn + 1, 1, FLAG_ACK, b"PING\n", link_padding_len=20)),
    ]
    e14 = [{
        "connection": {"src_ip": c14_src, "sport": c14_sport, "dst_ip": c14_dst, "dport": c14_dport},
        "generation": 0,
        "confirmed": "PING\n",
        "gaps": [],
        "conflicts": [],
        "total_observed_bytes": 5,
        "unambiguous_bytes": 5
    }]
    make_case(14, "ethernet_link_padding_stripping", p14, e14)

    # ==========================================
    # CASE 15: Variable TCP Options Header Offset
    # TCP header length > 20 bytes (MSS, Timestamp, NOP)
    # ==========================================
    c15_src, c15_sport, c15_dst, c15_dport = "10.0.0.1", 50015, "10.0.0.2", 80
    c15_isn = 15000
    t0 = base_ts + timedelta(seconds=16)
    # MSS option: kind=2, len=4, value=1460 (4 bytes)
    # NOP, NOP: 0x01, 0x01 (2 bytes)
    # SACK permitted: kind=4, len=2 (2 bytes)
    # Total options = 8 bytes -> TCP header = 28 bytes (data offset = 7)
    tcp_opts = struct.pack(">BBH", 2, 4, 1460) + b"\x01\x01" + struct.pack(">BB", 4, 2)
    p15 = [
        (t0, build_raw_packet(c15_src, c15_dst, c15_sport, c15_dport, c15_isn, 0, FLAG_SYN, b"", tcp_options=tcp_opts)),
        (t0 + timedelta(milliseconds=10), build_raw_packet(c15_src, c15_dst, c15_sport, c15_dport, c15_isn + 1, 1, FLAG_ACK, b"OPTIONS_PAYLOAD", tcp_options=tcp_opts)),
    ]
    e15 = [{
        "connection": {"src_ip": c15_src, "sport": c15_sport, "dst_ip": c15_dst, "dport": c15_dport},
        "generation": 0,
        "confirmed": "OPTIONS_PAYLOAD",
        "gaps": [],
        "conflicts": [],
        "total_observed_bytes": 15,
        "unambiguous_bytes": 15
    }]
    make_case(15, "variable_tcp_options_header_offset", p15, e15)

    # ==========================================
    # CASE 16: Variable IPv4 Header Length (IHL > 5)
    # IP options present (e.g. Record Route: 4 bytes)
    # ==========================================
    c16_src, c16_sport, c16_dst, c16_dport = "10.0.0.1", 50016, "10.0.0.2", 80
    c16_isn = 16000
    t0 = base_ts + timedelta(seconds=17)
    ip_opts = b"\x01\x01\x01\x01"  # 4 NOP bytes -> IHL = 6 (24 bytes)
    p16 = [
        (t0, build_raw_packet(c16_src, c16_dst, c16_sport, c16_dport, c16_isn, 0, FLAG_SYN, b"", ip_options=ip_opts)),
        (t0 + timedelta(milliseconds=10), build_raw_packet(c16_src, c16_dst, c16_sport, c16_dport, c16_isn + 1, 1, FLAG_ACK, b"IP_OPTIONS_DATA", ip_options=ip_opts)),
    ]
    e16 = [{
        "connection": {"src_ip": c16_src, "sport": c16_sport, "dst_ip": c16_dst, "dport": c16_dport},
        "generation": 0,
        "confirmed": "IP_OPTIONS_DATA",
        "gaps": [],
        "conflicts": [],
        "total_observed_bytes": 15,
        "unambiguous_bytes": 15
    }]
    make_case(16, "variable_ipv4_ihl_options", p16, e16)

    # ==========================================
    # CASE 17: Multiple Concurrent Connections Across Distinct 4-Tuples
    # ==========================================
    t0 = base_ts + timedelta(seconds=18)
    p17 = [
        (t0, build_raw_packet("10.0.0.1", "10.0.0.2", 10001, 80, 100, 0, FLAG_SYN, b"")),
        (t0 + timedelta(milliseconds=5), build_raw_packet("10.0.0.1", "10.0.0.3", 10002, 443, 200, 0, FLAG_SYN, b"")),
        (t0 + timedelta(milliseconds=10), build_raw_packet("10.0.0.1", "10.0.0.2", 10001, 80, 101, 1, FLAG_ACK, b"HTTP_REQ")),
        (t0 + timedelta(milliseconds=15), build_raw_packet("10.0.0.1", "10.0.0.3", 10002, 443, 201, 1, FLAG_ACK, b"TLS_CLIENT_HELLO")),
    ]
    e17 = [
        {
            "connection": {"src_ip": "10.0.0.1", "sport": 10001, "dst_ip": "10.0.0.2", "dport": 80},
            "generation": 0,
            "confirmed": "HTTP_REQ",
            "gaps": [],
            "conflicts": [],
            "total_observed_bytes": 8,
            "unambiguous_bytes": 8
        },
        {
            "connection": {"src_ip": "10.0.0.1", "sport": 10002, "dst_ip": "10.0.0.3", "dport": 443},
            "generation": 0,
            "confirmed": "TLS_CLIENT_HELLO",
            "gaps": [],
            "conflicts": [],
            "total_observed_bytes": 16,
            "unambiguous_bytes": 16
        }
    ]
    make_case(17, "concurrent_distinct_connections", p17, e17)

    # ==========================================
    # CASE 18: Bi-directional Traffic on Same 4-Tuple
    # Client -> Server and Server -> Client are two distinct directional streams
    # ==========================================
    t0 = base_ts + timedelta(seconds=19)
    ip_a, port_a = "192.168.1.50", 49152
    ip_b, port_b = "192.168.1.1", 80
    isn_a = 500000
    isn_b = 800000
    p18 = [
        # Handshake
        (t0, build_raw_packet(ip_a, ip_b, port_a, port_b, isn_a, 0, FLAG_SYN, b"")),
        (t0 + timedelta(milliseconds=5), build_raw_packet(ip_b, ip_a, port_b, port_a, isn_b, isn_a + 1, FLAG_SYN | FLAG_ACK, b"")),
        # Data A -> B
        (t0 + timedelta(milliseconds=10), build_raw_packet(ip_a, ip_b, port_a, port_b, isn_a + 1, isn_b + 1, FLAG_ACK, b"GET / HTTP/1.1\r\n\r\n")),
        # Data B -> A
        (t0 + timedelta(milliseconds=20), build_raw_packet(ip_b, ip_a, port_b, port_a, isn_b + 1, isn_a + 19, FLAG_ACK, b"HTTP/1.1 200 OK\r\n\r\n")),
    ]
    # Sorted by (src_ip, sport, dst_ip, dport)
    e18 = [
        {
            "connection": {"src_ip": ip_a, "sport": port_a, "dst_ip": ip_b, "dport": port_b},
            "generation": 0,
            "confirmed": "GET / HTTP/1.1\r\n\r\n",
            "gaps": [],
            "conflicts": [],
            "total_observed_bytes": 18,
            "unambiguous_bytes": 18
        },
        {
            "connection": {"src_ip": ip_b, "sport": port_b, "dst_ip": ip_a, "dport": port_a},
            "generation": 0,
            "confirmed": "HTTP/1.1 200 OK\r\n\r\n",
            "gaps": [],
            "conflicts": [],
            "total_observed_bytes": 19,
            "unambiguous_bytes": 19
        }
    ]
    e18.sort(key=lambda x: (x["connection"]["src_ip"], x["connection"]["sport"], x["connection"]["dst_ip"], x["connection"]["dport"]))
    make_case(18, "bidirectional_directional_separation", p18, e18)

    # ==========================================
    # CASE 19: Repeated Conflicts Across Multiple Overlapping Windows
    # ==========================================
    c19_src, c19_sport, c19_dst, c19_dport = "10.0.0.1", 50019, "10.0.0.2", 80
    c19_isn = 19000
    t0 = base_ts + timedelta(seconds=20)
    p19 = [
        (t0, build_raw_packet(c19_src, c19_dst, c19_sport, c19_dport, c19_isn, 0, FLAG_SYN, b"")),
        (t0 + timedelta(milliseconds=10), build_raw_packet(c19_src, c19_dst, c19_sport, c19_dport, c19_isn + 1, 1, FLAG_ACK, b"START_AA_MID_BB_END")),
        (t0 + timedelta(milliseconds=20), build_raw_packet(c19_src, c19_dst, c19_sport, c19_dport, c19_isn + 7, 1, FLAG_ACK, b"XX_MID_")),
        (t0 + timedelta(milliseconds=30), build_raw_packet(c19_src, c19_dst, c19_sport, c19_dport, c19_isn + 14, 1, FLAG_ACK, b"YY_END")),
    ]
    # Analysis:
    # 0..5: "START_"
    # 6, 7: offset 6: 'A' vs 'X'; offset 7: 'A' vs 'X'
    # 8..12: "_MID_" (agreed)
    # 13, 14: offset 13: 'B' vs 'Y'; offset 14: 'B' vs 'Y'
    # 15..18: "_END" (agreed)
    e19 = [{
        "connection": {"src_ip": c19_src, "sport": c19_sport, "dst_ip": c19_dst, "dport": c19_dport},
        "generation": 0,
        "confirmed": "START_??_MID_??_END",
        "gaps": [],
        "conflicts": [
            {"offset": 6, "observed": ["A", "X"]},
            {"offset": 7, "observed": ["A", "X"]},
            {"offset": 13, "observed": ["B", "Y"]},
            {"offset": 14, "observed": ["B", "Y"]},
        ],
        "total_observed_bytes": 19,
        "unambiguous_bytes": 15
    }]
    make_case(19, "multiple_conflict_windows", p19, e19)

    # ==========================================
    # CASE 20: Empty Payload Packets (Pure ACKs) Do Not Extend Span
    # ==========================================
    c20_src, c20_sport, c20_dst, c20_dport = "10.0.0.1", 50020, "10.0.0.2", 80
    c20_isn = 20000
    t0 = base_ts + timedelta(seconds=21)
    p20 = [
        (t0, build_raw_packet(c20_src, c20_dst, c20_sport, c20_dport, c20_isn, 0, FLAG_SYN, b"")),
        (t0 + timedelta(milliseconds=5), build_raw_packet(c20_src, c20_dst, c20_sport, c20_dport, c20_isn + 1, 1, FLAG_ACK, b"DATA_CHUNK")),
        (t0 + timedelta(milliseconds=10), build_raw_packet(c20_src, c20_dst, c20_sport, c20_dport, c20_isn + 11, 100, FLAG_ACK, b"")), # Pure ACK
        (t0 + timedelta(milliseconds=15), build_raw_packet(c20_src, c20_dst, c20_sport, c20_dport, c20_isn + 11, 200, FLAG_ACK, b"")), # Duplicate ACK
    ]
    e20 = [{
        "connection": {"src_ip": c20_src, "sport": c20_sport, "dst_ip": c20_dst, "dport": c20_dport},
        "generation": 0,
        "confirmed": "DATA_CHUNK",
        "gaps": [],
        "conflicts": [],
        "total_observed_bytes": 10,
        "unambiguous_bytes": 10
    }]
    make_case(20, "pure_ack_empty_payloads", p20, e20)

    # ==========================================
    # CASE 21: Full-Spectrum Combination: Wrap-Around + Conflicts + Padding
    # ==========================================
    c21_src, c21_sport, c21_dst, c21_dport = "10.0.0.1", 50021, "10.0.0.2", 80
    c21_isn = 0xFFFFFFFC
    t0 = base_ts + timedelta(seconds=22)
    # ISN: 0xFFFFFFFC
    # Data starts at 0xFFFFFFFD (offset 0)
    # Packet 1: 0xFFFFFFFD .. 0x00000002 (6 bytes: "WRAP_A") with 30 bytes link padding
    # Packet 2: 0xFFFFFFFE .. 0x00000003 (6 bytes: "RAP_X9") -> conflict at offset 5 ('A' vs 'X')
    p21 = [
        (t0, build_raw_packet(c21_src, c21_dst, c21_sport, c21_dport, c21_isn, 0, FLAG_SYN, b"")),
        (t0 + timedelta(milliseconds=10), build_raw_packet(c21_src, c21_dst, c21_sport, c21_dport, 0xFFFFFFFD, 1, FLAG_ACK, b"WRAP_A", link_padding_len=30)),
        (t0 + timedelta(milliseconds=20), build_raw_packet(c21_src, c21_dst, c21_sport, c21_dport, 0xFFFFFFFE, 1, FLAG_ACK, b"RAP_X9")),
    ]
    # Offsets:
    # 0: W (P1)
    # 1: R (P1, P2)
    # 2: A (P1, P2)
    # 3: P (P1, P2)
    # 4: _ (P1, P2)
    # 5: P1='A', P2='X' -> '?'
    # 6: P2='9'
    e21 = [{
        "connection": {"src_ip": c21_src, "sport": c21_sport, "dst_ip": c21_dst, "dport": c21_dport},
        "generation": 0,
        "confirmed": "WRAP_?9",
        "gaps": [],
        "conflicts": [{"offset": 5, "observed": ["A", "X"]}],
        "total_observed_bytes": 7,
        "unambiguous_bytes": 6
    }]
    make_case(21, "wrap_around_conflicts_padding", p21, e21)

    # ==========================================
    # CASE 22: Generational Isolation with Identical ISN
    # Two successive connections happen to have the exact same ISN
    # Generation must still advance because of FIN teardown
    # ==========================================
    c22_src, c22_sport, c22_dst, c22_dport = "10.0.0.1", 50022, "10.0.0.2", 80
    same_isn = 44000
    t0 = base_ts + timedelta(seconds=23)
    p22 = [
        # Gen 0
        (t0, build_raw_packet(c22_src, c22_dst, c22_sport, c22_dport, same_isn, 0, FLAG_SYN, b"")),
        (t0 + timedelta(milliseconds=5), build_raw_packet(c22_src, c22_dst, c22_sport, c22_dport, same_isn + 1, 1, FLAG_ACK, b"GEN_ZERO")),
        (t0 + timedelta(milliseconds=10), build_raw_packet(c22_src, c22_dst, c22_sport, c22_dport, same_isn + 9, 1, FLAG_FIN, b"")),
        # Gen 1 (reusing same ISN)
        (t0 + timedelta(milliseconds=20), build_raw_packet(c22_src, c22_dst, c22_sport, c22_dport, same_isn, 0, FLAG_SYN, b"")),
        (t0 + timedelta(milliseconds=25), build_raw_packet(c22_src, c22_dst, c22_sport, c22_dport, same_isn + 1, 1, FLAG_ACK, b"GEN_ONE_DIFF")),
        (t0 + timedelta(milliseconds=30), build_raw_packet(c22_src, c22_dst, c22_sport, c22_dport, same_isn + 13, 1, FLAG_FIN, b"")),
    ]
    e22 = [
        {
            "connection": {"src_ip": c22_src, "sport": c22_sport, "dst_ip": c22_dst, "dport": c22_dport},
            "generation": 0,
            "confirmed": "GEN_ZERO",
            "gaps": [],
            "conflicts": [],
            "total_observed_bytes": 8,
            "unambiguous_bytes": 8
        },
        {
            "connection": {"src_ip": c22_src, "sport": c22_sport, "dst_ip": c22_dst, "dport": c22_dport},
            "generation": 1,
            "confirmed": "GEN_ONE_DIFF",
            "gaps": [],
            "conflicts": [],
            "total_observed_bytes": 12,
            "unambiguous_bytes": 12
        }
    ]
    make_case(22, "generational_isolation_identical_isn", p22, e22)

    # ==========================================
    # CASE 23: Out-of-Order Gap Filling with Intermediate Conflict
    # ==========================================
    c23_src, c23_sport, c23_dst, c23_dport = "10.0.0.1", 50023, "10.0.0.2", 80
    c23_isn = 23000
    t0 = base_ts + timedelta(seconds=24)
    p23 = [
        (t0, build_raw_packet(c23_src, c23_dst, c23_sport, c23_dport, c23_isn, 0, FLAG_SYN, b"")),
        (t0 + timedelta(milliseconds=10), build_raw_packet(c23_src, c23_dst, c23_sport, c23_dport, c23_isn + 1, 1, FLAG_ACK, b"PREFIX_")),       # 0..6
        (t0 + timedelta(milliseconds=20), build_raw_packet(c23_src, c23_dst, c23_sport, c23_dport, c23_isn + 14, 1, FLAG_ACK, b"_SUFFIX")),     # 13..19 (gap 7..12)
        (t0 + timedelta(milliseconds=30), build_raw_packet(c23_src, c23_dst, c23_sport, c23_dport, c23_isn + 8, 1, FLAG_ACK, b"GAPDATA")),      # 7..13 fills gap with 'GAPDATA'
        (t0 + timedelta(milliseconds=40), build_raw_packet(c23_src, c23_dst, c23_sport, c23_dport, c23_isn + 11, 1, FLAG_ACK, b"XXX")),         # 10..12 conflict: 'DAT' vs 'XXX'
    ]
    # Analysis:
    # 0..6: "PREFIX_"
    # 7..9: "GAP"
    # 10..12: offset 10: 'D' vs 'X'; offset 11: 'A' vs 'X'; offset 12: 'T' vs 'X' -> "???"
    # 13: 'A' (from GAPDATA[6]) vs '_' (from _SUFFIX[0]) -> offset 13: '?'
    # 14..19: "SUFFIX"
    e23 = [{
        "connection": {"src_ip": c23_src, "sport": c23_sport, "dst_ip": c23_dst, "dport": c23_dport},
        "generation": 0,
        "confirmed": "PREFIX_GAP????SUFFIX",
        "gaps": [],
        "conflicts": [
            {"offset": 10, "observed": ["D", "X"]},
            {"offset": 11, "observed": ["A", "X"]},
            {"offset": 12, "observed": ["T", "X"]},
            {"offset": 13, "observed": ["A", "_"]},
        ],
        "total_observed_bytes": 20,
        "unambiguous_bytes": 16
    }]
    make_case(23, "gap_filling_with_conflict", p23, e23)

    # ==========================================
    # CASE 24: High-Volume Multi-Packet Wrap-Around Stream
    # 100 consecutive small segments wrapping across 2^32
    # ==========================================
    c24_src, c24_sport, c24_dst, c24_dport = "10.0.0.1", 50024, "10.0.0.2", 80
    c24_isn = 0xFFFFFF00
    t0 = base_ts + timedelta(seconds=25)
    p24 = [(t0, build_raw_packet(c24_src, c24_dst, c24_sport, c24_dport, c24_isn, 0, FLAG_SYN, b""))]
    curr_seq = c24_isn + 1
    full_str = ""
    for i in range(50):
        chunk = f"BLOCK_{i:02d};"
        full_str += chunk
        chunk_bytes = chunk.encode("ascii")
        p24.append((t0 + timedelta(milliseconds=10 * (i + 1)),
                    build_raw_packet(c24_src, c24_dst, c24_sport, c24_dport, curr_seq, 1, FLAG_ACK, chunk_bytes)))
        curr_seq = (curr_seq + len(chunk_bytes)) & 0xFFFFFFFF

    e24 = [{
        "connection": {"src_ip": c24_src, "sport": c24_sport, "dst_ip": c24_dst, "dport": c24_dport},
        "generation": 0,
        "confirmed": full_str,
        "gaps": [],
        "conflicts": [],
        "total_observed_bytes": len(full_str),
        "unambiguous_bytes": len(full_str)
    }]
    make_case(24, "multi_packet_continuous_wrap_around", p24, e24)

    return cases

if __name__ == "__main__":
    import sys
    out = sys.argv[1] if len(sys.argv) > 1 else "./fixtures"
    cases = generate_all_cases(out)
    print(f"Generated {len(cases)} PCAP test scenarios in {out}")
