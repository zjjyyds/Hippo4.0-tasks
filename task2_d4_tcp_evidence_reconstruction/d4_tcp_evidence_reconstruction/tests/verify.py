#!/usr/bin/env python3
"""
Verifier for D4 TCP Evidence Reconstruction.
Validates:
  1. Upstream engine regressions (18 tests) remain unchanged and passing.
  2. 24 randomized PCAP test scenarios in original capture order (24 checks).
  3. 24 randomized PCAP test scenarios in reversed/permuted packet order (24 checks).
Total: 48 rigorous evidence reconstruction checks.
"""

import os
import sys
import json
import tempfile
import struct
import subprocess
from datetime import datetime

# Import generate_cases from local tests directory
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import generate_cases

def run_upstream_regression(workspace_dir: str) -> bool:
    """Run upstream unit test suite to guarantee backward compatibility."""
    print("[*] Running upstream regression tests...")
    cmd = [sys.executable, "-m", "unittest", "discover", "tests"]
    proc = subprocess.run(cmd, cwd=workspace_dir, capture_output=True, text=True)
    if proc.returncode != 0:
        print(f"[-] Upstream tests failed:\n{proc.stderr}\n{proc.stdout}")
        return False
    print("[+] All upstream regression tests passed.")
    return True


def normalize_evidence_entry(entry: dict) -> dict:
    """Normalize evidence entry for order-independent comparison."""
    norm = {
        "connection": {
            "src_ip": str(entry["connection"]["src_ip"]),
            "sport": int(entry["connection"]["sport"]),
            "dst_ip": str(entry["connection"]["dst_ip"]),
            "dport": int(entry["connection"]["dport"]),
        },
        "generation": int(entry.get("generation", 0)),
        "confirmed": str(entry.get("confirmed", "")),
        "gaps": sorted([list(g) for g in entry.get("gaps", [])]),
        "conflicts": sorted(
            [
                {"offset": int(c["offset"]), "observed": sorted(list(c["observed"]))}
                for c in entry.get("conflicts", [])
            ],
            key=lambda x: x["offset"]
        ),
        "total_observed_bytes": int(entry.get("total_observed_bytes", 0)),
        "unambiguous_bytes": int(entry.get("unambiguous_bytes", 0))
    }
    return norm


def sort_evidence_list(ev_list: list) -> list:
    """Sort evidence entries by connection 4-tuple and generation."""
    return sorted(
        [normalize_evidence_entry(e) for e in ev_list],
        key=lambda x: (
            x["connection"]["src_ip"],
            x["connection"]["sport"],
            x["connection"]["dst_ip"],
            x["connection"]["dport"],
            x["generation"]
        )
    )


def reverse_pcap_packets(src_pcap: str, dst_pcap: str):
    """Read packets from src_pcap and write them in reverse order to dst_pcap."""
    with open(src_pcap, "rb") as f:
        data = f.read()

    global_header = data[:24]
    packets = []
    offset = 24
    while offset < len(data) - 16:
        hdr = data[offset:offset + 16]
        ts_sec, ts_usec, incl_len, orig_len = struct.unpack("<IIII", hdr)
        pkt_data = data[offset + 16: offset + 16 + incl_len]
        packets.append((hdr, pkt_data))
        offset += 16 + incl_len

    # Reverse packet delivery order
    reversed_packets = list(reversed(packets))

    with open(dst_pcap, "wb") as f:
        f.write(global_header)
        for hdr, pkt_data in reversed_packets:
            f.write(hdr)
            f.write(pkt_data)


def verify_scenario(nf_class, pcap_path: str, expected: list, label: str) -> bool:
    """Run full_analysis() on pcap_path and verify tcp_evidence matches expected."""
    try:
        engine = nf_class(pcap_path)
        if not engine.load():
            print(f"[-] {label}: Failed to load PCAP {pcap_path}")
            return False

        result = engine.full_analysis()
        if "tcp_evidence" not in result:
            print(f"[-] {label}: 'tcp_evidence' key missing from full_analysis() result")
            return False

        actual_evidence = sort_evidence_list(result["tcp_evidence"])
        expected_evidence = sort_evidence_list(expected)

        if len(actual_evidence) != len(expected_evidence):
            print(f"[-] {label}: Connection/generation count mismatch! Expected {len(expected_evidence)}, got {len(actual_evidence)}")
            print(f"    Expected: {json.dumps(expected_evidence, indent=2)}")
            print(f"    Actual:   {json.dumps(actual_evidence, indent=2)}")
            return False

        for idx, (exp, act) in enumerate(zip(expected_evidence, actual_evidence)):
            # Check connection
            if exp["connection"] != act["connection"]:
                print(f"[-] {label} stream #{idx}: Connection tuple mismatch:")
                print(f"    Expected: {exp['connection']}")
                print(f"    Actual:   {act['connection']}")
                return False

            if exp["generation"] != act["generation"]:
                print(f"[-] {label} stream #{idx}: Generation mismatch: Expected {exp['generation']}, got {act['generation']}")
                return False

            if exp["confirmed"] != act["confirmed"]:
                print(f"[-] {label} stream #{idx}: Confirmed string mismatch!")
                print(f"    Expected: {repr(exp['confirmed'])}")
                print(f"    Actual:   {repr(act['confirmed'])}")
                return False

            if exp["gaps"] != act["gaps"]:
                print(f"[-] {label} stream #{idx}: Gaps mismatch: Expected {exp['gaps']}, got {act['gaps']}")
                return False

            if exp["conflicts"] != act["conflicts"]:
                print(f"[-] {label} stream #{idx}: Conflicts mismatch!")
                print(f"    Expected: {json.dumps(exp['conflicts'])}")
                print(f"    Actual:   {json.dumps(act['conflicts'])}")
                return False

            if exp["total_observed_bytes"] != act["total_observed_bytes"]:
                print(f"[-] {label} stream #{idx}: Total bytes mismatch: Expected {exp['total_observed_bytes']}, got {act['total_observed_bytes']}")
                return False

            if exp["unambiguous_bytes"] != act["unambiguous_bytes"]:
                print(f"[-] {label} stream #{idx}: Unambiguous bytes mismatch: Expected {exp['unambiguous_bytes']}, got {act['unambiguous_bytes']}")
                return False

        return True

    except Exception as e:
        import traceback
        print(f"[-] {label}: Exception occurred during analysis:\n{traceback.format_exc()}")
        return False


def main():
    workspace_dir = sys.argv[1] if len(sys.argv) > 1 else "/workspace/d4-net-forensics"
    workspace_dir = os.path.abspath(workspace_dir)

    print(f"[*] Starting D4 TCP Evidence Reconstruction Verifier on {workspace_dir}...")

    # Step 1: Upstream regression
    if not run_upstream_regression(workspace_dir):
        print("[-] Verification failed: Upstream regressions broken.")
        sys.exit(1)

    # Step 2: Import target NetworkForensics from workspace
    firmware_dir = os.path.join(workspace_dir, "firmware")
    sys.path.insert(0, firmware_dir)
    try:
        from net_forensics import NetworkForensics
    except ImportError as e:
        print(f"[-] Failed to import NetworkForensics from {firmware_dir}: {e}")
        sys.exit(1)

    # Step 3: Generate test cases in a secure temp directory
    with tempfile.TemporaryDirectory() as tmpdir:
        cases = generate_cases.generate_all_cases(tmpdir)
        print(f"[+] Generated {len(cases)} PCAP scenarios.")

        passed_checks = 0
        total_checks = len(cases) * 2  # Each tested in original order + reverse order

        for case in cases:
            cid = case["case_id"]
            title = case["title"]
            pcap_path = os.path.join(tmpdir, case["pcap_file"])
            expected = case["expected_evidence"]

            # Check 1: Normal capture order
            lbl_normal = f"[Case {cid:02d} Normal] {title}"
            if not verify_scenario(NetworkForensics, pcap_path, expected, lbl_normal):
                print(f"[-] FAILED on {lbl_normal}")
                sys.exit(1)
            print(f"[OK] {lbl_normal}")
            passed_checks += 1

            # Check 2: Reversed packet order (stress testing sequence space independent of arrival)
            rev_pcap = os.path.join(tmpdir, f"rev_{case['pcap_file']}")
            reverse_pcap_packets(pcap_path, rev_pcap)
            lbl_rev = f"[Case {cid:02d} Reversed] {title}"
            if not verify_scenario(NetworkForensics, rev_pcap, expected, lbl_rev):
                print(f"[-] FAILED on {lbl_rev}")
                sys.exit(1)
            print(f"[OK] {lbl_rev}")
            passed_checks += 1

    print("\n" + "=" * 60)
    print(f"[+] SUCCESS: {passed_checks}/{total_checks} condition checks passed successfully.")
    print("=" * 60)
    sys.exit(0)


if __name__ == "__main__":
    main()
