#!/usr/bin/env python3
"""One-pass public specimen smoke check, NOT the hidden grader."""
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

REPO = Path("/workspace/binwalk")
DOCS = Path("/task_docs/samples")
EXPECTED = re.compile(
    r"Expected recovery: stream \x60(\d+)\x60\s+—\s+payload\s+\((\d+)\s+bytes\):\s*"
    r"sha256 \x60([0-9a-f]{64})\x60\s+contributing carriers: \x60(\[[^\]]*\])\x60"
)

def main():
    text = (DOCS / "MANIFEST.md").read_text()
    chunks = re.split(r"^## (spec_\d+\.bin)\s*$", text, flags=re.MULTILINE)
    if len(chunks) != 21:
        raise RuntimeError(f"Expected 10 public specimen sections, got {(len(chunks)-1)//2}")
    subprocess.run(["cargo", "build", "--offline", "--locked", "--quiet", "--example", "dbsf_smoke"],
                   cwd=REPO, check=True, timeout=240)
    program = REPO / "target/debug/examples/dbsf_smoke"
    passed = 0
    for index in range(1, len(chunks), 2):
        name, section = chunks[index:index+2]
        expected = sorted((int(sid), int(n), digest, json.loads(offsets))
                          for sid, n, digest, offsets in EXPECTED.findall(section))
        if not expected and "Expected recoveries: **NONE**" not in section:
            raise RuntimeError(f"No manifest assertion for {name}")
        result = subprocess.run([str(program), str(DOCS / name)],
                                check=True, capture_output=True, text=True, timeout=30)
        actual = json.loads(result.stdout).get("derived", [])
        observed = sorted((int(e["stream_id"]), len(e["payload"]),
                           hashlib.sha256(bytes(e["payload"])).hexdigest(), e["carrier_offsets"])
                          for e in actual)
        ok = observed == expected
        passed += ok
        print(f"[{'PASS' if ok else 'FAIL'}] {name}: {len(observed)} stream(s)", flush=True)
    legacy = subprocess.run([str(program), str(DOCS / "spec_01.bin"), "--legacy"],
                            check=True, capture_output=True, text=True, timeout=30)
    off_ok = "derived" not in json.loads(legacy.stdout)
    print(f"Public smoke: {passed}/10, disabled-mode={'PASS' if off_ok else 'FAIL'}", flush=True)
    return 0 if passed == 10 and off_ok else 1

if __name__ == "__main__":
    sys.exit(main())
