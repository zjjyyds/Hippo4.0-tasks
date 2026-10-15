#!/usr/bin/env python3
"""Trusted, root-owned randomized verifier for an untrusted Rust artifact."""
import json
import hashlib
import os
import pathlib
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
from generate_cases import create_cases


def run_candidate(binary: str, dbpath: pathlib.Path) -> tuple[int, str]:
    proc = subprocess.run([binary, str(dbpath)], cwd=str(dbpath.parent),
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          text=True, timeout=8,
                          preexec_fn=lambda: (os.setgroups([]), os.setgid(65534), os.setuid(65534)))
    return proc.returncode, proc.stdout


def main() -> int:
    binary = sys.argv[1]
    if os.geteuid() != 0:
        raise RuntimeError('trusted verifier must run as root')
    if not os.path.isfile(binary):
        raise RuntimeError('candidate harness missing')
    with tempfile.TemporaryDirectory(prefix='wal-lineage-') as td:
        d = pathlib.Path(td)
        os.chmod(d, 0o755)
        specs = create_cases(d, seed=secrets.randbits(64))
        if len(specs) != 24:
            raise RuntimeError('invalid verifier fixture inventory')
        results = []
        for i, spec in enumerate(specs):
            db = d / spec['input_name']
            os.chmod(db, 0o644)
            wal = pathlib.Path(str(db) + '-wal')
            if wal.exists(): os.chmod(wal, 0o644)
            try:
                rc, output = run_candidate(binary, db)
                actual = json.loads(output) if rc == 0 else None
                ok = (rc != 0) if spec['expect_error'] else (rc == 0 and actual == spec['expected'])
                # Keys and types are exact. A hard-coded empty-array answer
                # cannot pass valid committed-history fixtures.
            except (subprocess.TimeoutExpired, json.JSONDecodeError) as e:
                ok = False
                actual = f'{type(e).__name__}'
            unchanged = (hashlib.sha256(db.read_bytes()).hexdigest() == spec['sha_main']
                         and hashlib.sha256(wal.read_bytes() if wal.exists() else b'').hexdigest() == spec['sha_wal'])
            ok = ok and unchanged
            print(f'[case {i + 1:02d}] {"PASS" if ok else "FAIL"}', flush=True)
            if not ok:
                print(f'  expected commits={len(spec["expected"])}; got={str(actual)[:250]}', flush=True)
            results.append(ok)
        passed = sum(results)
        print(f'Summary: {passed}/{len(results)} verified', flush=True)
        return 0 if passed == len(results) else 1


if __name__ == '__main__':
    sys.exit(main())
