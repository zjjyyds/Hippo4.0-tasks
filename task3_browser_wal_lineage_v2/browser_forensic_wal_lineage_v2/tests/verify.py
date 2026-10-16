#!/usr/bin/env python3
"""Private final-outcome verifier for multi-acquisition evidence reconstruction."""
import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile
from generate_cases import create_cases


def check_candidate(binary: str, folder: Path):
    proc=subprocess.run([binary,str(folder)],cwd=str(folder),capture_output=True,
                        text=True,timeout=9,
                        preexec_fn=lambda:(os.setgroups([]),os.setgid(65534),os.setuid(65534)))
    return proc.returncode, proc.stdout


def main():
    if os.geteuid()!=0:
        raise RuntimeError('trusted verifier must run as root')
    binary=sys.argv[1]
    with tempfile.TemporaryDirectory(prefix='wal-lineage-v2-') as td:
        root=Path(td)
        os.chmod(root,0o755)
        cases=create_cases(root,secrets.randbits(64))
        assert len(cases)==32
        passed=0
        for i,case in enumerate(cases):
            directory=root/case['input_name']
            for d in directory.rglob('*'):
                os.chmod(d,0o755 if d.is_dir() else 0o644)
            try:
                rc,stdout=check_candidate(binary,directory)
                got=json.loads(stdout) if rc==0 else None
                ok=rc!=0 if case['expect_error'] else (rc==0 and got==case['expected'])
            except (subprocess.TimeoutExpired,json.JSONDecodeError,UnicodeError):
                ok=False
            for rel,(main_hash,wal_hash) in case['evidence_hashes'].items():
                db=directory/rel
                wal=Path(str(db)+'-wal')
                h=lambda p:hashlib.sha256(p.read_bytes() if p.exists() else b'').hexdigest()
                ok=ok and h(db)==main_hash and h(wal)==wal_hash
            passed+=bool(ok)
            print(f'[case {i+1:02d}] {"PASS" if ok else "FAIL"}',flush=True)
        print(f'Summary: {passed}/{len(cases)} verified',flush=True)
        return 0 if passed==len(cases) else 1


if __name__=='__main__':
    sys.exit(main())
