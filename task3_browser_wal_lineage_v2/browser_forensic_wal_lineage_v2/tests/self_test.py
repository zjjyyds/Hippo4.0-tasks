"""Independent SQLite-engine oracle check for every committed-state prefix.

The expected historical physical images are not obtained by calling the Rust
reference or by trusting final-state rows. SQLite itself recovers copied prefixes.
"""
import hashlib
import json
import pathlib
import secrets
import shutil
import sqlite3
import tempfile
from generate_cases import create_cases


def digest_file(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def check_once(seed: int) -> tuple[int,int]:
    count=0
    prefix_count=0
    with tempfile.TemporaryDirectory(prefix='v2-sqlite-selftest-') as td:
        d=pathlib.Path(td)
        cases=create_cases(d,seed)
        assert len(cases)==32
        for case in cases:
            folder=d/case['input_name']
            manifest=json.loads((folder/'manifest.json').read_text())
            if case['expect_error']:
                continue
            expected=case['expected']
            mapping={x['id']:x for x in expected['captures']}
            for entry in manifest['captures']:
                orig=folder/entry['db']
                c=mapping[entry['id']]
                base=orig.read_bytes()
                size=int.from_bytes(base[16:18],'big')
                size=65536 if size==1 else size
                wal=pathlib.Path(str(orig)+'-wal')
                raw=wal.read_bytes() if wal.exists() else None
                clone=d/f'recov_{count:05d}.db'
                def check_prefix(walbytes,expected_digest):
                    clone.write_bytes(base)
                    wc=pathlib.Path(str(clone)+'-wal')
                    if wc.exists(): wc.unlink()
                    if walbytes is not None: wc.write_bytes(walbytes)
                    con=sqlite3.connect(str(clone))
                    con.execute('SELECT COUNT(*) FROM sqlite_master').fetchone()
                    con.close()
                    observed=digest_file(clone)
                    assert observed==expected_digest,(case['scenario'],entry['id'],expected_digest,observed)
                check_prefix(raw,c['terminal_sha256'])
                count+=1
                for commit in c['commits']:
                    assert raw is not None
                    end=32+commit['end_frame']*(24+size)
                    check_prefix(raw[:end],commit['sha256'])
                    prefix_count+=1
                clone.unlink(missing_ok=True)
                pathlib.Path(str(clone)+'-wal').unlink(missing_ok=True)
                pathlib.Path(str(clone)+'-shm').unlink(missing_ok=True)
    return count,prefix_count


def check():
    total=[0,0]
    for seed in [11,29,745]:
        n,p=check_once(seed)
        total[0]+=n;total[1]+=p
    print(f'SQLite independent check: {total[0]} evidence captures, {total[1]} commit prefixes, 3 seeds × 32 scenarios')


if __name__=='__main__':
    check()
