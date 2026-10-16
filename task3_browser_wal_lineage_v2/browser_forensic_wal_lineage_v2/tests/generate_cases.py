"""Private multi-acquisition SQLite evidence generator and format-based oracle.

Makes real SQLite WAL/checkpoint histories, then introduces controlled acquisition
variations. The expected report is calculated from independent physical evidence.
"""
from __future__ import annotations
import copy
import hashlib
import json
import os
import random
import shutil
import sqlite3
import struct
from pathlib import Path

from base_cases import reference, rechecksum, u32, store32


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def resigned_salts(raw: bytes, rng: random.Random) -> bytes:
    """A different valid WAL incarnation with exactly the same committed page images."""
    if len(raw) < 32:
        return raw
    w = bytearray(raw)
    new_salt = bytes(rng.getrandbits(8) for _ in range(8))
    while new_salt == w[16:24]:
        new_salt = bytes(rng.getrandbits(8) for _ in range(8))
    w[16:24] = new_salt
    stride = u32(w, 8) + 24
    for at in range(32, len(w) - stride + 1, stride):
        w[at + 8:at + 16] = new_salt
    return rechecksum(bytes(w))


def resigned_page_mutation(raw: bytes, rng: random.Random) -> bytes:
    """Valid but independent committed page content, not a continuation."""
    w = bytearray(raw)
    stride = u32(w, 8) + 24
    assert len(w) >= 32 + stride
    i = w.rfind(b'https://')
    if i >= 0:
        # Mutate URL text without changing SQLite cell length/structure.
        w[i + 8] ^= 1
    else:
        w[32 + 24 + rng.randrange(100, stride - 24)] ^= 0x01
    return rechecksum(bytes(w))


def corrupt_tail(raw: bytes) -> bytes:
    w = bytearray(raw)
    sz = u32(w, 8)
    assert len(w) >= 32 + 2 * (24 + sz), 'expected more than one committed frame'
    w[-7] ^= 0x40
    return bytes(w)


def corrupt_salt(raw: bytes) -> bytes:
    w = bytearray(raw)
    w[16] ^= 0x80
    return rechecksum(bytes(w))  # leaves the old frame salts untouched


def append_uncommitted(raw: bytes) -> bytes:
    w = bytearray(raw)
    stride = u32(w, 8) + 24
    last = w[-stride:]
    frame = bytearray(last)
    store32(frame, 4, 0)
    return rechecksum(bytes(w + frame))


def byte_files(c: dict) -> tuple[bytes, bytes | None]:
    return c['main'], c['wal']


def capture_snapshot(main: bytes, wal: bytes | None, cid: str, order: int, rng: random.Random) -> dict:
    return {
        'id': cid,
        'order': order,
        'file': f'{rng.getrandbits(48):012x}/{rng.getrandbits(32):08x}.db',
        'main': main,
        'wal': wal,
    }


def capture_view(c: dict) -> dict:
    main, wal = byte_files(c)
    commits = reference(main, wal)
    return {
        'id': c['id'], 'base_sha256': sha(main),
        'commits': commits, 'terminal_sha256': commits[-1]['sha256'] if commits else sha(main)
    }


def shared_committed_prefix(a: dict, b: dict, ca: dict, cb: dict) -> bool:
    if ca['base_sha256'] != cb['base_sha256'] or not ca['commits']:
        return False
    aw, bw = a['wal'], b['wal']
    if aw is None or bw is None:
        return False
    page_size = int.from_bytes(a['main'][16:18], 'big')
    if page_size == 1:
        page_size = 65536
    boundary = 32 + ca['commits'][-1]['end_frame'] * (24 + page_size)
    if len(aw) < boundary or len(bw) < boundary or aw[:boundary] != bw[:boundary]:
        return False
    return (len(cb['commits']) >= len(ca['commits'])
            and cb['commits'][:len(ca['commits'])] == ca['commits'])


def relation(a: dict, b: dict, ca: dict, cb: dict) -> tuple[str,list[int]]:
    if a['main'] == b['main'] and a['wal'] == b['wal']:
        return 'identical_evidence', []
    if shared_committed_prefix(a, b, ca, cb):
        return 'shared_wal_prefix', []
    anchors=[c['end_frame'] for c in ca['commits'] if c['sha256']==cb['base_sha256']]
    if anchors and ca['base_sha256'] != cb['base_sha256']:
        return 'checkpoint_compatible', anchors
    if ca['terminal_sha256'] == cb['terminal_sha256']:
        return 'equal_result_only', []
    return 'unproven', []


def assemble_expected(captures: list[dict]) -> dict:
    ordered = sorted(captures, key=lambda x: x['order'])
    views = [capture_view(c) for c in ordered]
    links = []
    for i, a in enumerate(ordered):
        for j in range(i + 1, len(ordered)):
            b = ordered[j]
            kind,anchors=relation(a,b,views[i],views[j])
            links.append({'from': a['id'], 'to': b['id'], 'relation': kind, 'anchors':anchors})
    return {'captures': views, 'links': links}


def new_case(root: Path, idx: int, rng: random.Random) -> dict:
    root.mkdir(parents=True, exist_ok=True)
    sqlite = root / 'working.sqlite'
    c = sqlite3.connect(str(sqlite))
    page_size = [512, 1024, 4096, 8192][idx // 8]
    c.execute(f'PRAGMA page_size={page_size}')
    c.execute('PRAGMA secure_delete=OFF')
    c.execute('CREATE TABLE history (id INTEGER PRIMARY KEY, url TEXT, content BLOB)')
    c.commit()
    c.execute('PRAGMA journal_mode=WAL')
    c.execute('PRAGMA wal_autocheckpoint=0')
    c.execute('PRAGMA wal_checkpoint(TRUNCATE)')
    walfile = Path(str(sqlite) + '-wal')
    def tx():
        for _ in range(1 + rng.randrange(3)):
            payload = bytes(rng.getrandbits(8) for _ in range(90 + rng.randrange(1, 3300 if idx % 4 == 3 else 450)))
            c.execute('INSERT INTO history(url,content) VALUES (?,?)',
                      (f'https://{rng.getrandbits(48):012x}.invalid/{rng.randrange(2000)}', payload))
        if idx % 5 == 0 and rng.randrange(2):
            c.execute('DELETE FROM history WHERE id IN (SELECT id FROM history ORDER BY id LIMIT 1)')
        c.commit()
    def raw():
        return sqlite.read_bytes(), walfile.read_bytes() if walfile.exists() else None
    def commit_sample():
        tx()
        return raw()
    for _ in range(2): tx()  # initial WAL has >=2 committed frames
    order_base = 100 + rng.randrange(50)
    step = 3 + rng.randrange(15)
    captures = []
    def take(main=None, wal=None):
        if main is None:
            main, w = raw()
            if wal is None: wal = w
        num = len(captures)
        captures.append(capture_snapshot(main, wal, f'acq_{rng.getrandbits(48):012x}', order_base + step * num, rng))
    recipe = idx % 8
    def checkpoint_prefix(src_main:bytes, src_wal:bytes, committed_end_frame:int)->bytes:
        # SQLite itself materializes this historical committed image.
        target=root/f'prefix_build_{rng.getrandbits(32):08x}.db'
        target.write_bytes(src_main)
        size=u32(src_wal,8)
        Path(str(target)+'-wal').write_bytes(src_wal[:32+committed_end_frame*(24+size)])
        snap=sqlite3.connect(str(target))
        snap.execute('SELECT COUNT(*) FROM sqlite_master').fetchone()
        snap.close()
        return target.read_bytes()
    if recipe == 0:  # one continuing WAL and independent captures
        take()
        commit_sample();take()
        commit_sample();take()
        commit_sample();take()
    elif recipe == 1:  # physical checkpoint, then a new WAL epoch
        take()
        c.execute('PRAGMA wal_checkpoint(TRUNCATE)')
        take()
        commit_sample();take()
        commit_sample();take()
    elif recipe == 2:  # bitwise duplicate plus a later WAL extension
        take();captures.append(copy.deepcopy(captures[-1]))
        captures[-1]['id'] = f'acq_{rng.getrandbits(48):012x}'
        captures[-1]['file'] = f'{rng.getrandbits(48):012x}/{rng.getrandbits(32):08x}.db'
        captures[-1]['order'] += step
        commit_sample();take()
    elif recipe == 3:  # two independently valid histories with same base
        take()
        m,w=raw();take(m,resigned_page_mutation(w,rng))
        commit_sample();take()
        commit_sample();take()
    elif recipe == 4:  # identical physical end state, independent WAL generation
        take()
        m,w=raw();take(m,resigned_salts(w,rng))
        commit_sample();take()
        commit_sample();take()
    elif recipe == 5:  # damaged late frames and a later intact acquisition
        take()
        commit_sample()
        m,w=raw();take(m,corrupt_tail(w))
        commit_sample();take()
        commit_sample();take()
    elif recipe == 6:  # mixed checkpoint and stale WAL generation
        take()
        oldwal=raw()[1]
        c.execute('PRAGMA wal_checkpoint(TRUNCATE)')
        take()
        commit_sample();take()
        m,w=raw();take(m,corrupt_salt(w))
    else:  # either a historical-prefix checkpoint or ordinary WAL turnover
        if idx in (15,23):
            m,w=raw()
            first=reference(m,w)[0]['end_frame']
            take()
            historical_main=checkpoint_prefix(m,w,first)
            take(historical_main,None)
            commit_sample();take()
            take(historical_main,None)
        else:
            take()
            m,w=raw();take(m,append_uncommitted(w))
            c.execute('PRAGMA wal_checkpoint(TRUNCATE)')
            take()
            commit_sample();take()
    c.close()
    # The last two cases exercise error handling, without turning the rest into invalid-input spam.
    expect_error = idx in (30,31)
    if idx == 30:
        captures[-1]['main'] = b'broken main header' + captures[-1]['main'][18:]
    if idx == 31:
        captures[1]['main'] = captures[1]['main'][:-1]
    manifest = {'captures': [dict(id=x['id'], order=x['order'], db=x['file']) for x in captures]}
    rng.shuffle(manifest['captures'])
    (root / 'manifest.json').write_text(json.dumps(manifest,ensure_ascii=False),encoding='utf-8')
    for cap in captures:
        p=root / cap['file']
        p.parent.mkdir(parents=True,exist_ok=True)
        p.write_bytes(cap['main'])
        if cap['wal'] is not None:
            Path(str(p)+'-wal').write_bytes(cap['wal'])
    expected = None if expect_error else assemble_expected(captures)
    return {
        'input_name':root.name, 'expected':expected,'expect_error':expect_error,
        'scenario':idx,
        'evidence_hashes': {c['file']: [sha(c['main']),sha(c['wal'] or b'')] for c in captures},
    }


def create_cases(directory: Path, seed: int, count:int=32) -> list[dict]:
    rng=random.Random(seed)
    directory.mkdir(parents=True,exist_ok=True)
    return [new_case(directory/f'case_{i:02d}_{rng.getrandbits(40):010x}',i,rng) for i in range(count)]


if __name__=='__main__':
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        cs=create_cases(Path(td),11)
        for c in cs:
            from collections import Counter
            print(c['scenario'], 'ERROR' if c['expect_error'] else len(c['expected']['captures']),
                  Counter(l['relation'] for l in c['expected']['links']) if not c['expect_error'] else '')
