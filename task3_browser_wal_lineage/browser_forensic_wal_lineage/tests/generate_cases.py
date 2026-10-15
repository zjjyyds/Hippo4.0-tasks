"""Private randomized crash-evidence generator, independent Python WAL oracle.

The data are created by SQLite itself, not by a fixture-name lookup.  Our
reference parses the SQLite disk format, validates the checksum chain and
reconstructs the physical, committed page images.
"""
from __future__ import annotations
import hashlib
import os
import random
import shutil
import sqlite3
import struct
import tempfile
from pathlib import Path

MAGICS = (0x377F0682, 0x377F0683)


def u32(b: bytes | bytearray, at: int) -> int:
    return struct.unpack_from('>I', b, at)[0]


def store32(buf: bytearray, offset: int, n: int) -> None:
    struct.pack_into('>I', buf, offset, n & 0xffffffff)


def checksum(data: bytes, endian: str, prev=(0, 0)) -> tuple[int, int]:
    assert len(data) % 8 == 0
    a, b = prev
    for i in range(0, len(data), 8):
        x, y = struct.unpack_from(endian + 'II', data, i)
        a = (a + x + b) & 0xffffffff
        b = (b + y + a) & 0xffffffff
    return a, b


def rechecksum(raw: bytes, *, flip_endian: bool = False) -> bytes:
    """Resign an intact WAL after intentionally changing its source bytes."""
    w = bytearray(raw)
    magic = u32(w, 0)
    if flip_endian:
        assert magic in MAGICS
        store32(w, 0, MAGICS[1] if magic == MAGICS[0] else MAGICS[0])
    endian = '<' if u32(w, 0) == MAGICS[0] else '>'
    state = checksum(w[:24], endian)
    store32(w, 24, state[0]); store32(w, 28, state[1])
    page_size = u32(w, 8)
    for pos in range(32, len(w) - 24 - page_size + 1, 24 + page_size):
        state = checksum(w[pos:pos + 8], endian, state)
        state = checksum(w[pos + 24:pos + 24 + page_size], endian, state)
        store32(w, pos + 16, state[0]); store32(w, pos + 20, state[1])
    return bytes(w)


def reference(main: bytes, wal: bytes | None) -> list[dict]:
    if not main.startswith(b'SQLite format 3\x00') or len(main) < 100:
        raise ValueError('invalid main database')
    sz = int.from_bytes(main[16:18], 'big')
    sz = 65536 if sz == 1 else sz
    if sz < 512 or sz > 65536 or (sz & (sz - 1)) or len(main) % sz:
        raise ValueError('invalid page layout')
    if wal is None or len(wal) < 32:
        return []
    magic = u32(wal, 0)
    if magic not in MAGICS or u32(wal, 4) != 3007000 or u32(wal, 8) != sz:
        return []
    endian = '<' if magic == MAGICS[0] else '>'
    running = checksum(wal[:24], endian)
    if running != (u32(wal, 24), u32(wal, 28)):
        return []
    header_salts = wal[16:24]
    overlay = {}
    pending = {}
    commits = []
    off = 32
    count = 0
    while off + 24 + sz <= len(wal):
        page = u32(wal, off)
        n_pages = u32(wal, off + 4)
        if page == 0 or wal[off + 8:off + 16] != header_salts:
            break
        running_next = checksum(wal[off:off + 8], endian, running)
        running_next = checksum(wal[off + 24:off + 24 + sz], endian, running_next)
        if running_next != (u32(wal, off + 16), u32(wal, off + 20)):
            break
        running = running_next
        pending[page] = wal[off + 24:off + 24 + sz]
        count += 1
        if n_pages:
            if n_pages > len(main) // sz + count:
                break
            overlay.update(pending)
            pending.clear()
            overlay = {page: payload for page, payload in overlay.items() if page <= n_pages}
            data = b''.join(overlay.get(page, main[(page - 1) * sz:page * sz].ljust(sz, b'\0'))
                            for page in range(1, n_pages + 1))
            commits.append(dict(end_frame=count, database_pages=n_pages,
                                sha256=hashlib.sha256(data).hexdigest()))
        off += 24 + sz
    return commits


def real_sqlite_pair(root: Path, rng: random.Random, page_size: int, n_commits: int, large: bool) -> tuple[bytes, bytes]:
    live = root / 'live.db'
    c = sqlite3.connect(str(live))
    c.execute(f'PRAGMA page_size={page_size}')
    c.execute('PRAGMA secure_delete=OFF')
    c.execute('CREATE TABLE history (id INTEGER PRIMARY KEY, url TEXT, title BLOB)')
    c.commit()
    c.execute('PRAGMA journal_mode=WAL')
    c.execute('PRAGMA wal_autocheckpoint=0')
    c.execute('PRAGMA wal_checkpoint(TRUNCATE)')
    main = live.read_bytes()
    # A randomized multi-transaction sequence leaves different physical page
    # versions, including occasional overflow/freelist activity.
    for tx in range(n_commits):
        for j in range(1 + (tx % 3)):
            n = rng.randrange(1, 1600)
            if large and j == 0:
                n += rng.randrange(2000, 5000)
            data = bytes(rng.getrandbits(8) for _ in range(n))
            c.execute('INSERT INTO history(url,title) VALUES(?,?)',
                      (f'https://{rng.getrandbits(48):x}.example/{tx}/{j}', data))
        if tx % 3 == 2:
            c.execute('DELETE FROM history WHERE id IN (SELECT id FROM history ORDER BY id LIMIT 2)')
        c.commit()
    wal = Path(str(live) + '-wal').read_bytes()
    # Separate byte snapshots are taken *before* closing the connection.
    c.close()
    assert len(wal) > 32
    return main, wal


def add_frame(wal: bytes, *, commit_pages: int = 0, page_id: int | None = None, page_data: bytes | None = None) -> bytes:
    size = u32(wal, 8)
    last = len(wal) - (24 + size)
    assert last >= 32 and (len(wal) - 32) % (24 + size) == 0
    payload = bytes(wal[last + 24:last + 24 + size]) if page_data is None else page_data
    assert len(payload) == size
    frame = bytearray(24 + size)
    store32(frame, 0, u32(wal, last) if page_id is None else page_id)
    store32(frame, 4, commit_pages)
    frame[8:16] = wal[16:24]
    frame[24:] = payload
    return rechecksum(wal + frame)


def new_case(root: Path, index: int, rng: random.Random) -> dict:
    root.mkdir(parents=True, exist_ok=True)
    page_size = 65536 if index == 0 else [512, 1024, 2048, 4096, 8192, 1024][index % 6]
    main, wal = real_sqlite_pair(root, rng, page_size, 1 + index % 4, index % 4 == 0)
    scenario = index
    size = u32(wal, 8)
    stride = size + 24
    frames = (len(wal) - 32) // stride
    assert frames >= 1
    original_expected = reference(main, wal)
    assert original_expected
    data = bytearray(wal)
    if scenario == 0:  # legitimate single/multi-commit WAL
        pass
    elif scenario == 1:
        pass
    elif scenario == 2:  # no sidecar
        wal = None
    elif scenario == 3:  # incomplete valid tail not committed
        wal = add_frame(wal)
    elif scenario == 4:  # valid redundant committed page after the original end
        wal = add_frame(wal, commit_pages=original_expected[-1]['database_pages'])
    elif scenario == 5:  # late checksum damage
        data[-3] ^= 1; wal = bytes(data)
    elif scenario == 6:  # late salt mismatch
        data[-stride + 8] ^= 1; wal = bytes(data)
    elif scenario == 7:  # truncated full last frame
        wal = wal[:-rng.randrange(1, 20)]
    elif scenario == 8:  # extra dangling bytes
        wal = wal + os.urandom(rng.randrange(1, 23))
    elif scenario == 9:  # header checksum mismatch
        data[24] ^= 1; wal = bytes(data)
    elif scenario == 10:  # bad header page size
        store32(data, 8, page_size * 2); wal = bytes(data)
    elif scenario == 11:  # invalid main SQLite file without a recoverable sidecar
        main = b'broken-database!!' + main[17:]
        wal = None
    elif scenario == 12:  # alternate official checksum byte order
        wal = rechecksum(wal, flip_endian=True)
    elif scenario == 13:  # late partial frame header only
        wal = wal + b'\x00' * rng.randrange(1, 24)
    elif scenario == 14:  # stale salt in a validly signed suffix
        wal = add_frame(wal, commit_pages=original_expected[-1]['database_pages'])
        data = bytearray(wal); data[-stride + 8] ^= 1; wal = rechecksum(bytes(data))
    elif scenario == 15:  # invalid later frame, forged valid suffix afterward
        wal = add_frame(wal, commit_pages=original_expected[-1]['database_pages'])
        wal = add_frame(wal, commit_pages=original_expected[-1]['database_pages'])
        data = bytearray(wal); data[-2*stride + 20] ^= 1; wal = bytes(data)
    elif scenario == 16:  # live valid series, only last complete commit counts
        wal = add_frame(wal)
        wal = add_frame(wal, commit_pages=original_expected[-1]['database_pages'])
    elif scenario == 17:  # page 0 is invalid even with a consistent checksum
        wal = add_frame(wal, page_id=0, commit_pages=original_expected[-1]['database_pages'])
    elif scenario == 18:  # salt collision rejected before the first commit
        data[32 + 8] ^= 2; wal = bytes(data)
    elif scenario == 19:  # corrupt first frame checksum
        data[32 + 16] ^= 8; wal = bytes(data)
    elif scenario == 20:  # multiple valid full frames, with stale suffix
        wal = add_frame(wal)
        wal = add_frame(wal, commit_pages=original_expected[-1]['database_pages'])
        data = bytearray(wal); data[-stride+8] ^= 1; wal = bytes(data)
    elif scenario == 21:  # valid frame reset salts, tail is old epoch
        data[16:24] = bytes(rng.randrange(256) for _ in range(8))
        # New header's salt mismatches old complete frames.
        wal = rechecksum(bytes(data))
    elif scenario == 22:  # valid uncommitted frame then torn subsequent frame
        wal = add_frame(wal)
        wal += bytes(rng.getrandbits(8) for _ in range(rng.randrange(8, size // 2)))
    elif scenario == 23:  # committed prefix, damaged page payload then intact suffix
        wal = add_frame(wal, commit_pages=original_expected[-1]['database_pages'])
        data = bytearray(wal)
        # Deliberately corrupt the last original page without updating its checksum
        data[len(wal) - 2*stride + 30] ^= 8
        wal = bytes(data)
    else:
        raise AssertionError(scenario)
    name = f'case_{index:02d}_{rng.getrandbits(64):016x}.db'
    path = root.parent / name
    path.write_bytes(main)
    if wal is not None:
        Path(str(path) + '-wal').write_bytes(wal)
    expect_error = not main.startswith(b'SQLite format 3\x00')
    return {'input_name': name, 'expected': [] if expect_error else reference(main, wal),
            'expect_error': expect_error, 'scenario': index,
            'sha_main': hashlib.sha256(main).hexdigest(),
            'sha_wal': hashlib.sha256(wal or b'').hexdigest()}


def create_cases(directory: Path, seed: int, count: int = 24) -> list[dict]:
    rng = random.Random(seed)
    out = []
    directory.mkdir(parents=True, exist_ok=True)
    for i in range(count):
        work = directory / f'__work_{i:02d}'
        try:
            out.append(new_case(work, i, rng))
        finally:
            shutil.rmtree(work)
    return out


if __name__ == '__main__':
    with tempfile.TemporaryDirectory() as td:
        records = create_cases(Path(td), int.from_bytes(os.urandom(8),'big'))
        for x in records:
            print(x['scenario'], len(x['expected']), x['expected'][-1] if x['expected'] else None)
