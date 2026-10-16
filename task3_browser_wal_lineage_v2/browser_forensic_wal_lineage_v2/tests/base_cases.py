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


