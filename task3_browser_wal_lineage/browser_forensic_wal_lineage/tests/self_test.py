"""Trusted independent SQLite-engine cross-check for the Python test oracle."""
import hashlib
import pathlib
import secrets
import shutil
import sqlite3
import tempfile

from generate_cases import create_cases


def check() -> None:
    for _ in range(3):
        with tempfile.TemporaryDirectory(prefix='trusted-sqlite-control-') as td:
            directory = pathlib.Path(td)
            cases = create_cases(directory, secrets.randbits(64))
            assert len(cases) == 24
            for case in cases:
                original = directory / case['input_name']
                clone = directory / ('sqlite_control_' + case['input_name'])
                shutil.copyfile(original, clone)
                original_wal = pathlib.Path(str(original) + '-wal')
                if original_wal.exists():
                    shutil.copyfile(original_wal, str(clone) + '-wal')
                if case['expect_error']:
                    try:
                        c = sqlite3.connect(str(clone))
                        c.execute('SELECT COUNT(*) FROM sqlite_master').fetchone()
                        c.close()
                    except sqlite3.DatabaseError:
                        continue
                    raise AssertionError('SQLite unexpectedly accepts an invalid main file')
                c = sqlite3.connect(str(clone))
                c.execute('SELECT COUNT(*) FROM sqlite_master').fetchone()
                c.close()
                expected_last = (case['expected'][-1]['sha256'] if case['expected']
                                 else hashlib.sha256(original.read_bytes()).hexdigest())
                observed = hashlib.sha256(clone.read_bytes()).hexdigest()
                assert observed == expected_last, (case['scenario'], expected_last, observed)
                # Every historical transaction, not just the latest visible
                # view, must independently agree with genuine SQLite recovery.
                if case['expected']:
                    main = original.read_bytes()
                    page_size = int.from_bytes(main[16:18], 'big')
                    if page_size == 1:
                        page_size = 65536
                    raw_wal = original_wal.read_bytes()
                    for j, snapshot in enumerate(case['expected']):
                        prefix = directory / f'prefix_{case["scenario"]}_{j}.db'
                        prefix.write_bytes(main)
                        nbytes = 32 + snapshot['end_frame'] * (24 + page_size)
                        pathlib.Path(str(prefix) + '-wal').write_bytes(raw_wal[:nbytes])
                        ck = sqlite3.connect(str(prefix))
                        ck.execute('SELECT COUNT(*) FROM sqlite_master').fetchone()
                        ck.close()
                        got = hashlib.sha256(prefix.read_bytes()).hexdigest()
                        assert got == snapshot['sha256'], (case['scenario'], j, got)


if __name__ == '__main__':
    check()
    print('Cross-checked 3 randomized suites × 24 cases against real SQLite recovery')
