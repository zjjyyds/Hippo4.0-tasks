#!/usr/bin/env python3
"""Verify actual DBSF payloads with private, fresh cases and a trusted scanner."""

import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path

from generate_cases import generate_all_cases
from sandbox import HarnessSandbox


MAX_PAYLOAD_SIZE = 16 * 1024 * 1024


def filter_args(case):
    args = []
    for field, flag in (('include', '-y'), ('exclude', '-x')):
        if case.get(field):
            args.extend([flag, ','.join(case[field])])
    return args


def normalize_signatures(file_map):
    if not isinstance(file_map, list) or any(not isinstance(s, dict) for s in file_map):
        raise ValueError('file_map must be an array of signature objects')
    # UUIDs are assigned afresh for every scan. All other serialized fields are
    # observable scanner behavior, including confidence and extraction decisions.
    return sorted(json.dumps({k: v for k, v in s.items() if k != 'id'}, sort_keys=True)
                  for s in file_map)


class ReferenceScanner:
    def __init__(self, binary):
        self.binary = Path(binary).resolve()
        if not self.binary.is_file():
            raise RuntimeError(f'Trusted scanner not found: {self.binary}')
        self.cache = {}

    def scan(self, payload, case):
        args = filter_args(case)
        key = (hashlib.sha256(payload).digest(), tuple(args))
        if key not in self.cache:
            proc = subprocess.run([str(self.binary), *args], input=payload,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  env={'PATH': '/nonexistent', 'LC_ALL': 'C.UTF-8'}, timeout=20)
            if proc.returncode:
                raise RuntimeError(f'Trusted scanner failed: {proc.stderr[:1000]!r}')
            self.cache[key] = json.loads(proc.stdout)
        return self.cache[key]


def validate_stream_entry(entry, expected_spec, case_id, scanner, case):
    if not isinstance(entry, dict):
        return False, f'[{case_id}] Derived entry must be an object'
    for field in ('kind', 'stream_id', 'total_payload_size'):
        if type(entry.get(field)) is not type(expected_spec[field]) or entry[field] != expected_spec[field]:
            return False, f'[{case_id}] {field} mismatch'
    offsets = entry.get('carrier_offsets')
    if (not isinstance(offsets, list) or any(type(o) is not int or o < 0 for o in offsets)
            or offsets != sorted(set(offsets)) or offsets != sorted(expected_spec['carrier_offsets'])):
        return False, f'[{case_id}] carrier_offsets must match and be sorted and deduplicated'

    raw = entry.get('payload')
    if (not isinstance(raw, list) or len(raw) != expected_spec['total_payload_size']
            or not 0 < len(raw) <= MAX_PAYLOAD_SIZE
            or any(type(b) is not int or not 0 <= b <= 255 for b in raw)):
        return False, f'[{case_id}] Missing or invalid complete payload byte array'
    payload = bytes(raw)
    expected_digest = expected_spec.get('expected_payload_sha256')
    if not expected_digest:
        raise RuntimeError(f'[{case_id}] Generator failed to supply a payload digest')
    if hashlib.sha256(payload).hexdigest() != expected_digest:
        return False, f'[{case_id}] Recovered payload SHA-256 mismatch'

    child_file_map = entry.get('file_map')
    try:
        if normalize_signatures(child_file_map) != normalize_signatures(scanner.scan(payload, case)):
            return False, f'[{case_id}] file_map differs from pinned Binwalk scanning the recovered bytes'
    except ValueError as error:
        return False, f'[{case_id}] {error}'

    # Hash actual signature content; a textual copyright digest proves nothing.
    for signature in expected_spec.get('expected_child_signatures', []):
        matches = [s for s in child_file_map if s.get('name') == signature['name']
                   and s.get('offset') == signature['offset']]
        if not matches:
            return False, f'[{case_id}] Missing expected signature {signature["name"]}'
        match = matches[0]
        if 'size' in signature and match.get('size') != signature['size']:
            return False, f'[{case_id}] Child signature size mismatch'
        if signature.get('description_contains'):
            if signature['description_contains'] not in match.get('description', ''):
                return False, f'[{case_id}] Child signature description mismatch'
        if signature.get('expected_content_sha256'):
            start = signature['offset']
            end = start + signature['size']
            if hashlib.sha256(payload[start:end]).hexdigest() != signature['expected_content_sha256']:
                return False, f'[{case_id}] Child content SHA-256 mismatch'
    for forbidden in expected_spec.get('forbidden_child_signatures', []):
        if any(s.get('name') == forbidden for s in child_file_map):
            return False, f'[{case_id}] Forbidden child signature {forbidden}'

    # Empty expected nesting is always checked, including terminal depth 3.
    return validate_streams(entry.get('nested_derived', []),
                            expected_spec.get('expected_nested_derived', []),
                            f'{case_id}::nested', scanner, case)


def validate_streams(actual, expected, case_id, scanner, case):
    if not isinstance(actual, list) or len(actual) != len(expected):
        return False, f'[{case_id}] Derived stream count mismatch'
    remaining = list(actual)
    for spec in expected:
        index = next((i for i, entry in enumerate(remaining)
                      if isinstance(entry, dict) and entry.get('stream_id') == spec['stream_id']
                      and entry.get('carrier_offsets') == sorted(spec['carrier_offsets'])), None)
        if index is None:
            return False, f'[{case_id}] Missing expected stream {spec["stream_id"]}'
        ok, message = validate_stream_entry(remaining.pop(index), spec, case_id, scanner, case)
        if not ok:
            return ok, message
    return True, f'[{case_id}] PASSED'


def run_case(sandbox, scanner, fixtures_dir, case):
    case_id = case['id']
    input_bytes = (fixtures_dir / case['file']).read_bytes()
    args = filter_args(case)
    if case.get('enable_derived', False):
        args.append('--derived')
    try:
        proc = sandbox.run(args, input_bytes)
    except subprocess.TimeoutExpired:
        return False, f'[{case_id}] Harness timed out'
    if proc.returncode:
        return False, f'[{case_id}] Harness exited with {proc.returncode}: {proc.stderr[:1000]!r}'
    try:
        data = json.loads(proc.stdout)
    except (ValueError, UnicodeError) as error:
        return False, f'[{case_id}] Invalid JSON: {error}'
    if not isinstance(data, dict):
        return False, f'[{case_id}] AnalysisResults must be an object'
    try:
        if normalize_signatures(data.get('file_map')) != normalize_signatures(scanner.scan(input_bytes, case)):
            return False, f'[{case_id}] Top-level signature map changed from pinned Binwalk'
    except ValueError as error:
        return False, f'[{case_id}] {error}'
    if not case.get('enable_derived', False):
        if 'derived' in data:
            return False, f'[{case_id}] derived must be absent when disabled'
        return True, f'[{case_id}] PASSED (disabled)'
    return validate_streams(data.get('derived', []), case.get('expected_streams', []),
                            case_id, scanner, case)



# Legacy inputs are copied from the pristine upstream commit into the root-owned
# verifier image at build time. They are never taken from the agent workspace.
LEGACY_SIGNATURE_INPUTS = (
    'arj.bin', 'cramfs.bin', '7z.bin', 'squashfs.bin',
    'squashfs_v2.bin', 'yaffs2.bin', 'zip.bin', 'zip_truncated.bin',
)


def check_legacy_signatures(sandbox, scanner, trusted_fixtures):
    """Compare original and submitted scanning for extractor fixtures whose
    extraction integration tests require unavailable system utilities.

    This is a signature compatibility regression, NOT a substitute for
    verifying the third-party extraction commands themselves.
    """
    passed = 0
    for filename in LEGACY_SIGNATURE_INPUTS:
        payload = (trusted_fixtures / filename).read_bytes()
        try:
            proc = sandbox.run([], payload)  # opt-in derived mode stays OFF
        except subprocess.TimeoutExpired:
            print(f'[FAIL] legacy {filename}: harness timed out', flush=True)
            continue
        if proc.returncode:
            print(f'[FAIL] legacy {filename}: harness exit {proc.returncode}', flush=True)
            continue
        try:
            output = json.loads(proc.stdout)
            if not isinstance(output, dict) or 'derived' in output:
                raise ValueError('legacy output must be a JSON object without derived')
            actual = normalize_signatures(output.get('file_map'))
            expected = normalize_signatures(scanner.scan(payload, {}))
            if actual != expected:
                raise ValueError('signature map diverged from pinned upstream')
        except (ValueError, UnicodeError) as error:
            print(f'[FAIL] legacy {filename}: {error}', flush=True)
            continue
        print(f'[OK] legacy {filename}: unchanged pinned signature scan', flush=True)
        passed += 1
    print(f'Legacy signature comparisons: {passed}/{len(LEGACY_SIGNATURE_INPUTS)}', flush=True)
    return passed == len(LEGACY_SIGNATURE_INPUTS)


def main():
    if len(sys.argv) != 4:
        sys.exit(f'Usage: {sys.argv[0]} <submitted_harness> <trusted_scanner> <trusted_runtime_root>')
    scanner = ReferenceScanner(sys.argv[2])
    # Generate only after the untrusted build and regression tests finish. The
    # 0700 directory belongs to the verifier and never enters the jail.
    with HarnessSandbox(sys.argv[1], sys.argv[3]) as sandbox, \
            tempfile.TemporaryDirectory(prefix='dbsf-private-') as private_dir:
        fixtures = Path(private_dir)
        generate_all_cases(fixtures)
        cases = json.loads((fixtures / 'cases_manifest.json').read_text())
        passed = 0
        for case in cases:
            ok, message = run_case(sandbox, scanner, fixtures, case)
            print(f'[{"OK" if ok else "FAIL"}] {message}', flush=True)
            passed += bool(ok)
        print(f'Summary: {passed} passed, {len(cases) - passed} failed out of {len(cases)} tests')
        legacy_ok = check_legacy_signatures(
            sandbox, scanner, Path('/tests/legacy-fixtures'))
        return 0 if passed == len(cases) and legacy_ok else 1


if __name__ == '__main__':
    sys.exit(main())
