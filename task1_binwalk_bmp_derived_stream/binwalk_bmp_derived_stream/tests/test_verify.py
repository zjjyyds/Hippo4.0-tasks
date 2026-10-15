"""Regression tests for manifest spoofing, byte integrity and the real jail."""

import copy
import contextlib
import hashlib
import io
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from generate_cases import generate_all_cases
from make_runtime import make_runtime
from sandbox import HarnessSandbox
from verify import validate_stream_entry, validate_streams


class Scanner:
    def __init__(self, file_map):
        self.file_map = file_map

    def scan(self, payload, case):
        return self.file_map


class IntegrityTests(unittest.TestCase):
    def setUp(self):
        self.payload = bytes(range(32))
        self.expected = {
            'kind': 'bmp-fragmented-stream', 'stream_id': 17,
            'carrier_offsets': [4, 100], 'total_payload_size': len(self.payload),
            'expected_payload_sha256': hashlib.sha256(self.payload).hexdigest(),
            'expected_payload_bytes': len(self.payload),
        }
        self.file_map = [{'id': 'reference-uuid', 'offset': 0, 'name': 'test',
                          'size': 32, 'description': 'known content', 'confidence': 250,
                          'always_display': False, 'extraction_declined': False}]
        self.entry = {k: self.expected[k] for k in ('kind', 'stream_id', 'carrier_offsets', 'total_payload_size')}
        self.entry.update(payload=list(self.payload), file_map=copy.deepcopy(self.file_map))
        self.scanner = Scanner(self.file_map)

    def validate(self, entry=None):
        return validate_stream_entry(self.entry if entry is None else entry,
                                     self.expected, 'test', self.scanner, {})[0]

    def test_correct_bytes_and_map(self):
        self.entry['file_map'][0]['id'] = 'fresh-submission-uuid'
        self.assertTrue(self.validate())

    def test_manifest_only_spoof_is_rejected(self):
        del self.entry['payload']
        self.assertFalse(self.validate())

    def test_self_reported_digest_is_insufficient(self):
        self.entry['payload_sha256'] = self.expected['expected_payload_sha256']
        self.entry['payload'] = [0] * len(self.payload)
        self.assertFalse(self.validate())

    def test_one_changed_byte_is_rejected(self):
        self.entry['payload'][-1] ^= 1
        self.assertFalse(self.validate())

    def test_truncated_bytes_are_rejected(self):
        self.entry['payload'].pop()
        self.assertFalse(self.validate())

    def test_invalid_byte_types_are_rejected(self):
        for bad in (True, -1, 256, '0', 0.0):
            with self.subTest(bad=bad):
                changed = copy.deepcopy(self.entry)
                changed['payload'][0] = bad
                self.assertFalse(self.validate(changed))

    def test_forged_signature_metadata_is_rejected(self):
        self.entry['file_map'][0]['description'] = 'Copyright sha256:' + self.expected['expected_payload_sha256']
        self.assertFalse(self.validate())

    def test_extra_signature_is_rejected(self):
        self.entry['file_map'].append({'name': 'invented', 'offset': 31})
        self.assertFalse(self.validate())

    def test_unexpected_nested_stream_is_rejected(self):
        # Top-level scanning only: any nested derived output is out of contract.
        self.entry['nested_derived'] = [copy.deepcopy(self.entry)]
        self.assertFalse(self.validate())

    def test_nested_output_alone_is_rejected(self):
        # Even a byte-correct nested tree must be rejected: recursion is out of scope.
        self.entry['nested_derived'] = [copy.deepcopy(self.entry)]
        self.assertFalse(self.validate())
        self.entry['nested_derived'][0]['payload'][0] ^= 1
        self.assertFalse(self.validate())

    def test_duplicate_carrier_offsets_are_rejected(self):
        self.entry['carrier_offsets'] = [4, 4, 100]
        self.assertFalse(self.validate())

    def test_one_entry_cannot_satisfy_two_expected_streams(self):
        wrong = copy.deepcopy(self.entry)
        wrong['stream_id'] = 18
        self.assertFalse(validate_streams([self.entry, wrong], [self.expected, self.expected],
                                          'test', self.scanner, {})[0])


class GeneratorTests(unittest.TestCase):
    def test_fresh_ids_payloads_names_and_complete_nested_digests(self):
        with tempfile.TemporaryDirectory() as directory, contextlib.redirect_stdout(io.StringIO()):
            root = Path(directory)
            with patch('generate_cases.secrets.randbits', side_effect=[1234, 0x12345678, 5678, 0x87654321]):
                generate_all_cases(root / 'first')
                generate_all_cases(root / 'second')
            first = json.loads((root / 'first/cases_manifest.json').read_text())
            second = json.loads((root / 'second/cases_manifest.json').read_text())
            self.assertEqual(len(first), 29)
            self.assertEqual([c['id'] for c in first], [c['id'] for c in second])
            self.assertEqual(first[0]['expected_streams'][0]['stream_id'], 1 ^ 0x12345678)
            self.assertEqual(second[0]['expected_streams'][0]['stream_id'], 1 ^ 0x87654321)
            self.assertNotEqual(first[0]['expected_streams'][0]['expected_payload_sha256'],
                                second[0]['expected_streams'][0]['expected_payload_sha256'])
            self.assertTrue(set(c['file'] for c in first).isdisjoint(c['file'] for c in second))

            def check_digests(streams):
                for stream in streams:
                    self.assertRegex(stream['expected_payload_sha256'], r'^[0-9a-f]{64}$')
                    check_digests(stream.get('expected_nested_derived', []))

            for run, cases in (('first', first), ('second', second)):
                for case in cases:
                    self.assertRegex(case['file'], r'^[0-9a-f]{32}\.bin$')
                    self.assertTrue((root / run / case['file']).is_file())
                    check_digests(case.get('expected_streams', []))


@unittest.skipUnless(os.geteuid() == 0 and shutil.which('cc'), 'requires Linux root and cc')
class SandboxTests(unittest.TestCase):
    def test_manifest_files_fds_network_and_privileges_are_isolated(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            probe = root / 'probe'
            secret = root / 'cases_manifest.json'
            secret.write_text('expected_streams must never reach the submission')
            subprocess.run(['cc', str(Path(__file__).with_name('security_probe.c')),
                            '-o', str(probe)], check=True)
            make_runtime(probe, root / 'runtime')
            with HarnessSandbox(probe, root / 'runtime') as jail:
                proc = jail.run([str(secret)], b'')
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertEqual(proc.stdout.strip(), b'isolated')


if __name__ == '__main__':
    unittest.main()
