"""Experimental rendering consumes actual temporary protocol-run artifacts."""
import copy
import importlib
import importlib.util
import json
from pathlib import Path
import shutil
import tempfile
import unittest

from damascus_a.fold import FoldParameters
from damascus_a.protocol_run import run_protocol_experiment


class ExperimentalPlotTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = tempfile.TemporaryDirectory()
        root = Path(cls.fixture.name)
        kwargs = dict(experimental_only=True, test_seed=71, data=b'\x00\x7f\xff',
            parameters=FoldParameters(2, 4, 2, (1 << 31) - 1), profile='toy-ternary32-full-v1')
        report = run_protocol_experiment(root / 'case', context_mode='decode', **kwargs)
        run_protocol_experiment(root / 'retained', context_mode='retained', **kwargs)
        cls.matrix = dict(schema='DF-experimental-matrix-v1', data_kind='low_security_experiment',
            profile=report['profile'], security_status=report['security_status'], environment_label='cloud',
            cases=[dict(status='ok', d=2, file_bytes=3, context_mode='decode', repetition=0,
                        report='case/protocol-experiment.json')])

    @classmethod
    def tearDownClass(cls):
        cls.fixture.cleanup()

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        shutil.copytree(Path(self.fixture.name) / 'case', self.root / 'case')
        self.matrix_path = self.root / 'matrix.json'
        self.matrix_path.write_text(json.dumps(self.matrix))
        self.report_path = self.root / 'case' / 'protocol-experiment.json'

    def renderer(self):
        self.assertIsNotNone(importlib.util.find_spec('damascus_a.experimental_plots'),
                             'the explicit low-security renderer is not implemented')
        return importlib.import_module('damascus_a.experimental_plots')

    def change_report(self, change):
        report = json.loads(self.report_path.read_text())
        change(report)
        self.report_path.write_text(json.dumps(report))

    def test_real_artifacts_drive_figures_and_missing_baselines_stay_pending(self):
        renderer = self.renderer()
        summary = renderer.summarize_experimental(self.matrix_path)
        report = json.loads(self.report_path.read_text())
        self.assertEqual(summary['figures']['A1']['status'], 'available')
        self.assertEqual(summary['figures']['A2']['status'], 'partial')
        self.assertEqual(summary['figures']['A3']['status'], 'available')
        self.assertEqual(summary['figures']['A4']['status'], 'partial')
        self.assertEqual(summary['figures']['A5']['status'], 'pending')
        communication = summary['communication'][0]
        self.assertEqual(communication['file_bytes'], 3)
        self.assertEqual(communication['full_proof_bytes'],
            sum(r['serialization']['full_proof']['bytes'] for r in report['epochs']) / 2)
        self.assertEqual(len(communication['round_record_bytes']), 2)
        amortization = summary['amortization'][-1]
        running = sum(row['prove_ns'] + row['verify_ns'] for row in report['epochs'])
        self.assertEqual(amortization['excluding_setup_ns'], running / 2)
        self.assertEqual(amortization['including_setup_ns'], (report['setup_once_ns'] + running) / 2)
        result = renderer.render_experimental(self.matrix_path, self.root / 'figures')
        self.assertEqual(result['source_matrix_sha256'], summary['source_matrix_sha256'])
        self.assertTrue((self.root / 'figures' / 'A1.svg').is_file())
        self.assertTrue((self.root / 'figures' / 'A4-cloud-supplement.png').is_file())
        self.assertFalse(any(path.suffix in ('.bin', '.sqlite3', '.jsonl')
                             for path in (self.root / 'figures').rglob('*')))
        svg = (self.root / 'figures' / 'A1.svg').read_text()
        for required in ('LOW-SECURITY EXPERIMENT', 'TEST_ONLY', 'cloud', 'not production security'):
            self.assertIn(required, svg)
        self.assertIn('pending', (self.root / 'figures' / 'A5-status.md').read_text())

    def test_untagged_or_claimed_production_results_are_rejected_before_output(self):
        renderer = self.renderer()
        for key, value in (('data_kind', 'correctness_test'), ('security_established', True),
                           ('publication_eligible', True)):
            with self.subTest(key=key):
                original = self.report_path.read_text()
                self.change_report(lambda r: r.__setitem__(key, value))
                with self.assertRaises(ValueError):
                    renderer.render_experimental(self.matrix_path, self.root / 'not-created')
                self.assertFalse((self.root / 'not-created').exists())
                self.report_path.write_text(original)

    def test_corrupted_artifact_is_rejected(self):
        renderer = self.renderer()
        report = json.loads(self.report_path.read_text())
        proof = self.root / 'case' / report['epochs'][0]['serialization']['full_proof']['path']
        proof.write_bytes(proof.read_bytes() + b'changed')
        with self.assertRaisesRegex(ValueError, 'artifact'):
            renderer.summarize_experimental(self.matrix_path)

    def test_supplied_report_digest_must_match(self):
        renderer = self.renderer()
        matrix = copy.deepcopy(self.matrix)
        matrix['cases'][0]['report_sha256'] = '0' * 64
        self.matrix_path.write_text(json.dumps(matrix))
        with self.assertRaisesRegex(ValueError, 'report hash'):
            renderer.summarize_experimental(self.matrix_path)

    def test_partition_offsets_and_bytes_are_checked(self):
        renderer = self.renderer()
        self.change_report(lambda r: r['epochs'][0]['serialization']['parts'][1].__setitem__('offset', 0))
        with self.assertRaisesRegex(ValueError, 'partition'):
            renderer.summarize_experimental(self.matrix_path)

    def test_timing_gap_is_rejected(self):
        renderer = self.renderer()
        self.change_report(lambda r: r['epochs'][0].__setitem__('verify_ns', r['epochs'][0]['verify_ns'] + 1))
        with self.assertRaisesRegex(ValueError, 'timing'):
            renderer.summarize_experimental(self.matrix_path)

    def test_repeated_epoch_is_not_amortized_as_a_new_epoch(self):
        renderer = self.renderer()
        self.change_report(lambda r: r['epochs'][1].__setitem__('epoch_id', r['epochs'][0]['epoch_id']))
        with self.assertRaisesRegex(ValueError, 'epoch'):
            renderer.summarize_experimental(self.matrix_path)

    def test_report_and_artifact_paths_cannot_escape_case_directory(self):
        renderer = self.renderer()
        self.change_report(lambda r: r['epochs'][0]['serialization']['full_proof'].__setitem__(
            'path', '../outside.bin'))
        with self.assertRaisesRegex(ValueError, 'path'):
            renderer.summarize_experimental(self.matrix_path)

    def test_retained_initial_decode_is_separate_from_later_reuse(self):
        renderer = self.renderer()
        shutil.rmtree(self.root / 'case')
        shutil.copytree(Path(self.fixture.name) / 'retained', self.root / 'case')
        matrix = copy.deepcopy(self.matrix)
        matrix['cases'][0]['context_mode'] = 'retained'
        self.matrix_path.write_text(json.dumps(matrix))
        summary = renderer.summarize_experimental(self.matrix_path)
        self.assertEqual({row['context_sample'] for row in summary['verify']},
                         {'retained-first-decode', 'retained-reuse'})

    def test_one_report_cannot_be_counted_twice_as_independent_repetitions(self):
        renderer = self.renderer()
        matrix = copy.deepcopy(self.matrix)
        matrix['cases'].append(dict(matrix['cases'][0], repetition=1))
        self.matrix_path.write_text(json.dumps(matrix))
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            renderer.summarize_experimental(self.matrix_path)


if __name__ == '__main__':
    unittest.main()
