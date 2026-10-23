import importlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


class ExperimentalEntryTests(unittest.TestCase):
    def module(self):
        self.assertIsNotNone(importlib.util.find_spec('damascus_a.experiments'),
                             'bounded experimental matrix entry is required')
        return importlib.import_module('damascus_a.experiments')

    def test_depth_input_is_bounded_and_unambiguous(self):
        module = self.module()
        self.assertEqual(module.parse_depths('2,3,5'), (2, 3, 5))
        for value in ('', '2,2', '2,,3', '2,-1', '8', '2,3.0'):
            with self.assertRaises(ValueError, msg=value):
                module.parse_depths(value)

    def test_explicit_experiment_authorization_precedes_output(self):
        module = self.module()
        with tempfile.TemporaryDirectory() as root:
            out = Path(root) / 'matrix'
            with self.assertRaisesRegex(ValueError, 'experimental_only'):
                module.run_experiment_matrix(out, depths=(2,), epochs=2, repetitions=1)
            self.assertFalse(out.exists())

    def test_resource_rejection_precedes_file_generation_and_worker(self):
        module = self.module()
        with tempfile.TemporaryDirectory() as root:
            out = Path(root) / 'matrix'
            with patch.object(module.subprocess, 'run') as spawn:
                with self.assertRaises(ValueError):
                    module.run_experiment_matrix(out, depths=(99,), experimental_only=True)
                spawn.assert_not_called()
            self.assertFalse(out.exists())

    def test_valid_shape_over_memory_budget_never_spawns(self):
        module = self.module()
        with tempfile.TemporaryDirectory() as root:
            out = Path(root) / 'matrix'
            with patch.object(module.subprocess, 'run') as spawn:
                with self.assertRaisesRegex(ValueError, 'max_estimated_python_bytes'):
                    module.run_experiment_matrix(out, depths=(5,), memory_mib=1,
                                                 experimental_only=True)
                spawn.assert_not_called()
            self.assertFalse(out.exists())

    def test_real_subprocesses_preserve_same_context_and_proof_bytes(self):
        module = self.module()
        with tempfile.TemporaryDirectory() as root:
            out = Path(root) / 'matrix'
            report = module.run_experiment_matrix(out, depths=(2,), epochs=2,
                repetitions=1, test_seed=123, backend='cpu-fused',
                experimental_only=True, environment_label='test-environment')
            self.assertEqual(report['status'], 'complete')
            self.assertEqual(report['data_kind'], 'low_security_experiment')
            self.assertEqual(len(report['cases']), 2)
            children = [json.loads((out / case['report']).read_text()) for case in report['cases']]
            self.assertEqual([row['proof_id'] for row in children[0]['epochs']],
                             [row['proof_id'] for row in children[1]['epochs']])
            self.assertNotEqual(children[0]['epochs'][0]['proof_id'],
                                children[0]['epochs'][1]['proof_id'])
            for child in children:
                self.assertFalse(child['security_established'])
                self.assertEqual(child['file_bytes'], 3)
                self.assertEqual(child['backend']['actual'], 'cpu-fused')
                self.assertEqual(child['evidence_provider']['kind'], 'TEST_ONLY_SIMULATED_PROVIDER')
                for row in child['epochs']:
                    self.assertTrue(row['accepted'] and row['admitted'])
                    self.assertEqual(sum(row['stages_ns'].values()), row['verify_ns'])
                    self.assertEqual(row['verify_init_ns'] if 'verify_init_ns' in row else row['verifier_init_ns'],
                                     row['stages_ns']['verifier_init'])
            self.assertFalse((out / 'RUN_INCOMPLETE.json').exists())

    def test_timeout_is_recorded_as_failed_measurement_without_report(self):
        module = self.module()
        with tempfile.TemporaryDirectory() as root:
            out = Path(root) / 'matrix'
            with patch.object(module.subprocess, 'run',
                              side_effect=subprocess.TimeoutExpired('worker', 1)):
                report = module.run_experiment_matrix(out, depths=(2,), epochs=1,
                    repetitions=1, context_modes=('decode',), experimental_only=True)
            self.assertEqual(report['status'], 'complete_with_failures')
            self.assertEqual(report['cases'][0]['status'], 'timeout')
            self.assertNotIn('report', report['cases'][0])
            self.assertTrue((out / 'RUN_INCOMPLETE.json').exists())

    def test_protocol_experiment_cli_requires_explicit_flag(self):
        self.module()
        with tempfile.TemporaryDirectory() as root:
            out = Path(root) / 'run'
            result = subprocess.run([sys.executable, '-m', 'damascus_a',
                'protocol-experiment', '--output', str(out), '--d', '2',
                '--input-hex', '0001ff'], capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('experimental_only', result.stderr)
            self.assertFalse(out.exists())

    def test_oversized_input_file_rejects_before_run_directory(self):
        self.module()
        with tempfile.TemporaryDirectory() as root:
            input_file = Path(root) / 'oversized.bin'
            input_file.write_bytes(bytes(4097))
            out = Path(root) / 'run'
            result = subprocess.run([sys.executable, '-m', 'damascus_a',
                'protocol-experiment', '--experimental-only', '--output', str(out),
                '--d', '2', '--input-file', str(input_file)], capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('max_input_bytes', result.stderr)
            self.assertFalse(out.exists())

    @unittest.skipUnless(hasattr(os, 'mkfifo'), 'FIFO test requires POSIX')
    def test_fifo_input_rejects_without_waiting_for_a_writer(self):
        self.module()
        with tempfile.TemporaryDirectory() as root:
            input_file = Path(root) / 'fifo'
            os.mkfifo(input_file)
            out = Path(root) / 'run'
            try:
                result = subprocess.run([sys.executable, '-m', 'damascus_a',
                    'protocol-experiment', '--experimental-only', '--output', str(out),
                    '--d', '2', '--input-file', str(input_file)],
                    capture_output=True, text=True, timeout=2)
            except subprocess.TimeoutExpired:
                self.fail('non-regular input blocked before bounded loading')
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('regular file', result.stderr)
            self.assertFalse(out.exists())

    def test_valid_report_with_wrong_requested_case_is_rejected(self):
        module = self.module()
        real_run = subprocess.run

        def wrong_context(command, **kwargs):
            completed = real_run(command, **kwargs)
            output = Path(command[command.index('--output') + 1])
            report_path = output / 'protocol-experiment.json'
            report = json.loads(report_path.read_text())
            report['context_mode'] = 'retained'
            report_path.write_text(json.dumps(report))
            return completed

        with tempfile.TemporaryDirectory() as root:
            with patch.object(module.subprocess, 'run', side_effect=wrong_context):
                report = module.run_experiment_matrix(Path(root) / 'matrix', depths=(2,),
                    epochs=1, repetitions=1, context_modes=('decode',), experimental_only=True)
            self.assertEqual(report['cases'][0]['status'], 'failed')
            self.assertNotIn('report', report['cases'][0])


if __name__ == '__main__':
    unittest.main()
