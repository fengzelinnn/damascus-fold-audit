"""Small actual protocol runs: correctness evidence only, never paper data."""
import csv
import dataclasses
import hashlib
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from damascus_a import protocol, transcript, wire
from damascus_a import protocol_run
from damascus_a.aggregate import aggregate
from damascus_a.backend import BackendUnavailable
from damascus_a.environment import AdmissionLedger, EnvironmentValidationError
from damascus_a.file_codec import Ternary32Codec
from damascus_a.fold import FoldParameters
from damascus_a.protocol_run import (TestOnlyEpochValidator,
    TestOnlyPublicationValidator, run_protocol_correctness, simulated_deadline)


class ProtocolRunTests(unittest.TestCase):
    def test_explicit_scope_and_new_output_are_required(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'new'
            for kwargs in ({}, {'correctness_only': 1},
                           {'correctness_only': True, 'epochs': 1},
                           {'correctness_only': True, 'epochs': 5},
                           {'correctness_only': True, 'epochs': True},
                           {'correctness_only': True, 'data': b'four'},
                           {'correctness_only': True, 'test_seed': True}):
                with self.subTest(kwargs=kwargs), self.assertRaises((ValueError, TypeError)):
                    run_protocol_correctness(target, **kwargs)
                self.assertFalse(target.exists())
            with self.assertRaises(BackendUnavailable):
                run_protocol_correctness(target, correctness_only=True, backend='gpu')
            self.assertFalse(target.exists())
            target.mkdir()
            marker = target / 'do-not-overwrite'
            marker.write_text('existing')
            with self.assertRaises(FileExistsError):
                run_protocol_correctness(target, correctness_only=True)
            self.assertEqual(marker.read_text(), 'existing')

    def test_actual_artifacts_timings_fresh_epochs_and_replay(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory) / 'run'
            report = run_protocol_correctness(out, correctness_only=True, test_seed=41)
            self.assertEqual(report, json.loads((out / 'protocol-correctness.json').read_text()))
            self.assertEqual(report['data_kind'], 'correctness_test')
            self.assertEqual(report['cache'], 'uncontrolled')
            for key in ('formal_measurement', 'publication_eligible', 'certify_real_time',
                        'security_established', 'production_ready'):
                self.assertIs(report[key], False)
            self.assertTrue(report['external_conditions_not_established'])
            self.assertTrue(report['non_paper'])
            self.assertEqual(report['parameter_audit']['status'], 'rejected_known_attack')
            self.assertTrue(report['parameter_audit']['attacks'])
            self.assertEqual(report['randomness']['setup_source'], 'injected_test_sampler')
            rows = report['epochs']
            self.assertEqual(len(rows), 2)
            self.assertEqual(len({r['epoch_id'] for r in rows}), 2)
            self.assertEqual(len({r['seed_hex'] for r in rows}), 2)
            self.assertEqual([r['epoch_sequence'] for r in rows], [1, 2])
            self.assertEqual([r['setup_ns'] for r in rows], [report['setup_once_ns'], 0])
            self.assertGreater(report['setup_once_ns'], 0)
            registration = wire.decode_registration((out / 'registration.bin').read_bytes())
            witness = Ternary32Codec().encode((out / 'input.bin').read_bytes(), registration.pp.arithmetic)
            for row in rows:
                self.assertEqual(row['data_kind'], 'correctness_test')
                self.assertEqual(row['cache'], 'uncontrolled')
                self.assertTrue(row['accepted'])
                self.assertTrue(row['admitted'])
                self.assertEqual(row['status'], 'ok')
                stages = row['stages_ns']
                self.assertEqual(set(stages), {'parsing_context', 'challenges', 'generator_replay',
                    'commitment_parity', 'norm', 'opening', 'admission', 'other'})
                self.assertEqual(sum(stages.values()), row['verify_ns'])
                self.assertTrue(all(type(t) is int and t >= 0 for t in stages.values()))
                self.assertGreater(stages['opening'], 0)
                self.assertGreater(stages['admission'], 0)
                self.assertEqual(len(row['rounds']), 2)
                self.assertTrue(all(r['duration_ns'] > 0 for r in row['rounds']))
                raw = (out / row['serialization']['full_proof']['path']).read_bytes()
                parts = []
                offset = 0
                for part in row['serialization']['parts']:
                    artifact = part['artifact']
                    part_raw = (out / artifact['path']).read_bytes()
                    self.assertEqual(part['offset'], offset)
                    self.assertEqual(len(part_raw), artifact['bytes'])
                    self.assertEqual(hashlib.sha256(part_raw).hexdigest(), artifact['sha256'])
                    offset += len(part_raw)
                    parts.append(part_raw)
                self.assertEqual(b''.join(parts), raw)
                self.assertEqual(offset, row['serialization']['full_proof']['bytes'])
                self.assertEqual(hashlib.sha256(raw).hexdigest(), row['serialization']['full_proof']['sha256'])
                auxiliary = row['auxiliary_artifacts']
                ctx = wire.decode_context((out / auxiliary['context']['path']).read_bytes())
                self.assertEqual(ctx.registration, registration)
                regenerated = protocol.prove_epoch(ctx, witness, policy='correctness')
                self.assertEqual(regenerated.proof_bytes, raw)
                epoch_provider = TestOnlyEpochValidator(ctx)
                publication_provider = TestOnlyPublicationValidator(ctx, raw)
                evidence = dict(epoch_validator=epoch_provider,
                    publication_validator=publication_provider,
                    epoch_evidence=(out / auxiliary['epoch_evidence']['path']).read_bytes(),
                    publication_evidence=(out / auxiliary['publication_evidence']['path']).read_bytes())
                historical = protocol.verify_published(raw, ctx, policy='correctness', **evidence)
                self.assertTrue(historical.accepted, historical.reason)
                replay = protocol.verify(raw, ctx, ledger=AdmissionLedger(out / 'admission.sqlite3'),
                                         policy='correctness', **evidence)
                self.assertEqual(replay.reason, 'replayed_epoch')
                self.assertFalse(replay.accepted)
                self.assertEqual(row['diagnostics']['same_epoch_replay']['reason'], 'replayed_epoch')
                self.assertTrue(row['diagnostics']['historical_verification']['accepted'])
            self.assertFalse(rows[1]['diagnostics']['previous_epoch_proof']['accepted'])
            with sqlite3.connect(out / 'admission.sqlite3') as connection:
                self.assertEqual(connection.execute('SELECT count(*) FROM damascus_admissions_v1').fetchone()[0], 2)
            with (out / 'protocol-correctness.csv').open(newline='') as stream:
                csv_rows = list(csv.DictReader(stream))
            self.assertEqual(len(csv_rows), 2)
            self.assertTrue(all(r['data_kind'] == 'correctness_test' for r in csv_rows))
            self.assertEqual(len((out / 'epochs.jsonl').read_text().splitlines()), 2)
            expected = report['setup_once_ns'] + sum(r['prove_ns'] + r['verify_ns'] for r in rows)
            self.assertEqual(report['fresh_epoch_cost']['total_ns'], expected)
            with self.assertRaises(ValueError):
                aggregate(rows, 'A1', publication=True)

    def test_explicit_test_seed_reproduces_wire_bytes_and_backend_is_honest(self):
        with tempfile.TemporaryDirectory() as directory:
            first, second = (Path(directory) / name for name in ('first', 'second'))
            a = run_protocol_correctness(first, correctness_only=True, test_seed=7)
            b = run_protocol_correctness(second, correctness_only=True, test_seed=7,
                                         backend='gpu', allow_cpu_fallback=True)
            self.assertEqual(a['randomness']['test_seed'], 7)
            self.assertEqual(b['backend']['requested'], 'gpu')
            self.assertEqual(b['backend']['actual'], 'cpu-reference')
            self.assertTrue(b['backend']['fallback'])
            self.assertTrue(b['backend']['reason'])
            for relative in ('public-parameters.bin', 'registration.bin',
                             'epochs/0001/context.bin', 'epochs/0001/proof.bin',
                             'epochs/0002/context.bin', 'epochs/0002/proof.bin'):
                self.assertEqual((first / relative).read_bytes(), (second / relative).read_bytes())

    def test_default_setup_uses_system_secrets(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch('damascus_a.protocol_run.protocol.setup', wraps=protocol.setup) as setup:
                report = run_protocol_correctness(Path(directory) / 'run', correctness_only=True, data=b'')
            self.assertIsNone(setup.call_args.kwargs.get('randbelow'))
            self.assertEqual(report['randomness']['setup_source'], 'system_secrets')
            self.assertIsNone(report['randomness']['test_seed'])
            self.assertEqual(report['file_bytes'], 0)

    def test_test_only_evidence_checks_exact_objects_and_simulated_deadline(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory) / 'run'
            run_protocol_correctness(out, correctness_only=True, test_seed=11)
            ctx = wire.decode_context((out / 'epochs/0001/context.bin').read_bytes())
            raw = (out / 'epochs/0001/proof.bin').read_bytes()
            epoch = TestOnlyEpochValidator(ctx)
            publication = TestOnlyPublicationValidator(ctx, raw)
            assertion = epoch.validate(ctx, epoch.evidence)
            self.assertEqual(publication.validate(ctx, raw, publication.evidence, assertion).proof_digest,
                             transcript.proof_digest(raw))
            changed = dataclasses.replace(ctx, seed=b'changed')
            with self.assertRaises(EnvironmentValidationError):
                epoch.validate(changed, epoch.evidence)
            for candidate_raw, evidence in ((raw + b'changed', publication.evidence),
                                             (raw, publication.evidence + b'changed')):
                with self.assertRaises(EnvironmentValidationError):
                    publication.validate(ctx, candidate_raw, evidence, assertion)
            late = TestOnlyPublicationValidator(ctx, raw, receipt_tick=101)
            with self.assertRaises(EnvironmentValidationError):
                late.validate(ctx, raw, late.evidence, assertion)
            boundary = TestOnlyPublicationValidator(ctx, raw, receipt_tick=100)
            boundary.validate(ctx, raw, boundary.evidence, assertion)
            changed = dataclasses.replace(ctx, deadline=simulated_deadline(89))
            with self.assertRaises(EnvironmentValidationError):
                publication.validate(changed, raw, publication.evidence, assertion)


class ProtocolExperimentTests(unittest.TestCase):
    def setUp(self):
        self.run_experiment = getattr(protocol_run, 'run_protocol_experiment', None)
        self.assertTrue(callable(self.run_experiment), 'explicit experiment collector is missing')
        self.parameters = FoldParameters(2, 4, 2, (1 << 31) - 1)

    def test_provenance_covers_present_experiment_orchestration_modules(self):
        source_files = protocol_run._sources()['source_files_sha256']
        package = Path(protocol_run.__file__).parent
        for name in ('experiments', 'experimental_plots'):
            if (package / (name + '.py')).is_file():
                self.assertIn('damascus_a/' + name + '.py', source_files)

    def test_missing_required_source_cannot_silently_disappear_from_provenance(self):
        original_is_file, original_read_bytes = Path.is_file, Path.read_bytes
        def exists(path):
            return False if path.name == 'protocol.py' else original_is_file(path)
        def read(path):
            if path.name == 'protocol.py':
                raise FileNotFoundError('required protocol source is missing')
            return original_read_bytes(path)
        with patch.object(Path, 'is_file', exists), patch.object(Path, 'read_bytes', read):
            with self.assertRaises(FileNotFoundError):
                protocol_run._sources()

    def test_explicit_experiment_gate_and_preflight_precede_output_and_setup(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory) / 'run'
            base = dict(parameters=self.parameters, profile='low-security-test', data=b'abc')
            bad = ({}, {'experimental_only': 1}, {'experimental_only': True, 'epochs': 0},
                   {'experimental_only': True, 'epochs': 33},
                   {'experimental_only': True, 'context_mode': 'pretend-cold'},
                   {'experimental_only': True, 'data': b'four'},
                   {'experimental_only': True, 'profile': ''},
                   {'experimental_only': True, 'test_seed': True},
                   {'experimental_only': True, 'parameters': FoldParameters(100, 4, 2, 2147483647)})
            with patch('damascus_a.protocol_run.protocol.setup', wraps=protocol.setup) as setup:
                for changes in bad:
                    with self.subTest(changes=changes), self.assertRaises((ValueError, TypeError)):
                        self.run_experiment(out, **(base | changes))
                    self.assertFalse(out.exists())
                setup.assert_not_called()

    def test_modes_measure_complete_verify_and_preserve_exact_artifacts(self):
        with tempfile.TemporaryDirectory() as directory:
            reports = []
            for mode in ('decode', 'retained'):
                out = Path(directory) / mode
                report = self.run_experiment(out, parameters=self.parameters, profile='low-security-test',
                    data=b'abc', epochs=2, test_seed=37, experimental_only=True, context_mode=mode)
                reports.append(report)
                self.assertEqual(report, json.loads((out / 'protocol-experiment.json').read_text()))
                self.assertEqual(report['data_kind'], 'low_security_experiment')
                self.assertEqual(report['context_mode'], mode)
                self.assertEqual(report['cache'], 'uncontrolled')
                self.assertFalse(report['cache_policy']['generator_result_cache'])
                self.assertIn('reuse_enabled', report['cache_policy'])
                self.assertEqual(report['cache_policy']['reuse_enabled'], mode == 'retained')
                self.assertEqual(report['cache_policy']['os_cache'], 'uncontrolled')
                self.assertEqual(report['security_status'], 'not_established_low_security_experiment')
                self.assertEqual(report['profile'], 'low-security-test')
                self.assertGreater(report['ledger_init_ns'], 0)
                self.assertFalse(report['formal_measurement'])
                self.assertFalse(report['publication_eligible'])
                self.assertFalse(report['certify_real_time'])
                self.assertEqual(len(report['epochs']), 2)
                self.assertEqual([row['first_context_decode'] for row in report['epochs']],
                                 [True, mode == 'decode'])
                self.assertEqual(report['parameters'], dataclasses.asdict(self.parameters))
                self.assertEqual(len({r['seed_hex'] for r in report['epochs']}), 2)
                for row in report['epochs']:
                    self.assertEqual(row['profile'], 'low-security-test')
                    self.assertEqual(row['parameters'], report['parameters'])
                    self.assertEqual(row['parameter_audit'], report['parameter_audit'])
                    self.assertEqual(row['hardware'], report['hardware'])
                    self.assertEqual(row['external_provider'], 'TEST_ONLY_SIMULATED_PROVIDER')
                    self.assertTrue(row['accepted'] and row['admitted'])
                    self.assertGreater(row['verifier_init_ns'], 0)
                    self.assertGreater(row['verify_call_ns'], 0)
                    self.assertEqual(row['verify_ns'], row['verifier_init_ns'] + row['verify_call_ns'])
                    self.assertEqual(sum(row['stages_ns'].values()), row['verify_ns'])
                    self.assertEqual(row['stages_ns']['verifier_init'], row['verifier_init_ns'])
                    self.assertGreater(row['stages_ns']['opening'], 0)
                    self.assertGreater(row['stages_ns']['admission'], 0)
                    self.assertEqual(row['diagnostics']['same_epoch_replay']['reason'], 'replayed_epoch')
                    self.assertEqual(row['context_mode'], mode)
                    self.assertEqual(row['cache_policy']['registration_reused'],
                                     mode == 'retained' and not row['first_context_decode'])
                    source_files = row['provenance']['source_files_sha256']
                    for name in ('arithmetic', 'resources', 'cli'):
                        self.assertIn('damascus_a/' + name + '.py', source_files)
                variable = sum(r['prove_ns'] + r['verify_ns'] for r in report['epochs'])
                self.assertEqual(report['setup_excluded_cost']['total_ns'], variable)
                self.assertEqual(report['fresh_epoch_cost']['total_ns'], report['setup_once_ns'] + variable)
                with sqlite3.connect(out / 'admission.sqlite3') as connection:
                    self.assertEqual(connection.execute('SELECT count(*) FROM damascus_admissions_v1').fetchone()[0], 2)
                with (out / 'protocol-experiment.csv').open(newline='') as stream:
                    csv_rows = list(csv.DictReader(stream))
                self.assertEqual(len(csv_rows), len(report['epochs']))
                jsonl_rows = [json.loads(line) for line in (out / 'epochs.jsonl').read_text().splitlines()]
                self.assertEqual(jsonl_rows, report['epochs'])
                for csv_row, row in zip(csv_rows, report['epochs']):
                    self.assertEqual(csv_row['context_mode'], mode)
                    self.assertEqual(int(csv_row['verify_call_ns']), row['verify_call_ns'])
                    self.assertEqual(json.loads(csv_row['parameters_json']), row['parameters'])
                    self.assertEqual(json.loads(csv_row['parameter_audit_json']), row['parameter_audit'])
                    self.assertEqual(json.loads(csv_row['row_json']), row)
                with self.assertRaises(ValueError):
                    aggregate(report['epochs'], 'A1', publication=True)
            for relative in ('public-parameters.bin', 'registration.bin', 'epochs/0001/context.bin',
                             'epochs/0001/proof.bin', 'epochs/0002/context.bin', 'epochs/0002/proof.bin'):
                self.assertEqual((Path(directory) / 'decode' / relative).read_bytes(),
                                 (Path(directory) / 'retained' / relative).read_bytes())

    def test_context_modes_use_distinct_verifier_state_without_skipping_checks(self):
        with tempfile.TemporaryDirectory() as directory:
            for mode in ('decode', 'retained'):
                contexts = []
                prove_contexts = []
                original_verify, original_prove = protocol.verify, protocol.prove_epoch
                def record_verify(raw, ctx, **kwargs):
                    result = original_verify(raw, ctx, **kwargs)
                    if result.admitted:
                        contexts.append(ctx)
                    return result
                def record_prove(ctx, *args, **kwargs):
                    prove_contexts.append(ctx)
                    return original_prove(ctx, *args, **kwargs)
                with patch('damascus_a.protocol_run.protocol.verify', side_effect=record_verify), \
                     patch('damascus_a.protocol_run.protocol.prove_epoch', side_effect=record_prove):
                    self.run_experiment(Path(directory) / mode, parameters=self.parameters,
                        profile='state-lifetime-test', data=b'a', epochs=2, test_seed=9,
                        experimental_only=True, context_mode=mode)
                self.assertEqual(len(contexts), 2)
                for verifier_ctx, prover_ctx in zip(contexts, prove_contexts):
                    self.assertEqual(verifier_ctx, prover_ctx)
                    self.assertIsNot(verifier_ctx, prover_ctx)
                    self.assertIsNot(verifier_ctx.registration, prover_ctx.registration)
                if mode == 'retained':
                    self.assertIs(contexts[0].registration, contexts[1].registration)
                else:
                    self.assertIsNot(contexts[0].registration, contexts[1].registration)

    def test_actual_backend_context_and_explicit_gpu_fallback(self):
        from damascus_a.backend import get_arithmetic_backend
        with tempfile.TemporaryDirectory() as directory:
            seen = []
            original_setup = protocol.setup
            def observe(*args, **kwargs):
                seen.append(get_arithmetic_backend())
                return original_setup(*args, **kwargs)
            with patch('damascus_a.protocol_run.protocol.setup', side_effect=observe):
                fused = self.run_experiment(Path(directory) / 'fused', parameters=self.parameters,
                    profile='backend-test', data=b'a', epochs=1, test_seed=8,
                    experimental_only=True, backend='cpu-fused')
            self.assertIsNotNone(seen[0])
            self.assertIsNone(get_arithmetic_backend())
            self.assertEqual(fused['backend']['actual'], 'cpu-fused')
            fallback = self.run_experiment(Path(directory) / 'fallback', parameters=self.parameters,
                profile='backend-test', data=b'a', epochs=1, test_seed=8, experimental_only=True,
                backend='gpu', allow_cpu_fallback=True)
            self.assertEqual(fallback['backend']['actual'], 'cpu-reference')
            self.assertTrue(fallback['backend']['fallback'])
            self.assertIsNone(fallback['resources']['peak_vram_bytes'])
            with self.assertRaises(BackendUnavailable):
                self.run_experiment(Path(directory) / 'no-gpu', parameters=self.parameters,
                    profile='backend-test', data=b'a', experimental_only=True, backend='gpu')
            self.assertFalse((Path(directory) / 'no-gpu').exists())


if __name__ == '__main__':
    unittest.main()
