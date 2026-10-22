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
from damascus_a.aggregate import aggregate
from damascus_a.backend import BackendUnavailable
from damascus_a.environment import AdmissionLedger, EnvironmentValidationError
from damascus_a.file_codec import Ternary32Codec
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


if __name__ == '__main__':
    unittest.main()
