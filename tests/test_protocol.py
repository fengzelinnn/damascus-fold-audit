"""Complete protocol correctness/negative tests with explicit TEST ONLY inputs.

Evidence fixtures below are deliberately not real certification authorities.
No passing test establishes security, seed freshness, or an authenticated cutoff.
"""
import dataclasses
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

from damascus_a import fold, protocol, transcript, wire
from damascus_a.environment import (AdmissionLedger, EpochContextValidator, EpochValidation,
    EnvironmentValidationError, PublicationEvidenceValidator, PublicationValidation,
    evidence_digest)
from damascus_a.protocol_types import EpochContext, ProtocolParameters, WireLimits
from tests.test_codec_interface import TinyTestCodec


class TestEpochEvidence(EpochContextValidator):
    def __init__(self, limits=WireLimits()):
        super().__init__(b'TEST_ONLY-epoch', b'TEST_ONLY-tick')
        self.limits = limits

    def validate(self, ctx, evidence):
        if evidence != transcript.context_digest(ctx, limits=self.limits):
            raise EnvironmentValidationError('test epoch evidence mismatch')
        return EpochValidation(transcript.context_digest(ctx, limits=self.limits),
            transcript.registration_digest(ctx.registration, limits=self.limits), ctx.epoch, ctx.deadline,
            self.provider_id, self.time_domain, evidence_digest(evidence))


class TestPublicationEvidence(PublicationEvidenceValidator):
    def __init__(self, limits=WireLimits()):
        super().__init__(b'TEST_ONLY-publication', b'TEST_ONLY-tick')
        self.limits = limits

    def validate(self, ctx, raw, evidence, epoch_validation):
        if type(evidence) is not bytes or len(evidence) != 40:
            raise EnvironmentValidationError('missing complete test receipt')
        if evidence[:32] != transcript.proof_digest(raw):
            raise EnvironmentValidationError('receipt proof mismatch')
        if int.from_bytes(evidence[32:], 'big') > int(ctx.deadline):
            raise EnvironmentValidationError('test receipt after deadline')
        return PublicationValidation(transcript.context_digest(ctx, limits=self.limits),
            transcript.registration_digest(ctx.registration, limits=self.limits), ctx.epoch, ctx.deadline,
            self.provider_id, self.time_domain, evidence_digest(evidence),
            transcript.proof_digest(raw), epoch_validation)


def test_evidence(ctx, raw, tick=90, limits=WireLimits()):
    return dict(epoch_validator=TestEpochEvidence(limits),
                publication_validator=TestPublicationEvidence(limits),
                epoch_evidence=transcript.context_digest(ctx, limits=limits),
                publication_evidence=transcript.proof_digest(raw)+tick.to_bytes(8, 'big'))


class ProtocolTests(unittest.TestCase):
    def test_custom_wire_limits_propagate_through_prove_evidence_and_admission(self):
        limits = WireLimits(max_metadata_bytes=8192)
        codec = TinyTestCodec()
        pp = ProtocolParameters(fold.FoldParameters(1, 4, 2, 2147483647), codec.descriptor)
        setup = protocol.setup(pp, policy='correctness', limits=limits)
        registered = protocol.register_bytes(setup, b'f' * 5000, b'A', codec=codec,
                                             policy='correctness', limits=limits)
        ctx = EpochContext(registered.registration, b'epoch', b'seed', b'100')
        produced = protocol.prove_epoch(ctx, registered.witness, policy='correctness', limits=limits)
        raw = produced.proof_bytes
        evidence = test_evidence(ctx, raw, limits=limits)
        result = protocol.verify_published(raw, ctx, policy='correctness', limits=limits, **evidence)
        self.assertTrue(result.accepted, result.reason)
        with tempfile.TemporaryDirectory() as directory:
            ledger = AdmissionLedger(Path(directory) / 'admission.sqlite3')
            result = protocol.verify(raw, ctx, policy='correctness', limits=limits,
                                     ledger=ledger, **evidence)
            self.assertTrue(result.admitted, result.reason)
            again = protocol.verify(raw, ctx, policy='correctness', limits=limits,
                                    ledger=ledger, **evidence)
            self.assertEqual(again.reason, 'replayed_epoch')
        with self.assertRaises(ValueError):
            protocol.prove_epoch(ctx, registered.witness, policy='correctness')
        self.assertFalse(protocol.verify_published(raw, ctx, policy='correctness', **evidence).accepted)

    def fixture(self, d=1, k=2, data=b'AB', q=2147483647):
        codec = TinyTestCodec()
        pp = ProtocolParameters(fold.FoldParameters(d, 4, k, q), codec.descriptor)
        counter = iter(range(1, k*(1 << (2*d))+1))
        setup = protocol.setup(pp, policy='correctness', randbelow=lambda q: next(counter) % q)
        registered = protocol.register_bytes(setup, b'test-file', data, codec=codec,
                                              policy='correctness')
        ctx = EpochContext(registered.registration, b'epoch-1', b'test-seed', b'100')
        result = protocol.prove_epoch(ctx, registered.witness, policy='correctness')
        return setup, registered, ctx, result

    def verify(self, ctx, raw, **overrides):
        kwargs = test_evidence(ctx, raw)
        kwargs.update(overrides)
        return protocol.verify_published(raw, ctx, policy='correctness', **kwargs)

    def test_complete_actual_serialization_replay_and_all_timing_stages(self):
        for d in (0, 1, 2):
            _, registered, ctx, produced = self.fixture(d, data=b'A')
            raw = produced.proof_bytes
            self.assertEqual(wire.decode_proof(raw, ctx), produced.proof)
            state = registered.registration.initial
            for trace, record in zip(produced.rounds, produced.proof.records):
                state = fold.round_update(state, record, trace.x, trace.y).next_state
            self.assertTrue(fold.check_terminal(state, produced.proof.opening))
            result = self.verify(ctx, raw)
            self.assertTrue(result.accepted, result.reason)
            self.assertFalse(result.secure_profile)
            self.assertEqual(result.parameter_report.security_status, 'not_established')
            self.assertEqual(result.assurance, 'externally_validated_unreviewed')
            self.assertEqual(result.epoch_validation.provider_id, b'TEST_ONLY-epoch')
            stages = ('parsing_context', 'challenges', 'generator_replay',
                      'commitment_parity', 'norm', 'opening', 'other')
            self.assertEqual(sum(result.timings_ns[name] for name in stages),
                             result.timings_ns['total'])
            self.assertTrue(all(result.timings_ns[name] >= 0 for name in stages))
            self.assertGreater(result.timings_ns['parsing_context'], 0)
            self.assertGreater(result.timings_ns['norm'], 0)
            self.assertGreater(result.timings_ns['opening'], 0)
            if d:
                for name in ('challenges', 'generator_replay', 'commitment_parity'):
                    self.assertGreater(result.timings_ns[name], 0)

    def test_every_user_entry_defaults_to_strict_and_retains_audit(self):
        setup, registered, ctx, produced = self.fixture()
        for operation in (
            lambda: protocol.setup(setup.pp),
            lambda: protocol.register_bytes(setup, b'x', b'A', codec=TinyTestCodec()),
            lambda: protocol.register_encoded(setup, b'x', 2, registered.witness,
                                               codec=TinyTestCodec()),
            lambda: protocol.epoch_init(ctx, registered.witness),
            lambda: protocol.prove_epoch(ctx, registered.witness),
        ):
            with self.assertRaises(protocol.ParameterPolicyError) as caught:
                operation()
            self.assertEqual(caught.exception.parameter_report.security_status, 'not_established')
        result = protocol.verify_published(produced.proof_bytes, ctx,
                                          **test_evidence(ctx, produced.proof_bytes))
        self.assertFalse(result.accepted)
        self.assertEqual(result.reason, 'parameter_policy_not_approved')
        self.assertIn('terminal_lll_bit_bound', result.parameter_report.attacks)

    def test_setup_preflight_before_sampling_and_exact_coefficient_count(self):
        calls = []
        def sampler(q):
            calls.append(q)
            return len(calls) % q
        codec = TinyTestCodec()
        pp = ProtocolParameters(fold.FoldParameters(2, 4, 3, 2147483647), codec.descriptor)
        result = protocol.setup(pp, policy='correctness', randbelow=sampler)
        self.assertEqual(calls, [pp.arithmetic.q] * 48)
        self.assertEqual(result.randomness_source, 'injected_test_sampler')
        with self.assertRaises(ValueError):
            protocol.setup(pp, policy='correctness', randbelow=sampler,
                           limits=WireLimits(max_coefficients=1))
        self.assertEqual(len(calls), 48)
        enormous = dataclasses.replace(pp, arithmetic=dataclasses.replace(pp.arithmetic, d=10**100))
        with self.assertRaises(ValueError):
            protocol.setup(enormous, policy='correctness', randbelow=sampler)
        self.assertEqual(len(calls), 48)
        with self.assertRaises((TypeError, ValueError)):
            protocol.setup(pp, policy='correctness', randbelow=lambda q: q)

    def test_encoded_registration_must_validate_codec_not_only_ternary_shape(self):
        setup, registered, _, _ = self.fixture(data=b'A')
        with self.assertRaises((TypeError, ValueError)):
            protocol.register_encoded(setup, b'x', 1, ((1, 0), (0, 1)),
                                      codec=TinyTestCodec(), policy='correctness')
        with self.assertRaises((TypeError, ValueError)):
            protocol.register_bytes(setup, b'x', b'A', codec=None, policy='correctness')
        again = protocol.register_encoded(setup, b'test-file', 1, registered.witness,
                                          codec=TinyTestCodec(), policy='correctness')
        self.assertEqual(again.registration, registered.registration)

    def test_epoch_starts_from_original_registration_and_checks_opening(self):
        _, registered, ctx, produced = self.fixture()
        state = protocol.epoch_init(ctx, registered.witness, policy='correctness')
        self.assertEqual(state.public.level, 0)
        with self.assertRaises(ValueError):
            protocol.prove_epoch(ctx, ((produced.proof.opening,),), policy='correctness')
        with self.assertRaises(ValueError):
            protocol.prove_epoch(ctx, ((0, 0), (0, 0)), policy='correctness')
        new_ctx = dataclasses.replace(ctx, epoch=b'epoch-2', seed=b'fresh-seed')
        new_proof = protocol.prove_epoch(new_ctx, registered.witness, policy='correctness')
        self.assertTrue(self.verify(new_ctx, new_proof.proof_bytes).accepted)

    def test_all_context_substitutions_reject_old_proof(self):
        _, _, ctx, produced = self.fixture()
        reg = ctx.registration
        replacements = [dataclasses.replace(ctx, **changes) for changes in
                        ({'epoch': b'epoch-2'}, {'seed': b'other'}, {'deadline': b'101'})]
        replacements += [dataclasses.replace(ctx, registration=dataclasses.replace(reg, **change))
                         for change in ({'file_id': b'other'}, {'file_length': 1},
                                        {'pp': dataclasses.replace(reg.pp, codec=b'other')})]
        changed = reg.initial.commitment[0] + reg.initial.ring.element((1, 0))
        replacements.append(dataclasses.replace(ctx, registration=dataclasses.replace(reg,
            initial=dataclasses.replace(reg.initial,
                commitment=(changed,) + reg.initial.commitment[1:]))))
        for changed_ctx in replacements:
            with self.subTest(ctx=changed_ctx):
                self.assertFalse(self.verify(changed_ctx, produced.proof_bytes).accepted)

    def test_missing_or_wrong_external_evidence_and_late_receipt_reject(self):
        _, _, ctx, produced = self.fixture()
        raw = produced.proof_bytes
        for change in ({'epoch_validator': None}, {'publication_validator': None},
                       {'epoch_evidence': b'bad'}, {'publication_evidence': b'bad'}):
            with self.subTest(change=change):
                self.assertFalse(self.verify(ctx, raw, **change).accepted)
        late = test_evidence(ctx, raw, tick=101)
        self.assertFalse(protocol.verify_published(raw, ctx, policy='correctness', **late).accepted)
        on_boundary = test_evidence(ctx, raw, tick=100)
        self.assertTrue(protocol.verify_published(raw, ctx, policy='correctness', **on_boundary).accepted)

    def test_receipt_binds_transmitted_opening_and_full_proof(self):
        _, _, ctx, produced = self.fixture()
        changed = dataclasses.replace(produced.proof, opening=produced.proof.opening + 1)
        raw = wire.encode_proof(changed, ctx)
        old_evidence = test_evidence(ctx, produced.proof_bytes)
        result = protocol.verify_published(raw, ctx, policy='correctness', **old_evidence)
        self.assertFalse(result.accepted)
        self.assertEqual(result.reason, 'external_evidence_rejected')
        self.assertEqual(result.timings_ns['opening'], 0)
        self.assertFalse(self.verify(ctx, raw).accepted)

    def test_integer_alias_rejected_before_modular_opening(self):
        _, _, ctx, produced = self.fixture()
        alias = dataclasses.replace(produced.proof,
                                    opening=produced.proof.opening + ctx.registration.pp.arithmetic.q)
        result = self.verify(ctx, wire.encode_proof(alias, ctx))
        self.assertFalse(result.accepted)
        self.assertEqual(result.reason, 'opening_norm_failed')
        self.assertEqual(result.timings_ns['opening'], 0)

    def test_parity_failure_occurs_before_polynomial_challenge(self):
        _, _, ctx, produced = self.fixture()
        record = produced.proof.records[0]
        changed = record.L_poly[0] + record.L_poly[0].ring.element((1,))
        record = dataclasses.replace(record, L_poly=(changed,) + record.L_poly[1:])
        raw = wire.encode_proof(dataclasses.replace(produced.proof, records=(record,)), ctx)
        with patch.object(transcript, 'polynomial_challenge', side_effect=AssertionError('too early')):
            result = self.verify(ctx, raw)
        self.assertFalse(result.accepted)
        self.assertEqual(result.reason, 'parity_failed')

    def test_terminal_opening_checks_all_k_coordinates(self):
        codec = TinyTestCodec()
        pp = ProtocolParameters(fold.FoldParameters(0, 4, 2, 257), codec.descriptor)
        values = iter((0, 7))
        setup = protocol.setup(pp, randbelow=lambda _: next(values), policy='correctness')
        reg = protocol.register_bytes(setup, b'id', b'A', codec=codec, policy='correctness')
        ctx = EpochContext(reg.registration, b'e', b's', b'100')
        proof = protocol.prove_epoch(ctx, reg.witness, policy='correctness').proof
        raw = wire.encode_proof(dataclasses.replace(proof, opening=0), ctx)
        result = self.verify(ctx, raw)
        self.assertFalse(result.accepted)
        self.assertEqual(result.reason, 'opening_relation_failed')

    def test_canonical_parser_rejects_trailing_truncated_and_wrong_count(self):
        _, _, ctx, produced = self.fixture(d=2)
        for raw in (b'', produced.proof_bytes[:-1], produced.proof_bytes+b'\0'):
            with self.subTest(raw=raw):
                self.assertFalse(self.verify(ctx, raw).accepted)
        for records in (produced.proof.records[:1], produced.proof.records[::-1], ()):
            with self.assertRaises(ValueError):
                wire.encode_proof(dataclasses.replace(produced.proof, records=records), ctx)

    def test_historical_verification_repeatable_admission_persistent_atomic(self):
        _, registered, ctx, produced = self.fixture()
        raw = produced.proof_bytes
        self.assertTrue(self.verify(ctx, raw).accepted)
        self.assertTrue(self.verify(ctx, raw).accepted)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'admissions.db'
            def attempt(_):
                return protocol.verify(raw, ctx, ledger=AdmissionLedger(path),
                    policy='correctness', **test_evidence(ctx, raw))
            AdmissionLedger(path)
            with ThreadPoolExecutor(max_workers=4) as pool:
                results = list(pool.map(attempt, range(4)))
            self.assertEqual(sum(result.accepted for result in results), 1)
            self.assertEqual(sum(result.reason == 'replayed_epoch' for result in results), 3)
            altered = dataclasses.replace(ctx, seed=b'different-seed', deadline=b'102')
            new = protocol.prove_epoch(altered, registered.witness, policy='correctness')
            result = protocol.verify(new.proof_bytes, altered, ledger=AdmissionLedger(path),
                policy='correctness', **test_evidence(altered, new.proof_bytes))
            self.assertEqual(result.reason, 'replayed_epoch')

    def test_failed_proof_does_not_consume_admission_and_missing_ledger_rejects(self):
        _, _, ctx, produced = self.fixture()
        with tempfile.TemporaryDirectory() as directory:
            ledger = AdmissionLedger(Path(directory)/'ledger.db')
            bad = wire.encode_proof(dataclasses.replace(produced.proof, opening=10**10), ctx)
            result = protocol.verify(bad, ctx, ledger=ledger, policy='correctness',
                                     **test_evidence(ctx, bad))
            self.assertFalse(result.accepted)
            raw = produced.proof_bytes
            result = protocol.verify(raw, ctx, ledger=ledger, policy='correctness',
                                     **test_evidence(ctx, raw))
            self.assertTrue(result.accepted, result.reason)
            self.assertFalse(protocol.verify(raw, ctx, ledger=None, policy='correctness',
                                            **test_evidence(ctx, raw)).accepted)
        with self.assertRaises(TypeError):
            protocol.verify(produced.proof_bytes, ctx)


if __name__ == '__main__':
    unittest.main()
