"""External boundary binding and persistent admission tests; no time guarantees."""

import dataclasses
import importlib.util
import inspect
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier


class EnvironmentTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(importlib.util.find_spec('damascus_a.environment'),
                             'external validation boundary is not implemented')
        from damascus_a import environment
        self.env = environment

    def result(self, **changes):
        values = dict(context_digest=b'c'*32, registration_digest=b'r'*32,
                      epoch=b'epoch', deadline=b'opaque-limit',
                      provider_id=b'TEST_ONLY-issuer', time_domain=b'TEST_ONLY-order',
                      evidence_digest=b'e'*32)
        values.update(changes)
        return self.env.EpochValidation(**values)

    def test_results_are_immutable_and_require_exact_byte_bindings(self):
        result = self.result()
        with self.assertRaises(dataclasses.FrozenInstanceError):
            result.epoch = b'other'
        for field, value in [('epoch', b''), ('deadline', b''), ('provider_id', b''),
                             ('time_domain', b''), ('epoch', bytearray(b'e')),
                             ('context_digest', b'short'), ('evidence_digest', b''),
                             ('registration_digest', 'r'*32)]:
            with self.subTest(field=field, value=value):
                with self.assertRaises((TypeError, ValueError)):
                    self.result(**{field: value})

    def test_no_concrete_default_issuer_exists(self):
        for cls in (self.env.EpochContextValidator, self.env.PublicationEvidenceValidator):
            with self.assertRaises(TypeError):
                cls(b'provider', b'domain')

    def test_evidence_digest_is_bytes_only_and_content_sensitive(self):
        a = self.env.evidence_digest(b'\0a')
        self.assertEqual(len(a), 32)
        self.assertEqual(a, self.env.evidence_digest(b'\0a'))
        self.assertNotEqual(a, self.env.evidence_digest(b'a'))
        with self.assertRaises(TypeError):
            self.env.evidence_digest(bytearray(b'a'))

    def test_publication_results_require_complete_proof_and_epoch_binding(self):
        self.assertTrue(hasattr(self.env, 'PublicationValidation'))
        epoch = self.result()
        fields = dataclasses.asdict(epoch)
        publication = self.env.PublicationValidation(**fields, proof_digest=b'p'*32,
                                                    epoch_validation=epoch)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            publication.proof_digest = b'q'*32
        for changes in ({'proof_digest': b''}, {'epoch_validation': True},
                        {'epoch_validation': self.result(epoch=b'other')},
                        {'time_domain': b'other-domain'}):
            with self.subTest(changes=changes):
                with self.assertRaises((TypeError, ValueError)):
                    dataclasses.replace(publication, **changes)

    def test_claim_survives_reopening_and_never_replaces_first_proof(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'admission.sqlite'
            first = self.env.AdmissionLedger(path)
            self.assertTrue(first.claim(b'registration/epoch', b'a'*32))
            reopened = self.env.AdmissionLedger(path)
            self.assertFalse(reopened.claim(b'registration/epoch', b'a'*32))
            self.assertFalse(reopened.claim(b'registration/epoch', b'b'*32))
            self.assertTrue(reopened.claim(b'registration/next-epoch', b'a'*32))

    def test_concurrent_connections_admit_exactly_one_proof(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'admission.sqlite'
            ledgers = [self.env.AdmissionLedger(path) for _ in range(12)]
            barrier = Barrier(len(ledgers))
            def claim(index):
                barrier.wait()
                return ledgers[index].claim(b'one-epoch', bytes([index])*32)
            with ThreadPoolExecutor(max_workers=len(ledgers)) as pool:
                accepted = list(pool.map(claim, range(len(ledgers))))
            self.assertEqual(sum(accepted), 1)
            self.assertFalse(self.env.AdmissionLedger(path).claim(b'one-epoch', b'x'*32))

    def test_ledger_rejects_nonpersistent_or_malformed_inputs_without_claim(self):
        with self.assertRaises(ValueError):
            self.env.AdmissionLedger(':memory:')
        with tempfile.TemporaryDirectory() as directory:
            ledger = self.env.AdmissionLedger(Path(directory) / 'admission.sqlite')
            for key, digest in [(b'', b'a'*32), ('key', b'a'*32),
                                (b'key', b''), (b'key', bytearray(b'a'*32))]:
                with self.subTest(key=key, digest=digest):
                    with self.assertRaises((TypeError, ValueError)):
                        ledger.claim(key, digest)
            self.assertTrue(ledger.claim(b'key', b'a'*32))


class BindingTests(unittest.TestCase):
    """Adapters below are TEST ONLY assertions, never certificate implementations."""

    def setUp(self):
        self.assertIsNotNone(importlib.util.find_spec('damascus_a.environment'))
        from damascus_a import environment
        self.env = environment
        for name in ('checked_epoch_validation', 'checked_publication_validation'):
            self.assertTrue(callable(getattr(self.env, name, None)), f'missing {name}')
        from damascus_a.algebra import Ring
        from damascus_a.fold import FoldParameters, initialize
        from damascus_a.protocol_types import EpochContext, ProtocolParameters, Registration, WireLimits
        from damascus_a.transcript import context_digest, registration_digest, proof_digest
        arithmetic = FoldParameters(d=1, T=4, k=1, q=2**31-1)
        ring = Ring(arithmetic.q, 2)
        state = initialize(arithmetic, ((0, 1), (-1, 0)),
                           ((ring.element((2, 3)),), (ring.element((5, 7)),)))
        reg = Registration(ProtocolParameters(arithmetic, b'TEST_ONLY-codec'),
                           b'test-file', 0, state.public)
        self.ctx = EpochContext(reg, b'epoch-1', b's'*32, b'opaque-height-boundary')
        self.epoch_evidence = b'TEST_ONLY epoch evidence'
        self.publication_evidence = b'TEST_ONLY publication evidence'
        self.raw = b'TEST_ONLY opaque proof bytes including integer opening=1'
        env = self.env
        epoch_evidence, publication_evidence = self.epoch_evidence, self.publication_evidence

        class TestEpoch(env.EpochContextValidator):
            """TEST ONLY: fixture response; no authentication or time assertion."""
            changes = None
            reject = False
            limits = WireLimits()
            def validate(adapter, ctx, evidence):
                if adapter.reject or evidence != epoch_evidence:
                    raise env.EnvironmentValidationError('TEST ONLY evidence rejected')
                result = env.EpochValidation(
                    context_digest(ctx, limits=adapter.limits),
                    registration_digest(ctx.registration, limits=adapter.limits),
                    ctx.epoch, ctx.deadline, adapter.provider_id, adapter.time_domain,
                    env.evidence_digest(evidence))
                if adapter.changes is True:
                    return True
                return dataclasses.replace(result, **(adapter.changes or {}))

        class TestPublication(env.PublicationEvidenceValidator):
            """TEST ONLY: fixture response; no authenticated receipt is produced."""
            changes = None
            reject = False
            limits = WireLimits()
            def validate(adapter, ctx, proof_bytes, evidence, epoch_validation):
                if adapter.reject or evidence != publication_evidence:
                    raise env.EnvironmentValidationError('TEST ONLY receipt rejected')
                fields = dict(context_digest=context_digest(ctx, limits=adapter.limits),
                              registration_digest=registration_digest(ctx.registration,
                                                                      limits=adapter.limits),
                              epoch=ctx.epoch, deadline=ctx.deadline,
                              provider_id=adapter.provider_id, time_domain=adapter.time_domain,
                              evidence_digest=env.evidence_digest(evidence),
                              proof_digest=proof_digest(proof_bytes),
                              epoch_validation=epoch_validation)
                if adapter.changes is True:
                    return True
                fields.update(adapter.changes or {})
                return env.PublicationValidation(**fields)

        self.epoch_provider = TestEpoch(b'TEST_ONLY epoch provider', b'TEST_ONLY ordered heights')
        self.publication_provider = TestPublication(b'TEST_ONLY receipt provider',
                                                   b'TEST_ONLY ordered heights')

    def epoch_validation(self):
        return self.env.checked_epoch_validation(self.epoch_provider, self.ctx,
                                                 self.epoch_evidence)

    def publication_validation(self, epoch=None, raw=None):
        return self.env.checked_publication_validation(
            self.publication_provider, self.ctx, self.raw if raw is None else raw,
            self.publication_evidence, self.epoch_validation() if epoch is None else epoch)

    def test_matching_bindings_accept_and_stateless_reverification_is_allowed(self):
        epoch = self.epoch_validation()
        result = self.publication_validation(epoch)
        self.assertEqual(result.epoch_validation, epoch)
        self.assertEqual(result.time_domain, epoch.time_domain)
        self.assertNotEqual(result.provider_id, epoch.provider_id)
        self.assertEqual(result, self.publication_validation(epoch))

    def test_each_wrong_epoch_result_binding_rejects(self):
        for field, value in [('context_digest', b'x'*32), ('registration_digest', b'x'*32),
                             ('epoch', b'other'), ('deadline', b'other'),
                             ('provider_id', b'other'), ('time_domain', b'other'),
                             ('evidence_digest', b'x'*32)]:
            with self.subTest(field=field):
                self.epoch_provider.changes = {field: value}
                with self.assertRaises(self.env.EnvironmentValidationError):
                    self.epoch_validation()

    def test_each_wrong_publication_binding_rejects(self):
        epoch = self.epoch_validation()
        for field, value in [('context_digest', b'x'*32), ('registration_digest', b'x'*32),
                             ('epoch', b'other'), ('deadline', b'other'),
                             ('provider_id', b'other'), ('time_domain', b'other'),
                             ('evidence_digest', b'x'*32), ('proof_digest', b'x'*32),
                             ('epoch_validation', dataclasses.replace(epoch, evidence_digest=b'x'*32))]:
            with self.subTest(field=field):
                self.publication_provider.changes = {field: value}
                with self.assertRaises(self.env.EnvironmentValidationError):
                    self.publication_validation(epoch)

    def test_opening_substitution_does_not_reuse_receipt_binding(self):
        accepted = self.publication_validation()
        self.publication_provider.changes = {'proof_digest': accepted.proof_digest}
        with self.assertRaises(self.env.EnvironmentValidationError):
            self.publication_validation(raw=self.raw.replace(b'opening=1', b'opening=2'))

    def test_missing_provider_boolean_result_and_cross_domain_reject(self):
        with self.assertRaises(self.env.EnvironmentValidationError):
            self.env.checked_epoch_validation(None, self.ctx, self.epoch_evidence)
        with self.assertRaises(self.env.EnvironmentValidationError):
            self.env.checked_publication_validation(None, self.ctx, self.raw,
                self.publication_evidence, self.epoch_validation())
        self.epoch_provider.changes = True
        with self.assertRaises(self.env.EnvironmentValidationError):
            self.epoch_validation()
        self.epoch_provider.changes = None
        self.publication_provider.changes = True
        with self.assertRaises(self.env.EnvironmentValidationError):
            self.publication_validation()
        self.publication_provider.changes = None
        self.publication_provider._time_domain = b'TEST_ONLY different domain'
        with self.assertRaises(self.env.EnvironmentValidationError):
            self.publication_validation()

    def test_rejected_evidence_does_not_consume_admission(self):
        with tempfile.TemporaryDirectory() as directory:
            ledger = self.env.AdmissionLedger(Path(directory) / 'admission.sqlite')
            self.publication_provider.reject = True
            with self.assertRaises(self.env.EnvironmentValidationError):
                receipt = self.publication_validation()
                ledger.claim(b'unclaimed-epoch', receipt.proof_digest)
            self.assertTrue(ledger.claim(b'unclaimed-epoch', b'p'*32))

    def test_mutable_or_empty_evidence_rejects(self):
        for value in (b'', bytearray(self.epoch_evidence)):
            with self.subTest(value=value), self.assertRaises((TypeError, ValueError)):
                self.env.checked_epoch_validation(self.epoch_provider, self.ctx, value)
        for raw, evidence in ((bytearray(self.raw), self.publication_evidence),
                              (self.raw, b''), (b'', self.publication_evidence)):
            with self.subTest(raw=raw, evidence=evidence), self.assertRaises((TypeError, ValueError)):
                self.env.checked_publication_validation(self.publication_provider, self.ctx,
                    raw, evidence, self.epoch_validation())

    def test_explicit_limits_allow_extended_context_and_defaults_still_reject(self):
        from damascus_a.protocol_types import WireLimits
        for helper in (self.env.checked_epoch_validation,
                       self.env.checked_publication_validation):
            self.assertIn('limits', inspect.signature(helper).parameters)
        limits = WireLimits(max_metadata_bytes=8192)
        extended = dataclasses.replace(self.ctx, registration=dataclasses.replace(
            self.ctx.registration, file_id=b'f'*5000))
        # TEST ONLY adapters have their own configured parser/encoder policy;
        # the live abstract adapter signatures intentionally have no limits arg.
        self.epoch_provider.limits = limits
        self.publication_provider.limits = limits
        with self.assertRaises(ValueError):
            self.env.checked_epoch_validation(self.epoch_provider, extended,
                                             self.epoch_evidence)
        epoch = self.env.checked_epoch_validation(self.epoch_provider, extended,
                                                  self.epoch_evidence, limits=limits)
        with self.assertRaises(ValueError):
            self.env.checked_publication_validation(self.publication_provider, extended,
                self.raw, self.publication_evidence, epoch)
        publication = self.env.checked_publication_validation(self.publication_provider,
            extended, self.raw, self.publication_evidence, epoch, limits=limits)
        self.assertEqual(publication.context_digest, epoch.context_digest)
        self.assertEqual(publication.registration_digest, epoch.registration_digest)
        self.assertEqual(publication.epoch_validation, epoch)


if __name__ == '__main__':
    unittest.main()
