"""Exact CPU backend differentials; no timing or security assertions."""
import importlib
import importlib.util
import random
import unittest
from contextvars import Context
from unittest.mock import patch

from damascus_a import algebra, backend, fold, protocol, wire
from damascus_a.file_codec import Ternary32Codec
from damascus_a.protocol_types import EpochContext, ProtocolParameters
from tests.test_protocol import test_evidence


def inner_oracle(witness, generators, q, n):
    """Ordinary integer convolution, then a separate X^n=-1 reduction."""
    coordinates = []
    for coordinate in range(len(generators[0])):
        product = [0] * (2 * n - 1)
        for left, generator in zip(witness, generators):
            right = generator[coordinate].coefficients
            for degree in range(2 * n - 1):
                product[degree] += sum(left[i] * right[degree - i]
                                       for i in range(n) if 0 <= degree - i < n)
        for degree in range(2 * n - 2, n - 1, -1):
            product[degree - n] -= product[degree]
        coordinates.append(tuple(value % q for value in product[:n]))
    return tuple(coordinates)


class ArithmeticBackendTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(importlib.util.find_spec('damascus_a.arithmetic'),
                             'the optional exact arithmetic backend is missing')
        self.arithmetic = importlib.import_module('damascus_a.arithmetic')
        self.assertTrue(callable(getattr(backend, 'using_backend', None)),
                        'context-local backend selection is missing')

    def sample(self, q=17, n=2, count=3, rank=2):
        rng = random.Random(418 + n + count + rank)
        ring = algebra.Ring(q, n)
        witness = tuple(tuple(rng.randrange(-2*q, 2*q) for _ in range(n))
                        for _ in range(count))
        generators = tuple(tuple(ring.element(tuple(rng.randrange(q) for _ in range(n)))
                                 for _ in range(rank)) for _ in range(count))
        return witness, generators

    def test_module_inner_matches_reference_and_independent_oracle(self):
        for q in (15, 17, (1 << 131) - 1, (1 << 521) - 1):
            for n, count, rank in ((1, 3, 3), (2, 1, 2), (4, 3, 2), (8, 2, 1)):
                with self.subTest(q_bits=q.bit_length(), n=n, count=count, rank=rank):
                    witness, generators = self.sample(q, n, count, rank)
                    original = (witness, generators)
                    expected = inner_oracle(witness, generators, q, n)
                    results = []
                    for name in ('cpu-reference', 'cpu-fused'):
                        with backend.using_backend(name):
                            result = algebra.module_inner(witness, generators)
                        self.assertEqual(tuple(x.coefficients for x in result), expected)
                        results.append(result)
                    self.assertEqual(*results)
                    self.assertEqual((witness, generators), original)

    def test_signed_lifts_zero_terms_cancellation_and_last_coordinate(self):
        q, n = (1 << 521) - 1, 4
        ring = algebra.Ring(q, n)
        huge = (1 << 2048) + 7
        zero = ring.zero()
        last = ring.element((0, 0, 0, q - 1))
        cases = (
            (((0, 0, 0, 0),), ((zero, last),)),
            (((-huge, 0, 0, 1),), ((zero, last),)),
            (((huge, -1, 0, 0), (-huge, 1, 0, 0)), ((last, zero), (last, zero))),
        )
        for witness, generators in cases:
            expected = inner_oracle(witness, generators, q, n)
            with backend.using_backend('cpu-fused'):
                actual = algebra.module_inner(witness, generators)
            self.assertEqual(tuple(x.coefficients for x in actual), expected)
        self.assertEqual(cases[1][0][0][0], -huge)

    def test_fused_kernel_consumes_terms_once_and_returns_canonical_ints(self):
        engine = self.arithmetic.CpuFusedBackend()
        seen = []
        def terms():
            for pair in (((-18,), (16,)), ((1 << 200,), (1,))):
                seen.append(pair)
                yield pair
        result = engine.accumulate_negacyclic(terms(), n=1, q=17)
        self.assertEqual(result, ((-18 * 16 + (1 << 200)) % 17,))
        self.assertEqual(len(seen), 2)
        self.assertIs(type(result[0]), int)
        self.assertEqual(engine.accumulate_negacyclic(iter(()), n=2, q=17), (0, 0))

    def test_kernel_rejects_noninteger_coefficients_and_bad_dimensions(self):
        engine = self.arithmetic.CpuFusedBackend()
        for terms, n, q in (([((True,), (1,))], 1, 17),
                            ([((1.0,), (1,))], 1, 17),
                            ([((1,), (1, 2))], 1, 17),
                            ([([1], (1,))], 1, 17),
                            ([], True, 17), ([], 3, 17), ([], 1, 16)):
            with self.subTest(terms=terms, n=n, q=q):
                with self.assertRaises((TypeError, ValueError)):
                    engine.accumulate_negacyclic(iter(terms), n=n, q=q)

    def test_module_inner_keeps_validation_and_never_mutates_input(self):
        a = algebra.Ring(17, 2).zero()
        bad = algebra.Ring(19, 2).zero()
        cases = (((), ()), (((1, 2),), ()), (((1,),), ((a,),)),
                 (((True, 2),), ((a,),)), (([1, 2],), ((a,),)),
                 (((1, 2), (3, 4)), ((a,), (bad,))),
                 (((1, 2), (3, 4)), ((a,), (a, a))))
        for witness, generators in cases:
            before = repr((witness, generators))
            errors = []
            for name in ('cpu-reference', 'cpu-fused'):
                with backend.using_backend(name):
                    try:
                        algebra.module_inner(witness, generators)
                    except (TypeError, ValueError) as error:
                        errors.append((type(error), str(error)))
                    else:
                        self.fail('malformed input must be rejected')
            self.assertEqual(*errors)
            self.assertEqual(repr((witness, generators)), before)

    def test_fused_dispatch_runs_after_validation_and_propagates_errors(self):
        witness, generators = self.sample()
        marker = RuntimeError('candidate arithmetic failed')
        # Replacing the kernel failure is needed to distinguish real dispatch
        # from merely changing a telemetry label or silently falling back.
        with patch.object(self.arithmetic.CpuFusedBackend, 'accumulate_negacyclic',
                          side_effect=marker):
            algebra.module_inner(witness, generators)
            with backend.using_backend('cpu-fused'):
                with self.assertRaises(TypeError):
                    algebra.module_inner(((False, 1),), (generators[0],))
                with self.assertRaises(RuntimeError) as caught:
                    algebra.module_inner(witness, generators)
                self.assertIs(caught.exception, marker)
            algebra.module_inner(witness, generators)

    def test_nested_context_restores_on_error_and_isolated_context_defaults(self):
        self.assertIsNone(backend.get_arithmetic_backend())
        with backend.using_backend('cpu-fused'):
            fused = backend.get_arithmetic_backend()
            self.assertIsInstance(fused, self.arithmetic.CpuFusedBackend)
            self.assertIsNone(Context().run(backend.get_arithmetic_backend))
            with self.assertRaisesRegex(RuntimeError, 'body failure'):
                with backend.using_backend('cpu-reference'):
                    self.assertIsNone(backend.get_arithmetic_backend())
                    raise RuntimeError('body failure')
            self.assertIs(backend.get_arithmetic_backend(), fused)
        self.assertIsNone(backend.get_arithmetic_backend())

    def test_invalid_backend_does_not_enter_or_change_active_context(self):
        with backend.using_backend('cpu-fused'):
            active = backend.get_arithmetic_backend()
            for name, error in (('automatic', ValueError), ('gpu', backend.BackendUnavailable)):
                with self.assertRaises(error):
                    with backend.using_backend(name):
                        self.fail('unsupported backend context must not enter')
                self.assertIs(backend.get_arithmetic_backend(), active)

    def test_backends_produce_identical_protocol_bytes_and_verification(self):
        codec = Ternary32Codec()
        pp = ProtocolParameters(fold.FoldParameters(2, 4, 2, (1 << 521) - 1), codec.descriptor)
        outcomes = []
        for name in ('cpu-reference', 'cpu-fused'):
            sampler = random.Random(931)
            with backend.using_backend(name):
                setup = protocol.setup(pp, policy='correctness', randbelow=sampler.randrange)
                registered = protocol.register_bytes(setup, b'backend-fixture', b'\x00\x7f\xff',
                    codec=codec, policy='correctness')
                ctx = EpochContext(registered.registration, b'epoch', b'seed', b'100')
                proved = protocol.prove_epoch(ctx, registered.witness, policy='correctness')
                verified = protocol.verify_published(proved.proof_bytes, ctx,
                    policy='correctness', **test_evidence(ctx, proved.proof_bytes))
            self.assertTrue(verified.accepted, verified.reason)
            outcomes.append((registered.witness, wire.encode_registration(registered.registration),
                             wire.encode_context(ctx), proved.proof_bytes, proved.proof.opening))
        self.assertEqual(*outcomes)


if __name__ == '__main__':
    unittest.main()
