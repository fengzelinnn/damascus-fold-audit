"""Fiat--Shamir transcript correctness; no cryptographic-security claim."""
from dataclasses import replace
import hashlib
import unittest
from unittest.mock import patch

from damascus_a.algebra import Ring
from damascus_a.fold import FoldParameters, PublicState, RoundRecord
from damascus_a.protocol_types import EpochContext, ProtocolParameters, Registration, WireLimits
from damascus_a import transcript
from damascus_a.wire import (encode_context, encode_module, encode_registration,
                            encode_round_record, context_binding)


def context(d=2, T=4, q=65537, k=2):
    """Small deterministic public data, not a secure parameter profile."""
    arithmetic = FoldParameters(d=d, T=T, k=k, q=q)
    pp = ProtocolParameters(arithmetic, b"TEST-ONLY-codec")
    ring = Ring(q, 1 << d)
    generators = tuple(tuple(ring.element(tuple((1 + i + coordinate + coefficient) % q for coefficient in range(ring.n))) for coordinate in range(k)) for i in range(ring.n))
    commitment = tuple(ring.element(tuple((9 + coordinate + coefficient) % q for coefficient in range(ring.n))) for coordinate in range(k))
    initial = PublicState(arithmetic, 0, generators, commitment)
    return EpochContext(Registration(pp, b"file-1", 3, initial), b"epoch-1", b"certified-seed", b"opaque-provider-deadline")


def record(ctx, level=0, offset=0):
    p = ctx.registration.pp.arithmetic
    ring, child = Ring(p.q, 1 << (p.d-level)), Ring(p.q, 1 << (p.d-level-1))
    def module(target, start):
        return tuple(target.element(tuple((start + offset + coordinate + coefficient) % p.q for coefficient in range(target.n))) for coordinate in range(p.k))
    return RoundRecord(module(ring, 1), module(ring, 5), module(child, 9), module(child, 13))


def independent_blob(value):
    return len(value).to_bytes(4, "big") + value


def independent_uint(value):
    return independent_blob(value.to_bytes((value.bit_length() + 7)//8, "big"))


def independent_frame(tag, payload):
    return independent_blob(tag) + independent_blob(payload)


def independent_input(ctx, prefix, j, domain, modules):
    payload = independent_blob(encode_context(ctx)) + independent_blob(domain) + independent_uint(j)
    payload += independent_uint(len(prefix))
    payload += b"".join(independent_blob(encode_round_record(previous, index, ctx.registration.pp)) for index, previous in enumerate(prefix))
    payload += b"".join(independent_blob(encode_module(module)) for module in modules)
    return independent_frame(b"DF/FS/v1", payload)


class TranscriptTests(unittest.TestCase):
    def test_exact_encoded_vector_preimage_golden(self):
        p = FoldParameters(1, 4, 1, 17)
        ring, child = Ring(17, 2), Ring(17, 1)
        initial = PublicState(p, 0, ((ring.element((1, 2)),), (ring.element((3, 4)),)), (ring.element((5, 6)),))
        ctx = EpochContext(Registration(ProtocolParameters(p, b"c"), b"f", 0, initial), b"e", b"s", b"D")
        rec = RoundRecord((ring.element((7, 8)),), (ring.element((9, 10)),), (child.element((11,)),), (child.element((12,)),))
        expected = bytes.fromhex(
            "0000000844462f46532f763100000128000000c30000000d44462f636f6e746578742f7631000000ae0000009b0000001244462f726567697374726174696f6e2f7631"
            "000000810000003b0000000844462f70702f76310000002b000000011100000001010000000101000000010400000001630000000e44462d5348414b453235362d7631"
            "0000000166000000000000000000000001020000000c0000000101000000010201020000000c0000000101000000010203040000000c000000010100000001020506"
            "000000016500000001730000000144000000037665630000000000000000000000250000000c44462f6d6f64756c652f76310000001100000001110000000102000000"
            "01010708000000250000000c44462f6d6f64756c652f763100000011000000011100000001020000000101090a"
        )
        self.assertEqual(len(expected), 312)
        self.assertEqual(transcript.vector_oracle_input(ctx, (), 0, rec.L_vec, rec.R_vec), expected)
        self.assertEqual(hashlib.sha256(transcript.polynomial_oracle_input(ctx, (), 0, rec)).hexdigest(), "f676a773ef7d47124840320c13a4fdae604d041ffd1a5e66fee59b0b05acb01c")
        self.assertEqual(transcript.vector_challenge(ctx, (), 0, rec.L_vec, rec.R_vec), 2)
        self.assertEqual(transcript.polynomial_challenge(ctx, (), 0, rec), 1)

    def test_full_context_prefix_and_exact_order_are_in_preimage(self):
        ctx = context()
        preceding = record(ctx, 0)
        current = record(ctx, 1)
        prefix = (preceding,)
        vector = transcript.vector_oracle_input(ctx, prefix, 1, current.L_vec, current.R_vec)
        polynomial = transcript.polynomial_oracle_input(ctx, prefix, 1, current)
        self.assertEqual(vector, independent_input(ctx, prefix, 1, b"vec", (current.L_vec, current.R_vec)))
        self.assertEqual(polynomial, independent_input(ctx, prefix, 1, b"poly", (current.L_vec, current.R_vec, current.L_poly, current.R_poly)))
        self.assertIn(encode_context(ctx), vector)
        self.assertIn(encode_round_record(preceding, 0, ctx.registration.pp), vector)
        self.assertNotEqual(vector, polynomial)

    def test_each_context_field_changes_preimage_without_assuming_small_T_injectivity(self):
        ctx = context()
        current = record(ctx)
        initial = ctx.registration.initial
        ring = initial.ring
        altered_generators = ((ring.element((42,) + initial.generators[0][0].coefficients[1:]),) + initial.generators[0][1:],) + initial.generators[1:]
        variants = [
            replace(ctx, epoch=b"epoch-2"), replace(ctx, seed=b"different-seed"), replace(ctx, deadline=b"different-opaque-deadline"),
            replace(ctx, registration=replace(ctx.registration, file_id=b"file-2")),
            replace(ctx, registration=replace(ctx.registration, file_length=4)),
            replace(ctx, registration=replace(ctx.registration, initial=replace(initial, commitment=(ring.zero(),) + initial.commitment[1:]))),
            replace(ctx, registration=replace(ctx.registration, initial=replace(initial, generators=altered_generators))),
            replace(ctx, registration=replace(ctx.registration, pp=replace(ctx.registration.pp, codec=b"TEST-ONLY-other-codec"))),
        ]
        original = transcript.vector_oracle_input(ctx, (), 0, current.L_vec, current.R_vec)
        for variant in variants:
            with self.subTest(variant=variant):
                self.assertNotEqual(original, transcript.vector_oracle_input(variant, (), 0, current.L_vec, current.R_vec))

    def test_all_preceding_and_current_cross_terms_are_bound(self):
        ctx = context()
        prefix = (record(ctx, 0),)
        current = record(ctx, 1)
        original_vector = transcript.vector_oracle_input(ctx, prefix, 1, current.L_vec, current.R_vec)
        original_poly = transcript.polynomial_oracle_input(ctx, prefix, 1, current)
        for name in ("L_vec", "R_vec", "L_poly", "R_poly"):
            previous_changed = replace(prefix[0], **{name: getattr(record(ctx, 0, 23), name)})
            with self.subTest(prefix_part=name):
                self.assertNotEqual(original_vector, transcript.vector_oracle_input(ctx, (previous_changed,), 1, current.L_vec, current.R_vec))
                self.assertNotEqual(original_poly, transcript.polynomial_oracle_input(ctx, (previous_changed,), 1, current))
            changed = replace(current, **{name: getattr(record(ctx, 1, 23), name)})
            with self.subTest(current_part=name):
                self.assertNotEqual(original_poly, transcript.polynomial_oracle_input(ctx, prefix, 1, changed))
                if name.endswith("vec"):
                    self.assertNotEqual(original_vector, transcript.vector_oracle_input(ctx, prefix, 1, changed.L_vec, changed.R_vec))

    def test_length_framing_separates_ambiguous_concatenations(self):
        ctx = context()
        current = record(ctx)
        left, right = replace(ctx, epoch=b"ab", seed=b"c"), replace(ctx, epoch=b"a", seed=b"bc")
        self.assertNotEqual(transcript.vector_oracle_input(left, (), 0, current.L_vec, current.R_vec), transcript.vector_oracle_input(right, (), 0, current.L_vec, current.R_vec))

    def test_multiple_preceding_records_keep_their_indices_order_and_bytes(self):
        ctx = context(d=3)
        prefix, current = (record(ctx, 0), record(ctx, 1)), record(ctx, 2)
        actual = transcript.vector_oracle_input(ctx, prefix, 2, current.L_vec, current.R_vec)
        self.assertEqual(actual, independent_input(ctx, prefix, 2, b"vec", (current.L_vec, current.R_vec)))
        for index in range(2):
            self.assertIn(encode_round_record(prefix[index], index, ctx.registration.pp), actual)
            changed = prefix[:index] + (record(ctx, index, 31),) + prefix[index+1:]
            self.assertNotEqual(actual, transcript.vector_oracle_input(ctx, changed, 2, current.L_vec, current.R_vec))
        with self.assertRaises(ValueError):
            transcript.vector_oracle_input(ctx, prefix[::-1], 2, current.L_vec, current.R_vec)

    def test_rejects_wrong_index_prefix_length_shape_and_mutability(self):
        ctx = context()
        rec0, rec1 = record(ctx), record(ctx, 1)
        bad = [lambda: transcript.vector_oracle_input(ctx, (), True, rec0.L_vec, rec0.R_vec), lambda: transcript.vector_oracle_input(ctx, (), -1, rec0.L_vec, rec0.R_vec), lambda: transcript.vector_oracle_input(ctx, (), 2, rec0.L_vec, rec0.R_vec), lambda: transcript.vector_oracle_input(ctx, (), 1, rec1.L_vec, rec1.R_vec), lambda: transcript.vector_oracle_input(ctx, [rec0], 1, rec1.L_vec, rec1.R_vec), lambda: transcript.vector_oracle_input(ctx, (rec1,), 1, rec1.L_vec, rec1.R_vec), lambda: transcript.vector_oracle_input(ctx, (), 0, rec1.L_vec, rec1.R_vec), lambda: transcript.polynomial_oracle_input(ctx, (), 0, rec1)]
        for operation in bad:
            with self.subTest(operation=operation), self.assertRaises((TypeError, ValueError)):
                operation()
        wrong_modulus = record(context(q=65539))
        with self.assertRaises(ValueError):
            transcript.vector_oracle_input(ctx, (), 0, wrong_modulus.L_vec, wrong_modulus.R_vec)
        wrong_rank = record(context(k=1))
        with self.assertRaises(ValueError):
            transcript.polynomial_oracle_input(ctx, (), 0, wrong_rank)

    def test_terminal_depth_has_no_challenge(self):
        ctx = context(d=0)
        with self.assertRaises(ValueError):
            transcript.vector_oracle_input(ctx, (), 0, ctx.registration.initial.commitment, ctx.registration.initial.commitment)

    def test_unsupported_suite_never_silently_uses_SHAKE(self):
        ctx = context()
        rec = record(ctx)
        changed = replace(ctx, registration=replace(ctx.registration, pp=replace(ctx.registration.pp, suite=b"UNSUPPORTED-SUITE")))
        with self.assertRaisesRegex(ValueError, "suite"):
            transcript.vector_challenge(changed, (), 0, rec.L_vec, rec.R_vec)
        with self.assertRaisesRegex(ValueError, "suite"):
            transcript.polynomial_challenge(changed, (), 0, rec)

    def test_explicit_wire_limits_propagate_without_changing_canonical_bytes(self):
        ctx, limits = context(), WireLimits(max_metadata_bytes=8192)
        rec = record(ctx)
        calls = (
            lambda c, **kw: transcript.context_digest(c, **kw),
            lambda c, **kw: transcript.registration_digest(c.registration, **kw),
            lambda c, **kw: transcript.admission_key(c, **kw),
            lambda c, **kw: transcript.vector_oracle_input(c, (), 0, rec.L_vec, rec.R_vec, **kw),
            lambda c, **kw: transcript.polynomial_oracle_input(c, (), 0, rec, **kw),
            lambda c, **kw: transcript.vector_challenge(c, (), 0, rec.L_vec, rec.R_vec, **kw),
            lambda c, **kw: transcript.polynomial_challenge(c, (), 0, rec, **kw),
        )
        for operation in calls:
            self.assertEqual(operation(ctx), operation(ctx, limits=limits))
        # A larger explicit metadata budget must reach each nested wire call.
        extended = replace(ctx, registration=replace(ctx.registration, file_id=b"x" * 5000))
        for operation in calls:
            with self.subTest(operation=operation):
                with self.assertRaises(ValueError):
                    operation(extended)
                operation(extended, limits=limits)
                with self.assertRaises(ValueError):
                    operation(ctx, limits=WireLimits(max_metadata_bytes=1))
        # Exercise propagation beyond just the context: both preceding indexed
        # records and current standalone modules exceed the default rank limit.
        wide = context(d=2, k=1025, q=17)
        prefix, current = (record(wide, 0),), record(wide, 1)
        rank_limits = WireLimits(max_module_rank=2048)
        with self.assertRaises(ValueError):
            transcript.vector_oracle_input(wide, prefix, 1, current.L_vec, current.R_vec)
        transcript.vector_oracle_input(wide, prefix, 1, current.L_vec, current.R_vec, limits=rank_limits)
        transcript.polynomial_oracle_input(wide, prefix, 1, current, limits=rank_limits)

    def test_exact_first_b_bits_plus_one_including_b_greater_than_256(self):
        for bits in (2, 7, 8, 9, 256, 257, 521):
            ctx = context(d=1, T=1 << bits, q=(1 << max(607, bits+2))-1)
            rec = record(ctx)
            inputs = (transcript.vector_oracle_input(ctx, (), 0, rec.L_vec, rec.R_vec), transcript.polynomial_oracle_input(ctx, (), 0, rec))
            actual = (transcript.vector_challenge(ctx, (), 0, rec.L_vec, rec.R_vec), transcript.polynomial_challenge(ctx, (), 0, rec))
            for preimage, challenge in zip(inputs, actual):
                # Independent bit-string oracle: take exactly b leading SHAKE bits.
                stream = hashlib.shake_256(preimage).digest((bits+7)//8)
                bit_string = "".join(f"{byte:08b}" for byte in stream)
                expected = int(bit_string[:bits], 2) + 1
                with self.subTest(bits=bits, preimage=preimage[:20]):
                    self.assertEqual(challenge, expected)
                    self.assertLessEqual(1, challenge)
                    self.assertLessEqual(challenge, 1 << bits)
                    if bits == 521:
                        self.assertGreater(challenge, 1 << 256)

    def test_challenge_endpoints_and_exact_XOF_byte_count(self):
        for bits in (2, 8, 9, 257, 521):
            width = (bits+7)//8
            for byte, expected in ((0, 1), (255, 1 << bits)):
                with self.subTest(bits=bits, byte=byte), patch("damascus_a.transcript.hashlib.shake_256") as shake:
                    shake.return_value.digest.return_value = bytes([byte]) * width
                    self.assertEqual(transcript._sample(b"TEST-ONLY known preimage", 1 << bits), expected)
                    shake.assert_called_once_with(b"TEST-ONLY known preimage")
                    shake.return_value.digest.assert_called_once_with(width)

    def test_small_T_collisions_are_permitted_not_mistaken_for_missing_binding(self):
        ctx = context()
        rec = record(ctx)
        preimages, challenges = set(), []
        for i in range(5):
            variant = replace(ctx, seed=bytes([i]))
            preimages.add(transcript.vector_oracle_input(variant, (), 0, rec.L_vec, rec.R_vec))
            challenges.append(transcript.vector_challenge(variant, (), 0, rec.L_vec, rec.R_vec))
        self.assertEqual(len(preimages), 5)
        self.assertLess(len(set(challenges)), 5)  # pigeonhole: T=4

    def test_digest_identifiers_are_domain_separated_and_context_matches_wire(self):
        ctx = context()
        values = [transcript.context_digest(ctx), transcript.registration_digest(ctx.registration), transcript.proof_digest(b"complete-proof-with-integer-opening"), transcript.admission_key(ctx)]
        self.assertTrue(all(type(value) is bytes and len(value) == 32 for value in values))
        self.assertEqual(len(set(values)), 4)
        self.assertEqual(transcript.context_digest(ctx), context_binding(ctx))
        self.assertEqual(values[0], hashlib.sha256(independent_frame(b"DF/context-id/v1", encode_context(ctx))).digest())
        self.assertEqual(values[1], hashlib.sha256(independent_frame(b"DF/registration-id/v1", encode_registration(ctx.registration))).digest())
        self.assertEqual(values[2], hashlib.sha256(independent_frame(b"DF/proof-id/v1", b"complete-proof-with-integer-opening")).digest())
        self.assertEqual(values[3], hashlib.sha256(independent_frame(b"DF/admission-id/v1", independent_blob(encode_registration(ctx.registration)) + independent_blob(ctx.epoch))).digest())
        self.assertNotEqual(transcript.proof_digest(b"proof/opening=1"), transcript.proof_digest(b"proof/opening=2"))
        with self.assertRaises(TypeError):
            transcript.proof_digest(bytearray(b"mutable"))

    def test_admission_key_binds_complete_registration_and_epoch_only(self):
        ctx = context()
        key = transcript.admission_key(ctx)
        self.assertEqual(key, transcript.admission_key(replace(ctx, seed=b"alternate-seed", deadline=b"alternate-deadline")))
        self.assertNotEqual(key, transcript.admission_key(replace(ctx, epoch=b"different-epoch")))
        ring = ctx.registration.initial.ring
        altered = replace(ctx.registration.initial, commitment=(ring.zero(),) + ctx.registration.initial.commitment[1:])
        generators = ((ring.zero(),) + ctx.registration.initial.generators[0][1:],) + ctx.registration.initial.generators[1:]
        altered_generators = replace(ctx.registration.initial, generators=generators)
        for reg in (replace(ctx.registration, file_id=b"other-file"), replace(ctx.registration, file_length=4), replace(ctx.registration, initial=altered), replace(ctx.registration, initial=altered_generators), replace(ctx.registration, pp=replace(ctx.registration.pp, codec=b"other-codec"))):
            self.assertNotEqual(key, transcript.admission_key(replace(ctx, registration=reg)))
        self.assertNotEqual(key, transcript.admission_key(context(T=8)))


if __name__ == "__main__":
    unittest.main()
