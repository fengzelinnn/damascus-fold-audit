"""Source-equation differential tests, with no security or protocol assertions."""

import dataclasses
import importlib.util
import random
import subprocess
import sys
import unittest

from damascus_a.algebra import Ring, RingElement
from test_algebra import multiplication_oracle


def commitment_oracle(witness, generators, q):
    """Recompute directly using the independent polynomial multiplication oracle."""
    n, k = len(witness[0]), len(generators[0])
    return tuple(tuple(sum(multiplication_oracle(witness[i],
                              generators[i][coordinate].coefficients, q)[degree]
                              for i in range(len(witness))) % q
                       for degree in range(n)) for coordinate in range(k))


def coefficients(module):
    return tuple(element.coefficients for element in module)


class FoldTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(importlib.util.find_spec('damascus_a.fold'),
                             'the mathematical fold harness is not implemented')
        from damascus_a import fold
        self.f = fold

    def fixture(self, d=1, seed=0, k=3, negative=False):
        q = 2**31 - 1 if d <= 1 else 2**521 - 1
        p = self.f.FoldParameters(d=d, T=4, k=k, q=q)
        ring = Ring(q, 1 << d)
        rng = random.Random(seed)
        witness = tuple(tuple(-1 if negative else rng.randrange(-1, 2)
                              for _ in range(ring.n)) for _ in range(ring.n))
        generators = tuple(tuple(ring.element(tuple(rng.randrange(q) for _ in range(ring.n)))
                                 for _ in range(k)) for _ in range(ring.n))
        return self.f.initialize(p, witness, generators)

    def assert_direct_commitment(self, state):
        self.assertEqual(coefficients(state.public.commitment),
                         commitment_oracle(state.witness, state.public.generators,
                                           state.public.parameters.q))

    def test_random_chains_match_independent_recomputation_at_both_stages(self):
        for d in (1, 2):
            for seed in range(60):
                with self.subTest(d=d, seed=seed):
                    state = initial = self.fixture(d, seed, k=1 + seed % 3)
                    rng = random.Random(1000 + seed)
                    records, challenges = [], []
                    self.assert_direct_commitment(initial)
                    for level in range(d):
                        x, y = rng.randrange(1, 5), rng.randrange(1, 5)
                        n, q = len(state.witness), state.public.parameters.q
                        half = n // 2
                        result = self.f.round_prove(state, x, y)
                        records.append(result.record)
                        challenges.append((x, y))
                        self.assertEqual(coefficients(result.record.L_vec),
                                         commitment_oracle(state.witness[:half],
                                             state.public.generators[half:], q))
                        self.assertEqual(coefficients(result.record.R_vec),
                                         commitment_oracle(state.witness[half:],
                                             state.public.generators[:half], q))
                        expected_witness = tuple(tuple(a + x*b for a, b in zip(left, right))
                            for left, right in zip(state.witness[:half], state.witness[half:]))
                        self.assertEqual(result.vector_state.witness, expected_witness)
                        vector_generators = tuple(tuple(tuple((a + pow(x, -1, q)*b) % q
                            for a, b in zip(left[c].coefficients, right[c].coefficients))
                            for c in range(initial.public.parameters.k))
                            for left, right in zip(state.public.generators[:half],
                                                   state.public.generators[half:]))
                        self.assertEqual(tuple(coefficients(g) for g in result.vector_state.public.generators),
                                         vector_generators)
                        self.assert_direct_commitment(result.vector_state)
                        fe = tuple(poly[::2] for poly in expected_witness)
                        fo = tuple(poly[1::2] for poly in expected_witness)
                        child = Ring(q, half)
                        ge = tuple(tuple(RingElement(child, poly[::2]) for poly in gen)
                                   for gen in vector_generators)
                        go = tuple(tuple(RingElement(child, poly[1::2]) for poly in gen)
                                   for gen in vector_generators)
                        self.assertEqual(coefficients(result.record.L_poly), commitment_oracle(fe, go, q))
                        self.assertEqual(coefficients(result.record.R_poly), commitment_oracle(fo, ge, q))
                        ee = commitment_oracle(fe, ge, q)
                        oo = commitment_oracle(fo, go, q)
                        even_expected = tuple(tuple((a + b) % q for a, b in zip(e, (-o[-1],) + o[:-1]))
                                              for e, o in zip(ee, oo))
                        odd_expected = tuple(tuple((a + b) % q for a, b in zip(L, R))
                                             for L, R in zip(coefficients(result.record.L_poly),
                                                             coefficients(result.record.R_poly)))
                        vector_commitment = coefficients(result.vector_state.public.commitment)
                        self.assertEqual(tuple(poly[::2] for poly in vector_commitment), even_expected)
                        self.assertEqual(tuple(poly[1::2] for poly in vector_commitment), odd_expected)
                        self.assertEqual(result.next_state.witness,
                            tuple(tuple(a + y*b for a, b in zip(left, right))
                                  for left, right in zip(fe, fo)))
                        # Explicit rotate-and-negate oracle for multiplication by Y.
                        next_generators = tuple(tuple(tuple((even + pow(y, -1, q)*odd) % q
                            for even, odd in zip(e.coefficients,
                                (-o.coefficients[-1],) + o.coefficients[:-1]))
                            for e, o in zip(g_even, g_odd)) for g_even, g_odd in zip(ge, go))
                        self.assertEqual(tuple(coefficients(g) for g in result.next_state.public.generators),
                                         next_generators)
                        self.assert_direct_commitment(result.next_state)
                        replayed_round = self.f.round_update(state.public, result.record, x, y)
                        self.assertEqual(replayed_round.vector_state, result.vector_state.public)
                        self.assertEqual(replayed_round.next_state, result.next_state.public)
                        state = result.next_state
                        self.assertEqual(state.public.level, level + 1)
                        self.assertEqual(len(state.witness), 1 << (d-level-1))
                    replayed = self.f.replay(initial.public, tuple(records), tuple(challenges))
                    self.assertEqual(replayed, state.public)
                    opening = self.f.final_open(state)
                    self.assertTrue(self.f.check_terminal(replayed, opening))
                    self.assertFalse(self.f.check_terminal(replayed, opening + 1))

    def test_negative_integer_witness_reaches_exact_honest_bound(self):
        for d in (1, 2):
            state = self.fixture(d=d, negative=True)
            for _ in range(d):
                state = self.f.round_prove(state, 4, 4).next_state
            m = self.f.final_open(state)
            self.assertEqual(m, -(5**(2*d)))
            self.assertLess(m, 0)
            self.assertTrue(self.f.check_terminal(state.public, m))
            self.assertFalse(self.f.check_terminal(state.public, m - state.public.parameters.q))

    def test_original_polynomial_cross_terms_do_not_include_Y(self):
        p = self.f.FoldParameters(d=1, T=4, k=1, q=2**31-1)
        ring = Ring(p.q, 2)
        state = self.f.initialize(p, ((1, 0), (0, 1)),
                                 ((ring.element((2, 3)),), (ring.element((4, 5)),)))
        result = self.f.round_prove(state, 1, 1)
        self.assertEqual(coefficients(result.record.L_poly), ((8,),))
        self.assertEqual(coefficients(result.record.R_poly), ((6,),))
        self.assertEqual(result.next_state.witness, ((2,),))
        self.assertEqual(coefficients(result.next_state.public.generators[0]), ((p.q-2,),))
        self.assertEqual(coefficients(result.next_state.public.commitment), ((p.q-4,),))

    def test_parity_alteration_rejects_and_swapped_polynomial_terms_fail_opening(self):
        state = self.fixture(seed=27)
        result = self.f.round_prove(state, 2, 3)
        record = result.record
        child = record.L_poly[0].ring
        changed = (record.L_poly[0] + child.element((1,)),) + record.L_poly[1:]
        with self.assertRaisesRegex(ValueError, 'parity'):
            self.f.round_update(state.public, dataclasses.replace(record, L_poly=changed), 2, 3)
        swapped = dataclasses.replace(record, L_poly=record.R_poly, R_poly=record.L_poly)
        public = self.f.round_update(state.public, swapped, 2, 3).next_state
        self.assertFalse(self.f.check_terminal(public, self.f.final_open(result.next_state)))
        swapped_vec = dataclasses.replace(record, L_vec=record.R_vec, R_vec=record.L_vec)
        with self.assertRaisesRegex(ValueError, 'parity'):
            self.f.round_update(state.public, swapped_vec, 2, 3)

    def test_missing_Y_changes_opening_and_wrong_last_coordinate_rejects(self):
        state = self.fixture(seed=41)
        result = self.f.round_prove(state, 2, 3)
        terminal = result.next_state.public
        m = self.f.final_open(result.next_state)
        last = terminal.commitment[-1]
        altered = terminal.commitment[:-1] + (last + last.ring.element((1,)),)
        self.assertFalse(self.f.check_terminal(dataclasses.replace(terminal, commitment=altered), m))
        # A faulty '+' in the terminal ring's Y contribution also changes the opening.
        e, _ = result.vector_state.public.commitment[0].split_even_odd()
        faulty = e + result.record.L_poly[0].scale(pow(3, -1, terminal.parameters.q)) + result.record.R_poly[0].scale(3)
        altered = (faulty,) + terminal.commitment[1:]
        self.assertFalse(self.f.check_terminal(dataclasses.replace(terminal, commitment=altered), m))

    def test_norm_uses_transmitted_integer_and_supports_more_than_64_bits(self):
        p = self.f.FoldParameters(d=20, T=4, k=2, q=2**521-1)
        ring = Ring(p.q, 1)
        m = -(2**80)
        generators = ((ring.element((7,)), ring.element((11,))),)
        commitment = tuple(g.scale(m) for g in generators[0])
        terminal = self.f.PublicState(p, 20, generators, commitment)
        self.assertTrue(self.f.check_terminal(terminal, m))
        self.assertFalse(self.f.check_terminal(terminal, m + p.q))
        self.assertFalse(self.f.check_terminal(terminal, m % (2**64)))
        zero_terminal = dataclasses.replace(terminal, generators=((ring.zero(), ring.zero()),),
                                            commitment=(ring.zero(), ring.zero()))
        self.assertTrue(self.f.check_terminal(zero_terminal, p.terminal_bound))
        self.assertFalse(self.f.check_terminal(zero_terminal, p.terminal_bound+1))
        self.assertFalse(self.f.check_terminal(zero_terminal, -p.terminal_bound-1))

    def test_bound_comparison_is_exact_near_bit_and_power_boundaries(self):
        ring = Ring(2**521-1, 1)
        for d in range(9):
            for T in (4, 8, 16):
                p = self.f.FoldParameters(d=d, T=T, k=1, q=ring.q)
                terminal = self.f.PublicState(p, d, ((ring.zero(),),), (ring.zero(),))
                B = (1 + T)**(2*d)
                values = (0, 1, B-1, B, B+1, 2**B.bit_length(), 2**(B.bit_length()-1))
                for value in values:
                    for signed in (value, -value):
                        self.assertEqual(self.f.check_terminal(terminal, signed), abs(signed) <= B)

    def test_rejects_invalid_shapes_types_challenges_and_unreduced_public_data(self):
        initial = self.fixture()
        p = initial.public.parameters
        for change in ({'d': -1}, {'d': True}, {'T': 3}, {'T': 6}, {'k': 0}, {'q': 16}):
            values = dict(d=1, T=4, k=3, q=2**31-1)
            values.update(change)
            with self.subTest(change=change), self.assertRaises((TypeError, ValueError)):
                self.f.FoldParameters(**values)
        for x, y in ((0, 1), (1, 5), (True, 1), (1, 1.0)):
            with self.subTest(x=x, y=y), self.assertRaises((TypeError, ValueError)):
                self.f.round_prove(initial, x, y)
        for witness in (initial.witness[:-1], ((0,), (0,)), ((True, 0), (0, 0)),
                        ((2, 0), (0, 0)), list(initial.witness)):
            with self.subTest(witness=witness), self.assertRaises((TypeError, ValueError)):
                self.f.initialize(p, witness, initial.public.generators)
        for changes in ({'generators': initial.public.generators[:-1]},
                        {'commitment': initial.public.commitment[:-1]}, {'level': 1},
                        {'parameters': dataclasses.replace(p, d=10**100)}):
            with self.subTest(changes=changes), self.assertRaises((TypeError, ValueError)):
                dataclasses.replace(initial.public, **changes)
        with self.assertRaises(ValueError):
            RingElement(Ring(p.q, 1), (p.q,))
        record = self.f.round_prove(initial, 2, 3).record
        for changes in ({'L_poly': record.L_vec}, {'L_vec': record.L_vec[:-1]},
                        {'L_poly': list(record.L_poly)}):
            with self.subTest(changes=changes), self.assertRaises((TypeError, ValueError)):
                malformed = dataclasses.replace(record, **changes)
                self.f.round_update(initial.public, malformed, 2, 3)
        wrong_commitment = (initial.public.commitment[0] + Ring(p.q, 2).element((1, 0)),) + initial.public.commitment[1:]
        wrong_state = dataclasses.replace(initial, public=dataclasses.replace(initial.public, commitment=wrong_commitment))
        with self.assertRaisesRegex(ValueError, 'commitment'):
            self.f.round_prove(wrong_state, 2, 3)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            initial.witness = ()
        with self.assertRaises(ValueError):
            self.f.check_terminal(initial.public, 0)
        with self.assertRaises(ValueError):
            self.f.final_open(initial)
        terminal = self.f.round_prove(initial, 2, 3).next_state.public
        for invalid_opening in (True, 1.0, '1'):
            with self.assertRaises(TypeError):
                self.f.check_terminal(terminal, invalid_opening)
        composite = self.f.FoldParameters(d=1, T=4, k=1, q=15)
        ring = Ring(15, 2)
        state = self.f.initialize(composite, ((1, 0), (0, 1)),
                                  ((ring.element((1, 2)),), (ring.element((3, 4)),)))
        with self.assertRaisesRegex(ValueError, 'invertible'):
            self.f.round_prove(state, 3, 1)

    def test_replay_requires_exact_ordered_round_and_challenge_counts(self):
        initial = self.fixture(d=2)
        first = self.f.round_prove(initial, 2, 3)
        second = self.f.round_prove(first.next_state, 4, 1)
        records, challenges = (first.record, second.record), ((2, 3), (4, 1))
        for bad_records, bad_challenges in ((records[:-1], challenges), (records+records, challenges),
                                           (records, challenges[:-1]), (tuple(reversed(records)), challenges),
                                           (list(records), challenges), (records, ((2, 3, 4), (4, 1)))):
            with self.subTest(records=bad_records), self.assertRaises((TypeError, ValueError)):
                self.f.replay(initial.public, bad_records, bad_challenges)
        with self.assertRaises(ValueError):
            self.f.replay(first.next_state.public, (second.record,), ((4, 1),))

    def test_huge_synthetic_depth_checks_small_values_without_materializing_bound(self):
        script = """
from damascus_a.algebra import Ring
from damascus_a.fold import FoldParameters, PublicState, WitnessState, check_terminal, round_prove
p = FoldParameters(d=10**100, T=4, k=1, q=17)
r = Ring(17, 1)
terminal = PublicState(p, p.d, ((r.zero(),),), (r.zero(),))
assert check_terminal(terminal, -(2**80))
r = Ring(17, 2)
near_terminal = PublicState(p, p.d-1, ((r.zero(),), (r.zero(),)), (r.zero(),))
result = round_prove(WitnessState(near_terminal, ((1, -1), (-1, 1))), 2, 3)
assert result.next_state.public.level == p.d
"""
        try:
            completed = subprocess.run([sys.executable, '-c', script], capture_output=True,
                                       text=True, timeout=1)
        except subprocess.TimeoutExpired:
            self.fail('norm comparison attempted to materialize an enormous bound')
        self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_zero_depth_is_only_the_terminal_math_identity(self):
        initial = self.fixture(d=0, negative=True)
        self.assertEqual(self.f.replay(initial.public, (), ()), initial.public)
        self.assertEqual(self.f.final_open(initial), -1)
        self.assertTrue(self.f.check_terminal(initial.public, -1))
        with self.assertRaises(ValueError):
            self.f.round_prove(initial, 1, 1)


if __name__ == '__main__':
    unittest.main()
