"""Independent arithmetic checks; these are correctness fixtures, not security tests."""

import dataclasses
import importlib.util
import random
import unittest


def multiplication_oracle(left, right, q):
    """Ordinary Z[X] product followed by separate division by X^n + 1."""
    n = len(left)
    product = [0] * (2 * n - 1)
    for degree in range(len(product)):
        product[degree] = sum(left[i] * right[degree - i]
                              for i in range(n) if 0 <= degree - i < n)
    for degree in range(len(product) - 1, n - 1, -1):
        product[degree - n] -= product[degree]
    return tuple(c % q for c in product[:n])


class AlgebraTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(importlib.util.find_spec('damascus_a.algebra'),
                             'the typed reference algebra is not implemented')
        from damascus_a import algebra
        self.a = algebra

    def test_negacyclic_product_matches_independent_integer_oracle(self):
        for q in (17, 2**31 - 1, 2**521 - 1):
            for n in (1, 2, 4, 8):
                ring = self.a.Ring(q, n)
                for seed in range(30):
                    rng = random.Random(seed + n)
                    left = tuple(rng.randrange(-2*q, 2*q) for _ in range(n))
                    right = tuple(rng.randrange(-2*q, 2*q) for _ in range(n))
                    self.assertEqual((ring.element(left) * ring.element(right)).coefficients,
                                     multiplication_oracle(left, right, q))

    def test_variable_is_negative_one_in_terminal_ring(self):
        ring = self.a.Ring(17, 1)
        self.assertEqual(ring.element((5,)).times_variable().coefficients, (12,))
        ring = self.a.Ring(17, 4)
        self.assertEqual(ring.element((2, 3, 4, 5)).times_variable().coefficients,
                         (12, 2, 3, 4))

    def test_even_odd_decomposition_and_scalar_arithmetic(self):
        ring = self.a.Ring(17, 4)
        a = ring.element((2, -3, 7, 9))
        even, odd = a.split_even_odd()
        self.assertEqual(even.coefficients, (2, 7))
        self.assertEqual(odd.coefficients, (14, 9))
        self.assertEqual(even.ring, self.a.Ring(17, 2))
        self.assertEqual((a + a.scale(-1)), ring.zero())
        self.assertEqual((a - a), ring.zero())
        self.assertEqual(a.scale(3).coefficients, (6, 8, 4, 10))
        self.assertEqual(ring.inverse_scalar(3), 6)
        with self.assertRaises(ValueError):
            self.a.Ring(15, 2).inverse_scalar(3)
        with self.assertRaises(ValueError):
            self.a.Ring(17, 1).zero().split_even_odd()

    def test_module_inner_product_uses_all_coordinates(self):
        ring = self.a.Ring(17, 2)
        witness = ((1, -1), (2, 3))
        generators = ((ring.element((2, 4)), ring.element((3, 8))),
                      (ring.element((7, 9)), ring.element((11, 13))))
        actual = self.a.module_inner(witness, generators)
        expected = tuple(tuple(sum(multiplication_oracle(witness[i],
                                  generators[i][k].coefficients, 17)[j]
                                  for i in range(2)) % 17 for j in range(2))
                         for k in range(2))
        self.assertEqual(tuple(x.coefficients for x in actual), expected)

    def test_rejects_noncanonical_public_coefficients_and_mutable_inputs(self):
        ring = self.a.Ring(17, 2)
        for coeffs in ((17, 0), (-1, 0), (True, 0), (1.0, 0), (1,), [1, 2]):
            with self.subTest(coeffs=coeffs), self.assertRaises((TypeError, ValueError)):
                self.a.RingElement(ring, coeffs)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            ring.q = 19
        with self.assertRaises(dataclasses.FrozenInstanceError):
            ring.zero().coefficients = (1, 0)
        with self.assertRaises(TypeError):
            ring.element((False, 1))

    def test_rejects_mixed_rings_and_malformed_dimensions(self):
        for q, n in ((1, 2), (16, 2), (17, 0), (17, 3), (True, 2), (17, False)):
            with self.subTest(q=q, n=n), self.assertRaises((TypeError, ValueError)):
                self.a.Ring(q, n)
        a = self.a.Ring(17, 2).zero()
        for b in (self.a.Ring(19, 2).zero(), self.a.Ring(17, 1).zero()):
            with self.assertRaises(ValueError):
                a + b
            with self.assertRaises(ValueError):
                a * b
        for witness, generators in (((), ()), (((1, 2),), ()),
                                     (((1,),), ((a,),)),
                                     (((1, 2),), ((a,), (a,))),
                                     (((1, 2),), ((a, self.a.Ring(19, 2).zero()),))):
            with self.subTest(witness=witness), self.assertRaises((TypeError, ValueError)):
                self.a.module_inner(witness, generators)


if __name__ == '__main__':
    unittest.main()
