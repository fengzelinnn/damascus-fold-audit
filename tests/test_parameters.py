"""Tests of source parameter boundaries, never cryptographic security tests."""

import unittest

from damascus_a.parameters import screen_terminal_sis, validate_current_parameters


class ParameterTests(unittest.TestCase):
    def test_source_formula_at_one_round(self):
        result = validate_current_parameters(d=1, T=4, k=1, q=2**127 - 1)
        self.assertEqual(result.derived["M"], 4)
        self.assertEqual(result.derived["mu"], 2)
        self.assertEqual(result.derived["B"], 25)
        self.assertEqual(result.derived["H_mu"], 32768)
        self.assertEqual(result.derived["beta_ext"], 104857600)
        self.assertEqual(result.arithmetic_status, "satisfied")
        self.assertEqual(result.primality_status, "unproven")
        self.assertEqual(result.status, "pending_primality_and_security_review")
        self.assertEqual(result.security_status, "not_established")

    def test_small_prime_does_not_create_security_claim(self):
        result = validate_current_parameters(d=0, T=4, k=1, q=257)
        self.assertEqual(result.primality_status, "proven_by_trial_division")
        self.assertEqual(result.status, "pending_security_review")
        self.assertEqual(result.security_status, "not_established")

    def test_source_challenge_set_requires_power_of_two(self):
        for T in (0, 2, 3, 5, 12):
            with self.subTest(T=T):
                result = validate_current_parameters(d=0, T=T, k=1, q=257)
                self.assertEqual(result.status, "rejected_constraints")
                self.assertIn("challenge_bound", result.rejections)

    def test_invalid_python_types_and_dimensions(self):
        for changes in ({"d": True}, {"d": -1}, {"T": 4.0},
                        {"k": 0}, {"q": "257"}):
            with self.subTest(changes=changes):
                values = dict(d=0, T=4, k=1, q=257)
                values.update(changes)
                self.assertEqual(validate_current_parameters(**values).status,
                                 "rejected_constraints")

    def test_modulus_strict_boundary(self):
        for q in (255, 256):
            with self.subTest(q=q):
                self.assertEqual(validate_current_parameters(d=0, T=4, k=1, q=q).status,
                                 "rejected_constraints")
        result = validate_current_parameters(d=1, T=4, k=4, q=209715199)
        self.assertIn("extraction_modulus_bound", result.rejections)
        self.assertEqual(result.arithmetic_status, "failed")

    def test_huge_depth_is_rejected_before_constructing_dimensions(self):
        result = validate_current_parameters(d=10**100, T=4, k=1, q=257)
        self.assertEqual(result.status, "rejected_constraints")
        self.assertIn("extraction_modulus_bit_bound", result.rejections)
        self.assertNotIn("M", result.derived)

    def test_large_challenge_bound_uses_capped_arithmetic(self):
        result = validate_current_parameters(d=0, T=1 << 100000, k=1, q=257)
        self.assertEqual(result.status, "rejected_constraints")
        self.assertIn("extraction_modulus_bound", result.rejections)
        self.assertNotIn("beta_ext", result.derived)

    def test_composite_modulus_is_explicitly_rejected(self):
        result = validate_current_parameters(d=0, T=4, k=1, q=513)
        self.assertEqual(result.primality_status, "composite")
        self.assertIn("modulus_composite", result.rejections)
        self.assertEqual(result.status, "rejected_constraints")

    def test_terminal_lll_attack_rejects_arithmetically_valid_parameters(self):
        result = validate_current_parameters(d=1, T=4, k=3, q=2**31 - 1)
        self.assertEqual(result.arithmetic_status, "satisfied")
        self.assertEqual(result.status, "rejected_known_attack")
        self.assertIn("terminal_lll_bit_bound", result.attacks)

    def test_centered_kernel_boundary(self):
        self.assertIn("terminal_centered_kernel", screen_terminal_sis(k=1, M=2, q=7, beta=3))
        self.assertNotIn("terminal_centered_kernel", screen_terminal_sis(k=1, M=2, q=7, beta=2))

    def test_zero_residue_q_vector_is_not_a_source_attack(self):
        self.assertEqual(screen_terminal_sis(k=1, M=1, q=7, beta=7), ())

    def test_lll_certificate_agrees_with_exact_power_inequality(self):
        for M in range(2, 9):
            for k in range(1, M):
                for q, beta in ((257, 128), (65537, 1024), (2147483647, 104857600)):
                    attacks = screen_terminal_sis(k=k, M=M, q=q, beta=beta)
                    if "terminal_lll_bit_bound" in attacks:
                        self.assertLessEqual(2**(M * (M - 1)) * q**(4 * k), beta**(4 * M))


if __name__ == "__main__":
    unittest.main()
