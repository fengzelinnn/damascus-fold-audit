"""Allocation-free collection budgets; these tests make no security claims."""
import dataclasses
import unittest
from unittest.mock import patch

from damascus_a.file_codec import required_coefficients
from damascus_a.fold import FoldParameters
from damascus_a.resources import (HARD_CAPS, ResourceBudget,
                                 codec_max_file_bytes, preflight_resources)


class ResourceTests(unittest.TestCase):
    def setUp(self):
        self.parameters = FoldParameters(d=2, T=4, k=2, q=31)

    def test_budget_is_frozen_with_explicit_work_budget_headroom(self):
        budget = ResourceBudget()
        expected = dict(HARD_CAPS)
        expected['max_estimated_operations'] = 100000000
        self.assertEqual(dataclasses.asdict(budget), expected)
        self.assertEqual(HARD_CAPS['max_estimated_operations'], 1000000000)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            budget.max_depth = 1

    def test_every_budget_is_a_positive_integer_within_hard_caps(self):
        for name, cap in HARD_CAPS.items():
            for value in (True, False, 1.5, '1', None, 0, -1, cap + 1):
                with self.subTest(name=name, value=value):
                    with self.assertRaises((TypeError, ValueError)):
                        ResourceBudget(**{name: value})
            self.assertEqual(getattr(ResourceBudget(**{name: 1}), name), 1)

    def test_exact_shape_wire_counts_and_explicit_estimate_labels(self):
        report = preflight_resources(self.parameters, 3, 2)
        self.assertEqual(report['status'], 'within_declared_budgets')
        expected = dict(ring_degree=4, witness_coefficients=16,
                        generator_coefficients=32, registered_coefficients=40,
                        wire_width_bytes=1, registered_payload_bytes=40,
                        codec_max_file_bytes=3, max_file_bytes=3,
                        required_input_coefficients=16)
        for name, value in expected.items():
            self.assertEqual(report[name], value, name)
        self.assertEqual(report['budget'], dataclasses.asdict(ResourceBudget()))
        self.assertGreater(report['estimated_python_bytes'], 0)
        self.assertGreater(report['estimated_operations'], 0)
        self.assertIs(report['estimates']['measured'], False)
        self.assertIs(report['estimates']['guarantees_fit'], False)
        self.assertTrue(report['estimates']['python_bytes_formula'])
        self.assertTrue(report['estimates']['operations_formula'])
        self.assertEqual(report['estimates']['operations_unit'], 'modeled coefficient work')

    def test_codec_capacity_is_the_exact_inverse_including_partial_blocks(self):
        expected = {0: 0, 1: 0, 2: 3, 3: 12, 4: 50, 5: 202, 6: 809, 7: 3236}
        for depth, capacity in expected.items():
            with self.subTest(depth=depth):
                parameters = FoldParameters(depth, 4, 1, 31)
                maximum = codec_max_file_bytes(parameters)
                self.assertEqual(maximum, capacity)
                self.assertLessEqual(required_coefficients(maximum), 1 << (2 * depth))
                self.assertGreater(required_coefficients(maximum + 1), 1 << (2 * depth))

    def test_input_epoch_and_object_types_are_checked(self):
        for value in (True, False, 1.5, '2', None, -1):
            with self.subTest(file_bytes=value), self.assertRaises((TypeError, ValueError)):
                preflight_resources(self.parameters, value, 2)
        for value in (True, False, 1.5, '2', None, 0, -1):
            with self.subTest(epochs=value), self.assertRaises((TypeError, ValueError)):
                preflight_resources(self.parameters, 0, value)
        with self.assertRaises(TypeError):
            preflight_resources(None, 0, 2)
        with self.assertRaises(TypeError):
            codec_max_file_bytes(None)
        with self.assertRaises(TypeError):
            preflight_resources(self.parameters, 0, 2, budget={})
        self.assertEqual(preflight_resources(self.parameters, 0, 1)['required_input_coefficients'], 0)

    def test_input_must_fit_the_unchanged_codec(self):
        with self.assertRaisesRegex(ValueError, 'codec capacity'):
            preflight_resources(self.parameters, 4, 2)

    def test_extreme_depth_rejects_before_wire_or_dimension_work(self):
        parameters = FoldParameters(10**12, 4, 1, 31)
        with patch('damascus_a.resources.wire.encode_pp') as encode:
            with self.assertRaisesRegex(ValueError, 'max_depth'):
                preflight_resources(parameters, 0, 1)
            encode.assert_not_called()
        with self.assertRaisesRegex(ValueError, 'depth|ring degree'):
            codec_max_file_bytes(parameters)

    def test_existing_wire_limits_are_reused_without_overrides(self):
        oversized_rank = FoldParameters(d=1, T=4, k=1025, q=31)
        with self.assertRaisesRegex(ValueError, 'module rank limit'):
            preflight_resources(oversized_rank, 0, 1)
        with patch('damascus_a.resources.wire.encode_pp',
                   side_effect=ValueError('original wire rejection')) as encode:
            with self.assertRaisesRegex(ValueError, 'original wire rejection'):
                preflight_resources(self.parameters, 0, 2)
            self.assertEqual(encode.call_args.kwargs, {})

    def test_each_budget_rejects_before_witness_or_generator_allocation(self):
        report = preflight_resources(self.parameters, 3, 2)
        limits = dict(max_input_bytes=2, max_epochs=1, max_depth=1,
                      max_generator_coefficients=31, max_registered_coefficients=39,
                      max_wire_payload_bytes=39,
                      max_estimated_python_bytes=report['estimated_python_bytes'] - 1,
                      max_estimated_operations=report['estimated_operations'] - 1)
        with patch('damascus_a.protocol.setup') as setup, \
             patch('damascus_a.file_codec.Ternary32Codec.encode') as encode, \
             patch('damascus_a.algebra.Ring.element') as element:
            for name, value in limits.items():
                with self.subTest(name=name), self.assertRaisesRegex(ValueError, name):
                    preflight_resources(self.parameters, 3, 2, ResourceBudget(**{name: value}))
            setup.assert_not_called()
            encode.assert_not_called()
            element.assert_not_called()

    def test_work_estimate_scales_with_epochs_and_rejects_large_declared_work(self):
        first = preflight_resources(self.parameters, 3, 1)
        second = preflight_resources(self.parameters, 3, 2)
        self.assertGreater(second['estimated_operations'], first['estimated_operations'])
        with self.assertRaisesRegex(ValueError, 'max_estimated_operations'):
            preflight_resources(FoldParameters(7, 4, 1, 31), 0, 32)

    def test_depth_seven_requires_explicit_work_budget_and_depth_eight_rejects(self):
        parameters = FoldParameters(7, 4, 2, (1 << 521) - 1)
        with self.assertRaisesRegex(ValueError, 'max_estimated_operations'):
            preflight_resources(parameters, 3236, 1)
        budget = ResourceBudget(max_estimated_operations=500000000)
        report = preflight_resources(parameters, 3236, 1, budget)
        self.assertEqual(report['max_file_bytes'], 3236)
        self.assertEqual(report['codec_max_file_bytes'], 3236)
        self.assertEqual(report['ring_degree'], 128)
        self.assertGreater(report['estimated_operations'], ResourceBudget().max_estimated_operations)
        self.assertLessEqual(report['estimated_operations'], budget.max_estimated_operations)
        self.assertLessEqual(report['estimated_python_bytes'], HARD_CAPS['max_estimated_python_bytes'])
        with self.assertRaisesRegex(ValueError, 'max_depth'):
            preflight_resources(FoldParameters(8, 4, 1, 31), 0, 1)


if __name__ == '__main__':
    unittest.main()
