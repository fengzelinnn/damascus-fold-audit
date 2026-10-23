import unittest
from damascus_a.backend import BackendUnavailable, select_backend
from damascus_a.telemetry import Timer, machine_info


class BackendTests(unittest.TestCase):
    def test_cpu_selection_is_explicit(self):
        r=select_backend('cpu-reference')
        self.assertEqual(r.actual,'cpu-reference'); self.assertFalse(r.fallback)

    def test_fused_cpu_selection_is_explicit(self):
        try:
            result = select_backend('cpu-fused')
        except ValueError as error:
            self.fail(f'the explicit fused CPU backend is missing: {error}')
        self.assertEqual(result.requested, 'cpu-fused')
        self.assertEqual(result.actual, 'cpu-fused')
        self.assertFalse(result.fallback)
        self.assertIsNone(result.reason)

    def test_gpu_fails_closed_or_records_explicit_fallback(self):
        with self.assertRaises(BackendUnavailable): select_backend('gpu')
        r=select_backend('gpu',allow_cpu_fallback=True)
        self.assertEqual(r.requested,'gpu'); self.assertEqual(r.actual,'cpu-reference')
        self.assertTrue(r.fallback); self.assertTrue(r.reason)
        with self.assertRaises(ValueError): select_backend('automatic')

    def test_real_timing_not_negative_and_lifecycle(self):
        t=Timer()
        with t.stage('opening'):
            sum(i*i for i in range(100))
        self.assertGreaterEqual(t.stages_ns['opening'],0)
        with self.assertRaises(ValueError):
            with t.stage('opening'): pass

    def test_machine_info_has_no_host_identity(self):
        m=machine_info(include_gpu=False)
        self.assertTrue(m['os']); self.assertGreater(m['logical_cpu_count'],0)
        self.assertNotIn('hostname',m); self.assertNotIn('username',m)
        self.assertEqual(m['gpu_query_status'],'not_requested')
