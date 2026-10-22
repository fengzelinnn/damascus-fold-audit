import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


class CLITests(unittest.TestCase):
    def run_cli(self,*args):
        return subprocess.run([sys.executable,'-m','damascus_a',*args],capture_output=True,text=True)

    def test_benchmark_is_closed(self):
        p=self.run_cli('benchmark')
        self.assertNotEqual(p.returncode,0)
        self.assertIn('not authorized',p.stderr)

    def test_correctness_produces_real_logs_without_file_bytes_or_wire_claim(self):
        with tempfile.TemporaryDirectory() as temp:
            output=Path(temp)/'run'
            p=self.run_cli('correctness','--output',str(output),'--d','1','--cases','2')
            self.assertEqual(p.returncode,0,p.stderr)
            data=json.loads((output/'correctness.json').read_text())
            self.assertEqual(data['data_kind'],'correctness_test')
            self.assertFalse(data['complete_protocol'])
            self.assertIsNone(data['file_bytes']);self.assertIsNone(data['serialization_bytes'])
            self.assertEqual(len(data['cases']),2)
            self.assertTrue(all(row['accepted'] for row in data['cases']))
            self.assertTrue(all(row['stages_ns']['terminal_norm_and_opening']>=0 for row in data['cases']))
            self.assertTrue((output/'correctness.csv').is_file())

    def test_gpu_request_never_silent(self):
        with tempfile.TemporaryDirectory() as temp:
            p=self.run_cli('correctness','--output',str(Path(temp)/'run'),'--backend','gpu')
            self.assertNotEqual(p.returncode,0)
            self.assertIn('not implemented',p.stderr)

    def test_bad_parameters_reject(self):
        p=self.run_cli('validate','--d','2','--T','4','--k','2','--q','257')
        self.assertEqual(p.returncode,2,p.stderr)
        data=json.loads(p.stdout)
        self.assertEqual(data['security_status'],'not_established')

