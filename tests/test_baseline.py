"""Measurement correctness checks; no network or corpus execution."""
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('baseline', Path(__file__).resolve().parents[1]/'lab/run_baseline.py')
b = importlib.util.module_from_spec(spec)
spec.loader.exec_module(b)


class MeasurementTests(unittest.TestCase):
    def case(self, attack=True):
        return {'intended_attack':attack,'route':'/docs' if not attack else '/sql',
                'q':'hello','variant':'raw','source':'fixture','cwe':'CWE-89'}

    def response(self, effect=False, status=200, echo='id', body='body'):
        return {'effect':effect,'status':status,'backend_request_id':echo,
                'body':body,'body_sha256':b.digest(body.encode())}

    def test_invalid_candidate_is_not_bypass(self):
        self.assertEqual(b.decision(self.case(),self.response(),self.response()),'invalid_attack')

    def test_transport_error_is_not_protection(self):
        self.assertEqual(b.decision(self.case(),self.response(True),{'error':'Timeout','effect':None}), 'uncertain_waf')

    def test_block_requires_no_backend_echo(self):
        direct=self.response(True)
        self.assertEqual(b.decision(self.case(),direct,self.response(status=403,echo=None)),'blocked_attack')
        self.assertEqual(b.decision(self.case(),direct,self.response(status=403)), 'not_blocked_no_effect')

    def test_benign_content_change_is_regression(self):
        direct=self.response(body='<!doctype html><html><body>hello</body></html>')
        self.assertEqual(b.decision(self.case(False),direct,self.response(body='changed')),'benign_regression')

    def test_unknown_oracle_is_not_negative(self):
        self.assertEqual(b.decision(self.case(),self.response(None),self.response()),'uncertain_direct')

    def test_denominators_exclude_invalid_and_unknown(self):
        rows=[]
        for outcome,eff in [('blocked_attack',True),('bypass',True),('invalid_attack',False),('uncertain_waf',True)]:
            rows.append({'case':self.case(),'direct':{'effect':eff},'outcome':outcome})
        metric=b.summarize(rows)[0]
        self.assertEqual(metric['valid_evaluable_attacks'],2)
        self.assertEqual(metric['coverage'],0.5)
        self.assertIsNone(metric['fpr'])

    def test_routes_cannot_be_external(self):
        row=dict(self.case(),id='id',family='f',split='dev',route='http://example.com')
        with self.assertRaises(ValueError): b.validate_case(row)


if __name__=='__main__':
    unittest.main()
