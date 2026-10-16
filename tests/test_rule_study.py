"""Policy boundary and approval tests without API calls or Docker mutation."""
from pathlib import Path
import sys
import unittest
import re

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'lab'))
from run_rule_study import compile_policy, dev_evidence, gate, serialize_pattern


class PolicyTests(unittest.TestCase):
    def test_safe_exclusions_are_parameter_scoped(self):
        config=compile_policy({'exempt_routes':['/docs'],'patterns':[]},'B1')
        self.assertIn('ARGS:q',config)
        self.assertNotIn('ruleEngine=Off',config)
        self.assertIn('^/docs(?:[?]|$)',config)

    def test_cannot_exempt_attack_route(self):
        with self.assertRaises(ValueError):
            compile_policy({'exempt_routes':['/sql'],'patterns':[]},'L1')

    def test_directive_injection_rejected(self):
        for regex in ['word\nSecRuleEngine Off','word\\','a'*513,'word\x00']:
            with self.subTest(regex_length=len(regex)), self.assertRaises(ValueError):
                compile_policy({'exempt_routes':[],'patterns':[{'route':'/sql','regex':regex}]},'L1')

    def test_literal_quote_semantics_preserved(self):
        for pattern in ['a"b', r'a\"b', r'a\\"b', '["x]', '[^"x]', r'a\\\"b']:
            converted=serialize_pattern(pattern)
            self.assertNotIn('"',converted)
            for value in ['a"b', 'a\\"b', '"', 'x', 'y']:
                self.assertEqual(bool(re.fullmatch(pattern,value)),bool(re.fullmatch(converted,value)))

    def test_embedded_directive_stays_inside_regex(self):
        compiled=compile_policy({'exempt_routes':[], 'patterns':[{'route':'/sql','regex':'x" SecRuleEngine Off'}]},'L1')
        self.assertNotIn('" SecRuleEngine Off',compiled)
        self.assertIn(r'\x22 SecRuleEngine Off',compiled)

    def test_quoted_pcre_region_is_not_silently_rewritten(self):
        with self.assertRaises(ValueError): serialize_pattern(r'\Q"\E')

    def test_nonstring_route_rejected(self):
        with self.assertRaises(ValueError):
            compile_policy({'exempt_routes':[],'patterns':[{'route':[],'regex':'word'}]},'L1')

    def test_error_json_is_not_a_policy(self):
        with self.assertRaises(ValueError): compile_policy({'error':'unavailable'},'L1')

    def test_governance_requires_functional_correctness(self):
        metrics=[]
        for cwe in ['ALL','CWE-89','CWE-79','CWE-22']:
            metrics.append({'source':'ALL','cwe':cwe,'coverage':1,'robustness':1,'fpr':0,
                'benign_regressions':1,'valid_evaluable_attacks':5,'valid_evaluable_benign':5})
        result=gate({'metrics_deduplicated':metrics,'uncertain_rows':0})
        self.assertFalse(result['pass'])
        self.assertIn('benign_functional_regression',result['reasons'])

    def test_missing_denominator_cannot_pass(self):
        metrics=[]
        for cwe in ['ALL','CWE-89','CWE-79','CWE-22']:
            metrics.append({'source':'ALL','cwe':cwe,'coverage':None,'robustness':None,'fpr':0,
                'benign_regressions':0,'valid_evaluable_attacks':0,'valid_evaluable_benign':5})
        self.assertFalse(gate({'metrics_deduplicated':metrics,'uncertain_rows':0})['pass'])


if __name__=='__main__': unittest.main()
