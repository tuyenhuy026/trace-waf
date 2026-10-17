"""No network, no API, no Docker. Tests negative and positive gate behaviors."""
from pathlib import Path
import importlib.util,json,sys,unittest
from unittest import mock
ROOT=Path(__file__).resolve().parents[2]/'checkpoint_tools'/'go_lab_v2'
sys.path.insert(0,str(ROOT))
from cohort import build
from go_gate import assess
from run_cve import match_audit
from trial import score

class TestProtocol(unittest.TestCase):
 def test_cohort_is_fixed_diverse(self):
  x=build();self.assertEqual(len(x),92);self.assertEqual(len(set(y['id'] for y in x)),92)
  self.assertEqual(len([y for y in x if not y['intended_attack']]),62)
  self.assertTrue(any(y['route']=='/sql' and y['q']=='hello -- world' and not y['intended_attack'] for y in x))
  self.assertTrue(any(y['route']=='/file' and y['q']=='../public/readme.txt' for y in x))
  self.assertEqual({y['cwe'] for y in x if y['intended_attack']},{'CWE-22','CWE-79','CWE-89'})
 def test_correlated_audit_uses_nested_transaction(self):
  value={'transaction':{'request':{'headers':{'X-Trace-Request':'allowed-lab-only'}},
   'response':{'http_code':403},'messages':[{'details':{'ruleId':'949110'}}]}}
  logs='waf-vuln-1 | '+json.dumps(value)+'\n'
  self.assertTrue(match_audit(logs,'allowed-lab-only')['has_crs_block'])
  self.assertFalse(match_audit(logs,'different-id')['matched'])
  self.assertFalse(match_audit('403 without audit','allowed-lab-only')['has_crs_block'])
 def valid_candidate(self):
  return {'coverage':1.0,'fpr':0.0,'robustness':1.0,'benign_n':62,
    'valid_attack_n':20,'valid_transformed_n':11,'uncertain_n':0,
    'functional_regressions':0,'valid_families_per_cwe':{'CWE-89':3,'CWE-79':3,'CWE-22':2}}
 def valid_inputs(self):
  cand=self.valid_candidate()
  trial={'status':'EVALUATED','frozen_before_test':True,'no_test_tuning':True,
   'rollback_verified':True,'direct_oracle_stable':True,'run_counts':{'B1':92,'G2':92},
   'model_requested':'gpt-5.6-sol','model_response':'gpt-5.6-sol',
   'candidate':cand,'baseline':dict(cand,coverage=.85,robustness=.80,fpr=.08)}
  cve={'status':'CVE_AND_WAF_CONFIRMED','cve_confirmed':True,'waf_protection_confirmed':True}
  return trial,cve
 def test_go_is_possible_but_requires_both_studies(self):
  a,b=self.valid_inputs();self.assertEqual(assess(a,b)['decision'],'LAB_GO')
  b['cve_confirmed']=False
  self.assertEqual(assess(a,b)['decision'],'NO_GO')
 def test_old_checkpoint_must_not_be_rebranded_go(self):
  a,b=self.valid_inputs();a['candidate']['fpr']=.1136
  self.assertEqual(assess(a,b)['decision'],'NO_GO')
 def test_reject_regression(self):
  a,b=self.valid_inputs();a['candidate']['functional_regressions']=1
  self.assertEqual(assess(a,b)['decision'],'NO_GO')
 def test_reject_no_llm_advantage(self):
  a,b=self.valid_inputs();a['baseline']=dict(a['candidate'])
  self.assertEqual(assess(a,b)['decision'],'NO_GO')
 def test_dedicated_waf_scoring_separates_false_positive_and_regression(self):
  def row(name, attack, variant, effect, outcome):
   return {'case':{'id':name,'intended_attack':attack,'variant':variant,
        'family':'fam-'+name,'cwe':'CWE-89'},'direct':{'effect':effect},'outcome':outcome}
  rows=[row('a1',True,'raw',True,'blocked_attack'),row('a2',True,'tab',True,'bypass'),
        row('a3',True,'percent',False,'invalid_attack'),row('b1',False,'benign',False,'false_positive'),
        row('b2',False,'benign',False,'benign_regression')]
  result=score(rows)
  self.assertEqual(result['coverage'],.5)
  self.assertEqual(result['fpr'],.5)
  self.assertEqual(result['robustness'],0.0)
  self.assertEqual(result['functional_regressions'],1)
  self.assertEqual(result['outcomes']['invalid_attack'],1)
 def test_reject_mismatched_model(self):
  a,b=self.valid_inputs();a['model_response']='gpt-6-luna'
  self.assertEqual(assess(a,b)['decision'],'NO_GO')
 def test_no_production_claim(self):
  a,b=self.valid_inputs();self.assertFalse(assess(a,b)['production_deployment_approval'])
if __name__=='__main__':unittest.main()
