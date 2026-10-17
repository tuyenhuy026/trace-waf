"""Local smoke tests. These never invoke Docker, CVE probes, or GPT API."""
from __future__ import annotations
import json
from pathlib import Path
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import common as c
import final_test
import cve_2024_23334 as cve
import drift_replay
import optional_llm_dev

class SafetyAndEvidenceTests(unittest.TestCase):
    def test_playwright_manager_is_not_stoppable(self):
        """Regression: .start() result has .stop(); context-manager does not."""
        from types import ModuleType
        browser=SimpleNamespace(close=lambda: None)
        stops=[]
        pw=SimpleNamespace(chromium=SimpleNamespace(launch=lambda **kw: browser),
                           stop=lambda: stops.append('stopped'))
        manager=SimpleNamespace(start=lambda: pw)  # Deliberately NO manager.stop().
        sync_api=ModuleType('playwright.sync_api')
        sync_api.sync_playwright=lambda: manager
        package=ModuleType('playwright')
        fake_rb=SimpleNamespace(DIRECT='http://127.0.0.1:18080',
          BrowserOracle=lambda _b,_w: SimpleNamespace(
            observe=lambda body,*args: '<script>' in body))
        with patch.dict(sys.modules,{'playwright':package,'playwright.sync_api':sync_api}):
            stopper,returned_browser,_oracle=c.browser_context(fake_rb)
        self.assertIs(stopper,pw)
        self.assertIs(returned_browser,browser)
        returned_browser.close(); stopper.stop()
        self.assertEqual(stops,['stopped'])

    def test_playwright_error_cleanup_preserves_original_error(self):
        from types import ModuleType
        stops=[]
        pw=SimpleNamespace(chromium=SimpleNamespace(
            launch=lambda **kw:SimpleNamespace(close=lambda:None)),
            stop=lambda:stops.append('stopped'))
        manager=SimpleNamespace(start=lambda:pw)
        sync_api=ModuleType('playwright.sync_api')
        sync_api.sync_playwright=lambda:manager
        package=ModuleType('playwright')
        fake_rb=SimpleNamespace(DIRECT='http://127.0.0.1:18080',
          BrowserOracle=lambda _b,_w: SimpleNamespace(observe=lambda body,*args:False))
        with patch.dict(sys.modules,{'playwright':package,'playwright.sync_api':sync_api}):
            with self.assertRaisesRegex(RuntimeError,'Positive browser control failed'):
                c.browser_context(fake_rb)
        self.assertEqual(stops,['stopped'])

    def test_hash_and_atomic_json(self):
        self.assertEqual(c.sha(b'abc'),'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad')
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'evidence.json'
            c.write_json(p,{'label':'CWE-22','count':4})
            self.assertEqual(c.read_json(p)['count'],4)
            self.assertFalse(p.with_name(p.name+'.new').exists())

    def test_correlate_requires_same_request_id(self):
        event={'transaction':{'transaction_id':'test'},
               'request':{'headers':{'X-Trace-Request':'local-probe'}},
               'response':{'http_code':403},
               'messages':[{'details':{'ruleId':'949110'}}]}
        logs='waf-1 | '+json.dumps(event)+'\n'
        self.assertTrue(cve.correlate(logs,'local-probe')['crs_949110'])
        self.assertFalse(cve.correlate(logs,'another-id')['matched_transaction'])
        self.assertFalse(cve.correlate('HTTP 403 only','local-probe')['crs_949110'])

    def test_interrupted_case_is_not_sent_twice(self):
        with tempfile.TemporaryDirectory() as d:
            dir=Path(d)
            marker=dir/'in-flight.json'
            journal=dir/'observations.jsonl'
            case={'id':'test-attack-4','intended_attack':True,'cwe':'CWE-89',
                  'q':'synthetic','route':'/sql','source':'heuristic','variant':'raw'}
            c.write_json(marker,{'case_index':4,'case_id':case['id']})
            fake_rb=SimpleNamespace()  # No browser/network interfaces on purpose.
            row=final_test.resume_case_marker(fake_rb,marker,case,4,'original',journal)
            self.assertEqual(row['outcome'],'uncertain_interrupted')
            self.assertFalse(marker.exists())
            self.assertEqual(len(c.read_jsonl(journal)),1)
            self.assertIsNone(c.read_jsonl(journal)[0]['direct']['effect'])

    def test_window_design_explicitly_repeats_benign(self):
        example=[{'id':'v-raw','split':'validation','intended_attack':True,'variant':'raw'},
                 {'id':'v-trans','split':'validation','intended_attack':True,'variant':'comments'},
                 {'id':'v-benign','split':'validation','intended_attack':False,'variant':'benign'}]
        windows=drift_replay.window_cases(example)
        self.assertEqual([len(x) for x in windows.values()],[2,2])
        self.assertEqual([drift_replay.distribution(x)['transformed_fraction_of_intended_attacks']
                          for x in windows.values()],[0.0,1.0])
        self.assertEqual(sum(q['id']=='v-benign' for w in windows.values() for q in w),2)

    def test_optional_llm_strict_dev_parent_and_budget(self):
        dev=[{'id':'dev-sql-0-raw','route':'/sql','q':'marker','cwe':'CWE-89',
              'split':'dev','intended_attack':True,'variant':'raw',
              'source':'heuristic','family':'dev-sql-0'}]
        record={'replica':0,'parsed':{'cases':[{'route':'/sql','q':'synthetic',
                    'parent_id':'dev-sql-0-raw'}]*12}}
        accepted,rejected=optional_llm_dev.collect_cases(dev,[record])
        self.assertEqual(len(accepted),12)
        self.assertTrue(all(x['split']=='dev' and x['source']=='gpt-6-luna' for x in accepted))
        short={'replica':0,'parsed':{'cases':[{'route':'/sql','q':'only-one',
                    'parent_id':'dev-sql-0-raw'}]}}
        accepted,rejected=optional_llm_dev.collect_cases(dev,[short])
        self.assertEqual(len(accepted),0)
        self.assertEqual(rejected[0]['reason'],'invalid_budget_or_schema')

    def test_legacy_b0_93_rows_are_copied_not_overwritten(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); prior=root/'final-test';old=prior/'B0-test';old.mkdir(parents=True)
            recover=root/'continuation'; active=root/'active-rules.conf'
            active.write_text('# original\n')
            cases=[{'id':f'case-{i}','route':'/search','q':str(i),
                   'source':'curated','intended_attack':False} for i in range(104)]
            rows=[{'case':q,'direct':{'effect':False},'waf':{'effect':False},
                   'outcome':'true_negative'} for q in cases[:93]]
            (old/'observations.jsonl').write_text(''.join(json.dumps(x)+'\n' for x in rows))
            c.write_json(old/'cases.json',cases)
            c.write_json(old/'input-audit.json',{'corpus_sha256':c.EXPECTED_CORPUS_SHA})
            c.write_json(old/'manifest.json',{'policy_id':'B0','split':'test',
                 'active_rules_sha256':'B0_SHA','corpus_sha256':c.EXPECTED_CORPUS_SHA})
            c.write_json(prior/'test-protocol.json',{'source_plan_sha256':c.EXPECTED_FROZEN_PLAN_SHA,
                 'api_calls':0,'selection_allowed':False})
            candidates=[{'id':name,'source':'synthetic','rule_sha256':('B0_SHA' if name=='B0' else name)}
                        for name in c.IDS]
            rb=SimpleNamespace(decision=lambda case,direct,waf:'true_negative')
            with patch.object(c,'PRIOR',prior),patch.object(c,'RECOVERY',recover),patch.object(c,'ACTIVE',active):
                final_test.init_output(rb,{'candidates':candidates},{'selected_rows':104},cases)
                copied=c.read_jsonl(recover/'B0-test'/'observations.jsonl')
                self.assertEqual(len(copied),93)
                self.assertEqual(copied,rows)
                self.assertEqual(c.read_json(recover/'run-info.json')['origin_partial_count'],93)
                with self.assertRaises(RuntimeError):
                    final_test.init_output(rb,{'candidates':candidates},{'selected_rows':104},cases)

    def test_comments_only_guard(self):
        self.assertTrue(c.is_comments_only(b'# managed experiment\n\n# more\n'))
        self.assertFalse(c.is_comments_only(b'SecRuleEngine Off\n'))

if __name__=='__main__':
    unittest.main()
