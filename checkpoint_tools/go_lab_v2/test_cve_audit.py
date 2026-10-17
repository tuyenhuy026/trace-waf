import json
from pathlib import Path
import tempfile
import unittest
from cve_audit_recheck import parse_events, classify, analyze


def event(rid='trace-cve-v2-raw_dotdot-vuln_waf',status=403,intercepted=True, rule_id='949110'):
    return {'transaction':{'time':'now','transaction_id':'xyz'},
            'request':{'headers':{'X-Trace-Request':rid},'request_line':'GET /static/../canary HTTP/1.1'},
            'response':{'status':status},
            'audit_data':{'action':{'intercepted':intercepted},
               'messages':[f'Access denied with code {status} [id "{rule_id}"]']}}

class EvidenceTests(unittest.TestCase):
    def test_real_audit_schema_has_request_outside_transaction(self):
        raw='waf-vuln-1 | '+json.dumps(event())+'\n'
        logs=parse_events({'stdout':raw})
        self.assertEqual(len(logs),1)
        self.assertTrue(logs[0]['crs_949110'])
        self.assertTrue(logs[0]['intercepted'])
        self.assertEqual(logs[0]['http_status'],403)
    def test_audit_requires_request_id_match(self):
        audits=parse_events({'stdout':json.dumps(event('different-request'))})
        d={'result':{'marker':True}}
        p={'result':{'marker':False}}
        w={'rid':'expected','result':{'status':403,'marker':False}}
        self.assertEqual(classify(d,p,w,audits),'WAF_403_NOT_CORROBORATED')
    def test_proxy_404_not_called_crs_block(self):
        audits=parse_events({'stdout':json.dumps(event(status=404,intercepted=False))})
        d={'result':{'marker':True}};p={'result':{'marker':False}}
        w={'rid':'trace-cve-v2-raw_dotdot-vuln_waf','result':{'status':404,'marker':False}}
        self.assertEqual(classify(d,p,w,audits),'WAF_OR_PROXY_REWRITE_INCONCLUSIVE')
    def test_direct_crs_block_when_all_signals_present(self):
        audits=parse_events({'stdout':json.dumps(event())})
        d={'result':{'marker':True}};p={'result':{'marker':False}}
        w={'rid':'trace-cve-v2-raw_dotdot-vuln_waf','result':{'status':403,'marker':False}}
        self.assertEqual(classify(d,p,w,audits),'WAF_CRS_BLOCK_CORROBORATED')
    def test_waf_bypass_overrides_log_matching(self):
        audits=parse_events({'stdout':json.dumps(event())})
        d={'result':{'marker':True}};p={'result':{'marker':False}}
        w={'rid':'trace-cve-v2-raw_dotdot-vuln_waf','result':{'status':200,'marker':True}}
        self.assertEqual(classify(d,p,w,audits),'WAF_BYPASS_MARKER_OBSERVED')
    def test_read_only_and_summary_in_same_layout(self):
        with tempfile.TemporaryDirectory() as tmp:
            t=Path(tmp)
            probes=['raw_dotdot','encoded_dotdot','encoded_slash','encoded_dotdot_slash']
            records=[];lines=[]
            for probe in probes:
                for service,port,marker,status in [('vuln_direct',18190,True,200),('fixed_direct',18191,False,404),
                                                   ('vuln_waf',18192,False,403),('fixed_waf',18193,False,404)]:
                    rid=f'trace-cve-v2-{probe}-{service}'
                    records.append({'label':probe,'service':service,'rid':rid,'result':{'marker':marker,'status':status}})
                    if service=='vuln_waf':lines.append('waf | '+json.dumps(event(rid=rid)))
            s={'status':'CVE_CONFIRMED_WAF_NOT_CONFIRMED',
               'public_controls':{k:True for k in ('vuln_direct','fixed_direct','vuln_waf','fixed_waf')},
               'records':records}
            p=t/'cve_v2_summary.json';p.write_text(json.dumps(s))
            (t/'waf-vuln-logs.json').write_text(json.dumps({'stdout':'\n'.join(lines)}))
            (t/'waf-fixed-logs.json').write_text(json.dumps({'stdout':''}))
            r=analyze(t)
            self.assertTrue(r['WAF_CRS_protection_confirmed'])
            self.assertEqual(r['review_conclusion'],'CVE_AND_WAF_CRS_CORROBORATED')
            self.assertEqual(json.loads(p.read_text()),s)

if __name__=='__main__':unittest.main()
