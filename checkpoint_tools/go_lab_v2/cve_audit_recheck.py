#!/usr/bin/env python3
"""Offline, read-only verification of existing TRACE-WAF GO Lab V2 CVE evidence.

No Docker, no network, no requests. It never rewrites cve_v2_summary.json.
Accepts only an existing CVE evidence directory and writes a *new* audit summary.
"""
from __future__ import annotations
import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import sys

RULE = re.compile(r'\[id\s+"(\d+)"\]')
DEFAULT_CANARY = 'TRACE_CVE_2024_23334_SYNTHETIC_MARKER\n'


def sha256(p: Path):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def read(p):
    return json.loads(p.read_text(encoding='utf-8'))


def parse_events(log_obj):
    """Return audit records from JSON events with ModSecurity v2-style keys.

    A normal audit record looks like:
    {"transaction": {...}, "request": {...}, "response": {...},
     "audit_data": {"messages": ["... [id \"949110\"] ..."],
                    "action": {"intercepted": true}}}
    """
    events = []
    blob = log_obj.get('stdout', '') if isinstance(log_obj, dict) else str(log_obj)
    for line in blob.splitlines():
        at = line.find('{"transaction":')
        if at < 0:
            continue
        try:
            obj = json.loads(line[at:])
        except json.JSONDecodeError:
            continue
        request = obj.get('request', {}) or {}
        headers = request.get('headers', {}) or {}
        if not isinstance(headers, dict):
            continue
        headers_low = {str(k).lower():v for k,v in headers.items()}
        trace_id = headers_low.get('x-trace-request')
        if not isinstance(trace_id, str):
            continue
        audit = obj.get('audit_data', {}) or {}
        messages = audit.get('messages', []) or []
        all_messages = []
        rules = []
        for m in messages:
            if isinstance(m, str):
                all_messages.append(m)
                rules.extend(RULE.findall(m))
            elif isinstance(m, dict):
                all_messages.append(str(m.get('message', '')))
                details = m.get('details', {}) or {}
                rid = details.get('ruleId') or details.get('rule_id') or m.get('ruleId')
                if rid:rules.append(str(rid))
        rules = list(dict.fromkeys(rules))
        events.append({
            'rid':trace_id,
            'http_status':(obj.get('response') or {}).get('status') or (obj.get('response') or {}).get('http_code'),
            'request_line':request.get('request_line'),
            'intercepted':bool((audit.get('action') or {}).get('intercepted', False)),
            'rule_ids':rules,
            'crs_949110': '949110' in rules,
            'disruptive_message': any('Access denied with code' in m for m in all_messages),
            'transaction_id':(obj.get('transaction') or {}).get('transaction_id'),
        })
    return events


def classify(vuln, patched, waf, audits):
    v = vuln.get('result', {})
    p = patched.get('result', {})
    w = waf.get('result', {})
    direct = bool(v.get('marker'))
    patched_leaks = bool(p.get('marker'))
    if not direct:
        return 'DIRECT_VULNERABILITY_NOT_PROVEN'
    if patched_leaks:
        return 'PATCHED_CONTROL_FAILED'
    if w.get('marker'):
        return 'WAF_BYPASS_MARKER_OBSERVED'
    if 'error' in w:
        return 'WAF_TRANSPORT_OR_INFRA_ERROR'
    status=w.get('status')
    matched=[a for a in audits if a.get('rid') == waf.get('rid')]
    if status == 403 and any(a['intercepted'] and a['crs_949110'] and a['http_status']==403 for a in matched):
        return 'WAF_CRS_BLOCK_CORROBORATED'
    if status == 403 and any(a['intercepted'] and a['http_status']==403 for a in matched):
        return 'WAF_403_OTHER_RULE_CORROBORATED'
    if status == 403:
        return 'WAF_403_NOT_CORROBORATED'
    if status in (301,302,307,308,400,404,405):
        return 'WAF_OR_PROXY_REWRITE_INCONCLUSIVE'
    return 'WAF_UNRESOLVED_OTHER_HTTP'


def analyze(folder: Path):
    original=folder/'cve_v2_summary.json'
    if not original.is_file():
        raise FileNotFoundError(f'Could not locate {original}')
    report=read(original)
    files={}
    audits={}
    for which in ('waf-vuln','waf-fixed'):
        file=folder/(which+'-logs.json')
        if file.is_file():
            files[which]=sha256(file)
            audits[which]=parse_events(read(file))
        else:
            audits[which]=[]
    records=report.get('records', [])
    look={(r.get('label'),r.get('service')):r for r in records}
    probes=sorted({r['label'] for r in records if r.get('label') not in (None, 'public')})
    rows=[]
    for probe in probes:
        d=look.get((probe,'vuln_direct'),{})
        f=look.get((probe,'fixed_direct'),{})
        w=look.get((probe,'vuln_waf'),{})
        fw=look.get((probe,'fixed_waf'),{})
        if not d or not f or not w:
            rows.append({'probe':probe,'status':'MISSING_REQUIRED_RECORD'})
            continue
        matches=[a for a in audits['waf-vuln'] if a.get('rid') == w.get('rid')]
        matches_fixed=[a for a in audits['waf-fixed'] if a.get('rid') == fw.get('rid')]
        row={
            'probe':probe,
            'vuln_direct':{'http_status':d['result'].get('status'), 'canary_leaked':bool(d['result'].get('marker'))},
            'fixed_direct':{'http_status':f['result'].get('status'),'canary_leaked':bool(f['result'].get('marker'))},
            'vuln_waf':{'http_status':w['result'].get('status'),'canary_leaked':bool(w['result'].get('marker')),'error':w['result'].get('error'),
                'trace_id':w.get('rid'),'audit_transactions_matched':len(matches),'correlated_audit':matches},
            'fixed_waf':{'http_status':fw.get('result',{}).get('status'),'canary_leaked':bool(fw.get('result',{}).get('marker')),
                'audit_transactions_matched':len(matches_fixed)},
            'status':classify(d,f,w,audits['waf-vuln'])
        }
        rows.append(row)
    public=report.get('public_controls',{})
    direct_confirmed=bool(probes and all(r.get('vuln_direct',{}).get('canary_leaked') for r in rows)
                          and all(not r.get('fixed_direct',{}).get('canary_leaked') for r in rows)
                          and all(public.get(k) is True for k in ('vuln_direct','fixed_direct','vuln_waf','fixed_waf')))
    statuses=Counter(r['status'] for r in rows)
    waf_protection=bool(direct_confirmed and all(r.get('status')=='WAF_CRS_BLOCK_CORROBORATED' for r in rows))
    conclusion=('CVE_AND_WAF_CRS_CORROBORATED' if waf_protection else
                'CVE_CONFIRMED_WAF_BYPASS' if 'WAF_BYPASS_MARKER_OBSERVED' in statuses and direct_confirmed else
                'CVE_CONFIRMED_WAF_NOT_FULLY_CORROBORATED' if direct_confirmed else
                'EVIDENCE_INSUFFICIENT_FOR_COMPLETE_CVE')
    return {'reviewed_utc':datetime.now(timezone.utc).isoformat(),
        'original_summary_sha256':sha256(original),
        'audit_log_sha256':files,
        'evidence_origin':str(folder),
        'original_status':report.get('status'),
        'probes':rows,
        'counts':dict(statuses),
        'direct_CVE_with_patched_negative_control_confirmed':direct_confirmed,
        'WAF_CRS_protection_confirmed':waf_protection,
        'review_conclusion':conclusion,
        'claim_boundary':'Cannot infer LLM rule protects CVE: this lab uses CRS separately.',
        'method':'Offline post-hoc correction of audit parser; original experiment and logs are immutable. No additional HTTP request.'}


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('evidence_dir',type=Path,help='Existing results/.../<UTC>/cve directory')
    ap.add_argument('--output',type=Path,help='Optional output JSON path; default under evidence_dir')
    args=ap.parse_args()
    folder=args.evidence_dir.expanduser().resolve()
    result=analyze(folder)
    path=args.output or folder/'cve_audit_recheck.json'
    if path.exists():
        raise FileExistsError(f'Do not overwrite an existing review: {path}')
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print('Original CVE:',result['original_status'])
    print('Recheck:',result['review_conclusion'])
    print('CVE direct + patched:',result['direct_CVE_with_patched_negative_control_confirmed'])
    print('WAF CRS protection:',result['WAF_CRS_protection_confirmed'])
    for r in result['probes']:
        if 'status' not in r:continue
        print(' -',r['probe'],r['status'],'waf_http=',r.get('vuln_waf',{}).get('http_status'),
              'audit_matches=',r.get('vuln_waf',{}).get('audit_transactions_matched'))
    print('Saved:',path)

if __name__=='__main__':
    try:main()
    except Exception as e:
        print(f'CVE AUDIT RECHECK ERROR: {type(e).__name__}: {e}',file=sys.stderr)
        sys.exit(2)
