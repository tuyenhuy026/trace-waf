"""TRACE-WAF frozen held-out checkpoint: exact-once per recorded case, resume-safe.

Continues B0 from its *existing* partial journal; does not replay the first
93 observations. Executes B1 and L1-L5 once each, using the original oracle
and frozen configuration. No API calls, tuning, or candidate selection.
"""
from __future__ import annotations
import argparse
from collections import Counter
from pathlib import Path
import hashlib
import json
import os
import shutil
import sys
import traceback

import common as c


def load_existing(rb, cases, directory):
    path=directory/'observations.jsonl'
    rows=c.read_jsonl(path) if path.exists() else []
    c.require(len(rows)<=len(cases), f'{directory}: too many observations.')
    for i,row in enumerate(rows):
        c.require(row.get('case')==cases[i],
                  f'{directory}: journal diverges from frozen input at index {i}.')
        c.require(row.get('outcome')==rb.decision(row['case'],row['direct'],row['waf'])
                  or row.get('outcome')=='uncertain_interrupted',
                  f'{directory}: altered classification at index {i}.')
    return rows


def init_output(rb, plan, audit, cases):
    c.require(not c.RECOVERY.exists(),
              f'Continuation directory already exists: {c.RECOVERY}. Use --resume, not --run.')
    c.require(not (c.PRIOR/'B0-test'/'summary.json').exists(),
              'B0 was already completed. Do not perform another B0 pass.')
    for ident in c.IDS[1:]:
        c.require(not (c.PRIOR/f'{ident}-test').exists(),
                  f'A previous final test for {ident} exists; manually reconcile before proceeding.')
    prior=c.PRIOR/'B0-test'
    for name in ('cases.json','manifest.json','input-audit.json','observations.jsonl'):
        c.require((prior/name).is_file(), f'Cannot recover partial B0: {prior/name} missing.')
    prev_manifest=c.read_json(prior/'manifest.json')
    c.require(prev_manifest['policy_id']=='B0' and prev_manifest['split']=='test'
            and prev_manifest['active_rules_sha256']==plan['candidates'][0]['rule_sha256']
            and prev_manifest['corpus_sha256']==c.EXPECTED_CORPUS_SHA,
            'Original B0 manifest does not match the frozen trial.')
    c.require(c.read_json(prior/'cases.json')==cases,
              'Previous B0 input differs from the frozen test corpus.')
    prior_rows=c.read_jsonl(prior/'observations.jsonl')
    c.require(0<len(prior_rows)<len(cases),
              f'Expected interrupted B0; found {len(prior_rows)} of {len(cases)}.')
    for i,row in enumerate(prior_rows):
        c.require(row['case']==cases[i] and row['outcome']==rb.decision(
                  row['case'],row['direct'],row['waf']),
                  f'Existing B0 journal failed identity/classification check at {i}.')
    protocol=c.read_json(c.PRIOR/'test-protocol.json')
    c.require(protocol['source_plan_sha256']==c.EXPECTED_FROZEN_PLAN_SHA
              and protocol['api_calls']==0 and protocol['selection_allowed'] is False,
              'Existing test-protocol does not match the committed one-shot plan.')
    c.RECOVERY.mkdir(parents=True,exist_ok=False)
    c.write_json(c.RECOVERY/'run-info.json',{
      'purpose':'Continue original B0 journal and test five frozen model candidates plus fixed heuristic',
      'started_utc':c.now(), 'source_plan_sha256':c.EXPECTED_FROZEN_PLAN_SHA,
      'corpus_sha256':c.EXPECTED_CORPUS_SHA, 'origin_partial_count':len(prior_rows),
      'expected_count_per_policy':len(cases), 'api_calls':0,'tuning_allowed':False,
      'selection_allowed':False,'final_validation_decision':'NO_GO',
      'method':'B0 session interruption is a limitation, not an independent whole run',
      'original_journal_sha256':c.digest_path(prior/'observations.jsonl'),
      'original_cases_sha256':c.digest_path(prior/'cases.json'),
      'original_manifest_sha256':c.digest_path(prior/'manifest.json'),
      'initial_active_rules_sha256':c.digest_path(c.ACTIVE),
      'runner_sha256':c.digest_path(Path(__file__)),
      'python':sys.version})
    c.write_json(c.RECOVERY/'frozen-plan-copy.json',plan)
    b0=c.RECOVERY/'B0-test'
    b0.mkdir()
    for name in ('cases.json','manifest.json','input-audit.json','observations.jsonl'):
        shutil.copy2(prior/name,b0/name)
    c.write_json(b0/'continuation.json',{
      'source_partial_journal_sha256':c.digest_path(prior/'observations.jsonl'),
      'source_partial_rows':len(prior_rows),
      'continuation_started_utc':c.now(), 'note':'Initial B0 rows copied byte-for-byte.'})
    for candidate in plan['candidates'][1:]:
        folder=c.RECOVERY/(candidate['id']+'-test')
        folder.mkdir()
        c.write_json(folder/'cases.json',cases)
        c.write_json(folder/'input-audit.json',audit)
        c.write_json(folder/'manifest.json',{
           'split':'test','policy_id':candidate['id'],
           'active_rules_sha256':candidate['rule_sha256'],
           'corpus_sha256':c.EXPECTED_CORPUS_SHA,
           'runner_sha256':c.digest_path(Path(__file__)),
           'baseline_functions_sha256':c.EXPECTED_BASELINE_SHA,
           'utc':c.now(), 'api_calls':0,
           'note':'Frozen candidate, one measurement per case, no test-based tuning.'})
        (folder/'observations.jsonl').touch(exist_ok=False)
    c.write_json(c.RECOVERY/'progress.json', {'status':'initialized','utc':c.now(),'completed':[]})


def resume_case_marker(rb, marker, case, idx, stamp, journal):
    prev=c.read_json(marker)
    c.require(prev.get('case_index')==idx and prev.get('case_id')==case['id'],
              'Existing in-flight marker mismatches next journal index.')
    # A crash happened between durable intent and durable outcome. Do not send again.
    uncertain={'case':case,'request_id':f'trace-{stamp}-{idx}',
      'direct':{'effect':None,'error':'interrupted_attempt_state_unknown'},
      'waf':{'effect':None,'error':'interrupted_attempt_state_unknown'},
      'outcome':'uncertain_interrupted'}
    c.append_jsonl(journal, uncertain)
    marker.unlink()
    return uncertain


def complete_policy(rb,candidate,cases,audit):
    ident=candidate['id']
    directory=c.RECOVERY/(ident+'-test')
    existing=load_existing(rb,cases,directory)
    journal=directory/'observations.jsonl'
    marker=directory/'in-flight.json'
    if (directory/'summary.json').exists():
        c.require(len(existing)==len(cases),f'{ident}: completed summary but incomplete journal.')
        return c.read_json(directory/'summary.json')
    if len(existing)==len(cases):
        # Crashed after last observation, before summary: finalize without requests.
        summary=finalize_policy(rb,directory,existing,audit)
        return summary
    print(f'{ident}: {len(existing)}/{len(cases)} rows already recorded; only missing indices will be sent.',flush=True)
    c.activate(None,candidate,c.RECOVERY)
    c.direct_and_waf_health(rb)
    import requests
    pctx,browser,oracle=c.browser_context(rb)
    stamp=(c.read_json(directory/'manifest.json').get('started_utc')
           or c.read_json(c.RECOVERY/'run-info.json')['started_utc'].replace(':','').replace('-',''))
    started=c.now()
    try:
        with requests.Session() as session:
            session.trust_env=False
            for i in range(len(existing),len(cases)):
                case=cases[i]
                if marker.exists():
                    row=resume_case_marker(rb,marker,case,i,stamp,journal)
                else:
                    # Durable write-ahead intent: avoids silent re-probing on interruption.
                    c.write_json(marker,{'case_index':i,'case_id':case['id'],
                              'candidate_id':ident,'utc':c.now()})
                    row=c.eval_case(rb,case,i,stamp,session,oracle)
                    c.append_jsonl(journal,row)
                    marker.unlink()
                existing.append(row)
                if (i+1)%10==0 or i+1==len(cases):
                    print(f'{ident}: {i+1}/{len(cases)}',flush=True)
    finally:
        browser.close()
        pctx.stop()
        c.collect_logs(directory,started)
    return finalize_policy(rb,directory,existing,audit)


def finalize_policy(rb,directory,rows,audit):
    cases=c.read_json(directory/'cases.json')
    c.require(len(rows)==len(cases),'Not enough rows to create a policy summary.')
    report=c.summarize(rb,rows,audit)
    report['complete'] = report['complete'] and len(rows)==len(cases)
    report['observations_sha256']=c.digest_path(directory/'observations.jsonl')
    report['source_label']='interrupted_B0_continuation' if directory.name=='B0-test' else 'frozen_heldout_test'
    c.write_json(directory/'summary.json',report)
    return report


def compare_all(rb,plan):
    result=[]
    ref=None
    for candidate in plan['candidates']:
        ident=candidate['id']
        directory=c.RECOVERY/(ident+'-test')
        if not (directory/'summary.json').exists():
            result.append({'id':ident,'status':'INCOMPLETE'})
            continue
        summary=c.read_json(directory/'summary.json')
        rows=c.read_jsonl(directory/'observations.jsonl')
        direct={x['case']['id']:[x['direct'].get('status'),
                x['direct'].get('effect'),x['direct'].get('body_sha256')] for x in rows}
        if ident=='B0': ref=direct
        drift=bool(ref is not None and direct != ref)
        allmetrics=next((v for v in summary['metrics_deduplicated']
                         if v['source']=='ALL' and v['cwe']=='ALL'),{})
        cwe={v['cwe']:{'valid_attacks':v['valid_evaluable_attacks'],
                 'blocked':v['counts'].get('blocked_attack',0),
                 'bypassed':v['counts'].get('bypass',0),
                 'invalid':v['counts'].get('invalid_attack',0),
                 'false_positive':v['counts'].get('false_positive',0),
                 'benign_regression':v['counts'].get('benign_regression',0),
                 'coverage':v['coverage'],'fpr':v['fpr'],'robustness':v['robustness']}
             for v in summary['metrics_deduplicated'] if v['source']=='ALL' and v['cwe']!='ALL'}
        result.append({'id':ident,'status':'COMPLETE' if summary['complete'] and not drift else 'REVIEW',
                       'source':candidate['source'],'direct_oracle_drift':drift,
                       'summary_sha256':c.digest_path(directory/'summary.json'),
                       'observations_sha256':summary['observations_sha256'],
                       'rows':summary['rows'],'outcomes':summary['outcomes'],
                       'coverage':allmetrics.get('coverage'),'fpr':allmetrics.get('fpr'),
                       'robustness':allmetrics.get('robustness'),'per_cwe':cwe})
    return {'evaluation':'FROZEN_FINAL_TEST',
      'utc':c.now(),'decided_policy':None,
      'validation_decision':'NO_GO','deployment_approval':'NO_GO',
      'test_used_for_model_or_rule_selection':False,
      'b0_from_interrupted_session':True,
      'all_seven_complete':len(result)==7 and all(x['status']=='COMPLETE' for x in result),
      'results':result,
      'limitations':['B0 spans an interrupted old session and a resumed new session.',
           'Oracle stability is only checked by case and response hash, not complete backend semantics.',
           'No repeated sampling, no inference of statistical independence, no production claim.']}


def preflight(rb, plan):
    cases,audit=rb.load_cases('test',False)
    c.require(len(cases)==104,'Frozen held-out test expected 104 cases.')
    c.require(len([q for q in cases if q['intended_attack']])==60,
              'Expected 60 intended attacks; inspect corpus.')
    c.docker_ready()
    c.direct_and_waf_health(rb)
    # Verify browser executable and positive/negative controls before creating
    # a one-shot evidence directory. Controls use intercepted pages, not HTTP.
    ctx,browser,_oracle = c.browser_context(rb)
    try:
        pass
    finally:
        browser.close()
        ctx.stop()
    return cases,audit


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    g=parser.add_mutually_exclusive_group(required=True)
    g.add_argument('--preflight',action='store_true',help='Hash, services and dependencies only. No test HTTP cases.')
    g.add_argument('--run',action='store_true',help='Start the single continuation attempt.')
    g.add_argument('--resume',action='store_true',help='Resume same attempt, never retest journaled cases.')
    g.add_argument('--status',action='store_true',help='Read existing evidence status, never send cases.')
    args=parser.parse_args()
    if args.status:
        if c.RECOVERY.exists():
            for ident in c.IDS:
                path=c.RECOVERY/(ident+'-test')
                journal=path/'observations.jsonl'
                print(f'{ident}: {len(c.read_jsonl(journal)) if journal.exists() else 0}/104 rows; '
                      f'summary={(path/"summary.json").exists()}')
            if (c.RECOVERY/'test-summary.json').exists():
                print(json.dumps(c.read_json(c.RECOVERY/'test-summary.json'),ensure_ascii=False,indent=2)[:4500])
        else:
            prior=c.PRIOR/'B0-test'/'observations.jsonl'
            print(f'No new continuation. Original B0 rows: {len(c.read_jsonl(prior)) if prior.exists() else 0}')
        return
    plan=c.plan_checked(allow_resume=args.resume)
    rb=c.import_baseline()
    with c.study_lock():
        cases,audit=preflight(rb,plan)
        if args.preflight:
            print('PRE-FLIGHT PASS: original hashes, 7 frozen rules, localhost lab services and Python dependencies.')
            return
        if args.run:
            init_output(rb,plan,audit,cases)
        else:
            c.require(c.RECOVERY.is_dir(),'No active continuation directory; use --run first.')
            c.require(c.read_json(c.RECOVERY/'run-info.json')['source_plan_sha256']==c.EXPECTED_FROZEN_PLAN_SHA,
                      'Existing continuation points to a different frozen plan.')
        was_activated=False
        try:
            for item in plan['candidates']:
                directory=c.RECOVERY/(item['id']+'-test')
                if (directory/'summary.json').exists():
                    print(item['id'],': complete in the same continuation; no repeat')
                    continue
                was_activated=True
                summary=complete_policy(rb,item,cases,audit)
                c.write_json(c.RECOVERY/'progress.json',{'last_complete':item['id'],
                       'last_summary_sha256':c.digest_path(directory/'summary.json'),
                       'utc':c.now(),'status':'in_progress'})
        finally:
            if was_activated:
                c.restore(c.RECOVERY)
        combined=compare_all(rb,plan)
        combined['rollback_verified']=c.read_json(c.RECOVERY/'rollback.json')['restored'] if (c.RECOVERY/'rollback.json').exists() else False
        c.write_json(c.RECOVERY/'test-summary.json',combined)
        c.write_json(c.RECOVERY/'progress.json',{'status':'complete' if combined['all_seven_complete'] else 'review',
                                              'utc':c.now(),'all_seven_complete':combined['all_seven_complete']})
        print(json.dumps({'all_seven_complete':combined['all_seven_complete'],
              'rollback_verified':combined['rollback_verified'],
              'decision':combined['deployment_approval'],
              'output':str(c.RECOVERY)},ensure_ascii=False,indent=2))
        c.require(combined['all_seven_complete'] and combined['rollback_verified'],
                  'Final test has unresolved observation/oracle differences; status REVIEW, not completed.')


if __name__=='__main__':
    try:
        main()
    except Exception as exc:
        print(f'RUN INCOMPLETE: {type(exc).__name__}: {exc}',file=sys.stderr)
        sys.exit(2)
