"""Controlled LIVE replay of validation cases under a synthetic input-mixture shift.

Two fixed windows: A = raw + benign, B = transformed + same benign.
B0 is observed first. With --approve-canary, pre-frozen B1 is applied as a
lab-only candidate, evaluated, and rolled back. No online learning, no GPT,
no test data, and no production approval.
"""
from __future__ import annotations
import argparse
from collections import Counter
from datetime import datetime,timezone
import json
import sys
from pathlib import Path
import common as c

DRIFT = c.CP/'drift-replay'


def window_cases(cases):
    a=[q for q in cases if not q['intended_attack'] or q['variant']=='raw']
    b=[q for q in cases if not q['intended_attack'] or q['variant']!='raw']
    c.require(all(q['split']=='validation' for q in a+b),
              'Drift replay must not use final held-out test.')
    c.require(len(a)>0 and len(b)>0 and all(q['intended_attack'] for q in cases if q['variant']!='benign'),
              'Unexpected validation corpus.')
    return {'A_raw_weighted':a,'B_transformed_weighted':b}


def distribution(window):
    counted=Counter((q['variant'] if q['intended_attack'] else 'benign') for q in window)
    attacks=[q for q in window if q['intended_attack']]
    transformed=sum(q['variant']!='raw' for q in attacks)
    return {'size':len(window),'intended_attack':len(attacks),
            'benign':len(window)-len(attacks),
            'variant_counts':dict(counted),
            'transformed_fraction_of_intended_attacks':round(transformed/len(attacks),6) if attacks else None,
            'not_temporal_production_drift':True}


def replay_policy(rb,dirpath,policy,windows):
    c.activate(None,policy,dirpath)
    c.direct_and_waf_health(rb)
    import requests
    ctx,browser,oracle=c.browser_context(rb)
    started=c.now()
    records=[]
    try:
        with requests.Session() as session:
            session.trust_env=False
            for wlabel,items in windows.items():
                stamp='drift-'+policy['id']+'-'+wlabel
                rows=[]
                with (dirpath/f'{policy["id"]}-{wlabel}.jsonl').open('x',encoding='utf-8') as stream:
                    for i,row in enumerate(items):
                        res=c.eval_case(rb,row,i,stamp,session,oracle)
                        res['window']=wlabel
                        stream.write(json.dumps(res,ensure_ascii=False)+'\n')
                        stream.flush()
                        rows.append(res)
                cases_report=c.summarize(rb,rows,{'window':wlabel,'corpus_sha256':c.EXPECTED_CORPUS_SHA},split='validation')
                metric=next(x for x in cases_report['metrics_deduplicated']
                            if x['source']=='ALL' and x['cwe']=='ALL')
                report={'policy_id':policy['id'],'window':wlabel,'distribution':distribution(items),
                        'rows':len(rows),'outcomes':cases_report['outcomes'],
                        'coverage':metric['coverage'],'robustness':metric['robustness'],
                        'fpr':metric['fpr'],'benign_regressions':metric['benign_regressions'],
                        'uncertain_rows':cases_report['uncertain_rows'],
                        'source':'LIVE_REPLAY_OF_VALIDATION_INPUTS',
                        'journal_sha256':c.digest_path(dirpath/f'{policy["id"]}-{wlabel}.jsonl')}
                records.append(report)
    finally:
        browser.close()
        ctx.stop()
        c.collect_logs(dirpath/policy['id'],started)
    return records


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run',required=True,action='store_true')
    parser.add_argument('--approve-canary',action='store_true',
             help='Explicit human approval for local B1 lab canary, NOT production deployment')
    args=parser.parse_args()
    # Run after locked final test so there is no interference with its held-out pass.
    completed=c.RECOVERY/'test-summary.json'
    c.require(completed.is_file(),
              'First run final_test.py; no drift experiments while held-out test is unfinished.')
    final=c.read_json(completed)
    c.require(final['all_seven_complete'] and final['rollback_verified'],
              'Final test incomplete or rollback not verified; preserve evidence, do not replay yet.')
    plan=c.plan_checked()
    rb=c.import_baseline()
    with c.study_lock():
        c.docker_ready()
        c.direct_and_waf_health(rb)
        cases,audit=rb.load_cases('validation',False)
        windows=window_cases(cases)
        DRIFT.mkdir(parents=True,exist_ok=True)
        folder=DRIFT/datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
        folder.mkdir(exist_ok=False)
        report={'started_utc':c.now(), 'status':'INCOMPLETE',
                'claim_level':'controlled live replay of validation inputs, not temporal production drift',
                'autonomous_self_adaptation_demonstrated':False,
                'human_approval_flag':args.approve_canary,
                'source_corpus_sha256':c.EXPECTED_CORPUS_SHA,
                'frozen_plan_sha256':c.EXPECTED_FROZEN_PLAN_SHA,
                'policies':{'B0':plan['candidates'][0]['rule_sha256'],
                            'B1':plan['candidates'][1]['rule_sha256']},
                'windows':{key:distribution(value) for key,value in windows.items()},
                'records':[], 'adaptation_proposal':'use pre-frozen B1 for lab canary; never tune on replay',
                'business_gate':{'coverage_min':0.90,'fpr_max':0.05,'robustness_min':0.85,
                                 'no_benign_regression':True},
                'production_decision':'NO_GO', 'canary_decision':'NOT_RUN'}
        activated=False
        try:
            activated=True
            report['records']+=replay_policy(rb,folder,plan['candidates'][0],windows)
            a,b=report['windows'].values()
            shift=abs(a['transformed_fraction_of_intended_attacks']-
                      b['transformed_fraction_of_intended_attacks'])
            report['composition_shift']=shift
            report['synthetic_alert']=shift >= 0.25
            if args.approve_canary:
                report['records']+=replay_policy(rb,folder,plan['candidates'][1],windows)
                proposed=[x for x in report['records'] if x['policy_id']=='B1']
                report['lab_canary_evaluated']=True
                report['canary_gate_pass'] = bool(proposed and all(
                    x['coverage'] is not None and x['coverage']>=.9
                    and x['fpr'] is not None and x['fpr']<=.05
                    and x['robustness'] is not None and x['robustness']>=.85
                    and not x['benign_regressions'] and not x['uncertain_rows']
                    for x in proposed))
                report['canary_decision']='LAB_ONLY_PASS_ROLLBACK_ANYWAY' if report['canary_gate_pass'] else 'LAB_NO_GO_ROLLBACK'
            else:
                report['lab_canary_evaluated']=False
                report['canary_decision']='NOT_APPROVED_NOT_RUN'
            report['status']='REPLAY_FINISHED'
        except Exception as exc:
            report['error']=f'{type(exc).__name__}: {exc}'
            report['status']='INCOMPLETE'
        finally:
            if activated:
                try:
                    report['rollback']=c.restore(folder)
                except Exception as exc:
                    report['rollback_error']=str(exc)
                    report['status']='ROLLBACK_NOT_VERIFIED'
            c.write_json(folder/'drift-summary.json',report)
        print(json.dumps({'status':report['status'],
             'composition_shift':report.get('composition_shift'),
             'canary_decision':report['canary_decision'],
             'rollback':report.get('rollback',{}).get('restored'),
             'output':str(folder)},ensure_ascii=False,indent=2))
        c.require(report['status']=='REPLAY_FINISHED' and report.get('rollback',{}).get('restored'),
                  'Drift run incomplete or rollback uncertain; inspect evidence.')


if __name__=='__main__':
    try:
        main()
    except Exception as exc:
        print(f'DRIFT NOT ACCEPTED: {exc}',file=sys.stderr)
        sys.exit(2)
