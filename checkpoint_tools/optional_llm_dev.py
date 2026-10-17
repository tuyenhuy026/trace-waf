"""Optional fixed-budget gpt-6-luna DEV-ONLY extension (never touches test).

Exactly 1-2 sequential requests on dev-only seeds to a local gateway. Failure
and invalid responses are preserved, with NO retries and NO prompt tuning.
Every valid generated case is tested only on the original development fixture.
A 12-case heuristic control uses the same number of requests, but sources are
not semantically independent; results cannot establish a model improvement.
"""
from __future__ import annotations
import argparse
from collections import Counter
from datetime import datetime,timezone
import importlib
import json
from pathlib import Path
import sys
import time
import urllib.error
import urllib.request
import common as c

HOME=c.CP/'llm-exploratory-dev-20261017'
ALIAS='gpt-6-luna'
GATEWAY='http://127.0.0.1:20128/v1/chat/completions'


def call_once(llm, dev, replica, out):
    body={'model':ALIAS,'messages':[{'role':'user','content':llm.prompt('payload',dev)}],
          'temperature':0.7,'max_tokens':3500,'stream':False}
    record={'model_alias':ALIAS,'replica':replica,'purpose':'dev-only exploratory',
            'gateway_host':'localhost:20128','started_utc':c.now(),
            'request':body,'model_weights_independently_verified':False}
    c.write_json(out/f'call-{replica}-intent.json',{'started_utc':c.now(),
                  'model_alias':ALIAS,'request_sha256':c.sha(json.dumps(body,sort_keys=True,ensure_ascii=False).encode())})
    data=json.dumps(body,ensure_ascii=False).encode('utf-8')
    try:
        req=urllib.request.Request(GATEWAY,data=data,
                         headers={'Content-Type':'application/json'},method='POST')
        with urllib.request.urlopen(req,timeout=190) as response:
            raw=response.read(3_000_000)
            record['http_status']=response.status
            payload=json.loads(raw)
            record['response']=payload
            content=payload['choices'][0]['message']['content'].strip()
            if content.startswith('```'):
                content=content.split('\n',1)[1].rsplit('```',1)[0]
            record['parsed']=json.loads(content)
    except urllib.error.HTTPError as exc:
        record['http_status']=exc.code
        record['error']='HTTPError'
        record['error_text']=exc.read(4000).decode(errors='replace')
    except (TimeoutError,OSError,ValueError,KeyError,IndexError) as exc:
        record['error']=type(exc).__name__
    record['ended_utc']=c.now()
    c.write_json(out/f'call-{replica}.json',record)
    return record


def collect_cases(dev, calls):
    parents={x['id']:x for x in dev if x['intended_attack'] and x['variant']=='raw'}
    cases=[]; reject=[]; counts={}
    for record in calls:
        number=record['replica']
        parsed=record.get('parsed',{})
        arr=parsed.get('cases') if isinstance(parsed,dict) else None
        if not isinstance(arr,list) or len(arr)!=12:
            reject.append({'replica':number,'reason':'invalid_budget_or_schema',
                           'count':len(arr) if isinstance(arr,list) else None})
            continue
        for i,item in enumerate(arr):
            parent=parents.get(item.get('parent_id')) if isinstance(item,dict) else None
            if (not parent or item.get('route')!=parent['route']
               or not isinstance(item.get('q'),str) or len(item['q'])>8192):
                reject.append({'replica':number,'index':i,'reason':'unsafe_or_invalid_parent'})
                continue
            case=dict(parent,id=f'exploratory-luna-{number}-{i}',q=item['q'],
                       source=ALIAS,variant='llm_exploratory',parent_id=parent['id'],
                       replicate=number)
            cases.append(case)
            counts[case['cwe']]=counts.get(case['cwe'],0)+1
        if any(counts.get(cwe,0)>4*(number+1) for cwe in ('CWE-89','CWE-79','CWE-22')):
            reject.append({'replica':number,'reason':'unexpected_distribution'})
    return cases,reject


def control_cases(dev,n):
    grouped={key:[] for key in ('CWE-89','CWE-79','CWE-22')}
    for x in dev:
        if x['intended_attack'] and x['variant']!='raw' and x['source']=='heuristic':
            grouped[x['cwe']].append(x)
    out=[]
    for k,items in grouped.items():
        # Fixed deterministic order; count 4 per CWE per LLM response.
        for i in range(n):
            row=dict(items[i % len(items)])
            row['id']=f'exploratory-heuristic-{k}-{i}'
            out.append(row)
    return out


def score(rows):
    o={}
    for name in ('heuristic','gpt-6-luna'):
        subset=[r for r in rows if r['case']['source']==name]
        by_cwe={}
        for group in ('ALL','CWE-89','CWE-79','CWE-22'):
            ss=[r for r in subset if group=='ALL' or r['case']['cwe']==group]
            valid=[r for r in ss if r['direct'].get('effect') is True]
            by_cwe[group]={'proposed':len(ss),'valid_oracle':len(valid),
              'invalid_attack':sum(r['outcome']=='invalid_attack' for r in ss),
              'blocked':sum(r['outcome']=='blocked_attack' for r in valid),
              'bypass':sum(r['outcome']=='bypass' for r in valid),
              'uncertain':sum(r['outcome'].startswith('uncertain') for r in ss),
              'bypass_per_valid':round(sum(r['outcome']=='bypass' for r in valid)/len(valid),6) if valid else None}
        o[name]=by_cwe
    return o


def run(reps):
    c.require(reps in (1,2),'Fixed-budget additional runs support 1 or 2 reps only.')
    c.require(not HOME.exists(),
              f'An exploratory attempt already exists in {HOME}. Do not resample until a favorable result.')
    # Users must finish one-shot test and lab drift first to avoid contamination.
    c.require((c.RECOVERY/'test-summary.json').is_file(),
              'First finish the held-out evaluation; optional generation must remain separate.')
    final=c.read_json(c.RECOVERY/'test-summary.json')
    c.require(final['all_seven_complete'] and final['rollback_verified'],
              'Final evaluation not validated or rollback not verified.')
    c.plan_checked()
    rb=c.import_baseline()
    if str(c.ROOT/'lab') not in sys.path:
        sys.path.insert(0,str(c.ROOT/'lab'))
    llm=importlib.import_module('llm')
    c.require(llm.MODELS==[ALIAS], 'Original model alias list differs from only gpt-6-luna.')
    dev,audit=rb.load_cases('dev',False)
    seeds=[x for x in dev if not x['intended_attack'] or x['variant']=='raw']
    with c.study_lock():
        HOME.mkdir(parents=True,exist_ok=False)
        raw_dir=HOME/'responses';raw_dir.mkdir()
        c.write_json(HOME/'experiment-plan.json',{
           'model':ALIAS,'reps':reps,'fixed_max_cases_per_request':12,
           'total_candidate_budget':12*reps,'dev_only':True,'new_calls':reps,
           'validation_or_test_data_used_in_prompt':False,
           'tuning_allowed':False,'selection_allowed':False,
           'comparison_heuristic_budget':12*reps,
           'source_dev_hash':c.sha(json.dumps(seeds,ensure_ascii=False,sort_keys=True).encode()),
           'created_utc':c.now()})
        responses=[]
        for rep in range(reps):
            responses.append(call_once(llm,seeds,rep,raw_dir))
        generated,rejected=collect_cases(seeds,responses)
        heur=control_cases(dev,4*reps)
        report={'utc':c.now(),'model_alias':ALIAS,'model_weights_verified':False,
                'reps':reps,'raw_response_files':[f'responses/call-{x}.json' for x in range(reps)],
                'accepted_generated':len(generated),'rejected':rejected,
                'heuristic_budget':len(heur),'status':'GENERATED_NOT_EVALUATED',
                'inference_is_exploratory':True,'development_split_only':True,
                'model_superiority_demonstrated':False,
                'limitations':['Dev-only: no held-out family independence.',
                   'Heuristic control differs from generative search space.',
                   'Gateway service model alias does not cryptographically verify weights.',
                   'No rule creation, modification, or promotion from this experiment.']}
        c.write_json(HOME/'generation-summary.json',report)
        if not generated:
            report['status']='NO_VALID_GENERATION'
            c.write_json(HOME/'exploratory-summary.json',report)
            print('No valid payloads generated; raw failures retained. No retries.')
            return
        c.docker_ready()
        c.direct_and_waf_health(rb)
        activated=False
        try:
            activated=True
            c.activate(None,c.read_json(c.STUDY/'frozen-plan.json')['candidates'][0],HOME)
            import requests
            ctx,browser,oracle=c.browser_context(rb)
            try:
                rows=[]
                with requests.Session() as s:
                    s.trust_env=False
                    for index,case in enumerate(heur+generated):
                        record=c.eval_case(rb,case,index,'llm-dev-exploratory',s,oracle)
                        c.append_jsonl(HOME/'observations.jsonl',record)
                        rows.append(record)
                report['observations_sha256']=c.digest_path(HOME/'observations.jsonl')
                report['comparison']=score(rows)
                report['status']='EXPLORATORY_DEV_MEASURED'
            finally:
                browser.close();ctx.stop()
        except Exception as exc:
            report['status']='EXPLORATORY_INCOMPLETE'
            report['error']=f'{type(exc).__name__}: {exc}'
        finally:
            if activated:
                try: report['rollback']=c.restore(HOME)
                except Exception as exc:
                    report['status']='ROLLBACK_NOT_VERIFIED';report['rollback_error']=str(exc)
        c.write_json(HOME/'exploratory-summary.json',report)
        print(json.dumps({'status':report['status'],'accepted_llm_cases':len(generated),
              'heuristic_control_cases':len(heur),'summary':str(HOME/'exploratory-summary.json')},
              ensure_ascii=False,indent=2))


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--run',required=True,action='store_true',help='Explicit opt-in; makes paid/new gpt-6-luna calls')
    p.add_argument('--reps',type=int,default=1,choices=(1,2),help='Exactly one or two fixed-budget calls')
    args=p.parse_args()
    try:
        run(args.reps)
    except Exception as exc:
        print(f'EXPLORATORY FAIL: {exc}',file=sys.stderr)
        sys.exit(2)
