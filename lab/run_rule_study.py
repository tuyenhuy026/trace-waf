"""Frozen validation study: stock CRS, scoped heuristic and five GPT proposals.

No test requests. Never executes model-provided shell/configuration text. Only a
restricted JSON policy is compiled; original local rules are restored in finally.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import fcntl
import json
from pathlib import Path
import re
import subprocess
import sys
import time

import requests

import llm
from run_baseline import ROOT, EVIDENCE, digest, save, load_cases

COMPOSE = ['docker', 'compose', '-f', 'lab/compose.yaml']
ACTIVE = ROOT/'lab/active-rules.conf'
SAFE_ROUTES = {'/docs', '/search'}
ATTACK_ROUTES = {'/sql', '/xss', '/file'}
TAGS = ('attack-sqli', 'attack-xss', 'attack-lfi', 'attack-rfi', 'attack-rce')


def serialize_pattern(pattern):
    """Represent literal quote tokens as PCRE hex escapes, preserving slash parity."""
    if (not isinstance(pattern, str) or not 1 <= len(pattern) <= 512 or
            any(ord(ch) < 32 for ch in pattern) or pattern.endswith('\\')):
        raise ValueError('Unsafe or oversized rule representation')
    if '"' in pattern and '\\Q' in pattern:
        raise ValueError('Quoted PCRE regions require a separate serializer')
    result = ''
    for ch in pattern:
        if ch != '"':
            result += ch
            continue
        slashes = len(result) - len(result.rstrip('\\'))
        if slashes % 2:
            result = result[:-1]
        result += r'\x22'
    return result


def compile_policy(policy, policy_id):
    if not re.fullmatch(r'[A-Za-z0-9_-]{1,60}', policy_id):
        raise ValueError('Invalid policy ID')
    if not isinstance(policy, dict) or 'error' in policy:
        raise ValueError('Not a candidate policy')
    exempt, patterns = policy.get('exempt_routes'), policy.get('patterns')
    if not isinstance(exempt, list) or not isinstance(patterns, list):
        raise ValueError('Policy arrays missing')
    if any(not isinstance(x,str) or x not in SAFE_ROUTES for x in exempt):
        raise ValueError('Exclusion outside verified escaping routes')
    if len(exempt) > 2 or len(set(exempt)) != len(exempt) or len(patterns) > 3:
        raise ValueError('Candidate exceeds policy budget')
    lines = [f'# TRACE policy {policy_id}', f'Header always set X-Trace-Policy "{policy_id}"']
    rule_id = 110000
    for route in sorted(exempt):
        actions = ','.join(f'ctl:ruleRemoveTargetByTag={tag};ARGS:q' for tag in TAGS)
        lines.append(f'SecRule REQUEST_URI "@rx ^{route}(?:[?]|$)" "id:{rule_id},phase:1,pass,nolog,t:none,{actions}"')
        rule_id += 1
    for item in patterns:
        if (not isinstance(item,dict) or not isinstance(item.get('route'),str)
                or item['route'] not in ATTACK_ROUTES):
            raise ValueError('Blocking route invalid')
        pattern = serialize_pattern(item.get('regex'))
        route = item['route']
        lines.append(f'SecRule REQUEST_URI "@rx ^{route}(?:[?]|$)" "id:{rule_id},phase:2,deny,status:403,log,t:none,chain"')
        lines.append(f'    SecRule ARGS:q "@rx {pattern}" "t:none,t:urlDecodeUni,t:htmlEntityDecode,t:lowercase"')
        rule_id += 1
    return '\n'.join(lines)+'\n'


def dev_evidence(directory):
    summary = json.loads((directory/'summary.json').read_text())
    raw = (directory/'observations.jsonl').read_bytes()
    if not summary.get('complete') or summary.get('split') != 'dev':
        raise ValueError('A completed dev run is required')
    if digest(raw) != summary.get('observations_sha256'):
        raise ValueError('Dev observation hash mismatch')
    rows = [json.loads(line) for line in raw.decode().splitlines()]
    if any(r['case']['split'] != 'dev' for r in rows):
        raise ValueError('Non-dev evidence rejected')
    selected = [r for r in rows if r['case']['variant']=='raw' or
                r['outcome'] in ('false_positive','benign_regression','bypass')]
    return {'split':'dev','source_sha256':digest(raw),
        'metrics':summary['metrics_deduplicated'],
        'observations':[{'case':r['case'],'outcome':r['outcome'],
                         'direct_effect':r['direct']['effect'],
                         'direct_status':r['direct'].get('status'),
                         'waf_status':r['waf'].get('status')} for r in selected],
        'known_proxy_behavior':'ProxyErrorOverride=on replaces backend 404 pages; this is recorded separately from WAF blocking.'}


def run_command(command, evidence_path, timeout=90):
    result = subprocess.run(command,cwd=ROOT,capture_output=True,text=True,timeout=timeout)
    save(evidence_path,{'command':command,'returncode':result.returncode,
                        'stdout':result.stdout,'stderr':result.stderr})
    return result.returncode == 0


def ready(expected, timeout=45):
    deadline = time.monotonic()+timeout
    session = requests.Session(); session.trust_env=False
    try:
        while time.monotonic()<deadline:
            try:
                r=session.get('http://127.0.0.1:18081/health',timeout=2,allow_redirects=False)
                if r.status_code==200 and r.text=='ok' and r.headers.get('X-Trace-Policy')==expected:
                    return True
            except requests.RequestException:
                pass
            time.sleep(1)
        return False
    finally:
        session.close()


def gate(summary):
    metrics=summary['metrics_deduplicated']
    overall=next(m for m in metrics if m['source']=='ALL' and m['cwe']=='ALL')
    reasons=[]
    for key,threshold,direction in [('coverage',.9,'min'),('fpr',.05,'max'),('robustness',.85,'min')]:
        value=overall[key]
        if value is None or (value<threshold if direction=='min' else value>threshold):
            reasons.append(key)
    if summary['uncertain_rows']:
        reasons.append('uncertain_measurements')
    if overall['benign_regressions']:
        reasons.append('benign_functional_regression')
    for cwe in ('CWE-89','CWE-79','CWE-22'):
        metric=next(m for m in metrics if m['source']=='ALL' and m['cwe']==cwe)
        if not metric['valid_evaluable_attacks'] or not metric['valid_evaluable_benign']:
            reasons.append('missing_evidence_'+cwe)
    return {'pass':not reasons,'reasons':reasons,'metrics':overall}


def prepare(args, directory):
    replay = getattr(args, 'replay_study', None)
    if replay:
        replay = replay.resolve()
        raw_plan = (replay/'frozen-plan.json').read_bytes()
        if digest(raw_plan) != (replay/'frozen-plan.sha256').read_text().strip():
            raise ValueError('Source study plan hash mismatch')
        old_plan = json.loads(raw_plan)
        evidence_bytes = (replay/'dev-evidence.json').read_bytes()
        if digest(evidence_bytes) != old_plan['dev_evidence_sha256']:
            raise ValueError('Source dev evidence hash mismatch')
        evidence = json.loads(evidence_bytes)
        if evidence.get('split') != 'dev':
            raise ValueError('Replay must use dev evidence')
    else:
        evidence=dev_evidence(args.dev_run)
    save(directory/'dev-evidence.json',evidence)
    llm.OUT=directory/'llm'
    source_responses = []
    for rep in range(5):
        if replay:
            source = replay/'llm'/f'rule-gpt-6-luna-{rep}.json'
            raw = source.read_bytes()
            record = json.loads(raw)
            if record.get('model_alias') != 'gpt-6-luna' or record.get('role') != 'rule':
                raise ValueError('Wrong API record role or alias')
            llm.OUT.mkdir(exist_ok=True)
            (llm.OUT/source.name).write_bytes(raw)
            source_responses.append({'file':source.name,'sha256':digest(raw)})
            print(f'Reused saved proposal {rep+1}/5; no API call', flush=True)
        else:
            print(f'GPT rule proposal {rep+1}/5',flush=True)
            print(llm.call('gpt-6-luna','rule',rep,evidence),flush=True)
    proposals=[('B0',{'exempt_routes':[],'patterns':[]},'stock_crs'),
               ('B1',{'exempt_routes':['/docs','/search'],'patterns':[]},'fixed_heuristic')]
    rejected=[]
    for rep in range(5):
        path=llm.OUT/f'rule-gpt-6-luna-{rep}.json'
        record=json.loads(path.read_text())
        if record.get('status')!=200 or 'parsed' not in record:
            rejected.append({'id':f'L{rep+1}','reason':'api_or_json_failure'})
        else:
            proposals.append((f'L{rep+1}',record['parsed'],'gpt-6-luna'))
    candidates=[]
    for ident,policy,source in proposals:
        try:
            config=compile_policy(policy,ident)
        except ValueError as exc:
            rejected.append({'id':ident,'reason':str(exc)})
            continue
        (directory/f'{ident}.conf').write_text(config)
        save(directory/f'{ident}.json',policy)
        candidates.append({'id':ident,'source':source,'rule_sha256':digest(config.encode())})
    # Freeze every candidate before examining any validation result.
    plan={'created_utc':datetime.now(timezone.utc).isoformat(),'candidates':candidates,
          'rejected':rejected,'dev_evidence_sha256':digest((directory/'dev-evidence.json').read_bytes()),
          'corpus_sha256':(EVIDENCE/'corpus.sha256').read_text().strip(),
          'selection':'passing validation gate; min FPR, max coverage, then ID',
          'gate':'coverage>=.90, FPR<=.05, robustness>=.85; all CWEs present; no uncertainty or functional regression',
          'test_accessed':False,'model':'gpt-6-luna','replicates':5,
          'compiler_version':'2-quote-token-serialization',
          'compiler_sha256':digest(Path(__file__).read_bytes()),
          'replayed_from':str(replay) if replay else None,'source_responses':source_responses,
          'interpretation':'Compiler correction replay, not five new independent model generations' if replay else 'Original model calls'}
    save(directory/'frozen-plan.json',plan)
    (directory/'frozen-plan.sha256').write_text(digest((directory/'frozen-plan.json').read_bytes())+'\n')
    return plan


def evaluate(directory, plan, split='validation'):
    if split not in ('validation', 'test'):
        raise ValueError('Unsupported evaluation split')
    original=ACTIVE.read_bytes()
    (directory/'original-rules.conf').write_bytes(original)
    if any(line.strip() and not line.lstrip().startswith(b'#') for line in original.splitlines()):
        raise ValueError('Expected original baseline only; refusing to overwrite unrelated active policy')
    results=[]
    direct_reference=None
    rollback={'attempted':False,'restored':False}
    try:
        for candidate in plan['candidates']:
            ident=candidate['id']
            config=(directory/f'{ident}.conf').read_bytes()
            if digest(config)!=candidate['rule_sha256']:
                raise ValueError('Candidate hash changed after freeze')
            print(f'{split.title()} policy {ident}',flush=True)
            ACTIVE.write_bytes(config)
            syntax_ok=run_command(COMPOSE+['exec','-T','waf','httpd','-t'],directory/f'{ident}-syntax.json')
            if not syntax_ok:
                results.append({'id':ident,'status':'rejected_syntax'})
                save(directory/'validation-progress.json',results)
                continue
            if not run_command(COMPOSE+['up','-d','--no-deps','--force-recreate','waf'],directory/f'{ident}-activate.json') or not ready(ident):
                raise RuntimeError('Policy activation or marker failed')
            output=directory/f'{ident}-{split}'
            command=[sys.executable,str(ROOT/'lab/run_baseline.py'),'--split',split,
                     '--output',str(output),'--policy-id',ident,'--expected-rule-sha256',candidate['rule_sha256']]
            # Stream only the runner's aggregate progress, never raw response/configuration.
            completed=subprocess.run(command,cwd=ROOT)
            if completed.returncode:
                results.append({'id':ident,'status':'evaluation_failed'})
            else:
                summary=json.loads((output/'summary.json').read_text())
                observations=[json.loads(line) for line in (output/'observations.jsonl').read_text().splitlines()]
                direct_signature={r['case']['id']:[r['direct'].get('status'),r['direct']['effect'],
                                                   r['direct'].get('body_sha256')] for r in observations}
                if direct_reference is None:
                    if ident!='B0': raise RuntimeError('No evaluated baseline reference')
                    direct_reference=direct_signature
                verdict=gate(summary)
                if direct_signature!=direct_reference:
                    verdict['pass']=False
                    verdict['reasons'].append('direct_oracle_changed_between_policies')
                results.append({'id':ident,'source':candidate['source'],'status':'evaluated',
                                'summary_sha256':digest((output/'summary.json').read_bytes()),'gate':verdict})
            save(directory/'validation-progress.json',results)
    finally:
        rollback['attempted']=True
        ACTIVE.write_bytes(original)
        try:
            restarted=run_command(COMPOSE+['up','-d','--no-deps','--force-recreate','waf'],directory/'rollback-command.json')
            rollback['restored']=restarted and ready(None) and ACTIVE.read_bytes()==original
        finally:
            rollback['original_sha256']=digest(original)
            save(directory/'rollback.json',rollback)
        if not rollback['restored']:
            raise RuntimeError('Rollback not verified; inspect rollback evidence before continuing')
    passing=[r for r in results if r.get('gate',{}).get('pass')]
    passing.sort(key=lambda r:(r['gate']['metrics']['fpr'],-r['gate']['metrics']['coverage'],r['id']))
    report={'results':results,'rejected_before_validation':plan['rejected'],
            'selected_policy':passing[0]['id'] if passing and split=='validation' else None,
            'decision':('ELIGIBLE_FOR_HELD_OUT_TEST' if passing else 'NO_GO') if split=='validation' else 'NO_GO_FROM_VALIDATION_UNCHANGED',
            'test_accessed':split=='test','rollback':rollback,
            'note':'Lab simulation by one operator; not production approval or independent human review.'}
    save(directory/'study-summary.json',report)
    print(json.dumps({'decision':report['decision'],'selected_policy':report['selected_policy'],
                     'evaluated':sum(r['status']=='evaluated' for r in results),
                     'rollback_verified':rollback['restored'],'test_accessed':split=='test'},indent=2))


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dev-run',type=Path)
    parser.add_argument('--prepare-only',action='store_true')
    parser.add_argument('--evaluate-prepared',type=Path,help='Existing frozen study; no API calls')
    parser.add_argument('--replay-study',type=Path,help='New study using five saved responses, no API calls')
    args=parser.parse_args()
    if args.replay_study and (args.evaluate_prepared or args.dev_run):
        parser.error('--replay-study cannot be combined with --evaluate-prepared or --dev-run')
    # Validation input is audited but not measured until all candidate rules are frozen.
    load_cases('validation',False)
    EVIDENCE.mkdir(parents=True,exist_ok=True)
    with (EVIDENCE/'rule-study.lock').open('w') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        if args.evaluate_prepared:
            directory=args.evaluate_prepared.resolve()
            raw=(directory/'frozen-plan.json').read_bytes()
            if digest(raw)!=(directory/'frozen-plan.sha256').read_text().strip():
                raise ValueError('Frozen study plan modified')
            plan=json.loads(raw)
            if (directory/'rollback.json').exists() or (directory/'validation-progress.json').exists():
                raise ValueError('Study already evaluated or interrupted; preserve its evidence')
        else:
            if not args.dev_run and not args.replay_study:
                runs=sorted((EVIDENCE/'baseline').glob('*/summary.json'))
                runs=[p for p in runs if json.loads(p.read_text()).get('split')=='dev']
                if not runs: raise ValueError('No completed dev baseline found')
                args.dev_run=runs[-1].parent
            stamp=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
            directory=EVIDENCE/'rule-study'/stamp
            directory.mkdir(parents=True,exist_ok=False)
            print('Study:',directory.relative_to(ROOT),flush=True)
            plan=prepare(args,directory)
        if plan['corpus_sha256']!=(EVIDENCE/'corpus.sha256').read_text().strip():
            raise ValueError('Corpus changed after candidate freeze')
        if args.prepare_only:
            print('Frozen candidates:',len(plan['candidates']),'Rejected:',len(plan['rejected']))
        else:
            evaluate(directory,plan)
        print('Evidence:',directory.relative_to(ROOT))


if __name__=='__main__':
    try:
        main()
    except KeyboardInterrupt:
        print('Interrupted. Check rollback.json; partial evidence retained.',file=sys.stderr)
        sys.exit(130)
    except Exception as exc:
        print(f'Study stopped: {type(exc).__name__}: {exc}',file=sys.stderr)
        sys.exit(1)
