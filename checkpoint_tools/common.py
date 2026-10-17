"""Shared, conservative tools for the TRACE-WAF local-only evidence runners.

Install alongside the original lab/ and results/checkpoint/ directories.
DO NOT use this module to test external hosts.
"""
from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
import fcntl
import hashlib
import importlib
import json
import os
import platform
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
CP = ROOT / 'results' / 'checkpoint'
STUDY = CP / 'rule-study' / '20261016T170642475819Z'
PRIOR = CP / 'final-test'
RECOVERY = CP / 'final-test-continuation' / '20261016T170642475819Z'
ACTIVE = ROOT / 'lab' / 'active-rules.conf'
COMPOSE = ['docker', 'compose', '-f', 'lab/compose.yaml']
EXPECTED_CORPUS_SHA = '2b96fbdf944bcb06f8d4918b063dc16e9e318091dcf8740e9e3b9538b3d7c707'
EXPECTED_FROZEN_PLAN_SHA = '80897b18898c5e90285e47de12f5de3acd4f14cf620cf802380537a2f592f5a3'
EXPECTED_BASELINE_SHA = 'b57de18a3a6a365af3c7f016805bb73364fec13d6350fba1c34cd7476d53d05c'
EXPECTED_RULE_STUDY_SHA = 'b9fd05cee7865f0ffe29b10ea510bc6a7051ae854501797c12ac9b914f1cebfc'
IDS = ('B0', 'B1', 'L1', 'L2', 'L3', 'L4', 'L5')


def now():
    return datetime.now(timezone.utc).isoformat()


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def digest_path(path: Path):
    return sha(path.read_bytes())


def write_json(path: Path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + '.new')
    with tmp.open('w', encoding='utf-8') as handle:
        json.dump(value, handle, ensure_ascii=False, indent=2)
        handle.write('\n')
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(tmp, path)


def read_json(path: Path):
    return json.loads(path.read_text(encoding='utf-8'))


def require(condition, msg):
    if not condition:
        raise RuntimeError(msg)


def is_comments_only(raw):
    return all(not line.strip() or line.lstrip().startswith(b'#') for line in raw.splitlines())


def plan_checked(allow_resume=False):
    require(ROOT.joinpath('lab/run_baseline.py').is_file(),
            'Place checkpoint_tools/ beside original lab/ folder in the repository root.')
    require(digest_path(STUDY/'frozen-plan.json') == EXPECTED_FROZEN_PLAN_SHA,
            'Frozen study plan does not match the pre-registered checkpoint hash.')
    require((STUDY/'frozen-plan.sha256').read_text().strip() == EXPECTED_FROZEN_PLAN_SHA,
            'Frozen plan sidecar mismatch.')
    require(digest_path(ROOT/'lab/run_baseline.py') == EXPECTED_BASELINE_SHA,
            'run_baseline.py changed since frozen checkpoint. Inspect changes; do not silently evaluate.')
    require(digest_path(ROOT/'lab/run_rule_study.py') == EXPECTED_RULE_STUDY_SHA,
            'run_rule_study.py changed since frozen checkpoint. Inspect changes; do not silently evaluate.')
    require(digest_path(CP/'corpus.json') == EXPECTED_CORPUS_SHA,
            'Frozen corpus changed; do not continue on a different dataset.')
    require((CP/'corpus.sha256').read_text().strip() == EXPECTED_CORPUS_SHA,
            'Corpus hash sidecar mismatch.')
    p = read_json(STUDY/'frozen-plan.json')
    require([x['id'] for x in p['candidates']] == list(IDS), 'Expected exactly B0/B1/L1-L5.')
    require(p.get('model') == 'gpt-6-luna', 'Unexpected model alias in frozen study.')
    require(all(digest_path(STUDY/(c['id']+'.conf')) == c['rule_sha256']
                for c in p['candidates']), 'Frozen candidate rule content changed.')
    require(all(not (PRIOR/(c['id']+'.conf')).exists() or
                digest_path(PRIOR/(c['id']+'.conf')) == c['rule_sha256']
                for c in p['candidates']), 'Pre-existing final-test rule copy mismatch.')
    summary = read_json(STUDY/'study-summary.json')
    require(summary.get('decision') == 'NO_GO' and summary['rollback']['restored'],
            'Validation NO_GO and rollback evidence are prerequisites.')
    require([x['id'] for x in summary['results']] == list(IDS),
            'Seven validation decisions missing.')
    require(all(not x['gate']['pass'] for x in summary['results']),
            'Unexpected changed gate outcome; re-audit before evaluation.')
    original = (STUDY/'original-rules.conf').read_bytes()
    require(is_comments_only(original), 'Saved original active rules are not comment-only.')
    require(sha(original) == summary['rollback']['original_sha256'],
            'Saved original rules do not match rollback audit.')
    require(ACTIVE.is_file(), 'lab/active-rules.conf missing.')
    allowed = {sha(original), p['candidates'][0]['rule_sha256']}
    if allow_resume and RECOVERY.is_dir():
        allowed |= {x['rule_sha256'] for x in p['candidates']}
    require(sha(ACTIVE.read_bytes()) in allowed,
            'Unexpected active rule. Preserve it and inspect before resuming; not overwritten.')
    return p


def import_baseline():
    p = ROOT/'lab'
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))
    return importlib.import_module('run_baseline')


@contextmanager
def study_lock():
    lock_path = CP/'rule-study.lock'
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open('a+b') as f:
        try:
            fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise RuntimeError('Another TRACE-WAF study holds rule-study.lock.') from exc
        yield


def command(cmd, evidence=None, timeout=120):
    try:
        x = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, timeout=timeout)
        result = {'command':cmd, 'exit_code':x.returncode, 'stdout':x.stdout[-1500000:],
                  'stderr':x.stderr[-300000:], 'utc':now()}
    except (OSError, subprocess.TimeoutExpired) as exc:
        result = {'command':cmd, 'error':str(exc), 'utc':now()}
    if evidence:
        write_json(evidence, result)
    return result


def docker_ready():
    r = command(['docker','info','--format','{{.ServerVersion}}'], timeout=18)
    require(r.get('exit_code') == 0, 'Docker daemon unavailable; open Docker Desktop.')
    return r['stdout'].strip()


def health(marker, port=18081, timeout=50):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            req=urllib.request.Request(f'http://127.0.0.1:{port}/health')
            with urllib.request.urlopen(req, timeout=2) as r:
                if (r.status == 200 and r.read() == b'ok' and
                        r.headers.get('X-Trace-Policy') == marker):
                    return True
        except (urllib.error.URLError, TimeoutError, ConnectionError):
            pass
        time.sleep(1)
    return False


def activate(p, item, ev_dir: Path):
    ident = item['id']
    data = (STUDY/(ident+'.conf')).read_bytes()
    require(sha(data) == item['rule_sha256'], 'Rule hash changed before activation.')
    ACTIVE.write_bytes(data)
    syntax = command(COMPOSE + ['exec','-T','waf','httpd','-t'], ev_dir/(ident+'-syntax.json'))
    require(syntax.get('exit_code') == 0, f'{ident}: Apache syntax validation failed.')
    up = command(COMPOSE+['up','-d','--no-deps','--force-recreate','waf'],
                 ev_dir/(ident+'-activate.json'), timeout=180)
    require(up.get('exit_code') == 0 and health(ident),
            f'{ident}: WAF activation or X-Trace-Policy marker failed.')


def restore(evidence_dir: Path):
    original = (STUDY/'original-rules.conf').read_bytes()
    ACTIVE.write_bytes(original)
    up = command(COMPOSE+['up','-d','--no-deps','--force-recreate','waf'],
                 evidence_dir/'rollback-command.json', timeout=180)
    ok = bool(up.get('exit_code') == 0 and health(None) and ACTIVE.read_bytes() == original)
    result = {'attempted': True, 'restored': ok, 'original_sha256':sha(original),
              'active_rules_sha256':sha(ACTIVE.read_bytes()), 'utc':now()}
    write_json(evidence_dir/'rollback.json', result)
    if not ok:
        raise RuntimeError('ROLLBACK NOT VERIFIED. Stop all runs; inspect lab/active-rules.conf and WAF.')
    return result


def browser_context(rb, window=750):
    """Return stoppable Playwright instance, Chrome browser, and original test oracle."""
    from playwright.sync_api import sync_playwright
    ctx = sync_playwright()
    pw = ctx.start()
    app = Path('/Applications/Google Chrome.app/Contents/MacOS/Google Chrome')
    opts={'headless':True, 'args':['--disable-background-networking','--disable-extensions']}
    if app.exists(): opts['executable_path']=str(app)
    try:
        browser=pw.chromium.launch(**opts)
        oracle=rb.BrowserOracle(browser,window)
        require(not oracle.observe('<html><body>control</body></html>','text/html',rb.DIRECT+'/control'),
                'Negative browser control failed.')
        require(oracle.observe('<script>window.__trace=1</script>','text/html',rb.DIRECT+'/control'),
                'Positive browser control failed.')
        return pw,browser,oracle
    except BaseException:
        pw.stop()
        raise


def direct_and_waf_health(rb):
    import requests
    with requests.Session() as s:
        s.trust_env=False
        for base in (rb.DIRECT, rb.WAF):
            resp=s.get(base+'/health', timeout=8, allow_redirects=False)
            require(resp.status_code==200 and resp.text=='ok', f'Health failed for {base}')


def eval_case(rb, case, index, stamp, session, browser_oracle):
    reqid=f'trace-{stamp}-{index}'
    direct=rb.fetch(session,case,rb.DIRECT,reqid+'-direct')
    direct['effect']=rb.effect(case,direct,browser_oracle)
    waf=rb.fetch(session,case,rb.WAF,reqid+'-waf')
    waf['effect']=rb.effect(case,waf,browser_oracle)
    return {'case':case,'request_id':reqid,'direct':direct,'waf':waf,
            'outcome':rb.decision(case,direct,waf)}


def summarize(rb, rows, audit, split='test'):
    from collections import Counter
    unique=[]; seen=set()
    for x in rows:
        c=x['case']; k=(c['source'],c['route'],c['q'])
        if k not in seen:
            seen.add(k); unique.append(x)
    outcomes=Counter(x['outcome'] for x in rows)
    return {'split':split,'rows':len(rows),'unique_within_source_rows':len(unique),
        'outcomes':dict(outcomes),'metrics_case_weighted':rb.summarize(rows),
        'metrics_deduplicated':rb.summarize(unique),
        'complete':not any(x['outcome'].startswith('uncertain') or x['outcome']=='invalid_benign' for x in rows),
        'uncertain_rows':sum(x['outcome'].startswith('uncertain') for x in rows),
        'input_audit':audit,'derived_utc':now()}


def append_jsonl(path: Path, item):
    with path.open('a',encoding='utf-8') as stream:
        stream.write(json.dumps(item,ensure_ascii=False)+'\n')
        stream.flush()
        os.fsync(stream.fileno())


def read_jsonl(path):
    with Path(path).open(encoding='utf-8') as f:
        return [json.loads(line) for line in f if line.strip()]


def collect_logs(directory, since):
    for service in ('waf','backend'):
        result=command(COMPOSE+['logs','--no-color','--since',since,service],timeout=45)
        write_json(directory/(service+'-logs.json'),result)


def environment():
    return {'timestamp_utc':now(),'python':sys.version,'platform':platform.platform(),
        'hostname_redacted':True,'runner':sha(Path(__file__).read_bytes()),
        'docker':command(['docker','version','--format','{{.Server.Version}}'],timeout=12),
        'compose':command(['docker','compose','version'],timeout=12)}
