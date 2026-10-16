"""Measure the existing localhost fixture; never generate samples or call an LLM.

Default dev-only run preserves the held-out test. Browser observations render
the captured HTTP response in a fresh Chromium context with network blocked.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from datetime import datetime, timezone
import hashlib
import html
import json
from pathlib import Path
import platform
import subprocess
import sys
import time
from urllib.parse import urlencode

import requests
from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / 'results/checkpoint'
DIRECT = 'http://127.0.0.1:18080'
WAF = 'http://127.0.0.1:18081'
ROUTES = {'/sql': 'CWE-89', '/xss': 'CWE-79', '/file': 'CWE-22',
          '/search': 'CWE-89', '/docs': 'CWE-79'}
SPLITS = {'dev', 'validation', 'test'}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def save(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')


def validate_case(row):
    if not isinstance(row, dict):
        raise ValueError('Case is not an object')
    for key in ('id', 'family', 'split', 'cwe', 'route', 'q', 'variant', 'source'):
        if not isinstance(row.get(key), str):
            raise ValueError(f'Case field {key} must be a string')
    if not row['id'] or not row['family'] or row['split'] not in SPLITS:
        raise ValueError('Invalid identifier or split')
    if row['route'] not in ROUTES or row['cwe'] != ROUTES[row['route']]:
        raise ValueError('Route/CWE mismatch')
    if type(row.get('intended_attack')) is not bool or len(row['q']) > 8192:
        raise ValueError('Invalid label or excessive input length')


def load_cases(split, include_llm):
    path = EVIDENCE / 'corpus.json'
    raw = path.read_bytes()
    expected = (EVIDENCE / 'corpus.sha256').read_text().strip()
    if digest(raw) != expected:
        raise ValueError('Frozen corpus hash mismatch; do not silently replace the manifest')
    corpus = json.loads(raw)
    ids, families, shared = {}, defaultdict(set), defaultdict(set)
    for row in corpus:
        validate_case(row)
        if row['id'] in ids:
            raise ValueError('Duplicate corpus case ID')
        ids[row['id']] = row
        families[row['family']].add(row['split'])
        shared[(row['route'], row['q'])].add(row['split'])
    if any(len(s) > 1 for s in families.values()):
        raise ValueError('A seed family crosses splits')
    audit = {'corpus_sha256': expected, 'corpus_rows': len(corpus),
             'shared_exact_inputs_across_splits': sum(len(v) > 1 for v in shared.values()),
             'note': 'Disjoint family identifiers do not prove semantic family independence.',
             'api_calls': [], 'rejected_llm_cases': []}
    cases = [dict(row) for row in corpus if row['split'] == split]
    if include_llm and split == 'dev':
        for path in sorted((EVIDENCE / 'llm').glob('payload-gpt-6-luna-*.json')):
            record = json.loads(path.read_text())
            parsed = record.get('parsed')
            candidates = parsed.get('cases') if isinstance(parsed, dict) else None
            valid_list = isinstance(candidates, list)
            audit['api_calls'].append({'file': path.name, 'sha256': digest(path.read_bytes()),
                'status': record.get('status'), 'parsed_json': 'parsed' in record,
                'candidate_count': len(candidates) if valid_list else 0,
                'budget_compliant': valid_list and len(candidates) == 12})
            if record.get('model_alias') != 'gpt-6-luna' or record.get('status') != 200:
                continue
            if not valid_list or len(candidates) > 12:
                continue
            for index, candidate in enumerate(candidates):
                reason = None
                parent = ids.get(candidate.get('parent_id')) if isinstance(candidate, dict) else None
                if not parent or parent['split'] != 'dev' or not parent['intended_attack']:
                    reason = 'missing_or_non_dev_attack_parent'
                elif candidate.get('route') != parent['route']:
                    reason = 'parent_route_mismatch'
                elif not isinstance(candidate.get('q'), str) or len(candidate['q']) > 8192:
                    reason = 'invalid_value'
                if reason:
                    audit['rejected_llm_cases'].append({'file': path.name, 'index': index, 'reason': reason})
                    continue
                row = dict(parent, id=f'llm-{path.stem}-{index}', q=candidate['q'],
                           variant='llm', source='gpt-6-luna', parent_id=parent['id'],
                           replicate=record.get('replicate'))
                validate_case(row)
                cases.append(row)
    seen = {}
    for row in cases:
        key = (row['source'], row['route'], row['q'])
        row['duplicate_of'] = seen.get(key)
        seen.setdefault(key, row['id'])
    audit['selected_rows'] = len(cases)
    audit['within_source_duplicates'] = sum(bool(x['duplicate_of']) for x in cases)
    return cases, audit


class BrowserOracle:
    def __init__(self, browser, window_ms):
        self.browser = browser
        self.window_ms = window_ms

    def observe(self, body, mime, url):
        context = self.browser.new_context(service_workers='block', accept_downloads=False)
        page = context.new_page()
        page.on('dialog', lambda dialog: dialog.dismiss())
        served = False

        def intercept(route):
            nonlocal served
            if not served and route.request.is_navigation_request() and route.request.url == url:
                served = True
                route.fulfill(status=200, content_type=mime, body=body)
            else:
                route.abort()

        context.route('**/*', intercept)
        if hasattr(context, 'route_web_socket'):
            context.route_web_socket('**/*', lambda ws: ws.close())
        try:
            page.goto(url, wait_until='domcontentloaded', timeout=5000)
            page.wait_for_timeout(self.window_ms)
            return page.evaluate('window.__trace === 1')
        finally:
            context.close()


def fetch(session, case, base, request_id):
    url = base + case['route'] + '?' + urlencode({'q': case['q']})
    start = time.perf_counter()
    try:
        response = session.get(url, timeout=10, allow_redirects=False,
                               headers={'X-Trace-Request': request_id})
        return {'status': response.status_code, 'body': response.text,
                'content_type': response.headers.get('Content-Type', ''),
                'backend_request_id': response.headers.get('X-Trace-Request'),
                'body_sha256': digest(response.content),
                'elapsed_ms': round((time.perf_counter() - start) * 1000, 3)}
    except requests.RequestException as exc:
        return {'error': type(exc).__name__, 'elapsed_ms': round((time.perf_counter()-start)*1000, 3)}


def effect(case, response, browser):
    if 'error' in response or response.get('status', 0) >= 500:
        return None
    if response.get('status') != 200:
        return False
    if case['route'] == '/sql':
        try:
            rows = json.loads(response['body'])
            return isinstance(rows, list) and any(isinstance(row, list) and 'TRACE_SQL_SECRET' in row for row in rows)
        except ValueError:
            return None
    if case['route'] == '/file':
        return response['body'] == 'TRACE_FILE_SECRET'
    if case['route'] in ('/xss', '/docs', '/search'):
        try:
            return browser.observe(response['body'], response['content_type'],
                                   DIRECT + case['route'] + '?' + urlencode({'q': case['q']}))
        except Exception as exc:
            response['oracle_error'] = type(exc).__name__
            return None
    return None


def benign_expected(case, response):
    if 'error' in response:
        return False
    if case['route'] in ('/docs', '/search'):
        expected = '<!doctype html><html><body>' + html.escape(case['q']) + '</body></html>'
        return response['status'] == 200 and response['body'] == expected
    if case['route'] == '/file':
        return ((response['status'] == 200 and response['body'] == 'PUBLIC_DOCUMENT') or
                (response['status'] == 404 and response['body'] == 'not found'))
    return False


def decision(case, direct, protected):
    if direct.get('effect') is None:
        return 'uncertain_direct'
    if case['intended_attack']:
        if not direct['effect']:
            return 'invalid_attack'
    elif direct['effect'] or not benign_expected(case, direct):
        return 'invalid_benign'
    if 'error' in protected or protected.get('status', 0) >= 500 or protected.get('effect') is None:
        return 'uncertain_waf'
    # Require the fixture echo to distinguish backend responses from intermediary errors.
    blocked = protected['status'] == 403 and not protected.get('backend_request_id')
    if case['intended_attack']:
        if blocked and not protected['effect']:
            return 'blocked_attack'
        if protected['effect']:
            return 'bypass'
        return 'not_blocked_no_effect'
    if blocked:
        return 'false_positive'
    if (protected.get('backend_request_id') and protected['status'] == direct['status']
            and protected['body_sha256'] == direct['body_sha256'] and not protected['effect']):
        return 'true_negative'
    return 'benign_regression'


def summarize(rows):
    groups = []
    for source in ['ALL'] + sorted({r['case']['source'] for r in rows}):
        for cwe in ['ALL', 'CWE-89', 'CWE-79', 'CWE-22']:
            chosen = [r for r in rows if (source == 'ALL' or r['case']['source'] == source) and
                      (cwe == 'ALL' or r['case']['cwe'] == cwe)]
            counts = Counter(r['outcome'] for r in chosen)
            attacks = [r for r in chosen if r['case']['intended_attack'] and r['direct']['effect'] is True
                       and r['outcome'] != 'uncertain_waf']
            benign = [r for r in chosen if r['outcome'] in ('false_positive','true_negative','benign_regression')]
            transformed = [r for r in attacks if r['case']['variant'] != 'raw']
            ratio = lambda n,d: round(n/d, 6) if d else None
            groups.append({'source': source, 'cwe': cwe, 'rows': len(chosen), 'counts': dict(counts),
                'valid_evaluable_attacks': len(attacks), 'valid_evaluable_benign': len(benign),
                'coverage': ratio(sum(r['outcome']=='blocked_attack' for r in attacks),len(attacks)),
                'bypass_rate': ratio(sum(r['outcome']=='bypass' for r in attacks),len(attacks)),
                'fpr': ratio(counts['false_positive'],len(benign)),
                'robustness': ratio(sum(r['outcome']=='blocked_attack' for r in transformed),len(transformed)),
                'benign_regressions': counts['benign_regression']})
    return groups


def command_evidence(command):
    try:
        p = subprocess.run(command, capture_output=True, text=True, timeout=20, cwd=ROOT)
        return {'command': command, 'returncode': p.returncode, 'stdout': p.stdout, 'stderr': p.stderr}
    except Exception as exc:
        return {'command': command, 'error': type(exc).__name__}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--split', choices=sorted(SPLITS), default='dev')
    parser.add_argument('--include-llm', action='store_true', help='Include saved GPT dev variants; no API call')
    parser.add_argument('--check', action='store_true', help='Preflight only; no corpus requests')
    parser.add_argument('--browser-path', type=Path)
    parser.add_argument('--window-ms', type=int, default=750)
    parser.add_argument('--output', type=Path, help='New, non-existing evidence directory')
    parser.add_argument('--policy-id', help='Policy study label; requires exact active rule hash')
    parser.add_argument('--expected-rule-sha256')
    args = parser.parse_args()
    if not 100 <= args.window_ms <= 5000:
        parser.error('--window-ms must be 100..5000')
    if args.include_llm and args.split != 'dev':
        parser.error('Saved generated samples are dev-only')
    active = (ROOT/'lab/active-rules.conf').read_text()
    if args.policy_id:
        if digest(active.encode()) != args.expected_rule_sha256:
            parser.error('Active rule hash differs from the frozen study candidate')
    elif any(line.strip() and not line.lstrip().startswith('#') for line in active.splitlines()):
        parser.error('Baseline requires empty/comment-only active-rules.conf; no configuration changed')
    cases, audit = load_cases(args.split, args.include_llm)
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    output = args.output or EVIDENCE/'baseline'/f'{stamp}-{args.split}'
    output.mkdir(parents=True, exist_ok=False)
    save(output/'input-audit.json', audit)
    save(output/'cases.json', cases)
    session = requests.Session()
    session.trust_env = False
    for base in (DIRECT, WAF):
        response = session.get(base+'/health', timeout=10, allow_redirects=False)
        if response.status_code != 200 or response.text != 'ok':
            raise RuntimeError('Health preflight failed')
        if base == WAF and args.policy_id and response.headers.get('X-Trace-Policy') != args.policy_id:
            raise RuntimeError('Running policy marker does not match selected policy')
    with sync_playwright() as pw:
        chrome = args.browser_path
        installed = Path('/Applications/Google Chrome.app/Contents/MacOS/Google Chrome')
        if chrome is None and installed.exists():
            chrome = installed
        options = {'headless': True, 'args': ['--disable-background-networking','--disable-extensions']}
        if chrome:
            options['executable_path'] = str(chrome)
        browser = pw.chromium.launch(**options)
        oracle = BrowserOracle(browser, args.window_ms)
        if oracle.observe('<html><body>control</body></html>', 'text/html', DIRECT+'/control'):
            raise RuntimeError('Negative browser control failed')
        if not oracle.observe('<script>window.__trace=1</script>', 'text/html', DIRECT+'/control'):
            raise RuntimeError('Positive browser control failed')
        page = browser.new_page()
        page.goto('about:blank')
        if page.evaluate('1 + 1') != 2:
            raise RuntimeError('Browser JavaScript control failed')
        page.close()
        manifest = {'started_utc': stamp, 'split': args.split, 'preflight_only': args.check,
            'policy_id': args.policy_id or 'baseline',
            'python': sys.version, 'platform': platform.platform(), 'browser': browser.version,
            'browser_window_ms': args.window_ms, 'corpus_sha256': audit['corpus_sha256'],
            'script_sha256': digest(Path(__file__).read_bytes()),
            'backend_sha256': digest((ROOT/'lab/backend.py').read_bytes()),
            'compose_sha256': digest((ROOT/'lab/compose.yaml').read_bytes()),
            'active_rules_sha256': digest(active.encode()),
            'compose_ps': command_evidence(['docker','compose','-f','lab/compose.yaml','ps','--format','json']),
            'images': command_evidence(['docker','image','inspect','python:3.12-slim','owasp/modsecurity-crs:apache',
                                       '--format','{{.Id}} {{json .RepoDigests}}']),
            'running_containers': command_evidence(['docker','inspect','trace-checkpoint-backend-1',
                'trace-checkpoint-waf-1','--format',
                '{{.Name}} image={{.Image}} env={{json .Config.Env}} mounts={{json .Mounts}}']),
            'limitations': ['Browser renders captured response with all subsequent networking blocked.',
                'Observation window is bounded; not proof of absence of all browser execution.',
                'SQL oracle checks marker output, not arbitrary data extraction or every SQLi impact.',
                '403 classification requires fixture behavior and should be corroborated with saved WAF logs.',
                'No CVE reproduction or production generalization is implied.',
                'Latency is sequential lab HTTP wall time, not throughput or causal WAF overhead.']}
        save(output/'manifest.json', manifest)
        print('Preflight OK; browser and both localhost services ready.', flush=True)
        if args.check:
            browser.close()
            print('Evidence:', output.relative_to(ROOT))
            return
        rows = []
        started = datetime.now(timezone.utc).isoformat()
        with (output/'observations.jsonl').open('w', encoding='utf-8') as journal:
            for i, case in enumerate(cases):
                request_id = f'trace-{stamp}-{i}'
                direct = fetch(session, case, DIRECT, request_id+'-direct')
                direct['effect'] = effect(case, direct, oracle)
                protected = fetch(session, case, WAF, request_id+'-waf')
                protected['effect'] = effect(case, protected, oracle)
                row = {'case': case, 'request_id': request_id, 'direct': direct, 'waf': protected,
                       'outcome': decision(case, direct, protected)}
                journal.write(json.dumps(row, ensure_ascii=False)+'\n'); journal.flush()
                rows.append(row)
                if (i+1) % 10 == 0 or i+1 == len(cases):
                    print(f'Completed {i+1}/{len(cases)}', flush=True)
        browser.close()
    unique = []; seen = set()
    for row in rows:
        key = (row['case']['source'], row['case']['route'], row['case']['q'])
        if key not in seen:
            seen.add(key); unique.append(row)
    summary = {'split': args.split, 'rows': len(rows), 'unique_within_source_rows':len(unique),
        'outcomes': dict(Counter(r['outcome'] for r in rows)), 'metrics_case_weighted': summarize(rows),
        'metrics_deduplicated': summarize(unique), 'complete': True,
        'uncertain_rows':sum(r['outcome'].startswith('uncertain') for r in rows),
        'input_audit': audit, 'observations_sha256': digest((output/'observations.jsonl').read_bytes())}
    save(output/'summary.json', summary)
    for service in ('backend','waf'):
        log = command_evidence(['docker','compose','-f','lab/compose.yaml','logs','--no-color','--since',started,service])
        save(output/f'{service}-logs.json', log)
    # Only dev evidence can later be supplied to a model.
    if args.split == 'dev':
        save(output/'dev-baseline.json', rows)
    print(json.dumps({'rows':len(rows),'outcomes':summary['outcomes'],'uncertain_rows':summary['uncertain_rows']}, indent=2))
    print('Evidence:', output.relative_to(ROOT))


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print('Interrupted; partial journal retained. No complete summary produced.', file=sys.stderr)
        sys.exit(130)
    except Exception as exc:
        print(f'Run stopped: {type(exc).__name__}. Check services, dependencies and input manifest. No success claim.', file=sys.stderr)
        sys.exit(1)
