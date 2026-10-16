"""Freeze explicit seed-family partitions before evaluating WAF candidates."""
import hashlib
import json
from pathlib import Path
from urllib.parse import quote

SEEDS = {
 'sql': {
  'dev': ["' OR 1=1 --", "' UNION SELECT name FROM items --"],
  'validation': ["' OR public=0 --", "' UNION SELECT 'TRACE_SQL_SECRET' --"],
  'test': ["' OR name GLOB 'TRACE*' --", "' OR public IN (0) --", "' OR NOT public --", "' UNION ALL SELECT name FROM items WHERE public=0 --"],
 },
 'xss': {
  'dev': ['<script>window.__trace=1</script>', '<img src=x onerror="window.__trace=1">'],
  'validation': ['<svg onload="window.__trace=1"></svg>', '<iframe srcdoc="<script>parent.__trace=1</script>"></iframe>'],
  'test': ['<body onload="window.__trace=1">', '<details open ontoggle="window.__trace=1">x</details>', '<video><source onerror="window.__trace=1" src=x></video>', '<input autofocus onfocus="window.__trace=1">'],
 },
 'file': {
  'dev': ['../secret.txt', 'public/../../secret.txt'],
  'validation': ['./../secret.txt', '../public/../secret.txt'],
  'test': ['../public/./../secret.txt', '././../secret.txt', 'a/../../secret.txt', '../public/a/../../secret.txt'],
 },
}
CWE = {'sql':'CWE-89', 'xss':'CWE-79', 'file':'CWE-22'}


def build():
    out = []
    for route, splits in SEEDS.items():
        for split, seeds in splits.items():
            for i, value in enumerate(seeds):
                variants = [('raw', value), ('percent', quote(value, safe='')),
                            ('double_percent', quote(quote(value, safe=''), safe=''))]
                if route == 'sql':
                    variants += [('comments', value.replace(' ', '/**/')), ('tab', value.replace(' ', '\t'))]
                elif route == 'xss':
                    variants += [('tag_case', value.replace('<script', '<ScRiPt').replace('<img', '<IMG').replace('<svg', '<SVG')),
                                 ('entities', value.replace('<', '&#60;').replace('>', '&#62;'))]
                else:
                    variants += [('backslash', value.replace('/', '\\')), ('extra_dot', './'+value)]
                for variant, payload in variants:
                    ident = f'{split}-{route}-{i}-{variant}'
                    out.append(dict(id=ident, family=f'{split}-{route}-{i}', split=split,
                                    cwe=CWE[route], route='/'+route, q=payload,
                                    intended_attack=True, variant=variant, source='heuristic'))
    benign = {
     'dev': ['apple','hello world','SQL UNION SELECT tutorial','<script>example</script>', 'readme.txt','./readme.txt'],
     'validation': ['orange','a & b','SELECT name FROM items','<img src=x onerror=demo()>','../public/readme.txt','missing.txt'],
     'test': ["O\u0027Reilly",'price < 20','UNION ALL documentation','<svg onload=example()>',
              'public/../readme.txt','././readme.txt','日本語の検索','café & tea',
              '1 OR 1=1 explanation','../../example in a manual','<iframe srcdoc="sample">',
              'javascript: as a tutorial','100% complete','a+b=c','null','',
              'docs/chapter.md','<details open>guide</details>','SELECT * FROM users', 'backslash \\ guide'],
    }
    for split, values in benign.items():
        for i, value in enumerate(values):
            for route,cwe in [('/search','CWE-89'),('/docs','CWE-79')]:
                out.append(dict(id=f'{split}-benign-{route[1:]}-{i}',family=f'{split}-benign-{i}',
                   split=split,cwe=cwe,route=route,q=value,intended_attack=False,variant='benign',source='curated'))
        for i,value in enumerate(['readme.txt','./readme.txt','../public/readme.txt','missing.txt']):
            out.append(dict(id=f'{split}-benign-file-{i}',family=f'{split}-file-benign-{i}',split=split,
                cwe='CWE-22',route='/file',q=value,intended_attack=False,variant='benign',source='curated'))
    return out


if __name__ == '__main__':
    path=Path('results/checkpoint/corpus.json')
    if path.exists():
        raise SystemExit('Corpus already frozen; choose a new experiment directory to replace it.')
    data=json.dumps(build(),ensure_ascii=False,indent=2)+'\n'
    path.write_text(data)
    Path('results/checkpoint/corpus.sha256').write_text(hashlib.sha256(data.encode()).hexdigest()+'\n')
    print(len(build()), 'cases frozen')
