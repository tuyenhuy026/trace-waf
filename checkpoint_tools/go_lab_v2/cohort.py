"""Fixed, prospective and deliberately adversarial family-based lab cohort.

No input is sent to an LLM. This fixture is publicly inspectable and therefore
not an independent deployment benchmark; it is a prospective controlled lab test.
It MUST be frozen before sending the single policy-generation LLM request.
"""
from __future__ import annotations
from urllib.parse import quote

SQL=[
 ("boolean_alternative","' OR 2=2 --"),
 ("quoted_tautology","' OR 'k'='k' --"),
 ("secret_like","' OR name LIKE 'TRACE%' --"),
 ("existence_test","' OR EXISTS(SELECT 1 FROM items WHERE public=0) --"),
]
XSS=[
 ("svg_space","<svg onload=\"window.__trace = 1\"></svg>"),
 ("image_alt","<img src=missing-image onerror=\"window.__trace=1\" alt=lab>"),
 ("body_attr","<body onload=\"window.__trace = 1\"></body>"),
]
FILES=[
 ("dot_extension",".././secret.txt"),
 ("nested_relative","./public/../../secret.txt"),
 ("inner_dir","tmp/../../secret.txt"),
]
BENIGN={
 "/sql":["apple","O'Reilly","hello -- world","--","-- just a note","test -- more","a--b",
   "UNION SELECT tutorial","name LIKE pattern","' punctuation only","UPDATE notes","abc'xyz",
   "quoted % percent","x+y=z","SQL lecture","white space","not found","name LIKE 'test'"],
 "/xss":["plain text","safe heading","<b>Formatting</b>","<i>Italic</i>","hello & goodbye",
   "<code>javascript</code>","<span>docs</span>","onerror in a sentence","script reference","<p>Class notes</p>"],
 "/file":["readme.txt","./readme.txt","../public/readme.txt","public/../readme.txt",
   "missing.txt","docs/missing.txt","images/missing.png","archive/no.txt","2026-notes.txt",
   "not_available.txt","./no.txt","./docs/no.txt","./temp/missing.txt","public/missing.txt"],
 "/search":["union all tutorial","<img src=x onerror=alert(1)>","../path in a guide",
   "${7*7} example","how to SQL -- commentary","SELECT * FROM users","%3Cscript%3E illustration",
   "Japanese 日本語","O'Reilly docs","web firewall FPR"],
 "/docs":["UNION SELECT lesson","<svg onload=demo()>","regex (?:x|y)","../public/readme.txt",
   "escaping HTML tags <script>","file access documentation","XSS detection","SQL tutorial",
   "../../path in docs","100% completed"],
}
CWES={"/sql":"CWE-89","/search":"CWE-89","/xss":"CWE-79","/docs":"CWE-79","/file":"CWE-22"}

def build():
 rows=[]
 for route,groups in (("/sql",SQL),("/xss",XSS),("/file",FILES)):
  for k,(label,seed) in enumerate(groups):
   variants=[("raw",seed)]
   if route=="/sql":
    variants += [("tab",seed.replace(" ","\t")),("comments",seed.replace(" ","/**/"))]
   elif route=="/xss":
    variants += [("case",seed.replace("<svg","<SVG").replace("<img","<IMG").replace("<body","<BODY")),
                 ("percent",quote(seed,safe=""))]
   else:
    variants += [("extra_dot","./"+seed), ("percent",quote(seed,safe=""))]
   for name,payload in variants:
    rows.append({"id":f"go2-{route[1:]}-{label}-{name}","family":f"go2-{route[1:]}-{label}",
     "split":"test","route":route,"cwe":CWES[route],"q":payload,
     "variant":name,"source":"prospective_curated","intended_attack":True})
 for route,values in BENIGN.items():
  for i,v in enumerate(values):
   rows.append({"id":f"go2-benign-{route[1:]}-{i}","family":f"go2-benign-{route[1:]}-{i}",
     "split":"test","route":route,"cwe":CWES[route],"q":v,
     "variant":"benign","source":"prospective_hard_negative","intended_attack":False})
 assert len({r["id"] for r in rows})==len(rows)
 return rows

if __name__=='__main__':
 from collections import Counter
 v=build();print(len(v),"cases:",Counter((r["route"],r["intended_attack"]) for r in v))
