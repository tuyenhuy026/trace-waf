#!/usr/bin/env python3
"""TRACE-WAF: deterministic, offline, synthetic WAF policy benchmark.

No sockets, no targets, no exploitation. This is NOT a commercial-WAF test.
The payload strings are synthetic attack-pattern test cases, not confirmed exploits.
"""
from __future__ import annotations
import argparse
import csv
import hashlib
import html
import json
import re
from collections import defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path
from urllib.parse import unquote

SEED = 20261016
ATTACKS = {
    "CWE-89": [
        "item{n}' OR 1=1 --",
        "item{n}') OR ('a'='a') --",
        "1 UNION SELECT marker{n} FROM demo",
        "name{n}' AND 7=7 --",
        'item{n}" OR 2=2 #',
    ],
    "CWE-79": [
        "<script>alert({n})</script>",
        "<img src=x onerror=alert({n})>",
        "<svg onload=alert({n})>",
        '<a href="javascript:alert({n})">test</a>',
        "<iframe srcdoc='<script>alert({n})</script>'></iframe>",
    ],
    "CWE-22": [
        "../../private/record{n}.txt",
        "../restricted/note{n}.log",
        "docs/../../../private/item{n}.txt",
        "..\\..\\restricted\\record{n}.ini",
        "./../private/note{n}.cfg",
    ],
}
ROUTES = {"CWE-89": "/api/search", "CWE-79": "/api/comment", "CWE-22": "/api/file"}
WAFS = ("raw_signature", "canonical_signature", "trace_policy")

@dataclass(frozen=True)
class Case:
    case_id: str
    split: str
    label: int
    cwe: str
    route: str
    variant: str
    group_id: str
    value: str


def encode_every_char(value: str) -> str:
    return "".join(f"%{b:02X}" for b in value.encode("utf-8"))


def flip_ascii_case(value: str) -> str:
    return "".join(ch.upper() if i % 2 else ch.lower() for i, ch in enumerate(value))


def variants(value: str, cwe: str):
    common = [("raw", value), ("url_1", encode_every_char(value)),
              ("url_2", encode_every_char(encode_every_char(value))),
              ("case", flip_ascii_case(value))]
    if cwe == "CWE-89":
        changed = re.sub(r"\s+", "/**/", value)
    elif cwe == "CWE-79":
        changed = value.replace("<", "&#60;").replace(">", "&#62;")
    else:
        changed = value.replace("/", "\\")
    return common + [("cwe_transform", changed)]


def build_cases():
    rows = []
    for cwe, patterns in ATTACKS.items():
        for j, templ in enumerate(patterns):
            for n in range(10):
                # 4 development instances and 6 held-out test instances per template.
                split = "dev" if n < 4 else "test"
                base = templ.format(n=n)
                group = f"{cwe}-{j}-{n}"
                for variant, payload in variants(base, cwe):
                    rows.append(Case(f"A-{cwe}-{j}-{n}-{variant}", split, 1,
                                     cwe, ROUTES[cwe], variant, group, payload))
    for n in range(30):
        split = "dev" if n < 10 else "test"
        regular = [
            ("CWE-89", "/api/search", f"find catalog item {n} in 2026"),
            ("CWE-79", "/api/comment", f"Enjoyed your article number {n}."),
            ("CWE-22", "/api/file", f"docs/chapter_{n}.md"),
        ]
        tricky = [
            ("CWE-89", "/api/search", f"guide to SQL UNION SELECT examples, chapter {n}"),
            ("CWE-79", "/api/tutorial", f"HTML tutorial {n}: <script>alert(0)</script> is escaped by the server"),
            ("CWE-22", "/api/file", f"docs/../docs/chapter_{n}.md"),
        ]
        for kind, items in (("normal", regular), ("hard_negative", tricky)):
            for k, (cwe, route, value) in enumerate(items):
                rows.append(Case(f"B-{kind}-{k}-{n}", split, 0, cwe, route, kind,
                                 f"B-{kind}-{k}-{n}", value))
    return rows


SQL_RE = re.compile(
    r"\bunion\s+select\b|\b(?:or|and)\s*\(?\s*['\"]?[a-z0-9]+['\"]?\s*=\s*['\"]?[a-z0-9]+['\"]?\s*\)?",
    re.IGNORECASE,
)
XSS_RE = re.compile(r"<\s*(?:script|iframe|svg|img)\b|\bon(?:error|load)\s*=|javascript\s*:", re.I)
PATH_RE = re.compile(r"\.\.[/\\]")


def signature(value: str) -> bool:
    return bool(SQL_RE.search(value) or XSS_RE.search(value) or PATH_RE.search(value))


def canonical(value: str, depth: int = 3) -> str:
    """Bounded representation normalization; not a browser or app parser."""
    current = value
    for _ in range(depth):
        new = html.unescape(unquote(current))
        if new == current:
            break
        current = new
    return current


def escapes_document_root(value: str) -> bool:
    """Toy POSIX/Windows-separator path policy: detect upward traversal out of root."""
    parts = value.replace("\\", "/").split("/")
    depth = 0
    for part in parts:
        if part in ("", "."):
            continue
        if part == "..":
            if depth == 0:
                return True
            depth -= 1
        else:
            depth += 1
    return False


def classify(case: Case, strategy: str) -> bool:
    if strategy == "raw_signature":
        return signature(case.value)
    normalized = canonical(case.value)
    if strategy == "canonical_signature":
        return signature(normalized)
    if strategy != "trace_policy":
        raise ValueError(f"Unknown classifier: {strategy}")
    # Route is trusted proxy metadata, not a user-supplied query field.
    if case.route == "/api/search":
        # Simplified token representation to capture comment-separated SQL tokens.
        compact = re.sub(r"/\*.*?\*/", " ", normalized, flags=re.S)
        return bool(SQL_RE.search(compact))
    if case.route == "/api/comment":
        return bool(XSS_RE.search(normalized))
    if case.route == "/api/file":
        return escapes_document_root(normalized)
    if case.route == "/api/tutorial":
        # Bench assumes the tutorial handler performs server-side output encoding.
        return False
    return signature(normalized)


def wilson95(k: int, n: int):
    """Descriptive per-case Wilson interval; cases share templates (not iid)."""
    if not n:
        return [None, None]
    z = 1.959963984540054
    p = k / n
    denom = 1 + z*z/n
    center = (p + z*z/(2*n)) / denom
    half = z * ((p*(1-p)/n + z*z/(4*n*n))**0.5) / denom
    return [round(max(0., center-half), 4), round(min(1., center+half), 4)]


def summarize(cases, predictions):
    out = []
    for strategy in WAFS:
        pred = predictions[strategy]
        for cwe in ("ALL", "CWE-89", "CWE-79", "CWE-22"):
            chosen = [i for i, item in enumerate(cases) if cwe == "ALL" or item.cwe == cwe]
            positives = [i for i in chosen if cases[i].label == 1]
            negatives = [i for i in chosen if cases[i].label == 0]
            transformed = [i for i in positives if cases[i].variant != "raw"]
            clean = [i for i in positives if cases[i].variant == "raw"]
            tp = sum(pred[i] for i in positives)
            fp = sum(pred[i] for i in negatives)
            rt = sum(pred[i] for i in transformed)
            rc = sum(pred[i] for i in clean)
            out.append({
                "strategy": strategy, "cwe": cwe, "tp": tp,
                "fn": len(positives)-tp, "fp": fp, "tn": len(negatives)-fp,
                "attack_n": len(positives), "benign_n": len(negatives),
                "attack_coverage": round(tp/len(positives), 4) if positives else None,
                "fpr": round(fp/len(negatives), 4) if negatives else None,
                "evasion_robustness": round(rt/len(transformed), 4) if transformed else None,
                "clean_recall": round(rc/len(clean), 4) if clean else None,
                "coverage_wilson95": wilson95(tp, len(positives)),
                "fpr_wilson95": wilson95(fp, len(negatives)),
                "robustness_wilson95": wilson95(rt, len(transformed)),
                "selection_rule_pass": bool(tp/len(positives) >= .90 and fp/len(negatives) <= .05 and rt/len(transformed) >= .85) if positives and negatives and transformed else False,
            })
    return out


def run(output: Path):
    output.mkdir(parents=True, exist_ok=True)
    cases = [r for r in build_cases() if r.split == "test"]
    preds = {strategy: [int(classify(c, strategy)) for c in cases] for strategy in WAFS}
    summaries = summarize(cases, preds)
    # Synthetic shift in representation mix; *not* a time-series from production.
    drift = []
    for name, allowed in (("A_raw_case", ("raw", "case")),
                          ("B_encoded", ("url_1", "url_2", "cwe_transform"))):
        idx = [i for i,c in enumerate(cases) if c.label == 1 and c.variant in allowed]
        for strategy in WAFS:
            hits = sum(preds[strategy][i] for i in idx)
            drift.append({"period":name, "strategy":strategy, "detected":hits,
                          "n":len(idx), "recall":round(hits/len(idx),4)})
    fields = list(asdict(cases[0]).keys()) + [f"pred_{s}" for s in WAFS]
    with (output / "detailed_predictions.csv").open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fields)
        writer.writeheader()
        for i,c in enumerate(cases):
            writer.writerow({**asdict(c), **{f"pred_{s}":preds[s][i] for s in WAFS}})
    summary_fields = [k for k in summaries[0] if not k.endswith("wilson95")]
    with (output / "summary.csv").open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, summary_fields)
        writer.writeheader()
        for r in summaries:
            writer.writerow({k:r[k] for k in summary_fields})
    dataset_bytes = (output / "detailed_predictions.csv").read_bytes()
    manifest = {
        "benchmark": "TRACE-WAF synthetic offline benchmark", "seed": SEED,
        "split": "test only (instances 4..9; dev 0..3)", "test_cases":len(cases),
        "dataset_sha256":hashlib.sha256(dataset_bytes).hexdigest(),
        "label_semantics":"synthetic attack-pattern origin; no server-side exploit verification",
        "systems":"3 toy classifiers; no real WAF and no LLM inference",
        "interval_note":"Wilson case-level intervals descriptive only; shared templates violate independence",
        "metrics":summaries, "synthetic_drift":drift,
        "references": ["https://cwe.mitre.org/data/definitions/89.html",
                       "https://cwe.mitre.org/data/definitions/79.html",
                       "https://cwe.mitre.org/data/definitions/22.html"],
    }
    (output / "metrics.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2)+"\n", encoding="utf-8")
    return manifest


if __name__ == "__main__":
    p=argparse.ArgumentParser()
    p.add_argument("--output", default="results", help="Output directory")
    args=p.parse_args()
    result=run(Path(args.output))
    print("Dataset SHA-256:", result["dataset_sha256"])
    print("Test cases:", result["test_cases"])
    for row in result["metrics"]:
        if row["cwe"] == "ALL":
            print(f"{row['strategy']:22} coverage={row['attack_coverage']:.1%} "
                  f"FPR={row['fpr']:.1%} robustness={row['evasion_robustness']:.1%} "
                  f"TP/FN/FP/TN={row['tp']}/{row['fn']}/{row['fp']}/{row['tn']}")
