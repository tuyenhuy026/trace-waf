#!/usr/bin/env python3
"""Validate prototype rule provenance and change-control metadata."""
import argparse
import json
from pathlib import Path
REQUIRED = ("rule_id", "cwe", "evidence", "scope", "policy", "owner", "review_state", "rollback", "expiration_days")

def audit(path: Path):
    records = json.loads(path.read_text(encoding="utf-8"))
    ids=set()
    for record in records:
        missing=[k for k in REQUIRED if k not in record or not record[k]]
        if missing:
            raise ValueError(f"Missing fields {missing} in {record}")
        assert record["rule_id"] not in ids, "duplicate rule ID"
        assert record["cwe"].startswith("CWE-"), "invalid CWE ID"
        assert all(url.startswith("https://") for url in record["evidence"]), "source must use HTTPS"
        assert record["expiration_days"] > 0, "expiration must be positive"
        ids.add(record["rule_id"])
    return len(records)

if __name__ == "__main__":
    p=argparse.ArgumentParser()
    p.add_argument("path", nargs="?", default="rules/rule_register.json")
    args=p.parse_args()
    print(f"PASS: {audit(Path(args.path))} prototype rules have all audit fields")
