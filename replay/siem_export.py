"""
siem_export.py -- turn the journal into something a SOC can actually ingest.

Format is Elastic Common Schema (ECS) field names, one JSON object per line
(NDJSON), because that is what Elastic, Splunk HEC and Sentinel all accept with
no custom parser. This is deliberately a translation layer and nothing more: the
journal is the evidence, this is the shipping label.

    python replay/siem_export.py                 # NDJSON to stdout
    python replay/siem_export.py --out ev.ndjson # ...or to a file
    python replay/siem_export.py --blocked-only

The field that matters to a responder is `agent.delegation_chain`: when something
is stopped four layers deep in a spawn tree, "which agent did this" is a bad
question. "Which chain of authority ended here" is the answer you can act on.
"""
import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from audit_log import AuditLog  # noqa: E402

DEFAULT_AUDIT = os.path.join(os.path.dirname(HERE), "logs", "replay_audit.jsonl")

# ECS event.outcome is a closed vocabulary: success | failure | unknown.
OUTCOME = {"EXECUTE": "success", "BLOCK": "failure", "HOLD": "unknown"}
SEVERITY = {"EXECUTE": 0, "HOLD": 5, "BLOCK": 8}


def to_ecs(record):
    p = record["payload"]
    d = p.get("decision", {})
    verdict = d.get("verdict", "UNKNOWN")
    return {
        "@timestamp": None,  # the journal is ordered by seq, not wall clock; see DISCLOSURE.md
        "event": {
            "kind": "event",
            "category": ["process", "iam"],
            "type": ["access"],
            "action": "agent.%s" % p.get("tool"),
            "outcome": OUTCOME.get(verdict, "unknown"),
            "severity": SEVERITY.get(verdict, 0),
            "reason": d.get("reason"),
            "sequence": record["seq"],
            "id": d.get("request_id"),
        },
        "rule": {"name": d.get("rule")},
        "agent": {
            "id": p.get("principal"),
            "delegation_chain": p.get("delegation_chain", []),
        },
        "target": {"resource": p.get("resource")},
        "labels": {"verdict": verdict, "tier": d.get("tier")},
        "log": {"hash": record["hash"], "prev_hash": record["prev"]},
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--audit", default=DEFAULT_AUDIT)
    ap.add_argument("--out")
    ap.add_argument("--blocked-only", action="store_true")
    args = ap.parse_args()

    ok, n, problem = AuditLog.verify(args.audit)
    if not ok:
        sys.stderr.write("refusing to export: journal does not verify -- %s\n" % problem)
        return 2

    lines = []
    for rec in AuditLog.read(args.audit):
        if args.blocked_only and rec["payload"].get("decision", {}).get("verdict") == "EXECUTE":
            continue
        lines.append(json.dumps(to_ecs(rec), sort_keys=True))

    body = "\n".join(lines) + ("\n" if lines else "")
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(body)
        sys.stderr.write("exported %d/%d verified events -> %s\n" % (len(lines), n, args.out))
    else:
        sys.stdout.write(body)
    return 0


if __name__ == "__main__":
    sys.exit(main())
