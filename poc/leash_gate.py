"""
leash_gate.py — a deterministic policy gate implementing agent-leash's
plan-vs-authorize pattern (docs/plan-vs-authorize.md, LEASH-8 domain 4 "Approvals"
+ domain 6 "Egress").

The whole point: authorization is enforced OUTSIDE the model loop, in code that
"cannot be sweet-talked". The model proposes a structured request; this gate
classifies it into a tier and decides. Tier-2 (outbound / irreversible) HOLDs
until an out-of-band approval TOKEN bound to the request id arrives.

This file is the PRODUCT half of the demo: it is what agent-leash teaches you to build.
"""
import re

# LEASH-8 domain 4: the written, boring, enumerated action classes.
# Undeclared classes default to the HIGHEST tier (fail-closed), per the doc.
OUTBOUND_TOOLS = {"send_feedback", "send_message", "email", "post", "http_post"}
DELETE_TOOLS   = {"delete", "rm", "drop_table"}

# LEASH-8 domain 6: a hard egress leak-scan. Secrets must never reach an exit.
SECRET_PATTERNS = [
    re.compile(r"sk-[A-Za-z0-9\-]{8,}"),        # API-key-shaped
    re.compile(r"(?i)\bDB_PASSWORD\s*="),
    re.compile(r"(?i)\bAPI_KEY\s*="),
]

def classify(action):
    """Return (tier, reason). Pure function, no model, no network."""
    tool = action.get("tool", "")
    if tool in DELETE_TOOLS:
        return 2, f"{tool}: irreversible deletion"
    if tool in OUTBOUND_TOOLS:
        return 2, f"{tool}: outbound message to a human/3rd party"
    # read-only / internal tools
    if tool in {"get_directions", "read_file", "query_db"}:
        return 0, f"{tool}: reversible, internal"
    return 2, f"{tool}: UNDECLARED class -> default to highest tier (fail-closed)"

def leak_scan(action):
    """Domain 6 hard gate: does this payload carry a secret out the door?"""
    blob = " ".join(str(v) for v in action.get("args", {}).values())
    for pat in SECRET_PATTERNS:
        if pat.search(blob):
            return True, pat.pattern
    return False, None

class LeashGate:
    """Deterministic gate. approvals: {request_id: token} from an out-of-band, allowlisted channel."""
    def __init__(self, approvals=None):
        self.approvals = approvals or {}   # nothing pre-approved by default

    def decide(self, action, request_id):
        tier, reason = classify(action)
        if tier <= 1:
            return {"decision": "EXECUTE", "tier": tier, "reason": reason}
        # tier 2: first, egress leak-scan (a second, independent layer)
        leaked, pat = leak_scan(action)
        if leaked:
            return {"decision": "BLOCK", "tier": 2,
                    "reason": f"egress leak-scan tripped ({pat}) — secret would exfiltrate"}
        # then require an out-of-band token bound to this request id
        token = self.approvals.get(request_id)
        if token == f"APPROVE {request_id}":
            return {"decision": "EXECUTE", "tier": 2, "reason": f"{reason}; approved out-of-band"}
        return {"decision": "HOLD", "tier": 2,
                "reason": f"{reason}; awaiting out-of-band APPROVE {request_id}"}
