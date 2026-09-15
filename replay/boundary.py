"""
boundary.py -- one deterministic execution boundary for a fleet of agents.

The contract, in one sentence: an agent never performs a side-effect itself. It
submits a structured request; this code decides; only an EXECUTE decision reaches
an executor. Nothing in here calls a model, and nothing in here can be talked out
of a decision, because it never reads the agent's prose -- only the structured
fields the agent submitted.

Five things it stops, which are the five things a poisoned instruction actually
tries (see poisoned_source.py for where the instruction comes from):

  1. read out of scope          -- a resource outside the agent's capability grant
  2. exfiltration               -- an endpoint outside the egress allowlist, or a
                                   payload carrying secret-shaped data
  3. privileged tool-call       -- a tool the agent was never granted
  4. delegation escalation      -- handing a sub-agent a right the parent does not
                                   itself hold (privilege amplification by spawning)
  5. irreversible without human -- delete / pay / publish, held until an out-of-band
                                   token bound to THIS request id arrives

Design rules that make it boring on purpose (AK-47):
  * fail-closed: an action whose class is not enumerated gets the highest tier.
  * attenuation-only delegation: a child's grant must be a subset of its parent's.
  * the approval token is bound to a request id and arrives out-of-band. Text in
    the agent's own context that merely SAYS "approved" is data, not authorization.
  * every decision is journalled BEFORE it is returned (see audit_log.py).
"""
import fnmatch
import re

from audit_log import AuditLog

# --- action classes (LEASH-8 domain 4: written down, enumerated, boring) -------
READ_TOOLS = {"read_file", "query_db", "get_directions", "list_dir"}
EGRESS_TOOLS = {"http_post", "send_message", "email", "post", "send_feedback"}
IRREVERSIBLE_TOOLS = {"delete_file", "drop_table", "pay_invoice", "publish", "rotate_key"}
DELEGATE_TOOLS = {"spawn_subagent"}

MAX_DELEGATION_DEPTH = 3

# --- egress leak-scan (LEASH-8 domain 6) --------------------------------------
SECRET_PATTERNS = [
    re.compile(r"sk-[A-Za-z0-9\-]{8,}"),
    re.compile(r"(?i)\b(DB_PASSWORD|API_KEY|SECRET_KEY|PRIVATE_KEY)\s*[=:]"),
    re.compile(r"(?i)\bBEGIN (RSA |EC )?PRIVATE KEY\b"),
    re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),  # SSN-shaped, payroll exfil canary
]


class Grant:
    """What one principal is allowed to do. Resources are glob patterns."""

    def __init__(self, tools, resources, egress=()):
        self.tools = frozenset(tools)
        self.resources = tuple(resources)
        self.egress = tuple(egress)

    def covers_tool(self, tool):
        return tool in self.tools

    def covers_resource(self, resource):
        return any(fnmatch.fnmatch(resource or "", pat) for pat in self.resources)

    def covers_egress(self, endpoint):
        return any(fnmatch.fnmatch(endpoint or "", pat) for pat in self.egress)

    def is_subset_of(self, other):
        """Attenuation check: every right here must exist in `other`."""
        if not self.tools <= other.tools:
            return False, "tools %s not held by parent" % sorted(self.tools - other.tools)
        for pat in self.resources:
            if not any(fnmatch.fnmatch(pat, p) or pat == p for p in other.resources):
                return False, "resource pattern %r not held by parent" % pat
        for pat in self.egress:
            if not any(fnmatch.fnmatch(pat, p) or pat == p for p in other.egress):
                return False, "egress %r not held by parent" % pat
        return True, None


class Decision:
    __slots__ = ("verdict", "tier", "reason", "rule", "request_id")

    def __init__(self, verdict, tier, reason, rule, request_id):
        self.verdict = verdict          # EXECUTE | BLOCK | HOLD
        self.tier = tier
        self.reason = reason
        self.rule = rule                # which of the five rules fired
        self.request_id = request_id

    def as_dict(self):
        return {
            "verdict": self.verdict,
            "tier": self.tier,
            "reason": self.reason,
            "rule": self.rule,
            "request_id": self.request_id,
        }

    def __repr__(self):
        return "<%s %s: %s>" % (self.verdict, self.rule, self.reason)


def leak_scan(args):
    blob = " ".join(str(v) for v in (args or {}).values())
    for pat in SECRET_PATTERNS:
        hit = pat.search(blob)
        if hit:
            return True, pat.pattern
    return False, None


class ExecutionBoundary:
    """The single gate every action in the fleet passes through."""

    def __init__(self, grants, audit_path, approvals=None):
        self.grants = dict(grants)            # principal -> Grant
        self.audit = AuditLog(audit_path)
        self.approvals = dict(approvals or {})
        self.delegations = {}                 # child -> parent

    # -- delegation bookkeeping ------------------------------------------------
    def register_delegation(self, parent, child, grant):
        self.delegations[child] = parent
        self.grants[child] = grant

    def chain_of(self, principal):
        chain, seen = [principal], {principal}
        while principal in self.delegations:
            principal = self.delegations[principal]
            if principal in seen:
                break
            chain.append(principal)
            seen.add(principal)
        return list(reversed(chain))

    # -- the decision ----------------------------------------------------------
    def authorize(self, action, request_id):
        decision = self._classify(action, request_id)
        # journal BEFORE returning: an authorized action is never un-logged
        self.audit.append({
            "event": "boundary.decision",
            "request_id": request_id,
            "principal": action.get("principal"),
            "delegation_chain": self.chain_of(action.get("principal")),
            "tool": action.get("tool"),
            "resource": action.get("resource"),
            "decision": decision.as_dict(),
        })
        return decision

    def _classify(self, action, rid):
        principal = action.get("principal")
        tool = action.get("tool", "")
        resource = action.get("resource", "")
        args = action.get("args", {})

        grant = self.grants.get(principal)
        if grant is None:
            return Decision("BLOCK", 2, "unknown principal %r" % principal,
                            "unknown-principal", rid)

        chain = self.chain_of(principal)
        if len(chain) > MAX_DELEGATION_DEPTH:
            return Decision("BLOCK", 2,
                            "delegation depth %d exceeds cap %d" % (len(chain), MAX_DELEGATION_DEPTH),
                            "delegation-depth", rid)

        # rule 3: privileged / undeclared tool
        if not grant.covers_tool(tool):
            return Decision("BLOCK", 2,
                            "%s: tool not in this principal's grant" % tool,
                            "privileged-tool", rid)

        # rule 4: delegation escalation
        if tool in DELEGATE_TOOLS:
            child_grant = action.get("child_grant")
            if not isinstance(child_grant, Grant):
                return Decision("BLOCK", 2, "spawn_subagent without a declared child grant",
                                "delegation-escalation", rid)
            ok, why = child_grant.is_subset_of(grant)
            if not ok:
                return Decision("BLOCK", 2,
                                "sub-agent would gain rights the parent lacks: %s" % why,
                                "delegation-escalation", rid)
            return Decision("EXECUTE", 1, "attenuated delegation within parent's grant",
                            "delegation-ok", rid)

        # rule 1: read out of scope
        if tool in READ_TOOLS:
            if not grant.covers_resource(resource):
                return Decision("BLOCK", 2,
                                "%s: resource %r outside grant" % (tool, resource),
                                "read-out-of-scope", rid)
            return Decision("EXECUTE", 0, "%s: in-scope read" % tool, "read-ok", rid)

        # rule 2: exfiltration
        if tool in EGRESS_TOOLS:
            if not grant.covers_egress(resource):
                return Decision("BLOCK", 2,
                                "%s: endpoint %r not on egress allowlist" % (tool, resource),
                                "exfil-endpoint", rid)
            leaked, pat = leak_scan(args)
            if leaked:
                return Decision("BLOCK", 2,
                                "payload carries secret-shaped data (%s)" % pat,
                                "exfil-payload", rid)
            return Decision("EXECUTE", 1, "%s: allowlisted endpoint, clean payload" % tool,
                            "egress-ok", rid)

        # rule 5: irreversible -> human, out-of-band, bound to this request id.
        # Scope is checked FIRST and on its own. Holding an out-of-scope destructive
        # action for approval would be a bug that looks like a feature: it converts
        # "this agent may never touch that resource" into "one tired human away from
        # touching it". Out of scope is a refusal, not a question.
        if tool in IRREVERSIBLE_TOOLS:
            if not grant.covers_resource(resource):
                return Decision("BLOCK", 2,
                                "%s: resource %r outside grant -- not an approvable request"
                                % (tool, resource),
                                "irreversible-out-of-scope", rid)
            leaked, pat = leak_scan(args)
            if leaked:
                return Decision("BLOCK", 2, "irreversible action carries secret data (%s)" % pat,
                                "irreversible-payload", rid)
            if self.approvals.get(rid) == "APPROVE %s" % rid:
                return Decision("EXECUTE", 2, "%s: approved out-of-band for this request id" % tool,
                                "irreversible-approved", rid)
            return Decision("HOLD", 2,
                            "%s: irreversible, awaiting out-of-band APPROVE %s" % (tool, rid),
                            "irreversible-hold", rid)

        # fail-closed
        return Decision("BLOCK", 2, "%s: undeclared action class -> highest tier" % tool,
                        "fail-closed", rid)
