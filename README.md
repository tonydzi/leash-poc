# leash-poc: MCP tool-poisoning, contained by an independent policy gate

A **reproducible** demonstration of one AI-agent vulnerability class — *indirect
prompt injection via MCP tool descriptions* ("tool poisoning" / "line jumping") —
and how [agent-leash](https://github.com/tonydzi/agent-leash)'s
**plan-vs-authorize** pattern neutralizes it.

> Same attacker. Same poisoned MCP server. Same compromised model.
> The only thing that changes is whether an **independent gate** authorizes outbound actions.

---

### New: the fleet replay (`replay/`)

The original demo above is one agent, one exfiltration. **[replay/](replay/README.md)**
is the same idea at fleet scale: one poisoned instruction reaches **four** agents
through four different input surfaces and tries **five** things (read out of scope,
exfiltrate, call a privileged tool, spawn an over-privileged sub-agent, destroy
without a human). One boundary stops all five before any side-effect, the four
agents still finish their real work, and the journal survives a `SIGKILL` mid-run.

```bash
python replay/repro.py     # five stages, exit 0 = every claim held on your machine
```

It also ships a mutation suite: the gate is broken six ways on purpose and the
checks must go red every time. Two of the defects it documents were real and found
this way.

---

## The class (why it matters)

An MCP server declares tools. Each tool's `description` is injected **verbatim** into the model's context as trusted tool-manifest text, which is what [poc/evil_mcp_server.py](poc/evil_mcp_server.py) abuses. A malicious (or compromised) server
hides instructions inside that description; the model reads tool descriptions as trusted
context and **obeys them** — reading a local secret and shipping it out a tool it was
given for another purpose. This is a textbook *confused deputy*, and [poc/run_poc.py](poc/run_poc.py) runs both halves of it end to end.

Public precedent for the **class** (cited, not re-run against anyone):
- Invariant Labs — *Tool Poisoning Attacks* (Apr 2025)
- Trail of Bits — *"line jumping"* in MCP (2025)
- **30 MCP CVEs in the first 60 days of 2026**; OpenClaw: 21 000+ exposed instances (CVE-2026-25253), 341 malicious skills (our DR synthesis, 2026-08-20)
- Indirect-injection success on recent models: **10.7%–29.6%** in realistic settings (benchmark range, per agent-leash/docs/plan-vs-authorize.md)

## Run it

```bash
python3 poc/run_poc.py     # the naive-vs-leashed contrast (exit 0 = PASS)
python3 poc/test_leash.py  # 7 adversarial checks on the gate (exit 0 = ALL PASS)
```

## What you see

| | naive agent | leashed agent |
|---|---|---|
| model decides | ✅ | ✅ |
| model **authorizes its own** outbound action | ✅ (confused deputy) | ❌ — a deterministic gate does |
| secret exfiltrated | **236 bytes leaked ❌** | **0 bytes — CONTAINED ✅** |
| utility preserved (directions still work) | ✅ | ✅ |

The leash in [poc/leash_gate.py](poc/leash_gate.py) stops the attack **two** independent ways (LEASH-8 domains 4 & 6):
1. **Egress leak-scan** in [poc/leash_gate.py](poc/leash_gate.py) — a secret-shaped payload never reaches an exit.
2. **Tier-2 approval** — outbound actions HOLD until an out-of-band token bound to the
   request id arrives. Text that merely *says* "approved" is data, not authorization, and [poc/leash_gate.py](poc/leash_gate.py) treats it that way.

## Honesty (claim discipline, per agent-leash/FOR-ROBOTS.md)

- The **gate is real code** and its behavior is **deterministic** — that half is proven by the logs in `logs/`.
- The **"model obeys the injection"** half is modeled by a deterministic stand-in
  (`CompromisedBrain`) that represents the *one successful-injection run* the published
  10.7–29.6% rate guarantees will happen. We are **not** claiming 100% of runs are exploited; we are showing what **one** does, and that the leash contains it regardless of rate — the scope and its limits are spelled out in [DISCLOSURE.md](DISCLOSURE.md).
- A **live-LLM susceptibility probe** against a real frontier model is a labeled TODO
  (see `DISCLOSURE.md` §Live-LLM leg) — **not yet run** in this build.
- This attacks **no third party**: the "attacker sink" writes to a local file such as [logs/attacker_sink_naive_20260824-012726.txt](logs/attacker_sink_naive_20260824-012726.txt), the
  "secret" is a fake file, there is zero network code.

## Safe by construction
No network. No third-party systems. No real credentials. No CVE scanning. Everything runs on your own machine.

---

<!--ecosystem-map:start-->

## 🧩 One piece of a working system

This repository is one piece lifted out of a live operation: one non-technical founder, an AI
cofounder, and a fleet of machines that reach consensus with each other and wake the human only
for money or the irreversible. It was extracted after it survived production, not written as a
demo — and it runs on its own: nothing here phones home to the rest.

**See how the whole thing fits together → [SYSTEM.md](https://github.com/tonydzi/tonydzi/blob/main/SYSTEM.md)**

<!--ecosystem-map:end-->

## AI contributors

This project is built by a human + AI team, and the git log says so under the rules in
[AI-CONTRIBUTORS.md](https://github.com/tonydzi/.github/blob/main/AI-CONTRIBUTORS.md): Claude
writes most of the code, Codex and Grok review it, Gemini feeds the research. Each is credited on a commit
**only if its output changed that commit's content** — no decorative credits. Lab-wide
policy, one source for every repo: [AI-CONTRIBUTORS.md](https://github.com/tonydzi/.github/blob/main/AI-CONTRIBUTORS.md).
