# Responsible-disclosure analysis

## Is there anything to disclose?

**No — as this PoC stands, there is nothing to report to a third party.**

This PoC demonstrates a **generic architectural class** (confused-deputy via
tool-description injection) on **our own testbed**, using a **mock** MCP server we
wrote. It does not target, name, scan, or touch any specific vendor's product, and it
relies only on a class that is **already public** (Invariant Labs / Trail of Bits /
30 MCP CVEs in 2026). Public class + our own stand ⇒ nothing new is being revealed, so
there is no disclosure obligation and no one to notify.

## IF a future iteration targets a specific product

If we later reproduce this against a **named** MCP server / agent product and find a
**specific, previously-unknown** flaw, the chain below applies. **Every step is
Tier-2 (outbound to a third party) → prepared here, but the button is Anton's.**

1. **Identify the vendor & channel.** Look for `security.txt` (`/.well-known/security.txt`),
   a `SECURITY.md`, a Vulnerability Disclosure Program (VDP), or a bug-bounty page
   (HackerOne/Bugcrowd/GitHub Security Advisories).
2. **Private report first.** Minimal reproducer, impact, affected version, our contact.
   Never a public issue, never a public PoC, before coordination.
3. **Coordinated window.** Standard **90 days** (or the vendor's stated window) before any
   public write-up; extend if they are actively fixing.
4. **Request a CVE** via the vendor's CNA or MITRE if they don't assign one.
5. **Credit the maintainer**, offer to verify the fix, publish the write-up only after the
   window closes or a patch ships.
6. **Never** weaponize: no exploit against live third-party systems, no scanning others'
   instances, no data exfiltration from anyone real.

## Live-LLM leg (labeled TODO — NOT run in this build)

A stronger demo puts a **real frontier model** in the loop to show it genuinely obeys the
poisoned description on some fraction of runs. Not run here because:
- the local `claude -p` path is blocked by our own blackbox-session guard (canon §9.2), and
- this scheduled session has no mandate to spawn sub-agents.

Anton can run it interactively: feed the poisoned manifest to any agent harness (Claude /
GPT / open model) as its tool list, ask a benign task, and log whether the plan calls the
outbound tool with the secret. Whatever the result — **report it truthfully**; partial model
resistance is itself a finding (*don't rely on the model; the leash catches the rest*).
