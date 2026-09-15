"""
node_kill_test.py -- kill a node mid-run and see whether the evidence survives.

    python replay/node_kill_test.py

Not a simulated crash: it starts a real child process, lets it authorize a few
hundred actions, and SIGKILLs it (TerminateProcess on Windows) with no chance to
clean up, flush or close anything. Then it checks the two things an incident
review actually needs:

  1. the hash chain still verifies end to end -- no half-written record, no gap
  2. every side-effect that happened has a journal record explaining it

Exit 0 = both held.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from audit_log import AuditLog  # noqa: E402


def main():
    workdir = tempfile.mkdtemp(prefix="leash-kill-")
    audit = os.path.join(workdir, "audit.jsonl")
    effects = os.path.join(workdir, "effects.jsonl")
    try:
        print("starting a node, letting it work, then killing it with no warning")
        proc = subprocess.Popen([sys.executable, os.path.join(HERE, "node_worker.py"), audit, effects])

        # let it get properly underway
        deadline = time.time() + 15
        while time.time() < deadline:
            if os.path.exists(audit) and len(AuditLog.read(audit)) >= 200:
                break
            time.sleep(0.05)

        proc.kill()          # SIGKILL / TerminateProcess -- no handlers, no flush
        proc.wait(timeout=10)
        print("  node killed (returncode %s), no graceful shutdown" % proc.returncode)

        records = AuditLog.read(audit)
        effect_ids = set()
        if os.path.exists(effects):
            with open(effects, encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if line:
                        effect_ids.add(json.loads(line)["request_id"])

        ok_chain, n, problem = AuditLog.verify(audit)
        journalled = {r["payload"]["decision"]["request_id"] for r in records}
        unexplained = effect_ids - journalled
        decided_but_not_done = len(journalled) - len(effect_ids)

        print("\n  journal records        : %d" % len(records))
        print("  side-effects performed : %d" % len(effect_ids))
        print("  chain verifies         : %s%s" % (ok_chain, "" if ok_chain else " -- %s" % problem))
        print("  effects with no journal record: %d" % len(unexplained))
        print("  decisions whose effect never ran (safe direction): %d" % decided_but_not_done)

        checks = [
            ("the node really was killed, not stopped politely", proc.returncode not in (0, None)),
            ("it got far enough to be a real test (>=200 decisions)", len(records) >= 200),
            ("hash chain verifies after the kill", ok_chain),
            ("no half-written or missing record in the middle", problem is None),
            ("every side-effect has a journal record explaining it", not unexplained),
            ("the only gap is decisions whose effect never ran", decided_but_not_done >= 0),
        ]
        print()
        failed = 0
        for label, ok in checks:
            print("  [%s] %s" % ("PASS" if ok else "FAIL", label))
            failed += 0 if ok else 1
        print("\n%s" % ("EVIDENCE SURVIVED THE KILL" if not failed else "FAILED: %d check(s)" % failed))
        return 1 if failed else 0
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
