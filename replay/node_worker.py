"""
node_worker.py -- a fleet node that is going to be killed mid-run, on purpose.

Run by node_kill_test.py as a real child process. It authorizes actions in a loop
and, on EXECUTE, records the side-effect to a SECOND file. The two files together
let the parent check the invariant that matters after a crash:

    every side-effect that happened has a journal record explaining it

The reverse (a journal record whose side-effect never happened) is fine and
expected: we journal the decision BEFORE the executor runs, so a kill in that
window leaves a decision with no effect. That direction is safe. The other
direction -- an effect nobody can explain -- is the one that ends an incident
review with "we don't know".
"""
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from boundary import ExecutionBoundary  # noqa: E402
from fleet import World, fleet_grants   # noqa: E402


def main():
    audit_path, effects_path = sys.argv[1], sys.argv[2]
    boundary = ExecutionBoundary(fleet_grants(), audit_path)
    world = World()

    i = 0
    while True:
        rid = "worker-%04d" % i
        action = {"principal": "nightly", "tool": "read_file",
                  "resource": "/srv/nightly/run.log", "args": {}}
        decision = boundary.authorize(action, rid)
        if decision.verdict == "EXECUTE":
            world.execute(action)
            with open(effects_path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps({"request_id": rid}) + "\n")
                fh.flush()
                os.fsync(fh.fileno())
        i += 1
        time.sleep(0.004)


if __name__ == "__main__":
    main()
