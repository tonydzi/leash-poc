"""
repro.py -- the one command. Everything this repo claims, checked on your machine.

    python replay/repro.py

No arguments, no dependencies, no network, nothing to configure. Five stages, each
with its own exit code; the run is green only if all five are. If any stage is red
on your machine and not on ours, that is a finding and we want it as an issue --
that is the whole reason this is checkable instead of a slide.

Stages:
  1 replay       one poisoned instruction -> four agents -> five forbidden actions
  2 checks       19 adversarial checks on the gate
  3 mutants      break the gate six ways; the checks must go red every time
  4 node kill    SIGKILL a node mid-run; the journal must still verify
  5 siem         export the verified journal as ECS NDJSON
"""
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

STAGES = [
    ("replay    ", [sys.executable, os.path.join(HERE, "run_replay.py")]),
    ("checks    ", [sys.executable, os.path.join(HERE, "test_boundary.py")]),
    ("mutants   ", [sys.executable, os.path.join(HERE, "test_boundary.py"), "--mutants"]),
    ("node kill ", [sys.executable, os.path.join(HERE, "node_kill_test.py")]),
    ("siem      ", [sys.executable, os.path.join(HERE, "siem_export.py"),
                    "--out", os.path.join(ROOT, "logs", "evidence.ndjson")]),
]


def main():
    quiet = "--quiet" in sys.argv
    results = []
    for name, cmd in STAGES:
        print("\n===== %s =====" % name.strip())
        proc = subprocess.run(cmd, cwd=ROOT,
                              stdout=subprocess.PIPE if quiet else None,
                              stderr=subprocess.STDOUT if quiet else None)
        results.append((name, proc.returncode))

    print("\n" + "=" * 46)
    for name, rc in results:
        print("  [%s] %s (exit %d)" % ("PASS" if rc == 0 else "FAIL", name, rc))
    failed = [n for n, rc in results if rc != 0]
    print("=" * 46)
    if failed:
        print("REPRO FAILED: %s" % ", ".join(n.strip() for n in failed))
        return 1
    print("REPRO GREEN -- every claim in README.md held on this machine")
    print("evidence: logs/replay_audit.jsonl (hash-chained), logs/evidence.ndjson (ECS)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
