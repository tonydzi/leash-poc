"""
audit_log.py -- append-only, hash-chained audit journal.

Why a hash chain and not "we write a log file": the claim that has to survive an
investor's engineer is not "we logged it", it is "nobody edited the log after the
fact, and nothing is missing from the middle". A chain gives you both in ~40 lines.
Each record carries the hash of the previous record, so deleting, reordering or
editing any record breaks every hash after it, and verify() names the exact index
where it broke.

Durability model (the "survives a node going down" half): every record is flushed
and fsync'd BEFORE the boundary is allowed to return its decision. If the machine
dies mid-run, the chain on disk is complete and verifiable up to the last decision
that was actually returned -- there is no window where an action got authorized but
its record was still sitting in a buffer.
"""
import hashlib
import json
import os

GENESIS = "0" * 64


def _digest(prev_hash, payload):
    """Hash of (previous hash + canonical payload). Canonical = sorted keys, no spaces."""
    blob = prev_hash + json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


class AuditLog:
    """Append-only hash-chained journal on disk. One JSON record per line."""

    def __init__(self, path):
        self.path = path
        parent = os.path.dirname(path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        self._last_hash = GENESIS
        self._count = 0
        for rec in self.read(path):
            self._last_hash = rec["hash"]
            self._count += 1

    def append(self, payload):
        """Write one record durably. fsync before returning."""
        record = {
            "seq": self._count,
            "prev": self._last_hash,
            "payload": payload,
            "hash": _digest(self._last_hash, payload),
        }
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, sort_keys=True) + "\n")
            fh.flush()
            os.fsync(fh.fileno())
        self._last_hash = record["hash"]
        self._count += 1
        return record

    @staticmethod
    def read(path):
        if not os.path.exists(path):
            return []
        out = []
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    out.append(json.loads(line))
        return out

    @staticmethod
    def verify(path):
        """Re-walk the chain. Returns (ok, count_or_index, problem_or_None)."""
        prev = GENESIS
        records = AuditLog.read(path)
        for i, rec in enumerate(records):
            if rec.get("prev") != prev:
                return False, i, "record %d: prev-hash mismatch (a record was removed or reordered)" % i
            if rec.get("hash") != _digest(prev, rec.get("payload")):
                return False, i, "record %d: payload was edited after it was written" % i
            if rec.get("seq") != i:
                return False, i, "record %d: sequence number rewritten" % i
            prev = rec["hash"]
        return True, len(records), None
