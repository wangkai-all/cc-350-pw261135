"""Record assembler / publisher.

Only a *complete* record is published:

* every expected segment ordinal is present
* no segment is in BAD state
* segment headers agree (seg_total / record_len / record_sha)
* the streamed concatenation reproduces the declared byte length and SHA-256

Isolation is per record (and therefore per tenant): a failure while evaluating
one record is recorded as that record's quarantine reason and never propagates
to the next record, so one tenant's bad segment cannot halt the pipeline for
everyone behind it.

Re-evaluation is incremental: the worker only passes the records touched by the
package that just arrived. Already-published records are skipped entirely; a
reassembled record whose SHA-256 is unchanged is not published again, which
makes replacement delivery idempotent for unaffected neighbour content.
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass
from pathlib import Path

from . import formats
from .storage import Storage

PUBLISH_CHUNK = 1024 * 1024


@dataclass
class AssemblyOutcome:
    tenant_id: str
    record_id: str
    status: str                       # PUBLISHED|REPUBLISHED|UNCHANGED|ASSEMBLING|QUARANTINED
    reason: str | None = None
    record_sha: str | None = None
    record_len: int | None = None


class RecordAssembler:
    def __init__(self, storage: Storage):
        self.s = storage

    def reevaluate(self, tenant_id: str, record_id: str) -> AssemblyOutcome:
        try:
            return self._evaluate(tenant_id, record_id)
        except Exception as exc:  # isolation boundary: never kill the worker
            reason = "assembler internal error: %s" % exc
            with self.s.tx() as conn:
                conn.execute(
                    "UPDATE records SET status='QUARANTINED', quarantine_reason=?,"
                    " updated_at=? WHERE tenant_id=? AND record_id=?",
                    (reason, time.time(), tenant_id, record_id))
                conn.execute(
                    "INSERT INTO events(ts,kind,tenant_id,record_id,seq,detail)"
                    " VALUES (?,?,?,?,?,?)",
                    (time.time(), "REC_QUARANTINE", tenant_id, record_id, None, reason))
            return AssemblyOutcome(tenant_id, record_id, "QUARANTINED", reason)

    # ------------------------------------------------------------------ #
    def _evaluate(self, tenant_id: str, record_id: str) -> AssemblyOutcome:
        rec = self.s.query_one(
            "SELECT * FROM records WHERE tenant_id=? AND record_id=?",
            (tenant_id, record_id))
        if rec is None:
            return AssemblyOutcome(tenant_id, record_id, "ASSEMBLING",
                                   "record not registered yet")
        if rec["status"] == "PUBLISHED":
            # Fast path: nothing can invalidate a published record except an
            # explicit replacement that reset its status in the receiver.
            return AssemblyOutcome(tenant_id, record_id, "UNCHANGED",
                                   "already published", rec["record_sha"],
                                   rec["record_len"])

        segs = self.s.query(
            "SELECT * FROM segments WHERE tenant_id=? AND record_id=?"
            " ORDER BY seg_index", (tenant_id, record_id))

        problem = self._structural_problem(rec, segs)
        if problem is not None:
            return self._quarantine_or_wait(tenant_id, record_id, problem, segs)

        # Stream the payload slices in ordinal order; hash while copying so
        # large records never need to be fully buffered in memory.
        hasher = hashlib.sha256()
        total_len = 0
        dest_tmp = self.s.tmp / ("rec-%s-%s-%d.pdrec"
                                 % (tenant_id, record_id, time.time_ns()))
        with open(dest_tmp, "wb") as out:
            for seg in segs:
                p = self.s.root / seg["seg_file"]
                with open(p, "rb") as fh:
                    while True:
                        chunk = fh.read(PUBLISH_CHUNK)
                        if not chunk:
                            break
                        hasher.update(chunk)
                        total_len += len(chunk)
                        out.write(chunk)
        digest = hasher.hexdigest()

        if total_len != rec["record_len"]:
            dest_tmp.unlink(missing_ok=True)
            return self._mark_quarantine(
                tenant_id, record_id,
                "assembled length %d != declared %d" % (total_len, rec["record_len"]))
        if digest != rec["record_sha"]:
            dest_tmp.unlink(missing_ok=True)
            return self._mark_quarantine(
                tenant_id, record_id,
                "assembled SHA-256 %s != declared %s" % (digest, rec["record_sha"]))

        return self._publish(tenant_id, record_id, digest, total_len, dest_tmp)

    # ------------------------------------------------------------------ #
    def _structural_problem(self, rec, segs) -> str | None:
        if not segs:
            return "no segments received yet"
        bad = [s["seg_index"] for s in segs if s["state"] == "BAD"]
        if bad:
            return "corrupt segment(s) at ordinal(s) %s" % bad
        seg_total = rec["seg_total"] or segs[0]["seg_total"]
        indexes = sorted(s["seg_index"] for s in segs)
        if indexes != list(range(seg_total)):
            missing = [i for i in range(seg_total) if i not in set(indexes)]
            return "missing segment ordinal(s) %s of %d" % (missing, seg_total)
        base = segs[0]
        for s in segs:
            if (s["seg_total"], s["record_len"], s["record_sha"]) != (
                    base["seg_total"], base["record_len"], base["record_sha"]):
                return "segment headers disagree on seg_total/record_len/record_sha"
        if rec["record_sha"] and base["record_sha"] != rec["record_sha"]:
            return "segment record_sha disagrees with manifest declaration"
        if rec["record_len"] and base["record_len"] != rec["record_len"]:
            return "segment record_len disagrees with manifest declaration"
        return None

    def _quarantine_or_wait(self, tenant_id, record_id, problem, segs) -> AssemblyOutcome:
        # "Not all here yet" is a gap, not a quarantine: keep waiting.
        if problem.startswith(("no segments", "missing segment")):
            with self.s.tx() as conn:
                conn.execute(
                    "UPDATE records SET status='ASSEMBLING', quarantine_reason=NULL,"
                    " updated_at=? WHERE tenant_id=? AND record_id=?",
                    (time.time(), tenant_id, record_id))
            return AssemblyOutcome(tenant_id, record_id, "ASSEMBLING", problem)
        return self._mark_quarantine(tenant_id, record_id, problem)

    def _mark_quarantine(self, tenant_id, record_id, reason: str) -> AssemblyOutcome:
        with self.s.tx() as conn:
            conn.execute(
                "UPDATE records SET status='QUARANTINED', quarantine_reason=?,"
                " updated_at=? WHERE tenant_id=? AND record_id=?",
                (reason, time.time(), tenant_id, record_id))
            conn.execute(
                "INSERT INTO events(ts,kind,tenant_id,record_id,seq,detail)"
                " VALUES (?,?,?,?,?,?)",
                (time.time(), "REC_QUARANTINE", tenant_id, record_id, None, reason))
        return AssemblyOutcome(tenant_id, record_id, "QUARANTINED", reason)

    def _publish(self, tenant_id, record_id, digest: str, length: int,
                 staged: Path) -> AssemblyOutcome:
        final = self.s.published_path(tenant_id, record_id)
        existing = self.s.query_one(
            "SELECT sha256 FROM published WHERE tenant_id=? AND record_id=?",
            (tenant_id, record_id))
        now = time.time()
        if existing is not None and existing["sha256"] == digest:
            # Idempotent: identical bytes must never be published twice.
            staged.unlink(missing_ok=True)
            with self.s.tx() as conn:
                conn.execute(
                    "UPDATE records SET status='PUBLISHED', quarantine_reason=NULL,"
                    " updated_at=? WHERE tenant_id=? AND record_id=?",
                    (now, tenant_id, record_id))
            return AssemblyOutcome(tenant_id, record_id, "UNCHANGED",
                                   "identical content, no re-publish", digest, length)

        # Wrap the staged payload in the published-record container atomically.
        payload = staged.read_bytes()
        staged.unlink(missing_ok=True)
        container = formats.encode_record_file(tenant_id, record_id, payload)
        self.s.atomic_write(final, container)

        kind = "REC_REPUBLISH" if existing is not None else "REC_PUBLISH"
        with self.s.tx() as conn:
            conn.execute(
                "INSERT INTO published(tenant_id, record_id, sha256, record_len,"
                " file_path, published_at) VALUES (?,?,?,?,?,?)"
                " ON CONFLICT(tenant_id,record_id) DO UPDATE SET sha256=excluded.sha256,"
                " record_len=excluded.record_len, file_path=excluded.file_path,"
                " published_at=excluded.published_at",
                (tenant_id, record_id, digest, length, self.s.rel(final), now))
            conn.execute(
                "UPDATE records SET status='PUBLISHED', quarantine_reason=NULL,"
                " updated_at=? WHERE tenant_id=? AND record_id=?",
                (now, tenant_id, record_id))
            conn.execute(
                "INSERT INTO events(ts,kind,tenant_id,record_id,seq,detail)"
                " VALUES (?,?,?,?,?,?)",
                (now, kind, tenant_id, record_id, None,
                 "%s sha256=%s len=%d -> %s"
                 % (kind, digest, length, self.s.rel(final))))
        return AssemblyOutcome(tenant_id, record_id,
                               "REPUBLISHED" if existing is not None else "PUBLISHED",
                               record_sha=digest, record_len=length)

    # ------------------------------------------------------------------ #
    def reevaluate_pending(self) -> list[AssemblyOutcome]:
        """Startup recovery: evaluate every record not already published."""
        rows = self.s.query(
            "SELECT tenant_id, record_id FROM records"
            " WHERE status != 'PUBLISHED' ORDER BY tenant_id, record_id")
        return [self.reevaluate(r["tenant_id"], r["record_id"]) for r in rows]
