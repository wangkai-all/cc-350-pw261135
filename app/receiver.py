"""Segment receiver: turns inbox package files into durable segments.

Ingest pipeline for one inbox file::

    1. atomically claim the file (rename into packages/ or quarantine/)
    2. full structural decode + package-level CRC32 check
       - any failure: whole package -> QUARANTINED, no segments extracted,
         other tenants are never affected
    3. membership / version check against the package directory
       - unknown sequence, stale (older) version -> rejected/quarantined
    4. per-segment CRC32 (already verified inside decode) and cross-segment
       header consistency (seg_total / record_len / record_sha must agree)
    5. transactional metadata + payload writes; on replacement, old version's
       segments and package rows are retired first

A bad segment payload is quarantined *at the record level*: it is stored with
state=BAD and the assembler isolates only that record. One tenant's bad bytes
never block another tenant's records.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from pathlib import Path

from . import formats
from .directory import (
    MANIFEST_STATE_PENDING,
    MANIFEST_STATE_QUARANTINED,
    MANIFEST_STATE_RECEIVED,
    MANIFEST_STATE_SUPERSEDED,
    PackageDirectoryService,
)
from .storage import Storage, validate_safe_name


@dataclass
class IngestResult:
    source: str
    outcome: str                       # ACCEPTED|REPLACED|DUPLICATE|QUARANTINED|REJECTED
    seq: int | None = None
    version: int | None = None
    reason: str | None = None
    affected_records: list[tuple[str, str]] = field(default_factory=list)


class SegmentReceiver:
    def __init__(self, storage: Storage, directory: PackageDirectoryService):
        self.s = storage
        self.dir = directory

    # ------------------------------------------------------------------ #
    def scan_inbox(self) -> list[Path]:
        return sorted(
            p for p in self.s.inbox.iterdir()
            if p.is_file() and not p.name.startswith(".")
        )

    def ingest_file(self, inbox_path: str | Path) -> IngestResult:
        inbox_path = Path(inbox_path)
        raw = self._read(inbox_path)
        if isinstance(raw, IngestResult):
            self._quarantine_file(inbox_path, raw)
            return raw

        result = self._decode_and_check(inbox_path.name, raw)
        if isinstance(result, IngestResult):
            self._quarantine_file(inbox_path, result)
            return result
        pkg = result
        pkg["pkg_sha256"] = formats.sha256_hex(raw)

        expected = self.dir.expected_version(pkg["seq"])
        if expected is None:
            res = IngestResult(inbox_path.name, "REJECTED", pkg["seq"], pkg["version"],
                               "sequence %d is not declared in the delivery manifest"
                               % pkg["seq"])
            self._quarantine_file(inbox_path, res)
            return res

        existing = self.s.query_one(
            "SELECT version, state, pkg_sha256 FROM packages"
            " WHERE seq=? ORDER BY version DESC LIMIT 1", (pkg["seq"],))
        if existing is not None and existing["state"] == "RECEIVED" \
                and existing["version"] == pkg["version"] \
                and existing["pkg_sha256"] == pkg["pkg_sha256"]:
            # Byte-identical re-delivery: safe idempotent discard.
            self._discard(inbox_path)
            res = IngestResult(inbox_path.name, "DUPLICATE", pkg["seq"], pkg["version"],
                               "byte-identical package already received")
            self.s.event("PKG_DUPLICATE", res.reason, seq=pkg["seq"])
            return res
        if pkg["version"] < expected:
            res = IngestResult(inbox_path.name, "REJECTED", pkg["seq"], pkg["version"],
                               "stale version: got v%d, manifest expects v%d"
                               % (pkg["version"], expected))
            self._quarantine_file(inbox_path, res)
            return res
        # Same seq/version but different bytes (补包 after a bad delivery) is a
        # corrective re-delivery; a higher version is a formal replacement.
        is_replacement = (existing is not None
                          and existing["state"] == "RECEIVED")

        try:
            affected = self._persist_package(pkg, inbox_path,
                                             is_replacement=is_replacement)
        except Exception as exc:  # defensive: metadata/payload write failure
            res = IngestResult(inbox_path.name, "QUARANTINED", pkg["seq"], pkg["version"],
                               "persistence failure: %s" % exc)
            self._quarantine_file(inbox_path, res)
            return res

        outcome = "REPLACED" if is_replacement else "ACCEPTED"
        self.s.event(
            "PKG_" + outcome,
            "seq=%d v%d segments=%d -> %d records"
            % (pkg["seq"], pkg["version"], pkg["seg_count"], len(affected)),
            seq=pkg["seq"],
        )
        self.dir.mark_manifest_state(pkg["seq"], MANIFEST_STATE_RECEIVED)
        return IngestResult(inbox_path.name, outcome, pkg["seq"], pkg["version"],
                            affected_records=affected)

    # ------------------------------------------------------------------ #
    # Stage 1-2: read + structural/checksum validation
    # ------------------------------------------------------------------ #
    def _read(self, path: Path) -> bytes | IngestResult:
        try:
            return path.read_bytes()
        except OSError as exc:
            return IngestResult(path.name, "QUARANTINED", reason="unreadable file: %s" % exc)

    def _decode_and_check(self, name: str, raw: bytes) -> dict | IngestResult:
        try:
            pkg = formats.decode_package(raw)
        except formats.FormatError as exc:
            seq = self._peek_seq(raw)
            return IngestResult(name, "QUARANTINED", seq, reason="decode failure: %s" % exc)

        try:
            by_record: dict[tuple[str, str], list[dict]] = {}
            for seg in pkg["segments"]:
                validate_safe_name(seg["tenant_id"])
                validate_safe_name(seg["record_id"])
                by_record.setdefault(
                    (seg["tenant_id"], seg["record_id"]), []).append(seg)
            # Cross-segment header consistency for every record in this package.
            for (tenant, rid), segs in by_record.items():
                base = segs[0]
                for seg in segs:
                    if (seg["seg_total"], seg["record_len"], seg["record_sha"]) != (
                            base["seg_total"], base["record_len"], base["record_sha"]):
                        return IngestResult(
                            name, "QUARANTINED", pkg["seq"], pkg["version"],
                            "inconsistent record headers inside package for %s/%s"
                            % (tenant, rid))
                if any(not 0 <= s["seg_index"] < base["seg_total"] for s in segs):
                    return IngestResult(
                        name, "QUARANTINED", pkg["seq"], pkg["version"],
                        "segment ordinal out of range for %s/%s" % (tenant, rid))
                # Offset sanity: a slice cannot start beyond the record length.
                if base["seg_total"] > 1 and base["record_len"] < base["seg_total"]:
                    return IngestResult(
                        name, "QUARANTINED", pkg["seq"], pkg["version"],
                        "record_len smaller than segment count for %s/%s" % (tenant, rid))
        except ValueError as exc:
            return IngestResult(name, "QUARANTINED", pkg["seq"], pkg["version"],
                                "unsafe identifier in package: %s" % exc)
        return pkg

    @staticmethod
    def _peek_seq(raw: bytes) -> int | None:
        import struct
        if len(raw) >= 8 + 4 and raw[:7] == formats.PKG_MAGIC:
            return struct.unpack_from(">I", raw, 8)[0]
        return None

    # ------------------------------------------------------------------ #
    # Stage 4-5: persistence
    # ------------------------------------------------------------------ #
    def _persist_package(self, pkg: dict, inbox_path: Path, *,
                         is_replacement: bool) -> list[tuple[str, str]]:
        now = time.time()
        dest = self.s.packages / ("pkg-%08d-v%02d.pdpkg" % (pkg["seq"], pkg["version"]))
        affected: set[tuple[str, str]] = set()
        bad_records: set[tuple[str, str]] = set()

        # Payload files first (atomic, idempotent); a later DB rollback leaves
        # only orphan files that recovery sweeps, never missing payloads.
        payload_writes: list[tuple[Path, bytes]] = []
        for seg in pkg["segments"]:
            key = (seg["tenant_id"], seg["record_id"])
            affected.add(key)
            path = self.s.seg_path(seg["tenant_id"], seg["record_id"], seg["seg_index"])
            payload_writes.append((path, seg["payload"]))
        for path, data in payload_writes:
            self.s.atomic_write(path, data)

        with self.s.tx() as conn:
            if is_replacement:
                old = conn.execute(
                    "SELECT version FROM packages WHERE seq=? AND state='RECEIVED'"
                    " ORDER BY version DESC LIMIT 1", (pkg["seq"],)).fetchone()
                old_ver = old["version"] if old else None
                if old_ver is not None:
                    # Retire old segments carried by this exact package.
                    old_rows = conn.execute(
                        "SELECT tenant_id, record_id, seg_index, seg_file FROM segments"
                        " WHERE seq=? AND pkg_version=?", (pkg["seq"], old_ver)).fetchall()
                    for r in old_rows:
                        affected.add((r["tenant_id"], r["record_id"]))
                        # If the replacement package also carries this ordinal,
                        # the row will be overwritten below; otherwise delete.
                        conn.execute(
                            "DELETE FROM segments WHERE tenant_id=? AND record_id=?"
                            " AND seg_index=? AND seq=? AND pkg_version=?",
                            (r["tenant_id"], r["record_id"], r["seg_index"],
                             pkg["seq"], old_ver))
                    conn.execute(
                        "UPDATE packages SET state=?, quarantine_reason=?,"
                        " source_file=? WHERE seq=? AND version=?",
                        (MANIFEST_STATE_SUPERSEDED, "replaced by v%d" % pkg["version"],
                         self.s.rel(self.s.quarantine /
                                    ("pkg-%08d-v%02d-superseded.pdpkg"
                                     % (pkg["seq"], old_ver))),
                         pkg["seq"], old_ver))
                    # Records that lost their only segments go back to ASSEMBLING.
                    for tenant, rid in affected:
                        n = conn.execute(
                            "SELECT COUNT(*) c FROM segments"
                            " WHERE tenant_id=? AND record_id=?", (tenant, rid)).fetchone()["c"]
                        if n == 0:
                            conn.execute(
                                "UPDATE records SET status='ASSEMBLING',"
                                " quarantine_reason=NULL, updated_at=?"
                                " WHERE tenant_id=? AND record_id=?",
                                (now, tenant, rid))

            for seg in pkg["segments"]:
                key = (seg["tenant_id"], seg["record_id"])
                state = "OK"
                # Reported (not raised) by the decoder so one bad segment only
                # isolates its own record; every other tenant proceeds.
                if not seg["crc_ok"]:
                    state = "BAD"
                    bad_records.add(key)
                seg_file = self.s.seg_path(seg["tenant_id"], seg["record_id"],
                                           seg["seg_index"])
                conn.execute(
                    "INSERT INTO segments(tenant_id, record_id, seg_index, seg_total,"
                    " record_len, record_sha, payload_len, payload_crc, seq, pkg_version,"
                    " state, seg_file, received_at)"
                    " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)"
                    " ON CONFLICT(tenant_id,record_id,seg_index) DO UPDATE SET"
                    " seg_total=excluded.seg_total, record_len=excluded.record_len,"
                    " record_sha=excluded.record_sha, payload_len=excluded.payload_len,"
                    " payload_crc=excluded.payload_crc, seq=excluded.seq,"
                    " pkg_version=excluded.pkg_version, state=excluded.state,"
                    " seg_file=excluded.seg_file, received_at=excluded.received_at",
                    (seg["tenant_id"], seg["record_id"], seg["seg_index"],
                     seg["seg_total"], seg["record_len"], seg["record_sha"],
                     seg["payload_len"], seg["payload_crc"], pkg["seq"],
                     pkg["version"], state, self.s.rel(seg_file), now))
                conn.execute(
                    "INSERT INTO records(tenant_id, record_id, seg_total, record_len,"
                    " record_sha, status, first_seen_at, updated_at)"
                    " VALUES (?,?,?,?,?, 'ASSEMBLING', ?, ?)"
                    " ON CONFLICT(tenant_id,record_id) DO UPDATE SET"
                    " seg_total=excluded.seg_total, record_len=excluded.record_len,"
                    " record_sha=excluded.record_sha,"
                    " status=CASE WHEN records.status='PUBLISHED'"
                    " THEN records.status ELSE 'ASSEMBLING' END,"
                    " quarantine_reason=CASE WHEN records.status='PUBLISHED'"
                    " THEN records.quarantine_reason ELSE NULL END,"
                    " updated_at=excluded.updated_at",
                    (seg["tenant_id"], seg["record_id"], seg["seg_total"],
                     seg["record_len"], seg["record_sha"], now, now))

            conn.execute(
                "INSERT INTO packages(seq, version, state, seg_count, pkg_crc,"
                " pkg_sha256, source_file, quarantine_reason, received_at)"
                " VALUES (?,?,'RECEIVED', ?, ?, ?, ?, NULL, ?)"
                " ON CONFLICT(seq,version) DO UPDATE SET state='RECEIVED',"
                " seg_count=excluded.seg_count, pkg_crc=excluded.pkg_crc,"
                " pkg_sha256=excluded.pkg_sha256,"
                " source_file=excluded.source_file, quarantine_reason=NULL,"
                " received_at=excluded.received_at",
                (pkg["seq"], pkg["version"], pkg["seg_count"], pkg["pkg_crc"],
                 pkg["pkg_sha256"], self.s.rel(dest), now))
            for tenant, rid in bad_records:
                conn.execute(
                    "UPDATE records SET status='QUARANTINED',"
                    " quarantine_reason=?, updated_at=?"
                    " WHERE tenant_id=? AND record_id=?",
                    ("segment CRC re-check failed after staging", now, tenant, rid))
                conn.execute(
                    "INSERT INTO events(ts,kind,tenant_id,record_id,seq,detail)"
                    " VALUES (?,?,?,?,?,?)",
                    (now, "SEG_BAD", tenant, rid, pkg["seq"],
                     "bad segment payload stored for isolation"))

        # Move the claimed file into place only after the txn commits.
        os.replace(inbox_path, dest)
        if is_replacement:
            old_arc = self.s.quarantine / ("pkg-%08d-v%02d-superseded.pdpkg"
                                           % (pkg["seq"], pkg["version"] - 1))
            prior = self.s.packages / ("pkg-%08d-v%02d.pdpkg"
                                       % (pkg["seq"], pkg["version"] - 1))
            if prior.exists():
                os.replace(prior, old_arc)
        return sorted(affected)

    # ------------------------------------------------------------------ #
    def _quarantine_file(self, inbox_path: Path, result: IngestResult) -> None:
        seq_part = "seq-%s" % result.seq if result.seq is not None else "seq-unknown"
        dest = self.s.quarantine / (
            "%s-%s-%s.pdpkg" % (inbox_path.stem, seq_part, str(time.time_ns())[-6:]))
        try:
            os.replace(inbox_path, dest)
        except OSError:
            dest = inbox_path
        now = time.time()
        with self.s.tx() as conn:
            if result.seq is not None:
                conn.execute(
                    "INSERT INTO packages(seq, version, state, seg_count, pkg_crc,"
                    " source_file, quarantine_reason, received_at)"
                    " VALUES (?, ?, 'QUARANTINED', 0, 0, ?, ?, ?)"
                    " ON CONFLICT(seq,version) DO UPDATE SET state='QUARANTINED',"
                    " quarantine_reason=excluded.quarantine_reason",
                    (result.seq, result.version or 0,
                     self.s.rel(dest), result.reason, now))
                conn.execute(
                    "UPDATE manifest_packages SET state=? WHERE seq=?",
                    (MANIFEST_STATE_QUARANTINED, result.seq))
            conn.execute(
                "INSERT INTO events(ts,kind,tenant_id,record_id,seq,detail)"
                " VALUES (?,?,?,?,?,?)",
                (now, "PKG_" + result.outcome, None, None, result.seq,
                 "%s: %s" % (result.source, result.reason)))

    def _discard(self, inbox_path: Path) -> None:
        # Duplicate byte-identical delivery: keep nothing new.
        os.replace(inbox_path,
                   self.s.quarantine / ("dup-%s-%d.pdpkg"
                                        % (inbox_path.stem, time.time_ns())))
