"""Package directory service.

Owns the *delivery manifest* (what the source says should exist): expected
package sequence numbers + versions, the records declared for delivery and the
mapping telling which package carries each segment of a record (the source of
truth for "cross-package position"). From that plus the receiver's tables it
computes package gaps, per-record gaps and replacement expectations.

Manifest files are JSON, applied in filename order from ``data/delivery/``::

    {
      "version": 1,
      "packages": [{"seq": 0, "version": 1}, ...],
      "records": [{
        "tenant_id": "t-a", "record_id": "r-0",
        "seg_total": 3, "record_len": 1234, "record_sha": "<hex>",
        "segments": [{"seg_index": 0, "seq": 0}, {"seg_index": 1, "seq": 1}]
      }]
    }

A manifest with ``"version": 2`` and ``replaces`` bumps the expected version
for one sequence; rows of the old delivery for that sequence are re-pointed.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from .storage import Storage, validate_safe_name

MANIFEST_STATE_PENDING = "PENDING"
MANIFEST_STATE_RECEIVED = "RECEIVED"
MANIFEST_STATE_QUARANTINED = "QUARANTINED"
MANIFEST_STATE_SUPERSEDED = "SUPERSEDED"


class ManifestError(ValueError):
    pass


class PackageDirectoryService:
    def __init__(self, storage: Storage):
        self.s = storage

    # ------------------------------------------------------------------ #
    # Manifest application
    # ------------------------------------------------------------------ #
    def apply_manifest_file(self, path: str | Path) -> dict[str, Any]:
        path = Path(path)
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ManifestError("cannot read manifest %s: %s" % (path.name, exc)) from None
        return self.apply_manifest(doc, source=path.name)

    def apply_manifest(self, doc: dict[str, Any], *, source: str = "<upload>") -> dict[str, Any]:
        if not isinstance(doc, dict) or doc.get("version") not in (1, 2):
            raise ManifestError("manifest.version must be 1 or 2")
        packages = doc.get("packages", [])
        records = doc.get("records", [])
        if doc["version"] == 1:
            if not isinstance(packages, list) or not packages:
                raise ManifestError("v1 manifest needs a non-empty packages list")
            return self._apply_v1(packages, records, source)
        replaces = doc.get("replaces")
        if (not isinstance(replaces, dict) or not isinstance(replaces.get("seq"), int)
                or not isinstance(replaces.get("new_version"), int)):
            raise ManifestError("v2 manifest needs replaces.{seq,new_version}")
        return self._apply_v2(replaces, packages, records, source)

    def _apply_v1(self, packages: list[dict[str, Any]],
                  records: list[dict[str, Any]], source: str) -> dict[str, Any]:
        seen: set[int] = set()
        now = time.time()
        n_rec = 0
        with self.s.tx() as conn:
            for pkg in packages:
                seq, ver = int(pkg["seq"]), int(pkg["version"])
                if seq < 0 or ver < 1 or seq in seen:
                    raise ManifestError("bad/duplicate package entry %r" % pkg)
                seen.add(seq)
                row = conn.execute(
                    "SELECT expected_version FROM manifest_packages WHERE seq=?", (seq,)
                ).fetchone()
                if row is None:
                    conn.execute(
                        "INSERT INTO manifest_packages(seq, expected_version, state, updated_at)"
                        " VALUES (?,?,?,?)",
                        (seq, ver, MANIFEST_STATE_PENDING, now),
                    )
                elif ver > row["expected_version"]:
                    conn.execute(
                        "UPDATE manifest_packages SET expected_version=?, state=?, updated_at=?"
                        " WHERE seq=?", (ver, MANIFEST_STATE_PENDING, now, seq),
                    )
            n_rec = self._upsert_records(conn, records)
            conn.execute(
                "INSERT INTO events(ts,kind,tenant_id,record_id,seq,detail)"
                " VALUES (?,?,?,?,?,?)",
                (now, "MANIFEST_APPLIED", None, None, None,
                 "%s: %d packages, %d records" % (source, len(seen), n_rec)),
            )
        return {"applied": source, "packages": len(seen), "records": n_rec}

    def _apply_v2(self, replaces: dict[str, Any], packages: list[dict[str, Any]],
                  records: list[dict[str, Any]], source: str) -> dict[str, Any]:
        seq, new_ver = int(replaces["seq"]), int(replaces["new_version"])
        now = time.time()
        with self.s.tx() as conn:
            row = conn.execute(
                "SELECT expected_version FROM manifest_packages WHERE seq=?", (seq,)
            ).fetchone()
            if row is None:
                raise ManifestError("cannot replace unknown package seq=%d" % seq)
            old_ver = row["expected_version"]
            if new_ver <= old_ver:
                raise ManifestError(
                    "new_version %d must exceed current expected version %d"
                    % (new_ver, old_ver),
                )
            # Old delivery rows for this seq become historical; re-point map at
            # the new (not-yet-arrived) version so gaps show immediately.
            conn.execute(
                "UPDATE manifest_segment_map SET version=? WHERE seq=? AND version=?",
                (new_ver, seq, old_ver),
            )
            conn.execute(
                "UPDATE manifest_packages SET expected_version=?, state=?, updated_at=?"
                " WHERE seq=?", (new_ver, MANIFEST_STATE_PENDING, now, seq),
            )
            n_rec = self._upsert_records(conn, records)
            conn.execute(
                "INSERT INTO events(ts,kind,tenant_id,record_id,seq,detail)"
                " VALUES (?,?,?,?,?,?)",
                (now, "MANIFEST_REPLACE", None, None, seq,
                 "%s: seq=%d v%d -> v%d, %d record specs"
                 % (source, seq, old_ver, new_ver, n_rec)),
            )
        return {"applied": source, "replaced_seq": seq,
                "old_version": old_ver, "new_version": new_ver, "records": n_rec}

    def _upsert_records(self, conn, records: list[dict[str, Any]]) -> int:
        now = time.time()
        for rec in records:
            tenant = rec["tenant_id"]
            rid = rec["record_id"]
            validate_safe_name(tenant)
            validate_safe_name(rid)
            seg_total = int(rec["seg_total"])
            record_len = int(rec["record_len"])
            rsha = str(rec["record_sha"]).lower()
            if seg_total < 1 or record_len < 1 or len(rsha) != 64:
                raise ManifestError("bad record spec %r" % rec)
            conn.execute(
                "INSERT INTO manifest_records(tenant_id, record_id, seg_total,"
                " record_len, record_sha) VALUES (?,?,?,?,?)"
                " ON CONFLICT(tenant_id,record_id) DO UPDATE SET"
                " seg_total=excluded.seg_total, record_len=excluded.record_len,"
                " record_sha=excluded.record_sha",
                (tenant, rid, seg_total, record_len, rsha),
            )
            idx_seen: set[int] = set()
            for m in rec.get("segments", []):
                idx, mseq = int(m["seg_index"]), int(m["seq"])
                if not 0 <= idx < seg_total or idx in idx_seen:
                    raise ManifestError("bad segment map for %s/%s: %r" % (tenant, rid, m))
                idx_seen.add(idx)
                conn.execute(
                    "INSERT INTO manifest_segment_map(tenant_id, record_id, seg_index,"
                    " seq, version) VALUES (?,?,?,?,?)"
                    " ON CONFLICT(tenant_id,record_id,seg_index) DO UPDATE SET"
                    " seq=excluded.seq, version=excluded.version",
                    (tenant, rid, idx, mseq,
                     int(m.get("version", 1))),
                )
            if len(idx_seen) != seg_total:
                raise ManifestError(
                    "manifest record %s/%s declares %d segments but maps %d"
                    % (tenant, rid, seg_total, len(idx_seen)),
                )
            conn.execute(
                "INSERT INTO records(tenant_id, record_id, seg_total, record_len,"
                " record_sha, status, first_seen_at, updated_at)"
                " VALUES (?,?,?,?,?,?,?,?)"
                " ON CONFLICT(tenant_id,record_id) DO UPDATE SET"
                " seg_total=excluded.seg_total, record_len=excluded.record_len,"
                " record_sha=excluded.record_sha, updated_at=excluded.updated_at",
                (tenant, rid, seg_total, record_len, rsha, "ASSEMBLING", now, now),
            )
        return len(records)

    # ------------------------------------------------------------------ #
    # Directory views
    # ------------------------------------------------------------------ #
    def package_directory(self) -> list[dict[str, Any]]:
        """One row per expected sequence: expected vs. actually received.

        Multiple package rows may exist for one seq (failed quarantine attempts
        plus a good delivery); the row chosen is the one matching the expected
        version when present, otherwise the highest version received.
        """
        rows = self.s.query(
            "WITH ranked AS ("
            " SELECT m.seq AS seq, m.expected_version AS expected_version,"
            " m.state AS manifest_state, m.updated_at AS updated_at,"
            " p.version AS got_version, p.state AS pkg_state,"
            " p.quarantine_reason AS quarantine_reason, p.seg_count AS seg_count,"
            " ROW_NUMBER() OVER ("
            "   PARTITION BY m.seq"
            "   ORDER BY CASE WHEN p.version = m.expected_version THEN 0 ELSE 1 END,"
            "            p.version DESC) AS rn"
            " FROM manifest_packages m"
            " LEFT JOIN packages p ON p.seq = m.seq)"
            " SELECT seq, expected_version, manifest_state, updated_at,"
            " got_version, pkg_state, quarantine_reason, seg_count"
            " FROM ranked WHERE rn = 1 ORDER BY seq"
        )
        out: list[dict[str, Any]] = []
        for r in rows:
            d = dict(r)
            if r["pkg_state"] is None:
                d["status"] = "MISSING"
            elif r["pkg_state"] == "QUARANTINED":
                d["status"] = "QUARANTINED"
            elif r["got_version"] != r["expected_version"]:
                d["status"] = "SUPERSEDED_AWAITING_REPLACEMENT"
            else:
                d["status"] = "OK"
            out.append(d)
        return out

    def package_gaps(self) -> list[int]:
        """Sequences inside the declared range with no package arrival at all.

        A quarantined arrival is *not* a gap: it is present-but-bad and shown
        with its quarantine reason. Only a missing row means a real gap.
        """
        rows = self.package_directory()
        if not rows:
            return []
        lo, hi = rows[0]["seq"], rows[-1]["seq"]
        arrived = {r["seq"] for r in rows if r["pkg_state"] is not None}
        return [s for s in range(lo, hi + 1) if s not in arrived]

    def record_cross_positions(self) -> list[dict[str, Any]]:
        """Per-record view: expected segment map vs. received segments."""
        out: list[dict[str, Any]] = []
        recs = self.s.query(
            "SELECT tenant_id, record_id, seg_total, record_len, record_sha"
            " FROM manifest_records ORDER BY tenant_id, record_id"
        )
        for rec in recs:
            key = (rec["tenant_id"], rec["record_id"])
            maps = {
                r["seg_index"]: dict(r)
                for r in self.s.query(
                    "SELECT seg_index, seq, version FROM manifest_segment_map"
                    " WHERE tenant_id=? AND record_id=? ORDER BY seg_index", key)
            }
            segs = {
                r["seg_index"]: dict(r)
                for r in self.s.query(
                    "SELECT seg_index, seq, pkg_version, state, payload_len, payload_crc"
                    " FROM segments WHERE tenant_id=? AND record_id=? ORDER BY seg_index",
                    key)
            }
            positions = []
            missing_indexes: list[int] = []
            bad_indexes: list[int] = []
            for idx in range(rec["seg_total"]):
                m = maps.get(idx)
                sg = segs.get(idx)
                if m is None:
                    continue
                if sg is None:
                    missing_indexes.append(idx)
                    positions.append({"seg_index": idx, "expected_seq": m["seq"],
                                      "expected_version": m["version"], "state": "MISSING"})
                else:
                    if sg["state"] == "BAD":
                        bad_indexes.append(idx)
                    positions.append({
                        "seg_index": idx, "expected_seq": m["seq"],
                        "expected_version": m["version"], "state": sg["state"],
                        "got_seq": sg["seq"], "got_version": sg["pkg_version"],
                        "payload_len": sg["payload_len"], "payload_crc": sg["payload_crc"],
                    })
            rrow = self.s.query_one(
                "SELECT status, quarantine_reason FROM records"
                " WHERE tenant_id=? AND record_id=?", key)
            out.append({
                "tenant_id": rec["tenant_id"], "record_id": rec["record_id"],
                "seg_total": rec["seg_total"], "record_len": rec["record_len"],
                "record_sha": rec["record_sha"],
                "assembly_status": rrow["status"] if rrow else "UNKNOWN",
                "quarantine_reason": rrow["quarantine_reason"] if rrow else None,
                "missing_segments": missing_indexes, "bad_segments": bad_indexes,
                "spans_packages": sorted({m["seq"] for m in maps.values()}),
                "positions": positions,
            })
        return out

    def expected_version(self, seq: int) -> int | None:
        row = self.s.query_one(
            "SELECT expected_version FROM manifest_packages WHERE seq=?", (seq,))
        return None if row is None else row["expected_version"]

    def mark_manifest_state(self, seq: int, state: str) -> None:
        with self.s.tx() as conn:
            conn.execute(
                "UPDATE manifest_packages SET state=?, updated_at=? WHERE seq=?",
                (state, time.time(), seq),
            )
