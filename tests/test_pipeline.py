"""Unit tests for wire formats, receiver isolation and assembler semantics.

Run:  python3 -I -m unittest discover -s tests -v
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import formats  # noqa: E402
from app.assembler import RecordAssembler  # noqa: E402
from app.directory import PackageDirectoryService  # noqa: E402
from app.receiver import SegmentReceiver  # noqa: E402
from app.storage import Storage  # noqa: E402


def make_manifest(seqs, records_spec):
    return {
        "version": 1,
        "packages": [{"seq": s, "version": 1} for s in seqs],
        "records": records_spec,
    }


def record_spec(tenant, rid, seg_total, record_len, sha, seq_per_index):
    return {
        "tenant_id": tenant, "record_id": rid, "seg_total": seg_total,
        "record_len": record_len, "record_sha": sha,
        "segments": [{"seg_index": i, "seq": s}
                     for i, s in enumerate(seq_per_index)],
    }


class FormatTests(unittest.TestCase):
    def test_roundtrip_segment_and_package(self):
        payload = bytes(range(256)) * 4
        seg = formats.encode_segment(
            tenant_id="t1", record_id="r1", seg_index=0, seg_total=1,
            record_len=len(payload), record_sha=formats.sha256_hex(payload),
            payload=payload)
        pkg = formats.encode_package(7, 1, 123, [seg])
        decoded = formats.decode_package(pkg)
        self.assertEqual(decoded["seq"], 7)
        self.assertEqual(decoded["segments"][0]["payload"], payload)
        self.assertTrue(decoded["segments"][0]["crc_ok"])

    def test_package_crc_detects_flip(self):
        seg = formats.encode_segment(
            tenant_id="t", record_id="r", seg_index=0, seg_total=1,
            record_len=4, record_sha=formats.sha256_hex(b"abcd"),
            payload=b"abcd")
        pkg = bytearray(formats.encode_package(1, 1, 1, [seg]))
        pkg[-1] ^= 0x01
        with self.assertRaises(formats.FormatError):
            formats.decode_package(bytes(pkg))

    def test_segment_crc_reported_not_raised(self):
        seg = bytearray(formats.encode_segment(
            tenant_id="t", record_id="r", seg_index=0, seg_total=1,
            record_len=4, record_sha=formats.sha256_hex(b"abcd"),
            payload=b"abcd"))
        seg[-1] ^= 0x01
        pkg = formats.encode_package(1, 1, 1, [bytes(seg)])
        decoded = formats.decode_package(pkg)  # package CRC recomputed, parses
        self.assertFalse(decoded["segments"][0]["crc_ok"])

    def test_trailing_garbage_rejected(self):
        seg = formats.encode_segment(
            tenant_id="t", record_id="r", seg_index=0, seg_total=1,
            record_len=1, record_sha=formats.sha256_hex(b"x"), payload=b"x")
        pkg = formats.encode_package(1, 1, 1, [seg]) + b"junk"
        with self.assertRaises(formats.FormatError):
            formats.decode_package(pkg)

    def test_record_container_roundtrip_and_tamper(self):
        blob = formats.encode_record_file("t", "r", b"hello world")
        self.assertEqual(formats.decode_record_file(blob)["payload"], b"hello world")
        tampered = bytearray(blob)
        tampered[-1] ^= 0x01
        with self.assertRaises(formats.FormatError):
            formats.decode_record_file(bytes(tampered))


class PipelineTestBase(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="pdp-test-"))
        self.data = self.tmp / "data"
        self.data.mkdir()
        self.s = Storage(self.data)
        self.d = PackageDirectoryService(self.s)
        self.rx = SegmentReceiver(self.s, self.d)
        self.asm = RecordAssembler(self.s)

    def tearDown(self):
        self.s.close()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def deliver(self, blob: bytes, name: str = "in.pdpkg"):
        path = self.s.inbox / name
        path.write_bytes(blob)
        result = self.rx.ingest_file(path)
        for tenant, rid in result.affected_records:
            self.asm.reevaluate(tenant, rid)
        return result

    def status(self, tenant, rid):
        row = self.s.query_one(
            "SELECT status, quarantine_reason FROM records"
            " WHERE tenant_id=? AND record_id=?", (tenant, rid))
        return None if row is None else dict(row)


class IsolationTests(PipelineTestBase):
    def _two_tenant_packages(self):
        # tenant A record split across pkg 0/1; tenant B wholly in pkg 1
        a = b"A-record-payload-" * 20
        b = b"B-record-payload!" * 10
        a_sha = formats.sha256_hex(a)
        b_sha = formats.sha256_hex(b)
        half = len(a) // 2
        a0 = formats.encode_segment(tenant_id="ta", record_id="ra", seg_index=0,
                                    seg_total=2, record_len=len(a),
                                    record_sha=a_sha, payload=a[:half])
        a1 = formats.encode_segment(tenant_id="ta", record_id="ra", seg_index=1,
                                    seg_total=2, record_len=len(a),
                                    record_sha=a_sha, payload=a[half:])
        b0 = formats.encode_segment(tenant_id="tb", record_id="rb", seg_index=0,
                                    seg_total=1, record_len=len(b),
                                    record_sha=b_sha, payload=b)
        pkg0 = formats.encode_package(0, 1, 1, [a0])
        pkg1 = formats.encode_package(1, 1, 2, [a1, b0])
        manifest = make_manifest([0, 1], [
            record_spec("ta", "ra", 2, len(a), a_sha, [0, 1]),
            record_spec("tb", "rb", 1, len(b), b_sha, [1]),
        ])
        return pkg0, pkg1, (a, b)

    def test_missing_middle_package_blocks_dependent_record_only(self):
        pkg0, pkg1, (a, b) = self._two_tenant_packages()
        self.d.apply_manifest(make_manifest([0, 1], [
            record_spec("ta", "ra", 2, len(a), formats.sha256_hex(a), [0, 1]),
            record_spec("tb", "rb", 1, len(b), formats.sha256_hex(b), [1]),
        ]))
        self.deliver(pkg0, "p0.pdpkg")
        self.assertEqual(self.status("ta", "ra")["status"], "ASSEMBLING")
        self.assertEqual(self.d.package_gaps(), [1])

    def test_bad_segment_isolates_one_record_not_tenant_behind_it(self):
        pkg0, pkg1, (a, b) = self._two_tenant_packages()
        self.d.apply_manifest(make_manifest([0, 1], [
            record_spec("ta", "ra", 2, len(a), formats.sha256_hex(a), [0, 1]),
            record_spec("tb", "rb", 1, len(b), formats.sha256_hex(b), [1]),
        ]))
        self.deliver(pkg0, "p0.pdpkg")
        # Damage B's segment inside its sealed block (stale segment CRC),
        # recomputing only the package CRC so the container stays valid.
        decoded = formats.decode_package(pkg1)
        target = next(x for x in decoded["segments"] if x["tenant_id"] == "tb")
        rebuilt_blocks = []
        for x in decoded["segments"]:
            block = formats.encode_segment(
                tenant_id=x["tenant_id"], record_id=x["record_id"],
                seg_index=x["seg_index"], seg_total=x["seg_total"],
                record_len=x["record_len"], record_sha=x["record_sha"],
                payload=x["payload"])
            if x is target:
                tampered = bytearray(block)
                tampered[-1] ^= 0xFF       # payload byte; header CRC left stale
                block = bytes(tampered)
            rebuilt_blocks.append(block)
        rebuilt = formats.encode_package(1, 1, 2, rebuilt_blocks)
        self.deliver(rebuilt, "p1-bad.pdpkg")
        self.assertEqual(self.status("tb", "rb")["status"], "QUARANTINED")
        self.assertIn("corrupt segment", self.status("tb", "rb")["quarantine_reason"])
        # A is fully present and must still publish.
        self.assertEqual(self.status("ta", "ra")["status"], "PUBLISHED")

    def test_corrupt_package_extracts_nothing(self):
        _pkg0, pkg1, _ = self._two_tenant_packages()
        self.d.apply_manifest(make_manifest([0, 1], []))
        bad = bytearray(pkg1)
        bad[20] ^= 0x01
        result = self.deliver(bytes(bad), "corrupt.pdpkg")
        self.assertEqual(result.outcome, "QUARANTINED")
        self.assertEqual(self.s.query("SELECT COUNT(*) c FROM segments")[0]["c"], 0)

    def test_unsafe_identifier_quarantines_package(self):
        evil = formats.encode_segment(
            tenant_id="../escape", record_id="r", seg_index=0, seg_total=1,
            record_len=1, record_sha=formats.sha256_hex(b"x"), payload=b"x")
        pkg = formats.encode_package(0, 1, 1, [evil])
        self.d.apply_manifest(make_manifest([0], []))
        result = self.deliver(pkg, "evil.pdpkg")
        self.assertEqual(result.outcome, "QUARANTINED")
        self.assertIn("unsafe identifier", result.reason)
        self.assertEqual(self.s.query("SELECT COUNT(*) c FROM segments")[0]["c"], 0)

    def test_repair_delivery_republishes_quarantined_record_once(self):
        pkg0, pkg1, (a, b) = self._two_tenant_packages()
        self.d.apply_manifest(make_manifest([0, 1], [
            record_spec("ta", "ra", 2, len(a), formats.sha256_hex(a), [0, 1]),
            record_spec("tb", "rb", 1, len(b), formats.sha256_hex(b), [1]),
        ]))
        self.deliver(pkg0, "p0.pdpkg")
        self.deliver(pkg1, "p1.pdpkg")
        self.assertEqual(self.status("tb", "rb")["status"], "PUBLISHED")
        # Re-deliver identical bytes -> duplicate, no new publish event.
        publishes_before = self.s.query(
            "SELECT COUNT(*) c FROM events WHERE kind='REC_PUBLISH'")[0]["c"]
        again = self.deliver(pkg1, "p1-redeliver.pdpkg")
        self.assertEqual(again.outcome, "DUPLICATE")
        publishes_after = self.s.query(
            "SELECT COUNT(*) c FROM events WHERE kind='REC_PUBLISH'")[0]["c"]
        self.assertEqual(publishes_before, publishes_after)


class IncrementalAndRecoveryTests(PipelineTestBase):
    def test_only_affected_records_reevaluated_and_recovery_skips_published(self):
        payload = b"split-me-please" * 8
        sha = formats.sha256_hex(payload)
        half = len(payload) // 2
        s0 = formats.encode_segment(tenant_id="t", record_id="r", seg_index=0,
                                    seg_total=2, record_len=len(payload),
                                    record_sha=sha, payload=payload[:half])
        s1 = formats.encode_segment(tenant_id="t", record_id="r", seg_index=1,
                                    seg_total=2, record_len=len(payload),
                                    record_sha=sha, payload=payload[half:])
        other = b"standalone"
        s_other = formats.encode_segment(tenant_id="t", record_id="r2", seg_index=0,
                                         seg_total=1, record_len=len(other),
                                         record_sha=formats.sha256_hex(other),
                                         payload=other)
        self.d.apply_manifest(make_manifest([0, 1], [
            record_spec("t", "r", 2, len(payload), sha, [0, 1]),
            record_spec("t", "r2", 1, len(other), formats.sha256_hex(other), [1]),
        ]))
        self.deliver(formats.encode_package(0, 1, 1, [s0]), "p0.pdpkg")
        self.deliver(formats.encode_package(1, 1, 2, [s1, s_other]), "p1.pdpkg")
        self.assertEqual(self.status("t", "r")["status"], "PUBLISHED")
        self.assertEqual(self.status("t", "r2")["status"], "PUBLISHED")

        # Simulate a fresh process: new Storage/assembler over the same data.
        s2 = Storage(self.data)
        try:
            asm2 = RecordAssembler(s2)
            outcomes = asm2.reevaluate_pending()
            self.assertEqual(outcomes, [])  # nothing pending; no re-publish
            publishes = s2.query(
                "SELECT COUNT(*) c FROM events WHERE kind='REC_PUBLISH'")[0]["c"]
            self.assertEqual(publishes, 2)
        finally:
            s2.close()

    def test_replacement_same_bytes_does_not_republish(self):
        payload = b"replacement-target" * 4
        sha = formats.sha256_hex(payload)
        half = len(payload) // 2
        v1_segs = [
            formats.encode_segment(tenant_id="t", record_id="r", seg_index=0,
                                   seg_total=2, record_len=len(payload),
                                   record_sha=sha, payload=payload[:half]),
            formats.encode_segment(tenant_id="t", record_id="r", seg_index=1,
                                   seg_total=2, record_len=len(payload),
                                   record_sha=sha, payload=payload[half:]),
        ]
        self.d.apply_manifest(make_manifest([0], [
            record_spec("t", "r", 2, len(payload), sha, [0, 0])]))
        self.deliver(formats.encode_package(0, 1, 1, v1_segs), "v1.pdpkg")
        self.assertEqual(self.status("t", "r")["status"], "PUBLISHED")

        # v2 re-cuts into different slices, identical assembled bytes.
        third = len(payload) // 3
        sizes = [third, third, len(payload) - 2 * third]
        v2_segs = []
        offset = 0
        for i, size in enumerate(sizes):
            v2_segs.append(formats.encode_segment(
                tenant_id="t", record_id="r", seg_index=i,
                seg_total=len(sizes), record_len=len(payload),
                record_sha=sha, payload=payload[offset:offset + size]))
            offset += size
        self.d.apply_manifest({
            "version": 2,
            "replaces": {"seq": 0, "new_version": 2},
            "packages": [{"seq": 0, "version": 2}],
            "records": [record_spec("t", "r", len(sizes), len(payload), sha,
                                    [0] * len(sizes))],
        })
        result = self.deliver(formats.encode_package(0, 2, 2, v2_segs), "v2.pdpkg")
        self.assertEqual(result.outcome, "REPLACED")
        self.assertEqual(self.status("t", "r")["status"], "PUBLISHED")
        self.assertEqual(self.s.query(
            "SELECT COUNT(*) c FROM events WHERE kind='REC_REPUBLISH'")[0]["c"], 0)
        # Superseded package archived.
        self.assertTrue(list((self.s.quarantine).glob("*superseded*")))


if __name__ == "__main__":
    unittest.main(verbosity=2)
