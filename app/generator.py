"""Sample-data generator: real byte splitting, no pre-assembled results.

The generator only ever writes *source* artefacts (delivery manifests and raw
packages). Every package is produced by splitting freshly generated record
payloads at byte offsets and re-encoding the slices with the production wire
format (``app.formats``). The assembler never reads the originals; the verifier
independently re-decodes the published ``.pdrec`` containers and compares bytes.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import random
import sys
import time
from pathlib import Path

if __package__ in (None, ""):  # executed directly under `python -I app/generator.py`
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import formats

TENANTS = ["t-alpha", "t-bravo", "t-charlie"]


def _record_bytes(tenant_id: str, record_id: str, length: int, seed: int) -> bytes:
    """Deterministic, human-recognisable, binary-safe record payload."""
    rng = random.Random(seed)
    header = ("RECORD tenant=%s id=%s len=%d seed=%d\n"
              % (tenant_id, record_id, length, seed)).encode()
    alphabet = (b"abcdefghijklmnopqrstuvwxyz ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                b"0123456789 .,!?-\n")
    body = bytes(rng.choice(alphabet) for _ in range(max(0, length - len(header))))
    blob = header + body
    return blob[:length] if len(blob) > length else blob + b"Z" * (length - len(blob))


def split_record(tenant_id: str, record_id: str, payload: bytes,
                 split_sizes: list[int]) -> list[bytes]:
    """Split *payload* into encoded segment blocks at real byte offsets."""
    total = sum(split_sizes)
    if total != len(payload):
        raise ValueError("split sizes sum %d != payload length %d"
                         % (total, len(payload)))
    digest = hashlib.sha256(payload).digest()
    blocks: list[bytes] = []
    offset = 0
    for i, size in enumerate(split_sizes):
        slice_ = payload[offset:offset + size]
        blocks.append(formats.encode_segment(
            tenant_id=tenant_id, record_id=record_id, seg_index=i,
            seg_total=len(split_sizes), record_len=len(payload),
            record_sha=digest, payload=slice_))
        offset += size
    assert offset == len(payload)
    return blocks


def build_package(seq: int, version: int, segment_blocks: list[bytes],
                  created_at: int | None = None) -> bytes:
    return formats.encode_package(
        seq, version, created_at or int(time.time()), segment_blocks)


class SampleGenerator:
    """Produces 4 ordered packages with deliberately out-of-order delivery."""

    # (tenant, record id, total payload bytes, [byte sizes of each slice])
    RECORD_SPECS = [
        ("t-alpha", "r-001", 300, [120, 90, 90]),            # spans pkgs 0,1,1
        ("t-bravo", "r-002", 512, [200, 156, 156]),          # spans pkgs 1,2
        ("t-charlie", "r-003", 175, [175]),                  # wholly in pkg 2
        ("t-alpha", "r-004", 640, [180, 180, 180, 100]),     # spans pkgs 2,3
        ("t-bravo", "r-005", 260, [130, 130]),               # wholly in pkg 3
    ]
    # package seq -> list of (record index, segment ordinal)
    PACKAGE_LAYOUT = {
        0: [(0, 0)],
        1: [(0, 1), (0, 2), (1, 0)],
        2: [(1, 1), (1, 2), (2, 0)],
        3: [(3, 0), (3, 1), (3, 2), (3, 3), (4, 0), (4, 1)],
    }
    # shuffled arrival order; seq 2 is withheld (the missing middle package)
    DELIVERY_ORDER = [3, 0, 1]

    def __init__(self, out_dir: str | Path, seed: int = 20261118):
        self.out = Path(out_dir)
        self.out.mkdir(parents=True, exist_ok=True)
        self.rng = random.Random(seed)
        self.created_at = 1_763_000_000
        self.payloads: dict[tuple[str, str], bytes] = {}

    # ------------------------------------------------------------------ #
    def generate(self) -> dict:
        """Write manifest, originals and packages; return a run description."""
        (self.out / "delivery").mkdir(exist_ok=True)
        (self.out / "packages").mkdir(exist_ok=True)
        (self.out / "originals").mkdir(exist_ok=True)

        records = self._build_records()
        manifest = self._write_manifest_v1(records)
        pkg_bytes = self._build_packages()
        for seq, blob in pkg_bytes.items():
            (self.out / "packages" / ("pkg-%08d-v01.pdpkg" % seq)).write_bytes(blob)
        # Originals: ground truth for the verifier only.
        for (tenant, rid), payload in self.payloads.items():
            (self.out / "originals" / ("%s__%s.bin" % (tenant, rid))).write_bytes(payload)
        run = {
            "delivery_order": self.DELIVERY_ORDER,
            "withheld": [2],
            "packages": {str(s): len(b) for s, b in pkg_bytes.items()},
            "records": [
                {"tenant_id": t, "record_id": r, "length": len(p),
                 "sha256": hashlib.sha256(p).hexdigest()}
                for (t, r), p in self.payloads.items()],
            "manifest": manifest,
        }
        (self.out / "sample-run.json").write_text(json.dumps(run, indent=2))
        return run

    def _build_records(self) -> list[dict]:
        records = []
        for i, (tenant, rid, length, sizes) in enumerate(self.RECORD_SPECS):
            payload = _record_bytes(tenant, rid, length, seed=1000 + i)
            self.payloads[(tenant, rid)] = payload
            positions = []
            for seq, items in self.PACKAGE_LAYOUT.items():
                for ri, ordinal in items:
                    if ri == i:
                        positions.append({"seg_index": ordinal, "seq": seq})
            records.append({
                "tenant_id": tenant, "record_id": rid,
                "seg_total": len(sizes), "record_len": length,
                "record_sha": hashlib.sha256(payload).hexdigest(),
                "segments": sorted(positions, key=lambda x: x["seg_index"]),
                "_sizes": sizes,
            })
        return records

    def _segment_locations(self):
        for seq, items in self.PACKAGE_LAYOUT.items():
            for ri, ordinal in items:
                yield ri, ordinal

    def _write_manifest_v1(self, records: list[dict]) -> dict:
        public = [{k: v for k, v in r.items() if not k.startswith("_")}
                  for r in records]
        manifest = {
            "version": 1,
            "packages": [{"seq": s, "version": 1} for s in sorted(self.PACKAGE_LAYOUT)],
            "records": public,
        }
        (self.out / "delivery" / "manifest-v1.json").write_text(
            json.dumps(manifest, indent=2))
        return manifest

    def _build_packages(self) -> dict[int, bytes]:
        blocks: dict[tuple[int, str, str, int], bytes] = {}
        for i, (tenant, rid, _length, sizes) in enumerate(self.RECORD_SPECS):
            payload = self.payloads[(tenant, rid)]
            for ordinal, block in enumerate(
                    split_record(tenant, rid, payload, sizes)):
                blocks[(i, tenant, rid, ordinal)] = block
        out = {}
        for seq, items in sorted(self.PACKAGE_LAYOUT.items()):
            pkg_segments = [blocks[(ri, *self.RECORD_SPECS[ri][:2], ordinal)]
                            for ri, ordinal in items]
            out[seq] = build_package(seq, 1, pkg_segments, self.created_at + seq)
        return out

    # ------------------------------------------------------------------ #
    # Fault injection (used by the demo) — returns path of the new file
    # ------------------------------------------------------------------ #
    def write_bad_segment_package(self, seq: int = 2, dest: Path | None = None) -> Path:
        """Damage one segment *inside its sealed block*.

        The payload byte is flipped after the segment header (including its
        CRC32) was sealed, so the segment's own CRC goes stale and the receiver
        marks exactly that segment BAD. Only the package-level CRC is
        recomputed, keeping the container structurally valid. This exercises
        the per-segment isolation path rather than the end-of-assembly SHA.
        """
        good_blob = (self.out / "packages" / ("pkg-%08d-v01.pdpkg" % seq)).read_bytes()
        pkg = formats.decode_package(good_blob)
        target = next(s for s in pkg["segments"] if s["tenant_id"] == "t-bravo")
        rebuilt_blocks: list[bytes] = []
        for s in pkg["segments"]:
            block = formats.encode_segment(
                tenant_id=s["tenant_id"], record_id=s["record_id"],
                seg_index=s["seg_index"], seg_total=s["seg_total"],
                record_len=s["record_len"], record_sha=s["record_sha"],
                payload=s["payload"])
            if s is target:
                # Flip a payload byte at the tail of the sealed block; the
                # header's payload_crc is deliberately left untouched.
                head_len = len(block) - s["payload_len"]
                tampered = bytearray(block)
                tampered[-1] ^= 0xFF
                assert head_len > 0 and bytes(tampered[head_len:]) != block[head_len:]
                block = bytes(tampered)
            rebuilt_blocks.append(block)
        blob = build_package(seq, 1, rebuilt_blocks, pkg["created_at"])
        # Sanity: package parses, but the damaged segment reports crc_ok=False.
        check = formats.decode_package(blob)
        bad = [x for x in check["segments"] if not x["crc_ok"]]
        assert len(bad) == 1 and bad[0]["record_id"] == target["record_id"]
        dest = dest or (self.out / ("pkg-%08d-v01-badsegment.pdpkg" % seq))
        dest.write_bytes(blob)
        return dest

    def write_corrupt_package(self, seq: int, dest: Path | None = None) -> Path:
        """Flip a raw byte without recomputing anything: package CRC must fail."""
        blob = bytearray((self.out / "packages"
                          / ("pkg-%08d-v01.pdpkg" % seq)).read_bytes())
        blob[-7] ^= 0xA5
        dest = dest or (self.out / ("pkg-%08d-v01-corrupt.pdpkg" % seq))
        dest.write_bytes(bytes(blob))
        return dest

    def write_replacement_package(self, seq: int = 3, dest: Path | None = None,
                                  manifest_dest: Path | None = None
                                  ) -> tuple[Path, Path]:
        """Re-cut seq 3 at v2 using different slice sizes, same record bytes.

        Identical assembled bytes -> the assembler must NOT republish; the
        manifest v2 file re-points expected delivery to the new version.
        """
        pkg = formats.decode_package(
            (self.out / "packages" / ("pkg-%08d-v01.pdpkg" % seq)).read_bytes())
        by_record: dict[tuple[str, str], list[dict]] = {}
        for s in pkg["segments"]:
            by_record.setdefault((s["tenant_id"], s["record_id"]), []).append(s)
        new_blocks: list[bytes] = []
        record_specs: list[dict] = []
        for (tenant, rid), segs in sorted(by_record.items()):
            payload = b"".join(s["payload"] for s in sorted(segs, key=lambda x: x["seg_index"]))
            # Different slicing: halves instead of the original 4/2-way split.
            half = len(payload) // 2
            sizes = [half, len(payload) - half]
            new_blocks.extend(split_record(tenant, rid, payload, sizes))
            record_specs.append({
                "tenant_id": tenant, "record_id": rid,
                "seg_total": len(sizes), "record_len": len(payload),
                "record_sha": hashlib.sha256(payload).hexdigest(),
                "segments": [{"seg_index": i, "seq": seq} for i in range(len(sizes))],
            })
        blob = build_package(seq, 2, new_blocks, self.created_at + seq + 100)
        dest = dest or (self.out / ("pkg-%08d-v02.pdpkg" % seq))
        dest.write_bytes(blob)
        manifest = {
            "version": 2,
            "replaces": {"seq": seq, "new_version": 2},
            "packages": [{"seq": seq, "version": 2}],
            "records": record_specs,
        }
        manifest_dest = manifest_dest or (self.out / "delivery" / "manifest-v2.json")
        manifest_dest.write_text(json.dumps(manifest, indent=2))
        return dest, manifest_dest


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="app.generator",
                                 description="Generate segmented sample delivery")
    ap.add_argument("--out", default="sample", help="output directory for source artefacts")
    ap.add_argument("--seed", type=int, default=20261118)
    args = ap.parse_args(argv)
    gen = SampleGenerator(args.out, seed=args.seed)
    run = gen.generate()
    print("generated %d packages, %d records under %s"
          % (len(run["packages"]), len(run["records"]),
             os.path.abspath(args.out)))
    for seq, size in sorted(run["packages"].items(), key=lambda kv: int(kv[0])):
        print("  package seq=%s: %d bytes" % (seq, size))
    return 0


if __name__ == "__main__":
    sys.exit(main())
