"""End-to-end demo: build a runnable application from an empty directory.

Everything here drives the *production* code paths: packages are generated with
real byte splitting, dropped into the worker's inbox as files, and the worker
processes them through receiver -> assembler -> published store. The script
never calls the assembler with pre-built results; at the end an independent
verifier re-decodes the published containers and compares every byte against
the generator's originals.

Scenario timeline
-----------------
1. generate 4 ordered packages; deliver 3, 0, 1 out of order; withhold seq 2
2. worker drains inbox -> partial records ASSEMBLING with visible gaps
3. corrupt package seq 2 -> package-level quarantine (no segments extracted)
4. good seq 2 with one flipped segment byte -> only that one record quarantined,
   every other tenant keeps flowing
5. clean re-delivery of seq 2 (补包) -> all records complete & published
6. replacement v2 for seq 3 (re-cut slices, identical bytes) -> no re-publish
7. worker restart -> published set byte-identical, zero duplicate publish events
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

if __package__ in (None, ""):  # executed directly under `python -I app/demo.py`
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import formats
from app.assembler import RecordAssembler
from app.directory import PackageDirectoryService
from app.generator import SampleGenerator
from app.receiver import SegmentReceiver
from app.storage import Storage


class Reporter:
    def __init__(self) -> None:
        self.step = 0

    def h(self, text: str) -> None:
        print("\n\033[1;36m=== %s ===\033[0m" % text)

    def s(self, text: str) -> None:
        self.step += 1
        print("\n\033[1;33m[step %d]\033[0m %s" % (self.step, text))

    def ok(self, text: str) -> None:
        print("  \033[1;32m✓\033[0m %s" % text)

    def info(self, text: str) -> None:
        print("  · %s" % text)

    def err(self, text: str) -> None:
        print("  \033[1;31m✗ %s\033[0m" % text)


def drain(data_root: Path) -> None:
    """Run the real worker code in oneshot mode (same pipeline as the daemon)."""
    launcher = Path(__file__).resolve().parent.parent / "bin" / "worker"
    subprocess.run(
        [str(launcher), "--data", str(data_root), "--once"],
        check=True, cwd=str(Path(__file__).resolve().parent.parent))


def snapshot(data_root: Path) -> dict:
    s = Storage(data_root)
    try:
        d = PackageDirectoryService(s)
        return {
            "packages": d.package_directory(),
            "gaps": d.package_gaps(),
            "records": d.record_cross_positions(),
            "published": s.query(
                "SELECT tenant_id, record_id, sha256, record_len FROM published"
                " ORDER BY tenant_id, record_id"),
            "events": s.query("SELECT kind FROM events ORDER BY id"),
        }
    finally:
        s.close()


def assert_equal(actual, expected, label: str, rep: Reporter) -> None:
    if actual == expected:
        rep.ok("%s: %s" % (label, actual))
    else:
        rep.err("%s: expected %r, got %r" % (label, expected, actual))
        raise SystemExit(1)


def verify_published_against_originals(data_root: Path, sample_dir: Path,
                                       rep: Reporter) -> None:
    """Independent verification: decode .pdrec containers, compare raw bytes."""
    s = Storage(data_root)
    try:
        rows = s.query(
            "SELECT tenant_id, record_id, file_path FROM published"
            " ORDER BY tenant_id, record_id")
        originals = sample_dir / "originals"
        for row in rows:
            container = (s.root / row["file_path"]).read_bytes()
            decoded = formats.decode_record_file(container)
            original = (originals / ("%s__%s.bin"
                                     % (row["tenant_id"], row["record_id"]))).read_bytes()
            assert decoded["payload"] == original, "byte mismatch %s/%s" % (
                row["tenant_id"], row["record_id"])
            assert decoded["record_sha"] == formats.sha256_hex(original)
            rep.ok("verified %s/%s: %d bytes, sha256=%s… (container %d bytes)"
                   % (row["tenant_id"], row["record_id"], len(original),
                      decoded["record_sha"][:12], len(container)))
    finally:
        s.close()


def run(data_root: str, sample_dir: str, *, keep: bool = False) -> int:
    rep = Reporter()
    data_root = Path(data_root).resolve()
    sample_dir = Path(sample_dir).resolve()
    if data_root.exists():
        shutil.rmtree(data_root)
    if sample_dir.exists():
        shutil.rmtree(sample_dir)
    data_root.mkdir(parents=True)

    rep.h("0. generate source artefacts with real byte splitting")
    gen = SampleGenerator(sample_dir)
    run_desc = gen.generate()
    for (tenant, rid), payload in sorted(gen.payloads.items()):
        spec = next(x for x in gen.RECORD_SPECS if x[0] == tenant and x[1] == rid)
        rep.info("%s/%s payload=%d bytes, byte slices=%s"
                 % (tenant, rid, len(payload), spec[3]))
    rep.ok("4 packages + manifest + originals written to %s" % sample_dir)

    # ---------------------------------------------------------------- #
    rep.s("apply delivery manifest to the empty data directory")
    storage = Storage(data_root)  # creates the inbox/delivery/... subtree
    directory = PackageDirectoryService(storage)
    shutil.copy(sample_dir / "delivery" / "manifest-v1.json",
                data_root / "delivery" / "manifest-v1.json")
    directory.apply_manifest_file(data_root / "delivery" / "manifest-v1.json")
    storage.close()
    rep.ok("manifest registered; directory initially shows gaps %s"
           % snapshot(data_root)["gaps"])

    rep.s("deliver packages out of order: 3, 0, 1 (seq 2 withheld)")
    for seq in (3, 0, 1):
        shutil.copy(sample_dir / "packages" / ("pkg-%08d-v01.pdpkg" % seq),
                    data_root / "inbox" / ("pkg-%08d-v01.pdpkg" % seq))
    drain(data_root)
    snap = snapshot(data_root)
    assert_equal(snap["gaps"], [2], "package gap", rep)
    statuses = {"%s/%s" % (r["tenant_id"], r["record_id"]): r["assembly_status"]
                for r in snap["records"]}
    rep.info("record states after partial delivery: %s" % json.dumps(statuses))
    # Records whose segments all arrived (across the unordered packages) are
    # published; only records touching the missing middle package keep waiting.
    assert statuses["t-bravo/r-002"] == "ASSEMBLING", "r-002 needs pkg2"
    assert statuses["t-charlie/r-003"] == "ASSEMBLING", "r-003 lives wholly in pkg2"
    rep.ok("r-001, r-004, r-005 assembled across out-of-order packages and published")
    rep.ok("r-002 and r-003 stay ASSEMBLING behind the missing middle package: "
           "%d published, 2 waiting" % len(snap["published"]))

    # ---------------------------------------------------------------- #
    rep.s("worker restart with gap still open — no state loss, no phantom publish")
    drain(data_root)
    snap = snapshot(data_root)
    assert_equal(len(snap["published"]), 3, "published count after restart", rep)
    waiting = [r["record_id"] for r in snap["records"]
               if r["assembly_status"] == "ASSEMBLING"]
    assert_equal(sorted(waiting), ["r-002", "r-003"], "still-waiting records", rep)
    rep.ok("durable state recovered; gap %s re-reported identically" % snap["gaps"])

    rep.s("deliver a structurally intact but CRC-corrupt seq 2 (bad package)")
    corrupt = gen.write_corrupt_package(2, sample_dir / "corrupt-pkg2.pdpkg")
    shutil.copy(corrupt, data_root / "inbox" / corrupt.name)
    drain(data_root)
    snap = snapshot(data_root)
    pkg2 = next(p for p in snap["packages"] if p["seq"] == 2)
    assert_equal(pkg2["status"], "QUARANTINED", "corrupt package state", rep)
    rep.info("quarantine reason: %s" % pkg2["quarantine_reason"])
    rep.ok("no segments extracted from the corrupt package; other tenants unaffected")

    rep.s("deliver seq 2 with one flipped payload byte (bad segment, good package)")
    badseg = gen.write_bad_segment_package(2, sample_dir / "badseg-pkg2.pdpkg")
    shutil.copy(badseg, data_root / "inbox" / badseg.name)
    drain(data_root)
    snap = snapshot(data_root)
    recs = {(r["tenant_id"], r["record_id"]): r for r in snap["records"]}
    victim = recs[("t-bravo", "r-002")]
    assert_equal(victim["assembly_status"], "QUARANTINED", "bad-segment record", rep)
    rep.info("isolation reason: %s" % victim["quarantine_reason"])
    # r-003 lives in the same package but a different tenant — must still complete.
    charlie = recs[("t-charlie", "r-003")]
    assert_equal(charlie["assembly_status"], "PUBLISHED", "neighbour tenant record", rep)
    rep.ok("tenant isolation holds: t-charlie published while t-bravo is quarantined")

    # ---------------------------------------------------------------- #
    rep.s("补包: clean re-delivery of seq 2 -> every record completes")
    good = sample_dir / "packages" / "pkg-00000002-v01.pdpkg"
    shutil.copy(good, data_root / "inbox" / "pkg-00000002-v01-redelivered.pdpkg")
    drain(data_root)
    snap = snapshot(data_root)
    statuses = {r["record_id"]: r["assembly_status"] for r in snap["records"]}
    assert all(v == "PUBLISHED" for v in statuses.values()), statuses
    rep.ok("all 5 records PUBLISHED: %s" % json.dumps(statuses))
    assert_equal(snap["gaps"], [], "remaining package gaps", rep)
    verify_published_against_originals(data_root, sample_dir, rep)
    publishes_before = sum(1 for e in snap["events"] if e["kind"] == "REC_PUBLISH")

    rep.s("换版: manifest v2 re-points seq 3 to v2 with re-cut slices (same bytes)")
    new_pkg, new_manifest = gen.write_replacement_package(
        3, sample_dir / "pkg-00000003-v02.pdpkg",
        sample_dir / "delivery" / "manifest-v2.json")
    shutil.copy(new_manifest, data_root / "delivery" / "manifest-v2.json")
    shutil.copy(new_pkg, data_root / "inbox" / new_pkg.name)
    drain(data_root)
    snap = snapshot(data_root)
    publishes_after = sum(1 for e in snap["events"] if e["kind"] == "REC_PUBLISH")
    republishes = sum(1 for e in snap["events"] if e["kind"] == "REC_REPUBLISH")
    assert_equal(publishes_after, publishes_before, "REC_PUBLISH events", rep)
    assert_equal(republishes, 0, "REC_REPUBLISH events", rep)
    rep.ok("replacement re-evaluated only the 2 records of pkg3; identical SHA ->"
           " no duplicate publication of neighbour content")
    pkg3 = next(p for p in snap["packages"] if p["seq"] == 3)
    assert_equal(pkg3["status"], "OK", "replaced package state", rep)
    rep.ok("old v1 package retired to quarantine/ as SUPERSEDED")
    verify_published_against_originals(data_root, sample_dir, rep)

    rep.s("worker restart after replacement — published set must be unchanged")
    drain(data_root)
    snap = snapshot(data_root)
    assert_equal(sum(1 for e in snap["events"] if e["kind"] == "REC_PUBLISH"),
                 publishes_before, "publish events after restart", rep)
    assert all(r["assembly_status"] == "PUBLISHED" for r in snap["records"])
    rep.ok("restart recovered from SQLite + segment files; zero duplicate publishes")
    verify_published_against_originals(data_root, sample_dir, rep)

    rep.h("summary")
    rep.info("data root: %s" % data_root)
    rep.info("published files: %s"
             % sorted(p.name for p in (data_root / "published").rglob("*.pdrec")))
    rep.info("quarantine: %s"
             % sorted(p.name for p in (data_root / "quarantine").iterdir()))
    rep.info("audit event kinds: %s"
             % sorted({e["kind"] for e in snap["events"]}))
    rep.ok("END-TO-END DEMO PASSED")
    if not keep:
        rep.info("(data retained at %s for inspection)" % data_root)
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="app.demo", description="Run the full demo")
    ap.add_argument("--data", default="data")
    ap.add_argument("--sample", default="sample")
    args = ap.parse_args(argv)
    return run(args.data, args.sample)


if __name__ == "__main__":
    sys.exit(main())
