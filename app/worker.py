"""Assembly worker process.

Responsibilities
----------------
* on startup: rebuild/verify assembly state from durable storage (recovery),
  then sweep the inbox — any file left there by a previous crash is reclaimed
* loop: claim inbox files atomically, hand them to the receiver, and pass only
  the affected record keys to the assembler (incremental recomputation)
* heartbeat + pid files under ``data/worker/`` drive the web "restart" action
* SIGTERM/SIGINT finish the current file before exiting
"""

from __future__ import annotations

import argparse
import os
import signal
import sys
import time
from pathlib import Path

if __package__ in (None, ""):  # executed directly under `python -I app/worker.py`
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.assembler import RecordAssembler
from app.directory import PackageDirectoryService
from app.receiver import SegmentReceiver
from app.storage import Storage

POLL_INTERVAL = 0.5


class Worker:
    def __init__(self, data_root: str):
        self.s = Storage(data_root)
        self.dir = PackageDirectoryService(self.s)
        self.receiver = SegmentReceiver(self.s, self.dir)
        self.assembler = RecordAssembler(self.s)
        self._stop = False
        self.pid_file = self.s.worker / "worker.pid"
        self.heartbeat = self.s.worker / "heartbeat"

    # ------------------------------------------------------------------ #
    def request_stop(self, *_args) -> None:
        self._stop = True

    def run(self) -> int:
        signal.signal(signal.SIGTERM, self.request_stop)
        signal.signal(signal.SIGINT, self.request_stop)
        self.pid_file.write_text(str(os.getpid()))
        self.s.event("WORKER_START", "pid=%d data=%s" % (os.getpid(), self.s.root))
        try:
            self._recover()
            while not self._stop:
                did_work = self._process_inbox_once()
                self._beat()
                if not did_work:
                    self._interruptible_sleep(POLL_INTERVAL)
            self.s.event("WORKER_STOP", "graceful shutdown pid=%d" % os.getpid())
            return 0
        finally:
            try:
                self.pid_file.unlink()
            except FileNotFoundError:
                pass
            self.s.close()

    def _interruptible_sleep(self, seconds: float) -> None:
        end = time.time() + seconds
        while not self._stop and time.time() < end:
            time.sleep(min(0.1, end - time.time()))

    def _beat(self) -> None:
        self.heartbeat.write_text(str(time.time()))

    # ------------------------------------------------------------------ #
    def _recover(self) -> None:
        """Rebuild runtime state after a crash.

        All state is durable, so recovery is: orphan-tmp sweep, inbox reclaim
        (files are only moved out of inbox inside committed flows), then a full
        re-evaluation of every non-published record. Published rows are never
        touched, which is why a restart cannot double-publish.
        """
        for tmp in self.s.tmp.glob("*"):
            try:
                tmp.unlink()
            except OSError:
                pass
        outcomes = self.assembler.reevaluate_pending()
        if outcomes:
            self.s.event(
                "WORKER_RECOVER",
                "re-evaluated %d non-published records: %s"
                % (len(outcomes),
                   ", ".join("%s/%s=%s" % (o.tenant_id, o.record_id, o.status)
                             for o in outcomes)),
            )
        self._beat()

    def _process_inbox_once(self) -> bool:
        files = self.receiver.scan_inbox()
        if not files:
            return False
        for path in files:
            if self._stop:
                break
            self._process_one(path)
        return True

    def _process_one(self, path: Path) -> None:
        try:
            result = self.receiver.ingest_file(path)
        except Exception as exc:  # absolute last line of defence
            self.s.event("WORKER_ERROR", "ingest crashed for %s: %s"
                         % (path.name, exc))
            return
        if result.outcome not in ("ACCEPTED", "REPLACED"):
            return
        # Incremental: only records touched by this package are recomputed.
        for tenant_id, record_id in result.affected_records:
            outcome = self.assembler.reevaluate(tenant_id, record_id)
            self.s.event(
                "ASSEMBLY_EVAL",
                "%s/%s -> %s%s"
                % (tenant_id, record_id, outcome.status,
                   (" (" + outcome.reason + ")") if outcome.reason else ""),
                tenant_id=tenant_id, record_id=record_id, seq=result.seq)

    def process_once_and_stop(self) -> int:
        """Test/demo helper: one inbox drain + recovery, no daemon loop."""
        self.s.event("WORKER_START", "oneshot pid=%d" % os.getpid())
        try:
            self._recover()
            while self._process_inbox_once():
                pass
            return 0
        finally:
            self.s.close()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="app.worker",
                                 description="Segment assembly worker")
    ap.add_argument("--data", default=os.environ.get("PDP_DATA", "data"),
                    help="data root directory")
    ap.add_argument("--once", action="store_true",
                    help="drain the inbox once and exit (no daemon loop)")
    args = ap.parse_args(argv)
    worker = Worker(args.data)
    if args.once:
        return worker.process_once_and_stop()
    return worker.run()


if __name__ == "__main__":
    sys.exit(main())
