"""Durable storage: SQLite-WAL metadata tree plus segment/payload files.

Persistence choice
------------------
Assembly state is *persisted*, not held in memory. A worker crash or machine
restart must not lose which segment ordinals already arrived, why a record was
quarantined, or which records were already published (restart would otherwise
republish). Reconstruction from segment files alone cannot recover quarantine
reasons or the delivery manifest, so the metadata lives in SQLite (WAL mode,
check_same_thread=False guarded by one lock) and payloads on disk.
"""

from __future__ import annotations

import os
import re
import sqlite3
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")

SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA synchronous=FULL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS manifest_packages (
    seq              INTEGER PRIMARY KEY,
    expected_version INTEGER NOT NULL,
    state            TEXT NOT NULL,              -- PENDING|RECEIVED|QUARANTINED|SUPERSEDED
    updated_at       REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS manifest_records (
    tenant_id  TEXT NOT NULL,
    record_id  TEXT NOT NULL,
    seg_total  INTEGER NOT NULL,
    record_len INTEGER NOT NULL,
    record_sha TEXT NOT NULL,
    PRIMARY KEY (tenant_id, record_id)
);

CREATE TABLE IF NOT EXISTS manifest_segment_map (
    tenant_id TEXT NOT NULL,
    record_id TEXT NOT NULL,
    seg_index INTEGER NOT NULL,
    seq       INTEGER NOT NULL,
    version   INTEGER NOT NULL,
    PRIMARY KEY (tenant_id, record_id, seg_index)
);

CREATE TABLE IF NOT EXISTS packages (
    seq               INTEGER NOT NULL,
    version           INTEGER NOT NULL,
    state             TEXT NOT NULL,            -- RECEIVED|QUARANTINED|SUPERSEDED
    seg_count         INTEGER NOT NULL,
    pkg_crc           INTEGER NOT NULL,
    pkg_sha256        TEXT,
    source_file       TEXT NOT NULL,
    quarantine_reason TEXT,
    received_at       REAL NOT NULL,
    PRIMARY KEY (seq, version)
);

CREATE TABLE IF NOT EXISTS records (
    tenant_id        TEXT NOT NULL,
    record_id        TEXT NOT NULL,
    seg_total        INTEGER,
    record_len       INTEGER,
    record_sha       TEXT,
    status           TEXT NOT NULL,             -- ASSEMBLING|COMPLETE|QUARANTINED|PUBLISHED
    quarantine_reason TEXT,
    first_seen_at    REAL NOT NULL,
    updated_at       REAL NOT NULL,
    PRIMARY KEY (tenant_id, record_id)
);

CREATE TABLE IF NOT EXISTS segments (
    tenant_id   TEXT NOT NULL,
    record_id   TEXT NOT NULL,
    seg_index   INTEGER NOT NULL,
    seg_total   INTEGER NOT NULL,
    record_len  INTEGER NOT NULL,
    record_sha  TEXT NOT NULL,
    payload_len INTEGER NOT NULL,
    payload_crc INTEGER NOT NULL,
    seq         INTEGER NOT NULL,
    pkg_version INTEGER NOT NULL,
    state       TEXT NOT NULL,                  -- OK|BAD
    seg_file    TEXT NOT NULL,                  -- path relative to data root
    received_at REAL NOT NULL,
    PRIMARY KEY (tenant_id, record_id, seg_index)
);

CREATE TABLE IF NOT EXISTS published (
    tenant_id    TEXT NOT NULL,
    record_id    TEXT NOT NULL,
    sha256       TEXT NOT NULL,
    record_len   INTEGER NOT NULL,
    file_path    TEXT NOT NULL,
    published_at REAL NOT NULL,
    PRIMARY KEY (tenant_id, record_id)
);

CREATE TABLE IF NOT EXISTS events (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    ts        REAL NOT NULL,
    kind      TEXT NOT NULL,
    tenant_id TEXT,
    record_id TEXT,
    seq       INTEGER,
    detail    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS idx_segments_record ON segments(tenant_id, record_id);
CREATE INDEX IF NOT EXISTS idx_records_status ON records(status);
"""


def validate_safe_name(name: str) -> None:
    if not isinstance(name, str) or not SAFE_NAME.match(name):
        raise ValueError("unsafe identifier: %r" % (name,))


class Storage:
    """File-tree + SQLite storage rooted at one data directory."""

    def __init__(self, data_root: str | os.PathLike[str]):
        self.root = Path(data_root).resolve()
        self.inbox = self.root / "inbox"
        self.packages = self.root / "packages"
        self.quarantine = self.root / "quarantine"
        self.segments = self.root / "segments"
        self.published = self.root / "published"
        self.delivery = self.root / "delivery"
        self.tmp = self.root / "tmp"
        self.worker = self.root / "worker"
        for d in (self.inbox, self.packages, self.quarantine, self.segments,
                  self.published, self.delivery, self.tmp, self.worker):
            d.mkdir(parents=True, exist_ok=True)
        self.db_path = self.root / "assembly.db"
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.executescript(SCHEMA)
            self._migrate()
            self._conn.commit()

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def _migrate(self) -> None:
        """Lightweight additive migrations for databases created by older code."""
        cols = {r["name"] for r in self._conn.execute("PRAGMA table_info(packages)")}
        if "pkg_sha256" not in cols:
            self._conn.execute(
                "ALTER TABLE packages ADD COLUMN pkg_sha256 TEXT")

    @contextmanager
    def tx(self) -> Iterator[sqlite3.Connection]:
        """Single serialised write transaction (BEGIN IMMEDIATE semantics)."""
        with self._lock:
            try:
                self._conn.execute("BEGIN IMMEDIATE")
                yield self._conn
                self._conn.commit()
            except BaseException:
                self._conn.rollback()
                raise

    def query(self, sql: str, params: tuple[Any, ...] = ()) -> list[sqlite3.Row]:
        with self._lock:
            return list(self._conn.execute(sql, params))

    def query_one(self, sql: str, params: tuple[Any, ...] = ()) -> sqlite3.Row | None:
        with self._lock:
            return self._conn.execute(sql, params).fetchone()

    # ------------------------------------------------------------------ #
    # Filesystem helpers
    # ------------------------------------------------------------------ #
    def atomic_write(self, dest: Path, data: bytes) -> None:
        """Write bytes to dest atomically (tmp file + fsync + rename)."""
        dest.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.tmp / ("%d-%d.tmp" % (time.time_ns(), os.getpid()))
        with open(tmp, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, dest)

    def seg_path(self, tenant_id: str, record_id: str, seg_index: int) -> Path:
        validate_safe_name(tenant_id)
        validate_safe_name(record_id)
        return self.segments / tenant_id / record_id / ("%08d.bin" % seg_index)

    def rel(self, path: Path) -> str:
        return str(path.relative_to(self.root))

    def published_path(self, tenant_id: str, record_id: str) -> Path:
        validate_safe_name(tenant_id)
        validate_safe_name(record_id)
        return self.published / tenant_id / (record_id + ".pdrec")

    # ------------------------------------------------------------------ #
    # Event journal
    # ------------------------------------------------------------------ #
    def event(self, kind: str, detail: str, *, tenant_id: str | None = None,
              record_id: str | None = None, seq: int | None = None) -> None:
        with self.tx() as conn:
            conn.execute(
                "INSERT INTO events(ts, kind, tenant_id, record_id, seq, detail)"
                " VALUES (?,?,?,?,?,?)",
                (time.time(), kind, tenant_id, record_id, seq, detail),
            )
