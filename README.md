# Pointwise Multi-Package Record Delivery — Assembler Service

A source splits a long record into byte slices spread across **adjacent,
ordered archive packages**. Packages are downloaded in **non-deterministic
order**, and a middle package may be missing. This service ingests the
packages, assembles complete records, and publishes only verified whole
records — while a bad segment quarantines just its own record instead of
halting every tenant behind it.

Pure Python 3.11 standard library. **No third-party dependencies.**

## What it implements

| Requirement | Component |
|---|---|
| Package directory service (manifest, gaps, replacement ledger) | `app/directory.py` |
| Segment receiver (3-level validation, transactional ingest) | `app/receiver.py` |
| Record assembler / publisher (streaming, incremental, idempotent) | `app/assembler.py` |
| Durable state (SQLite-WAL + segment files) | `app/storage.py` |
| Worker process (inbox polling, crash recovery, graceful stop) | `app/worker.py` |
| Operations web console (positions/gaps/isolation, upload, restart) | `app/webapp.py` |
| Binary wire formats (segment / package / published record) | `app/formats.py` |
| Real byte-splitting sample generator + fault injection | `app/generator.py` |
| End-to-end orchestrated demo | `app/demo.py` |

## Key design decisions

### State is persisted, not held in memory

Assembly state lives in **SQLite in WAL mode** plus per-segment payload files.
A worker crash or restart must not lose which ordinals arrived, why a record
was quarantined, or what was already published (otherwise restart would
double-publish). Reconstructing from segment files alone cannot recover
quarantine reasons or the delivery manifest, so the metadata is durable.
Recovery is therefore cheap: sweep `tmp/`, reclaim anything left in `inbox/`,
and re-evaluate only non-published records.

### Only complete records are published

A record is published only when every expected ordinal is present, no segment
is `BAD`, headers agree, and the streamed concatenation reproduces the declared
byte length **and** SHA-256. Missing ordinals are a *gap* (status
`ASSEMBLING`), not a quarantine — the record keeps waiting.

### Failure is isolated per record, never per tenant

- A package that fails its package-level CRC or structural decode is wholly
  quarantined; **no segment is extracted**, so no tenant is touched.
- A package that parses but contains a segment whose own CRC is stale marks
  exactly that segment `BAD` and quarantines only that record. Every other
  record — including other tenants in the same package — keeps flowing.
- The assembler wraps each record in its own try/except boundary so an
  internal error on one record cannot kill the worker or block later records.

### Incremental recomputation, no duplicate publication

The worker passes only the records touched by an arriving package to the
assembler. Already-published records are skipped. On replacement delivery, a
reassembled record whose SHA-256 is unchanged is **not** published again
(idempotent store), so neighbour content already completed in adjacent
packages is never re-published. Re-delivery dedup is based on the package's
byte SHA-256, not merely its version, which lets a corrective re-delivery
(补包) of the same version replace a prior bad attempt.

## Binary format and a real byte/checksum example

All integers are big-endian. Frames start with a 7-byte magic + 1-byte version.

```
PDSEG01 segment:  tenant/record (len-prefixed) | seg_index seg_total
                  record_len | record_sha256(32) | payload_len payload_crc32 | payload
PDPKG01 package:  seq version created_at pkg_crc32 seg_count | segments...
PDREC01 record:   tenant/record | record_len | record_sha256(32) | payload
```

Real numbers produced by the generator (record `t-alpha/r-001`,
300 payload bytes split at byte offsets **120 / 90 / 90**):

```
record sha256      = 010dcd32864209c266440c7f84966316266f2a072c4890f9d4f3c24fda312c6a
seg#0 bytes[0:120] len=120  crc32=2c55be54
seg#1 bytes[120:210] len=90 crc32=bc29afd4
seg#2 bytes[210:300] len=90 crc32=84e81f3f
```

Package `seq=1` (which carries segments `r-001#1, r-001#2, r-002#0`):

```
file_len=664  magic=PDPKG01  version=1
seq=1 ver=1 created_at=1763000001 pkg_crc32=1009f432 seg_count=3
```

The published container for that record is 364 bytes = 300 payload + 64 header,
and independently re-decoding it reproduces the exact original bytes.

## Run it

Everything runs under Python isolated mode (`-I`) via the launchers in `bin/`,
so untrusted downloaded data can never shadow stdlib modules.

```bash
# 1. Full end-to-end scenario (builds from empty directories)
./bin/demo --data data --sample sample

# 2. Just (re)generate source artefacts with real byte splitting
./bin/generate-sample --out sample

# 3. Worker as a long-running daemon (polls data/inbox)
./bin/worker --data data

# 4. Operations web console
./bin/webapp --data data --host 127.0.0.1 --port 8088
#    http://127.0.0.1:8088/        dashboard
#    http://127.0.0.1:8088/events  audit journal
#    http://127.0.0.1:8088/api/state   JSON snapshot
```

The console supports uploading a package (补包 / replacement) into the inbox,
applying a replacement manifest (换版), and start/stop/restart of the worker.

## Demo scenario timeline

1. Generate 4 ordered packages; deliver `3, 0, 1` out of order; withhold seq 2.
2. Records touching only arrived packages publish; records needing seq 2 wait;
   the directory reports gap `[2]`.
3. Restart the worker — durable recovery, no phantom/duplicate publish.
4. Deliver a CRC-corrupt seq 2 → whole-package quarantine, nothing extracted.
5. Deliver seq 2 with one tampered sealed segment → only that record
   quarantines (`corrupt segment(s) at ordinal(s) [1]`); the neighbour tenant
   in the same package still publishes.
6. 补包: clean re-delivery of seq 2 → all records complete and verified
   byte-for-byte against the generator's originals.
7. 换版: manifest v2 re-points seq 3 to v2 with re-cut slices but identical
   assembled bytes → zero re-publishes; old package archived as SUPERSEDED.
8. Restart again → published set byte-identical, still zero duplicates.

## Tests

```bash
python3 -I -m unittest discover -s tests -v
```

Covers wire-format round trips and checksum rejection, package-vs-segment
isolation boundaries, unsafe-identifier rejection, gap handling, corrective
re-delivery, replacement-with-identical-bytes (no re-publish), and recovery
that skips already-published records.

## Data directory layout

```
data/
  inbox/         drop zone; the worker claims files atomically
  packages/      accepted raw packages
  quarantine/    corrupt/rejected packages and superseded versions
  segments/<tenant>/<record>/NNNNNNNN.bin   durable payload slices
  published/<tenant>/<record>.pdrec         complete verified records
  delivery/      applied manifest JSON files
  worker/        pid, heartbeat, log
  tmp/           staging (atomic rename target source)
  assembly.db    SQLite-WAL metadata tree + audit event journal
```
