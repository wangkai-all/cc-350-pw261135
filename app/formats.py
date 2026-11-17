"""Binary wire formats for segmented record delivery.

On-disk / on-wire layout (all multi-byte integers are big-endian).

Segment file/block (``PDSEG01``)::

    magic        6 bytes   b"PDSEG01"
    version      1 byte    1
    tenant_id    u16 len + UTF-8 bytes
    record_id    u16 len + UTF-8 bytes
    seg_index    u32       zero-based ordinal of this segment in the record
    seg_total    u32       number of segments the record was split into
    record_len   u64       total byte length of the assembled record
    record_sha   32 bytes  SHA-256 of the *assembled* record payload
    payload_len  u64       byte length of this segment's payload slice
    payload_crc  u32       CRC32 of this segment's payload slice
    payload      payload_len bytes

Package file (``PDPKG01``)::

    magic        6 bytes   b"PDPKG01"
    version      1 byte    1
    seq          u32       package sequence number (ordered, gap-prone)
    ver          u32       package version (re-delivery / replacement)
    created_at   u64       source-side UNIX timestamp, seconds
    pkg_crc      u32       CRC32 over every byte following the magic/version,
                           with the pkg_crc field itself zeroed
    seg_count    u32
    segments     seg_count concatenated segment blocks

Published record file (``PDREC01``)::

    magic 6 | version 1 | tenant_id lp | record_id lp |
    record_len u64 | record_sha 32 | payload record_len bytes
"""

from __future__ import annotations

import hashlib
import struct
import zlib
from typing import Any

SEG_MAGIC = b"PDSEG01"
PKG_MAGIC = b"PDPKG01"
REC_MAGIC = b"PDREC01"
FORMAT_VERSION = 1

MAX_NAME_LEN = 256
MAX_SEGMENTS_PER_PACKAGE = 1_000_000
MAX_PACKAGE_BYTES = 256 * 1024 * 1024
SHA_LEN = 32


class FormatError(ValueError):
    """Raised when a binary block is structurally invalid or fails checksum."""


def _encode_lp(text: str) -> bytes:
    raw = text.encode("utf-8")
    if not raw or len(raw) > MAX_NAME_LEN:
        raise FormatError("name must be 1..%d UTF-8 bytes: %r" % (MAX_NAME_LEN, text))
    return struct.pack(">H", len(raw)) + raw


def _decode_lp(buf: bytes, offset: int) -> tuple[str, int]:
    if offset + 2 > len(buf):
        raise FormatError("truncated length prefix at offset %d" % offset)
    (n,) = struct.unpack_from(">H", buf, offset)
    offset += 2
    if n == 0 or offset + n > len(buf):
        raise FormatError("invalid length-prefixed string at offset %d" % offset)
    try:
        text = buf[offset : offset + n].decode("utf-8")
    except UnicodeDecodeError as exc:
        raise FormatError("non-UTF8 name at offset %d: %s" % (offset, exc)) from None
    return text, offset + n


def crc32(data: bytes) -> int:
    return zlib.crc32(data) & 0xFFFFFFFF


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# --------------------------------------------------------------------------- #
# Segment
# --------------------------------------------------------------------------- #
def encode_segment(
    *,
    tenant_id: str,
    record_id: str,
    seg_index: int,
    seg_total: int,
    record_len: int,
    record_sha: bytes | str,
    payload: bytes,
) -> bytes:
    if not 0 <= seg_index < seg_total:
        raise FormatError("seg_index %d out of range for seg_total %d" % (seg_index, seg_total))
    if record_len < len(payload):
        raise FormatError("segment payload longer than declared record")
    if isinstance(record_sha, str):
        record_sha = bytes.fromhex(record_sha)
    if len(record_sha) != SHA_LEN:
        raise FormatError("record_sha must be 32 bytes")
    head = (
        SEG_MAGIC
        + bytes([FORMAT_VERSION])
        + _encode_lp(tenant_id)
        + _encode_lp(record_id)
        + struct.pack(">IIQ", seg_index, seg_total, record_len)
        + record_sha
        + struct.pack(">QI", len(payload), crc32(payload))
    )
    return head + payload


def decode_segment(buf: bytes, offset: int) -> tuple[dict[str, Any], int]:
    start = offset
    if offset + 8 > len(buf) or buf[offset : offset + 7] != SEG_MAGIC:
        raise FormatError("bad segment magic at offset %d" % offset)
    if buf[offset + 7] != FORMAT_VERSION:
        raise FormatError("unsupported segment version at offset %d" % offset)
    offset += 8
    tenant_id, offset = _decode_lp(buf, offset)
    record_id, offset = _decode_lp(buf, offset)
    fixed = struct.calcsize(">IIQ") + SHA_LEN + struct.calcsize(">QI")
    if offset + fixed > len(buf):
        raise FormatError("truncated segment header at offset %d" % start)
    seg_index, seg_total, record_len = struct.unpack_from(">IIQ", buf, offset)
    offset += struct.calcsize(">IIQ")
    record_sha = buf[offset : offset + SHA_LEN]
    offset += SHA_LEN
    payload_len, payload_crc = struct.unpack_from(">QI", buf, offset)
    offset += struct.calcsize(">QI")
    if seg_total == 0 or seg_index >= seg_total:
        raise FormatError("invalid segment ordinal %d/%d" % (seg_index, seg_total))
    if record_len < payload_len:
        raise FormatError("segment payload longer than declared record")
    if offset + payload_len > len(buf):
        raise FormatError("truncated segment payload at offset %d" % start)
    payload = buf[offset : offset + payload_len]
    offset += payload_len
    # Segment-level CRC mismatch is *reported*, not raised: the package-level
    # CRC already guards transport, while a re-packed / tampered container can
    # be internally consistent yet carry a corrupted segment. Callers isolate
    # the single affected record instead of rejecting the whole package.
    return (
        {
            "tenant_id": tenant_id,
            "record_id": record_id,
            "seg_index": seg_index,
            "seg_total": seg_total,
            "record_len": record_len,
            "record_sha": record_sha.hex(),
            "payload_len": payload_len,
            "payload_crc": payload_crc,
            "crc_ok": crc32(payload) == payload_crc,
            "payload": payload,
        },
        offset,
    )


# --------------------------------------------------------------------------- #
# Package
# --------------------------------------------------------------------------- #
def encode_package(seq: int, version: int, created_at: int, segments: list[bytes]) -> bytes:
    if not 0 < len(segments) <= MAX_SEGMENTS_PER_PACKAGE:
        raise FormatError("package must contain 1..%d segments" % MAX_SEGMENTS_PER_PACKAGE)
    body = (
        struct.pack(">IIQI", seq, version, created_at, 0)
        + struct.pack(">I", len(segments))
        + b"".join(segments)
    )
    if len(body) > MAX_PACKAGE_BYTES:
        raise FormatError("package exceeds %d bytes" % MAX_PACKAGE_BYTES)
    crc = crc32(body)
    body = body[:16] + struct.pack(">I", crc) + body[20:]
    return PKG_MAGIC + bytes([FORMAT_VERSION]) + body


def decode_package(buf: bytes) -> dict[str, Any]:
    # 7-byte outer magic/version + 24-byte body header
    # (seq I, version I, created_at Q, pkg_crc I, seg_count I = 24 bytes)
    body_header = struct.calcsize(">IIQII")
    if len(buf) > MAX_PACKAGE_BYTES:
        raise FormatError("package too large: %d bytes" % len(buf))
    if len(buf) < 8 + body_header or buf[:7] != PKG_MAGIC:
        raise FormatError("bad package magic / truncated header")
    if buf[7] != FORMAT_VERSION:
        raise FormatError("unsupported package version")
    body = buf[8:]
    seq, version, created_at, header_crc = struct.unpack_from(">IIQI", body, 0)
    (seg_count,) = struct.unpack_from(">I", body, 20)
    if seg_count == 0 or seg_count > MAX_SEGMENTS_PER_PACKAGE:
        raise FormatError("invalid segment count %d" % seg_count)
    zeroed = body[:16] + b"\x00\x00\x00\x00" + body[20:]
    actual_crc = crc32(zeroed)
    if actual_crc != header_crc:
        raise FormatError(
            "package seq=%d v%d CRC32 mismatch: header=%08x actual=%08x"
            % (seq, version, header_crc, actual_crc)
        )
    # segments follow the 24-byte package body header; body starts at byte 8
    offset = 8 + 24
    segments: list[dict[str, Any]] = []
    for _ in range(seg_count):
        seg, offset = decode_segment(buf, offset)
        segments.append(seg)
    if offset != len(buf):
        raise FormatError("trailing %d garbage bytes after last segment" % (len(buf) - offset))
    return {
        "seq": seq,
        "version": version,
        "created_at": created_at,
        "pkg_crc": header_crc,
        "seg_count": seg_count,
        "segments": segments,
    }


# --------------------------------------------------------------------------- #
# Published record
# --------------------------------------------------------------------------- #
def encode_record_file(tenant_id: str, record_id: str, payload: bytes) -> bytes:
    return (
        REC_MAGIC
        + bytes([FORMAT_VERSION])
        + _encode_lp(tenant_id)
        + _encode_lp(record_id)
        + struct.pack(">Q", len(payload))
        + hashlib.sha256(payload).digest()
        + payload
    )


def decode_record_file(buf: bytes) -> dict[str, Any]:
    if len(buf) < 8 or buf[:7] != REC_MAGIC or buf[7] != FORMAT_VERSION:
        raise FormatError("bad record file magic")
    offset = 8
    tenant_id, offset = _decode_lp(buf, offset)
    record_id, offset = _decode_lp(buf, offset)
    if offset + 8 + SHA_LEN > len(buf):
        raise FormatError("truncated record header")
    (record_len,) = struct.unpack_from(">Q", buf, offset)
    offset += 8
    record_sha = buf[offset : offset + SHA_LEN]
    offset += SHA_LEN
    if offset + record_len != len(buf):
        raise FormatError("record length mismatch (declared %d, actual %d)"
                          % (record_len, len(buf) - offset))
    payload = buf[offset:]
    if hashlib.sha256(payload).digest() != record_sha:
        raise FormatError("record payload SHA-256 mismatch")
    return {"tenant_id": tenant_id, "record_id": record_id,
            "record_len": record_len, "record_sha": record_sha.hex(), "payload": payload}
