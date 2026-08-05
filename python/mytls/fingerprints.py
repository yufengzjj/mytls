"""Compute ja3 / ja4 / peetprint from a ClientHello, locally.

These used to come from tls.peet.ws, which meant every capture needed a human
holding a phone: the browser cannot read peet's response (peet sends no CORS
headers), so the JSON had to be opened in a second tab and pasted into our page
by hand.  Everything peet reports about the TLS layer is a pure function of the
ClientHello we already have in full - `hpack_probe.peek_client_hello` takes the
record off the socket before the handshake proceeds - so none of that was ever
necessary information, only a second opinion.

Working from the raw record rather than from `parse_client_hello`'s output is
deliberate: that function keeps only what the byte-level diff needs (types and
lengths, bodies for GREASE alone), while a fingerprint needs the contents of
supported_groups, signature_algorithms and friends.  Re-parsing also means these
functions work on captures taken before this module existed, since `raw` has
always been stored.

What is lost by not asking peet is independence - a bug shared between our
parser and our client would now go unnoticed.  `verify_fp.py` still goes over
the real network for that; this is for the everyday capture.
"""

from __future__ import annotations

import hashlib
import struct

GREASE = {0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A,
          0x8A8A, 0x9A9A, 0xAAAA, 0xBABA, 0xCACA, 0xDADA, 0xEAEA, 0xFAFA}

#: Extension types JA4 leaves out of its sorted list. SNI and ALPN are excluded
#: by the specification - they are the two that say *where* the client is going
#: rather than *what* it is. They still count towards the two-digit total.
JA4_SKIP = {0x0000, 0x0010}

SNI = 0x0000
EC_POINT_FORMATS = 0x000B
SUPPORTED_GROUPS = 0x000A
SIG_ALGS = 0x000D
ALPN = 0x0010
PADDING = 0x0015
COMPRESS_CERT = 0x001B
SUPPORTED_VERSIONS = 0x002B
PSK_KEX_MODES = 0x002D

_TLS_VERSION = {0x0304: "13", 0x0303: "12", 0x0302: "11", 0x0301: "10",
                0x0300: "s3"}


def parse(record: bytes) -> dict:
    """Take a ClientHello record apart, extension bodies included.

    Raises ValueError rather than returning None: every caller here already
    knows it is holding a ClientHello, so a failure means the bytes are
    corrupt and silently producing a fingerprint of nothing would be worse.
    """
    if len(record) < 6 or record[0] != 0x16 or record[5] != 0x01:
        msg = "not a TLS handshake record containing a ClientHello"
        raise ValueError(msg)

    b = record[5 + 4:5 + 4 + int.from_bytes(record[6:9], "big")]
    o = 2 + 32                                        # legacy_version, random
    o += 1 + b[o]                                     # session id
    n = struct.unpack_from("!H", b, o)[0]
    ciphers = [struct.unpack_from("!H", b, o + 2 + i)[0] for i in range(0, n, 2)]
    o += 2 + n
    o += 1 + b[o]                                     # compression methods
    end = o + 2 + struct.unpack_from("!H", b, o)[0]
    o += 2

    exts: list[tuple[int, bytes]] = []
    while o < end:
        etype, elen = struct.unpack_from("!HH", b, o)
        exts.append((etype, b[o + 4:o + 4 + elen]))
        o += 4 + elen

    return {
        "legacy_version": struct.unpack_from("!H", b, 0)[0],
        "ciphers": ciphers,
        "extensions": exts,
    }


def _body(ch: dict, etype: int) -> bytes | None:
    return next((body for t, body in ch["extensions"] if t == etype), None)


def _u16s(body: bytes | None, prefix: int) -> list[int]:
    """The u16 list inside an extension whose body opens with a length prefix."""
    if body is None or len(body) < prefix:
        return []
    n = (int.from_bytes(body[:prefix], "big") if prefix else len(body))
    return [struct.unpack_from("!H", body, prefix + i)[0]
            for i in range(0, min(n, len(body) - prefix), 2)]


def _u8s(body: bytes | None, prefix: int) -> list[int]:
    if body is None or len(body) < prefix:
        return []
    n = int.from_bytes(body[:prefix], "big") if prefix else len(body)
    return list(body[prefix:prefix + n])


def _alpn(ch: dict) -> list[str]:
    body = _body(ch, ALPN)
    if not body:
        return []
    out, o = [], 2
    while o < len(body):
        out.append(body[o + 1:o + 1 + body[o]].decode("ascii", "replace"))
        o += 1 + body[o]
    return out


def _versions(ch: dict) -> list[int]:
    """supported_versions in wire order, falling back to the legacy field.

    The list has a one-byte length prefix, not the two-byte one every other
    extension here uses.
    """
    body = _body(ch, SUPPORTED_VERSIONS)
    if not body:
        return [ch["legacy_version"]]
    return [struct.unpack_from("!H", body, 1 + i)[0] for i in range(0, body[0], 2)]


def _md5(text: str) -> str:
    # Not a security use: ja3 and the akamai fingerprint are defined as md5.
    return hashlib.md5(text.encode(), usedforsecurity=False).hexdigest()


def _sha12(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()[:12]


# --- ja3 ---------------------------------------------------------------------

def ja3(ch: dict) -> dict:
    """The ja3 string and its md5.

    Note what is *not* here: extension contents. ja3 hashes the list of
    extension types and nothing inside them, which is why two builds of iOS
    with different signature algorithms produce the same ja3 hash. It is also
    why Chrome's ja3 is unstable - it shuffles the extension order per
    connection, and ja3 preserves wire order.
    """
    fields = [
        str(ch["legacy_version"]),
        "-".join(str(c) for c in ch["ciphers"] if c not in GREASE),
        "-".join(str(t) for t, _ in ch["extensions"] if t not in GREASE),
        "-".join(str(g) for g in _u16s(_body(ch, SUPPORTED_GROUPS), 2)
                 if g not in GREASE),
        "-".join(str(f) for f in _u8s(_body(ch, EC_POINT_FORMATS), 1)),
    ]
    text = ",".join(fields)
    return {"fingerprint": text, "hash": _md5(text)}


# --- ja4 ---------------------------------------------------------------------

def _ja4_prefix(ch: dict) -> str:
    version = max((v for v in _versions(ch) if v not in GREASE),
                  default=ch["legacy_version"])
    protocols = _alpn(ch)
    alpn = f"{protocols[0][0]}{protocols[0][-1]}" if protocols else "00"
    ciphers = [c for c in ch["ciphers"] if c not in GREASE]
    exts = [t for t, _ in ch["extensions"] if t not in GREASE]
    return (f"t{_TLS_VERSION.get(version, '00')}"
            f"{'d' if _body(ch, SNI) is not None else 'i'}"
            f"{min(len(ciphers), 99):02d}{min(len(exts), 99):02d}{alpn}")


def _ja4_lists(ch: dict, *, count_padding: bool) -> tuple[str, str]:
    skip = JA4_SKIP if count_padding else JA4_SKIP | {PADDING}
    ciphers = sorted(f"{c:04x}" for c in ch["ciphers"] if c not in GREASE)
    exts = sorted(f"{t:04x}" for t, _ in ch["extensions"]
                  if t not in GREASE and t not in skip)
    sigalgs = [f"{s:04x}" for s in _u16s(_body(ch, SIG_ALGS), 2)]
    return ",".join(ciphers), ",".join(exts) + "_" + ",".join(sigalgs)


def ja4(ch: dict, *, count_padding: bool = False) -> str:
    """ja4, in the flavour `tls.peet.ws` computes by default.

    `count_padding` is the one place implementations disagree, and it matters
    only for clients that send a padding extension - which among the profiles
    here means Safari and not Chrome. peet leaves 0x0015 out of the sorted
    extension list while still counting it in the two-digit total; Wireshark
    includes it in both, which is what the specification says. Same bytes,
    different answer, so a ja4 is only ever comparable to one from the same
    tool. The default is peet's because that is what `references/` holds.
    """
    ciphers, tail = _ja4_lists(ch, count_padding=count_padding)
    return f"{_ja4_prefix(ch)}_{_sha12(ciphers)}_{_sha12(tail)}"


def ja4_r(ch: dict, *, count_padding: bool = False) -> str:
    """ja4 with the lists spelled out instead of hashed - what to read on a mismatch."""
    ciphers, tail = _ja4_lists(ch, count_padding=count_padding)
    return f"{_ja4_prefix(ch)}_{ciphers}_{tail}"


# --- peetprint ---------------------------------------------------------------

def _decimal(values: list[int]) -> str:
    return "-".join("GREASE" if v in GREASE else str(v) for v in values)


def peetprint(ch: dict) -> dict:
    """tls.peet.ws's own fingerprint: eight fields, and unlike ja3 it reads bodies.

    Its extension field is sorted as *text* ("10" before "5"), not numerically,
    with the GREASE entries moved to the end - so like ja4 and unlike ja3 it
    survives Chrome's per-connection shuffle.
    """
    types = [t for t, _ in ch["extensions"]]
    fields = [
        _decimal(_versions(ch)),
        # h2 -> 2, http/1.1 -> 1.1: peet keeps only the digits and dots.
        "-".join("".join(c for c in p if c.isdigit() or c == ".")
                 for p in _alpn(ch)),
        _decimal(_u16s(_body(ch, SUPPORTED_GROUPS), 2)),
        _decimal(_u16s(_body(ch, SIG_ALGS), 2)),
        "-".join(str(m) for m in _u8s(_body(ch, PSK_KEX_MODES), 1)),
        _decimal(_u16s(_body(ch, COMPRESS_CERT), 1)),
        _decimal(ch["ciphers"]),
        "-".join(sorted((str(t) for t in types if t not in GREASE), key=str)
                 + ["GREASE"] * sum(t in GREASE for t in types)),
    ]
    text = "|".join(fields)
    return {"fingerprint": text, "hash": _md5(text)}


# --- everything at once ------------------------------------------------------

def of_client_hello(raw: str | bytes) -> dict:
    """Every TLS-layer fingerprint of one ClientHello, shaped like peet's `tls` key.

    Both ja4 flavours are reported rather than one, because the difference is
    real and a caller comparing against a capture from some other tool needs to
    be able to find its own answer in here.
    """
    record = bytes.fromhex(raw) if isinstance(raw, str) else raw
    ch = parse(record)
    j3, pp = ja3(ch), peetprint(ch)
    return {
        "ja3": j3["fingerprint"],
        "ja3_hash": j3["hash"],
        "ja4": ja4(ch),
        "ja4_r": ja4_r(ch),
        "ja4_padding_counted": ja4(ch, count_padding=True),
        "ja4_r_padding_counted": ja4_r(ch, count_padding=True),
        "peetprint": pp["fingerprint"],
        "peetprint_hash": pp["hash"],
    }
