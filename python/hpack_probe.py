"""Capture the raw HPACK bytes a client sends, so Chrome and we can be diffed.

Runs a minimal HTTP/2 server over TLS and dumps the HEADERS frame exactly as it
arrived - the header block fragment is written out verbatim, before anything
decodes it. Point Chrome at it, then point our own client at it, and compare.

    # terminal 1
    python hpack_probe.py serve --out chrome.json

    # Windows, fresh profile so no cookies/extensions get in the way
    chrome.exe --user-data-dir=%TEMP%\\cfp --ignore-certificate-errors ^
               https://localhost:8443/api/all

    # terminal 2, once Chrome has been captured
    python hpack_probe.py serve --out ours.json &
    python hpack_probe.py client
    python hpack_probe.py diff chrome.json ours.json

Only the first HEADERS frame of a connection is recorded: the HPACK dynamic
table starts empty there, which is the only state both sides are guaranteed to
share.
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import socket
import ssl
import struct
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
#: Generated artefacts live outside the tree so nothing lands in git.
WORK = Path(os.environ.get("HPACK_PROBE_DIR", Path.home() / ".cache/hpack_probe"))
CERT = WORK / "cert.pem"
KEY = WORK / "key.pem"
PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

FRAME_TYPES = {
    0: "DATA", 1: "HEADERS", 2: "PRIORITY", 3: "RST_STREAM", 4: "SETTINGS",
    5: "PUSH_PROMISE", 6: "PING", 7: "GOAWAY", 8: "WINDOW_UPDATE",
    9: "CONTINUATION",
}
SETTING_NAMES = {
    1: "HEADER_TABLE_SIZE", 2: "ENABLE_PUSH", 3: "MAX_CONCURRENT_STREAMS",
    4: "INITIAL_WINDOW_SIZE", 5: "MAX_FRAME_SIZE", 6: "MAX_HEADER_LIST_SIZE",
    8: "ENABLE_CONNECT_PROTOCOL",
}


def ensure_cert(openssl: str) -> None:
    if CERT.exists() and KEY.exists():
        return
    WORK.mkdir(parents=True, exist_ok=True)
    conf = WORK / "openssl.cnf"
    conf.write_text(
        "[req]\ndistinguished_name=dn\nx509_extensions=v3\nprompt=no\n"
        "[dn]\nCN=localhost\n"
        "[v3]\nsubjectAltName=DNS:localhost,IP:127.0.0.1\n"
        "basicConstraints=CA:FALSE\n",
    )
    subprocess.run(  # noqa: S603
        [openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-keyout", str(KEY), "-out", str(CERT), "-days", "30",
         "-config", str(conf)],
        check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    print(f"generated self-signed cert at {CERT}")


GREASE = {0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
          0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa}


def peek_client_hello(sock: socket.socket, limit: int = 16384) -> bytes:
    """Return the raw ClientHello without consuming it from the socket.

    The ClientHello goes out in the clear before any key exchange, so unlike the
    HTTP/2 side there is nothing to decrypt - MSG_PEEK leaves the bytes in the
    kernel buffer for wrap_socket() to read normally afterwards. This is what
    makes a packet capture unnecessary for the TLS layer.
    """
    buf = b""
    while True:
        try:
            buf = sock.recv(limit, socket.MSG_PEEK)
        except OSError:
            return b""
        if len(buf) < 5:
            if not buf:
                return b""
            continue
        need = 5 + struct.unpack("!H", buf[3:5])[0]
        if len(buf) >= need or len(buf) >= limit:
            return buf[:need]


def parse_client_hello(record: bytes) -> dict | None:
    """Pull out the parts that a fingerprint depends on, lengths included."""
    if len(record) < 6 or record[0] != 0x16 or record[5] != 0x01:
        return None
    body = record[5:]
    n = int.from_bytes(body[1:4], "big")
    b = body[4:4 + n]

    o = 2 + 32
    sid_len = b[o]
    o += 1 + sid_len
    cs_len = struct.unpack_from("!H", b, o)[0]
    ciphers = [struct.unpack_from("!H", b, o + 2 + i)[0] for i in range(0, cs_len, 2)]
    o += 2 + cs_len
    o += 1 + b[o]                                    # compression methods
    ext_len = struct.unpack_from("!H", b, o)[0]
    o += 2
    end = o + ext_len

    exts = []
    while o < end:
        etype, elen = struct.unpack_from("!HH", b, o)
        o += 4
        exts.append({
            "type": etype,
            "hex": f"0x{etype:04x}",
            "length": elen,
            "grease": etype in GREASE,
            # Only GREASE bodies are dumped: everything else is either huge
            # (key_share) or per-connection random (ECH), and the length is the
            # part that matters for reproducing the wire format.
            "body": b[o:o + elen].hex() if etype in GREASE else None,
        })
        o += elen

    return {
        "record_version": f"0x{struct.unpack_from('!H', record, 1)[0]:04x}",
        "legacy_version": f"0x{struct.unpack_from('!H', b, 0)[0]:04x}",
        "session_id_len": sid_len,
        "cipher_suites": [f"0x{c:04x}" for c in ciphers],
        "extensions": exts,
        "raw": record.hex(),
    }


def read_exactly(sock: ssl.SSLSocket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            msg = "peer closed mid-frame"
            raise ConnectionError(msg)
        buf += chunk
    return buf


def read_frame(sock: ssl.SSLSocket) -> tuple[int, int, int, bytes]:
    head = read_exactly(sock, 9)
    length = int.from_bytes(head[:3], "big")
    ftype, flags = head[3], head[4]
    stream = struct.unpack("!I", head[5:9])[0] & 0x7FFFFFFF
    return ftype, flags, stream, read_exactly(sock, length)


def describe(ftype: int, flags: int, stream: int, payload: bytes) -> dict:
    out: dict = {
        "type": FRAME_TYPES.get(ftype, f"UNKNOWN({ftype})"),
        "flags": flags,
        "stream": stream,
        "length": len(payload),
    }
    if ftype == 4:  # SETTINGS
        out["settings"] = [
            {"id": sid, "name": SETTING_NAMES.get(sid, str(sid)), "value": val}
            for sid, val in (
                struct.unpack("!HI", payload[i:i + 6])
                for i in range(0, len(payload), 6)
            )
        ]
    elif ftype == 8:  # WINDOW_UPDATE
        out["increment"] = struct.unpack("!I", payload)[0] & 0x7FFFFFFF
    elif ftype == 1:  # HEADERS
        body = payload
        if flags & 0x08:  # PADDED
            body = body[1:]
        if flags & 0x20:  # PRIORITY
            dep = struct.unpack("!I", body[:4])[0]
            out["priority"] = {
                "exclusive": bool(dep >> 31),
                "depends_on": dep & 0x7FFFFFFF,
                "weight": body[4] + 1,
            }
            body = body[5:]
        out["header_block"] = body.hex()
    return out


def serve(args: argparse.Namespace) -> int:
    ensure_cert(args.openssl)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(CERT), str(KEY))
    ctx.set_alpn_protocols(["h2", "http/1.1"])

    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", args.port))  # noqa: S104 - must be reachable from Windows
    srv.listen(8)
    print(f"listening on :{args.port} — waiting for an h2 client "
          f"(https://localhost:{args.port}/api/all)")

    while True:
        raw, peer = srv.accept()
        # Peek first: wrap_socket() would consume the ClientHello.
        client_hello = parse_client_hello(peek_client_hello(raw))
        try:
            sock = ctx.wrap_socket(raw, server_side=True)
        except ssl.SSLError as exc:
            print(f"  {peer[0]}: TLS failed ({exc.reason})")
            raw.close()
            continue

        if sock.selected_alpn_protocol() != "h2":
            print(f"  {peer[0]}: negotiated "
                  f"{sock.selected_alpn_protocol()!r}, not h2 — ignoring")
            sock.close()
            continue

        try:
            record = handle_h2(sock)
        except (ConnectionError, ssl.SSLError, struct.error) as exc:
            print(f"  {peer[0]}: {type(exc).__name__}: {exc}")
            sock.close()
            continue
        sock.close()

        if record is None:
            continue
        record["client_hello"] = client_hello
        record["captured_at"] = datetime.datetime.now(
            datetime.timezone.utc).replace(microsecond=0).isoformat()
        Path(args.out).write_text(json.dumps(record, indent=2))
        print(f"  captured from {peer[0]} -> {args.out}")
        if client_hello:
            g = [e for e in client_hello["extensions"] if e["grease"]]
            print(f"    ClientHello   {len(client_hello['raw']) // 2}B, "
                  f"{len(client_hello['cipher_suites'])} ciphers, "
                  f"{len(client_hello['extensions'])} extensions"
                  + (f", GREASE bodies {[e['length'] for e in g]}" if g else ""))
        for f in record["frames"]:
            extra = ""
            if f["type"] == "SETTINGS" and f.get("settings"):
                extra = " " + ", ".join(
                    f"{x['name']}={x['value']}" for x in f["settings"])
            elif f["type"] == "WINDOW_UPDATE":
                extra = f" increment={f['increment']}"
            elif f["type"] == "HEADERS":
                extra = (f" priority={f.get('priority')}"
                         f" block={f['length']}B")
            print(f"    {f['type']:<14}{extra}")
        return 0


def handle_h2(sock: ssl.SSLSocket) -> dict | None:
    if read_exactly(sock, len(PREFACE)) != PREFACE:
        return None
    sock.sendall(b"\x00\x00\x00\x04\x00\x00\x00\x00\x00")  # empty SETTINGS

    frames = []
    while True:
        ftype, flags, stream, payload = read_frame(sock)
        frames.append(describe(ftype, flags, stream, payload))
        if ftype == 4 and not flags & 0x01:
            sock.sendall(b"\x00\x00\x00\x04\x01\x00\x00\x00\x00")  # ACK
        if ftype == 1 and flags & 0x04:  # HEADERS + END_HEADERS
            body = b"hi"
            # Just `:status: 200` - static index 8, one byte. Enough to keep
            # the client happy, and nothing else to get wrong.
            hdr = bytes([0x88])
            sock.sendall(
                struct.pack("!I", len(hdr))[1:] + b"\x01\x04"
                + struct.pack("!I", stream) + hdr)
            sock.sendall(
                struct.pack("!I", len(body))[1:] + b"\x00\x01"
                + struct.pack("!I", stream) + body)
            return {"frames": frames}


def client(args: argparse.Namespace) -> int:
    sys.path.insert(0, str(HERE))
    import chrome_h2  # noqa: F401  patches httpcore
    import httpx

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with httpx.Client(http2=True, verify=ctx, timeout=15) as c:
        try:
            c.get(f"https://localhost:{args.port}/api/all")
        except Exception as exc:  # noqa: BLE001 - server closes early by design
            print(f"(request ended with {type(exc).__name__}: {exc})")
    print("done — check the server's --out file")
    return 0


def _decode(block: bytes) -> list[tuple[str, str]]:
    """Decode for display only - hpack returns str or bytes by version."""
    import hpack

    def text(x: bytes | str) -> str:
        return x if isinstance(x, str) else x.decode("utf-8", "replace")

    return [(text(k), text(v)) for k, v in hpack.Decoder().decode(block)]


def diff_client_hello(a: dict | None, b: dict | None, na: str, nb: str) -> bool:
    """Compare the TLS side. GREASE values are wildcarded - they are meant to
    differ per connection - but their body *lengths* are not."""
    if a is None or b is None:
        print("=== ClientHello ===\n  (missing on one side, skipped)")
        return True

    def shape(ch):
        return {
            "record_version": ch["record_version"],
            "legacy_version": ch["legacy_version"],
            "session_id_len": ch["session_id_len"],
            "ciphers": ["GREASE" if int(c, 16) in GREASE else c
                        for c in ch["cipher_suites"]],
            # Sorted: both Chrome and we shuffle extension order on purpose,
            # so only the set and each body's length are comparable.
            "extensions": sorted(
                ("GREASE" if e["grease"] else e["hex"], e["length"])
                for e in ch["extensions"]),
            # These positions are not shuffled and are part of the shape.
            "first_ext": ("GREASE" if ch["extensions"][0]["grease"]
                          else ch["extensions"][0]["hex"]),
            "last_ext": ("GREASE" if ch["extensions"][-1]["grease"]
                         else ch["extensions"][-1]["hex"]),
        }

    sa, sb = shape(a), shape(b)
    print("=== ClientHello ===")
    same = True
    for key in sa:
        if sa[key] == sb[key]:
            print(f"  {key:<16} OK")
            continue
        same = False
        print(f"  {key:<16} DIFFER")
        if key == "extensions":
            seta, setb = dict(sa[key]), dict(sb[key])
            for name in sorted(set(seta) | set(setb)):
                if seta.get(name) != setb.get(name):
                    print(f"      {name}: {na}={seta.get(name, '-')} "
                          f"{nb}={setb.get(name, '-')}")
        else:
            print(f"      {na}: {sa[key]}")
            print(f"      {nb}: {sb[key]}")
    return same


def diff(args: argparse.Namespace) -> int:
    a = json.loads(Path(args.a).read_text())
    b = json.loads(Path(args.b).read_text())

    def headers_frame(rec):
        return next(f for f in rec["frames"] if f["type"] == "HEADERS")

    fa, fb = headers_frame(a), headers_frame(b)
    ba = bytes.fromhex(fa["header_block"])
    bb = bytes.fromhex(fb["header_block"])

    ok = diff_client_hello(a.get("client_hello"), b.get("client_hello"),
                           args.a, args.b)

    print(f"\n=== HPACK header block ===")
    print(f"{args.a}: {len(ba)} bytes")
    print(f"{args.b}: {len(bb)} bytes")

    ha, hb = _decode(ba), _decode(bb)
    if [k for k, _ in ha] != [k for k, _ in hb]:
        print("\n!! header NAMES/order differ - fix that before comparing bytes")
    for (ka, va), (kb, vb) in zip(ha, hb):
        if (ka, va) != (kb, vb):
            print(f"  value differs: {ka}={va!r} vs {kb}={vb!r}")

    if ba == bb:
        print("\nHPACK bytes are IDENTICAL")
        return 0 if ok else 1

    print("\nfirst differing byte offsets:")
    shown = 0
    for i in range(max(len(ba), len(bb))):
        x = ba[i:i + 1]
        y = bb[i:i + 1]
        if x != y:
            print(f"  @{i:4d}  {x.hex() or '--'}  vs  {y.hex() or '--'}")
            shown += 1
            if shown >= 20:
                print("  ...")
                break
    return 1


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("serve", help="capture one client's HEADERS frame")
    s.add_argument("--port", type=int, default=8443)
    s.add_argument("--out", default="capture.json")
    s.add_argument("--openssl", default=str(Path.home() / "openssl/bin/openssl"))
    s.set_defaults(func=serve)

    c = sub.add_parser("client", help="drive our own httpx client at the server")
    c.add_argument("--port", type=int, default=8443)
    c.set_defaults(func=client)

    d = sub.add_parser("diff", help="compare two captures byte by byte")
    d.add_argument("a")
    d.add_argument("b")
    d.set_defaults(func=diff)

    args = p.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
