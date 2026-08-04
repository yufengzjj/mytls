"""Capture the raw bytes a browser sends, so it and we can be diffed.

Runs a minimal HTTP/2 server over TLS and records the ClientHello and the first
HEADERS frame exactly as they arrived - the header block fragment is written out
verbatim, before anything decodes it. Point a browser at it to capture that
browser, then point our own client at it and compare.

    # wait for any browser at all
    python hpack_probe.py serve

    # Windows, fresh profile so no cookies/extensions get in the way
    chrome.exe --user-data-dir=%TEMP%\\cfp --ignore-certificate-errors ^
               https://localhost:8443/api/all

    # that is all - it stored profiles/chrome.json and browser_fp now has a
    # "chrome" transport
    python hpack_probe.py list
    python hpack_probe.py selftest

Which browser it was is read off the request it just sent, so nothing has to be
named up front - point Chrome, Firefox or a phone at the address and each lands
in its own file. A brand is a browser, not a browser version: capturing Chrome
again replaces profiles/chrome.json, and the version stays inside the capture.

A phone reaches this machine over the LAN, so it needs an address that is not
localhost, and a certificate that says so:

    python hpack_probe.py serve --host 192.168.1.5

--host goes into the certificate's SAN and is printed as the URL to open. iOS
Safari will offer to continue past the untrusted certificate; trusting it
properly (README) avoids the extra tap. Note that the address ends up in
`:authority` and decides whether an SNI is sent, so a LAN capture is only
reproducible from that same address - `where` prints it and selftest says so
when it cannot get there.

The page we serve back then has the browser fetch tls.peet.ws and post the
answer here, so the same visit also writes references/<brand>.json - what an
independent fingerprinter made of that browser, which is the one thing our own
parsing cannot check about itself. --no-reference skips it.

`selftest` does the whole loop in one process - stand up the server, drive our
own client at it, compare byte for byte - which is what proves a fresh build
still reproduces the captured browser. It needs no network.

Only the first HEADERS frame of a connection is recorded: the HPACK dynamic
table starts empty there, which is the only state both sides are guaranteed to
share.
"""

from __future__ import annotations

import argparse
import datetime
import ipaddress
import json
import os
import re
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time
import typing
from pathlib import Path

HERE = Path(__file__).resolve().parent
#: Kept in step with browser_fp.PROFILES_DIR, but spelled out here so capturing
#: does not depend on httpx being importable.
PROFILES_DIR = Path(os.environ.get("BROWSER_FP_PROFILES") or HERE / "profiles")
#: The other half: what tls.peet.ws made of the same browser. Only verify_fp.py
#: reads these, and only when checking against a live server.
REFERENCES_DIR = Path(os.environ.get("BROWSER_FP_REFERENCES") or HERE / "references")
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
    # RFC 9218. Safari announces it and still puts RFC 7540 priority on its
    # HEADERS frames, so the two are not alternatives in practice.
    9: "NO_RFC7540_PRIORITIES",
}


def profile_path(brand: str) -> Path:
    """Where `brand`'s capture lives. One file per brand, no version in the name."""
    if not re.fullmatch(r"[a-z][a-z0-9_]*", brand):
        msg = (f"bad brand {brand!r}: use lowercase letters, digits and "
               f"underscores, starting with a letter (chrome, chrome_android, "
               f"edge)")
        raise SystemExit(msg)
    if re.search(r"\d{2,}$", brand):
        print(f"note: {brand!r} looks like it carries a version. A brand is a "
              f"browser, not a browser version - the version is read off the "
              f"capture's user-agent, and one capture per brand means nothing "
              f"stays pinned to an old one.", file=sys.stderr)
    return PROFILES_DIR / f"{brand}.json"


def local_ipv4() -> str | None:
    """This machine's address on the network it routes through, or None.

    A UDP connect() sends nothing - it only asks the kernel which interface
    would be used - so this is free and works without name resolution. On WSL2
    it returns the VM's address, which is *not* what a phone can reach; see
    `serve --host`.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("10.255.255.255", 1))
        return s.getsockname()[0]
    except OSError:
        return None
    finally:
        s.close()


def can_bind(host: str) -> bool:
    """True if `host` is an address this machine actually holds.

    Binding to an address you do not own fails with EADDRNOTAVAIL, which is the
    only reliable answer - name resolution and gethostname() both lie under
    WSL, containers and split-horizon DNS.
    """
    s = socket.socket()
    try:
        s.bind((host, 0))
        return True
    except OSError:
        return False
    finally:
        s.close()


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return False
    return True


def _san(hosts: typing.Iterable[str]) -> str:
    """subjectAltName covering loopback plus whatever else was asked for."""
    names, ips = ["localhost"], ["127.0.0.1"]
    for host in hosts:
        (ips if _is_ip(host) else names).append(host)
    entries = [f"DNS:{n}" for n in dict.fromkeys(names)]
    entries += [f"IP:{i}" for i in dict.fromkeys(ips)]
    return ",".join(entries)


def ensure_cert(openssl: str, hosts: typing.Iterable[str] = ()) -> None:
    """Make sure the server cert covers every name a client might use.

    The SAN accumulates: a run without --host keeps the addresses an earlier
    run put in, because regenerating means re-installing on every phone that
    trusted the old one. iOS is the reason for the extensions - since iOS 13 a
    server certificate is rejected outright unless it has a SAN (CN is
    ignored), carries extendedKeyUsage=serverAuth and lives no longer than 398
    days.
    """
    stamp = WORK / "cert.san"
    have = stamp.read_text().split(",") if stamp.exists() else []
    want = _san(hosts)
    merged = ",".join(dict.fromkeys([*have, *want.split(",")]))
    # DNS entries first, IP after: order inside the extension is cosmetic, but
    # a stable spelling is what lets us compare against the stamp at all.
    merged = ",".join(sorted(merged.split(","), key=lambda e: e.startswith("IP:")))
    if CERT.exists() and KEY.exists() and merged == ",".join(have):
        return

    WORK.mkdir(parents=True, exist_ok=True)
    conf = WORK / "openssl.cnf"
    conf.write_text(
        "[req]\ndistinguished_name=dn\nx509_extensions=v3\nprompt=no\n"
        "[dn]\nCN=localhost\n"
        f"[v3]\nsubjectAltName={merged}\n"
        "basicConstraints=CA:FALSE\n"
        "keyUsage=digitalSignature,keyEncipherment\n"
        "extendedKeyUsage=serverAuth\n",
    )
    subprocess.run(  # noqa: S603
        [openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-keyout", str(KEY), "-out", str(CERT), "-days", "30",
         "-config", str(conf)],
        check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    stamp.write_text(merged)
    print(f"generated self-signed cert at {CERT}\n  valid for {merged}")
    if have:
        print("  the old one is gone - anything that trusted it has to trust "
              "this one instead")


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
    elif ftype == 2:  # PRIORITY
        dep = struct.unpack("!I", payload[:4])[0]
        out["priority"] = {
            "exclusive": bool(dep >> 31),
            "depends_on": dep & 0x7FFFFFFF,
            "weight": payload[4] + 1,
        }
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


# --- capturing --------------------------------------------------------------

def listen(port: int) -> socket.socket:
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port))  # noqa: S104 - must be reachable from Windows
    srv.listen(8)
    return srv


def tls_context(openssl: str, hosts: typing.Iterable[str] = ()) -> ssl.SSLContext:
    ensure_cert(openssl, hosts)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(CERT), str(KEY))
    ctx.set_alpn_protocols(["h2", "http/1.1"])
    # No session tickets, ever. Python's server hands them out by default, so a
    # browser that has been here before comes back with a pre_shared_key and the
    # capture is a *resumed* handshake - one extra extension, several hundred
    # bytes, and different every time depending on whether the user happened to
    # visit earlier. Our own client never resumes, so a capture that did is not
    # a usable reference.
    ctx.num_tickets = 0                     # TLS 1.3
    ctx.options |= ssl.OP_NO_TICKET         # TLS 1.2
    return ctx


class _Session:
    """What one capture run is collecting, shared across connections.

    A browser is not one connection. The navigation we capture arrives on one,
    and the page's fetch back to us may well arrive on another - Chrome is free
    to open a second connection to the same origin, and does. So connections are
    served concurrently and the results land here; the first HEADERS frame to
    arrive anywhere is the profile, and any /reference POST finishes the run.
    """

    def __init__(self, *, want_reference: bool, timeout: float, quiet: bool,
                 want_kinds: frozenset = frozenset()) -> None:
        self.want_reference = want_reference
        #: Kinds of peet response to hold out for; empty means the first will do.
        self.want_kinds = want_kinds
        self.timeout = timeout
        self.quiet = quiet
        self.lock = threading.Lock()
        self.record: dict | None = None
        self.reference: dict | None = None
        #: Set once the profile is captured: from then on we are only waiting
        #: for the reference, and only for so long.
        self.deadline: float | None = None
        self.done = threading.Event()

    def note(self, msg: str) -> None:
        if not self.quiet:
            print(msg, flush=True)

    def claim_record(self, record: dict) -> bool:
        """True if this connection is the one that captured the profile."""
        with self.lock:
            if self.record is not None:
                return False
            self.record = record
            self.deadline = time.monotonic() + self.timeout
        if not self.want_reference:
            self.done.set()
        return True

    def add_reference(self, part: dict) -> bool:
        """Merge in what one source answered; True once peet's half is in.

        The two sources arrive together when the browser can reach both, and
        separately when peet had to be pasted, so this accumulates rather than
        replaces. Only peet completes the run: check.ja3.zone alone is worth
        keeping but not worth stopping for, since the paste box is still up.
        """
        with self.lock:
            merged = {**(self.reference or {})}
            for name, value in part.items():
                if name == "peet":
                    merged["peet"] = _as_list(merged.get("peet")) + [value]
                else:
                    merged[name] = value
            self.reference = merged
            have = {peet_kind(e) for e in _as_list(merged.get("peet"))}
            complete = bool(have) and self.want_kinds <= have
        if complete:
            self.done.set()
        return complete

    def extend(self, seconds: float) -> None:
        """Keep waiting - the page failed automatically and offered a paste box."""
        with self.lock:
            if self.deadline is not None:
                self.deadline = max(self.deadline, time.monotonic() + seconds)

    def missing(self) -> list[str]:
        """Which kinds of peet response the run is still holding out for."""
        with self.lock:
            have = {peet_kind(e) for e in _as_list((self.reference or {}).get("peet"))}
        return sorted((self.want_kinds or {"any"}) - have)

    def expired(self) -> bool:
        return self.deadline is not None and time.monotonic() > self.deadline


def _serve_connection(raw: socket.socket, peer: tuple, ctx: ssl.SSLContext,
                      state: _Session) -> None:
    # Peek first: wrap_socket() would consume the ClientHello.
    client_hello = parse_client_hello(peek_client_hello(raw))
    try:
        sock = ctx.wrap_socket(raw, server_side=True)
    except ssl.SSLError as exc:
        state.note(f"  {peer[0]}: TLS failed ({exc.reason})")
        raw.close()
        return

    if sock.selected_alpn_protocol() != "h2":
        state.note(f"  {peer[0]}: negotiated "
                   f"{sock.selected_alpn_protocol()!r}, not h2 - ignoring")
        sock.close()
        return

    try:
        handle_h2(sock, state, client_hello=client_hello, peer=peer[0])
    except (ConnectionError, ssl.SSLError, struct.error, TimeoutError) as exc:
        state.note(f"  {peer[0]}: {type(exc).__name__}: {exc}")
    finally:
        _graceful_close(sock)


def _graceful_close(sock: ssl.SSLSocket) -> None:
    """Let the peer read our last response before the socket goes away.

    Closing while inbound data is still unread makes the kernel answer with RST,
    which throws away everything we just wrote - the page would see its POST
    fail even though the file is already on disk.
    """
    try:
        sock.settimeout(1.0)
        sock.shutdown(socket.SHUT_WR)
        while sock.recv(65536):
            pass
    except OSError:
        pass
    finally:
        sock.close()


def capture(srv: socket.socket, ctx: ssl.SSLContext, *, quiet: bool = False,
            want_reference: bool = False, timeout: float = 25.0,
            want_kinds: frozenset = frozenset()) -> dict | None:
    """Serve until the profile is captured (and the reference, if asked for).

    Returns None if the listening socket is closed from under us, which is how
    selftest stops a capture that never arrived.
    """
    state = _Session(want_reference=want_reference, timeout=timeout, quiet=quiet,
                     want_kinds=want_kinds)
    threads: list[threading.Thread] = []
    srv.settimeout(0.5)

    while not state.done.is_set() and not state.expired():
        try:
            raw, peer = srv.accept()
        except TimeoutError:
            continue
        except OSError:
            if state.record is None:
                return None
            break
        t = threading.Thread(target=_serve_connection,
                             args=(raw, peer, ctx, state), daemon=True)
        t.start()
        threads.append(t)

    # Long enough for the winning connection to finish writing its response -
    # the page is waiting on that 200 to say it is done.
    for t in threads:
        t.join(timeout=2)

    if state.record is not None and state.reference is not None:
        state.record["reference"] = state.reference
    return state.record


def summarise(record: dict) -> None:
    client_hello = record.get("client_hello")
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
            extra = f" priority={f.get('priority')} block={f['length']}B"
        print(f"    {f['type']:<14}{extra}")


def headers_of(record: dict) -> dict[str, str]:
    """The captured request headers, decoded. Only for reading who sent it."""
    frame = next(f for f in record["frames"] if f["type"] == "HEADERS")
    return dict(_decode(bytes.fromhex(frame["header_block"])))


def brand_of(record: dict) -> str:
    """Which brand this capture is, according to the client's own user-agent."""
    sys.path.insert(0, str(HERE))
    import browser_fp

    return browser_fp.brand_for(headers_of(record))


def serve(args: argparse.Namespace) -> int:
    """Capture one client and store it under the brand it says it is.

    The browser identifies itself in the request it just sent, so the brand is
    read off the capture rather than typed in beforehand: point any browser at
    the address, and it lands in the right file. --brand overrides that, --out
    stores at a path without registering a brand at all.
    """
    if args.brand and args.out:
        print("give --brand or --out, not both", file=sys.stderr)
        return 2
    if args.brand:
        profile_path(args.brand)          # reject a bad name before we listen

    # A path capture has nowhere to file a reference, and our own client cannot
    # run the page's javascript, so asking for one would only waste the timeout.
    want_reference = not args.out and not args.no_reference

    hosts = [h.strip() for h in (args.host or "").split(",") if h.strip()]
    detected = local_ipv4()
    if detected:
        hosts.append(detected)
    ctx = tls_context(args.openssl, hosts)
    srv = listen(args.port)

    reach = hosts[0] if hosts else "localhost"
    print(f"listening on :{args.port} - waiting for any h2 client "
          f"(https://{reach}:{args.port}/api/all)")
    if hosts and not can_bind(hosts[0]):
        # Under WSL2 the VM sits behind NAT, so the address a phone can reach
        # is the Windows host's and packets only arrive if Windows forwards
        # them. Saying so here beats a browser that just hangs.
        print(f"  {hosts[0]} is not an address this machine holds, so nothing "
              f"will arrive unless it is forwarded here. Under WSL2, either "
              f"set networkingMode=mirrored in .wslconfig, or from an admin "
              f"PowerShell:\n"
              f"    netsh interface portproxy add v4tov4 listenport={args.port}"
              f" listenaddress=0.0.0.0 connectport={args.port} "
              f"connectaddress={detected or '<wsl-ip>'}\n"
              f"    netsh advfirewall firewall add rule name=hpack_probe "
              f"dir=in action=allow protocol=TCP localport={args.port}")

    record = capture(srv, ctx, want_reference=want_reference,
                     timeout=args.reference_timeout,
                     want_kinds=frozenset({"navigate", "cors"}) if args.both
                     else frozenset())
    srv.close()
    if record is None:
        return 1

    peer = record.pop("peer", "?")
    reference = record.pop("reference", None)
    if args.out:
        out, brand = Path(args.out), None
    else:
        try:
            brand = args.brand or brand_of(record)
        except Exception as exc:  # noqa: BLE001 - the capture is worth keeping
            fallback = Path("capture.json")
            fallback.write_text(json.dumps(record, indent=2))
            print(f"  captured from {peer}, but {exc}\n"
                  f"  kept it at {fallback} - re-run with --brand, or move it "
                  f"into {PROFILES_DIR} yourself", file=sys.stderr)
            return 1
        out = profile_path(brand)
        out.parent.mkdir(parents=True, exist_ok=True)
        record = {"brand": brand, **record}

    replacing = out.exists()
    out.write_text(json.dumps(record, indent=2))
    ua = headers_of(record).get("user-agent", "?")
    print(f"  captured from {peer}: {ua}")
    print(f"  {'replaced' if replacing else 'stored as'} {out}")

    # We refuse to issue tickets, but a browser that collected one before that
    # was true still offers it, and the capture is then a resumed handshake.
    ch = record.get("client_hello") or {}
    if any(e["hex"] == "0x0029" for e in ch.get("extensions", [])):
        print("  !! this ClientHello carries pre_shared_key: the browser resumed "
              "a session it had from an earlier visit, so the capture has one "
              "extension our client never sends. Re-capture from a fresh "
              "browser profile (a new --user-data-dir).", file=sys.stderr)

    if brand and reference:
        ref_out = REFERENCES_DIR / f"{brand}.json"
        REFERENCES_DIR.mkdir(parents=True, exist_ok=True)
        was = ref_out.exists()
        previous = json.loads(ref_out.read_text()) if was else {}
        if "tls" in previous:                 # the pre-container format
            previous = {"peet": previous}
        merged = merge_reference(previous, reference, ua)
        ref_out.write_text(json.dumps(
            {"brand": brand, "collected_at": record["captured_at"], **merged},
            indent=2))
        detail = [f"peet {peet_kind(e) or '?'} "
                  f"ja4 {e.get('tls', {}).get('ja4', '?')}"
                  for e in _as_list(merged.get("peet"))]
        if merged.get("ja3zone"):
            detail.append(f"ja3 {merged['ja3zone'].get('hash', '?')}")
        print(f"  {'replaced' if was else 'stored as'} {ref_out}"
              f"  ({'; '.join(detail) or 'empty'})")
        if not merged.get("peet"):
            print("  (no tls.peet.ws half: the xhr header template cannot be "
                  "derived without it, and verify_fp.py has less to compare)")
    elif want_reference:
        print("  no reference at all - the browser reached neither service. "
              "Everything except `verify_fp.py` still works.")

    summarise(record)
    if brand:
        report_profile(brand)
    return 0


def report_profile(brand: str) -> None:
    """Show what the freshly captured brand now looks like to browser_fp.

    Capturing is the whole act of adding a browser - there is no code to write
    afterwards - so the capture step is where you get to see the transport it
    produced.
    """
    sys.path.insert(0, str(HERE))
    try:
        import browser_fp
        browser_fp.reload()
        print()
        print(browser_fp.describe(brand))
    except Exception as exc:  # noqa: BLE001 - the capture is already saved
        print(f"\n(capture saved, but browser_fp could not read it back: "
              f"{type(exc).__name__}: {exc})", file=sys.stderr)


#: Served to the browser once its request has been captured, to collect the
#: other half of the picture. tls.peet.ws reports the fingerprint of whoever
#: asks, so the only way to learn what the *real* browser looks like there is to
#: have the real browser ask - which is what this page does, before posting the
#: answer back to us.
#:
#: Two sources, because only one of them can be reached from a plain browser:
#:
#: * check.ja3.zone answers `access-control-allow-origin: *` on the response
#:   itself, so every browser can fetch it - a phone included, with no flags. It
#:   only reports JA3, but JA3 *is* the thing our own parsing cannot check about
#:   itself, since a ClientHello can never be compared byte for byte.
#: * tls.peet.ws reports far more (ja4, peetprint, the whole h2 layer) but only
#:   sends CORS headers on the OPTIONS preflight, never on the GET, so a plain
#:   browser blocks it. Two ways round that, both offered by the page: start the
#:   browser with --disable-web-security (renderer-side only, it does not touch
#:   the network stack, so the capture is unaffected), or open peet in a tab and
#:   paste the JSON back.
PEET_URL = "https://tls.peet.ws/api/all"
JA3_URL = "https://check.ja3.zone/"

PAGE = ("""<!doctype html>
<meta charset="utf-8"><title>hpack_probe</title>
<style>body{font:14px/1.6 system-ui;margin:3em;max-width:46em}
code{background:#eee;padding:2px 4px}textarea{width:100%%;font:12px monospace}
#f{margin-top:2em;padding:1em;border:1px solid #ccc;border-radius:6px}</style>
<body>
<p id="s">captured. collecting the reference...</p>
<div id="f">
  <p id="w"></p>
  <p>The fetch above is an <b>XHR</b>, and a browser does not send the same
  headers for one of those as for a <b>navigation</b>. To record the navigation
  variant too, <a href="%(peet)s" target="_blank" rel="noopener">open %(peet)s</a>
  in a tab and bring the JSON back here. On a phone, do not drag out a
  selection: <b>long-press the text &rarr; Select All &rarr; Copy</b>, come back
  and press the button.</p>
  <p><button id="c" hidden>read the clipboard</button></p>
  <textarea id="t" rows="6" placeholder="...or paste the JSON in here"></textarea>
  <p><button id="b">save it</button> <button id="d">skip</button></p>
</div>
<script>
const say = t => document.getElementById("s").textContent = t;
const post = b => fetch("/reference", {method: "POST", body: b});
// Cache-busted through the URL, not {cache:"no-store"} - that option makes
// Chrome add `pragma: no-cache` and `cache-control: no-cache`, which would
// then be in the reference as if the browser always sent them.
const grab = u => fetch(u + (u.indexOf("?") < 0 ? "?" : "&") + "_=" + Date.now())
                    .then(r => r.json()).catch(() => null);
const warn = t => document.getElementById("w").innerHTML = t;
Promise.all([grab("%(peet)s"), grab("%(ja3)s")]).then(([peet, ja3zone]) => {
  post(JSON.stringify({peet: peet, ja3zone: ja3zone})).then(() => {
    say(peet ? "captured, and the tls.peet.ws reference with it"
             : (ja3zone ? "captured; check.ja3.zone answered but tls.peet.ws did not"
                        : "captured; no reference could be collected"));
    if (!peet) {
      warn("<b>The browser blocked the tls.peet.ws fetch</b> - it sends no CORS "
         + "header on the response itself. Starting the browser with "
         + "<code>--user-data-dir=&lt;temp&gt; --disable-web-security</code> "
         + "lets it through; otherwise paste it below.");
    }
  });
});
const ta = document.getElementById("t");
// Checked here rather than server-side: a half-selected copy is the likely
// mistake, and the person who can fix it is looking at this page.
const send = text => {
  try { JSON.parse(text); } catch (e) {
    say("that is not whole JSON - copy all of %(peet)s, not part of it");
    return;
  }
  post(text).then(() => fetch("/reference/done", {method: "POST"}))
            .then(() => say("done - saved the pasted navigation as well"));
};
document.getElementById("b").onclick = () => send(ta.value);
// One tap instead of long-pressing the box and hunting for Paste. Safari shows
// its own confirmation before handing the clipboard over, so this cannot read
// anything behind the user's back; where it is unavailable the box still is.
if (navigator.clipboard && navigator.clipboard.readText) {
  const c = document.getElementById("c");
  c.hidden = false;
  c.onclick = () => navigator.clipboard.readText()
    .then(t => { ta.value = t; send(t); })
    .catch(() => say("the browser kept the clipboard to itself - use the box"));
}
document.getElementById("d").onclick = () =>
  fetch("/reference/done", {method: "POST"})
    .then(() => say("done - you can close this tab"));
</script>
""" % {"peet": PEET_URL, "ja3": JA3_URL}).encode()

MAX_REFERENCE = 1 << 20
#: Extra time granted once the page has told us its fetch was blocked and put a
#: paste box on screen. Long enough to open a tab, copy and paste.
PASTE_GRACE = 180.0


def reference_part(body: bytes) -> dict | None:
    """What one POST to /reference carries, or None if it carries nothing.

    Either the page's own `{"peet": ..., "ja3zone": ...}` - with nulls for
    whatever it could not reach - or a bare tls.peet.ws response pasted in by
    hand, which is recognisable by its "tls" key.
    """
    try:
        data = json.loads(body)
    except ValueError:
        return None
    if not isinstance(data, dict):
        return None
    if "tls" in data:
        return {"peet": data}
    part = {k: v for k, v in data.items() if k in ("peet", "ja3zone") and v}
    return part or None


def peet_kind(entry: dict) -> str | None:
    """`navigate` or `cors` - which kind of request this peet response describes."""
    for frame in (entry or {}).get("http2", {}).get("sent_frames", []):
        if frame.get("frame_type") != "HEADERS":
            continue
        sent = dict(h.split(": ", 1) for h in frame.get("headers", []) if ": " in h)
        return sent.get("sec-fetch-mode")
    return None


def _as_list(value: typing.Any) -> list:
    if not value:
        return []
    return value if isinstance(value, list) else [value]


def merge_reference(previous: dict, fresh: dict, user_agent: str) -> dict:
    """Keep the kinds this visit could not produce, if it is the same browser.

    One visit yields one kind: the page's own fetch is always `cors`, and the
    `navigate` variant only arrives when the JSON is pasted in from a real
    navigation. Both are worth having - navigate is where the default header
    template's `referer` position comes from - so they accumulate rather than
    replace. A capture from a different browser build drops the old entries
    instead, since a stale order is worse than a derived one.
    """
    entries = [e for e in _as_list(fresh.get("peet")) if e]
    kinds = {peet_kind(e) for e in entries}
    for old in _as_list(previous.get("peet")):
        if not old or old.get("user_agent") != user_agent:
            continue
        if peet_kind(old) in kinds:
            continue
        entries.append(old)
        kinds.add(peet_kind(old))

    ja3zone = fresh.get("ja3zone")
    if not ja3zone:
        old = previous.get("ja3zone")
        ja3zone = old if old and old.get("user_agent") == user_agent else None

    out: dict = {}
    if entries:
        out["peet"] = entries
    if ja3zone:
        out["ja3zone"] = ja3zone
    return out


def send_response(sock: ssl.SSLSocket, encoder, stream: int, status: bytes,
                  ctype: bytes, body: bytes) -> None:
    """One HEADERS + one DATA. Bodies here are far below any max frame size."""
    hdr = encoder.encode([(b":status", status), (b"content-type", ctype),
                          (b"content-length", str(len(body)).encode()),
                          (b"cache-control", b"no-store")])
    sock.sendall(struct.pack("!I", len(hdr))[1:] + b"\x01\x04"
                 + struct.pack("!I", stream) + hdr)
    sock.sendall(struct.pack("!I", len(body))[1:] + b"\x00\x01"
                 + struct.pack("!I", stream) + body)


def handle_h2(sock: ssl.SSLSocket, state: _Session, *,
              client_hello: dict | None = None, peer: str = "?") -> None:
    """Serve one connection, contributing whatever it carries to `state`.

    The profile is finished the moment the first request arrives anywhere and is
    never affected by what follows: its frame list is frozen there, so serving a
    page and taking a POST back cannot contaminate it.
    """
    import hpack

    if read_exactly(sock, len(PREFACE)) != PREFACE:
        return
    sock.sendall(b"\x00\x00\x00\x04\x00\x00\x00\x00\x00")  # empty SETTINGS

    # Every HEADERS block on the connection has to go through one decoder, in
    # order, or the HPACK dynamic table desyncs and later blocks fail to decode.
    decoder, encoder = hpack.Decoder(), hpack.Encoder()
    frames: list[dict] = []
    capturing = state.record is None
    bodies: dict[int, bytearray] = {}

    while not state.done.is_set():
        if state.deadline is not None:
            remaining = state.deadline - time.monotonic()
            if remaining <= 0:
                return
            sock.settimeout(remaining)
        try:
            ftype, flags, stream, payload = read_frame(sock)
        except (TimeoutError, ConnectionError, ssl.SSLError, struct.error):
            if capturing and state.record is None:
                raise
            return          # the profile is safe; the reference is optional

        if capturing:
            frames.append(describe(ftype, flags, stream, payload))

        if ftype == 4 and not flags & 0x01:
            sock.sendall(b"\x00\x00\x00\x04\x01\x00\x00\x00\x00")  # ACK

        elif ftype == 1 and flags & 0x04:  # HEADERS + END_HEADERS
            info = describe(ftype, flags, stream, payload)
            headers = dict(
                (k if isinstance(k, str) else k.decode(),
                 v if isinstance(v, str) else v.decode())
                for k, v in decoder.decode(bytes.fromhex(info["header_block"])))
            path, method = headers.get(":path", ""), headers.get(":method", "")

            if capturing:
                capturing = False
                record = {
                    "frames": frames,
                    "client_hello": client_hello,
                    "captured_at": datetime.datetime.now(
                        datetime.timezone.utc).replace(microsecond=0).isoformat(),
                    "peer": peer,
                }
                if state.claim_record(record) and not state.want_reference:
                    send_response(sock, encoder, stream, b"200", b"text/plain", b"hi")
                    return
                send_response(sock, encoder, stream, b"200", b"text/html", PAGE)
                state.note(f"  waiting up to {state.timeout:.0f}s for the browser "
                           f"to fetch tls.peet.ws (keep the tab open)")

            elif method == "POST" and path.startswith("/reference/done"):
                send_response(sock, encoder, stream, b"200", b"text/plain", b"ok")
                state.done.set()
                return

            elif method == "POST" and path.startswith("/reference"):
                bodies[stream] = bytearray()

            elif method == "GET" and not path.startswith("/favicon"):
                # Any connection serves the page: after clicking through the
                # certificate warning the browser may retry on a fresh one.
                send_response(sock, encoder, stream, b"200", b"text/html", PAGE)

            else:
                send_response(sock, encoder, stream, b"404", b"text/plain", b"")

        elif ftype == 0 and stream in bodies:  # DATA for the reference POST
            bodies[stream] += payload
            if len(bodies[stream]) > MAX_REFERENCE:
                del bodies[stream]
                send_response(sock, encoder, stream, b"413", b"text/plain", b"")
            elif flags & 0x01:  # END_STREAM
                send_response(sock, encoder, stream, b"200", b"text/plain", b"ok")
                body = bytes(bodies.pop(stream))
                part = reference_part(body)
                if part is None:
                    state.note(f"  unusable reply from the page "
                               f"({body[:120].decode('utf-8', 'replace') or 'empty'})")
                    state.extend(PASTE_GRACE)
                    continue
                state.note(f"  reference: {', '.join(sorted(part))} "
                           f"({len(body)} bytes)")
                if state.add_reference(part):
                    return
                # Still short of what was asked for; the paste box is up.
                missing = state.missing()
                state.note(
                    f"  still missing the {' and '.join(missing)} variant of "
                    f"tls.peet.ws - paste it into the page or press skip"
                    if missing != ["any"] else
                    f"  tls.peet.ws is still missing - paste its JSON into the "
                    f"page or press skip")
                state.extend(PASTE_GRACE)


# --- driving our own client -------------------------------------------------

def run_client(authority: str, brand: str | None, *, quiet: bool = False,
               like: dict[str, str] | None = None) -> None:
    """Send one request through the brand's transport at our own server.

    `authority` and not a port: it goes into the HPACK block verbatim and
    decides whether an SNI is sent, so a capture can only be reproduced by
    addressing the server exactly the way the browser did.

    `like` is a set of captured headers to imitate the *kind* of request from.
    Which browser sent a capture is one thing; how it got there is another, and
    three headers depend on the latter - a navigation reached by tapping a link
    carries `sec-fetch-site: cross-site` and a `referer`, a reload adds
    `cache-control`, and a page's own fetch is `sec-fetch-mode: cors`. Without
    this a capture taken any way but by typing the address into a fresh tab
    could never be reproduced, which says nothing about the fingerprint.
    """
    sys.path.insert(0, str(HERE))
    import browser_fp
    import httpx

    headers: dict[str, str] = {}
    if like is not None:
        prof = browser_fp.profile(brand)
        if like.get("sec-fetch-mode") == "cors":
            prof.header_profile = "xhr"
        prof.sec_fetch_site = like.get("sec-fetch-site")
        prof.send_cache_control = "cache-control" in like
        if "referer" in like:
            headers["Referer"] = like["referer"]

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    # verify goes on the transport: httpx ignores its own when given one.
    transport = browser_fp.Transport(brand, verify=ctx)
    with httpx.Client(transport=transport, timeout=15) as c:
        try:
            c.get(f"https://{authority}/api/all", headers=headers)
        except Exception as exc:  # noqa: BLE001 - server closes early by design
            if not quiet:
                print(f"(request ended with {type(exc).__name__}: {exc})")


def client(args: argparse.Namespace) -> int:
    run_client(f"{args.host}:{args.port}", args.brand)
    print("done - check the server's output file")
    return 0


# --- comparing --------------------------------------------------------------

def _decode(block: bytes) -> list[tuple[str, str]]:
    """Decode for display only - hpack returns str or bytes by version."""
    import hpack

    def text(x: bytes | str) -> str:
        return x if isinstance(x, str) else x.decode("utf-8", "replace")

    return [(text(k), text(v)) for k, v in hpack.Decoder().decode(block)]


def akamai_fingerprint(rec: dict) -> str:
    """The akamai HTTP/2 fingerprint of a capture.

    Four fields: the client's SETTINGS in wire order, the connection-level
    WINDOW_UPDATE, any standalone PRIORITY frames, and the pseudo-header order.
    browser_fp derives exactly these from a capture, so this is what tells you
    whether a new capture needs any code change at all.
    """
    frames = rec["frames"]

    def find(kind, pred=lambda _f: True):
        return next((f for f in frames if f["type"] == kind and pred(f)), None)

    # An ACK carries no payload, so an empty settings list is not the client's.
    settings = find("SETTINGS", lambda f: bool(f.get("settings")) and not f["flags"] & 0x01)
    window = find("WINDOW_UPDATE", lambda f: f["stream"] == 0)
    headers = find("HEADERS")

    fields = [
        ";".join(f"{s['id']}:{s['value']}" for s in settings["settings"])
        if settings else "0",
        str(window["increment"]) if window else "0",
        ",".join(
            f"{f['stream']}:{int(f['priority']['exclusive'])}"
            f":{f['priority']['depends_on']}:{f['priority']['weight']}"
            for f in frames if f["type"] == "PRIORITY"
        ) or "0",
        ",".join(k[1] for k, _ in _decode(bytes.fromhex(headers["header_block"]))
                 if k.startswith(":")) if headers else "",
    ]
    return "|".join(fields)


def diff_h2(a: dict, b: dict, na: str, nb: str) -> bool:
    """Compare the akamai layer: SETTINGS, WINDOW_UPDATE, PRIORITY, pseudo-headers."""
    print("=== HTTP/2 frame layer ===")
    fa, fb = akamai_fingerprint(a), akamai_fingerprint(b)
    print(f"  {na}: {fa}")
    print(f"  {nb}: {fb}")

    names = ("settings", "window_update", "priority", "pseudo_headers")
    same = True
    for name, x, y in zip(names, fa.split("|"), fb.split("|")):
        if x == y:
            print(f"  {name:<16} OK")
            continue
        same = False
        print(f"  {name:<16} DIFFER\n      {na}: {x}\n      {nb}: {y}")

    # Not part of the fingerprint, but browser_fp reproduces it and a mismatch
    # here means the HEADERS frame has the wrong flags and length.
    def prio(rec):
        f = next((x for x in rec["frames"] if x["type"] == "HEADERS"), None)
        return f.get("priority") if f else None

    pa, pb = prio(a), prio(b)
    if pa == pb:
        print("  headers_priority OK")
    else:
        same = False
        print(f"  headers_priority DIFFER\n      {na}: {pa}\n      {nb}: {pb}")
    return same


def authority_of(rec: dict) -> str:
    """The `:authority` the capture was taken against.

    A capture is only byte-comparable against one taken at the same address.
    The whole string lands in the HPACK block, so `localhost:8443` and
    `192.168.1.5:8443` differ within the first few bytes - and the host half
    decides the ClientHello too, since an IP literal carries no SNI at all
    while a name does. Phone captures arrive over the LAN, so neither half can
    be assumed any more.
    """
    frame = next(f for f in rec["frames"] if f["type"] == "HEADERS")
    return dict(_decode(bytes.fromhex(frame["header_block"])))[":authority"]


def split_authority(authority: str) -> tuple[str, int]:
    host, sep, port = authority.rpartition(":")
    if not sep or (host.startswith("[") and not host.endswith("]")):
        return authority, 443
    return host, int(port)


def port_of(rec: dict) -> int:
    """Just the port half, for the places that only need to know where to listen."""
    return split_authority(authority_of(rec))[1]


#: Extensions whose body length is not constant even for one real browser, so
#: comparing it would fail at random. Only ECH so far: BoringSSL's GREASE ECH
#: carries a random payload and two Chrome 150 captures of the same URL came out
#: 218 and 250 bytes. The lengths are still printed, because a client that
#: always sends exactly one of them is its own kind of tell.
VARIABLE_LENGTH = {"0xfe0d"}

#: Extensions whose *body* carries per-connection randomness, so only their
#: shape can be compared. key_share is not in here: its bodies are handled
#: specially below, because the group ids in it are fingerprint material even
#: though the public keys beside them are fresh every time.
RANDOM_BODY = {"0xfe0d", "0x0029"}


def ext_bodies(ch: dict) -> dict[str, str]:
    """Extension bodies, re-parsed out of the stored raw ClientHello.

    The capture only keeps GREASE bodies inline, but it keeps the whole record,
    so the bodies are still there - and they have to be compared. Extension
    *lengths* alone hide real differences: Chrome and Safari both send a 12-byte
    supported_groups, listing entirely different groups.

    Values are rendered rather than returned raw, so that the parts which are
    meant to differ per connection do not show up as failures.
    """
    raw = bytes.fromhex(ch["raw"])
    o = 5 + 4 + 2 + 32
    o += 1 + raw[o]                                   # session_id
    o += 2 + int.from_bytes(raw[o:o + 2], "big")      # cipher_suites
    o += 1 + raw[o]                                   # compression methods
    o += 2                                            # extensions length
    out: dict[str, str] = {}
    while o + 4 <= len(raw):
        etype = int.from_bytes(raw[o:o + 2], "big")
        elen = int.from_bytes(raw[o + 2:o + 4], "big")
        body = raw[o + 4:o + 4 + elen]
        o += 4 + elen
        name = "GREASE" if etype in GREASE else f"0x{etype:04x}"
        if etype in GREASE:
            continue
        if name in RANDOM_BODY:
            out[name] = "(random)"
        elif etype == 51:                             # key_share
            out[name] = " ".join(_key_share_shape(body))
        elif etype in U16_LIST:
            out[name] = " ".join(_u16_list(body, U16_LIST[etype]))
        else:
            out[name] = body.hex()
    return out


#: Extensions carrying a list of 2-byte codepoints, and the width of the length
#: prefix in front of it. Rendered element by element rather than as raw hex
#: for two reasons: the GREASE entry inside has to be wildcarded like any other
#: GREASE, and a difference is far easier to place when the elements are split.
U16_LIST = {10: 2, 43: 1, 13: 2}   # supported_groups, supported_versions, sigalgs


def _u16_list(body: bytes, prefix: int) -> list[str]:
    return [("GREASE" if int.from_bytes(body[o:o + 2], "big") in GREASE
             else f"0x{int.from_bytes(body[o:o + 2], 'big'):04x}")
            for o in range(prefix, len(body) - 1, 2)]


def _key_share_shape(body: bytes) -> list[str]:
    """`group:keylen` per entry, GREASE wildcarded, the keys themselves dropped."""
    entries, o = [], 2
    while o + 4 <= len(body):
        group = int.from_bytes(body[o:o + 2], "big")
        n = int.from_bytes(body[o + 2:o + 4], "big")
        entries.append(f"{'GREASE' if group in GREASE else f'0x{group:04x}'}:{n}")
        o += 4 + n
    return entries


def diff_client_hello(a: dict | None, b: dict | None, na: str, nb: str) -> bool:
    """Compare the TLS side. GREASE values are wildcarded - they are meant to
    differ per connection - but their body *lengths* are not, except for
    VARIABLE_LENGTH."""
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
            # Sorted: both browsers and we shuffle extension order on purpose,
            # so only the set and each body's length are comparable.
            "extensions": sorted(
                ("GREASE" if e["grease"] else e["hex"],
                 "varies" if e["hex"] in VARIABLE_LENGTH else e["length"])
                for e in ch["extensions"]),
            # These positions are not shuffled and are part of the shape.
            "first_ext": ("GREASE" if ch["extensions"][0]["grease"]
                          else ch["extensions"][0]["hex"]),
            "last_ext": ("GREASE" if ch["extensions"][-1]["grease"]
                         else ch["extensions"][-1]["hex"]),
        }

    sa, sb = shape(a), shape(b)
    print("=== ClientHello ===")
    for hexid in sorted(VARIABLE_LENGTH):
        la, lb = (next((e["length"] for e in ch["extensions"] if e["hex"] == hexid), None)
                  for ch in (a, b))
        if la is not None or lb is not None:
            print(f"  {hexid:<16} {na}={la}B {nb}={lb}B"
                  + ("" if la == lb else "  (length varies per connection, not compared)"))
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

    ba, bb = ext_bodies(a), ext_bodies(b)
    differing = [k for k in sorted(set(ba) | set(bb)) if ba.get(k) != bb.get(k)]
    if differing:
        same = False
        print("  ext bodies       DIFFER")
        for k in differing:
            print(f"      {k}: {na}={_short(ba.get(k))}")
            print(f"      {' ' * len(k)}  {nb}={_short(bb.get(k))}")
    else:
        print("  ext bodies       OK")
    return same


def _short(value: str | None, limit: int = 72) -> str:
    if value is None:
        return "(absent)"
    return value if len(value) <= limit else f"{value[:limit]}... ({len(value)//2}B)"


def diff_records(a: dict, b: dict, na: str, nb: str) -> int:
    """Full comparison of two captures: TLS, h2 frames, then HPACK bytes."""
    def headers_frame(rec):
        return next(f for f in rec["frames"] if f["type"] == "HEADERS")

    ba = bytes.fromhex(headers_frame(a)["header_block"])
    bb = bytes.fromhex(headers_frame(b)["header_block"])

    ok = diff_client_hello(a.get("client_hello"), b.get("client_hello"), na, nb)
    print()
    ok &= diff_h2(a, b, na, nb)

    print("\n=== HPACK header block ===")
    print(f"{na}: {len(ba)} bytes")
    print(f"{nb}: {len(bb)} bytes")

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


def _load(name: str) -> tuple[dict, str]:
    """A capture, by path or by brand."""
    path = Path(name)
    if not path.exists():
        candidate = PROFILES_DIR / f"{name}.json"
        if candidate.exists():
            path = candidate
    return json.loads(path.read_text()), str(path)


def diff(args: argparse.Namespace) -> int:
    a, na = _load(args.a)
    b, nb = _load(args.b)
    return diff_records(a, b, na, nb)


# --- the self-test ----------------------------------------------------------

def selftest_one(brand: str, openssl: str, *, port: int | None = None) -> int:
    """Capture ourselves impersonating `brand` and diff it against the reference.

    Everything happens in this process and on loopback: the server runs in a
    thread while our own client drives a request at it. No network, so the same
    result on an air-gapped machine, and nothing to clean up if it fails.
    """
    ref, source = _load(brand)
    # The address is not free to choose: `:authority` is part of the HPACK
    # block and the host half decides whether an SNI goes out. Address the
    # server the way the captured browser did, or the comparison fails on
    # differences that mean nothing.
    authority = authority_of(ref)
    host, want = split_authority(authority)

    if port is not None and port != want:
        print(f"note: {brand} was captured on port {want}; using {port} instead "
              f"means :authority differs and the HPACK block cannot match. The "
              f"ClientHello and HTTP/2 layers are still meaningful.")
        authority = f"{host}:{port}"
    else:
        port = want

    if not can_bind(host):
        # A phone capture came in over the LAN, and that address belongs to
        # whatever the browser could reach - a router-assigned one that has
        # since changed, or under WSL the Windows host rather than this VM.
        print(f"note: {brand} was captured at {host}, which is not an address "
              f"this machine holds, so the request goes to localhost instead. "
              f":authority differs, so the HPACK block cannot match"
              + (", and the capture carried no SNI while this one does, so the "
                 "ClientHello will differ by one extension"
                 if _is_ip(host) else "")
              + ". The HTTP/2 layer is still compared in full.")
        authority = f"localhost:{port}"

    ctx = tls_context(openssl)
    try:
        srv = listen(port)
    except OSError as exc:
        print(f"cannot listen on :{port} ({exc}). The port cannot simply be "
              f"changed - it is baked into {source}'s :authority - so free it "
              f"and re-run.", file=sys.stderr)
        return 1

    got: list[dict] = []
    thread = threading.Thread(
        target=lambda: got.extend(filter(None, [capture(srv, ctx, quiet=True)])),
        daemon=True)
    thread.start()
    try:
        run_client(authority, brand, quiet=True, like=headers_of(ref))
    finally:
        thread.join(timeout=20)
        srv.close()
        thread.join(timeout=5)

    if not got:
        print(f"the probe captured nothing for {brand}", file=sys.stderr)
        return 1

    print(f"=== {brand}: our bytes vs {source} ===\n")
    return diff_records(ref, got[0], brand, "ours")


def selftest(args: argparse.Namespace) -> int:
    if args.brand:
        targets = [args.brand]
    else:
        targets = sorted(p.stem for p in PROFILES_DIR.glob("*.json"))
    if not targets:
        print(f"no profiles in {PROFILES_DIR} - capture one with "
              f"`serve --brand <name>`", file=sys.stderr)
        return 1

    results = {}
    for i, brand in enumerate(targets):
        if i:
            print()
        results[brand] = selftest_one(brand, args.openssl, port=args.port)

    if len(targets) > 1:
        print("\n=== summary ===")
        for brand, rc in results.items():
            print(f"  {brand:<16} {'PASS' if rc == 0 else 'FAIL'}")
    return 0 if all(rc == 0 for rc in results.values()) else 1


def list_profiles(_args: argparse.Namespace) -> int:
    sys.path.insert(0, str(HERE))
    import browser_fp
    print(browser_fp.catalog())
    return 0


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser(
        "serve",
        help="capture one client and store it as the brand it says it is")
    s.add_argument("--brand", help="override the brand read off the client's "
                                   "user-agent (one file per browser, no "
                                   "version in the name)")
    s.add_argument("--out", help="store at this path instead, without "
                                 "registering it as a brand")
    s.add_argument("--no-reference", action="store_true",
                   help="do not ask the browser to fetch tls.peet.ws; capture "
                        "the raw bytes only (offline machines)")
    s.add_argument("--both", action="store_true",
                   help="wait for both the XHR and the navigation variant of "
                        "the reference; the page's own fetch gives the first, "
                        "pasting tls.peet.ws into the page gives the second")
    s.add_argument("--reference-timeout", type=float, default=25.0,
                   help="how long to wait for that fetch (default 25s)")
    s.add_argument("--host", help="address the client will use, comma-separated "
                                  "if several; goes into the certificate's SAN "
                                  "and is printed as the URL to visit. Needed "
                                  "for a phone, which reaches this machine over "
                                  "the LAN and not on localhost")
    s.add_argument("--port", type=int, default=8443)
    s.add_argument("--openssl", default=str(Path.home() / "openssl/bin/openssl"))
    s.set_defaults(func=serve)

    c = sub.add_parser("client", help="drive our own httpx client at the server")
    c.add_argument("--brand", help="which profile to impersonate")
    c.add_argument("--host", default="localhost",
                   help="must match the capture's :authority to be comparable")
    c.add_argument("--port", type=int, default=8443)
    c.set_defaults(func=client)

    t = sub.add_parser(
        "selftest",
        help="capture ourselves and diff against a stored brand, offline")
    t.add_argument("--brand", help="default: every installed brand")
    t.add_argument("--port", type=int, help="override the reference's port")
    t.add_argument("--openssl", default=str(Path.home() / "openssl/bin/openssl"))
    t.set_defaults(func=selftest)

    ls = sub.add_parser("list", help="what browser_fp currently offers")
    ls.set_defaults(func=list_profiles)

    d = sub.add_parser("diff", help="compare two captures byte by byte")
    d.add_argument("a", help="path, or a brand name")
    d.add_argument("b", help="path, or a brand name")
    d.set_defaults(func=diff)

    p2 = sub.add_parser(
        "where", help="print the :authority a capture was taken at, which is "
                      "the only address it can be reproduced from")
    p2.add_argument("capture", help="path, or a brand name")
    p2.set_defaults(func=lambda a: (print(authority_of(_load(a.capture)[0])), 0)[1])

    args = p.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
