"""Capture the raw bytes a browser sends, so it and we can be diffed.

Runs a minimal HTTP/2 server over TLS and records the ClientHello and the first
HEADERS frame exactly as they arrived - the header block fragment is written out
verbatim, before anything decodes it. Point a browser at it to capture that
browser, then point our own client at it and compare.

    # wait for any browser at all; the raw dumps land in ./captures.
    # Browse for as long as you like, then Ctrl-C.
    mytls-probe serve

    # Windows, fresh profile so no cookies/extensions get in the way
    chrome.exe --user-data-dir=%TEMP%\\cfp --ignore-certificate-errors ^
               https://localhost:8443/api/all

    # then make a profile out of what arrived, and browser_fp has a "chrome"
    # transport
    mytls-probe import-mitm ./captures --brand chrome
    mytls-probe list
    mytls-probe selftest

On its own `serve` only *records*, and it keeps recording until interrupted -
the same shape as `capture-mitm`, against our own server rather than a real
site. One dump per connection, every request on it, in the layout mitm_addon.py
writes, so `import-mitm` and `match` read a capture taken here and one taken
through mitmproxy with the same code. Nothing is installed as a brand until you
say which brand it is - and a connection that never got as far as a request is
kept too, which is the only way to measure a client that refuses our
certificate.

`serve --brand chrome` is the one-step form, and the one that ends by itself:
capture until one profile is complete, take the connection that carried the
request, write profiles/chrome.json. A brand is a browser, not a browser
version: capturing Chrome again replaces profiles/chrome.json, and the version
stays inside the capture.

A phone reaches this machine over the LAN, so it needs an address that is not
localhost, and a certificate that says so:

    mytls-probe serve --host 192.168.1.5

--host goes into the certificate's SAN and is printed as the URL to open. iOS
Safari will offer to continue past the untrusted certificate; trusting it
properly (README) avoids the extra tap. Note that the address ends up in
`:authority` and decides whether an SNI is sent, so a LAN capture is only
reproducible from that same address - `where` prints it and selftest says so
when it cannot get there.

A capture is one page load with nothing to read and nothing to press. What an
outside service makes of the same client is not stored beside it: `mytls-verify`
asks tls.peet.ws and check.ja3.zone live, about our own client, and compares
their answers against fingerprints computed from this capture's raw bytes.

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
import hashlib
import ipaddress
import json
import os
import re
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time
import typing
from pathlib import Path

from . import fingerprints

HERE = Path(__file__).resolve().parent
#: Kept in step with browser_fp.PROFILES_DIR, but spelled out here so capturing
#: does not depend on httpx being importable.
PROFILES_DIR = Path(os.environ.get("BROWSER_FP_PROFILES") or HERE / "profiles")
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


def carried_meta(path: Path) -> dict:
    """The `meta` of the capture this run is about to replace.

    Everything else in a profile is re-read from the new dump, which is the
    point of re-capturing. `meta` is the one part no dump can produce - it is
    what a person knew and the bytes do not say - so a rewrite has to bring it
    across rather than drop it.

    Not cosmetic: `meta.tls_profile` is what points a brand at another brand's
    ClientHello, and without it the brand falls back to the library default.
    Re-capturing iOS 17 used to silently start sending Chrome's handshake -
    the HTTP/2 layer would still be iOS 17's, so nothing looked wrong until
    the self-test.
    """
    if not path.exists():
        return {}
    try:
        old = json.loads(path.read_text())
    except (OSError, ValueError):
        # Not a capture, or not readable: this is a best-effort rescue of a
        # file that is being replaced anyway, so it must never be what fails.
        return {}
    meta = old.get("meta") if isinstance(old, dict) else None
    return meta if isinstance(meta, dict) else {}


def profile_path(brand: str) -> Path:
    """Where `brand`'s capture lives. One file per brand, no version in the name."""
    if not re.fullmatch(r"[a-z][a-z0-9_]*", brand):
        msg = (f"bad brand {brand!r}: use lowercase letters, digits and "
               f"underscores, starting with a letter (chrome, chrome_android, "
               f"edge)")
        raise SystemExit(msg)
    # A trailing number used to be warned about here - a brand is a browser,
    # not a browser version, and `chrome150` would pin callers to a stale
    # capture. It is not a mistake when the number is an *OS* version: iOS
    # changes its ClientHello between releases while every app on the device
    # shares it, so `ios16` and `ios18` are two stacks, not one browser twice.
    # The warning fired on exactly the profiles that are named correctly, so
    # it is gone; naming is reviewed when a capture is added, not at runtime.
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


def _cert_validity(openssl: str, within: int = 7 * 24 * 3600) -> tuple[str, str]:
    """How much life the certificate has left: (state, notAfter).

    `state` is "ok", "expiring" within the window, "expired", or "unknown" when
    openssl cannot be reached. The date is what openssl printed, verbatim.

    openssl is asked rather than the date parsed here, because `%b` in strptime
    follows the locale and none of this may depend on one. The common case
    costs a single call; a second is only made to tell "nearly out" from "out".

    A certificate openssl cannot read at all comes back "expired", which is the
    useful answer: a corrupt one has to be replaced too, and replacing is what
    that verdict does.
    """
    def ask(seconds: int) -> subprocess.CompletedProcess:
        return subprocess.run(  # noqa: S603
            [openssl, "x509", "-in", str(CERT), "-noout", "-enddate",
             "-checkend", str(seconds)],
            capture_output=True, text=True, check=False)

    try:
        proc = ask(within)
    except OSError:
        # No openssl to ask. A certificate that is fine needs none - only
        # issuing one does - so this must not be what stops a run.
        return "unknown", ""
    end = (proc.stdout.partition("notAfter=")[2].splitlines() or [""])[0].strip()
    if proc.returncode == 0:
        return "ok", end
    return ("expired" if ask(0).returncode != 0 else "expiring"), end


def ensure_cert(openssl: str, hosts: typing.Iterable[str] = (),
                optional: typing.Iterable[str] = ()) -> None:
    """Make sure the server cert covers every name a client might use.

    Re-issuing is the expensive operation here, and the cost is not ours: every
    device that trusted the old certificate has to be walked through trusting
    the new one by hand. So it happens only when a host that was *asked for* is
    not covered already. The SAN accumulates for the same reason - a run
    without --host keeps the addresses an earlier run put in.

    `optional` goes into a certificate that is being issued anyway and is never
    itself a reason to issue one. This machine's own address is optional: it
    moves with DHCP, with a VPN coming up, and with every WSL restart, and none
    of those are a reason to invalidate a phone's trust. When it turns out not
    to be covered, that is reported rather than fixed - `--host` is how you say
    an address matters enough to pay for it.

    The one thing that re-issues without being asked is an expiry that has
    already passed. There is no trust left to protect at that point: every
    client refuses the certificate, so keeping it costs everything and saves
    nothing. Running *low* is only reported - the old one still works, and
    replacing it is a job for a moment you choose.

    iOS is the reason for the extensions - since iOS 13 a server certificate is
    rejected outright unless it has a SAN (CN is ignored), carries
    extendedKeyUsage=serverAuth and lives no longer than 398 days.
    """
    stamp = WORK / "cert.san"
    have = stamp.read_text().split(",") if stamp.exists() else []
    asked = _san(hosts).split(",")
    everything = _san([*hosts, *optional]).split(",")

    covers = (CERT.exists() and KEY.exists()
              and not [e for e in asked if e not in have])
    state, end = _cert_validity(openssl) if covers else ("", "")

    if covers and state != "expired":
        uncovered = [e for e in everything if e not in have]
        if uncovered:
            print(f"keeping the cert at {CERT}\n"
                  f"  it does not cover {', '.join(uncovered)}, so a client "
                  f"reaching us there sees a name mismatch. That address was "
                  f"detected, not asked for, and re-issuing would cost every "
                  f"device that already trusts this cert - pass --host "
                  f"{uncovered[0].partition(':')[2]} to say it is worth it.")
        if state == "expiring":
            print(f"  !! this certificate is only valid until {end}. After that "
                  f"every client refuses it and it is re-issued automatically, "
                  f"which means trusting it again on every device - so replace "
                  f"it when that suits you, not when it runs out:\n"
                  f"       rm {CERT} {KEY}", file=sys.stderr)
        return

    if covers:                                   # state == "expired"
        # Nothing is being protected by keeping this one: every client already
        # refuses it, so the trust it used to carry is gone whatever we do.
        print(f"the cert at {CERT} is out of date"
              + (f" (expired {end})" if end else " (openssl cannot read it)")
              + " - issuing a new one.")

    merged = ",".join(dict.fromkeys([*have, *everything]))
    # DNS entries first, IP after: order inside the extension is cosmetic, but
    # a stable spelling is what lets us compare against the stamp at all.
    merged = ",".join(sorted(merged.split(","), key=lambda e: e.startswith("IP:")))
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


def frames_from_stream(buf: bytes) -> typing.Iterator[tuple[int, int, int, bytes]]:
    """Slice a recorded HTTP/2 byte stream into frames.

    `read_frame` does the same off a live socket; this is for bytes that were
    captured elsewhere - by mitm_addon.py - and arrive all at once. Both feed
    `describe()`, so a capture taken either way is parsed by the same code.

    A trailing partial frame is dropped rather than raised on: a dump written
    while the connection was still open ends wherever the last TCP segment did,
    and everything before that point is still good.
    """
    if buf.startswith(PREFACE):
        buf = buf[len(PREFACE):]
    o = 0
    while o + 9 <= len(buf):
        length = int.from_bytes(buf[o:o + 3], "big")
        if o + 9 + length > len(buf):
            return
        ftype, flags = buf[o + 3], buf[o + 4]
        stream = struct.unpack_from("!I", buf, o + 5)[0] & 0x7FFFFFFF
        yield ftype, flags, stream, buf[o + 9:o + 9 + length]
        o += 9 + length


def carries_psk(ch: dict | None) -> bool:
    """True if this ClientHello resumed a session.

    A resumed handshake carries pre_shared_key, which our client never sends,
    so a capture that resumed is not a usable reference no matter how it was
    taken.
    """
    return any(e["hex"] == "0x0029" for e in (ch or {}).get("extensions", []))


# --- capturing --------------------------------------------------------------

def listen(port: int) -> socket.socket:
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port))  # noqa: S104 - must be reachable from Windows
    srv.listen(8)
    return srv


def tls_context(openssl: str, hosts: typing.Iterable[str] = (),
                optional: typing.Iterable[str] = ()) -> ssl.SSLContext:
    ensure_cert(openssl, hosts, optional)
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


def _safe(name: str) -> str:
    """A hostname reduced to something that can be a filename.

    The same rule mitm_addon.py applies, written out again rather than shared:
    that file runs under mitmproxy's own interpreter and imports nothing from
    here.
    """
    return re.sub(r"[^a-zA-Z0-9._-]", "_", name) or "unknown"


def sni_of(raw: bytes) -> str | None:
    """The server_name a ClientHello carried, or None if it sent none.

    A client addressing an IP literal sends no SNI at all, which is ordinary
    here - the browser was pointed at this machine's address - and is why a
    dump is named after the peer when this comes back empty.
    """
    try:
        for etype, body in _walk_extensions(raw):
            if etype == 0x0000 and len(body) >= 5:
                n = int.from_bytes(body[3:5], "big")
                return body[5:5 + n].decode("ascii", "replace") or None
    except (IndexError, ValueError):
        return None
    return None


#: How often a dump is rewritten while its connection is still open. The same
#: interval mitm_addon.py uses, for the same reason: a run ends when the request
#: it was waiting for arrives or when someone stops waiting, and neither is a
#: moment the connections choose, so an interrupted one loses at most this much
#: instead of the whole connection.
FLUSH_INTERVAL = 1.0


class _Wire:
    """A socket that also keeps every decrypted byte that crossed it.

    `serve` records frames as it parses them, which is all a profile needs. A
    dump is the byte stream itself, so it has to be kept as it is read - after
    decryption, before anything looks at it. The layout written out is
    mitm_addon.py's, so one importer reads captures taken either way.

    Everything that is not recv/sendall is forwarded to the real socket, so
    `handle_h2` cannot tell it is not holding one. It is handed the socket by
    `attach()` rather than at construction, because a connection that fails the
    handshake never gets one and is still worth a dump.
    """

    def __init__(self, out: Path, peer: str, hello: bytes) -> None:
        self._sock: ssl.SSLSocket | None = None
        self._out = out
        self.peer = peer
        self.hello = hello
        self.sni = sni_of(hello)
        self.alpn: str | None = None
        self.client = bytearray()
        self.server = bytearray()
        #: What the last write held, so an idle connection is not rewritten.
        self._size = -1
        self._flushed = 0.0
        self.captured_at = datetime.datetime.now(
            datetime.timezone.utc).replace(microsecond=0).isoformat()
        # Named after this connection's own client_random, so the repeated
        # writes of one connection land on one path while a second visit from
        # the same browser gets a file of its own instead of overwriting it.
        stamp = hashlib.sha256(hello).hexdigest()[:8]
        self.path = out / f"{_safe(self.sni or peer)}-{stamp}.json"

    def attach(self, sock: ssl.SSLSocket) -> _Wire:
        self._sock = sock
        return self

    def recv(self, n: int) -> bytes:
        chunk = self._sock.recv(n)
        self.client += chunk
        return chunk

    def sendall(self, data: bytes) -> None:
        self.server += data
        self._sock.sendall(data)

    def __getattr__(self, name: str) -> typing.Any:
        return getattr(self._sock, name)

    def due(self) -> bool:
        """True if new bytes have arrived and it is time to write them again."""
        return (len(self.client) + len(self.server) != self._size
                and time.monotonic() - self._flushed >= FLUSH_INTERVAL)

    def write(self) -> Path:
        payload = {
            "format": MITM_FORMAT,
            "captured_at": self.captured_at,
            "sni": self.sni,
            "alpn": self.alpn,
            "peer": self.peer,
            "client_hello": self.hello.hex(),
            # Peeked off the socket before wrap_socket() consumed it, so this
            # is the record exactly as it went over the wire - the one thing
            # mitmproxy cannot always supply.
            "client_hello_exact": True,
            "client": bytes(self.client).hex(),
            "server": bytes(self.server).hex(),
        }
        # From the payload, not from the buffers: they may have grown while it
        # was being built, and those bytes are not in this file.
        self._size = (len(payload["client"]) + len(payload["server"])) // 2
        self._flushed = time.monotonic()
        self._out.mkdir(parents=True, exist_ok=True)
        # A dump may be written while its connection is still open, so never
        # leave a half-written file where the importer might pick it up.
        tmp = self.path.with_name(self.path.name + ".tmp")
        tmp.write_text(json.dumps(payload, indent=1))
        tmp.replace(self.path)
        return self.path


class _Session:
    """What one capture run is collecting, shared across connections.

    A browser is not one connection. The navigation we capture arrives on one,
    and the page's fetch back to us may well arrive on another - Chrome is free
    to open a second connection to the same origin, and does. So connections are
    served concurrently and the results land here; the first HEADERS frame to
    arrive anywhere is the profile.

    `forever` is the recording run: it has no such finishing line, keeps every
    connection open and serving, and ends only when interrupted. What stops a
    one-shot run - the profile is captured, the xhr arrived, the timeout ran
    out - is precisely what it must not stop on.
    """

    def __init__(self, *, timeout: float, quiet: bool,
                 want_xhr: bool = False, dumps: Path | None = None,
                 written: list[Path] | None = None,
                 forever: bool = False) -> None:
        #: Hold the connection open past the first request to also catch the
        #: page's own /xhr-sample. The browser sends one by itself; our own
        #: client has to be told to, which is what selftest does.
        self.want_xhr = want_xhr
        self.timeout = timeout
        self.quiet = quiet
        #: Serve until interrupted rather than until one profile is complete.
        self.forever = forever
        #: Where one dump per connection goes, or None to record nothing but
        #: the profile. Set when the run is not filing anything under a brand.
        self.dumps = dumps
        #: Dumps already on disk, in the order they were written.
        self.written = [] if written is None else written
        #: Connections still open, so a run that ends while one is mid-request
        #: still writes out what it had.
        self.wires: list[_Wire] = []
        self.lock = threading.Lock()
        self.record: dict | None = None
        #: The page's own GET, decoded and kept raw: the only measurement of
        #: what this browser's XHRs look like that does not need a third party.
        self.xhr: dict | None = None
        #: Set once the profile is captured: from then on we are only waiting
        #: for the page's own fetch, and only for so long.
        self.deadline: float | None = None
        self.done = threading.Event()

    def claim_xhr(self, info: dict, decoded: list[tuple[str, str]]) -> None:
        """Keep the first /xhr-sample request; later ones would be identical."""
        with self.lock:
            if self.xhr is not None:
                return
            self.xhr = {
                "header_block": info["header_block"],
                "priority": info.get("priority"),
                "headers": [[k, v] for k, v in decoded if not k.startswith(":")],
            }
        if not self.forever:
            self.done.set()

    def note(self, msg: str) -> None:
        if not self.quiet:
            print(msg, flush=True)

    def open_dump(self, hello: bytes, peer: str) -> _Wire | None:
        """Start recording a connection, if this run is writing dumps at all.

        A connection that sent no ClientHello sent nothing that identifies it,
        so there is nothing to dump - port scanners and health checks land here.
        """
        if self.dumps is None or not hello:
            return None
        wire = _Wire(self.dumps, peer, hello)
        with self.lock:
            self.wires.append(wire)
        return wire

    def close_dump(self, wire: _Wire | None) -> None:
        """Write a connection out for the last time. Safe to call twice."""
        if wire is None:
            return
        with self.lock:
            if wire not in self.wires:
                return
            self.wires.remove(wire)
        self._write_dump(wire, announce=True)

    def _write_dump(self, wire: _Wire, *, announce: bool = False) -> None:
        try:
            path = wire.write()
        except OSError as exc:
            print(f"  {wire.peer}: could not write {wire.path} ({exc})",
                  file=sys.stderr)
            return
        with self.lock:
            if path not in self.written:
                self.written.append(path)
        if announce:
            self.note(f"  {wire.peer}: {len(wire.client)}B from the client "
                      f"-> {path.name}")

    def flush_dumps(self, *, final: bool = False) -> None:
        """Bring the open connections' dumps up to date on disk.

        `final` also unregisters them, which is how a run ends: it stops on the
        request it was waiting for, not on the browser closing its sockets, so
        several connections are normally still live at that point - and one of
        them may be the one that carried the xhr.
        """
        with self.lock:
            pending = self.wires
            if final:
                pending, self.wires = self.wires, []
        for wire in list(pending):
            if final or wire.due():
                self._write_dump(wire, announce=final)

    def claim_record(self, record: dict) -> bool:
        """True if this connection is the one that captured the profile."""
        with self.lock:
            if self.record is not None:
                return False
            self.record = record
            # A recording run has nothing to give up on - it is not waiting for
            # the xhr, it is keeping whatever arrives - so it takes no deadline.
            if not self.forever:
                self.deadline = time.monotonic() + self.timeout
        if not self.want_xhr and not self.forever:
            self.done.set()
        return True

    def expired(self) -> bool:
        return self.deadline is not None and time.monotonic() > self.deadline

    def running(self) -> bool:
        """Whether the accept loop should go round again."""
        return self.forever or (not self.done.is_set() and not self.expired())


def shape_of(ch: dict) -> str:
    """One line describing a ClientHello, for connections that go no further."""
    ext = {e["hex"]: e["length"] for e in ch["extensions"]}
    sigalgs = ext.get("0x000d")
    return (f"{len(ch['cipher_suites'])} ciphers, {len(ch['extensions'])} ext, "
            f"sigalgs {sigalgs}B ({(sigalgs - 2) // 2 if sigalgs else '?'} algs), "
            f"{len(ch['raw']) // 2}B total")


def _serve_connection(raw: socket.socket, peer: tuple, ctx: ssl.SSLContext,
                      state: _Session) -> None:
    # Peek first: wrap_socket() would consume the ClientHello.
    hello = peek_client_hello(raw)
    client_hello = parse_client_hello(hello)
    # Every connection is dumped, including the ones that go no further: the
    # ClientHello is already in hand by now, and it is what `match` reads.
    wire = state.open_dump(hello, peer[0])
    try:
        sock = ctx.wrap_socket(raw, server_side=True)
    except OSError as exc:
        # The ClientHello goes out before any certificate is validated, so a
        # client that refuses our self-signed one has still told us everything
        # about itself. Report it rather than throwing it away: a client that
        # cannot be clicked through (an in-app WebView) is otherwise impossible
        # to measure at all.
        #
        # OSError and not just SSLError: a client that dislikes the certificate
        # may send an alert (SSLError here) or simply reset the connection
        # (ConnectionResetError), and the second one used to end this thread
        # with a traceback - now it is the same reportable outcome as the
        # first, with the same ClientHello behind it.
        why = getattr(exc, "reason", None) or type(exc).__name__
        state.note(f"  {peer[0]}: TLS failed ({why})"
                   + (f" - {shape_of(client_hello)}" if client_hello else ""))
        raw.close()
        state.close_dump(wire)
        return

    alpn = sock.selected_alpn_protocol()
    if wire is not None:
        wire.alpn = alpn
    if alpn != "h2":
        state.note(f"  {peer[0]}: negotiated {alpn!r}, not h2 - ignoring")
        sock.close()
        state.close_dump(wire)
        return

    try:
        handle_h2(wire.attach(sock) if wire is not None else sock, state,
                  client_hello=client_hello, peer=peer[0])
    except (ConnectionError, ssl.SSLError, struct.error, TimeoutError) as exc:
        state.note(f"  {peer[0]}: {type(exc).__name__}: {exc}")
    finally:
        state.close_dump(wire)
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
            timeout: float = 25.0, want_xhr: bool = False,
            dumps: Path | None = None,
            written: list[Path] | None = None,
            forever: bool = False) -> dict | None:
    """Serve until the profile is captured, and the page's own fetch with it.

    Returns None if the listening socket is closed from under us, which is how
    selftest stops a capture that never arrived.

    `dumps` additionally writes every connection's raw bytes into that
    directory, and `written` collects the paths - the return value is one
    profile, and a run may have recorded several connections worth keeping.

    `forever` drops the finishing line: serve and record until interrupted,
    keeping every connection open and answering every request on it, the way
    `capture-mitm` runs until you stop it. The return value is still the first
    request seen - it is what the caller summarises - but by then it is one of
    many, and the dumps are the output.
    """
    state = _Session(timeout=timeout, quiet=quiet, want_xhr=want_xhr,
                     dumps=dumps, written=written, forever=forever)
    threads: list[threading.Thread] = []
    srv.settimeout(0.5)

    # Ctrl-C is the only way out of a run that nothing ever completes - a
    # client that will not accept our certificate leaves no request to wait
    # for - so it ends the run rather than propagating, and what arrived is
    # written out below. The guard is around the whole loop and not just
    # accept(): the interrupt is delivered at whatever bytecode boundary comes
    # next, which is as often the flush or the loop condition.
    try:
        while state.running():
            # At least twice a second, since accept() times out that often.
            state.flush_dumps()
            accepted = None
            try:
                accepted = srv.accept()
            except TimeoutError:
                pass          # nothing yet; see below for why not `continue`
            except OSError:
                if state.record is None:
                    state.flush_dumps(final=True)
                    return None
                break
            if accepted is None:
                # Deliberately out here rather than a `continue` in the handler
                # above: an interrupt delivered on that jump is raised while
                # the TimeoutError is still being handled, and escapes the
                # guard below - measured, on CPython 3.12. Since a timeout is
                # the state this loop spends all its time in, that is where a
                # Ctrl-C almost always lands.
                continue
            raw, peer = accepted
            t = threading.Thread(target=_serve_connection,
                                 args=(raw, peer, ctx, state), daemon=True)
            t.start()
            threads.append(t)
            # A recording run outlives any number of connections - a phone
            # browsing for ten minutes opens hundreds - and the finished ones
            # would otherwise be joined one by one at the end.
            if len(threads) > 32:
                threads = [t for t in threads if t.is_alive()]
    except KeyboardInterrupt:
        state.note("\ninterrupted - writing out what arrived")

    # Long enough for the winning connection to finish writing its response -
    # the page is waiting on that 200 to say it is done. Bounded in total
    # rather than per thread: the connections still open at the end of a
    # recording run are blocked reading a request that will never come, and
    # there may be many of them.
    until = time.monotonic() + 3.0
    for t in threads:
        t.join(timeout=max(0.0, until - time.monotonic()))
    state.flush_dumps(final=True)

    if state.record is not None and state.xhr is not None:
        # Attached after the fact rather than into the frozen frame list: the
        # profile is the first request, and this is a second, separate one.
        state.record["xhr"] = state.xhr
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
    from . import browser_fp

    return browser_fp.brand_for(headers_of(record))


def serve(args: argparse.Namespace) -> int:
    """Capture whatever visits, and write it down.

    On its own this only records, and it records until you stop it: one dump
    per connection under --captures, in the layout mitm_addon.py writes, to be
    handed to `import-mitm` afterwards. That is `capture-mitm` without a
    --brand, against our own server instead of a real site - browse for as long
    as you like, Ctrl-C, and every connection and every request on it is on
    disk. --brand instead does both steps here and now, ending as soon as one
    profile is complete and storing it; --out is the same, at a path, without
    registering a brand. The two combine: --out picks the path, and --brand
    given with it writes the name into the file without installing it.

    Recording and filing are separate because they fail separately. Which
    browser a capture is cannot always be read off it - a WebView, an app on
    NSURLSession, or anything that refused our certificate before sending a
    request - and those are exactly the clients worth capturing. Guessing a
    brand there used to lose the whole visit; now the bytes are on disk either
    way and naming them is a later decision.
    """
    if args.brand:
        profile_path(args.brand)          # reject a bad name before we listen
    dumps = None if (args.brand or args.out) else Path(args.captures).resolve()

    named = [h.strip() for h in (args.host or "").split(",") if h.strip()]
    detected = local_ipv4()
    # The address this machine happens to hold today goes into a certificate
    # that is being issued anyway, but never causes one to be issued: it moves
    # on its own, and a phone's trust does not. See ensure_cert.
    hosts = [*named, detected] if detected else list(named)
    ctx = tls_context(args.openssl, named,
                      optional=[detected] if detected else [])
    srv = listen(args.port)

    reach = hosts[0] if hosts else "localhost"
    print(f"listening on :{args.port} - waiting for any h2 client "
          f"(https://{reach}:{args.port}/api/all)")
    if dumps is not None:
        print(f"  dumps    {dumps}   (one per connection, rewritten as it "
              f"grows; nothing is filed under a brand)\n"
              f"  Browse for as long as you like, then stop with Ctrl-C. "
              f"Pass --brand to capture one profile and stop instead.")
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

    written: list[Path] = []
    record = capture(srv, ctx, timeout=args.xhr_timeout,
                     # The page fetches /xhr-sample by itself, but the run has
                     # to be told to stay up for it - otherwise it ends on the
                     # navigation and the xhr half is lost. It arrives in
                     # milliseconds; the timeout is only the giving-up point.
                     want_xhr=True, dumps=dumps, written=written,
                     # Recording has no finishing line: it is not after one
                     # profile, so nothing it collects is a reason to stop.
                     forever=dumps is not None)
    srv.close()
    if dumps is not None:
        return report_dumps(dumps, written, record)
    if record is None:
        return 1

    peer = record.pop("peer", "?")
    # As in import_mitm: --out picks the path, --brand names what is in it, and
    # the two are independent. Only a capture filed into the profiles directory
    # is reported back at the end.
    if args.out:
        out, brand, filed = Path(args.out), args.brand, False
    else:
        brand, filed = args.brand, True
        out = profile_path(brand)
        out.parent.mkdir(parents=True, exist_ok=True)
    if brand:
        record = {"brand": brand, **record}
    kept = carried_meta(out)
    if kept:
        record["meta"] = kept

    replacing = out.exists()
    out.write_text(json.dumps(record, indent=2))
    ua = headers_of(record).get("user-agent", "?")
    print(f"  captured from {peer}: {ua}")
    if kept:
        print(f"  kept the meta the old file carried: {', '.join(kept)}")
    print(f"  {'replaced' if replacing else 'stored as'} {out}")
    warn_if_resumed(record)

    summarise(record)
    if filed:
        report_profile(brand)
    return 0


def warn_if_resumed(record: dict) -> None:
    """Say so if the capture is of a resumed handshake, which is not usable.

    We refuse to issue tickets, but a browser that collected one before that
    was true still offers it, and the ClientHello then carries an extension our
    client never sends.
    """
    if carries_psk(record.get("client_hello")):
        print("  !! this ClientHello carries pre_shared_key: the browser resumed "
              "a session it had from an earlier visit, so the capture has one "
              "extension our client never sends. Re-capture from a fresh "
              "browser profile (a new --user-data-dir).", file=sys.stderr)


def report_dumps(out: Path, written: list[Path], record: dict | None) -> int:
    """Say what landed in the captures directory and how to make use of it.

    Nothing is installed here - that is `import-mitm`'s job, and it is given
    the whole directory rather than a chosen file, because it is the one that
    knows which connection carried a navigation and which carried the xhr.
    What this does say is whether a *request* arrived at all: a run that only
    collected rejected handshakes is worth telling apart from one that got
    everything, and the exit status follows that rather than the file count.

    Each dump is read back rather than reported from what was in memory. It
    costs nothing at this point and it is the honest question: what is on disk
    for `import-mitm` to find, not what we believe we wrote.
    """
    if not written:
        print("\nnothing was captured. Check that the browser really reached "
              "this address, and that it got as far as sending a ClientHello.",
              file=sys.stderr)
        return 1

    print(f"\n{len(written)} dump(s) in {out}")
    requests = 0
    for path in written:
        try:
            rec = _dump_record(path)
        except Exception as exc:  # noqa: BLE001 - one bad file, not a crash
            print(f"  {path.name:<38} unreadable ({type(exc).__name__}: {exc})")
            continue
        if rec is None:
            print(f"  {path.name:<38} (no ClientHello)")
            continue
        n = sum(1 for f in rec["frames"] if f["type"] == "HEADERS")
        requests += n
        print(f"  {path.name:<38} {rec['sni'] or '?':<26} "
              f"{rec['alpn'] or '-':<9} {n:>3} req")

    if record is None:
        print("\n  none of them carries an HTTP/2 request - a ClientHello alone "
              "still says which stack it came from (`mytls-probe match "
              f"{out}`), but a profile cannot be built from it. If the browser "
              "stopped at the certificate warning, click through it.",
              file=sys.stderr)
        return 1

    peer = record.pop("peer", "?")
    try:
        ua = headers_of(record).get("user-agent", "?")
    except Exception as exc:  # noqa: BLE001 - the dumps are already on disk
        ua = f"(user-agent unreadable: {type(exc).__name__}: {exc})"
    print(f"\n{requests} request(s); the first was from {peer}: {ua}")
    warn_if_resumed(record)
    summarise(record)
    print(f"\n  import with:\n    mytls-probe import-mitm {out} --brand <name>")
    return 0


def report_profile(brand: str) -> None:
    """Show what the freshly captured brand now looks like to browser_fp.

    Capturing is the whole act of adding a browser - there is no code to write
    afterwards - so the capture step is where you get to see the transport it
    produced.
    """
    try:
        from . import browser_fp
        browser_fp.reload()
        print()
        print(browser_fp.describe(brand))
    except Exception as exc:  # noqa: BLE001 - the capture is already saved
        print(f"\n(capture saved, but browser_fp could not read it back: "
              f"{type(exc).__name__}: {exc})", file=sys.stderr)


#: Served to the browser once its request has been captured. It has one job:
#: fire the same-origin /xhr-sample, because how a browser words an XHR cannot
#: be derived from its navigation and no third party can measure it for us - a
#: cross-origin service is blocked by CORS on every iOS Safari there is.
#:
#: There used to be a second page here that asked the browser to fetch
#: tls.peet.ws and post the answer back, so that a `references/<brand>.json`
#: could be stored next to the capture. That whole apparatus is gone. What an
#: outside service makes of a browser is now asked *live* by verify_fp, of our
#: own client, and compared against fingerprints computed from this capture's
#: raw bytes - which needs nothing stored, works for a brand captured through
#: mitmproxy (where a third party would only ever see mitmproxy's TLS), and
#: costs no paste-box UI on a phone.
PAGE = b"""<!doctype html>
<meta charset="utf-8"><title>hpack_probe</title>
<style>body{font:14px/1.6 system-ui;margin:3em;max-width:46em}</style>
<body>
<p id="s">captured. one moment...</p>
<script>
const say = t => document.getElementById("s").textContent = t;
fetch("/xhr-sample").catch(() => null)
  .then(() => say("done - you can close this tab"))
  .catch(() => say("done"));
</script>
"""


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
            decoded = [(k if isinstance(k, str) else k.decode(),
                        v if isinstance(v, str) else v.decode())
                       for k, v in decoder.decode(bytes.fromhex(info["header_block"]))]
            headers = dict(decoded)
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
                won = state.claim_record(record)
                # The page goes back either way: even when nothing is being
                # collected from a third party, it is what makes the browser
                # send the /xhr-sample. Our own client ignores the body.
                send_response(sock, encoder, stream, b"200", b"text/html", PAGE)
                if won and not state.want_xhr:
                    return

            elif method == "GET" and path.startswith("/xhr-sample"):
                state.claim_xhr(info, decoded)
                send_response(sock, encoder, stream, b"200", b"text/plain", b"ok")

            elif method == "GET" and not path.startswith("/favicon"):
                # Any connection serves the page: after clicking through the
                # certificate warning the browser may retry on a fresh one.
                send_response(sock, encoder, stream, b"200", b"text/html", PAGE)

            else:
                send_response(sock, encoder, stream, b"404", b"text/plain", b"")


# --- driving our own client -------------------------------------------------

def run_client(authority: str, brand: str | None, *, quiet: bool = False,
               like: dict[str, str] | None = None,
               xhr: dict | None = None,
               method: str = "GET", path: str = "/api/all",
               xhr_method: str = "GET", xhr_path: str = "/xhr-sample") -> None:
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

    `method` and `path` are the capture's own. They are two thirds of the
    pseudo-header block, so driving a fixed `GET /api/all` at a capture taken
    from real traffic made every such block differ on fields that say nothing
    about the encoder. A body is synthesised when the captured headers declare
    a `content-length`, because a POST whose length header disagrees with what
    follows it is not a request either end would accept.
    """
    import httpx

    from . import browser_fp

    # The library supplies the header *order* and never the values, so the
    # values have to come from here for the comparison to mean anything: these
    # are the ones the captured browser sent, handed back to it verbatim. A
    # difference in the resulting bytes is then a difference in ordering or in
    # HPACK encoding, which is exactly what is under test.
    # A profile now carries only what belongs to the network stack, so the
    # things that belong to the captured *client* - its header set, their
    # order, and whether it put a priority on the HEADERS frame - have to be
    # handed back explicitly for this to reproduce anything. That is the point
    # of the comparison: what remains under test is the stack's half.
    captured = browser_fp.profile(brand)
    defaults = list(captured.headers)
    headers: dict[str, str] = {}

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    # verify goes on the transport: httpx ignores its own when given one.
    transport = browser_fp.Transport(
        brand, verify=ctx, headers=defaults,
        priority=captured.captured_priority("navigate") or None)
    # The transport holds its own copy, so this is the one to adjust - the
    # shared Profile that profile() hands out no longer reaches it.
    prof = transport.profile
    if like is not None:
        if like.get("sec-fetch-mode") == "cors":
            prof.header_profile = "xhr"
        # A capture taken by following a link or reloading carries headers the
        # navigate template has no value for. Pass them through as the caller
        # would, rather than teaching the profile to invent them.
        for name in ("sec-fetch-site", "cache-control", "referer"):
            if name in like:
                headers[name] = like[name]
    def body_for(pairs: typing.Iterable[tuple[typing.Any, typing.Any]]
                 ) -> bytes | None:
        """Bytes matching whatever `content-length` the capture declared.

        The value goes on the wire from the profile's own header list, so this
        only has to make the request consistent - httpx would otherwise refuse
        to send a body-less request that claims a length, and httpcore would
        end the stream on the HEADERS frame.
        """
        for name, value in pairs:
            # A profile holds str pairs; browser_fp's encoder holds bytes.
            key = name.decode() if isinstance(name, bytes) else name
            if key.lower() == "content-length":
                return b"\x00" * int(value)
        return None

    with httpx.Client(transport=transport, timeout=15) as c:
        try:
            c.request(method, f"https://{authority}{path}", headers=headers,
                      content=body_for(defaults))
            if xhr is not None:
                # A second request on the *same* connection, the way the page's
                # own fetch arrived. Its HPACK block only comes out right if the
                # first one did too - the dynamic table carries over - so this
                # tests the encoder far harder than one frame in isolation.
                # Swap the whole set, not add to it: an xhr's headers are a
                # different set from a navigation's, so the navigation values
                # standing on this transport have to step aside or they would
                # be spliced in as caller extras.
                was_hdrs, was_prio = prof.default_headers, prof.priority_override
                prof.default_headers = browser_fp._as_header_pairs(
                    xhr.get("headers") or [])
                prof.priority_override = captured.captured_priority("xhr") or None
                try:
                    c.request(xhr_method, f"https://{authority}{xhr_path}",
                              content=body_for(prof.default_headers))
                finally:
                    prof.default_headers = was_hdrs
                    prof.priority_override = was_prio
        except Exception as exc:  # noqa: BLE001 - server closes early by design
            if not quiet:
                print(f"(request ended with {type(exc).__name__}: {exc})")


def client(args: argparse.Namespace) -> int:
    # Empty rather than absent: it sends the /xhr-sample the way a browser's
    # page would, with nothing captured to imitate. `serve` waits for that
    # request, so without it every manual run would sit out the timeout.
    run_client(f"{args.host}:{args.port}", args.brand, xhr={})
    print("done - check the server's output file")
    return 0


# --- comparing --------------------------------------------------------------

def _decode_with(decoder, block: bytes) -> list[tuple[str, str]]:
    """Decode one block against a decoder that carries the connection's state.

    Every block on a connection has to go through one decoder, in order: HPACK
    indexes into a table the earlier blocks built, so the second request on a
    connection cannot be decoded on its own at all.
    """
    def text(x: bytes | str) -> str:
        return x if isinstance(x, str) else x.decode("utf-8", "replace")

    return [(text(k), text(v)) for k, v in decoder.decode(block)]


def _decode(block: bytes) -> list[tuple[str, str]]:
    """Decode a block that is the first on its connection, so the table is
    empty. Anything later needs `_decode_with` and the decoder that saw the
    blocks before it."""
    import hpack

    return _decode_with(hpack.Decoder(), block)


def _decode_primed(rec: dict, block: bytes) -> list[tuple[str, str]]:
    """Decode a block that is *not* the first on its connection.

    The xhr HEADERS block indexes into the dynamic table the navigate request
    already built, so decoding it against a fresh table raises the moment it
    references an inserted entry (a shared `:authority` or `user-agent` is
    enough). Feed the record's navigate block through a decoder first to rebuild
    that table, then decode this block against it - the order the client encoded
    them in. If the record carries no navigate HEADERS frame the table stays
    empty, same as `_decode`.
    """
    import hpack

    decoder = hpack.Decoder()
    nav = next((f for f in rec.get("frames", []) if f["type"] == "HEADERS"), None)
    if nav is not None:
        _decode_with(decoder, bytes.fromhex(nav["header_block"]))
    return _decode_with(decoder, block)


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


#: Extensions whose *body* is fresh on every connection, so it is blanked
#: rather than compared. The body *length* is still compared, because it comes
#: from the length bytes in front of it, which are not blanked - and a client
#: whose GREASE ECH is always exactly one size is its own kind of tell.
#:
#: key_share is deliberately not in here: its group ids are fingerprint
#: material even though the public keys beside them are fresh every time, so
#: `canonical_client_hello` blanks the keys and keeps the groups.
RANDOM_BODY = {"0xfe0d", "0x0029"}


class Malformed(ValueError):
    """A ClientHello whose declared lengths do not add up."""


def canonical_client_hello(raw: bytes, *, keep_record_version: bool = True,
                           drop_host_dependent: bool = False
                           ) -> tuple[bytes, list[tuple[str, int]], list[str]]:
    """Zero out only what genuinely varies per connection.

    This is what the self-test compares, and it is deliberately not a list of
    parsed fields. Two ClientHellos that agree everywhere outside the regions
    named below *are the same message*, and every fingerprint anyone computes
    from them - ja3, ja4, peetprint, or one nobody has published - is therefore
    equal by construction. Comparing hashes was only ever a way of asking that
    question indirectly, and a worse one: it can only find what the hash
    happens to cover.

    A field-by-field comparison has the opposite failure: it silently ignores
    anything nobody thought to list. `compression_methods` was never compared
    by the old one. Here nothing is skipped unless it appears in the returned
    blank list, which the caller prints.

    This also checks itself. Locating the variable regions means walking the
    message, and walking it wrongly blanks the wrong bytes - which makes the
    comparison *fail*, loudly, rather than pass. That is the opposite of a
    parser bug in a field comparison, which makes a difference invisible.

    Returns (canonical bytes, [(what, how many bytes)], [problems]).
    `problems` holds the assertions that did not hold - regions whose contents
    are supposed to be fixed, so they are checked rather than blanked:

      * `padding` must be all zeroes (RFC 7685)
      * a GREASE extension's body must be empty or a single zero byte

    Blanking those instead would hide 190 bytes of an iOS ClientHello.

    `drop_host_dependent` removes the two extensions in `HOST_DEPENDENT_EXTS`
    outright - TLV and all - and blanks the extension block length with them.
    Blanking their bodies would not be enough: `server_name` carries the
    hostname, whose *length* differs, and `padding` is computed from the total
    record length, so it silently absorbs that difference and comes out a
    different size too. Two ClientHellos sent to different hostnames therefore
    have no byte comparison at all unless both are excised, and the result is a
    real one: everything the hostname does not touch, compared byte for byte,
    instead of nothing. What is given up - that a name is padded to 512 - is
    what `sniscan` measures across a sweep of hostname lengths, which is a
    better test of it than one sample would be.
    """
    b = bytearray(raw)
    blanked: list[tuple[str, int]] = []
    problems: list[str] = []
    #: (start, end) of each extension `drop_host_dependent` removes, plus the
    #: two length bytes in front of the whole extension block.
    host_spans: list[tuple[int, int]] = []
    ext_len_at = 0

    def wipe(lo: int, hi: int, why: str) -> None:
        if hi > lo:
            b[lo:hi] = b"\x00" * (hi - lo)
            blanked.append((why, hi - lo))

    def need(o: int, n: int, what: str) -> None:
        if o + n > len(b):
            msg = f"{what} runs {o + n - len(b)} bytes past the end of the record"
            raise Malformed(msg)

    need(0, 43, "the record and handshake headers")
    if not keep_record_version:
        # An imported capture whose ClientHello mitmproxy had to synthesise
        # carries a fabricated 0x0303 here. Comparing it would report a
        # difference that the browser never made.
        wipe(1, 3, "record_version (unmeasured)")
    wipe(3, 5, "record_length")
    wipe(6, 9, "handshake_length")
    wipe(11, 43, "client_random")

    o = 43
    need(o, 1, "the session id length")
    sid = b[o]
    o += 1
    need(o, sid, "the session id")
    wipe(o, o + sid, "session_id")
    o += sid

    need(o, 2, "the cipher list length")
    n = int.from_bytes(b[o:o + 2], "big")
    o += 2
    need(o, n, "the cipher list")
    for i in range(o, o + n - 1, 2):
        if int.from_bytes(b[i:i + 2], "big") in GREASE:
            wipe(i, i + 2, "GREASE cipher")
    o += n

    need(o, 1, "the compression method length")
    o += 1 + b[o]                                  # compared, never blanked
    need(o, 2, "the extension block length")
    ext_len_at = o
    o += 2

    while o + 4 <= len(b):
        etype = int.from_bytes(b[o:o + 2], "big")
        elen = int.from_bytes(b[o + 2:o + 4], "big")
        body = o + 4
        need(body, elen, f"extension 0x{etype:04x}")
        if etype in GREASE:
            wipe(o, o + 2, "GREASE extension id")
            if bytes(b[body:body + elen]) not in (b"", b"\x00"):
                problems.append(f"GREASE extension body is "
                                f"{bytes(b[body:body + elen]).hex()}, "
                                f"expected empty or 00")
        elif etype == 0x0000:                      # server_name
            host_spans.append((o, body + elen))
            wipe(body, body + elen, "server_name")
        elif etype == 0x0015:                      # padding
            host_spans.append((o, body + elen))
            if set(b[body:body + elen]) - {0}:
                problems.append(f"padding is not all zeroes ({elen}B)")
        elif f"0x{etype:04x}" in RANDOM_BODY:      # GREASE ECH, pre_shared_key
            wipe(body, body + elen, f"0x{etype:04x} body")
        elif etype == 0x0033:                      # key_share
            p = body + 2
            while p + 4 <= body + elen:
                group = int.from_bytes(b[p:p + 2], "big")
                klen = int.from_bytes(b[p + 2:p + 4], "big")
                if group in GREASE:
                    wipe(p, p + 2, "GREASE key_share group")
                wipe(p + 4, p + 4 + klen, "key_share key")
                p += 4 + klen
        elif etype in (0x000a, 0x002b):            # groups, supported_versions
            p = body + (2 if etype == 0x000a else 1)
            while p + 2 <= body + elen:
                if int.from_bytes(b[p:p + 2], "big") in GREASE:
                    wipe(p, p + 2, "GREASE codepoint")
                p += 2
        o = body + elen

    if o != len(b):
        msg = f"{len(b) - o} trailing bytes after the last extension"
        raise Malformed(msg)

    if drop_host_dependent:
        # The extension block length counts the bytes about to disappear, so it
        # cannot survive them. record_length and handshake_length are already
        # blanked above for the same reason.
        wipe(ext_len_at, ext_len_at + 2, "extensions_length")
        # `blanked` already counts server_name's body; only the bytes that are
        # not in it get their own entry, so the printed totals still add up.
        kept = bytearray()
        last = 0
        for lo, hi in sorted(host_spans):
            kept += b[last:lo]
            last = hi
            etype = int.from_bytes(b[lo:lo + 2], "big")
            size = hi - lo
            if etype == 0x0000:
                size -= int.from_bytes(b[lo + 2:lo + 4], "big")
            blanked.append((f"0x{etype:04x} dropped (host-dependent)", size))
        kept += b[last:]
        b = kept

    return bytes(b), blanked, problems


def _walk_extensions(buf: bytes) -> typing.Iterator[tuple[int, bytes]]:
    """(id, body) for each extension in a ClientHello, in wire order."""
    o = 43
    o += 1 + buf[o]                                  # session_id
    o += 2 + int.from_bytes(buf[o:o + 2], "big")     # cipher_suites
    o += 1 + buf[o]                                  # compression_methods
    o += 2                                           # extension block length
    while o + 4 <= len(buf):
        elen = int.from_bytes(buf[o + 2:o + 4], "big")
        yield int.from_bytes(buf[o:o + 2], "big"), buf[o + 4:o + 4 + elen]
        o += 4 + elen


def extension_sequence(canon: bytes, raw: bytes, *,
                       dropped_host_dependent: bool = False
                       ) -> list[tuple[str, bytes]]:
    """(id, canonical body) in wire order, for placing a difference.

    Takes both records because neither alone is enough: the bodies must come
    from the canonical bytes, which are free of per-connection noise, but the
    *ids* must come from the original - blanking a GREASE id turns it into
    0x0000, which is `server_name`, and a Chrome ClientHello carrying two
    GREASE extensions would then appear to send `server_name` three times.

    The two are walked separately rather than by a shared offset, because
    `canonical_client_hello(drop_host_dependent=True)` makes them different
    lengths - and a shared offset then reads ids out of the middle of whatever
    followed the first extension it removed.
    """
    ids = [t for t, _ in _walk_extensions(raw)
           if not (dropped_host_dependent
                   and f"0x{t:04x}" in HOST_DEPENDENT_EXTS)]
    bodies = [body for _, body in _walk_extensions(canon)]
    if len(ids) != len(bodies):
        msg = (f"{len(ids)} extension ids against {len(bodies)} bodies - the "
               f"canonical record and the raw one disagree on how many there are")
        raise Malformed(msg)
    return [("GREASE" if t in GREASE else f"0x{t:04x}", body)
            for t, body in zip(ids, bodies)]


def _prefix_regions(raw: bytes) -> list[tuple[str, int, int]]:
    """Everything before the extensions, named, so a difference has a place."""
    o = 43
    out = [("record_header", 0, 5), ("handshake_header", 5, 9),
           ("legacy_version", 9, 11), ("client_random", 11, 43)]
    out.append(("session_id", o, o + 1 + raw[o]))
    o += 1 + raw[o]
    n = int.from_bytes(raw[o:o + 2], "big")
    out.append(("cipher_suites", o, o + 2 + n))
    o += 2 + n
    out.append(("compression_methods", o, o + 1 + raw[o]))
    o += 1 + raw[o]
    out.append(("extensions_length", o, o + 2))
    return out


def diff_client_hello(a: dict | None, b: dict | None, na: str, nb: str,
                      *, host_differs: bool = False) -> bool:
    """Compare two ClientHellos byte for byte, outside what varies per connection.

    Not a list of fields. See `canonical_client_hello` for why: if these bytes
    match, the two messages are the same message, and no fingerprint - named or
    unnamed - can tell them apart.

    Extension *order* is reported separately rather than folded in, because one
    profile is meant to shuffle it (Chrome, since 110) and the others are meant
    not to. A shuffle with an identical extension set is not a failure, but it
    is printed every time so that an iOS profile quietly starting to shuffle is
    visible rather than absorbed by a sort.
    """
    print("=== ClientHello ===")
    if a is None or b is None:
        print("  (missing on one side, skipped)")
        return True
    if not a.get("raw") or not b.get("raw"):
        print("  (one side has no raw record - nothing to compare byte by byte)")
        return True

    # mitmproxy hands us a synthetic record whose version is always 0x0303, so
    # an imported capture records None rather than that artefact. Comparing it
    # against a measured 0x0301 would report a difference that is not one.
    keep_version = (a["record_version"] is not None
                    and b["record_version"] is not None)
    if host_differs:
        print("  note: the two were addressed at different hostnames, so "
              "server_name and\n        padding - which absorbs server_name's "
              "length - are dropped rather than\n        compared. Everything "
              "the hostname does not reach still is.")
    try:
        ca, wa, pa = canonical_client_hello(bytes.fromhex(a["raw"]),
                                            keep_record_version=keep_version,
                                            drop_host_dependent=host_differs)
        cb, wb, pb = canonical_client_hello(bytes.fromhex(b["raw"]),
                                            keep_record_version=keep_version,
                                            drop_host_dependent=host_differs)
    except Malformed as exc:
        print(f"  MALFORMED: {exc}")
        return False

    print(f"  {na} {len(ca)}B compared, {nb} {len(cb)}B compared")
    for who, blanks, raw in ((na, wa, a["raw"]), (nb, wb, b["raw"])):
        merged: dict[str, int] = {}
        for why, size in blanks:
            merged[why] = merged.get(why, 0) + size
        # Against the size of the record as it went out, not the size of what
        # is left of it: with drop_host_dependent those differ, and a total
        # larger than the denominator reads as a bug in the arithmetic.
        print(f"  not compared ({who}, {sum(merged.values())}B of "
              f"{len(raw) // 2} on the wire): "
              + ", ".join(f"{k} {v}B" for k, v in sorted(merged.items())))

    same = True
    for who, problems in ((na, pa), (nb, pb)):
        for text in problems:
            same = False
            print(f"  ASSERTION FAILED ({who}): {text}")

    ea = extension_sequence(ca, bytes.fromhex(a["raw"]),
                            dropped_host_dependent=host_differs)
    eb = extension_sequence(cb, bytes.fromhex(b["raw"]),
                            dropped_host_dependent=host_differs)
    order_a, order_b = [t for t, _ in ea], [t for t, _ in eb]
    if order_a == order_b:
        print("  extension order  identical")
    elif sorted(order_a) == sorted(order_b):
        print(f"  extension order  SHUFFLED - same {len(order_a)} extensions, "
              f"different order. Correct only for a profile that sets "
              f"SSL_FP_SHUFFLE_EXTS (Chrome does; iOS does not)")
        print(f"      {na}: {' '.join(order_a)}")
        print(f"      {nb}: {' '.join(order_b)}")
    else:
        same = False
        print("  extension order  DIFFER - not a shuffle, the sets differ")
        print(f"      {na}: {' '.join(order_a)}")
        print(f"      {nb}: {' '.join(order_b)}")

    if ca == cb:
        print("  bytes            IDENTICAL outside the regions above")
        return same

    # Same set in a different order is the shuffle already reported; compare
    # the extensions as a multiset so the shuffle does not drown the real
    # answer. A multiset and not a dict: Chrome sends two GREASE extensions,
    # and a dict would silently keep one of them.
    if sorted(order_a) == sorted(order_b) and order_a != order_b:
        prefix_bad = False
        pre_b = {n: bytes(cb[lo:hi]) for n, lo, hi in _prefix_regions(cb)}
        for name, lo, hi in _prefix_regions(ca):
            if pre_b.get(name) != bytes(ca[lo:hi]):
                prefix_bad = same = False
                print(f"  {name:<16} DIFFER")
                print(f"      {na}: {bytes(ca[lo:hi]).hex()}")
                print(f"      {nb}: {pre_b.get(name, b'').hex()}")
        if sorted(ea) == sorted(eb):
            if not prefix_bad:
                print("  bytes            IDENTICAL as a multiset "
                      "(order shuffled, see above)")
            return same
        same = False
        print("  extension bodies DIFFER")
        left, right = list(ea), list(eb)
        for item in list(left):
            if item in right:
                left.remove(item)
                right.remove(item)
        for tag, items in ((na, left), (nb, right)):
            for k, v in items:
                print(f"      only in {tag}: {k} = {_short(v.hex())}")
        return same

    same = False
    print("  bytes            DIFFER")
    where: dict[str, int] = {}
    for i in range(min(len(ca), len(cb))):
        if ca[i] != cb[i]:
            for name, lo, hi in _prefix_regions(ca):
                if lo <= i < hi:
                    where[name] = where.get(name, 0) + 1
                    break
            else:
                where["extensions"] = where.get("extensions", 0) + 1
    if len(ca) != len(cb):
        where["(length)"] = abs(len(ca) - len(cb))
    for name, count in where.items():
        print(f"      {name}: {count} byte(s)")
    for i, (x, y) in enumerate(zip(ea, eb)):
        if x != y:
            print(f"      extension {i}: {na}={x[0]} {_short(x[1].hex())}")
            print(f"      {' ' * (11 + len(str(i)))}{nb}={y[0]} {_short(y[1].hex())}")
    return same


def _short(value: str | None, limit: int = 72) -> str:
    if value is None:
        return "(absent)"
    return value if len(value) <= limit else f"{value[:limit]}... ({len(value)//2}B)"


def diff_xhr(a: dict, b: dict, na: str, nb: str,
             excused: typing.Collection[str] = ()) -> bool:
    """Compare the page's own GET - the second HEADERS block on the connection.

    Only possible because both sides sent the same first request first: the
    HPACK dynamic table carries over, so this block matching means the encoder
    agreed about what to index as well as how to encode it.
    """
    xa, xb = a.get("xhr"), b.get("xhr")
    print("\n=== HPACK header block (xhr, same connection) ===")
    if xa is None or xb is None:
        which = na if xa is None else nb
        print(f"  no /xhr-sample in {which} - capture again to get one "
              f"(the probe's page fetches it by itself)")
        return True
    same = True
    pa, pb = xa.get("priority"), xb.get("priority")
    if pa != pb:
        same = False
        print(f"  priority DIFFER\n      {na}: {pa}\n      {nb}: {pb}")
    else:
        print(f"  priority OK ({pa or 'no PRIORITY flag'})")

    ba, bb = bytes.fromhex(xa["header_block"]), bytes.fromhex(xb["header_block"])
    print(f"{na}: {len(ba)} bytes\n{nb}: {len(bb)} bytes\n")
    if ba == bb:
        print("xhr HPACK bytes are IDENTICAL")
        return same
    # The dynamic table carries the first block's `:authority` into this one,
    # so an unreproducible authority moves these bytes too - and does it twice,
    # once as a table reference and once in whatever it displaced. This block is
    # the second on the connection, so it has to be decoded against the table
    # the navigate request built (`_decode_primed`), not a fresh one.
    try:
        da, db = _decode_primed(a, ba), _decode_primed(b, bb)
    except Exception as exc:  # noqa: BLE001 - a block we cannot decode is a finding, not a crash
        print(f"!! xhr HPACK could not be decoded ({type(exc).__name__}: {exc}) "
              f"- raw bytes only")
        print(f"  {na}: {ba.hex()}\n  {nb}: {bb.hex()}")
        return False
    differing = {k for (k, v), (k2, v2) in zip(da, db) if (k, v) != (k2, v2)}
    if excused and [k for k, _ in da] == [k for k, _ in db] \
            and differing <= set(excused):
        print(f"xhr fields are identical apart from {', '.join(sorted(differing))}, "
              f"not reproducible here")
        return same
    print("!! xhr HPACK bytes DIFFER")
    for name, blk in ((na, da), (nb, db)):
        print(f"  {name}: " + " ".join(f"{k}={v}" for k, v in blk))
    return False


def diff_records(a: dict, b: dict, na: str, nb: str,
                 excused: typing.Collection[str] = ()) -> int:
    """Full comparison of two captures: TLS, h2 frames, then HPACK bytes.

    `excused` names the header fields the replay could not reproduce - in
    practice `:authority`, when the capture was taken at an address this
    machine does not hold. Those fields are still printed, but a block that
    differs *only* in them is reported as such rather than as a failure and a
    wall of byte offsets: the bytes cannot match, and saying so twenty times
    over is not a finding. `diff_hpack_offline` is what still gives that block
    a byte-level verdict.
    """
    def headers_frame(rec):
        return next(f for f in rec["frames"] if f["type"] == "HEADERS")

    ba = bytes.fromhex(headers_frame(a)["header_block"])
    bb = bytes.fromhex(headers_frame(b)["header_block"])

    ok = diff_client_hello(a.get("client_hello"), b.get("client_hello"), na, nb,
                           host_differs=":authority" in excused)
    print()
    ok &= diff_h2(a, b, na, nb)

    print("\n=== HPACK header block ===")
    print(f"{na}: {len(ba)} bytes")
    print(f"{nb}: {len(bb)} bytes")

    ha, hb = _decode(ba), _decode(bb)
    if [k for k, _ in ha] != [k for k, _ in hb]:
        print("\n!! header NAMES/order differ - fix that before comparing bytes")
    unexcused = False
    for (ka, va), (kb, vb) in zip(ha, hb):
        if (ka, va) != (kb, vb):
            tag = "  (not reproducible here)" if ka in excused and ka == kb else ""
            unexcused |= not tag
            print(f"  value differs: {ka}={va!r} vs {kb}={vb!r}{tag}")

    if ba == bb:
        print("\nHPACK bytes are IDENTICAL")
        ok &= diff_xhr(a, b, na, nb)
        return 0 if ok else 1

    if excused and not unexcused:
        print(f"\nfields are identical apart from {', '.join(sorted(excused))}, "
              f"which this machine cannot\nreproduce - so the bytes cannot "
              f"match and are not compared. What the live path\nproves here is "
              f"the field set and its order; the encoding is judged by the "
              f"re-encode\nbelow, on the capture's own fields.")
        ok &= diff_xhr(a, b, na, nb, excused=excused)
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


def _split_table_size_update(block: bytes) -> tuple[bytes, int | None]:
    """Peel a leading dynamic table size update off a header block.

    RFC 7541 section 6.3: `001` in the top three bits, then a 5-bit prefix
    integer. Clients emit one to acknowledge the peer's
    SETTINGS_HEADER_TABLE_SIZE, and some emit it even when the value equals the
    4096 default - which `hpack` never does, because it only writes one when
    the size *changed*. That is an acknowledgement rather than an encoding
    rule, so it is reported separately instead of counting as a difference in
    how the fields were encoded.

    Returns (block without the update, the size) or (block, None).
    """
    if not block or block[0] & 0xE0 != 0x20:
        return block, None
    value = block[0] & 0x1F
    i = 1
    if value == 0x1F:                              # continuation octets follow
        shift = 0
        while i < len(block):
            octet = block[i]
            i += 1
            value += (octet & 0x7F) << shift
            shift += 7
            if not octet & 0x80:
                break
        else:
            return block, None
    return block[i:], value


def diff_hpack_offline(ref: dict, brand: str) -> bool:
    """Re-encode the capture's own fields with this brand's encoder.

    The live replay cannot always reproduce a capture's `:authority` - one
    taken off a real site names that site, and this machine does not hold its
    address - and `:authority` is inside the header block, so those brands used
    to be skipped outright.

    This asks the same question without the network: decode the captured block,
    hand the fields straight back to the encoder the profile selects, and
    compare the result to the captured bytes. The input is the browser's own,
    including the authority, so nothing has to be excused; what is under test is
    exactly the encoder's policy - what it indexes, what it huffman-codes, what
    it refuses to index - which is what the byte comparison was ever for.

    What it does *not* cover is the part the live replay does: that httpx and
    httpcore emit that field list, in that order, at all. The two are
    complementary and both run.
    """
    import hpack

    from . import browser_fp

    prof = browser_fp.profile(brand)
    print(f"\n=== HPACK re-encode (capture's own fields, {prof.hpack} encoder) ===")

    decoder = hpack.Decoder()
    encoder = browser_fp._ENCODERS[prof.hpack]()
    ok = True
    for label, rec in (("navigate", ref), ("xhr", ref.get("xhr"))):
        if rec is None:
            continue
        frame = next((f for f in rec["frames"] if f["type"] == "HEADERS"), None) \
            if "frames" in rec else None
        block = bytes.fromhex(frame["header_block"] if frame else rec["header_block"])
        # One decoder for both blocks and in order: the second indexes into the
        # table the first built, so it cannot be decoded on its own.
        fields = decoder.decode(block, raw=True)
        body, update = _split_table_size_update(block)
        ours = encoder.encode(fields)
        if ours == body:
            note = ("" if update is None else
                    f" (after a {len(block) - len(body)}B dynamic table size "
                    f"update to {update}, which hpack does not emit)")
            print(f"  {label:<9} {len(block)}B  IDENTICAL{note}")
            continue
        ok = False
        print(f"  {label:<9} {len(block)}B captured, {len(ours)}B ours  DIFFER")
        for i in range(max(len(body), len(ours))):
            if body[i:i + 1] != ours[i:i + 1]:
                print(f"      first difference at byte {i}: "
                      f"{body[i:i + 1].hex() or '--'} vs {ours[i:i + 1].hex() or '--'}")
                break
    return ok


# --- importing a mitmproxy capture ------------------------------------------

#: The dump layout mitm_addon.py writes. Bumped together with it, so a dump
#: from an older addon is refused instead of misread.
MITM_FORMAT = 2

#: selftest_one's return for "this capture cannot be replayed on this machine",
#: as distinct from 0 (matched) and 1 (differed).
SKIPPED = 2


def capture_mitm(args: argparse.Namespace) -> int:
    """Run mitmproxy with our addon loaded, then import what it recorded.

    mitmproxy is a separate process, not an import. It may now be the *same*
    interpreter - `install-python.sh` builds 3.12 against the fork, which is
    what mitmproxy requires - but it need not be, and running it out of process
    is what keeps a standalone build or a pipx venv working unchanged. It is
    also why the addon is passed by path rather than by module name: it is read
    by whichever interpreter mitmdump happens to be.
    """
    from . import addon_path

    # Alongside this interpreter first. `install-python.sh --with-mitmproxy`
    # puts it there, and a pyenv interpreter's bin/ is normally not on PATH -
    # so without this the one case the script sets up is the one that is not
    # found. PATH still wins if --mitmdump was not given and nothing is beside
    # us, which keeps a pipx or distro install working as before.
    beside = Path(sys.executable).parent / "mitmdump"
    mitmdump = (args.mitmdump
                or (str(beside) if beside.exists() else None)
                or shutil.which("mitmdump"))
    if not mitmdump:
        print("mitmdump was not found beside this interpreter or on PATH.\n\n"
              "  ./install-python.sh --with-mitmproxy   # into this interpreter\n"
              "  pipx install mitmproxy                 # or keep it separate\n\n"
              "or point at one with --mitmdump. It does not have to be this "
              "Python: the addon is loaded by path and imports nothing from "
              "mytls, so any interpreter >= 3.12 will do.",
              file=sys.stderr)
        return 2

    out = Path(args.out).resolve()
    out.mkdir(parents=True, exist_ok=True)
    argv = [mitmdump, "-s", addon_path(),
            "--set", f"fp_out={out}",
            "--mode", args.mode]
    # Several --host become one alternation: the addon takes a single regex,
    # and asking a caller to write the `|` themselves is asking them to quote
    # it past a shell as well.
    hosts = "|".join(f"(?:{h})" for h in args.host) if args.host else ""
    if hosts:
        argv += ["--set", f"fp_hosts={hosts}"]
    for pattern in args.ignore_hosts or ():
        argv += ["--ignore-hosts", pattern]
    if args.port is not None:
        argv += ["--listen-port", str(args.port)]
    # argparse.REMAINDER hands back the "--" that separated our options from
    # mitmdump's, which mitmdump should not see.
    extra = args.extra[1:] if args.extra[:1] == ["--"] else args.extra
    argv += extra

    ca = Path(os.environ.get("MITMPROXY_CONFDIR", Path.home() / ".mitmproxy"))
    print(f"  addon    {addon_path()}")
    print(f"  dumps    {out}")
    print(f"  hosts    {hosts or 'every TLS connection (consider --host)'}")
    if args.ignore_hosts:
        print(f"  ignored  {', '.join(args.ignore_hosts)}   "
              f"(passed through untouched, never decrypted)")
    print(f"  CA cert  {ca}/mitmproxy-ca-cert.pem   (http://mitm.it from the "
          f"device once it is proxied)")
    print("\nBrowse the site, then stop with Ctrl-C.\n")
    # mitmdump writes straight to the terminal; without this our own preamble
    # sits in a buffer and surfaces underneath its output.
    sys.stdout.flush()

    proc = subprocess.Popen(argv)
    # Ctrl-C goes to the whole foreground group, so mitmdump gets it too and
    # starts shutting down. Wait for it rather than racing it: its `done` hook
    # is where connections still open get written out.
    #
    # Every interrupt has to be swallowed, not just the first. Shutting down
    # takes a moment, a second Ctrl-C is the natural reaction to that, and if
    # it escaped here it would kill this process while mitmdump was still
    # flushing - which loses the import, and looks exactly like the capture
    # silently doing nothing. mitmdump still receives each one through the
    # group, so its own force-quit path is unaffected.
    interrupted = False
    while True:
        try:
            proc.wait(timeout=None if not interrupted else 20)
            break
        except KeyboardInterrupt:
            if not interrupted:
                print("\nstopping mitmproxy, waiting for it to write out what "
                      "it has...", flush=True)
            interrupted = True
        except subprocess.TimeoutExpired:
            print("mitmproxy has not stopped; terminating it.", flush=True)
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except (subprocess.TimeoutExpired, KeyboardInterrupt):
                proc.kill()
            break

    if proc.returncode not in (0, None) and not interrupted:
        print(f"\nmitmdump exited with {proc.returncode} - see its output "
              f"above.", file=sys.stderr)

    dumps = sorted(p for p in out.iterdir() if p.suffix == ".json")
    print(f"\n{len(dumps)} dump(s) in {out}")
    if not dumps:
        print("  nothing was captured. Check that the device really went "
              "through the proxy, that it trusts the CA, and that --host "
              "matches the SNI you were after.", file=sys.stderr)
        return 1
    if not args.brand:
        print(f"  import them with:\n"
              f"    mytls-probe import-mitm {out} --brand <name>")
        return 0

    print(f"\n=== importing into {args.brand} ===")
    rc = import_mitm(argparse.Namespace(
        source=str(out), brand=args.brand, out=None,
        allow_resumed=args.allow_resumed))
    if rc:
        # The dumps are the expensive part - they took a browsing session to
        # collect. Say plainly that nothing was written and that they survive,
        # rather than leaving a non-zero exit to be inferred from.
        print(f"\nno profile was written. The dumps are still in {out} - fix "
              f"whatever is reported above and re-run:\n"
              f"    mytls-probe import-mitm {out} --brand {args.brand}",
              file=sys.stderr)
    return rc


def read_mitm_dump(path: Path) -> dict | None:
    """Turn one raw mitmproxy dump into the same shape `serve` produces.

    The dump is a whole connection, not one request. The profile takes the part
    that matches what `serve` records: everything up to and including the
    *first* HEADERS, whose HPACK block is encoded against an empty table.

    The xhr template is taken from the same connection, never another one, and
    this matters more than it looks. An xhr block is encoded against a table
    the navigation already filled - all three stored profiles fail to decode
    with a fresh decoder and decode cleanly after their navigation - so its
    bytes are only meaningful in that sequence. Our own client is driven the
    same way, navigation then xhr on one connection, so its encoder reaches the
    same state and the two are comparable. Lifting a cors request off a
    different connection would give a cold-table encoding that matches nothing.

    Returns None for a connection with no usable request in it, which is
    ordinary - browsers open connections they never use.
    """
    import hpack

    dump = json.loads(path.read_text())
    if dump.get("format") != MITM_FORMAT:
        print(f"  {path.name}: format {dump.get('format')!r}, expected "
              f"{MITM_FORMAT} - written by a different mitm_addon.py, skipped",
              file=sys.stderr)
        return None

    ch = parse_client_hello(bytes.fromhex(dump["client_hello"]))
    if ch is not None and not dump.get("client_hello_exact"):
        # The addon could not catch the ClientHello on the wire and had to let
        # mitmproxy synthesise a record header, which is always stamped 0x0303
        # whatever the browser sent. None says "not measured here" rather than
        # recording that artefact; no fingerprint reads this field anyway.
        ch["record_version"] = None

    decoder = hpack.Decoder()
    frames: list[dict] = []
    profile_frames: list[dict] | None = None
    navigation: tuple[dict, list] | None = None
    xhr: dict | None = None
    requests = 0

    for ftype, flags, stream, payload in frames_from_stream(
            bytes.fromhex(dump["client"])):
        described = describe(ftype, flags, stream, payload)
        if profile_frames is None:
            frames.append(described)
        if ftype != 1:  # only HEADERS carry a request
            continue
        if profile_frames is None:
            profile_frames = frames      # ends with this HEADERS, as serve does
        block = described.get("header_block")
        if block is None:
            continue
        if not flags & 0x04:  # END_HEADERS
            print(f"  {path.name}: a HEADERS frame is continued into "
                  f"CONTINUATION, which nothing here reassembles - skipped",
                  file=sys.stderr)
            return None
        try:
            decoded = _decode_with(decoder, bytes.fromhex(block))
        except Exception as exc:  # noqa: BLE001 - one bad dump, not a crash
            print(f"  {path.name}: HPACK decoding failed at request "
                  f"{requests + 1} ({type(exc).__name__}: {exc}). The stream is "
                  f"misaligned, most likely recorded from part-way through a "
                  f"connection - skipped", file=sys.stderr)
            return None
        requests += 1
        if navigation is None:
            navigation = (described, decoded)
        elif xhr is None and _request_kind(dict(decoded)) == "cors":
            xhr = {
                "header_block": block,
                "priority": described.get("priority"),
                "headers": [[k, v] for k, v in decoded if not k.startswith(":")],
            }

    if navigation is None or profile_frames is None:
        return None
    first, headers = navigation
    flat = dict(headers)
    return {
        "path": path,
        "sni": dump.get("sni"),
        "alpn": dump.get("alpn"),
        "resumed": carries_psk(ch),
        "kind": _request_kind(flat),
        "requests": requests,
        "headers": headers,
        "user_agent": flat.get("user-agent", ""),
        "record": {
            "frames": profile_frames,
            "client_hello": ch,
            "captured_at": dump.get("captured_at", ""),
        },
        "xhr": xhr,
    }


#: What a request whose client sends no Fetch Metadata at all is called here.
#: Not a `sec-fetch-mode` value - that is the point of it.
UNLABELLED = "unlabelled"


def _request_kind(flat: dict) -> str:
    """navigate, cors, ... - which template this request would exercise.

    `sec-fetch-mode` says it outright wherever it is sent, and where it is sent
    it is authoritative: a request the browser itself calls `cors` is not a
    navigation, whatever else it looks like.

    Where it is absent the question is different, because `sec-fetch-*` is a
    browser header - the Fetch spec's, not HTTP's. A native client, an iOS app
    on NSURLSession, anything that is not a browser, sends none of it and has
    no notion of a navigation to report. Such a request is `unlabelled`: not
    "not a navigation", but "this client does not classify its requests".
    Those are still worth capturing - the ClientHello and the HTTP/2 layer do
    not care what a request is for - so `import-mitm` takes them, and says so.

    An old browser is the one case in between: it sends no Fetch Metadata but
    does ask for HTML on a navigation, which is enough to call it one.
    """
    mode = flat.get("sec-fetch-mode")
    if mode:
        return mode
    if flat.get("accept", "").startswith("text/html"):
        return "navigate"
    return UNLABELLED


def import_mitm(args: argparse.Namespace) -> int:
    """Build a profile out of what mitm_addon.py recorded off a real site."""
    source = Path(args.source)
    paths = (sorted(p for p in source.iterdir() if p.suffix == ".json")
             if source.is_dir() else [source])
    if not paths:
        print(f"no dumps in {source}", file=sys.stderr)
        return 2

    found = [d for d in (read_mitm_dump(p) for p in paths) if d]
    if not found:
        print(f"{len(paths)} dump(s) in {source}, none with a complete request "
              f"in it. Capture again and let the page finish loading.",
              file=sys.stderr)
        return 2

    print(f"{len(found)} connection(s) with a request:")
    for d in found:
        print(f"  {d['path'].name:<38} {d['sni'] or '?':<26} "
              f"{d['alpn'] or '?':<5} {d['kind']:<10} {d['requests']:>3} req"
              f"{'  +xhr' if d['xhr'] else '':<6}"
              f"{'  RESUMED' if d['resumed'] else ''}")

    usable = [d for d in found if not d["resumed"]] if not args.allow_resumed else found
    if not usable:
        print("\nevery connection resumed a session, so every ClientHello here "
              "carries a pre_shared_key our client never sends. mitmproxy "
              "cannot be told to stop issuing tickets, so clear the browser's "
              "TLS state (a fresh --user-data-dir, or a new private window on "
              "iOS) and capture again.", file=sys.stderr)
        return 1

    # A navigation is what the default header template reproduces, so it is
    # what to look for. Failing that, a client that sends no Fetch Metadata at
    # all has no navigation to find and its one kind of request is the one to
    # take - see _request_kind. What is refused is the middle case: a browser
    # that told us this request was a subresource, where taking it would put
    # cors headers into a template that claims to be a navigation.
    navigations = [d for d in usable if d["kind"] == "navigate"]
    unlabelled = [d for d in usable if d["kind"] == UNLABELLED]
    if not navigations and not unlabelled:
        print(f"\nevery connection here carries a request the client itself "
              f"labelled as something other than a navigation "
              f"({', '.join(sorted({d['kind'] for d in usable}))}). The "
              f"profile's header template is a navigation, so it cannot be "
              f"built from these.\n"
              f"  - from a browser: open the site in a new tab once the proxy "
              f"is running, so a fresh connection carries the document "
              f"request first\n"
              f"  - check --host matches the domain serving the HTML, not just "
              f"a CDN", file=sys.stderr)
        return 1

    # Prefer a navigation that also carried a cors request, so both templates
    # come from one connection and the xhr block's HPACK state is the one our
    # client reaches. A navigation alone is still fine; it just leaves the xhr
    # template as it was.
    if navigations:
        navigation = next((d for d in navigations if d["xhr"]), navigations[0])
    else:
        navigation = unlabelled[0]
        accept = dict(navigation["headers"]).get("accept", "(none)")
        print(f"\nnote: this client sends no sec-fetch-* headers, so nothing "
              f"says which of its requests are navigations - it is not a "
              f"browser, or not a recent one. Taking the first request on "
              f"{navigation['path'].name} as the template; it asked for "
              f"{accept[:48]!r}. Check that is the request you meant to "
              f"reproduce.", file=sys.stderr)
    xhr = navigation["xhr"]

    record = navigation["record"]
    if args.out:
        # --out decides where the file goes; --brand, when given, still says
        # whose bytes are in it. Dropping the name here left a capture that had
        # been named claiming nothing, and the loader falls back to the file's
        # stem - so `--brand ios18a --out aaa.json` loaded as brand `aaa`.
        # Without a --brand the file stays anonymous, which is what makes an
        # --out capture safe to rename and try out under any name.
        out, brand, filed = Path(args.out), args.brand, False
        if brand:
            profile_path(brand)          # reject a bad name before writing it
    else:
        brand, filed = args.brand or brand_of(record), True
        out = profile_path(brand)
        out.parent.mkdir(parents=True, exist_ok=True)
    if brand:
        record = {"brand": brand, **record}
    if xhr is not None:
        record["xhr"] = xhr
    kept = carried_meta(out)
    if kept:
        record["meta"] = kept

    replacing = out.exists()
    out.write_text(json.dumps(record, indent=2))
    label = "navigation" if navigation["kind"] == "navigate" else "request"
    print(f"\n  {label} from {navigation['path'].name}: "
          f"{navigation['user_agent'] or '?'}")
    if kept:
        print(f"  kept the meta the old file carried: {', '.join(kept)}")
    if xhr:
        print(f"  xhr from the same connection "
              f"({len(xhr['header_block']) // 2}B)")
    elif navigation["kind"] == "navigate":
        print("  !! no cors request on that connection, so this profile has "
              "no xhr template. Load a page that fetches something, and take "
              "the capture from the connection that carried both.")
    else:
        # Nothing here reports a cors request, so there is no second template
        # to look for and its absence is not a shortfall.
        print("  no xhr template - this client does not label its requests, "
              "so there is only the one")
    print(f"  {'replaced' if replacing else 'stored as'} {out}")

    summarise(record)
    # Only for a capture that was filed under its brand: report_profile reads
    # it back out of the profiles directory, and an --out file is not there -
    # naming one would report whatever else already holds that brand.
    if filed:
        report_profile(brand)
    return 0


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
    # `:authority` is inside the HPACK block and its host half decides whether
    # an SNI goes out, so a capture reproduces exactly only when it is
    # addressed the way the browser addressed it. Where that is possible it is
    # done. Where it is not - a capture taken off a real site names that site,
    # and this machine neither holds its address nor may bind :443 - the
    # request goes somewhere reachable and `:authority` joins `excused`.
    # Refusing to run at all was the old behaviour and it cost everything: the
    # ClientHello, the frame layer and the header order were all measurable the
    # whole time, and every capture taken through mitmproxy is in this position.
    authority = authority_of(ref)
    host, want = split_authority(authority)
    excused: set[str] = set()

    if port is not None and port != want:
        print(f"note: {brand} was captured on port {want}; using {port} instead.")
        authority, excused = f"{host}:{port}", {":authority"}
    else:
        port = want

    if not can_bind(host):
        # A phone capture came in over the LAN, and that address belongs to
        # whatever the browser could reach - a router-assigned one that has
        # since changed, or under WSL the Windows host rather than this VM.
        print(f"note: {brand} was captured at {host}, which is not an address "
              f"this machine holds, so the request goes to localhost instead."
              + (" The capture carried no SNI while this one does, so the "
                 "ClientHello will differ by one extension." if _is_ip(host) else ""))
        authority, excused = f"localhost:{port}", {":authority"}

    ctx = tls_context(openssl)
    try:
        srv = listen(port)
    except OSError as exc:
        # Not being able to bind the captured port is a fact about this machine,
        # not about the capture. Move to one that is free and say so; the port
        # is part of `:authority`, which is already excused above whenever the
        # host was, and is excused here when it was not.
        host, _, _ = authority.partition(":")
        for fallback in (8443, 0):
            try:
                srv = listen(fallback)
            except OSError:
                continue
            port = srv.getsockname()[1]
            print(f"note: cannot listen on :{split_authority(authority)[1]} "
                  f"({exc}); using :{port} instead.")
            authority = f"{host}:{port}"
            excused.add(":authority")
            break
        else:
            print(f"no port could be bound at all, so {source} cannot be "
                  f"replayed here.", file=sys.stderr)
            return SKIPPED

    got: list[dict] = []
    want_xhr = ref.get("xhr") is not None
    thread = threading.Thread(
        target=lambda: got.extend(filter(None, [
            capture(srv, ctx, quiet=True, want_xhr=want_xhr, timeout=10.0)])),
        daemon=True)
    thread.start()
    import hpack

    # One decoder, in order: the xhr block indexes into the table the first
    # block built, so decoding it on its own raises InvalidTableIndex.
    decoder = hpack.Decoder()
    frame = next(f for f in ref["frames"] if f["type"] == "HEADERS")
    pseudo = dict(_decode_with(decoder, bytes.fromhex(frame["header_block"])))
    xhr_pseudo = dict(
        _decode_with(decoder, bytes.fromhex(ref["xhr"]["header_block"]))
        if ref.get("xhr") else [])
    try:
        run_client(authority, brand, quiet=True, like=pseudo,
                   xhr=ref.get("xhr"),
                   method=pseudo.get(":method", "GET"),
                   path=pseudo.get(":path", "/api/all"),
                   xhr_method=xhr_pseudo.get(":method", "GET"),
                   xhr_path=xhr_pseudo.get(":path", "/xhr-sample"))
    finally:
        thread.join(timeout=20)
        srv.close()
        thread.join(timeout=5)

    if not got:
        print(f"the probe captured nothing for {brand}", file=sys.stderr)
        return 1

    print(f"=== {brand}: our bytes vs {source} ===\n")
    rc = diff_records(ref, got[0], brand, "ours", excused=excused)
    # Always, not only when something was excused: it is the one check that
    # judges the encoder on the browser's own fields, and it costs no network.
    return rc or (0 if diff_hpack_offline(ref, brand) else 1)


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
            verdict = {0: "PASS", SKIPPED: "SKIP (not replayable here)"}
            print(f"  {brand:<16} {verdict.get(rc, 'FAIL')}")
    # A skip is not a pass, but it is not a failure either - exiting non-zero
    # on it would make "some profile came from a real site" look like a broken
    # build for anyone running this in CI.
    return 0 if all(rc in (0, SKIPPED) for rc in results.values()) else 1


def one_client_hello(brand: str, sni: str, alpn: typing.Sequence[str] = ("h2", "http/1.1")
                     ) -> bytes:
    """The ClientHello this brand emits for `sni`, caught off a local socket.

    No server, no certificate, no handshake: the ClientHello is the first thing
    on the wire, so accepting the connection and reading once is enough. The
    peer then closes and OpenSSL fails, which is the expected outcome here.
    """
    from . import browser_fp

    got: dict[str, bytes] = {}
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]

    def accept_one() -> None:
        conn, _ = srv.accept()
        got["raw"] = peek_client_hello(conn)
        conn.close()

    thread = threading.Thread(target=accept_one, daemon=True)
    thread.start()
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_alpn_protocols(list(alpn))
    browser_fp.tls_profile.set_profile(ctx, browser_fp.profile(brand).tls_profile)
    sock = socket.create_connection(("127.0.0.1", port), timeout=5)
    try:
        ctx.wrap_socket(sock, server_hostname=sni)
    except OSError:
        pass                       # no server on the other end; expected
    finally:
        sock.close()
        thread.join(timeout=5)
        srv.close()
    return got.get("raw", b"")


#: What a padded ClientHello aims for, in handshake bytes (RFC 7685 / the F5
#: workaround; 5 more on the wire for the record header).
PAD_TARGET = 512


#: Extensions a *client* chooses per connection rather than inheriting from the
#: network stack, so a difference here does not mean a different stack.
#:
#: Measured on one iOS 16.7.12 device in a single session: the App Store's
#: amp-api and xp.apple.com connections offer an empty session_ticket while the
#: same device's mzstatic, fpinit and weather-edge connections do not - same OS,
#: same ciphers, same groups, same HTTP/2 fingerprint. So `match` reports it,
#: and does not let it turn a match into a miss. See
#: SSL_CTX_set_fp_empty_ticket() and Transport(session_ticket=...).
APP_CONTROLLED_EXTS = {"0x0023"}

#: Extensions whose body is decided by the host the capture was taken against,
#: so two captures of one client to different sites disagree about them by
#: construction. server_name is the name; padding compensates for its length,
#: which is why comparing two captures cannot be a byte comparison the way
#: comparing our own output against one capture can.
HOST_DEPENDENT_EXTS = {"0x0000", "0x0015"}


def stack_shape(raw: bytes, *, measured_record_version: bool = True) -> dict:
    """What a ClientHello says about the network stack that built it.

    Everything a capture of one client to *any* host has in common with a
    capture of the same client to any other: the record header, the session id
    length, the cipher list, the extension order, and every extension body
    except the ones the host decides.

    Not a byte comparison, and it cannot be one - `selftest` compares our own
    output against one capture and can hold the SNI equal, but two captures
    taken against different sites carry different names, hence different
    padding, hence different lengths throughout. What is left after removing
    those is still the whole fingerprint-bearing part of the message.

    That is the reason for the two fields no published fingerprint reads.
    `session_id_len` is 32 for every client measured so far, because they all
    run TLS 1.3 in middlebox-compatibility mode - but a client that does not
    send a legacy session id is a different stack, and ja3, ja4 and peetprint
    would all call it the same one. `record_version` is 0x0301 throughout for
    the same kind of reason. Neither has ever differed here; both are compared
    so that the first client that differs is not silently absorbed.

    `measured_record_version=False` for a capture whose record header mitmproxy
    synthesised - see `read_mitm_dump`. The field is then None and skipped,
    rather than reporting the artefact 0x0303 as a property of the client.
    """
    canon, _, problems = canonical_client_hello(raw)
    exts = extension_sequence(canon, raw)
    o = 43
    sid = canon[o]
    o += 1 + sid
    n = int.from_bytes(canon[o:o + 2], "big")
    ciphers = [("GREASE" if int.from_bytes(raw[o + 2 + i:o + 4 + i], "big") in GREASE
                else f"0x{int.from_bytes(raw[o + 2 + i:o + 4 + i], 'big'):04x}")
               for i in range(0, n, 2)]
    o += 2 + n
    return {
        "record_version": (f"0x{int.from_bytes(raw[1:3], 'big'):04x}"
                           if measured_record_version else None),
        "legacy_version": f"0x{int.from_bytes(canon[9:11], 'big'):04x}",
        "session_id_len": sid,
        "ciphers": ciphers,
        "compression": canon[o:o + 1 + canon[o]].hex(),
        "extension_order": [k for k, _ in exts],
        "bodies": {k: v.hex() for k, v in exts
                   if k not in HOST_DEPENDENT_EXTS and k != "GREASE"},
        "problems": problems,
    }


def _dump_record(path: Path) -> dict | None:
    """The ClientHello and h2 frames of one capture, whatever wrote it.

    Accepts a mitm_addon dump, a `serve` profile and a `--out` capture alike,
    and unlike `read_mitm_dump` it does not insist on a decodable request - a
    connection that only ever produced a ClientHello still says which stack
    made it, which is the whole question here.

    `exact` says whether the five record header bytes are the client's own. A
    dump the addon could not catch on the wire carries a header mitmproxy
    synthesised, stamped 0x0303 whatever the client sent, and a profile
    imported from one records `record_version: null` to remember that.
    """
    data = json.loads(path.read_text())
    if "client" in data and data.get("format") == MITM_FORMAT:
        raw = bytes.fromhex(data["client_hello"])
        frames = [describe(*f) for f in
                  frames_from_stream(bytes.fromhex(data["client"]))]
        return {"sni": data.get("sni"), "alpn": data.get("alpn"),
                "raw": raw, "frames": frames,
                "exact": bool(data.get("client_hello_exact"))}
    ch = data.get("client_hello")
    if isinstance(ch, dict) and ch.get("raw"):
        return {"sni": None, "alpn": None, "raw": bytes.fromhex(ch["raw"]),
                "frames": data.get("frames") or [],
                "exact": ch.get("record_version") is not None}
    return None


def _first_request(frames: list[dict]) -> dict[str, str]:
    """The first request's headers on a connection, or {} if there is none.

    Only the first, and only ever the first: HPACK indexes into a table the
    earlier blocks built, so a later block cannot be decoded on its own, while
    this one is guaranteed to decode against an empty table.

    A capture recorded from part-way through a connection decodes to nothing
    rather than raising - it is a fine capture of a ClientHello and simply has
    no readable request in it.
    """
    frame = next((f for f in frames
                  if f["type"] == "HEADERS" and f.get("header_block")), None)
    if frame is None:
        return {}
    try:
        return dict(_decode(bytes.fromhex(frame["header_block"])))
    except Exception:  # noqa: BLE001 - one unreadable block, not a failed run
        return {}


def _headers_priority(frames: list[dict]) -> tuple | None:
    """RFC 7540 priority on the first HEADERS frame, or None if it carries none.

    A tuple rather than the dict it comes from, so that it compares by value
    and `None` stays distinguishable from "priority with everything at zero".
    """
    frame = next((f for f in frames if f["type"] == "HEADERS"), None)
    prio = frame.get("priority") if frame else None
    return (None if not prio else
            (prio["exclusive"], prio["depends_on"], prio["weight"]))


def _priority_text(prio: tuple | None) -> str:
    if prio is None:
        return "none"
    exclusive, depends_on, weight = prio
    return (f"{'exclusive ' if exclusive else ''}"
            f"depends_on={depends_on} weight={weight}")


def match(args: argparse.Namespace) -> int:
    """Which installed profile, if any, produced each of these captures.

    The question this answers is not "is our client right" - `selftest` does
    that - but "does this recording come from the stack a profile describes".
    That is how an app is shown to be on the system stack rather than carrying
    its own: five unrelated iOS clients agreeing on every field below is what
    established that the iOS profiles belong to the OS and not to Safari.

    Differences are reported in two groups, because they answer different
    questions. A cipher list or a SETTINGS frame that disagrees means a
    different stack or a different version of one. An `0x0023` that disagrees
    means the same stack and a differently configured app - that one is the
    caller's to set, so it never turns a match into a miss.
    """
    from . import browser_fp

    paths: list[Path] = []
    for name in args.source:
        root = Path(name)
        paths += sorted(root.rglob("*.json")) if root.is_dir() else [root]
    if not paths:
        print(f"no .json under {', '.join(args.source)}", file=sys.stderr)
        return 2

    brands = [args.brand] if args.brand else list(browser_fp.brands())
    wanted = {}
    for brand in brands:
        prof_path = profile_path(brand)
        rec = _dump_record(prof_path)
        if rec is None:
            print(f"{brand}: {prof_path} has no ClientHello to match against",
                  file=sys.stderr)
            return 2
        wanted[brand] = (stack_shape(rec["raw"],
                                     measured_record_version=rec["exact"]),
                         akamai_fingerprint({"frames": rec["frames"]})
                         if rec["frames"] else None,
                         _headers_priority(rec["frames"]))

    tally: dict[str, int] = {}
    unmatched = 0
    for path in paths:
        try:
            rec = _dump_record(path)
        except Exception as exc:                       # noqa: BLE001
            print(f"{path}: unreadable ({type(exc).__name__}: {exc})")
            continue
        if rec is None:
            continue
        try:
            shape = stack_shape(rec["raw"],
                                measured_record_version=rec["exact"])
        except Malformed as exc:
            print(f"{path.name}: malformed ClientHello ({exc})")
            unmatched += 1
            continue
        theirs = (akamai_fingerprint({"frames": rec["frames"]})
                  if any(f["type"] == "HEADERS" for f in rec["frames"]) else None)

        label = rec["sni"] or path.stem
        # Reported, not compared. The verdict below comes from the fields
        # themselves; a hash could only ever be a lossier way of asking the
        # same thing, and JA3 in particular is blind to two of the differences
        # that matter here - it does not cover signature algorithms at all
        # (iOS 16 and iOS 18 share a JA3 and differ in JA4), and it hashes the
        # extension list in wire order, so a shuffling client never repeats
        # one. Both are printed because between them they place a capture at a
        # glance, and because "same JA3, different JA4" is worth seeing.
        f = fingerprints.of_client_hello(rec["raw"])
        print(f"\n{path.name}")
        print(f"  {label}  alpn={rec['alpn'] or '?'}")
        print(f"  ja3={f['ja3_hash']}  ja4={f['ja4']}")
        print(f"  akamai={theirs or '(no h2 request in this connection)'}")
        # Which OS made this connection, when it said so. Only a capture that
        # got as far as a request can answer that at all - the ClientHello
        # names no one - so the line is absent rather than empty when there is
        # no request, where the akamai line above has already said why.
        request = _first_request(rec["frames"])
        if request:
            system = browser_fp.system_of(request)
            # Falling back to the user-agent rather than printing "unknown":
            # when the OS cannot be read, what it could not be read from is
            # the useful thing to see.
            print(f"  system={system}" if system else
                  f"  system=?  ua={request.get('user-agent', '(none sent)')[:72]}")
        for text in shape["problems"]:
            print(f"  !! {text}")
        # Said once about the capture, not once per brand: a ClientHello with
        # no server_name is a fact about how the recording was made, and it
        # decides the outcome against every profile that has one. RFC 6066
        # allows no IP literal there, so a client reaching the server by
        # address omits the extension entirely rather than filling it in.
        if "0x0000" not in shape["extension_order"]:
            print("  !! no SNI in this ClientHello - the client reached the "
                  "server by IP address.")
            print("     Against a profile recorded through a hostname this is "
                  "an extension set that")
            print("     differs by 0x0000 alone and can never match. Re-record "
                  "over a hostname")
            print("     (`serve --host 192-168-1-7.nip.io`) to compare the TLS "
                  "half at all.")

        their_prio = _headers_priority(rec["frames"])

        hit = False
        for brand, (want_shape, want_akamai, want_prio) in wanted.items():
            stack, app = _shape_diff(want_shape, shape)
            if theirs is not None and want_akamai is not None and theirs != want_akamai:
                stack.append(f"akamai {want_akamai} vs {theirs}")
            # Reported like the empty session_ticket and for the same measured
            # reason: on one iOS TLS stack, Safari puts priority on its HEADERS
            # frame and the CFNetwork apps send none - 72 captures with none and
            # 2 with it all match `ios16` on every other field. So it says which
            # client, not which stack, and never turns a match into a miss. The
            # akamai fingerprint's third field cannot see it: that counts
            # standalone PRIORITY frames, which none of these clients send.
            if theirs is not None and their_prio != want_prio:
                app.append(f"HEADERS priority {_priority_text(want_prio)} "
                           f"vs {_priority_text(their_prio)}")
            if stack:
                if args.brand or args.verbose:
                    print(f"  {brand:<16} no - {'; '.join(stack[:4])}"
                          + (f" (+{len(stack) - 4} more)" if len(stack) > 4 else ""))
                continue
            hit = True
            tally[brand] = tally.get(brand, 0) + 1
            note = f" [app-controlled: {'; '.join(app)}]" if app else ""
            print(f"  {brand:<16} MATCH{note}")
        if not hit:
            unmatched += 1
            if not (args.brand or args.verbose):
                print("  no installed profile matches this stack")

    print(f"\n=== {len(paths)} file(s) ===")
    for brand, n in sorted(tally.items()):
        print(f"  {brand:<16} {n} match(es)")
    if unmatched:
        print(f"  {'unmatched':<16} {unmatched}")
    return 0


def _shape_diff(want: dict, got: dict) -> tuple[list[str], list[str]]:
    """(differences that mean a different stack, differences an app chooses)."""
    stack: list[str] = []
    app: list[str] = []
    for key in ("legacy_version", "compression"):
        if want[key] != got[key]:
            stack.append(f"{key} {want[key]} vs {got[key]}")
    # Only where both sides measured it: a capture imported from a dump the
    # addon could not catch on the wire has mitmproxy's synthetic 0x0303 here,
    # and reporting that would be reporting mitmproxy, not the client.
    if (want["record_version"] and got["record_version"]
            and want["record_version"] != got["record_version"]):
        stack.append(f"record_version {want['record_version']} "
                     f"vs {got['record_version']}")
    if want["session_id_len"] != got["session_id_len"]:
        stack.append(f"session_id {want['session_id_len']} bytes "
                     f"vs {got['session_id_len']}")
    if want["ciphers"] != got["ciphers"]:
        stack.append(f"{len(want['ciphers'])} ciphers vs {len(got['ciphers'])}"
                     if len(want["ciphers"]) != len(got["ciphers"])
                     else "cipher list differs")

    wo = [e for e in want["extension_order"] if e not in APP_CONTROLLED_EXTS]
    go = [e for e in got["extension_order"] if e not in APP_CONTROLLED_EXTS]
    #: Extensions the extension-set difference below already named, so that the
    #: body walk does not say the same thing again in other words.
    named: set[str] = set()
    if wo != go:
        # An SNI-less capture is off by exactly one extension from every
        # profile taken through a hostname, and "extension set differs (16 vs
        # 15)" sends the reader counting extension lists to rediscover that.
        # Named here, and again as a note on the capture itself in `match`.
        missing = [e for e in dict.fromkeys(wo) if e not in go]
        extra = [e for e in dict.fromkeys(go) if e not in wo]
        if sorted(wo) == sorted(go):
            stack.append("extension order differs")
        elif missing == ["0x0000"] and not extra:
            stack.append("no SNI in the capture (0x0000), the profile has one")
        elif extra == ["0x0000"] and not missing:
            stack.append("no SNI in the profile (0x0000), the capture has one")
        elif (missing or extra) and len(missing) + len(extra) <= 4:
            # Which extension, not how many: a count leaves the reader to align
            # two lists to find that out, and says nothing at all when one
            # extension replaced another (the old "16 vs 16"). Capped because
            # this line is joined with the other differences and truncated.
            parts = []
            if missing:
                parts.append(f"lacks {' '.join(missing)}")
            if extra:
                parts.append(f"adds {' '.join(extra)}")
            stack.append("capture " + " and ".join(parts))
            named = set(missing) | set(extra)
        else:
            # Too many to name, so how many of each - the two totals alone can
            # be equal while the sets differ, which says nothing at all.
            #
            # Both are empty for a difference in nothing but repeats, which in
            # practice means a different number of GREASE entries: nothing to
            # name and nothing to count, but the totals do differ there, since
            # every GREASE is an entry of its own. Two of any other extension
            # is illegal and `canonical_client_hello` reports it as a problem.
            detail = ", ".join(p for p in
                               (f"{len(missing)} gone" if missing else "",
                                f"{len(extra)} new" if extra else "") if p)
            stack.append(f"extension set differs ({len(wo)} vs {len(go)}"
                         + (f": {detail})" if detail else ")"))
    for name in sorted(set(want["bodies"]) | set(got["bodies"])):
        w, g = want["bodies"].get(name), got["bodies"].get(name)
        if w == g:
            continue
        if w is None or g is None:
            # An extension present on one side only was already named above,
            # unless there were too many to name. Repeating it in other words
            # costs a slot on a line that is cut off after four differences.
            if name in named:
                continue
            text = (f"{name} in the capture, not in the profile" if w is None
                    else f"{name} in the profile, not in the capture")
        else:
            text = f"{name} body differs"
        (app if name in APP_CONTROLLED_EXTS else stack).append(text)
    return stack, app


def _hostname_of_length(n: int) -> str:
    """A syntactically valid hostname of exactly `n` characters.

    Not just `"a" * n`: a DNS label is capped at 63 bytes and Python's idna
    codec enforces it, so anything longer has to be split into labels. What is
    being varied here is the length of the SNI on the wire, and the dots count
    towards it exactly like any other byte.
    """
    if n <= 63:
        return "a" * n
    parts, left = [], n
    while left > 63:
        parts.append("a" * 63)
        left -= 64                       # 63 characters and the dot after them
    parts.append("a" * max(left, 1))
    return ".".join(parts)[:n]


def sniscan(args: argparse.Namespace) -> int:
    """Emit a ClientHello at many SNI lengths and check the shape holds.

    The one thing `selftest` cannot see. It compares against a capture taken at
    one address, so it exercises exactly one SNI length - but a padded profile
    computes its padding from the *total* length, so a different hostname moves
    a byte count that nothing else in the tree ever varies. A padding rule that
    is off by one, or that gives up past some length, would pass the self-test
    every time and then send a differently-shaped ClientHello to the first real
    site with a longer name than the probe's.

    A padded profile must come out at exactly 512 bytes of handshake (517 on
    the wire) until the message no longer fits, and then grow without padding.
    An unpadded one must simply grow with the name.
    """
    from . import browser_fp

    brands = [args.brand] if args.brand else list(browser_fp.brands())
    rc = 0
    for brand in brands:
        print(f"=== {brand} ===")
        rows: list[tuple[int, int, int | None]] = []
        for n in range(1, args.max_length + 1, args.step):
            host = _hostname_of_length(n)
            try:
                raw = one_client_hello(brand, host)
            except Exception as exc:                       # noqa: BLE001
                print(f"  {len(host):3d} chars: FAILED ({type(exc).__name__}: {exc})")
                rc = 1
                continue
            if not raw:
                print(f"  {len(host):3d} chars: no ClientHello captured")
                rc = 1
                continue
            pad = next((len(body) for kind, body in
                        extension_sequence(raw, raw) if kind == "0x0015"), None)
            rows.append((len(host), len(raw), pad))

        if not rows:
            rc = 1
            continue
        padded = [r for r in rows if r[2] is not None]
        plain = [r for r in rows if r[2] is None]

        if not padded:
            grew = all(x[1] < y[1] for x, y in zip(plain, plain[1:]))
            print(f"  never padded; {plain[0][1]}B at {plain[0][0]} chars up to "
                  f"{plain[-1][1]}B at {plain[-1][0]}, growing with the name: "
                  f"{'OK' if grew else 'NOT MONOTONIC'}")
            rc |= 0 if grew else 1
            continue

        # 512 is only reachable while the unpadded message still leaves room
        # for the extension's own 4-byte header. Past that the target cannot be
        # hit at all, so demanding it would be demanding the impossible.
        exact, over, wrong = [], [], []
        for chars, size, pad in padded:
            unpadded = size - 5 - 4 - pad
            (exact if unpadded + 4 <= PAD_TARGET else over).append((chars, size, pad))
        wrong = [r for r in exact if r[1] != PAD_TARGET + 5]
        if wrong:
            rc = 1
            print(f"  PADDING WRONG at {len(wrong)} of {len(exact)} reachable "
                  f"lengths - it should hit exactly {PAD_TARGET + 5}B:")
            for chars, size, pad in wrong:
                print(f"      {chars:3d} chars -> {size}B record, padding {pad}B")
        elif exact:
            print(f"  {PAD_TARGET + 5}B on the wire at every SNI length that can "
                  f"reach it: {exact[0][0]} to {exact[-1][0]} chars "
                  f"({len(exact)} lengths), padding {exact[0][2]}B down to "
                  f"{exact[-1][2]}B - OK")
        if over:
            # Upstream OpenSSL's own rule, unchanged by this fork: when fewer
            # than 4 bytes are left it still emits a 1-byte padding extension
            # rather than none, overshooting 512 by up to 4. No capture in this
            # tree has an SNI that long, so there is nothing to say whether a
            # real client does the same - it is reported, not corrected.
            print(f"  {over[0][0]}-{over[-1][0]} chars: {PAD_TARGET}B is out of "
                  f"reach, sizes {sorted({r[1] for r in over})} - upstream's "
                  f"1-byte fallback, unmeasured against a real client")
        for chars, size, pad in plain:
            print(f"  {chars:3d} chars: {size}B, no padding extension")
    return rc


# --- the second ClientHello, after a HelloRetryRequest -----------------------

#: SHA-256("HelloRetryRequest"), RFC 8446 section 4.1.3. A ServerHello carrying
#: this as its random *is* a HelloRetryRequest - there is no separate message
#: type, which is why one can be assembled by hand as easily as below.
HRR_RANDOM = bytes.fromhex(
    "cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c")

#: Extensions RFC 8446 section 4.1.2 permits the second ClientHello to change,
#: so a difference in them is not a finding: key_share is replaced with the one
#: entry the server asked for, padding absorbs that size change, pre_shared_key
#: is recomputed over the new transcript, cookie is echoed back and early_data
#: is dropped.
HRR_MAY_CHANGE = {0x0033, 0x0015, 0x0029, 0x002c, 0x002a}

#: Extensions the second ClientHello may *add*, so their absence from the first
#: is not a reordering. Only cookie, in practice - the server has to have sent
#: one for it to be echoed.
HRR_MAY_APPEAR = {0x002c}

#: Extensions the second ClientHello may *drop*, so their absence is not a
#: reordering either. early_data because RFC 8446 says a retry ends 0-RTT, and
#: padding because a real iOS device does - see `_hrr_check`.
HRR_MAY_VANISH = {0x0015, 0x002a}


def _recv_exactly(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            break
        buf += chunk
    return buf


def _read_record(sock: socket.socket) -> bytes:
    """One TLS record, header included, or b"" at end of stream."""
    head = _recv_exactly(sock, 5)
    if len(head) < 5:
        return b""
    return head + _recv_exactly(sock, int.from_bytes(head[3:5], "big"))


def _key_share_groups(body: bytes) -> list[int]:
    """The group of each KeyShareEntry in a client's key_share extension."""
    out, o = [], 2
    while o + 4 <= len(body):
        out.append(int.from_bytes(body[o:o + 2], "big"))
        o += 4 + int.from_bytes(body[o + 2:o + 4], "big")
    return out


def _hrr_group(ch: bytes) -> int:
    """A group to demand: offered in supported_groups, not already shared.

    Both halves matter. A group the client never offered makes it abort with
    illegal_parameter, and one it already sent a share for makes the retry
    pointless - RFC 8446 forbids the server asking for it.
    """
    exts = dict(_walk_extensions(ch))
    have = set(_key_share_groups(exts.get(0x0033, b"")))
    groups = exts.get(0x000a, b"")
    for i in range(2, len(groups) - 1, 2):
        group = int.from_bytes(groups[i:i + 2], "big")
        if group not in GREASE and group not in have:
            return group
    msg = "the client sent a key_share for every group it offered"
    raise Malformed(msg)


def _hello_retry_request(ch: bytes, group: int) -> bytes:
    """A HelloRetryRequest demanding `group`, built from the ClientHello.

    Hand-assembled rather than produced by a real server, because a real one
    would need a certificate, a cipher configuration that happens to leave the
    right group unshared, and a way to be told to retry at all. What is under
    test here is the *client*, and everything it checks before accepting an HRR
    is in these thirty-odd bytes: the version, the echoed session id, a cipher
    suite it offered, and a group it offered but did not share.
    """
    body = ch[9:]                                   # past both headers
    o = 2 + 32
    sid = body[o + 1:o + 1 + body[o]]
    o += 1 + body[o]
    n = int.from_bytes(body[o:o + 2], "big")
    offered = [int.from_bytes(body[o + 2 + i:o + 4 + i], "big")
               for i in range(0, n, 2)]
    # A HelloRetryRequest only exists in TLS 1.3, so a ClientHello offering no
    # 1.3 suite cannot be answered with one. That is not a broken client: it is
    # what an Apple client sends on its *third* attempt after two handshakes
    # have failed - 157 bytes, legacy_version 0x0301, no key_share, no
    # supported_versions, TLS_FALLBACK_SCSV on the end. Our probe kills every
    # handshake by design, so it induces exactly that, and reporting it as
    # "the client would not retry" sent the reader looking in the wrong place.
    suite = next((c for c in offered if c in (0x1301, 0x1302, 0x1303)), None)
    if suite is None:
        msg = ("this ClientHello offers no TLS 1.3 cipher suite, so no "
               "HelloRetryRequest applies to it - the client has already "
               "fallen back")
        raise Malformed(msg)

    exts = (b"\x00\x2b\x00\x02\x03\x04"             # supported_versions: 1.3
            + b"\x00\x33\x00\x02" + group.to_bytes(2, "big"))   # key_share
    hs = (b"\x03\x03" + HRR_RANDOM
          + bytes([len(sid)]) + sid
          + suite.to_bytes(2, "big") + b"\x00"
          + len(exts).to_bytes(2, "big") + exts)
    hs = b"\x02" + len(hs).to_bytes(3, "big") + hs
    return b"\x16\x03\x03" + len(hs).to_bytes(2, "big") + hs


def hrr_exchange(conn: socket.socket, timeout: float = 15.0
                 ) -> tuple[bytes, bytes, int, str]:
    """Answer one connection with a HelloRetryRequest; return both ClientHellos.

    The whole server side of the measurement, and deliberately the *whole* of
    it: there is no certificate, no key exchange and no ServerHello, because
    nothing past the second ClientHello is being measured. The peer's handshake
    then fails, which for a browser means an error page - the price of the
    only measurement that shows what its second ClientHello looks like.

    Returns (first, second, group, note); `note` is empty unless the second
    never arrived, in which case it says what came instead.
    """
    conn.settimeout(timeout)
    first = second = b""
    group = 0
    try:
        first = _read_record(conn)
        if len(first) < 6 or first[0] != 0x16 or first[5] != 0x01:
            return first, b"", 0, "the first record was not a ClientHello"
        group = _hrr_group(first)
        conn.sendall(_hello_retry_request(first, group))
        # Middlebox compatibility: a real server sends this after an HRR, and a
        # client that has already sent its own expects to see one.
        conn.sendall(b"\x14\x03\x03\x00\x01\x01")
        while True:
            rec = _read_record(conn)
            if not rec:
                return first, b"", group, ("the connection closed without a "
                                           "second ClientHello")
            if rec[0] == 0x15:                      # alert
                why = (f"alert {rec[5]}/{rec[6]}" if len(rec) >= 7
                       else "a truncated alert")
                return first, b"", group, f"the client rejected the retry: {why}"
            if rec[0] == 0x14:                      # its own CCS, expected
                continue
            if rec[0] == 0x16 and len(rec) > 5 and rec[5] == 0x01:
                return first, rec, group, ""
            return first, b"", group, f"unexpected record type 0x{rec[0]:02x}"
    except Malformed as exc:
        return first, b"", group, str(exc)
    except OSError as exc:
        return first, second, group, f"{type(exc).__name__}: {exc}"
    finally:
        conn.close()


def hello_retry_pair(brand: str, sni: str = "example.com",
                     alpn: typing.Sequence[str] = ("h2", "http/1.1")
                     ) -> tuple[bytes, bytes, int, str]:
    """Both ClientHellos of one handshake, and the group the retry demanded.

    Like `one_client_hello`, no certificate and no completed handshake: we
    answer the first ClientHello with a HelloRetryRequest, read the second, and
    close. The client then fails, which is the expected outcome.

    Returns (first, second, group, note). `note` is empty unless the second
    never arrived, in which case it says what came instead.
    """
    from . import browser_fp

    got: dict[str, typing.Any] = {"note": ""}
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]

    def serve_one() -> None:
        conn, _ = srv.accept()
        got.update(zip(("first", "second", "group", "note"),
                       hrr_exchange(conn)))

    thread = threading.Thread(target=serve_one, daemon=True)
    thread.start()
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_alpn_protocols(list(alpn))
    browser_fp.tls_profile.set_profile(ctx, browser_fp.profile(brand).tls_profile)
    sock = socket.create_connection(("127.0.0.1", port), timeout=10)
    try:
        ctx.wrap_socket(sock, server_hostname=sni)
    except OSError:
        pass                           # we never send a ServerHello; expected
    finally:
        sock.close()
        thread.join(timeout=10)
        srv.close()
    return (got.get("first", b""), got.get("second", b""),
            got.get("group", 0), got["note"])


def _grease_positions(ch: bytes) -> dict[str, list[str]]:
    """Every GREASE codepoint in a ClientHello, by where it sits.

    Keyed by position rather than collected into a set, because the rule being
    checked is that each *slot* holds the same value in both ClientHellos - and
    BoringSSL draws them all from one seed, so two slots legitimately hold the
    same value (supported_groups and key_share always do).
    """
    out: dict[str, list[str]] = {}

    def add(where: str, value: int) -> None:
        out.setdefault(where, []).append(f"0x{value:04x}")

    o = 43
    o += 1 + ch[o]
    n = int.from_bytes(ch[o:o + 2], "big")
    for i in range(o + 2, o + 2 + n, 2):
        value = int.from_bytes(ch[i:i + 2], "big")
        if value in GREASE:
            add("cipher_suites", value)

    for etype, body in _walk_extensions(ch):
        if etype in GREASE:
            add("extension id", etype)
        elif etype == 0x000a:                        # supported_groups
            for i in range(2, len(body) - 1, 2):
                value = int.from_bytes(body[i:i + 2], "big")
                if value in GREASE:
                    add("supported_groups", value)
        elif etype == 0x002b:                        # supported_versions
            for i in range(1, len(body) - 1, 2):
                value = int.from_bytes(body[i:i + 2], "big")
                if value in GREASE:
                    add("supported_versions", value)
        elif etype == 0x0033:                        # key_share
            for value in _key_share_groups(body):
                if value in GREASE:
                    add("key_share", value)
    return out


def _ch_invariants(ch: bytes) -> dict[str, bytes]:
    """The ClientHello fields the retry must repeat byte for byte.

    RFC 8446 section 4.1.2 lets the second ClientHello differ from the first
    only in key_share, pre_shared_key, early_data, cookie and padding - every
    one an extension. Everything ahead of the extensions is fixed: the
    legacy_version, the session_id, the cipher_suites list (GREASE entries
    included, since those are drawn once per connection and so must recur) and
    the compression methods. `_grease_positions` only checks the GREASE
    codepoints inside that region, not the region itself, so without this a
    client that reordered or trimmed its ordinary cipher suites on the retry -
    a real, fingerprintable divergence - would slip through unnoticed.

    Offsets follow `_walk_extensions`: `ch` carries the 5-byte record header.
    """
    version = ch[9:11]
    o = 43
    session_id = ch[o:o + 1 + ch[o]]
    o += 1 + ch[o]
    cs_len = int.from_bytes(ch[o:o + 2], "big")
    ciphers = ch[o:o + 2 + cs_len]
    o += 2 + cs_len
    compression = ch[o:o + 1 + ch[o]]
    return {"legacy_version": version, "session_id": session_id,
            "cipher_suites": ciphers, "compression": compression}


def _hrr_check(first: bytes, second: bytes, group: int) -> bool:
    """Everything the second ClientHello has to keep from the first."""
    ok = True
    ga, gb = _grease_positions(first), _grease_positions(second)
    # key_share's GREASE entry is *meant* to disappear - RFC 8446 requires the
    # retry to carry exactly one entry - so it is checked below instead.
    ga.pop("key_share", None)
    gb.pop("key_share", None)
    if ga == gb:
        print("  GREASE values     repeated  " + ", ".join(
            f"{k} {'/'.join(v)}" for k, v in sorted(ga.items())))
    else:
        ok = False
        print("  GREASE values     REDRAWN - a real BoringSSL client derives "
              "them from one\n                    per-handshake seed, so both "
              "ClientHellos carry the same ones")
        for name, values in (("first ", ga), ("second", gb)):
            print(f"      {name}: " + ", ".join(
                f"{k}={'/'.join(v)}" for k, v in sorted(values.items())))

    # The extensions are the only thing RFC 8446 4.1.2 lets the retry change;
    # the fields ahead of them must return byte for byte. The GREASE scan above
    # only looked at the GREASE codepoints, not the cipher list or the header
    # fields around it, so compare those here - a second ClientHello that
    # reorders or trims its cipher suites, or alters its session_id,
    # legacy_version or compression, is a divergence that would otherwise read
    # as "no divergence".
    ia, ib = _ch_invariants(first), _ch_invariants(second)
    fixed = (("legacy_version", "legacy_version"),
             ("session_id", "session_id"),
             ("cipher_suites", "cipher suites"),
             ("compression", "compression"))
    if all(ia[k] == ib[k] for k, _ in fixed):
        print("  fixed fields      identical: legacy_version, session_id, "
              "cipher suites, compression")
    else:
        for key, human in fixed:
            if ia[key] != ib[key]:
                ok = False
                print(f"  {human:<16} DIFFERS between the two ClientHellos - RFC "
                      f"8446 4.1.2\n                    requires it unchanged in "
                      f"the retry")
                print(f"      first : {_short(ia[key].hex())}")
                print(f"      second: {_short(ib[key].hex())}")

    ea = [t for t, _ in _walk_extensions(first)]
    eb = [t for t, _ in _walk_extensions(second)]
    # An extension appearing or disappearing is not a reordering, and reporting
    # it as one buried the actual finding the first time a real device was
    # measured: iOS drops padding from the retry, and every one of its sixteen
    # pairs came out as "extension order DIFFER" with two near-identical lines
    # underneath that the eye had to diff by hand.
    added = [t for t in eb if t not in ea and t in HRR_MAY_APPEAR]
    dropped = [t for t in ea if t not in eb and t in HRR_MAY_VANISH]
    trimmed = [t for t in eb if t not in added]
    kept = [t for t in ea if t not in dropped]
    if trimmed == kept:
        bits = []
        if added:
            bits.append("plus " + ", ".join(f"0x{t:04x}" for t in added))
        if dropped:
            bits.append("less " + ", ".join(f"0x{t:04x}" for t in dropped))
        print(f"  extension order   identical, {len(ea)} extensions"
              + (f" ({'; '.join(bits)})" if bits else ""))
    else:
        ok = False
        print("  extension order   DIFFER - the permutation is drawn once per "
              "handshake, so\n                    the retry must reuse it")
        print(f"      first : {' '.join(f'0x{t:04x}' for t in ea)}")
        print(f"      second: {' '.join(f'0x{t:04x}' for t in eb)}")

    # Measured on a real iOS 18 device, sixteen retries out of sixteen: the
    # padding extension is not in the second ClientHello at all - 517 bytes
    # padded to 512 in the first, 324 unpadded in the second, though 315 bytes
    # of handshake is well inside the range that otherwise pads. Upstream
    # OpenSSL pads both, which is what this caught.
    if 0x0015 in ea:
        if 0x0015 in eb:
            ok = False
            print("  padding           STILL THERE in the retry - a real iOS "
                  "device drops it\n                    outright, so a padded "
                  "second ClientHello is 193 bytes and one\n                  "
                  "  extension away from the client being imitated")
        else:
            print("  padding           dropped from the retry, as iOS does")

    ks = dict(_walk_extensions(second)).get(0x0033)
    if ks is None:
        ok = False
        print("  key_share         MISSING from the retry")
    else:
        groups = _key_share_groups(ks)
        if groups == [group]:
            print(f"  key_share         one entry, 0x{group:04x} as demanded")
        else:
            ok = False
            print(f"  key_share         WRONG - RFC 8446 4.1.2 requires exactly "
                  f"one entry for\n                    0x{group:04x}, got "
                  + ", ".join(f"0x{g:04x}" for g in groups))

    # Everything else, body by body. Two dicts and not a zip: the order check
    # above already reported any reordering, and pairing by id keeps this from
    # reporting the same thing a second time as a wall of mismatched bodies.
    ba, bb = dict(_walk_extensions(first)), dict(_walk_extensions(second))
    moved = sorted(t for t in set(ba) & set(bb)
                   if t not in HRR_MAY_CHANGE and ba[t] != bb[t])
    if not moved:
        print("  extension bodies  identical outside key_share and padding")

    # What the client was *allowed* to change, and did. Not a verdict - it is
    # the interesting half when the client is somebody else's, because it says
    # what a real stack actually does with the freedom the RFC gives it.
    allowed = sorted(t for t in set(ba) & set(bb)
                     if t in HRR_MAY_CHANGE and ba[t] != bb[t])
    for etype in allowed:
        print(f"  0x{etype:04x}            changed, as the RFC permits: "
              f"{len(ba[etype])}B -> {len(bb[etype])}B")
    gone = sorted(set(ba) - set(bb) - GREASE - {0x0015})
    for etype in gone:
        print(f"  0x{etype:04x}            dropped from the second ClientHello")
    for etype in moved:
        ok = False
        print(f"  0x{etype:04x}            DIFFERS between the two ClientHellos")
        if etype == 0xfe0d:
            # Field by field rather than as one blob: the three parts do not
            # carry the same weight. config_id names the ECHConfig in use, and
            # a retry does not change which config the client holds, so a real
            # ECH repeats it - redrawing it is the part that is wrong on its
            # own terms. What `enc` and `payload` are supposed to do across a
            # retry is the ECH draft's business and is not asserted here.
            fa, fb = _ech_fields(ba[etype]), _ech_fields(bb[etype])
            for name in ("type", "kdf", "aead", "config_id", "enc", "payload"):
                verdict = "same" if fa[name] == fb[name] else "REDRAWN"
                print(f"      {name:<10} {verdict:<8} "
                      f"{_short(fa[name], 32)} -> {_short(fb[name], 32)}")
            print("      config_id names the ECHConfig, which a retry does not "
                  "change - a real\n      ECH repeats it, so a GREASE one that "
                  "does not is distinguishable")
        else:
            print(f"      first : {_short(ba[etype].hex())}")
            print(f"      second: {_short(bb[etype].hex())}")
    return ok


def _ech_fields(body: bytes) -> dict[str, str]:
    """The outer ECHClientHello, split up: type, suite, config_id, enc, payload."""
    enc_len = int.from_bytes(body[6:8], "big")
    enc = body[8:8 + enc_len]
    rest = body[8 + enc_len:]
    return {
        "type": body[0:1].hex(),
        "kdf": body[1:3].hex(),
        "aead": body[3:5].hex(),
        "config_id": body[5:6].hex(),
        "enc": enc.hex(),
        "payload": rest[2:].hex(),
    }


def hrr_serve(args: argparse.Namespace) -> int:
    """Answer whatever connects with a retry, and measure *its* second hello.

    The same measurement as `hrr`, pointed at somebody else's client. What it
    is for is the half of the question no amount of local testing settles: our
    profiles say what a real iOS stack sends in a *first* ClientHello, because
    that was captured - but no capture in this tree contains a second one, so
    the rules `hrr` checks are read off the RFC and off BoringSSL's source
    rather than off a measurement. Pointing a real device at this answers it.

    Needs no certificate, which is the one part that is easier than `serve`:
    the handshake dies before anything is authenticated, so there is nothing
    for the phone to be asked to trust. The browser shows an error page, and
    both ClientHellos are already recorded by then.
    """
    out = Path(args.out)
    srv = listen(args.port)
    host = args.host or local_ipv4() or "localhost"
    print(f"listening on :{args.port} - point a client at https://{host}:{args.port}/\n"
          f"every connection is answered with a HelloRetryRequest and both of its\n"
          f"ClientHellos are written to {out}/. The client will report an error; "
          f"that is\nexpected and does not affect what was measured. Ctrl-C to stop.\n")
    seen = 0
    started = time.monotonic()
    # Stamped with the run, not just a counter. The counter restarts at 1 in
    # every process, so a second listener silently overwrote eight pairs from
    # the first one - and the pairs a phone produces are expensive enough that
    # losing them to a filename collision is not acceptable.
    run = datetime.datetime.now().strftime("%m%d-%H%M%S")
    try:
        while True:
            conn, peer = srv.accept()
            first, second, group, note = hrr_exchange(conn)
            if not first:
                print(f"{peer[0]}: nothing usable - {note or 'no ClientHello'}")
                continue
            seen += 1
            sni = sni_of(first) or "(no SNI)"
            print(f"=== {peer[0]}:{peer[1]} #{seen}: {sni} "
                  f"(+{time.monotonic() - started:.2f}s) ===")
            if not second:
                print(f"  no second ClientHello - {note}")
                print("  stored anyway: the first one is a measurement too")
            else:
                print(f"  retry demanded    0x{group:04x}; {len(first)}B then "
                      f"{len(second)}B on the wire")
                _hrr_check(first, second, group)
            out.mkdir(parents=True, exist_ok=True)
            path = out / f"hrr-{run}-{_safe(sni)}-{seen:03d}.json"
            path.write_text(json.dumps({
                # Timestamped because the first real run could not answer a
                # plain question about itself: one page load produced nine
                # connections in three rounds of a fallback ladder, and nothing
                # stored said whether those were three sockets in parallel or
                # one retried nine times. This server accepts one at a time, so
                # the order alone cannot tell them apart.
                "at": datetime.datetime.now().isoformat(timespec="milliseconds"),
                "elapsed": round(time.monotonic() - started, 3),
                "peer": peer[0], "peer_port": peer[1],
                "sni": sni_of(first), "group": group,
                "note": note, "first": first.hex(), "second": second.hex(),
            }, indent=2))
            print(f"  stored {path}\n")
    except KeyboardInterrupt:
        print(f"\nstopped after {seen} connection(s)")
    finally:
        srv.close()
    return 0


def hrr_pair(args: argparse.Namespace) -> int:
    """Re-check a pair stored by `hrr --serve`, without the device."""
    rec = json.loads(Path(args.pair).read_text())
    first = bytes.fromhex(rec["first"])
    second = bytes.fromhex(rec["second"])
    print(f"=== {args.pair}: {rec.get('sni') or '(no SNI)'} from "
          f"{rec.get('peer', '?')} ===")
    if not second:
        print(f"  no second ClientHello was recorded - {rec.get('note', '')}")
        return 1
    print(f"  retry demanded    0x{rec['group']:04x}; {len(first)}B then "
          f"{len(second)}B on the wire")
    return 0 if _hrr_check(first, second, rec["group"]) else 1


def hrr(args: argparse.Namespace) -> int:
    """Check the second ClientHello against the first, after a retry.

    The other thing `selftest` cannot see. It drives one fresh handshake
    against a server that never retries, so every rule about what the *second*
    ClientHello must keep from the first goes unexercised - and those rules are
    where a client that is otherwise byte-perfect gives itself away, because
    they are the ones a fingerprinting server can trigger at will simply by
    asking for a group the client did not share.

    Needs no network and no certificate: the retry is assembled by hand.
    """
    from . import browser_fp

    if args.pair:
        return hrr_pair(args)
    if args.serve:
        return hrr_serve(args)

    brands = [args.brand] if args.brand else list(browser_fp.brands())
    results: dict[str, int] = {}
    for i, brand in enumerate(brands):
        if i:
            print()
        print(f"=== {brand} ===")
        try:
            first, second, group, note = hello_retry_pair(brand, args.sni)
        except Exception as exc:                              # noqa: BLE001
            print(f"  FAILED ({type(exc).__name__}: {exc})")
            results[brand] = 1
            continue
        if not first:
            print(f"  no ClientHello at all - {note or 'nothing arrived'}")
            results[brand] = 1
            continue
        if not second:
            print(f"  no second ClientHello - {note}")
            results[brand] = 1
            continue
        print(f"  retry demanded    0x{group:04x}; {len(first)}B then "
              f"{len(second)}B on the wire")
        results[brand] = 0 if _hrr_check(first, second, group) else 1

    if len(brands) > 1:
        print("\n=== summary ===")
        for brand, rc in results.items():
            print(f"  {brand:<16} {'PASS' if rc == 0 else 'FAIL'}")
    return 0 if all(rc == 0 for rc in results.values()) else 1


def list_profiles(_args: argparse.Namespace) -> int:
    from . import browser_fp
    print(browser_fp.catalog())
    return 0


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser(
        "serve",
        help="run an h2 server and record whatever connects to it",
        description="Stand up an HTTP/2 server over TLS and write down the raw "
                    "bytes of every connection that reaches it, until you stop "
                    "it with Ctrl-C. Nothing is installed: the dumps go to "
                    "--captures in mitm_addon.py's layout, for `import-mitm` to "
                    "turn into a profile afterwards - the same two steps as "
                    "capture-mitm, against our own server instead of a real "
                    "site. --brand collapses them into one and ends the run as "
                    "soon as a single profile is complete.")
    s.add_argument("--captures", default="captures", metavar="DIR",
                   help="where the raw dumps go when no --brand is given; "
                        "default: ./captures")
    s.add_argument("--brand", help="capture one profile and stop, storing it "
                                   "as this brand instead of dumping (one file "
                                   "per browser, no version in the name)")
    s.add_argument("--out", help="the same single capture, stored at this path, "
                                 "without registering it as a brand; with "
                                 "--brand the file still records that name")
    s.add_argument("--xhr-timeout", type=float, default=25.0,
                   help="with --brand/--out only: how long to wait for the "
                        "page's own /xhr-sample after the navigation arrives "
                        "before ending the run (default 25s)")
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

    cm = sub.add_parser(
        "capture-mitm",
        help="run mitmproxy with the addon loaded, then import the result",
        description="Start mitmdump with mytls/mitm_addon.py loaded, wait "
                    "while you browse, and import what it recorded. mitmproxy "
                    "runs as a separate process on its own Python (>= 3.12); "
                    "it is not imported here.")
    cm.add_argument("--out", default="captures",
                    help="where the raw dumps go; default: ./captures")
    cm.add_argument("--host", action="append", metavar="REGEX",
                    help="only dump connections whose SNI matches this regex - "
                         "worth setting, or every TLS connection the device "
                         "makes is dumped. Repeatable; several are combined "
                         "with |")
    cm.add_argument("--ignore-hosts", action="append", metavar="REGEX",
                    help="do not intercept these at all - mitmproxy passes the "
                         "connection through and never sees inside it. "
                         "Different from --host, which decrypts everything and "
                         "then dumps a subset. Repeatable. Worth pointing at "
                         "whatever the device chatters to in the background: "
                         "certificate-pinned endpoints fail the handshake when "
                         "intercepted and the OS then retries and backs off, "
                         "which is noise at best and can crowd out the flow "
                         "being captured. On iOS: "
                         r"--ignore-hosts '.*\.apple\.com' "
                         r"--ignore-hosts '.*icloud\.com' "
                         r"--ignore-hosts '.*mzstatic\.com'")
    cm.add_argument("--brand", help="import into this profile once mitmproxy "
                                    "stops; without it the dumps are only left "
                                    "on disk")
    cm.add_argument("--mode", default="regular",
                    help="mitmproxy mode: regular (default), wireguard, "
                         "transparent, local, socks5. wireguard suits phones "
                         "and, unlike an explicit proxy, does not stop the "
                         "browser resolving DNS itself - which is what GREASE "
                         "ECH depends on")
    cm.add_argument("--port", type=int, help="listen port; mitmproxy's default "
                                             "is 8080 for regular mode")
    cm.add_argument("--mitmdump", help="path to mitmdump, if not on PATH")
    cm.add_argument("--allow-resumed", action="store_true",
                    help="passed through to the import step")
    cm.add_argument("extra", nargs=argparse.REMAINDER,
                    help="further mitmdump options, after a '--' separator: "
                         "capture-mitm --host x -- --showhost --anticache")
    cm.set_defaults(func=capture_mitm)

    m = sub.add_parser(
        "import-mitm",
        help="build a profile from what mitm_addon.py recorded off a real site",
        description="Read the raw dumps mitm_addon.py wrote and turn them into "
                    "a profile. Point it at the directory, not one file: a "
                    "browser spreads a page load over several connections, and "
                    "the navigation and the xhr are usually on different ones.")
    m.add_argument("source", help="the --set fp_out directory, or one dump")
    m.add_argument("--brand", help="which profile to write; default: read off "
                                   "the captured user-agent")
    m.add_argument("--out", help="write here instead of into the profiles "
                                 "directory, and skip the reference; --brand "
                                 "given as well is recorded in the file")
    m.add_argument("--allow-resumed", action="store_true",
                   help="accept a ClientHello carrying pre_shared_key; it will "
                        "not match our client, which never resumes")
    m.set_defaults(func=import_mitm)

    mt = sub.add_parser(
        "match",
        help="which profile, if any, each raw capture came from",
        description="Compare captures - mitmproxy dumps, `serve` profiles, "
                    "`--out` files - against the installed profiles, and say "
                    "which stack produced them. Differences are split into "
                    "ones that mean a different stack and ones an app chooses "
                    "for itself; the second kind never turns a match into a "
                    "miss. Offline.")
    mt.add_argument("source", nargs="+",
                    help="directories of captures, or files, or both")
    mt.add_argument("--brand", help="test against this profile only, and say "
                                    "why it does not match when it does not")
    mt.add_argument("--verbose", "-v", action="store_true",
                    help="show the reason for every profile that does not match")
    mt.set_defaults(func=match)

    sc = sub.add_parser(
        "sniscan",
        help="emit a ClientHello at many SNI lengths and check the shape holds",
        description="The one thing selftest cannot see. It compares against a "
                    "capture taken at one address, so it exercises one SNI "
                    "length - but a padded profile computes its padding from "
                    "the total length, which a longer hostname changes. Needs "
                    "no server and no network.")
    sc.add_argument("--brand", help="just one; default: every installed profile")
    sc.add_argument("--max-length", type=int, default=253,
                    help="longest hostname to try (default 253, the DNS maximum)")
    sc.add_argument("--step", type=int, default=7,
                    help="hostname length increment (default 7)")
    sc.set_defaults(func=sniscan)

    hr = sub.add_parser(
        "hrr",
        help="answer our own ClientHello with a HelloRetryRequest and check "
             "what the second one keeps",
        description="The other thing selftest cannot see. It runs one fresh "
                    "handshake against a server that never retries, so nothing "
                    "exercises the rules about what the *second* ClientHello "
                    "must carry over from the first - the GREASE values, the "
                    "extension order, the GREASE ECH payload. A fingerprinting "
                    "server can trigger a retry at will by asking for a group "
                    "the client did not share. Needs no server, no certificate "
                    "and no network: the retry is assembled by hand.")
    hr.add_argument("--brand", help="just one; default: every installed profile")
    hr.add_argument("--sni", default="example.com",
                    help="hostname to send (default example.com)")
    hr.add_argument("--serve", action="store_true",
                    help="instead of testing ourselves, listen and measure "
                         "whatever connects - a real phone, whose second "
                         "ClientHello no capture in this tree contains. Needs "
                         "no certificate: the handshake dies before anything "
                         "is authenticated")
    hr.add_argument("--host", help="with --serve: the address to print in the "
                                   "URL; default is this machine's LAN address")
    hr.add_argument("--port", type=int, default=8443,
                    help="with --serve: what to listen on (default 8443)")
    hr.add_argument("--out", default="captures/hrr", metavar="DIR",
                    help="with --serve: where the pairs are written "
                         "(default ./captures/hrr)")
    hr.add_argument("--pair", metavar="FILE",
                    help="re-check a pair stored by --serve, with no device")
    hr.set_defaults(func=hrr)

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
