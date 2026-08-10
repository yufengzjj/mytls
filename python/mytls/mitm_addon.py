r"""A mitmproxy addon that records a browser's raw TLS and HTTP/2 bytes.

`hpack_probe serve` can only capture a browser that visits *us*: it is the
server, so the page, the certificate warning and the request are all ours. That
is enough to measure a ClientHello and one navigation, and it is what every
profile in this package was built from. What it cannot do is watch a browser
talk to a *real* site - and a real site is where `referer`, `cookie`, the
subresource `priority` values and the whole range of `sec-fetch-site` actually
occur.

mitmproxy can, because it holds the browser's session keys. But mitmproxy in its
normal mode is an HTTP/2 endpoint: it decodes HPACK, keeps the decoded headers,
and re-encodes towards the server. The header *names and values* survive that;
the header *block* does not, and the block is what this package compares byte
for byte. So the trick here is to not let mitmproxy speak HTTP at all.

The `next_layer` hook below replaces the HTTP layer with a raw `TCPLayer`, one
level *below* where HTTP would be parsed but *above* TLS. mitmproxy still
terminates TLS, still generates a certificate, still relays to the real server -
pages load normally - but what reaches this addon is the decrypted TCP stream
with the HTTP/2 frames still in it, HPACK and all.

Deliberately dumb
-----------------
This file parses nothing. It writes the raw ClientHello and the raw byte stream
and stops there, because `hpack_probe` already has the parsers that produced
every existing profile - `parse_client_hello()` and `describe()`. Parsing here
too would mean two implementations that have to agree, and the whole point of
the byte-level comparison is that there is only one.

It also imports nothing from `mytls`, and that stays true even though the two
can now share an interpreter: `install-python.sh` builds 3.12 precisely so that
mitmproxy - which requires 3.12 - can be installed alongside, but a standalone
mitmproxy build brings its own bundled Python, and a `pipx`-installed one gets
its own venv. This file has to work in all three, so it depends on nothing but
mitmproxy itself.

Usage
-----
    mitmdump -s "$(python -c 'import mytls; print(mytls.addon_path())')" \
             --set fp_out=./captures --set fp_hosts='example\.com'

then browse, and feed the directory to:

    mytls-probe import-mitm ./captures --brand ios18

`fp_hosts` is worth setting. Without it every TLS connection the browser makes
is relayed raw and dumped, which works but buries the one you wanted.

The ClientHello is caught twice
------------------------------
Once as mitmproxy parsed it, and once as raw bytes off the wire before TLS was
set up - a ClientHello is plaintext, so both views exist. The raw one is
preferred, because it is the only one carrying the true record-layer version
(browsers send 0x0301 there; mitmproxy's own `raw_bytes()` always stamps
0x0303). Each dump says which it got in `client_hello_exact`.

Two things this cannot control
------------------------------
*Session resumption.* The probe refuses to issue session tickets, so its
captures are always fresh handshakes. Nothing in mitmproxy's stack can do the
same: pyOpenSSL has no `set_num_tickets`, and cryptography links OpenSSL
statically without exporting `SSL_CTX_set_num_tickets`, so it cannot be reached
by ctypes either. `OP_NO_TICKET` is exposed but only makes the server refuse -
measured, the browser still offers the PSK, and the offer is what pollutes the
capture. Restarting this proxy therefore changes nothing; only clearing the
browser's TLS state does. `import-mitm` detects resumed dumps and refuses them;
the first connection of a browsing session is normally fresh, and every
connection is dumped, so there is usually a usable one.

*What a proxy does to the browser.* A browser that knows it is behind an
explicit proxy does not resolve DNS itself, and Chrome's GREASE ECH depends on
a DNS HTTPS record lookup - so the ClientHello may legitimately lack an
extension it would send otherwise. Transparent or WireGuard mode avoids this.
Compare against the existing profile before believing a difference.
"""

from __future__ import annotations

import datetime
import json
import logging
import re
import time
from pathlib import Path

from mitmproxy import ctx
from mitmproxy import tcp
from mitmproxy import tls
from mitmproxy.proxy import layer
from mitmproxy.proxy.layers import ClientTLSLayer
from mitmproxy.proxy.layers import TCPLayer

logger = logging.getLogger(__name__)

#: Bumped when the dump layout changes, so `import-mitm` can refuse a stale one
#: rather than misread it.
FORMAT = 2

#: More than enough for any ClientHello, and a bound on what is held per
#: connection while waiting for the handshake to be parsed.
MAX_PREFIX = 32 * 1024

#: A dump is rewritten at most this often while its connection is still open,
#: so that a capture is usable without waiting for the browser to close - and
#: without writing the file once per TCP segment.
FLUSH_INTERVAL = 1.0


def _now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).replace(
        microsecond=0).isoformat()


def _safe(name: str) -> str:
    """A hostname reduced to something that can be a filename."""
    return re.sub(r"[^a-zA-Z0-9._-]", "_", name) or "unknown"


class FingerprintCapture:
    """One dump per TLS connection: the ClientHello and both byte streams."""

    def __init__(self) -> None:
        #: client connection id -> what its ClientHello said. Filled by
        #: tls_clienthello, read when the TCP flow for the same connection
        #: starts; mitmproxy reuses one Connection object for both, so the id
        #: is the join key.
        self._hello: dict[str, dict] = {}
        self._flows: dict[str, dict] = {}
        #: client connection id -> the raw bytes the client sent before TLS was
        #: set up, which is the ClientHello exactly as it went over the wire.
        self._prefix: dict[str, bytes] = {}
        self._host_re: re.Pattern | None = None

    # -- options -----------------------------------------------------------

    def load(self, loader) -> None:
        loader.add_option(
            "fp_out", str, "captures",
            "Directory to write raw fingerprint dumps into.")
        loader.add_option(
            "fp_hosts", str, "",
            "Only capture connections whose SNI matches this regex. Empty "
            "captures every TLS connection.")

    def configure(self, updated) -> None:
        if "fp_hosts" in updated:
            pattern = ctx.options.fp_hosts
            self._host_re = re.compile(pattern, re.IGNORECASE) if pattern else None

    # -- the two hooks that matter ------------------------------------------

    def tls_clienthello(self, data: tls.ClientHelloData) -> None:
        """Keep the browser's ClientHello before mitmproxy answers it.

        `raw_bytes()` would wrap the handshake in a *synthetic* record stamped
        0x0303, losing the real record version (browsers send 0x0301 there).
        But a ClientHello is plaintext - it is the first thing on the
        connection, before any key exchange - so the true bytes were already
        on the wire, and `next_layer` below caught them on the way past.

        Prefer those. Fall back to splicing the true record header onto the
        parsed body, and only if even that is unavailable accept the synthetic
        record and say the version was not measured.
        """
        client_id = data.context.client.id
        body = data.client_hello.raw_bytes(wrap_in_record=False)
        prefix = self._prefix.pop(client_id, b"")
        raw, exact = self._wire_record(prefix, body)
        self._hello[client_id] = {
            "sni": data.client_hello.sni,
            "raw": raw.hex(),
            "exact": exact,
        }

    @staticmethod
    def _wire_record(prefix: bytes, body: bytes) -> tuple[bytes, bool]:
        """The ClientHello record as sent, and whether that is what this is.

        `body` is the ClientHello structure alone. A record is five bytes of
        record header then four of handshake header in front of it, and only
        the two version bytes of the record header are not derivable - which
        is exactly what `prefix`, the untouched wire bytes, supplies.
        """
        want = 5 + 4 + len(body)
        # The whole record arrived before TLS was set up: use it verbatim.
        if len(prefix) >= want and prefix[5] == 0x01 and prefix[9:want] == body:
            return prefix[:want], True
        # Only the head of it did - still enough, since everything after the
        # record header is either fixed or the body we already hold. A record
        # length that disagrees means the handshake was split across records,
        # and then no single record is the wire format.
        if (len(prefix) >= 5 and prefix[0] == 0x16
                and int.from_bytes(prefix[3:5], "big") == len(body) + 4):
            return (prefix[:5] + b"\x01" + len(body).to_bytes(3, "big") + body,
                    True)
        return (b"\x16\x03\x03" + (len(body) + 4).to_bytes(2, "big")
                + b"\x01" + len(body).to_bytes(3, "big") + body), False

    def next_layer(self, nextlayer: layer.NextLayer) -> None:
        """Hand us the decrypted stream instead of letting mitmproxy parse it.

        Only once TLS is already up: the hook fires several times per
        connection, and forcing a raw relay before the handshake would just
        copy ciphertext. The presence of a ClientTLSLayer in the stack is what
        says the next decision is about the application protocol.

        This addon is loaded by ScriptLoader, which sits ahead of the built-in
        NextLayer addon in `default_addons()`, and that one returns early if a
        layer has already been chosen - so setting it here wins without having
        to fight anyone.
        """
        if nextlayer.layer is not None:
            return
        context = nextlayer.context
        if not any(isinstance(x, ClientTLSLayer) for x in context.layers):
            # Before TLS. Whatever the client has sent so far is plaintext, and
            # if it starts a TLS record it is the ClientHello as it really went
            # over the wire - the only place the true record header exists.
            # Keep the longest view of it; this hook is asked again as more
            # data arrives, until a layer gets chosen.
            data = nextlayer.data_client()
            if data[:1] == b"\x16" and len(data) > len(
                    self._prefix.get(context.client.id, b"")):
                self._prefix[context.client.id] = data[:MAX_PREFIX]
            return
        if not self._wanted(context.client.id):
            return  # let mitmproxy handle it as HTTP, so browsing still works
        nextlayer.layer = TCPLayer(context)

    def _wanted(self, client_id: str) -> bool:
        if self._host_re is None:
            return True
        sni = (self._hello.get(client_id) or {}).get("sni") or ""
        return bool(self._host_re.search(sni))

    # -- collecting ----------------------------------------------------------

    def tcp_message(self, flow: tcp.TCPFlow) -> None:
        record = self._flows.get(flow.client_conn.id) or self._begin(flow)
        if record is None:
            return
        message = flow.messages[-1]
        record["client" if message.from_client else "server"].append(
            message.content)
        now = time.monotonic()
        if now - record["_flushed"] >= FLUSH_INTERVAL:
            record["_flushed"] = now
            self._write(record)

    def _begin(self, flow: tcp.TCPFlow) -> dict | None:
        hello = self._hello.get(flow.client_conn.id)
        if hello is None:
            # A raw TCP flow we have no ClientHello for - not something this
            # addon put into raw mode, so not ours to record.
            return None
        alpn = flow.client_conn.alpn
        alpn = alpn.decode("ascii", "replace") if alpn else None
        host = hello["sni"] or "unknown"
        record = {
            "format": FORMAT,
            "captured_at": _now(),
            "sni": hello["sni"],
            "alpn": alpn,
            "peer": f"{flow.client_conn.peername[0]}",
            "client_hello": hello["raw"],
            #: False if the record header had to be synthesised, in which case
            #: its version is an artefact and import-mitm will not record one.
            "client_hello_exact": hello["exact"],
            "client": [],
            "server": [],
            "_file": f"{_safe(host)}-{flow.client_conn.id[:8]}.json",
            "_flushed": 0.0,
        }
        self._flows[flow.client_conn.id] = record
        if alpn != "h2":
            logger.warning(
                f"{host}: ALPN is {alpn!r}, not h2 - the ClientHello is still "
                f"usable but there are no HTTP/2 frames to read")
        return record

    def tcp_end(self, flow: tcp.TCPFlow) -> None:
        self._finish(flow.client_conn.id)

    def tcp_error(self, flow: tcp.TCPFlow) -> None:
        self._finish(flow.client_conn.id)

    def done(self) -> None:
        for client_id in list(self._flows):
            self._finish(client_id)

    def _finish(self, client_id: str) -> None:
        record = self._flows.pop(client_id, None)
        if record is not None:
            self._write(record)
        self._hello.pop(client_id, None)
        self._prefix.pop(client_id, None)

    # -- writing -------------------------------------------------------------

    def _write(self, record: dict) -> None:
        out = Path(ctx.options.fp_out)
        out.mkdir(parents=True, exist_ok=True)
        payload = {k: v for k, v in record.items() if not k.startswith("_")}
        payload["client"] = b"".join(record["client"]).hex()
        payload["server"] = b"".join(record["server"]).hex()
        path = out / record["_file"]
        # Rewritten repeatedly while the connection lives, so never leave a
        # half-written file where the importer might pick it up.
        tmp = path.with_name(path.name + ".tmp")
        tmp.write_text(json.dumps(payload, indent=1))
        tmp.replace(path)
        logger.info(f"{record['sni']}: {len(payload['client']) // 2}B from "
                    f"client -> {path}")


addons = [FingerprintCapture()]
