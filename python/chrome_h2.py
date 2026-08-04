"""Make httpx's HTTP/2 layer look like Chrome's.

The TLS layer is already handled by the patched OpenSSL in ~/openssl, but a
server that speaks HTTP/2 sees a second, independent fingerprint built from the
SETTINGS frame, the connection WINDOW_UPDATE, any PRIORITY frames and the
pseudo-header order.  Out of the box httpcore sends

    1:4096;2:0;4:65535;5:16384;3:100;6:65536|16777216|0|m,a,s,p

which is nothing like Chrome and gives the game away.  This module provides a
transport that sends Chrome's values instead, and replaces the request headers
with Chrome's set, in Chrome's order.

    import chrome_h2
    import httpx

    with httpx.Client(transport=chrome_h2.ChromeTransport()) as client:
        client.get("https://example.com/")

Importing has no effect on its own: only clients given one of these transports
behave differently, so a library can use this without changing how the rest of
the process makes requests.  Comparing against stock behaviour is just a matter
of dropping the transport argument.

Nothing here is hand-maintained: the SETTINGS, the WINDOW_UPDATE, the HEADERS
priority, the pseudo-header order and the whole request-header profile are all
read out of REFERENCE_CAPTURE, a capture taken with hpack_probe.py.  Retargeting
at a different browser or a phone means capturing it and re-pointing that path -
see describe() for what the current capture resolves to.

The reference capture holds (Chrome 150 desktop; unchanged from Chrome 119 on):

    1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p
    md5 = 52d84b11737d980aef856699f885ca86

which matches Chromium's own source - `AddDefaultHttp2Settings()` in
net/http/http_network_session.cc and `SendInitialData()` in
net/spdy/spdy_session.cc, with kSpdyMaxHeaderTableSize=64K,
kSpdyStreamMaxRecvWindowSize=6M, kSpdyMaxHeaderListSize=256K and
kSpdySessionMaxRecvWindowSize=15M (15M - 65535 = 15663105).  `spdy::SettingsMap`
is a std::map, so Chrome emits the settings in ascending id order 1,2,4,6 - note
there is no MAX_CONCURRENT_STREAMS (3) and no MAX_FRAME_SIZE (5).

Two things this deliberately does not do:

* No fifth "GREASE" setting.  Chrome can emit one, but both its id and value are
  drawn fresh per connection and `enable_http2_settings_grease` is false by
  default, so the fixed pairs floating around the internet are themselves a
  tell.
* No standalone PRIORITY frames - hence the `0` in the fingerprint.  Chrome
  carries priority on the HEADERS frame instead, which we do reproduce.

This works by subclassing httpcore internals, which is only safe against the
exact versions it was written for, so it checks them and warns.
"""

from __future__ import annotations

import hashlib
import json
import os
import typing
import warnings
from pathlib import Path

import h2.settings
import hpack
import hpack.hpack
import httpcore
import httpcore._async.http2 as _async_mod
import httpcore._sync.http2 as _sync_mod
import httpx
import httpx._client

__all__ = ["ChromeTransport", "AsyncChromeTransport", "describe",
           "AKAMAI_FINGERPRINT", "AKAMAI_HASH", "PROFILE", "TARGET",
           "SETTINGS", "CONNECTION_WINDOW_UPDATE", "PSEUDO_ORDER"]

_EXPECTED = {"httpx": "0.27.2", "httpcore": "1.0.9", "h2": "4.4.0"}

#: The capture everything below is read from. Re-point this at a newer
#: hpack_probe.py capture to retarget the whole module - either edit this line
#: or set CHROME_H2_CAPTURE, which is handy for trying a capture out before
#: committing it. See describe() for what the current one resolves to.
REFERENCE_CAPTURE = Path(
    os.environ.get("CHROME_H2_CAPTURE")
    or Path(__file__).resolve().parent / "references" / "chrome150_probe.json")

#: Used only if the capture cannot be read, so that importing still works.
#: Same shape as _read_capture()'s return value.
_FALLBACK = {
    "headers": [
        ("sec-ch-ua", '"Not;A=Brand";v="8", "Chromium";v="150", "Google Chrome";v="150"'),
        ("sec-ch-ua-mobile", "?0"),
        ("sec-ch-ua-platform", '"Windows"'),
        ("upgrade-insecure-requests", "1"),
        ("user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                       "(KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36"),
        ("accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,"
                   "image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"),
        ("sec-fetch-site", "none"),
        ("sec-fetch-mode", "navigate"),
        ("sec-fetch-user", "?1"),
        ("sec-fetch-dest", "document"),
        ("accept-encoding", "gzip, deflate, br, zstd"),
        ("accept-language", "en-US,en;q=0.9"),
        ("priority", "u=0, i"),
    ],
    "pseudo_order": [":method", ":authority", ":scheme", ":path"],
    "settings": [(1, 65536), (2, 0), (4, 6291456), (6, 262144)],
    "window_update": 15663105,
    "priority": {"exclusive": True, "depends_on": 0, "weight": 256},
    "priority_frames": 0,
    "captured_at": None,
}


def _read_capture(path: Path) -> dict:
    """Everything this module impersonates, read out of a hpack_probe.py capture.

    Deriving it rather than hand-maintaining it means a new Chrome version - or
    a different client altogether - only needs a fresh capture.  The brand list
    in `sec-ch-ua` gets permuted every major release and the akamai numbers are
    easy to transcribe wrong, so hand-kept copies rot silently.

    Order is load-bearing in three places and must survive verbatim: the
    SETTINGS ids, the pseudo-headers and the request headers are all fingerprint
    material, so nothing here gets sorted or normalised.
    """
    data = json.loads(path.read_text())
    frames = data["frames"]

    def find(kind: str, pred: typing.Callable[[dict], bool] = lambda _f: True):
        return next((f for f in frames if f["type"] == kind and pred(f)), None)

    headers_frame = find("HEADERS")
    if headers_frame is None:
        msg = f"{path} has no HEADERS frame"
        raise ValueError(msg)

    def text(x: bytes | str) -> str:
        return x if isinstance(x, str) else x.decode("utf-8", "replace")

    decoded = [(text(k), text(v))
               for k, v in hpack.Decoder().decode(bytes.fromhex(headers_frame["header_block"]))]

    # An ACK carries no payload, so an empty settings list is not a client's.
    settings = find("SETTINGS", lambda f: bool(f.get("settings")) and not f["flags"] & 0x01)
    window = find("WINDOW_UPDATE", lambda f: f["stream"] == 0)

    return {
        "headers": [(k, v) for k, v in decoded if not k.startswith(":")],
        "pseudo_order": [k for k, _ in decoded if k.startswith(":")],
        "settings": [(s["id"], s["value"]) for s in settings["settings"]] if settings else [],
        # 0 doubles as "the client sent none", which is what it means on the wire.
        "window_update": window["increment"] if window else 0,
        "priority": headers_frame.get("priority"),
        "priority_frames": sum(1 for f in frames if f["type"] == "PRIORITY"),
        "captured_at": data.get("captured_at"),
    }


try:
    _CAP = _read_capture(REFERENCE_CAPTURE)
    _SOURCE = str(REFERENCE_CAPTURE)
except Exception as _exc:  # noqa: BLE001 - importing must not hard-fail
    warnings.warn(
        f"chrome_h2: could not read {REFERENCE_CAPTURE} ({_exc}); "
        f"falling back to the values baked in at the time of writing",
        RuntimeWarning, stacklevel=2)
    _CAP, _SOURCE = dict(_FALLBACK), "(built-in)"

_CAPTURED = _CAP["headers"]
_CAPTURED_AT = _CAP["captured_at"]
_CAPTURED_MAP = dict(_CAPTURED)


# --- the HTTP/2 wire layer, as captured ------------------------------------
# These four are exactly what the akamai fingerprint is computed from.

#: SETTINGS in wire order. Both the ids present and their order are fingerprint
#: material, so this stays a list of pairs and never becomes a dict literal.
SETTINGS: list[tuple[int, int]] = list(_CAP["settings"])

#: Connection-level WINDOW_UPDATE; 0 means the captured client sent none.
CONNECTION_WINDOW_UPDATE: int = _CAP["window_update"]

_PSEUDO_DEFAULT = (":method", ":authority", ":scheme", ":path")

#: Pseudo-header order, the last field of the fingerprint. Chrome is
#: m,a,s,p; other clients differ, which is why it is read from the capture.
PSEUDO_ORDER: tuple[str, ...] = tuple(_CAP["pseudo_order"])
if set(PSEUDO_ORDER) != set(_PSEUDO_DEFAULT):
    warnings.warn(
        f"chrome_h2: capture has pseudo-headers {list(PSEUDO_ORDER)}, expected "
        f"{list(_PSEUDO_DEFAULT)}; only those four can be reproduced, so the "
        f"standard order is used instead",
        RuntimeWarning, stacklevel=2)
    PSEUDO_ORDER = _PSEUDO_DEFAULT

#: RFC 7540 priority carried on the HEADERS frame, or {} if the capture had
#: none. h2 takes the human-readable 1..256 weight, subtracts one for the wire
#: byte, and sets the PRIORITY flag for us.
_HEADERS_PRIORITY = (
    {
        "priority_exclusive": _CAP["priority"]["exclusive"],
        "priority_depends_on": _CAP["priority"]["depends_on"],
        "priority_weight": _CAP["priority"]["weight"],
    }
    if _CAP["priority"] else {}
)

if _CAP["priority_frames"]:
    warnings.warn(
        f"chrome_h2: capture contains {_CAP['priority_frames']} standalone "
        f"PRIORITY frame(s), which are not reproduced - the third field of the "
        f"akamai fingerprint will not match",
        RuntimeWarning, stacklevel=2)


def _akamai_fingerprint() -> str:
    """SETTINGS | connection WINDOW_UPDATE | PRIORITY frames | pseudo-headers."""
    settings = ";".join(f"{sid}:{value}" for sid, value in SETTINGS)
    pseudo = ",".join(name[1] for name in PSEUDO_ORDER)
    # Third field is standalone PRIORITY frames, which we never send.
    return f"{settings}|{CONNECTION_WINDOW_UPDATE}|0|{pseudo}"


AKAMAI_FINGERPRINT = _akamai_fingerprint()
AKAMAI_HASH = hashlib.md5(  # noqa: S324 - akamai defines the hash as md5
    AKAMAI_FINGERPRINT.encode("ascii"), usedforsecurity=False).hexdigest()


def _chrome_version(user_agent: str) -> str:
    for token in user_agent.split():
        if token.startswith("Chrome/"):
            return token[len("Chrome/"):]
    return "unknown"


#: What this module currently impersonates. Read-only - to change it, capture a
#: new profile with hpack_probe.py and re-point REFERENCE_CAPTURE.
TARGET = {
    "chrome_version": _chrome_version(_CAPTURED_MAP.get("user-agent", "")),
    "user_agent": _CAPTURED_MAP.get("user-agent", ""),
    "sec_ch_ua": _CAPTURED_MAP.get("sec-ch-ua", ""),
    "platform": _CAPTURED_MAP.get("sec-ch-ua-platform", ""),
    "accept_language": _CAPTURED_MAP.get("accept-language", ""),
    "sec_fetch_mode": _CAPTURED_MAP.get("sec-fetch-mode", ""),
    "akamai_fingerprint": AKAMAI_FINGERPRINT,
    "akamai_hash": AKAMAI_HASH,
    "source": _SOURCE,
    "captured_at": _CAPTURED_AT,
}

#: Overridable. Defaults come from the capture, which was taken with whatever
#: UI language that Chrome profile had.
ACCEPT_LANGUAGE = TARGET["accept_language"]

#: Chrome sends `cache-control: max-age=0` on a reload or a re-entered URL, but
#: *not* on a plain navigation to a new address - both were confirmed against
#: live captures. Defaults to whatever the capture did.
SEND_CACHE_CONTROL = "cache-control" in _CAPTURED_MAP

#: "navigate" reproduces what Chrome sends for a top-level page load; its header
#: order is taken from real captures.  "xhr" is what a page's own fetch()/XHR
#: looks like - the header *set* is well known but I could not confirm the exact
#: order against a first-hand capture, so treat it as best-effort.
PROFILE = "navigate"


#: Marks where headers the caller supplied get spliced in.  Chrome puts cookie
#: and referer here, between `accept` and the sec-fetch block.
_EXTRA = "\x00extra\x00"

def _navigate_template() -> list[tuple[str, str | None]]:
    """The captured headers, with the caller's extras spliced in after `accept`.

    Everything except `cache-control` and `accept-language` comes straight from
    the capture, so a new Chrome only needs a new capture - no constants to
    hand-edit and get subtly wrong.
    """
    out: list[tuple[str, str | None]] = []
    for name, value in _CAPTURED:
        if name == "cache-control":
            if SEND_CACHE_CONTROL:
                out.append((name, value))
            continue
        out.append((name, ACCEPT_LANGUAGE if name == "accept-language" else value))
        if name == "accept":
            out.append((_EXTRA, None))
    if SEND_CACHE_CONTROL and "cache-control" not in _CAPTURED_MAP:
        out.insert(0, ("cache-control", "max-age=0"))
    if not any(n == _EXTRA for n, _ in out):
        out.append((_EXTRA, None))
    return out


def _template(profile: str) -> list[tuple[str, str | None]]:
    """Ordered (name, value) pairs; None means 'only if the caller supplied it'."""
    if profile == "navigate":
        return _navigate_template()
    if profile == "xhr":
        return [
            ("sec-ch-ua", TARGET["sec_ch_ua"]),
            ("sec-ch-ua-mobile", "?0"),
            ("sec-ch-ua-platform", TARGET["platform"]),
            ("user-agent", TARGET["user_agent"]),
            ("accept", "*/*"),
            (_EXTRA, None),
            ("sec-fetch-site", "same-origin"),
            ("sec-fetch-mode", "cors"),
            ("sec-fetch-dest", "empty"),
            ("accept-encoding", "gzip, deflate, br, zstd"),
            ("accept-language", ACCEPT_LANGUAGE),
            ("priority", "u=1, i"),
        ]
    msg = f"unknown profile {profile!r}, expected 'navigate' or 'xhr'"
    raise ValueError(msg)


def _httpx_default_headers() -> set[tuple[bytes, bytes]]:
    """The four headers httpx injects into every request.

    They have to be told apart from headers the caller actually asked for,
    otherwise httpx's `user-agent: python-httpx/...` would be treated as a
    deliberate override and survive into the request.  Read out of httpx rather
    than hardcoded so a version bump doesn't silently break the match.
    """
    return {
        (b"accept", b"*/*"),
        (b"accept-encoding", httpx._client.ACCEPT_ENCODING.encode("ascii")),
        (b"connection", b"keep-alive"),
        (b"user-agent", httpx._client.USER_AGENT.encode("ascii")),
    }


#: Never forwarded: `host` becomes :authority, the rest are HTTP/1-only hop
#: headers that h2 would strip anyway.
_DROP = frozenset(
    [b"host", b"transfer-encoding", b"connection", b"keep-alive", b"upgrade"],
)


def _build_headers(request: typing.Any) -> list[tuple[bytes, bytes]]:
    """Chrome's header list for this request, pseudo-headers first."""
    authority = [v for k, v in request.headers if k.lower() == b"host"][0]

    defaults = _httpx_default_headers()
    supplied: list[tuple[bytes, bytes]] = []
    for key, value in request.headers:
        key = key.lower()
        if key in _DROP or (key, value) in defaults:
            continue
        supplied.append((key, value))

    template = _template(PROFILE)
    known = {name.encode("ascii") for name, _ in template if name != _EXTRA}

    # Caller values win over the template; anything not in the template is
    # spliced in at the _EXTRA slot, keeping the caller's relative order.
    overrides: dict[bytes, list[bytes]] = {}
    extras: list[tuple[bytes, bytes]] = []
    for key, value in supplied:
        if key in known:
            overrides.setdefault(key, []).append(value)
        else:
            extras.append((key, value))

    pseudo = {
        ":method": request.method,
        ":authority": authority,
        ":scheme": request.url.scheme,
        ":path": request.url.target,
    }
    headers: list[tuple[bytes, bytes]] = [
        (name.encode("ascii"), pseudo[name]) for name in PSEUDO_ORDER
    ]
    for name, default in template:
        if name == _EXTRA:
            headers.extend(extras)
            continue
        key = name.encode("ascii")
        if key in overrides:
            headers.extend((key, v) for v in overrides[key])
        elif default is not None:
            headers.append((key, default.encode("ascii")))

    return _crumble_cookies(headers)


class _ChromeSettings(h2.settings.Settings):
    """Settings that advertise the captured ones, but still answer to h2/httpcore.

    `initiate_connection()` builds the SETTINGS frame by iterating this mapping,
    so narrowing iteration is what controls the wire - both which ids go out and
    in what order - and it is *only* iteration that we narrow.  Deleting the
    other entries outright is not an option: httpcore sizes a semaphore from
    `local_settings.max_concurrent_streams`, and h2 returns 2**32+1 when that
    key is missing, at which point httpcore tries to acquire the semaphore four
    billion times and the request never leaves.

    Everything else reads values through `__getitem__` or `_settings` directly,
    so the hidden entries keep working.
    """

    def __iter__(self) -> typing.Iterator[int]:
        return iter([sid for sid, _ in SETTINGS])

    def __len__(self) -> int:
        return len(SETTINGS)


class _ChromeHpackEncoder(hpack.Encoder):
    """HPACK encoder that makes the same choices quiche (Chrome) makes.

    The akamai fingerprint doesn't look at HPACK, but anything hashing the raw
    HEADERS payload will see these.  hpack and quiche disagree in three places:

    * **Huffman.** hpack Huffman-codes every literal unconditionally; quiche
      computes the Huffman size first and only uses it when strictly shorter
      (`if (encoded_size < str.size())` in hpack_encoder.cc).  For short ASCII
      values Huffman can be *longer*, so this changes real bytes.
    * **Never-indexed.** h2 rewrites `authorization`, `proxy-authorization` and
      any `cookie` under 20 bytes into never-indexed literals - its own comment
      says the rule comes from Firefox and nghttp2.  quiche emits only indexed
      and non-indexed literals, never the never-indexed opcode, so we ignore the
      `sensitive` flag entirely.
    * **What goes in the dynamic table.** hpack indexes everything indexable.
      quiche's DefaultPolicy skips empty names and every pseudo-header except
      `:authority`, which changes both the opcode of e.g. `:path` and the
      dynamic table state for every later request on the connection.
    """

    @staticmethod
    def _chrome_should_index(name: bytes) -> bool:
        """quiche's DefaultPolicy."""
        if not name:
            return False
        if name[:1] == b":":
            return name == b":authority"
        return True

    def _maybe_huffman(self, data: bytes, huffman: bool) -> tuple[bytes, bool]:
        if not huffman:
            return data, False
        encoded = self.huffman_coder.encode(data)
        if len(encoded) < len(data):
            return encoded, True
        return data, False

    def add(
        self,
        to_add: tuple[bytes, bytes],
        sensitive: bool,  # noqa: ARG002 - quiche has no never-indexed mode
        huffman: bool = False,
    ) -> bytes:
        name, value = to_add
        index = self._chrome_should_index(name)
        indexbit = hpack.hpack.INDEX_INCREMENTAL if index else hpack.hpack.INDEX_NONE

        match = self.header_table.search(name, value)
        if match is None:
            encoded = self._encode_literal(name, value, indexbit, huffman)
            if index:
                self.header_table.add(name, value)
            return encoded

        position, name, perfect = match
        if perfect is not None:
            return self._encode_indexed(position)

        encoded = self._encode_indexed_literal(position, value, indexbit, huffman)
        if index:
            self.header_table.add(name, value)
        return encoded

    def _encode_literal(
        self, name: bytes, value: bytes, indexbit: bytes, huffman: bool = False,
    ) -> bytes:
        name, name_huffed = self._maybe_huffman(name, huffman)
        value, value_huffed = self._maybe_huffman(value, huffman)

        name_len = hpack.hpack.encode_integer(len(name), 7)
        value_len = hpack.hpack.encode_integer(len(value), 7)
        if name_huffed:
            name_len[0] |= 0x80
        if value_huffed:
            value_len[0] |= 0x80

        return b"".join([indexbit, bytes(name_len), name, bytes(value_len), value])

    def _encode_indexed_literal(
        self, index: int, value: bytes, indexbit: bytes, huffman: bool = False,
    ) -> bytes:
        prefix_bits = 6 if indexbit == hpack.hpack.INDEX_INCREMENTAL else 4
        prefix = hpack.hpack.encode_integer(index, prefix_bits)
        prefix[0] |= ord(indexbit)

        value, value_huffed = self._maybe_huffman(value, huffman)
        value_len = hpack.hpack.encode_integer(len(value), 7)
        if value_huffed:
            value_len[0] |= 0x80

        return b"".join([bytes(prefix), bytes(value_len), value])


def _crumble_cookies(
    headers: list[tuple[bytes, bytes]],
) -> list[tuple[bytes, bytes]]:
    """Split `cookie` into one field per crumb, the way quiche does.

    RFC 7540 section 8.1.2.5 allows it and Chrome takes it: HpackEncoder is
    constructed with `crumble_cookies_(true)`.  h2 has its own
    `split_outbound_cookies` option but splits on b"; ", whereas quiche splits
    on ';' and then eats a single following space - so `a=1;b=2` crumbles for
    Chrome and would not for h2.  Doing it here keeps the two in step.
    """
    out: list[tuple[bytes, bytes]] = []
    for name, value in headers:
        if name != b"cookie":
            out.append((name, value))
            continue
        pos = 0
        while True:
            end = value.find(b";", pos)
            if end == -1:
                out.append((name, value[pos:]))
                break
            out.append((name, value[pos:end]))
            pos = end + 1
            if pos != len(value) and value[pos : pos + 1] == b" ":
                pos += 1
    return out


def _apply_settings(state: typing.Any) -> None:
    """Install the captured SETTINGS and make the HPACK decoder agree with them.

    h2 only pushes HEADER_TABLE_SIZE and MAX_HEADER_LIST_SIZE into the decoder
    when a *pending* settings change gets ACKed.  We hand it finished values, so
    nothing is pending and the decoder would quietly keep hpack's 4096-byte
    default while we advertise 64K.  Servers that take us at our word and use a
    bigger dynamic table - google.com does - then blow up with
    "Encoder exceeded max allowable table size" on the response headers.
    """
    codes = h2.settings.SettingCodes
    values = dict(SETTINGS)
    state.local_settings = _ChromeSettings(
        client=True,
        initial_values={
            **values,
            # Kept even when the capture has no id 3, because httpcore reads it;
            # __iter__ decides what actually goes on the wire. 100 is the value
            # stock httpcore uses, so its stream limiting is unchanged.
            codes.MAX_CONCURRENT_STREAMS: values.get(codes.MAX_CONCURRENT_STREAMS, 100),
        },
    )
    if codes.HEADER_TABLE_SIZE in values:
        state.decoder.max_allowed_table_size = values[codes.HEADER_TABLE_SIZE]
    if codes.MAX_HEADER_LIST_SIZE in values:
        state.decoder.max_header_list_size = values[codes.MAX_HEADER_LIST_SIZE]

    # h2 builds a stock hpack.Encoder in H2Connection.__init__; swap in one that
    # encodes the way Chrome does. Safe here because nothing has been encoded on
    # this connection yet, so the dynamic table is empty either way.
    state.encoder = _ChromeHpackEncoder()


class ChromeHTTP2Connection(_sync_mod.HTTP2Connection):
    def _send_connection_init(self, request: typing.Any) -> None:
        _apply_settings(self._h2_state)
        self._h2_state.initiate_connection()
        if CONNECTION_WINDOW_UPDATE:
            self._h2_state.increment_flow_control_window(CONNECTION_WINDOW_UPDATE)
        self._write_outgoing_data(request)

    def _send_request_headers(self, request: typing.Any, stream_id: int) -> None:
        end_stream = not _sync_mod.has_body_headers(request)
        self._h2_state.send_headers(
            stream_id,
            _build_headers(request),
            end_stream=end_stream,
            **_HEADERS_PRIORITY,
        )
        # No per-stream WINDOW_UPDATE here: we advertise a 6MB stream window in
        # SETTINGS, which is what Chrome relies on. h2's flow control manager
        # tops the window up as the response is consumed.
        self._write_outgoing_data(request)


class AsyncChromeHTTP2Connection(_async_mod.AsyncHTTP2Connection):
    async def _send_connection_init(self, request: typing.Any) -> None:
        _apply_settings(self._h2_state)
        self._h2_state.initiate_connection()
        if CONNECTION_WINDOW_UPDATE:
            self._h2_state.increment_flow_control_window(CONNECTION_WINDOW_UPDATE)
        await self._write_outgoing_data(request)

    async def _send_request_headers(
        self, request: typing.Any, stream_id: int,
    ) -> None:
        end_stream = not _async_mod.has_body_headers(request)
        self._h2_state.send_headers(
            stream_id,
            _build_headers(request),
            end_stream=end_stream,
            **_HEADERS_PRIORITY,
        )
        await self._write_outgoing_data(request)


_CONNECTION_VARIANTS: dict[tuple[type, type], type] = {}


def _chrome_connection_class(cls: type, stock: type, chrome: type) -> type:
    """A subclass of `cls` whose HTTP/2 connection is upgraded to ours.

    httpcore has three classes that set up an HTTP/2 connection - the direct
    one, the proxy tunnel and the SOCKS one - and every one of them ends with

        from .http2 import HTTP2Connection          # function-local import
        self._connection = HTTP2Connection(origin=..., stream=..., ...)

    so there is no class to pass in and no hook to install. Rebinding that
    module attribute would change behaviour for every httpx client in the
    process, which is exactly what a transport is supposed to avoid.

    What all three do have in common is the attribute, so we intercept the
    assignment: `_connection` becomes a data descriptor that retags a
    freshly-built HTTP/2 connection as ours. Sound because ChromeHTTP2Connection
    adds no state and no __init__, and nothing has gone out yet - the HTTP/2
    preface is sent on the first handle_request(), which is after this point.

    The pay-off is that none of httpcore's connection logic is copied here, so
    proxy and SOCKS connections keep working unchanged and an httpcore upgrade
    cannot leave a stale copy of their internals behind.
    """
    key = (cls, chrome)
    if key not in _CONNECTION_VARIANTS:
        def _get(self: typing.Any) -> typing.Any:
            # The classes assign None in __init__, so it is already in the
            # instance dict by the time we retag; read from there to keep
            # their semantics exactly.
            return self.__dict__.get("_connection")

        def _set(self: typing.Any, conn: typing.Any) -> None:
            if type(conn) is stock:
                conn.__class__ = chrome
            self.__dict__["_connection"] = conn

        _CONNECTION_VARIANTS[key] = type(
            f"Chrome{cls.__name__}", (cls,),
            {"_connection": property(_get, _set)})
    return _CONNECTION_VARIANTS[key]


class _ChromePoolMixin:
    """Layered over whichever pool httpx built, so its own routing survives.

    A proxy pool's create_connection() is what knows how to reach the proxy, so
    it must not be replaced - only wrapped. Everything the pool hands out gets
    retagged on the way past, no matter which class it is.
    """

    _H2_CLASSES: typing.ClassVar[tuple[type, type]]

    def create_connection(self, origin: typing.Any) -> typing.Any:
        conn = super().create_connection(origin)  # type: ignore[misc]
        conn.__class__ = _chrome_connection_class(type(conn), *self._H2_CLASSES)
        return conn


class _ChromeSyncPool(_ChromePoolMixin):
    _H2_CLASSES = (_sync_mod.HTTP2Connection, ChromeHTTP2Connection)


class _ChromeAsyncPool(_ChromePoolMixin):
    _H2_CLASSES = (_async_mod.AsyncHTTP2Connection, AsyncChromeHTTP2Connection)


_warned_versions = False


def _check_versions() -> None:
    """Warn once if the libraries are not the ones this was written against."""
    global _warned_versions
    if _warned_versions:
        return
    _warned_versions = True

    import h2 as _h2
    import httpcore as _httpcore
    import httpx as _httpx

    actual = {
        "httpx": _httpx.__version__,
        "httpcore": _httpcore.__version__,
        "h2": _h2.__version__,
    }
    off = {k: v for k, v in actual.items() if v != _EXPECTED[k]}
    if off:
        detail = ", ".join(f"{k} {v} (expected {_EXPECTED[k]})" for k, v in off.items())
        warnings.warn(
            f"chrome_h2 subclasses library internals and was written against "
            f"{_EXPECTED}; found {detail}. Re-check httpcore's handle_request, "
            f"create_connection, _send_connection_init and _send_request_headers "
            f"before trusting the fingerprint.",
            RuntimeWarning,
            stacklevel=3,
        )


_POOL_VARIANTS: dict[tuple[type, type], type] = {}


def _retag_pool(transport: typing.Any, mixin: type, base: type) -> None:
    """Layer `mixin` onto whatever pool the transport built.

    Retagging the instance rather than constructing our own pool: the mixin adds
    no state, while rebuilding would mean mirroring the dozen arguments httpx
    passes - and re-mirroring them on every httpx release. Building the subclass
    from the pool's *actual* type is what keeps proxies working: HTTPProxy and
    SOCKSProxy are ConnectionPool subclasses with their own create_connection,
    and the mixin's super() call goes to theirs.
    """
    _check_versions()
    pool = transport._pool
    if not isinstance(pool, base):
        warnings.warn(
            f"chrome_h2: the transport built a {type(pool).__name__}, which is "
            f"not a {base.__name__}; leaving its HTTP/2 layer alone, so the "
            f"akamai fingerprint will NOT match.",
            RuntimeWarning, stacklevel=3)
        return

    key = (type(pool), mixin)
    if key not in _POOL_VARIANTS:
        _POOL_VARIANTS[key] = type(
            f"Chrome{type(pool).__name__}", (mixin, type(pool)), {})
    pool.__class__ = _POOL_VARIANTS[key]


class ChromeTransport(httpx.HTTPTransport):
    """An httpx transport whose HTTP/2 layer looks like Chrome's.

        import chrome_h2, httpx

        with httpx.Client(transport=chrome_h2.ChromeTransport()) as client:
            client.get("https://example.com/")

    Takes everything httpx.HTTPTransport takes, `proxy` included; `http2`
    defaults to True here. Note that arguments like `verify` and `proxy` belong
    on the transport, not on the Client - httpx ignores its own when a transport
    is supplied:

        chrome_h2.ChromeTransport(proxy="http://127.0.0.1:8080")
    """

    def __init__(self, *args: typing.Any, **kwargs: typing.Any) -> None:
        kwargs.setdefault("http2", True)
        super().__init__(*args, **kwargs)
        _retag_pool(self, _ChromeSyncPool, httpcore.ConnectionPool)


class AsyncChromeTransport(httpx.AsyncHTTPTransport):
    """Async twin of ChromeTransport, for httpx.AsyncClient."""

    def __init__(self, *args: typing.Any, **kwargs: typing.Any) -> None:
        kwargs.setdefault("http2", True)
        super().__init__(*args, **kwargs)
        _retag_pool(self, _ChromeAsyncPool, httpcore.AsyncConnectionPool)


def describe() -> str:
    """What this module is currently impersonating."""
    prio = (f"exclusive={_HEADERS_PRIORITY['priority_exclusive']} "
            f"dep={_HEADERS_PRIORITY['priority_depends_on']} "
            f"weight={_HEADERS_PRIORITY['priority_weight']}"
            if _HEADERS_PRIORITY else "none (no PRIORITY flag on HEADERS)")
    lines = [
        f"chrome_h2 target",
        f"  chrome        : {TARGET['chrome_version']}",
        f"  user-agent    : {TARGET['user_agent']}",
        f"  sec-ch-ua     : {TARGET['sec_ch_ua']}",
        f"  platform      : {TARGET['platform']}",
        f"  accept-language: {ACCEPT_LANGUAGE}"
        + ("" if ACCEPT_LANGUAGE == TARGET["accept_language"]
           else f"  (capture had {TARGET['accept_language']})"),
        f"  cache-control : {'sent' if SEND_CACHE_CONTROL else 'not sent'}",
        f"  profile       : {PROFILE} (capture was sec-fetch-mode: "
        f"{TARGET['sec_fetch_mode'] or 'unknown'})",
        f"  akamai        : {AKAMAI_FINGERPRINT}",
        f"  akamai md5    : {AKAMAI_HASH}",
        f"  settings      : "
        + ", ".join(f"{sid}={value}" for sid, value in SETTINGS),
        f"  window update : "
        + (str(CONNECTION_WINDOW_UPDATE) if CONNECTION_WINDOW_UPDATE else "not sent"),
        f"  headers prio  : {prio}",
        f"  derived from  : {TARGET['source']}",
        f"  captured at   : {TARGET['captured_at'] or 'unknown'}",
    ]
    return "\n".join(lines)
