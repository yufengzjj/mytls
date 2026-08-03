"""Make httpx's HTTP/2 layer look like Chrome's.

The TLS layer is already handled by the patched OpenSSL in ~/openssl, but a
server that speaks HTTP/2 sees a second, independent fingerprint built from the
SETTINGS frame, the connection WINDOW_UPDATE, any PRIORITY frames and the
pseudo-header order.  Out of the box httpcore sends

    1:4096;2:0;4:65535;5:16384;3:100;6:65536|16777216|0|m,a,s,p

which is nothing like Chrome and gives the game away.  Importing this module
rewrites those to Chrome's values and replaces the request headers with
Chrome's set, in Chrome's order.

    import chrome_h2          # patches on import
    import httpx
    httpx.Client(http2=True).get(...)

`chrome_h2.disable()` / `enable()` are there mainly so tests can show that the
difference really comes from this patch.

Target (Chrome 150 desktop; the h2 layer is unchanged from Chrome 119 on):

    1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p
    md5 = 52d84b11737d980aef856699f885ca86

The numbers come from Chromium: `AddDefaultHttp2Settings()` in
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

This works by rebinding module attributes in httpcore.  That is only safe
against the exact versions it was written for, so it checks them and warns.
"""

from __future__ import annotations

import json
import typing
import warnings
from pathlib import Path

import h2.settings
import hpack
import hpack.hpack
import httpcore._async.http2 as _async_mod
import httpcore._sync.http2 as _sync_mod
import httpx._client

__all__ = ["enable", "disable", "is_enabled", "describe",
           "AKAMAI_FINGERPRINT", "PROFILE", "TARGET"]

_EXPECTED = {"httpx": "0.27.2", "httpcore": "1.0.9", "h2": "4.4.0"}

AKAMAI_FINGERPRINT = "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p"
AKAMAI_HASH = "52d84b11737d980aef856699f885ca86"

#: The capture everything below is read from. Re-point this at a newer
#: hpack_probe.py capture to retarget the whole module - see describe().
REFERENCE_CAPTURE = Path(__file__).resolve().parent / "references" / "chrome150_probe.json"

#: Used only if the capture cannot be read, so that importing still works.
_FALLBACK_NAVIGATE = [
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
]


def _read_capture(path: Path) -> tuple[list[tuple[str, str]], str | None]:
    """Return the request headers of a hpack_probe.py capture, in wire order.

    Deriving the profile from a capture rather than hand-maintaining it means a
    new Chrome version only needs a fresh capture: the brand list in
    `sec-ch-ua`, for one, gets permuted every major release, so a hand-kept
    copy silently rots.
    """
    data = json.loads(path.read_text())
    frame = next(f for f in data["frames"] if f["type"] == "HEADERS")
    block = bytes.fromhex(frame["header_block"])

    def text(x: bytes | str) -> str:
        return x if isinstance(x, str) else x.decode("utf-8", "replace")

    headers = [(text(k), text(v)) for k, v in hpack.Decoder().decode(block)]
    # Pseudo-headers are produced per request, not part of the profile.
    return ([(k, v) for k, v in headers if not k.startswith(":")],
            data.get("captured_at"))


try:
    _CAPTURED, _CAPTURED_AT = _read_capture(REFERENCE_CAPTURE)
    _SOURCE = str(REFERENCE_CAPTURE)
except Exception as _exc:  # noqa: BLE001 - importing must not hard-fail
    warnings.warn(
        f"chrome_h2: could not read {REFERENCE_CAPTURE} ({_exc}); "
        f"falling back to the values baked in at the time of writing",
        RuntimeWarning, stacklevel=2)
    _CAPTURED, _CAPTURED_AT, _SOURCE = list(_FALLBACK_NAVIGATE), None, "(built-in)"

_CAPTURED_MAP = dict(_CAPTURED)


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
    "akamai_fingerprint": None,   # filled in below, once it is defined
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

CONNECTION_WINDOW_UPDATE = 15663105

# HEADERS carries RFC 7540 priority: exclusive, no parent, weight 256.  h2 takes
# the human-readable 1..256 weight and subtracts one for the wire byte, and sets
# the PRIORITY flag for us.
_HEADERS_PRIORITY = {
    "priority_exclusive": True,
    "priority_depends_on": 0,
    "priority_weight": 256,
}


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

    headers: list[tuple[bytes, bytes]] = [
        (b":method", request.method),
        (b":authority", authority),
        (b":scheme", request.url.scheme),
        (b":path", request.url.target),
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
    """Settings that advertise Chrome's four, but still answer to h2/httpcore.

    `initiate_connection()` builds the SETTINGS frame by iterating this mapping,
    so narrowing iteration is what controls the wire - and it is *only*
    iteration that we narrow.  Deleting the other entries outright is not an
    option: httpcore sizes a semaphore from
    `local_settings.max_concurrent_streams`, and h2 returns 2**32+1 when that
    key is missing, at which point httpcore tries to acquire the semaphore four
    billion times and the request never leaves.

    Everything else reads values through `__getitem__` or `_settings` directly,
    so the hidden entries keep working.
    """

    _EMIT: typing.ClassVar[tuple[h2.settings.SettingCodes, ...]] = (
        h2.settings.SettingCodes.HEADER_TABLE_SIZE,
        h2.settings.SettingCodes.ENABLE_PUSH,
        h2.settings.SettingCodes.INITIAL_WINDOW_SIZE,
        h2.settings.SettingCodes.MAX_HEADER_LIST_SIZE,
    )

    def __iter__(self) -> typing.Iterator[h2.settings.SettingCodes]:
        return iter(self._EMIT)

    def __len__(self) -> int:
        return len(self._EMIT)


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


_SETTINGS_VALUES = {
    h2.settings.SettingCodes.HEADER_TABLE_SIZE: 65536,
    h2.settings.SettingCodes.ENABLE_PUSH: 0,
    h2.settings.SettingCodes.INITIAL_WINDOW_SIZE: 6291456,
    h2.settings.SettingCodes.MAX_HEADER_LIST_SIZE: 262144,
}


def _apply_settings(state: typing.Any) -> None:
    """Install Chrome's SETTINGS and make the HPACK decoder agree with them.

    h2 only pushes HEADER_TABLE_SIZE and MAX_HEADER_LIST_SIZE into the decoder
    when a *pending* settings change gets ACKed.  We hand it finished values, so
    nothing is pending and the decoder would quietly keep hpack's 4096-byte
    default while we advertise 64K.  Servers that take us at our word and use a
    bigger dynamic table - google.com does - then blow up with
    "Encoder exceeded max allowable table size" on the response headers.
    """
    codes = h2.settings.SettingCodes
    state.local_settings = _ChromeSettings(
        client=True,
        initial_values={
            **_SETTINGS_VALUES,
            # Not advertised - kept only because httpcore reads it. 100 is the
            # value stock httpcore uses, so its stream limiting is unchanged.
            codes.MAX_CONCURRENT_STREAMS: 100,
        },
    )
    state.decoder.max_allowed_table_size = _SETTINGS_VALUES[codes.HEADER_TABLE_SIZE]
    state.decoder.max_header_list_size = _SETTINGS_VALUES[codes.MAX_HEADER_LIST_SIZE]

    # h2 builds a stock hpack.Encoder in H2Connection.__init__; swap in one that
    # encodes the way Chrome does. Safe here because nothing has been encoded on
    # this connection yet, so the dynamic table is empty either way.
    state.encoder = _ChromeHpackEncoder()


class ChromeHTTP2Connection(_sync_mod.HTTP2Connection):
    def _send_connection_init(self, request: typing.Any) -> None:
        _apply_settings(self._h2_state)
        self._h2_state.initiate_connection()
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


_ORIGINAL = {
    "sync": _sync_mod.HTTP2Connection,
    "async": _async_mod.AsyncHTTP2Connection,
}
_enabled = False


def _check_versions() -> None:
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
            f"chrome_h2 patches library internals and was written against "
            f"{_EXPECTED}; found {detail}. Re-check "
            f"httpcore's _send_connection_init/_send_request_headers before "
            f"trusting the fingerprint.",
            RuntimeWarning,
            stacklevel=3,
        )


def enable() -> None:
    """Point httpcore at our HTTP/2 connection classes.

    httpcore imports the class inside `handle_request` rather than at module
    import time, so rebinding the module attribute is enough - no need to
    subclass HTTPConnection or ConnectionPool.
    """
    global _enabled
    if _enabled:
        return
    _check_versions()
    _sync_mod.HTTP2Connection = ChromeHTTP2Connection  # type: ignore[misc]
    _async_mod.AsyncHTTP2Connection = AsyncChromeHTTP2Connection  # type: ignore[misc]
    _enabled = True


def disable() -> None:
    """Restore httpcore's own classes."""
    global _enabled
    if not _enabled:
        return
    _sync_mod.HTTP2Connection = _ORIGINAL["sync"]  # type: ignore[misc]
    _async_mod.AsyncHTTP2Connection = _ORIGINAL["async"]  # type: ignore[misc]
    _enabled = False


def is_enabled() -> bool:
    return _enabled


TARGET["akamai_fingerprint"] = AKAMAI_FINGERPRINT


def describe() -> str:
    """What this module is currently impersonating."""
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
        f"  derived from  : {TARGET['source']}",
        f"  patched       : {'yes' if _enabled else 'no'}",
    ]
    return "\n".join(lines)


enable()
