"""Make httpx's HTTP/2 layer and request headers look like a real browser's.

The TLS layer is handled by the patched OpenSSL in ~/openssl, but a server that
speaks HTTP/2 sees a second, independent fingerprint built from the SETTINGS
frame, the connection WINDOW_UPDATE, any PRIORITY frames and the pseudo-header
order.  Out of the box httpcore sends

    1:4096;2:0;4:65535;5:16384;3:100;6:65536|16777216|0|m,a,s,p

which is nothing like a browser and gives the game away.  This module provides
transports that send a captured browser's values instead, and put the request
headers in that browser's order.

**The order, not the values.**  A transport sets nothing a caller could set
themselves: no user-agent, no accept, no accept-language, no sec-ch-ua.  Those
are the caller's to supply, and a header goes on the wire only if they did -
`client.get(url)` with no headers sends the four pseudo-headers and nothing
else.  What the transport does impose is everything httpx gives no way to
reach: where each header sits, the pseudo-header order, the HPACK encoding,
the SETTINGS, the WINDOW_UPDATE, the HEADERS priority and the TLS layer.

    import httpx
    import mytls

    with httpx.Client(transport=fp.transport("chrome")) as client:
        client.get("https://example.com/", headers={"User-Agent": ...})

To send what the captured browser sent, ask for it - `headers=` on the
transport is the caller speaking, so it is applied to every request:

    fp.Transport("chrome", headers=fp.profile("chrome").headers)

Importing has no effect on its own: only clients given one of these transports
behave differently, so a library can use this without changing how the rest of
the process makes requests.  Comparing against stock behaviour is just a matter
of dropping the transport argument.

Nothing here is hand-maintained and nothing here is written for a particular
browser.  Every profile is a capture taken with hpack_probe.py and dropped into
PROFILES_DIR:

    mytls-probe serve --brand firefox   # capture it
    fp.PROFILES                                   # it is already there
    fp.transport("firefox")                       # and already usable
    fp.FirefoxTransport()                         # same thing, by name

The SETTINGS, the WINDOW_UPDATE, the HEADERS priority, the pseudo-header order,
the whole request-header profile and the reported metadata (user-agent,
sec-ch-ua, platform, ...) are all read out of that one file, so a new browser
version needs a new capture and no code change at all.  See catalog() for what
is currently installed and describe() for the details of one profile.

A brand is a browser, not a browser *version*: there is one `chrome.json`, and
capturing Chrome again replaces it.  The version is inside the capture, read off
its user-agent and reported as Profile.version, so nothing has to be renamed
when Chrome updates and no caller ends up pinned to a stale profile.

Chrome 150 desktop, for reference, comes out as

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
  tell.  A capture of a GREASEing client would carry one fixed pair here, which
  is worse than none - check catalog() after capturing.
* No standalone PRIORITY frames - hence the `0` in the fingerprint.  Chrome
  carries priority on the HEADERS frame instead, which we do reproduce.  A
  capture containing standalone PRIORITY frames warns on load.

This works by subclassing httpcore internals, which is only safe against the
exact versions it was written for, so it checks them and warns.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import ssl
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

from . import tls_profile

__all__ = ["Profile", "PROFILES", "PROFILES_DIR", "DEFAULT_BRAND",
           "Transport", "AsyncTransport", "transport", "async_transport",
           "send_exact",
           "profile", "brands", "brand_for", "system_of", "reload", "describe",
           "catalog", "tls_profile"]

#: Versions this module's subclassing has actually been run against, not
#: versions it requires - pyproject pins only httpx, and h2 is left to whatever
#: `httpx[http2]` resolves (`h2>=3,<5`). Several are listed where several have
#: been measured: h2 4.3.0, 4.4.0 and 4.4.1 produce a byte-for-byte identical
#: selftest across all four profiles, because everything that changed between
#: them is on the *receiving* side (`validate_received_setting`, zero-length
#: DATA flow control, `_get_stream_by_id`, a duplicate-Host check) while what
#: is overridden here - `Settings` slot order, `__delitem__`, `send_headers`'
#: priority arguments - did not move; 4.4.0 and 4.4.1 ship a byte-identical
#: `connection.py` and `settings.py`.
#: 4.3.0 matters because that is the version mitmproxy pins, so listing it is
#: what lets mitmproxy live in the same interpreter.
#:
#: hpack is here for the opposite reason to h2: nothing pins it *at all* - it
#: arrives two hops down, httpx[http2] -> h2>=3,<5 -> hpack>=4.1,<5 - and what
#: this module does to it is deeper than anything it does to h2. `_QuicheEncoder`
#: subclasses `hpack.Encoder` and calls `_encode_literal`,
#: `_encode_indexed_literal`, `header_table.search`, `huffman_coder` and
#: `hpack.hpack.INDEX_NEVER`, all private. A change there does not raise: it
#: silently encodes different bytes, which is the one failure this package
#: exists to prevent. 4.1.0 is what every listed h2 resolves to, and all four
#: profiles re-encode byte-identically on it. 4.2.0 verified the same way
#: (`mytls-probe selftest`: every profile re-encodes byte-identical), so it is
#: listed too rather than warned about.
_EXPECTED = {
    "httpx": ("0.27.2",),
    "httpcore": ("1.0.9",),
    "h2": ("4.4.1", "4.4.0", "4.3.0"),
    "hpack": ("4.2.0", "4.1.0"),
}

#: Default for `priority_override` / `Transport(priority=...)`: whatever the
#: capture did. A distinct sentinel rather than None, because None is a
#: meaningful value there - "send no priority at all".
FROM_CAPTURE = "capture"

#: One capture per brand, named `<brand>.json`. Written by
#: `mytls-probe serve --brand <brand>`; set BROWSER_FP_PROFILES to try a
#: directory of captures out before committing them.
PROFILES_DIR = Path(
    os.environ.get("BROWSER_FP_PROFILES")
    or Path(__file__).resolve().parent / "profiles")

#: Which brand the no-argument forms use. Falls back to the only installed
#: profile; with several installed and no BROWSER_FP_BRAND set, the brand has to
#: be named, because silently picking one is how you ship the wrong fingerprint.
DEFAULT_BRAND: str | None = os.environ.get("BROWSER_FP_BRAND") or None


# --- reading a capture ------------------------------------------------------

def _read_capture(path: Path) -> dict:
    """Everything a profile impersonates, read out of a hpack_probe.py capture.

    Deriving it rather than hand-maintaining it means a new Chrome version - or
    a different browser altogether - only needs a fresh capture.  The brand list
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
        "brand": data.get("brand") or path.stem,
        "meta": data.get("meta") or {},
        "headers": [(k, v) for k, v in decoded if not k.startswith(":")],
        "pseudo_order": [k for k, _ in decoded if k.startswith(":")],
        "settings": [(s["id"], s["value"]) for s in settings["settings"]] if settings else [],
        # 0 doubles as "the client sent none", which is what it means on the wire.
        "window_update": window["increment"] if window else 0,
        "priority": headers_frame.get("priority"),
        "priority_frames": sum(1 for f in frames if f["type"] == "PRIORITY"),
        "captured_at": data.get("captured_at"),
        # Whether the captured ClientHello offered a session_ticket extension.
        # The only TLS detail read here, because it is the only one the caller
        # can override - see Profile.session_ticket_override. None means the
        # capture has no ClientHello to read it from.
        "session_ticket": _captured_session_ticket(data.get("client_hello")),
        # Present only when the probe caught the page's own fetch; see Profile.
        **({"xhr": data["xhr"]} if "xhr" in data else {}),
    }


def _captured_session_ticket(client_hello: dict | None) -> bool | None:
    """Did this ClientHello carry extension 0x0023, empty or otherwise?"""
    if not client_hello or "extensions" not in client_hello:
        return None
    return any(ext.get("type") == 0x0023
               for ext in client_hello["extensions"])


_PSEUDO_DEFAULT = (":method", ":authority", ":scheme", ":path")

#: sec-fetch-mode as the browser reports it -> which of our templates it is.
_MODE_TO_KIND = {"navigate": "navigate", "cors": "xhr"}


#: Product tokens in the order they have to be tested: every Chromium fork keeps
#: `Chrome/x` in its user-agent and adds its own token, and everything with a
#: rendering engine still claims `Safari/537.36`.
_PRODUCTS = ("Edg", "OPR", "YaBrowser", "Vivaldi", "SamsungBrowser",
             "Firefox", "Chrome", "Safari")


def _product(user_agent: str) -> tuple[str, str]:
    """(browser, version) as claimed by the user-agent, best effort."""
    for name in _PRODUCTS:
        m = re.search(rf"\b{name}/(\S+)", user_agent)
        if m:
            return name, m.group(1)
    return "unknown", "unknown"


#: Product token -> brand. A brand is a browser on a platform, which is as fine
#: as it gets: two builds of the same browser that produce different bytes need
#: different names, and anything finer (a version) would leave callers pinned to
#: a stale capture.
_BRANDS = {"Edg": "edge", "OPR": "opera", "YaBrowser": "yandex",
           "Vivaldi": "vivaldi", "SamsungBrowser": "samsung",
           "Firefox": "firefox", "Chrome": "chrome", "Safari": "safari"}


def brand_for(headers: dict[str, str]) -> str:
    """The brand a captured client should be stored as, from its own headers.

    Naming the brand at capture time would mean typing it in every time and
    getting it wrong once; the client already says who it is, so read it off the
    user-agent.  No version goes in the name - `chrome`, not `chrome150` - so
    capturing Chrome again simply replaces the profile.
    """
    user_agent = headers.get("user-agent", "")
    browser, _ = _product(user_agent)
    base = _BRANDS.get(browser)
    if base is None:
        msg = (f"cannot tell which browser sent this from its user-agent "
               f"({user_agent!r}); name it with --brand")
        raise ValueError(msg)

    mobile = headers.get("sec-ch-ua-mobile") == "?1"
    if "Android" in user_agent:
        return f"{base}_android"
    if "iPhone" in user_agent or "iPad" in user_agent:
        return f"{base}_ios"
    if mobile:
        return f"{base}_mobile"
    return base


#: How a client names its operating system, most specific form first. The
#: second element is what to call it; None means the pattern captures the name
#: itself.
#:
#: `sec-ch-ua-platform-version` is deliberately not consulted. It is only sent
#: when a server asks for it through Accept-CH, and its number is the *platform
#: release* rather than the marketing version - on Windows it reads "15.0.0"
#: for Windows 11, which would be a more precise way of being wrong than the
#: user-agent already is.
_SYSTEMS: tuple[tuple[re.Pattern, str | None], ...] = (
    # A native client naming its OS outright: `WhatsApp/2.26.30.78 iOS/16.7.12
    # Device/iPhone_8_Plus`. The most precise form there is - an app reports
    # the real point release, where a browser has frozen or rounded it.
    (re.compile(r"\b(iOS|iPadOS|Android|Windows|macOS)/(\d[\d._]*)"), None),
    # Apple's browsers: `CPU iPhone OS 18_5 like Mac OS X`, and `CPU OS 16_7`
    # on an iPad.
    (re.compile(r"CPU (?:iPhone )?OS (\d[\d_]*) like Mac OS X"), "iOS"),
    (re.compile(r"Mac OS X (\d[\d_]*)"), "macOS"),
    (re.compile(r"\bAndroid (\d[\d.]*)"), "Android"),
    # Reported as the user-agent spells it rather than translated: NT 10.0 is
    # Windows 10 *and* 11, since Chrome freezes it at 10.0 for both.
    (re.compile(r"\bWindows NT (\d[\d.]*)"), "Windows NT"),
)


#: Tokens a browser sends whatever the device runs. Reading a version out of
#: one measures the freeze and not the phone, so it is not read at all: Chrome
#: reduced its Android token in 110 and has sent this exact string - down to
#: the `K` where the model used to be - on every Android device since. A real
#: Android 10 running an older Chrome says `Android 10; SM-G973F`, so matching
#: the whole frozen string leaves that one readable.
_FROZEN = ("Android 10; K",)

#: Safari's own version, `Version/26.0`. On iOS it is the OS version - every
#: capture in this repository agrees, 18.0 through 18.6 - which makes it the
#: way past a frozen Apple token. See _unfrozen().
_SAFARI_VERSION = re.compile(r"\bVersion/(\d[\d.]*)")


def _major(version: str) -> int:
    return int(version.partition(".")[0])


def _unfrozen(name: str, version: str, user_agent: str) -> str:
    """The OS version, corrected where Apple's token has stopped advancing.

    Apple freezes these tokens rather than dropping them: every Mac has
    claimed `Mac OS X 10_15_7` since Big Sur, and since iOS 26 every iPhone
    claims `CPU iPhone OS 18_6`. The two captures in ../captures are the
    measurement - an iOS 18.6 phone and an iOS 26.0 phone send a byte-identical
    OS token and are told apart by `Version/` alone, 18.6 against 26.0.

    Safari's version is what corrects it because on iOS the two have always
    been the same number; 18.0, 18.1, 18.2, 18.4 and 18.6 each sent a matching
    `Version/`. Where the token is not behind it is the better of the two - an
    iOS 18.3.1 device sends `CPU iPhone OS 18_3_1` against `Version/18.3` - so
    Safari wins only when its major is higher, which is exactly the frozen
    case.

    macOS gets the same treatment only from 26. Safari 18 ran on macOS 15 and
    Safari 17 on macOS 14, so below 26 the two numbers are unrelated and
    Safari's says nothing about the system underneath; the frozen 10.15.7 is
    left to stand as what the machine itself claimed.
    """
    found = _SAFARI_VERSION.search(user_agent)
    if found is None or name not in ("iOS", "iPadOS", "macOS"):
        return version
    safari = found.group(1)
    if _major(safari) <= _major(version):
        return version
    if name == "macOS" and _major(safari) < 26:
        return version
    return safari


def system_of(headers: dict[str, str]) -> str | None:
    """The client's operating system and version, as it reports them.

    None when nothing in the request says - which is an answer too, and a
    common one: `Android 10; K` is what every Chrome since 110 sends whatever
    the device runs, and a client that sends no user-agent at all says nothing
    here either.

    What a client says is not always what it runs, and where that is known the
    known part is corrected rather than repeated - see _unfrozen(). An iPhone
    on iOS 26 reports its OS as 18.6, and reporting it back would make the one
    capture whose TLS layer changed look like the one whose did not.

    This needs a decoded request, so it exists only for a capture that got as
    far as HTTP/2. A connection that stopped at the ClientHello still has a
    fingerprint and no idea whose it is.
    """
    user_agent = headers.get("user-agent", "")
    if any(token in user_agent for token in _FROZEN):
        return None
    for pattern, spelling in _SYSTEMS:
        found = pattern.search(user_agent)
        if not found:
            continue
        name = spelling or found.group(1)
        version = found.group(2 if spelling is None else 1).replace("_", ".")
        return f"{name} {_unfrozen(name, version, user_agent)}"
    return None


def _platform(headers: dict[str, str], user_agent: str) -> str:
    """`sec-ch-ua-platform` when the browser sends it, else read off the UA."""
    if "sec-ch-ua-platform" in headers:
        return headers["sec-ch-ua-platform"].strip('"')
    for token, name in (("Android", "Android"), ("iPhone", "iOS"), ("iPad", "iOS"),
                        ("Windows", "Windows"), ("Macintosh", "macOS"),
                        ("CrOS", "Chrome OS"), ("Linux", "Linux")):
        if token in user_agent:
            return name
    return "unknown"


#: How the HPACK encoder behaves.  Not derivable from a capture - the bytes tell
#: you whether a guess was right, they do not tell you the rule - so it is
#: guessed from the user-agent and overridable per capture with
#: `{"meta": {"hpack": "..."}}`.  A wrong guess costs nothing but a failing
#: byte-level self-test, which is exactly where it should show up.
_HPACK_ENGINES = ("quiche", "cfnetwork", "stock")


def _hpack_engine(meta: dict, browser: str, platform: str = "") -> str:
    engine = meta.get("hpack")
    if engine is None:
        # Apple's stack first: it is decided by the OS and not by the client,
        # so the user-agent is no guide at all - a WhatsApp capture and a
        # Safari capture off one iPhone encode identically and share nothing
        # in their product tokens.
        if platform == "iOS":
            return "cfnetwork"
        # Every Chromium fork ships quiche; nothing else does.
        return "quiche" if browser not in ("Firefox", "unknown") else "stock"
    if engine not in _HPACK_ENGINES:
        msg = f"unknown hpack engine {engine!r}, expected one of {_HPACK_ENGINES}"
        raise ValueError(msg)
    return engine


class Profile:
    """One captured browser: its wire behaviour and the metadata that goes with it.

    Read-only as far as the capture goes.  The two attributes that are *not*
    part of the capture - `header_profile` and `default_headers` - are knobs,
    because they depend on what the user is
    doing rather than on which browser they are pretending to be.  Changing one
    affects every transport built from this profile, live connections included.
    """

    def __init__(self, cap: dict, source: str) -> None:
        self.brand: str = cap["brand"]
        self.source = source
        self.captured_at: str | None = cap["captured_at"]

        #: {kind: the HEADERS-frame priority that request carried, or None}.
        #: Read straight out of the capture - `navigate` from its first HEADERS
        #: frame, `xhr` from the page's own /xhr-sample if the probe caught
        #: one. Nothing else is stored per brand any more; what an outside
        #: service made of the same browser is asked live, by verify_fp.
        self.captured_priorities: dict[str, dict | None] = {
            "navigate": dict(cap["priority"]) if cap["priority"] else None,
            "xhr": (dict(cap["xhr"]["priority"])
                    if cap.get("xhr") and cap["xhr"].get("priority") else None),
        }

        #: Request headers as captured, pseudo-headers excluded, in wire order.
        self.headers: list[tuple[str, str]] = list(cap["headers"])
        self.header_map: dict[str, str] = dict(self.headers)

        self.user_agent = self.header_map.get("user-agent", "")
        self.browser, self.version = _product(self.user_agent)
        self.platform = _platform(self.header_map, self.user_agent)
        self.hpack = _hpack_engine(cap["meta"], self.browser, self.platform)

        #: Whether the captured ClientHello offered a session_ticket extension,
        #: or None if the capture had no ClientHello. Reference data, like
        #: `captured_priority()` - what the transport actually sends is
        #: `session_ticket_override` and the OpenSSL profile behind it.
        self.captured_session_ticket: bool | None = cap.get("session_ticket")

        #: Which OpenSSL fingerprint profile this brand's ClientHello wants.
        #: Defaults to the brand, so a capture needs no extra field; override
        #: with `{"meta": {"tls_profile": "..."}}` when several brands share one
        #: TLS stack (every Chromium fork does) and only one profile exists for
        #: them in ssl/ssl_fp_profile.c.
        self.tls_profile: str = cap["meta"].get("tls_profile") or self.brand

        #: The capture file's own `meta` object, verbatim. Three of its keys
        #: are acted on - `hpack`, `tls_profile` and `label`, each read where
        #: it is used - and anything else a capture carries is kept here and
        #: surfaced through `meta` below: which device it came from, why it was
        #: taken, whatever the person who made it knew and the bytes do not
        #: say. A field nothing reads is still a field somebody wrote down.
        self.stored_meta: dict = dict(cap["meta"])

        #: What listings call this profile. Derived here rather than stored in
        #: the capture, like everything else a capture can say about itself:
        #: `{"meta": {"label": "..."}}` still wins, but a stored label freezes
        #: one reading of the user-agent into the file, where a derived one
        #: improves for every capture already on disk when the reading does -
        #: which it just did, see system_of().
        #:
        #: An Apple capture is named for the OS and not for the client, the way
        #: the profiles themselves are: the ClientHello and the HPACK encoder
        #: belong to CFNetwork, so Safari, WhatsApp and the App Store on one
        #: phone are one stack behind three product tokens, and calling this
        #: one "Safari 604" would name the one part of it that is not being
        #: imitated. Everything else is named for the browser, where the stack
        #: does ship with the browser.
        system = system_of(self.header_map)
        self.label: str = cap["meta"].get("label") or (
            f"{system} network stack" if system and self.platform == "iOS"
            else f"{self.browser} {self.version.split('.')[0]} on {self.platform}")

        # --- the four fields the akamai fingerprint is computed from ---

        #: SETTINGS in wire order. Both the ids present and their order are
        #: fingerprint material, so this stays a list of pairs, never a dict.
        self.settings: list[tuple[int, int]] = list(cap["settings"])

        #: Connection-level WINDOW_UPDATE; 0 means the client sent none.
        self.window_update: int = cap["window_update"]

        self.pseudo_order: tuple[str, ...] = tuple(cap["pseudo_order"])
        if set(self.pseudo_order) != set(_PSEUDO_DEFAULT):
            warnings.warn(
                f"browser_fp: {self.brand} has pseudo-headers "
                f"{list(self.pseudo_order)}, expected {list(_PSEUDO_DEFAULT)}; "
                f"only those four can be reproduced, so the standard order is "
                f"used instead", RuntimeWarning, stacklevel=3)
            self.pseudo_order = _PSEUDO_DEFAULT

        self.priority_frames: int = cap["priority_frames"]
        if self.priority_frames:
            warnings.warn(
                f"browser_fp: {self.brand} contains {self.priority_frames} "
                f"standalone PRIORITY frame(s), which are not reproduced - the "
                f"third field of its akamai fingerprint will not match",
                RuntimeWarning, stacklevel=3)

        #: RFC 7540 priority carried on the HEADERS frame, or {} if the capture
        #: had none. h2 takes the human-readable 1..256 weight, subtracts one
        #: for the wire byte, and sets the PRIORITY flag for us.
        prio = cap["priority"]
        self.headers_priority: dict[str, typing.Any] = (
            {
                "priority_exclusive": prio["exclusive"],
                "priority_depends_on": prio["depends_on"],
                "priority_weight": prio["weight"],
            }
            if prio else {}
        )

        self.akamai_fingerprint = "|".join([
            ";".join(f"{sid}:{value}" for sid, value in self.settings),
            str(self.window_update),
            "0",                       # standalone PRIORITY frames, never sent
            ",".join(name[1] for name in self.pseudo_order),
        ])
        self.akamai_hash = hashlib.md5(  # noqa: S324 - akamai defines it as md5
            self.akamai_fingerprint.encode("ascii"),
            usedforsecurity=False).hexdigest()

        # --- knobs ---

        #: Which captured request `captured_priority()` and `describe()`
        #: report by default. It no longer changes what goes on the wire -
        #: headers and priority are the caller's - so it is a lookup key, not
        #: a mode.
        self.header_profile = "navigate"

        #: Whether the HEADERS frame carries an RFC 7540 priority, overriding
        #: what the capture did. Three states, because "send none" and "no
        #: measurement" are different things:
        #:
        #:   FROM_CAPTURE  reproduce the capture, per kind (the default)
        #:   None          never set the PRIORITY flag
        #:   {"exclusive": bool, "depends_on": int, "weight": int}
        #:
        #: This is not a header and no caller can reach it through httpx, so
        #: unlike header values it stays the library's to set - the override is
        #: for measuring, and for a request kind the capture never covered.
        self.priority_override: typing.Any = FROM_CAPTURE

        #: Headers the caller wants on every request through this transport,
        #: as `Transport(brand, headers=...)`. Empty by default, because the
        #: library sets no values of its own - see `_build_headers`. Set it to
        #: `self.headers` to send exactly what the capture contained, which is
        #: what selftest does and the only way the HPACK bytes can match it.
        self.default_headers: list[tuple[bytes, bytes]] = []

        #: When True, `_build_headers` keeps every request header verbatim
        #: instead of dropping the ones whose (name, value) equals an httpx
        #: auto-default. Only safe when the caller has taken full control of the
        #: header list - e.g. after overwriting `request.headers` - because
        #: otherwise httpx's own `user-agent: python-httpx` etc. would survive.
        #: It exists so an explicit `accept: */*` (indistinguishable from
        #: httpx's default by value) can be sent at the position the caller put
        #: it, which the value-strip otherwise makes impossible.
        self.raw_headers: bool = False

        #: Whether the ClientHello offers an empty session_ticket extension,
        #: overriding the OpenSSL profile. `FROM_CAPTURE` leaves the profile's
        #: own answer alone; True and False pin it.
        #:
        #: Here rather than in the profile data because it is not the network
        #: stack's to decide, which is unusual for a TLS extension and was
        #: measured rather than assumed: on one iOS 16.7.12 device the App
        #: Store's amp-api and xp.apple.com connections offer it and the same
        #: device's mzstatic, fpinit and weather-edge connections do not. Same
        #: OS, same ciphers, same groups, same HTTP/2 fingerprint - and a JA4
        #: extension count of 15 against 14, with a different extension hash.
        self.session_ticket_override: typing.Any = FROM_CAPTURE

        self._classes: dict[typing.Any, type] = {}

    def __copy__(self) -> Profile:
        """A copy with its own class cache, which is the whole point of it.

        Every transport copies its profile so that `headers=`, `priority=` and
        `header_profile` stay local to it. But the generated pool and
        connection classes hold `_PROFILE` on the class, and they are cached in
        `_classes` - share that dict and the first transport's profile is baked
        into classes every later one reuses, so its overrides silently win.
        Sharing the attributes and not the cache is worse than not copying at
        all, because the copy looks isolated when inspected.
        """
        clone = object.__new__(type(self))
        clone.__dict__.update(self.__dict__)
        clone._classes = {}
        return clone

    def __repr__(self) -> str:
        return f"<Profile {self.brand}: {self.label}>"

    def captured_priority(self, kind: str = "navigate") -> dict | None:
        """The HEADERS-frame priority the capture carried, or None for none.

        Reference data, not a default. Measured on one iPhone: Safari puts a
        priority on its navigation and none on its XHRs, WhatsApp puts none on
        any of seven requests - same iOS, same network stack. So this belongs
        to the client and the request, not to the stack the profile describes,
        and reproducing it is the caller's to ask for:

            fp.Transport("ios18",
                         headers=prof.headers,
                         priority=prof.captured_priority())
        """
        prio = self.captured_priorities.get(kind)
        return dict(prio) if prio else None

    def priority_for(self) -> dict:
        """What to pass send_headers(), which is nothing unless asked.

        An empty dict leaves the PRIORITY flag off the HEADERS frame - the
        default, because a priority is a property of the client and of the
        request rather than of the network stack. `captured_priority()` says
        what the capture did; `Transport(priority=...)` is how to send it.
        """
        if self.priority_override is None or self.priority_override == FROM_CAPTURE:
            return {}
        return {
            "priority_exclusive": bool(self.priority_override["exclusive"]),
            "priority_depends_on": self.priority_override["depends_on"],
            "priority_weight": self.priority_override["weight"],
        }

    @property
    def meta(self) -> dict:
        """Everything about the captured browser that is not wire behaviour.

        Derived first, then whatever else the capture's own `meta` carried -
        `{"meta": {"device": "iPhone 8 Plus"}}` reads back as
        `profile(...).meta["device"]`. Derived wins on a collision: a stored
        `label` is already here as the effective one, and a stored `platform`
        must not overwrite what was read off the wire. `stored_meta` is the
        unmixed version, for a caller that wants to know which is which.
        """
        derived = {
            "brand": self.brand,
            "label": self.label,
            "browser": self.browser,
            "version": self.version,
            "platform": self.platform,
            "user_agent": self.user_agent,
            "sec_ch_ua": self.header_map.get("sec-ch-ua", ""),
            "accept": self.header_map.get("accept", ""),
            "accept_encoding": self.header_map.get("accept-encoding", ""),
            "accept_language": self.header_map.get("accept-language", ""),
            "sec_fetch_mode": self.header_map.get("sec-fetch-mode", ""),
            "hpack": self.hpack,
            "tls_profile": self.tls_profile,
            "akamai_fingerprint": self.akamai_fingerprint,
            "akamai_hash": self.akamai_hash,
            "source": self.source,
            "captured_at": self.captured_at,
        }
        for key, value in self.stored_meta.items():
            derived.setdefault(key, value)
        return derived

    @property
    def class_name(self) -> str:
        """The synthesised transport class name, e.g. chrome_android -> ChromeAndroid."""
        return _class_name(self.brand)


def _class_name(brand: str) -> str:
    parts = re.split(r"[^0-9A-Za-z]+", brand)
    return "".join(p[:1].upper() + p[1:] for p in parts if p)


# --- the registry -----------------------------------------------------------

#: brand -> Profile, one entry per capture in PROFILES_DIR. Populated at import
#: and by reload(); nothing in this module is written for a particular brand.
PROFILES: dict[str, Profile] = {}


def reload() -> dict[str, Profile]:
    """Rescan PROFILES_DIR. Call after capturing without restarting Python."""
    PROFILES.clear()
    if not PROFILES_DIR.is_dir():
        warnings.warn(
            f"browser_fp: {PROFILES_DIR} does not exist, so no browser profiles "
            f"are installed; capture one with "
            f"`mytls-probe serve --brand <name>`",
            RuntimeWarning, stacklevel=2)
        return PROFILES

    for path in sorted(PROFILES_DIR.glob("*.json")):
        try:
            prof = Profile(_read_capture(path), str(path))
        except Exception as exc:  # noqa: BLE001 - one bad file must not hide the rest
            warnings.warn(f"browser_fp: ignoring {path} ({type(exc).__name__}: {exc})",
                          RuntimeWarning, stacklevel=2)
            continue
        if prof.brand in PROFILES:
            warnings.warn(
                f"browser_fp: {path} is brand {prof.brand!r}, which "
                f"{PROFILES[prof.brand].source} already claims; keeping the "
                f"first", RuntimeWarning, stacklevel=2)
            continue
        PROFILES[prof.brand] = prof
    return PROFILES


reload()


def brands() -> list[str]:
    return sorted(PROFILES)


def profile(brand: str | None = None) -> Profile:
    """The named profile, or the default one - see DEFAULT_BRAND."""
    if brand is None:
        brand = DEFAULT_BRAND
    if brand is None:
        if len(PROFILES) == 1:
            return next(iter(PROFILES.values()))
        if not PROFILES:
            msg = (f"no browser profiles in {PROFILES_DIR}; capture one with "
                   f"`mytls-probe serve --brand <name>`")
            raise LookupError(msg)
        msg = (f"several profiles are installed ({', '.join(brands())}) and no "
               f"default is set, so the brand has to be named: "
               f"transport('<brand>'), or set browser_fp.DEFAULT_BRAND / "
               f"BROWSER_FP_BRAND")
        raise LookupError(msg)
    try:
        return PROFILES[brand]
    except KeyError:
        msg = (f"unknown brand {brand!r}; installed: "
               f"{', '.join(brands()) or '(none)'} (from {PROFILES_DIR})")
        raise LookupError(msg) from None


# --- request headers --------------------------------------------------------

#: Marks where headers the caller supplied get spliced in.  Browsers put cookie
#: and referer here, between `accept` and the sec-fetch block.

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


def _check_priority(value: typing.Any) -> typing.Any:
    """Validate `Transport(priority=...)` at construction rather than on send.

    Getting this wrong is silent otherwise - a stray key would just fall
    through to a KeyError inside the connection, on the first request, in
    whichever thread happened to make it.
    """
    if value is None or value is FROM_CAPTURE or value == FROM_CAPTURE:
        return value
    wanted = {"exclusive", "depends_on", "weight"}
    if not isinstance(value, dict) or set(value) != wanted:
        msg = (f"priority must be {FROM_CAPTURE!r} (reproduce the capture), "
               f"None (never send a PRIORITY flag), or a dict with exactly "
               f"{sorted(wanted)}; got {value!r}")
        raise ValueError(msg)
    if not 1 <= value["weight"] <= 256:
        msg = (f"priority weight is 1..256 as RFC 7540 counts it - the wire "
               f"carries it minus one - got {value['weight']!r}")
        raise ValueError(msg)
    return value


def _check_session_ticket(value: typing.Any) -> typing.Any:
    """Validate `Transport(session_ticket=...)`, for the same reason.

    Deliberately strict about 0 and 1 not being accepted as booleans: this is a
    three-state setting and `session_ticket=0` reads like "off" while meaning
    it only by accident.
    """
    if value is FROM_CAPTURE or value == FROM_CAPTURE or isinstance(value, bool):
        return value
    msg = (f"session_ticket must be {FROM_CAPTURE!r} (leave the OpenSSL profile "
           f"alone), True (always offer an empty session_ticket) or False "
           f"(never offer one); got {value!r}")
    raise ValueError(msg)


def _as_header_pairs(headers: typing.Any) -> list[tuple[bytes, bytes]]:
    """Normalise `Transport(headers=...)` into lowercase byte pairs.

    Accepts what httpx accepts - a mapping or a sequence of pairs, str or
    bytes - because that is what a caller will reach for. Order is kept: two
    values for one name stay in the order given, which `cookie` and
    `set-cookie` both depend on.
    """
    items = headers.items() if hasattr(headers, "items") else headers
    out: list[tuple[bytes, bytes]] = []
    for key, value in items:
        k = key.encode("ascii") if isinstance(key, str) else bytes(key)
        v = value.encode("utf-8") if isinstance(value, str) else bytes(value)
        out.append((k.lower(), v))
    return out


#: Never forwarded: `host` becomes :authority, the rest are HTTP/1-only hop
#: headers that h2 would strip anyway.
_DROP = frozenset(
    [b"host", b"transfer-encoding", b"connection", b"keep-alive", b"upgrade"],
)


def _build_headers(prof: Profile, request: typing.Any) -> list[tuple[bytes, bytes]]:
    """This request's headers: the caller's, in the caller's order.

    A profile carries only what belongs to the *network stack* - the thing
    that changes with the OS or browser version and that no caller can reach
    through httpx: the pseudo-header order, the HPACK encoding, the SETTINGS,
    the WINDOW_UPDATE and the TLS layer.

    Request headers are not that.  Measured on one iPhone, one iOS version and
    one network stack, Safari and WhatsApp sent different header sets in
    different orders - and WhatsApp's own GET and POST disagreed with each
    other too.  So neither the set, the order nor the values are a property of
    the stack, and imposing any of them would stop the caller reproducing a
    request that is not the one we happened to capture.

    Order therefore comes from the caller, who controls it by the order they
    pass headers in - httpx preserves it, for a dict as for a list of pairs.
    `Transport(headers=...)` comes first, then the request's own, matching how
    httpx layers client-level and request-level headers.  To reproduce the
    captured client exactly, pass `profile.headers`, which is that order.
    """
    # :authority comes from the host header when there is one - httpx/httpcore
    # put it there from the URL. A caller who has replaced the whole header list
    # (send_exact) may have left it out, so fall back to the request URL; still
    # pass host explicitly when the connection target and the authority differ
    # (e.g. dialing an IP but presenting a hostname).
    host = [v for k, v in request.headers if k.lower() == b"host"]
    if host:
        authority = host[0]
    else:
        u = request.url
        default_port = b"443" if u.scheme == b"https" else b"80"
        port = b"" if u.port is None or str(u.port).encode() == default_port \
            else b":" + str(u.port).encode()
        authority = u.host + port

    defaults = set() if prof.raw_headers else _httpx_default_headers()
    supplied: list[tuple[bytes, bytes]] = []
    for key, value in request.headers:
        key = key.lower()
        # `_DROP` stays even in raw mode: host becomes :authority and the rest
        # are HTTP/1 hop headers that h2 forbids. Only the httpx-default
        # value-strip is what `raw_headers` turns off.
        if key in _DROP or (key, value) in defaults:
            continue
        supplied.append((key, value))

    # Transport(headers=...) is the caller speaking too, and it has to be kept
    # apart from httpx's own defaults above: the captured `accept-encoding` is
    # byte-identical to httpx's, so passing it on the request would be mistaken
    # for httpx having put it there and dropped.  A name the request sets again
    # keeps the transport's position and takes the request's value, which is
    # what overriding one header out of a set is normally meant to do.
    if prof.default_headers:
        override = {k: v for k, v in supplied}
        seen: set[bytes] = set()
        merged = []
        for key, value in prof.default_headers:
            merged.append((key, override.get(key, value)))
            seen.add(key)
        merged += [(k, v) for k, v in supplied if k not in seen]
        supplied = merged

    pseudo = {
        ":method": request.method,
        ":authority": authority,
        ":scheme": request.url.scheme,
        ":path": request.url.target,
    }
    headers: list[tuple[bytes, bytes]] = [
        (name.encode("ascii"), pseudo[name]) for name in prof.pseudo_order
    ]
    headers += supplied

    # cfnetwork is in here on weaker evidence than quiche is: App Store
    # captures taken on an iOS 16.7.12 device carried ten and eleven *separate*
    # `cookie` fields in one HEADERS block, which is a crumbled cookie and
    # nothing else. Those dumps are no longer in the tree and the current
    # capture set has no cookies at all, so it cannot be re-derived from what
    # is here - re-capture a request with cookies before trusting it.
    if prof.hpack in ("quiche", "cfnetwork"):
        headers = _crumble_cookies(headers)
    return headers


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


# --- the HTTP/2 wire layer --------------------------------------------------

def _settings_class(prof: Profile) -> type:
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
    ids = [sid for sid, _ in prof.settings]

    class _Settings(h2.settings.Settings):
        def __iter__(self) -> typing.Iterator[int]:
            return iter(ids)

        def __len__(self) -> int:
            return len(ids)

    return _Settings


class _QuicheEncoder(hpack.Encoder):
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


#: Only quiche's rules are implemented; "stock" is hpack's own encoder, which is
#: what a non-Chromium capture gets until someone works out its real rules. The
#: byte-level self-test is what tells you whether that is good enough.
class _CFNetworkEncoder(_QuicheEncoder):
    """quiche's rules, plus two names that are treated differently.

    Apple's stack and Chrome's agree on everything else measured here -
    conditional Huffman, pseudo-headers other than `:authority` kept out of the
    dynamic table - which is why this subclasses rather than repeats. The two
    differences are `content-length` (kept out of the table) and
    `authorization` (emitted with the never-indexed opcode, which quiche never
    emits at all).

    Measured against 37 requests over 34 connections captured from WhatsApp on
    one iOS 16.7.12 device:

        stock hpack     0/37
        quiche          3/37    the three GETs, which carry no content-length
        this           36/37

    Neither rule is cosmetic. `content-length` decides most blocks outright.
    `authorization` decides more than its own field: indexing it adds a dynamic
    entry the real client never adds, so every index in every later request on
    that connection comes out one too high - one connection here carries four
    requests and the first mistake corrupts the other three.

    The rules generalise past the app that revealed them: the same encoder
    reproduces the stored Safari capture, navigation and xhr alike, so this
    belongs to iOS and not to WhatsApp - which is what every other measurement
    on this device also found.

    Chrome is deliberately left on quiche. Every Chrome capture in the tree is
    a GET without an `authorization`, so none of them says what quiche does
    with either name, and quiche's own source is the better authority where no
    measurement exists.

    The one remaining miss is not an encoding rule. On the second request of
    that four-request connection the client opens the block with a dynamic
    table size update to 4096 - the value the server had just advertised, and
    also the default, so hpack considers it unchanged and emits nothing. Strip
    those three bytes and the remaining 135 are identical. It is an
    acknowledgement of the peer's SETTINGS rather than a choice about how to
    encode, and in a live connection h2 owns that decision, so nothing is done
    about it here.
    """

    #: Kept out of the dynamic table with an ordinary non-indexed literal. Its
    #: value is different on every request that has one, so an entry made for
    #: it can never be hit again - it would only push something reusable out of
    #: a 4KB table.
    _NOT_INDEXED = frozenset({b"content-length"})

    #: Emitted with the *never-indexed* opcode, which additionally forbids any
    #: proxy along the way from indexing it. quiche never emits this opcode at
    #: all; Apple's stack does, for exactly one name in everything measured
    #: here. Getting it wrong is not a one-field mistake: indexing
    #: `authorization` adds a dynamic entry the real client never adds, so
    #: every index in every later request on that connection is off by one.
    _NEVER_INDEXED = frozenset({b"authorization"})

    @classmethod
    def _chrome_should_index(cls, name: bytes) -> bool:
        if name in cls._NOT_INDEXED:
            return False
        return _QuicheEncoder._chrome_should_index(name)

    def add(
        self,
        to_add: tuple[bytes, bytes],
        sensitive: bool,
        huffman: bool = False,
    ) -> bytes:
        name, value = to_add
        if name not in self._NEVER_INDEXED:
            return super().add(to_add, sensitive, huffman)
        # Never-indexed is always a literal: a match in the table would be
        # emitted as an index, which is the thing this opcode exists to avoid.
        match = self.header_table.search(name, value)
        if match is None:
            return self._encode_literal(name, value,
                                        hpack.hpack.INDEX_NEVER, huffman)
        position, name, _perfect = match
        return self._encode_indexed_literal(position, value,
                                            hpack.hpack.INDEX_NEVER, huffman)


_ENCODERS = {"quiche": _QuicheEncoder, "cfnetwork": _CFNetworkEncoder,
             "stock": hpack.Encoder}


def _apply_settings(prof: Profile, state: typing.Any) -> None:
    """Install the captured SETTINGS and make the HPACK decoder agree with them.

    h2 only pushes HEADER_TABLE_SIZE and MAX_HEADER_LIST_SIZE into the decoder
    when a *pending* settings change gets ACKed.  We hand it finished values, so
    nothing is pending and the decoder would quietly keep hpack's 4096-byte
    default while we advertise 64K.  Servers that take us at our word and use a
    bigger dynamic table - google.com does - then blow up with
    "Encoder exceeded max allowable table size" on the response headers.
    """
    codes = h2.settings.SettingCodes
    values = dict(prof.settings)
    settings_class = prof._classes.get("settings")
    if settings_class is None:
        settings_class = prof._classes["settings"] = _settings_class(prof)

    state.local_settings = settings_class(
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
    # encodes the way this browser does. Safe here because nothing has been
    # encoded on this connection yet, so the dynamic table is empty either way.
    state.encoder = _ENCODERS[prof.hpack]()


class _ProfileHTTP2Connection(_sync_mod.HTTP2Connection):
    """httpcore's HTTP/2 connection, sending what _PROFILE captured."""

    _PROFILE: typing.ClassVar[Profile]

    def _send_connection_init(self, request: typing.Any) -> None:
        prof = self._PROFILE
        _apply_settings(prof, self._h2_state)
        self._h2_state.initiate_connection()
        if prof.window_update:
            self._h2_state.increment_flow_control_window(prof.window_update)
        self._write_outgoing_data(request)

    def _send_request_headers(self, request: typing.Any, stream_id: int) -> None:
        prof = self._PROFILE
        end_stream = not _sync_mod.has_body_headers(request)
        self._h2_state.send_headers(
            stream_id,
            _build_headers(prof, request),
            end_stream=end_stream,
            **prof.priority_for(),
        )
        # No per-stream WINDOW_UPDATE here: the stream window is advertised in
        # SETTINGS, which is what browsers rely on. h2's flow control manager
        # tops the window up as the response is consumed.
        self._write_outgoing_data(request)


class _AsyncProfileHTTP2Connection(_async_mod.AsyncHTTP2Connection):
    """Async twin of _ProfileHTTP2Connection."""

    _PROFILE: typing.ClassVar[Profile]

    async def _send_connection_init(self, request: typing.Any) -> None:
        prof = self._PROFILE
        _apply_settings(prof, self._h2_state)
        self._h2_state.initiate_connection()
        if prof.window_update:
            self._h2_state.increment_flow_control_window(prof.window_update)
        await self._write_outgoing_data(request)

    async def _send_request_headers(
        self, request: typing.Any, stream_id: int,
    ) -> None:
        prof = self._PROFILE
        end_stream = not _async_mod.has_body_headers(request)
        self._h2_state.send_headers(
            stream_id,
            _build_headers(prof, request),
            end_stream=end_stream,
            **prof.priority_for(),
        )
        await self._write_outgoing_data(request)


def _http2_class(prof: Profile, is_async: bool) -> type:
    """The HTTP/2 connection class bound to this profile, built once."""
    key = ("http2", is_async)
    cls = prof._classes.get(key)
    if cls is None:
        base = _AsyncProfileHTTP2Connection if is_async else _ProfileHTTP2Connection
        name = f"{'Async' if is_async else ''}{prof.class_name}HTTP2Connection"
        cls = prof._classes[key] = type(name, (base,), {"_PROFILE": prof})
    return cls


def _connection_class(prof: Profile, cls: type, is_async: bool) -> type:
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
    freshly-built HTTP/2 connection as ours. Sound because the subclass adds no
    state and no __init__, and nothing has gone out yet - the HTTP/2 preface is
    sent on the first handle_request(), which is after this point.

    The pay-off is that none of httpcore's connection logic is copied here, so
    proxy and SOCKS connections keep working unchanged and an httpcore upgrade
    cannot leave a stale copy of their internals behind.
    """
    key = ("conn", cls, is_async)
    variant = prof._classes.get(key)
    if variant is not None:
        return variant

    stock = _async_mod.AsyncHTTP2Connection if is_async else _sync_mod.HTTP2Connection
    ours = _http2_class(prof, is_async)

    def _get(self: typing.Any) -> typing.Any:
        # The classes assign None in __init__, so it is already in the instance
        # dict by the time we retag; read from there to keep their semantics.
        return self.__dict__.get("_connection")

    def _set(self: typing.Any, conn: typing.Any) -> None:
        if type(conn) is stock:
            conn.__class__ = ours
        self.__dict__["_connection"] = conn

    variant = prof._classes[key] = type(
        f"{prof.class_name}{cls.__name__}", (cls,),
        {"_connection": property(_get, _set)})
    return variant


class _PoolMixin:
    """Layered over whichever pool httpx built, so its own routing survives.

    A proxy pool's create_connection() is what knows how to reach the proxy, so
    it must not be replaced - only wrapped. Everything the pool hands out gets
    retagged on the way past, no matter which class it is.
    """

    _PROFILE: typing.ClassVar[Profile]
    _ASYNC: typing.ClassVar[bool]

    def create_connection(self, origin: typing.Any) -> typing.Any:
        conn = super().create_connection(origin)  # type: ignore[misc]
        conn.__class__ = _connection_class(self._PROFILE, type(conn), self._ASYNC)
        return conn


_warned_versions = False


def _check_versions() -> None:
    """Warn once if the libraries are not the ones this was written against."""
    global _warned_versions
    if _warned_versions:
        return
    _warned_versions = True

    import h2 as _h2
    import hpack as _hpack
    import httpcore as _httpcore
    import httpx as _httpx

    actual = {
        "httpx": _httpx.__version__,
        "httpcore": _httpcore.__version__,
        "h2": _h2.__version__,
        "hpack": _hpack.__version__,
    }
    off = {k: v for k, v in actual.items() if v not in _EXPECTED[k]}
    if off:
        detail = ", ".join(f"{k} {v} (tested: {', '.join(_EXPECTED[k])})"
                           for k, v in off.items())
        warnings.warn(
            f"browser_fp subclasses library internals and has only been run "
            f"against {detail}. Re-check httpcore's handle_request, "
            f"create_connection, _send_connection_init and _send_request_headers, "
            f"and hpack's Encoder internals, before trusting the fingerprint. "
            f"`mytls-probe selftest` answers it as bytes and needs no network.",
            RuntimeWarning,
            stacklevel=3,
        )


def _retag_pool(transport: typing.Any, prof: Profile, is_async: bool) -> None:
    """Layer the pool mixin onto whatever pool the transport built.

    Retagging the instance rather than constructing our own pool: the mixin adds
    no state, while rebuilding would mean mirroring the dozen arguments httpx
    passes - and re-mirroring them on every httpx release. Building the subclass
    from the pool's *actual* type is what keeps proxies working: HTTPProxy and
    SOCKSProxy are ConnectionPool subclasses with their own create_connection,
    and the mixin's super() call goes to theirs.
    """
    _check_versions()
    base = httpcore.AsyncConnectionPool if is_async else httpcore.ConnectionPool
    pool = transport._pool
    if not isinstance(pool, base):
        warnings.warn(
            f"browser_fp: the transport built a {type(pool).__name__}, which is "
            f"not a {base.__name__}; leaving its HTTP/2 layer alone, so the "
            f"akamai fingerprint will NOT match.",
            RuntimeWarning, stacklevel=3)
        return

    key = ("pool", type(pool), is_async)
    variant = prof._classes.get(key)
    if variant is None:
        variant = prof._classes[key] = type(
            f"{prof.class_name}{type(pool).__name__}",
            (_PoolMixin, type(pool)),
            {"_PROFILE": prof, "_ASYNC": is_async})
    pool.__class__ = variant


def _tls_state(prof: Profile) -> str:
    """What the TLS layer would do for this brand, for `describe()`.

    Says so plainly when OpenSSL has no matching profile, because that is the
    case where the two layers disagree and nothing else on screen shows it.
    """
    try:
        known = tls_profile.available()
    except tls_profile.Unavailable as exc:
        return f"{prof.tls_profile} - UNAVAILABLE ({exc.args[0].split('.')[0]})"
    if prof.tls_profile not in known:
        return (f"{prof.tls_profile} - NOT IN OpenSSL ({', '.join(known)}); "
                f"the ClientHello will be the default one")
    return prof.tls_profile


def _ticket_state(prof: Profile) -> str:
    """Whether an empty session_ticket goes out, for `describe()`.

    The capture is reported alongside the setting, because the two answer
    different questions: what this transport will send, and what the device
    that was recorded sent. A brand whose capture is not in the reference at
    all says so rather than guessing.
    """
    seen = prof.captured_session_ticket
    measured = ("not recorded" if seen is None else
                "the capture offered one" if seen else
                "the capture offered none")
    if prof.session_ticket_override is FROM_CAPTURE:
        return f"whatever the OpenSSL profile does ({measured})"
    return (f"{'always offered' if prof.session_ticket_override else 'never offered'}"
            f" - set on the transport ({measured})")


def _apply_tls_profile(transport: typing.Any, prof: Profile) -> str | None:
    """Point the transport's SSL_CTX at this brand's ClientHello.

    Per transport rather than per process: the profile lives on the SSL_CTX,
    httpx builds one per transport, and that is what lets one program hold a
    Chrome client and a Safari client at the same time. A context passed in by
    the caller and shared between two transports of different brands would be
    set twice and the last one would win - so give each transport its own, or
    accept that they agree.

    A missing profile is a warning, not an error: the HTTP/2 half of a brand is
    useful on its own, and several brands legitimately have no TLS profile yet.
    But it is a loud warning, because a client whose two layers disagree is
    more identifiable than one that never pretended at all.
    """
    context = getattr(getattr(transport, "_pool", None), "_ssl_context", None)
    if not isinstance(context, ssl.SSLContext):
        warnings.warn(
            f"browser_fp: the transport has no ssl.SSLContext to configure, so "
            f"its TLS layer is NOT {prof.brand}'s while its HTTP/2 layer is.",
            RuntimeWarning, stacklevel=3)
        return None

    try:
        tls_profile.set_profile(context, prof.tls_profile)
        # After the profile, never before: setting a profile does not clear
        # this override, but reading it back would report the old profile's
        # answer if the two were the other way round.
        if prof.session_ticket_override is not FROM_CAPTURE:
            tls_profile.set_empty_ticket(context, prof.session_ticket_override)
    except tls_profile.Unavailable as exc:
        # httpx has already built the SSLContext by now, so its NO_CIPHER_MATCH
        # residue is on the queue even when our own profile step fails; scrub
        # before returning so it cannot be misreported on a later read.
        tls_profile.clear_error_queue()
        warnings.warn(
            f"browser_fp: the TLS layer is NOT {prof.brand}'s - {exc} The "
            f"HTTP/2 layer still is, so the two halves disagree.",
            RuntimeWarning, stacklevel=3)
        return None
    # Construction is complete and synchronous: scrub the benign residue httpx's
    # SSL setup leaves under @SECLEVEL=2 (a NO_CIPHER_MATCH the fp profile's own
    # C-side mark/pop cannot reach, because httpx runs before set_profile) so it
    # cannot masquerade as a later connection's read failure. See
    # tls_profile.clear_error_queue.
    tls_profile.clear_error_queue()
    return prof.tls_profile


class Transport(httpx.HTTPTransport):
    """An httpx transport whose HTTP/2 layer looks like a captured browser's.

        import httpx, mytls

        with httpx.Client(transport=fp.Transport("chrome")) as client:
            client.get("https://example.com/")

    Takes everything httpx.HTTPTransport takes, `proxy` included; `brand` is
    keyword-or-first-positional and `http2` defaults to True.  Note that
    arguments like `verify` and `proxy` belong on the transport, not on the
    Client - httpx ignores its own when a transport is supplied:

        fp.Transport("chrome", proxy="http://127.0.0.1:8080")
    """

    #: Set on the synthesised per-brand subclasses; None means "the default".
    _BRAND: typing.ClassVar[str | None] = None
    _ASYNC: typing.ClassVar[bool] = False

    def __init__(self, brand: str | None = None, *,
                 headers: typing.Any = None,
                 priority: typing.Any = FROM_CAPTURE,
                 session_ticket: typing.Any = FROM_CAPTURE,
                 raw_headers: bool = False,
                 **kwargs: typing.Any) -> None:
        # A copy, not the shared Profile: `headers=`, `priority=`,
        # `session_ticket=` and `header_profile` are per-transport, and
        # mutating the one profile() hands out would leak them into every
        # transport of the same brand.
        self.profile = copy.copy(profile(brand if brand is not None
                                         else self._BRAND))
        if headers is not None:
            self.profile.default_headers = _as_header_pairs(headers)
        self.profile.priority_override = _check_priority(priority)
        self.profile.session_ticket_override = _check_session_ticket(session_ticket)
        self.profile.raw_headers = bool(raw_headers)
        kwargs.setdefault("http2", True)
        super().__init__(**kwargs)
        _retag_pool(self, self.profile, self._ASYNC)
        #: The OpenSSL profile actually in force, or None if it could not be
        #: set - so a caller can check rather than trust the warning was seen.
        self.tls_profile = _apply_tls_profile(self, self.profile)

    def __repr__(self) -> str:
        return f"<{type(self).__name__} {self.profile.brand}>"


class AsyncTransport(httpx.AsyncHTTPTransport):
    """Async twin of Transport, for httpx.AsyncClient."""

    _BRAND: typing.ClassVar[str | None] = None
    _ASYNC: typing.ClassVar[bool] = True

    def __init__(self, brand: str | None = None, *,
                 headers: typing.Any = None,
                 priority: typing.Any = FROM_CAPTURE,
                 session_ticket: typing.Any = FROM_CAPTURE,
                 raw_headers: bool = False,
                 **kwargs: typing.Any) -> None:
        # A copy, not the shared Profile: `headers=`, `priority=`,
        # `session_ticket=` and `header_profile` are per-transport, and
        # mutating the one profile() hands out would leak them into every
        # transport of the same brand.
        self.profile = copy.copy(profile(brand if brand is not None
                                         else self._BRAND))
        if headers is not None:
            self.profile.default_headers = _as_header_pairs(headers)
        self.profile.priority_override = _check_priority(priority)
        self.profile.session_ticket_override = _check_session_ticket(session_ticket)
        self.profile.raw_headers = bool(raw_headers)
        kwargs.setdefault("http2", True)
        super().__init__(**kwargs)
        _retag_pool(self, self.profile, self._ASYNC)
        #: The OpenSSL profile actually in force, or None if it could not be
        #: set - so a caller can check rather than trust the warning was seen.
        self.tls_profile = _apply_tls_profile(self, self.profile)

    def __repr__(self) -> str:
        return f"<{type(self).__name__} {self.profile.brand}>"


def transport(brand: str | None = None, **kwargs: typing.Any) -> Transport:
    """A sync transport for `brand`; same as Transport(brand, ...)."""
    return Transport(brand, **kwargs)


def async_transport(brand: str | None = None, **kwargs: typing.Any) -> AsyncTransport:
    """An async transport for `brand`; same as AsyncTransport(brand, ...)."""
    return AsyncTransport(brand, **kwargs)


#: `send()` takes these; `build_request()` takes everything else. Splitting on
#: this is what lets send_exact forward a single **kwargs to both.
_SEND_KWARGS = frozenset({"auth", "follow_redirects", "stream"})


async def send_exact(client: typing.Any, method: str, url: typing.Any, *,
                     headers: typing.Any = None,
                     **kwargs: typing.Any) -> typing.Any:
    """Send a request whose header list is emitted exactly as given.

    A drop-in for `await client.post(url, ...)` when the on-wire header order
    has to be yours to the byte: build the request, then replace its headers
    with `headers` verbatim - so httpx's own client-default headers cannot sit
    in front of yours, and its auto `content-length` cannot be appended after
    them.  Everything else (`content`/`data`/`json`/`params`/`cookies`/
    `timeout`/`auth`/`follow_redirects`/...) is forwarded to httpx unchanged.

        r = await fp.send_exact(client, "POST", url, headers=[...], content=body)

    Because the header list is taken literally, YOU own the whole of it:

    * include `host` (it becomes `:authority`), `content-type` and an explicit
      `content-length` - overwriting the headers discards the ones httpx built
      from the body;
    * to keep a header whose value equals an httpx default - `accept: */*` most
      often - give the transport `raw_headers=True`, otherwise `_build_headers`
      still drops it by value even though you set it here;
    * `content=` is the way to pin the body bytes (and thus content-length),
      rather than `data=`/`json=` whose encoders would set headers you have
      just replaced.

    `headers=None` sends whatever httpx built, i.e. it behaves like a plain
    send.  Intended for `httpx.AsyncClient`; `client.send` is awaited.
    """
    send_kwargs = {k: kwargs.pop(k) for k in list(kwargs) if k in _SEND_KWARGS}
    request = client.build_request(method, url, **kwargs)
    if headers is not None:
        request.headers = httpx.Headers(headers)
    return await client.send(request, **send_kwargs)


def __getattr__(name: str) -> typing.Any:
    """Synthesise `<Brand>Transport` / `Async<Brand>Transport` on demand.

    A capture named chrome.json is reachable as both transport("chrome")
    and ChromeTransport, without this module containing a line of code about
    Chrome.  Done through the module __getattr__ (PEP 562) rather than by
    injecting names at import so that reload() needs no bookkeeping.
    """
    for prefix, base in (("Async", AsyncTransport), ("", Transport)):
        if not name.startswith(prefix) or not name.endswith("Transport"):
            continue
        stem = name[len(prefix):-len("Transport")]
        for brand, prof in PROFILES.items():
            if prof.class_name == stem:
                return type(name, (base,), {"_BRAND": brand})
    msg = (f"module {__name__!r} has no attribute {name!r}"
           + (f"; installed brands: {', '.join(brands())}" if PROFILES else ""))
    raise AttributeError(msg)


def __dir__() -> list[str]:
    return sorted(set(globals()) | {
        f"{prefix}{prof.class_name}Transport"
        for prof in PROFILES.values() for prefix in ("", "Async")})


# --- reporting --------------------------------------------------------------

def describe(brand: str | None = None) -> str:
    """What one profile - or every installed profile - impersonates."""
    if brand is None and DEFAULT_BRAND is None and len(PROFILES) != 1:
        return "\n\n".join(describe(b) for b in brands()) or (
            f"no browser profiles in {PROFILES_DIR}")

    prof = profile(brand)
    live = prof.priority_for()
    prio = (f"exclusive={live['priority_exclusive']} "
            f"dep={live['priority_depends_on']} weight={live['priority_weight']}"
            if live else "none (no PRIORITY flag on HEADERS)")
    def shown(kind: str) -> str:
        """What `captured_priority(kind)` would return, spelled out."""
        got = prof.captured_priority(kind)
        return (f"{kind}=w{got['weight']}"
                f"{'/excl' if got['exclusive'] else ''}" if got else f"{kind}=none")

    templates = ", ".join(shown(kind) for kind in ("navigate", "xhr"))
    sends = "the caller's, none of its own" if not prof.default_headers else (
        f"{len(prof.default_headers)} set on the transport")
    lines = [
        f"{prof.brand}  ({prof.label})",
        f"  transport      : browser_fp.{prof.class_name}Transport()"
        f" / transport({prof.brand!r})",
        # Everything under "capture" is what the browser sent, not what this
        # transport will send: header values are the caller's to supply. Say so
        # once here rather than let each line be read as a setting.
        f"  header values  : {sends}",
        f"  ---- the capture, for reference / headers= ----",
        f"  user-agent     : {prof.user_agent}",
        f"  sec-ch-ua      : {prof.header_map.get('sec-ch-ua', '(none)')}",
        f"  platform       : {prof.platform}",
        f"  accept-language: {prof.header_map.get('accept-language', '(none)')}",
        f"  request kind   : {prof.header_map.get('sec-fetch-mode') or 'unlabelled'}"
        f" (captured_priority() reports {prof.header_profile!r})",
        f"  captured prio  : {templates}",
        f"  ---- what this transport imposes ----",
        f"  hpack          : {prof.hpack}",
        f"  tls profile    : {_tls_state(prof)}",
        f"  session_ticket : {_ticket_state(prof)}",
        f"  akamai         : {prof.akamai_fingerprint}",
        f"  akamai md5     : {prof.akamai_hash}",
        "  settings       : "
        + ", ".join(f"{sid}={value}" for sid, value in prof.settings),
        "  window update  : "
        + (str(prof.window_update) if prof.window_update else "not sent"),
        f"  headers prio   : {prio}",
        f"  derived from   : {prof.source}",
        f"  captured at    : {prof.captured_at or 'unknown'}",
    ]
    return "\n".join(lines)


def catalog() -> str:
    """One line per installed profile."""
    if not PROFILES:
        return (f"no browser profiles in {PROFILES_DIR} - capture one with "
                f"`mytls-probe serve --brand <name>`")
    width = max(len(b) for b in PROFILES)
    lines = [f"{len(PROFILES)} profile(s) in {PROFILES_DIR}:"]
    for brand in brands():
        prof = PROFILES[brand]
        lines.append(f"  {brand:<{width}}  {prof.label:<28}  {prof.akamai_fingerprint}")
    return "\n".join(lines)


if __name__ == "__main__":
    print(catalog())
    print()
    print(describe())
