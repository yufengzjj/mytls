"""Make httpx's HTTP/2 layer and request headers look like a real browser's.

The TLS layer is handled by the patched OpenSSL in ~/openssl, but a server that
speaks HTTP/2 sees a second, independent fingerprint built from the SETTINGS
frame, the connection WINDOW_UPDATE, any PRIORITY frames and the pseudo-header
order.  Out of the box httpcore sends

    1:4096;2:0;4:65535;5:16384;3:100;6:65536|16777216|0|m,a,s,p

which is nothing like a browser and gives the game away.  This module provides
transports that send a captured browser's values instead, and replace the
request headers with that browser's set, in its order.

    import browser_fp as fp
    import httpx

    with httpx.Client(transport=fp.transport("chrome")) as client:
        client.get("https://example.com/")

Importing has no effect on its own: only clients given one of these transports
behave differently, so a library can use this without changing how the rest of
the process makes requests.  Comparing against stock behaviour is just a matter
of dropping the transport argument.

Nothing here is hand-maintained and nothing here is written for a particular
browser.  Every profile is a capture taken with hpack_probe.py and dropped into
PROFILES_DIR:

    python hpack_probe.py serve --brand firefox   # capture it
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

import hashlib
import json
import os
import re
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

__all__ = ["Profile", "PROFILES", "PROFILES_DIR", "DEFAULT_BRAND",
           "Transport", "AsyncTransport", "transport", "async_transport",
           "profile", "brands", "brand_for", "reload", "describe", "catalog"]

_EXPECTED = {"httpx": "0.27.2", "httpcore": "1.0.9", "h2": "4.4.0"}

#: One capture per brand, named `<brand>.json`. Written by
#: `hpack_probe.py serve --brand <brand>`; set BROWSER_FP_PROFILES to try a
#: directory of captures out before committing them.
PROFILES_DIR = Path(
    os.environ.get("BROWSER_FP_PROFILES")
    or Path(__file__).resolve().parent / "profiles")

#: Optional second half of a capture: what independent fingerprinters made of
#: the same browser, collected in the same visit. Used for two things a local
#: probe cannot see - a request that carries a `referer` and one that is an
#: XHR - so it is what the header templates' *order* is derived from.
REFERENCES_DIR = Path(
    os.environ.get("BROWSER_FP_REFERENCES")
    or Path(__file__).resolve().parent / "references")

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
    }


_PSEUDO_DEFAULT = (":method", ":authority", ":scheme", ":path")

#: sec-fetch-mode as the browser reports it -> which of our templates it is.
_MODE_TO_KIND = {"navigate": "navigate", "cors": "xhr"}


def _read_reference(path: Path) -> dict:
    """Header order and HEADERS priority per kind, read out of a reference.

    A capture taken against our own probe can only ever be a first-party
    navigation with no cookies and no referer, so it cannot say where those go -
    and a request whose `sec-fetch-mode` is `cors` never reaches it at all. The
    reference is a request the same browser made to a real site, so it answers
    both. Only the *order* and the priority are taken from here; the values
    still come from the capture, because they belong to that other site.
    """
    data = json.loads(path.read_text())
    # One entry per kind of request, oldest formats first: a bare tls.peet.ws
    # response, then a single one under "peet", now a list of them.
    entries = data if "tls" in data else data.get("peet")
    if isinstance(entries, dict) or entries is None:
        entries = [entries] if entries else []

    out: dict[str, dict] = {}
    for entry in entries:
        for frame in (entry or {}).get("http2", {}).get("sent_frames", []):
            if frame.get("frame_type") != "HEADERS":
                continue
            pairs = [tuple(h.split(": ", 1)) for h in frame.get("headers", [])
                     if ": " in h]
            headers = [(k, v) for k, v in pairs if not k.startswith(":")]
            kind = _MODE_TO_KIND.get(dict(headers).get("sec-fetch-mode", ""))
            if kind is None or kind in out:
                continue
            out[kind] = {"headers": headers, "priority": frame.get("priority")}
    return out

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
_HPACK_ENGINES = ("quiche", "stock")


def _hpack_engine(meta: dict, browser: str) -> str:
    engine = meta.get("hpack")
    if engine is None:
        # Every Chromium fork ships quiche; nothing else does.
        return "quiche" if browser not in ("Firefox", "unknown") else "stock"
    if engine not in _HPACK_ENGINES:
        msg = f"unknown hpack engine {engine!r}, expected one of {_HPACK_ENGINES}"
        raise ValueError(msg)
    return engine


class Profile:
    """One captured browser: its wire behaviour and the metadata that goes with it.

    Read-only as far as the capture goes.  The three attributes that are *not*
    part of the capture - `header_profile`, `accept_language` and
    `send_cache_control` - are knobs, because they depend on what the user is
    doing rather than on which browser they are pretending to be.  Changing one
    affects every transport built from this profile, live connections included.
    """

    def __init__(self, cap: dict, source: str, reference: dict | None = None) -> None:
        self.brand: str = cap["brand"]
        self.source = source
        self.captured_at: str | None = cap["captured_at"]

        #: {kind: {"headers": [...], "priority": {...}}} from REFERENCES_DIR, or
        #: {} when this brand has no reference - then the templates fall back to
        #: what can be worked out from the capture alone.
        self.reference: dict[str, dict] = reference or {}

        #: Request headers as captured, pseudo-headers excluded, in wire order.
        self.headers: list[tuple[str, str]] = list(cap["headers"])
        self.header_map: dict[str, str] = dict(self.headers)

        self.user_agent = self.header_map.get("user-agent", "")
        self.browser, self.version = _product(self.user_agent)
        self.platform = _platform(self.header_map, self.user_agent)
        self.hpack = _hpack_engine(cap["meta"], self.browser)
        self.label: str = cap["meta"].get("label") or (
            f"{self.browser} {self.version.split('.')[0]} on {self.platform}")

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

        #: "navigate" reproduces a top-level page load, which is what the
        #: capture is. "xhr" is what a page's own fetch()/XHR looks like: the
        #: header *set* is well known, but the exact order is derived from the
        #: navigate capture rather than confirmed first-hand, so treat it as
        #: best-effort.
        self.header_profile = "navigate"

        #: Follows the captured browser's UI language. Overridable.
        self.accept_language = self.header_map.get("accept-language", "")

        #: `sec-fetch-site` is worked out per request by the browser, so there
        #: is no right constant; None means the default for the current kind.
        self.sec_fetch_site: str | None = None

        #: Browsers send `cache-control: max-age=0` on a reload or a re-entered
        #: URL but not on a plain navigation to a new address - both confirmed
        #: against live captures. Defaults to whatever the capture did.
        self.send_cache_control = "cache-control" in self.header_map

        self._classes: dict[typing.Any, type] = {}

    def __repr__(self) -> str:
        return f"<Profile {self.brand}: {self.label}>"

    def priority_for(self, kind: str | None = None) -> dict:
        """HEADERS-frame priority for this kind of request.

        Chrome does not give an XHR the same stream priority as a navigation -
        weight 220 against 256, measured - so this is per kind, and the XHR one
        is only known when a reference supplied it.
        """
        kind = kind or self.header_profile
        prio = (self.reference.get(kind) or {}).get("priority")
        if prio:
            return {
                "priority_exclusive": bool(prio["exclusive"]),
                "priority_depends_on": prio["depends_on"],
                "priority_weight": prio["weight"],
            }
        return self.headers_priority

    @property
    def meta(self) -> dict:
        """Everything about the captured browser that is not wire behaviour."""
        return {
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
            "akamai_fingerprint": self.akamai_fingerprint,
            "akamai_hash": self.akamai_hash,
            "source": self.source,
            "captured_at": self.captured_at,
        }

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
            f"`python hpack_probe.py serve --brand <name>`",
            RuntimeWarning, stacklevel=2)
        return PROFILES

    for path in sorted(PROFILES_DIR.glob("*.json")):
        try:
            ref_path = REFERENCES_DIR / path.name
            reference = _read_reference(ref_path) if ref_path.is_file() else None
            prof = Profile(_read_capture(path), str(path), reference)
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
                   f"`python hpack_probe.py serve --brand <name>`")
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
_EXTRA = "\x00extra\x00"

#: What an XHR/fetch changes relative to a navigation. Applied to the captured
#: header list so the *order* still comes from the capture and this generalises
#: to browsers that send a different set.
_XHR_VALUES = {
    "accept": "*/*",
    "sec-fetch-site": "same-origin",
    "sec-fetch-mode": "cors",
    "sec-fetch-dest": "empty",
    "priority": "u=1, i",
}
_XHR_DROP = frozenset(["upgrade-insecure-requests", "sec-fetch-user"])


#: Headers whose value belongs to the individual request rather than to the
#: browser. A reference tells us where in the order they go; it must never tell
#: us what they say, because there they describe a request to somewhere else.
_PER_REQUEST = frozenset([
    "referer", "cookie", "origin", "authorization", "content-type",
    "content-length", "range", "if-none-match", "if-modified-since",
])

#: `sec-fetch-site` is computed per request too, but leaving it out would be
#: unlike the browser, so each kind gets its commonest value as a default.
_SITE_DEFAULT = {"navigate": "none", "xhr": "same-origin"}


def _template(prof: Profile) -> list[tuple[str, str | None]]:
    """Ordered (name, value) pairs; None means 'only if the caller supplied it'."""
    kind = prof.header_profile
    if kind not in ("navigate", "xhr"):
        msg = f"unknown header_profile {kind!r}, expected 'navigate' or 'xhr'"
        raise ValueError(msg)
    ref = prof.reference.get(kind)
    if ref is None:
        return _derived_template(prof)
    return _reference_template(prof, ref["headers"], kind)


def _reference_template(prof: Profile, headers: list[tuple[str, str]],
                        kind: str) -> list[tuple[str, str | None]]:
    """Order from the reference, values from the capture.

    This is the only way to learn where `referer` and `cookie` sit: a capture
    taken against localhost has neither. Measured against real Chrome, `referer`
    goes after `sec-fetch-dest` rather than after `accept`, which is where the
    generic slot used to put everything.
    """
    out: list[tuple[str, str | None]] = []
    last_caller = -1
    for name, ref_value in headers:
        if name in _PER_REQUEST:
            last_caller = len(out)
            out.append((name, None))
            continue
        if name == "cache-control":
            if prof.send_cache_control:
                out.append((name, ref_value))
            continue
        if name == "accept-language":
            value: str | None = prof.accept_language
        elif name == "sec-fetch-site":
            value = prof.sec_fetch_site or _SITE_DEFAULT[kind]
        elif kind == "navigate":
            # Both are navigations by the same browser, so they agree - but the
            # capture is this profile's own, so it wins.
            value = prof.header_map.get(name, ref_value)
        else:
            value = ref_value
        out.append((name, value))

    if prof.send_cache_control and not any(n == "cache-control" for n, _ in out):
        out.insert(0, ("cache-control", "max-age=0"))
    # Headers we have never seen a browser send go next to the ones we have.
    out.insert(last_caller + 1 if last_caller >= 0 else len(out), (_EXTRA, None))
    return out


def _derived_template(prof: Profile) -> list[tuple[str, str | None]]:
    """Fallback for a brand with no reference: everything from the capture.

    The navigate order is real; the xhr one is the navigate order with the
    known substitutions applied, which is an inference - a reference replaces
    it with the real thing.
    """
    xhr = prof.header_profile == "xhr"
    out: list[tuple[str, str | None]] = []
    for name, value in prof.headers:
        if name == "cache-control":
            if prof.send_cache_control and not xhr:
                out.append((name, value))
            continue
        if xhr and name in _XHR_DROP:
            continue
        if name == "accept-language":
            value = prof.accept_language
        elif name == "sec-fetch-site" and prof.sec_fetch_site:
            value = prof.sec_fetch_site
        elif xhr and name in _XHR_VALUES:
            value = _XHR_VALUES[name]
        out.append((name, value))
        if name == "accept":
            out.append((_EXTRA, None))

    if prof.send_cache_control and not xhr and "cache-control" not in prof.header_map:
        out.insert(0, ("cache-control", "max-age=0"))
    if not any(n == _EXTRA for n, _ in out):
        out.append((_EXTRA, None))
    return out


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


def _build_headers(prof: Profile, request: typing.Any) -> list[tuple[bytes, bytes]]:
    """The profile's header list for this request, pseudo-headers first."""
    authority = [v for k, v in request.headers if k.lower() == b"host"][0]

    defaults = _httpx_default_headers()
    supplied: list[tuple[bytes, bytes]] = []
    for key, value in request.headers:
        key = key.lower()
        if key in _DROP or (key, value) in defaults:
            continue
        supplied.append((key, value))

    template = _template(prof)
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
        (name.encode("ascii"), pseudo[name]) for name in prof.pseudo_order
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

    if prof.hpack == "quiche":
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
_ENCODERS = {"quiche": _QuicheEncoder, "stock": hpack.Encoder}


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
            f"browser_fp subclasses library internals and was written against "
            f"{_EXPECTED}; found {detail}. Re-check httpcore's handle_request, "
            f"create_connection, _send_connection_init and _send_request_headers "
            f"before trusting the fingerprint.",
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


class Transport(httpx.HTTPTransport):
    """An httpx transport whose HTTP/2 layer looks like a captured browser's.

        import browser_fp as fp, httpx

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

    def __init__(self, brand: str | None = None, **kwargs: typing.Any) -> None:
        self.profile = profile(brand if brand is not None else self._BRAND)
        kwargs.setdefault("http2", True)
        super().__init__(**kwargs)
        _retag_pool(self, self.profile, self._ASYNC)

    def __repr__(self) -> str:
        return f"<{type(self).__name__} {self.profile.brand}>"


class AsyncTransport(httpx.AsyncHTTPTransport):
    """Async twin of Transport, for httpx.AsyncClient."""

    _BRAND: typing.ClassVar[str | None] = None
    _ASYNC: typing.ClassVar[bool] = True

    def __init__(self, brand: str | None = None, **kwargs: typing.Any) -> None:
        self.profile = profile(brand if brand is not None else self._BRAND)
        kwargs.setdefault("http2", True)
        super().__init__(**kwargs)
        _retag_pool(self, self.profile, self._ASYNC)

    def __repr__(self) -> str:
        return f"<{type(self).__name__} {self.profile.brand}>"


def transport(brand: str | None = None, **kwargs: typing.Any) -> Transport:
    """A sync transport for `brand`; same as Transport(brand, ...)."""
    return Transport(brand, **kwargs)


def async_transport(brand: str | None = None, **kwargs: typing.Any) -> AsyncTransport:
    """An async transport for `brand`; same as AsyncTransport(brand, ...)."""
    return AsyncTransport(brand, **kwargs)


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
    templates = ", ".join(
        f"{kind}={'reference' if kind in prof.reference else 'derived'}"
        for kind in ("navigate", "xhr"))
    captured_lang = prof.header_map.get("accept-language", "")
    lines = [
        f"{prof.brand}  ({prof.label})",
        f"  transport      : browser_fp.{prof.class_name}Transport()"
        f" / transport({prof.brand!r})",
        f"  user-agent     : {prof.user_agent}",
        f"  sec-ch-ua      : {prof.header_map.get('sec-ch-ua', '(not sent)')}",
        f"  platform       : {prof.platform}",
        f"  accept-language: {prof.accept_language}"
        + ("" if prof.accept_language == captured_lang
           else f"  (capture had {captured_lang})"),
        f"  cache-control  : {'sent' if prof.send_cache_control else 'not sent'}",
        f"  header profile : {prof.header_profile} (capture was sec-fetch-mode: "
        f"{prof.header_map.get('sec-fetch-mode') or 'unknown'})",
        f"  header order   : {templates}",
        f"  hpack          : {prof.hpack}",
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
                f"`python hpack_probe.py serve --brand <name>`")
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
