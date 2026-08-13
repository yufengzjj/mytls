"""Make an httpx client indistinguishable from a real browser, at both layers.

    import httpx
    import mytls

    with httpx.Client(transport=mytls.Transport("ios18")) as client:
        client.get("https://example.com/")

One transport sets both halves: the TLS layer (which ClientHello OpenSSL emits)
and the HTTP/2 layer (SETTINGS, WINDOW_UPDATE, HEADERS priority, HPACK encoding
and the request headers in the browser's own order).

It sets the header *order*, never their values - anything you could set
yourself is yours to set, so a request with no headers sends none.  For the
captured browser's own values, pass them:

    mytls.Transport("chrome", headers=mytls.profile("chrome").headers)

Two more things turned out not to belong to the network stack either, because
two apps on one device and one OS build were measured disagreeing about them -
the HEADERS frame's priority and whether the ClientHello offers an empty
session_ticket.  Both default to reproducing the capture and both are yours:

    mytls.Transport("ios18", priority=None, session_ticket=True)

**This package is only half of the machine.**  The HTTP/2 half is pure Python
and works anywhere; the TLS half is not, and cannot be - a ClientHello is built
inside OpenSSL, so it needs the OpenSSL fork this package was written for and a
CPython linked against it.  Installed against a stock Python the transports
still work, still send the browser's frames and headers, and send a ClientHello
that looks like Python's - which is worse than not pretending, because the two
layers then disagree with each other.

So the check is loud rather than silent.  `check()` reports it, `available()`
lists what the loaded library offers, and constructing a transport for a brand
the library has no profile for warns.  See `python/README.md` in the repository
for the build, and `install-python.sh` for doing it in one command.
"""

from __future__ import annotations

from . import fingerprints, tls_profile
from .browser_fp import (
    DEFAULT_BRAND,
    PROFILES,
    PROFILES_DIR,
    AsyncTransport,
    Profile,
    Transport,
    async_transport,
    brand_for,
    brands,
    catalog,
    describe,
    profile,
    reload,
    transport,
)

__version__ = "0.1.0"

__all__ = [
    "DEFAULT_BRAND", "PROFILES", "PROFILES_DIR",
    "AsyncTransport", "Profile", "Transport", "async_transport", "brand_for",
    "brands", "catalog", "describe", "profile", "reload", "transport",
    "fingerprints", "tls_profile", "check", "tls_profiles", "addon_path",
    "__version__",
]


def __getattr__(name: str):
    """Forward `mytls.ChromeTransport` to the class browser_fp synthesises.

    Those are made on demand from whatever captures are installed (PEP 562), so
    they cannot be imported by name here - re-exporting a fixed list would be
    exactly the hardcoded-per-browser knowledge the rest of this avoids.
    """
    from . import browser_fp

    return getattr(browser_fp, name)


def __dir__() -> list[str]:
    from . import browser_fp

    return sorted(set(globals()) | set(dir(browser_fp)))


def addon_path() -> str:
    """Where the mitmproxy addon lives, for `mitmdump -s`.

    Returned as a path rather than imported, because that module runs inside
    mitmproxy's interpreter. That may now be this one - `install-python.sh`
    builds 3.12 so mitmproxy can be installed alongside - but it may equally be
    a standalone build's bundled Python or a pipx venv, so nothing here imports
    it.
    """
    from pathlib import Path

    return str(Path(__file__).resolve().parent / "mitm_addon.py")


def tls_profiles() -> tuple[str, ...]:
    """The fingerprint profiles the loaded OpenSSL knows, asked of it directly.

    Empty if this Python is not linked against the fork, which is the one thing
    worth checking before trusting anything else here.
    """
    try:
        return tls_profile.available()
    except tls_profile.Unavailable:
        return ()


def check() -> str:
    """A one-line verdict on whether both layers are actually in place.

    Written to be printed, not parsed - `python -m mytls` is exactly this.
    Deliberately not raised at import time: the capture tools, `fingerprints`
    and the HTTP/2 layer are all useful on a stock Python, and refusing to
    import would take those away to prevent a mistake that is already reported
    the moment a transport is built.
    """
    import ssl

    got = tls_profiles()
    installed = ", ".join(brands()) or "none"
    if not got:
        return (f"TLS layer: NOT ACTIVE - {ssl.OPENSSL_VERSION} has no fingerprint "
                f"profiles, so every ClientHello will be Python's own. "
                f"HTTP/2 layer: ready ({installed}).")
    # What each brand *asks* the library for, which is not always its own name:
    # `{"meta": {"tls_profile": "..."}}` points a brand at another brand's
    # ClientHello, and several legitimately share one - every Chromium fork has
    # Chrome's TLS, and iOS 17 has iOS 16's. Comparing brand names here instead
    # reported those as missing, sending you to write a profile that is already
    # there under the name the capture names.
    wanted = {}
    for brand in brands():
        wanted.setdefault(profile(brand).tls_profile, []).append(brand)
    missing = {name: bs for name, bs in wanted.items() if name not in got}
    if missing:
        return (f"TLS layer: partial - {ssl.OPENSSL_VERSION} offers "
                f"{', '.join(got)}, but no profile for "
                + ", ".join(f"{name} (wanted by {', '.join(bs)})"
                            for name, bs in missing.items())
                + f". HTTP/2 layer: ready ({installed}).")
    return (f"both layers ready - TLS profiles {', '.join(got)} "
            f"({ssl.OPENSSL_VERSION}); HTTP/2 profiles {installed}.")
