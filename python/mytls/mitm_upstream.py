r"""A mitmproxy addon that gives mitmproxy's *upstream* TLS a browser's ClientHello.

`mitm_addon.py` watches the browser -> mitmproxy side and records it. This is
the other direction: the connection mitmproxy opens to the real server, which
is where a site fingerprints whoever is behind the proxy.

mitmproxy builds that connection with pyOpenSSL, which goes through
cryptography's own libssl. When cryptography is built from source and linked
dynamically against this repository's OpenSSL (see the mitmproxy notes in
README.md), that libssl is the fork, and one call per connection,
`SSL_set_fp_profile()`, picks the ClientHello. The HTTP/2 half - SETTINGS,
WINDOW_UPDATE, pseudo-header order, HPACK - is not done here: it lives in
mitmproxy itself, as the `http2_fingerprint` option.

    mitmdump -s "$(python -c 'import mytls; print(mytls.upstream_addon_path())')" \
             --set fp_profile=chrome --set http2_fingerprint=chrome --set http3=false

`http3=false` because upstream QUIC is aioquic's own TLS, which this cannot
reach.

Like `mitm_addon.py` this imports nothing from `mytls`: it runs in whichever
interpreter mitmdump is.

The self-tests (`mytls-probe mitm-selftest`, `mytls-verify --via-mitm`)
load `mitm_testhooks.py` beside this one, or beside any script of your own
that takes the same `fp_profile` option.
"""

from __future__ import annotations

import ctypes

from mitmproxy import ctx
from mitmproxy import exceptions
from mitmproxy import tls


def _libssl() -> ctypes.CDLL:
    """The libssl pyOpenSSL is actually using, by way of cryptography's extension.

    dlsym on an extension module's handle searches its dependency chain, so this
    reaches exactly the library behind pyOpenSSL. Loading "libssl.so.3" by name
    instead could find a different OpenSSL on the default search path, and an
    SSL* handed to that one is read with the wrong struct layout.
    """
    from cryptography.hazmat.bindings import _rust

    lib = ctypes.CDLL(_rust.__file__)
    try:
        lib.SSL_set_fp_profile.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
        lib.SSL_set_fp_profile.restype = ctypes.c_int
        lib.SSL_fp_profile_name.argtypes = [ctypes.c_size_t]
        lib.SSL_fp_profile_name.restype = ctypes.c_char_p
    except AttributeError as exc:
        from cryptography.hazmat.backends.openssl import backend

        msg = (f"mitmproxy's TLS goes through {backend.openssl_version_text()}, "
               f"which is not the mytls fork ({exc}). cryptography has to be "
               f"built from source and linked against it - see the mitmproxy "
               f"section of mytls/python/README.md.")
        raise RuntimeError(msg) from exc
    return lib


def _known(lib: ctypes.CDLL) -> list[str]:
    names: list[str] = []
    while (name := lib.SSL_fp_profile_name(len(names))) is not None:
        names.append(name.decode())
    return names


class UpstreamFingerprint:
    def __init__(self) -> None:
        self.lib: ctypes.CDLL | None = None

    def load(self, loader) -> None:
        loader.add_option(
            "fp_profile", str, "",
            "mytls ClientHello profile for upstream TLS, e.g. chrome or ios18. "
            "Empty leaves the library default (MYTLS_FP_PROFILE, else its "
            "compiled-in browser).")

    def configure(self, updated) -> None:
        if "fp_profile" in updated and ctx.options.fp_profile:
            self.lib = self.lib or _libssl()
            known = _known(self.lib)
            if ctx.options.fp_profile not in known:
                raise exceptions.OptionsError(
                    f"unknown fp_profile {ctx.options.fp_profile!r}; the library "
                    f"knows {', '.join(known)}")

    def tls_start_server(self, data: tls.TlsData) -> None:
        if not ctx.options.fp_profile:
            return
        # Script addons run before mitmproxy's own TlsConfig, so let it build the
        # connection first - it leaves one that already exists alone - and only
        # then switch the profile on it.
        ctx.master.addons.get("tlsconfig").tls_start_server(data)
        assert data.ssl_conn is not None and self.lib is not None
        from OpenSSL._util import ffi
        from OpenSSL._util import lib as openssl_lib

        ptr = int(ffi.cast("uintptr_t", data.ssl_conn._ssl))
        if self.lib.SSL_set_fp_profile(ptr, ctx.options.fp_profile.encode()) != 1:
            # A failure leaves an error on OpenSSL's queue, which pyOpenSSL's next
            # call would otherwise report as its own.
            openssl_lib.ERR_clear_error()
            raise ValueError(f"SSL_set_fp_profile({ctx.options.fp_profile!r}) failed")


addons = [UpstreamFingerprint()]
