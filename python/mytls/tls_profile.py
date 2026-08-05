"""Select which browser's ClientHello OpenSSL emits, from Python.

The TLS layer of this fork is switchable at runtime - see ssl/ssl_fp_profile.c -
but CPython's `ssl` module exposes no way to reach the switch: it has no
SSL_CONF passthrough and no generic setter, so `SSLContext` simply has no
method that would carry a profile name down.  This module calls
`SSL_CTX_set_fp_profile()` directly instead.

    import ssl, tls_profile
    ctx = ssl.create_default_context()
    tls_profile.set_profile(ctx, "safari_ios")

`browser_fp.Transport` does this for you; use this module directly only when
driving OpenSSL through something other than browser_fp.

Nothing here is best-effort: if the library is not this fork, or the profile
name is unknown, or the SSL_CTX pointer is not where it is expected, you get an
exception rather than a context that quietly keeps sending Chrome's bytes.
"""

from __future__ import annotations

import _ssl
import ctypes
import ssl
import typing


class Unavailable(RuntimeError):
    """The loaded OpenSSL is not this fork, or its layout is not recognised."""


_lib: ctypes.CDLL | None = None


def library() -> ctypes.CDLL:
    """The libssl this interpreter's `ssl` module is actually linked against.

    Opening the `_ssl` extension rather than "libssl" by name: dlsym searches a
    handle's dependency chain, so this reaches exactly the libssl behind
    `ssl`, whereas loading one by name can find a *different* OpenSSL that
    happens to be installed - and then every pointer handed to it is read with
    the wrong struct layout, which segfaults rather than fails.
    """
    global _lib
    if _lib is not None:
        return _lib

    lib = ctypes.CDLL(_ssl.__file__)
    try:
        lib.SSL_CTX_set_fp_profile.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
        lib.SSL_CTX_set_fp_profile.restype = ctypes.c_int
        lib.SSL_CTX_get_fp_profile.argtypes = [ctypes.c_void_p]
        lib.SSL_CTX_get_fp_profile.restype = ctypes.c_char_p
        lib.SSL_fp_profile_name.argtypes = [ctypes.c_size_t]
        lib.SSL_fp_profile_name.restype = ctypes.c_char_p
        lib.SSL_CTX_get_options.argtypes = [ctypes.c_void_p]
        lib.SSL_CTX_get_options.restype = ctypes.c_uint64
    except AttributeError as exc:
        msg = (f"{ssl.OPENSSL_VERSION} has no fingerprint profiles ({exc}). "
               f"This needs the OpenSSL fork in this repository; a stock build "
               f"will negotiate normally and look nothing like a browser.")
        raise Unavailable(msg) from exc

    _lib = lib
    return lib


def available() -> tuple[str, ...]:
    """The profile names the library knows, asked of the library itself."""
    lib = library()
    out: list[str] = []
    while (name := lib.SSL_fp_profile_name(len(out))) is not None:
        out.append(name.decode())
    return tuple(out)


def _ssl_ctx(context: ssl.SSLContext) -> int:
    """The SSL_CTX* inside a Python SSLContext, verified before it is used.

    CPython's PySSLContext keeps the SSL_CTX* in its first slot after the
    object header, which is not a documented layout - so rather than trust the
    offset, read something through the pointer that Python also knows
    (`options`, a 64-bit mask the caller has usually just changed) and require
    the two to agree.  A wrong pointer fails here instead of corrupting memory.
    """
    lib = library()
    offset = ctypes.sizeof(ctypes.c_void_p) * 2       # after PyObject_HEAD
    ptr = ctypes.c_void_p.from_address(id(context) + offset).value
    if ptr is None or lib.SSL_CTX_get_options(ptr) != int(context.options):
        msg = (f"the SSL_CTX pointer inside this {type(context).__name__} is "
               f"not at the expected offset {offset} - refusing to write "
               f"through it. This means CPython's PySSLContext layout changed; "
               f"the profile has NOT been set.")
        raise Unavailable(msg)
    return ptr


def set_profile(context: ssl.SSLContext, name: str) -> None:
    """Make `context`'s connections emit `name`'s ClientHello.

    Takes effect for handshakes started afterwards, so set it before the
    context is used.  A context is shared by every connection made through it,
    which is why browser_fp gives each transport its own.
    """
    lib = library()
    ptr = _ssl_ctx(context)
    if lib.SSL_CTX_set_fp_profile(ptr, name.encode()) != 1:
        msg = (f"OpenSSL has no fingerprint profile {name!r}; it knows "
               f"{', '.join(available())}. The TLS layer would still be "
               f"emitting the default, so this is an error rather than a "
               f"warning.")
        raise Unavailable(msg)


def get_profile(context: ssl.SSLContext) -> str:
    """Which profile `context` is set to, read back out of OpenSSL."""
    return library().SSL_CTX_get_fp_profile(_ssl_ctx(context)).decode()


def describe() -> str:
    try:
        names = available()
    except Unavailable as exc:
        return f"tls profiles: unavailable ({exc})"
    return f"tls profiles: {', '.join(names)}  ({ssl.OPENSSL_VERSION})"


if __name__ == "__main__":  # pragma: no cover - a one-line health check
    print(describe())
