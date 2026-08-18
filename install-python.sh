#!/usr/bin/env bash
#
# Build this OpenSSL fork and a CPython linked against it, from scratch.
#
# Meant for a fresh server: installs the build dependencies, builds and installs
# the library, gets pyenv if it is missing, builds CPython against the library,
# and installs the Python packages python/ needs.
#
#   ./install-python.sh
#
# Everything is overridable:
#
#   PREFIX=/opt/mytls PYTHON_VERSION=3.12.13 JOBS=8 ./install-python.sh
#
# Flags: --skip-deps --skip-openssl --skip-python --skip-selftest --yes
#        --with-mitmproxy   also install mitmproxy, which `capture-mitm` shells
#                           out to. Needs Python >= 3.12, which is why that is
#                           the default version.
#
set -euo pipefail

PREFIX="${PREFIX:-$HOME/openssl}"
# 3.12 rather than 3.11 so that mitmproxy, which needs >= 3.12, can be installed
# into this same interpreter instead of needing a second Python of its own. The
# two dependency sets do coexist: mitmproxy pins h2 exactly at 4.3.0, and 4.3.0
# is one of the versions browser_fp has been measured against - see _EXPECTED
# there. Nothing else in mytls cares which of the two is installed.
PYTHON_VERSION="${PYTHON_VERSION:-3.12.13}"
PYENV_ROOT="${PYENV_ROOT:-$HOME/.pyenv}"
JOBS="${JOBS:-$( (nproc || sysctl -n hw.ncpu || echo 4) 2>/dev/null )}"
# Leave empty to let Configure detect the platform (works for x86_64 and arm64).
OPENSSL_TARGET="${OPENSSL_TARGET:-}"

SKIP_DEPS=0 SKIP_OPENSSL=0 SKIP_PYTHON=0 SKIP_SELFTEST=0 ASSUME_YES=0
WITH_MITMPROXY=0
for arg in "$@"; do
    case "$arg" in
        --skip-deps)     SKIP_DEPS=1 ;;
        --skip-openssl)  SKIP_OPENSSL=1 ;;
        --skip-python)   SKIP_PYTHON=1 ;;
        --skip-selftest) SKIP_SELFTEST=1 ;;
        --with-mitmproxy) WITH_MITMPROXY=1 ;;
        --yes|-y)        ASSUME_YES=1 ;;
        # The leading comment block, stripped of its `# `. Printed by scanning
        # until the first non-comment line rather than by matching an end
        # pattern: an earlier version stopped at /^# Flags/, and the range then
        # reopened on the `# Building one per brand` comment further down and
        # ran to the end of the file.
        -h|--help)      awk 'NR > 1 && !/^#/ {exit}
                             NR > 1 {sub(/^# ?/, ""); print}' "$0"; exit 0 ;;
        *) echo "unknown option: $arg (try --help)" >&2; exit 2 ;;
    esac
done

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

say()  { printf '\n\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m warning:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m error:\033[0m %s\n' "$*" >&2; exit 1; }

[ -f Configure ] && [ -d python ] \
    || die "run this from the repository root (Configure and python/ must be here)"

# Which libssl a binary actually resolves at runtime, or "" if that cannot be
# told. Empty is deliberately not an error here: it means no ldd (not Linux) or
# no dynamic link, and every caller decides for itself what to make of that.
# LD_LIBRARY_PATH is unset on purpose - what matters is what the binary finds on
# its own, not what this shell happens to be pointing at.
#
# ldd's own exit status is discarded on purpose. musl's ldd exits 127 when the
# object has undefined symbols, and a CPython extension module always does -
# every Py* symbol is resolved from the interpreter at load time, not from any
# library. It still prints the DT_NEEDED lines we want first. Without the
# `|| true` the `set -o pipefail` above turns that 127 into an abort, and the
# script dies on Alpine right after reporting the CLI's linkage.
libssl_of() {
    command -v ldd >/dev/null 2>&1 || return 0
    { env -u LD_LIBRARY_PATH ldd "$1" 2>/dev/null || true; } \
        | awk '/libssl\.so/ {print $3}'
}

# --- privileges -------------------------------------------------------------
SUDO=""
if [ "$(id -u)" -ne 0 ]; then
    if command -v sudo >/dev/null 2>&1; then
        SUDO="sudo"
    fi
fi

# --- 1. build dependencies --------------------------------------------------
# libssl-dev is deliberately absent: we build our own and do not want a second
# set of OpenSSL headers on the include path.
DEB_PKGS="build-essential pkg-config git curl ca-certificates perl
          zlib1g-dev libffi-dev libreadline-dev libncurses-dev libbz2-dev
          liblzma-dev libsqlite3-dev libbrotli-dev"
RPM_PKGS="gcc gcc-c++ make git curl ca-certificates perl-core perl-IPC-Cmd
          zlib-devel libffi-devel readline-devel ncurses-devel bzip2-devel
          xz-devel sqlite-devel brotli-devel"
APK_PKGS="build-base linux-headers git curl ca-certificates perl
          zlib-dev libffi-dev readline-dev ncurses-dev bzip2-dev
          xz-dev sqlite-dev brotli-dev"

install_deps() {
    local mgr pkgs
    if   command -v apt-get >/dev/null 2>&1; then mgr=apt; pkgs="$DEB_PKGS"
    elif command -v dnf     >/dev/null 2>&1; then mgr=dnf; pkgs="$RPM_PKGS"
    elif command -v yum     >/dev/null 2>&1; then mgr=yum; pkgs="$RPM_PKGS"
    elif command -v apk     >/dev/null 2>&1; then mgr=apk; pkgs="$APK_PKGS"
    else
        warn "no supported package manager found; install these yourself:"
        printf '  %s\n' $DEB_PKGS >&2
        return 0
    fi

    if [ "$(id -u)" -ne 0 ] && [ -z "$SUDO" ]; then
        warn "not root and no sudo - skipping dependency install."
        warn "install these first, then re-run with --skip-deps:"
        printf '  %s\n' $pkgs >&2
        return 0
    fi

    say "installing build dependencies via $mgr"
    case "$mgr" in
        apt) $SUDO apt-get update -qq
             DEBIAN_FRONTEND=noninteractive $SUDO apt-get install -y -qq $pkgs ;;
        dnf) $SUDO dnf install -y -q $pkgs ;;
        yum) $SUDO yum install -y -q $pkgs ;;
        apk) $SUDO apk add --no-progress $pkgs ;;
    esac
}

[ "$SKIP_DEPS" -eq 1 ] || install_deps

# --- 2. line endings --------------------------------------------------------
# A Windows checkout leaves CRLF everywhere, which breaks both the perl build
# scripts and backslash line-continuations inside the C headers.
if grep -q $'\r' Configure 2>/dev/null; then
    say "converting CRLF -> LF (the tree came from a Windows checkout)"
    if [ "$ASSUME_YES" -eq 0 ]; then
        printf 'this rewrites every file in %s. continue? [y/N] ' "$ROOT"
        read -r reply </dev/tty || reply=n
        case "$reply" in [yY]*) ;; *) die "aborted" ;; esac
    fi
    # Binary files are skipped, and this is not cosmetic: `sed -i 's/\r$//'`
    # over the whole tree silently truncates any file with a 0d 0a byte pair in
    # it that is data rather than a line ending. test/smcont.bin loses two
    # bytes that way and the S/MIME tests then fail on content nobody edited.
    # perl's -B is the same heuristic `grep -I` uses, and perl is already
    # required to run Configure.
    find . -path ./.git -prune -o -type f -print0 \
        | xargs -0 -P"$JOBS" -n200 \
            perl -i -pe 'BEGIN { @ARGV = grep { !-B $_ } @ARGV } s/\r\n$/\n/'
fi

# --- 3. OpenSSL -------------------------------------------------------------
# Where the distro keeps its CA bundle, so create_default_context() just works
# instead of every caller having to pass cafile=.
detect_openssldir() {
    for d in /etc/ssl /etc/pki/tls; do
        [ -d "$d/certs" ] && { echo "$d"; return; }
    done
    echo /etc/ssl
}

build_openssl() {
    local ssldir
    ssldir="$(detect_openssldir)"
    say "building OpenSSL -> $PREFIX (openssldir=$ssldir, -j$JOBS)"

    # -Wl,-rpath,$(LIBRPATH) bakes $PREFIX/lib into everything we link,
    # including apps/openssl. Without it the CLI resolves libcrypto through the
    # default search path and picks up the distro's, which fails with e.g.
    # "BIO_f_brotli: symbol not found" - our library has it, theirs does not.
    # LIBRPATH is OpenSSL's own variable for this and expands to $(libdir), so
    # it stays correct if --libdir changes. Single-quoted on purpose: it has to
    # reach the makefile unexpanded.
    # shellcheck disable=SC2086 - OPENSSL_TARGET is intentionally word-split
    # enable-weak-ssl-ciphers builds the three 3DES suites. They are needed
    # because Safari still offers them: without them its ClientHello carries 17
    # cipher suites instead of 20 and its JA4 comes out t13d1714 instead of
    # t13d2014, which is a fingerprint of its own. Only a profile that lists
    # them can offer them - the chrome profile does not - but a server could
    # then negotiate 3DES on an ios18 connection, exactly as it could with
    # the real client.
    # enable-zlib is not optional here: the ios profiles advertise zlib
    # certificate compression (RFC 8879), so the server compresses its chain
    # with zlib and this library has to be able to decompress it - without
    # zlib the handshake dies with SSL_R_BAD_COMPRESSION_ALGORITHM. brotli is
    # the same story for the chrome profiles.
    # shellcheck disable=SC2086 - OPENSSL_TARGET is intentionally word-split
    ./Configure $OPENSSL_TARGET shared enable-brotli enable-zlib \
        enable-weak-ssl-ciphers \
        --prefix="$PREFIX" --libdir=lib --openssldir="$ssldir" \
        '-Wl,-rpath,$(LIBRPATH)'

    for feat in BROTLI ZLIB; do
        grep -q "OPENSSL_NO_$feat\b" include/openssl/configuration.h 2>/dev/null \
            && warn "$feat certificate compression did NOT get enabled - a
             server that compresses its certificate chain with it will fail the
             handshake. Install the $feat development package and re-run."
    done

    # build_generated first: with -j the generated headers can otherwise lose a
    # race against the compiles that include them.
    make build_generated >/dev/null
    make -j"$JOBS"
    make install_sw
}

[ "$SKIP_OPENSSL" -eq 1 ] || build_openssl
[ -f "$PREFIX/lib/libssl.so" ] || [ -f "$PREFIX/lib/libssl.dylib" ] \
    || die "$PREFIX/lib/libssl.so is missing - the OpenSSL build did not finish"

# --- 4. pyenv + CPython -----------------------------------------------------
build_python() {
    if [ ! -x "$PYENV_ROOT/bin/pyenv" ]; then
        say "installing pyenv -> $PYENV_ROOT"
        git clone --depth 1 https://github.com/pyenv/pyenv.git "$PYENV_ROOT"
    fi
    export PYENV_ROOT
    export PATH="$PYENV_ROOT/bin:$PATH"

    # pyenv install --skip-existing returns 0 without building when the version
    # is already there, and silently ignores every option below - so an
    # interpreter pyenv installed the ordinary way, linked against the system
    # OpenSSL, would sail through here and only be caught by the linkage check
    # two steps later, where the error blames the OpenSSL rpath and sends the
    # reader off in the wrong direction. Settle it here, where the cause is
    # known, and say what it actually is.
    local existing="$PYENV_ROOT/versions/$PYTHON_VERSION"
    if [ -d "$existing" ]; then
        local ssl_so linked
        ssl_so="$("$existing/bin/python3" -c 'import _ssl; print(_ssl.__file__)' 2>/dev/null)"
        linked="${ssl_so:+$(libssl_of "$ssl_so")}"
        case "$linked" in
            "$PREFIX"/*)
                say "reusing CPython $PYTHON_VERSION, already built against $PREFIX"
                return
                ;;
            "")
                die "pyenv already has $PYTHON_VERSION at $existing, but its
         _ssl module cannot be inspected - it may be broken, or built with
         no OpenSSL at all. This script will not overwrite it. Either remove
         it and re-run:
             pyenv uninstall -f $PYTHON_VERSION
         or build a different version instead:
             PYTHON_VERSION=3.12.12 $0"
                ;;
            *)
                die "pyenv already has $PYTHON_VERSION at $existing, and it is
         linked against $linked - not the OpenSSL in this repository
         ($PREFIX/lib). Without that link the TLS half of the fingerprint does
         not exist: every ClientHello would be Python's own.

         'pyenv install --skip-existing' will not rebuild it, and this script
         will not delete an interpreter you may be using. Pick one:

           - remove it and re-run this script:
                 pyenv uninstall -f $PYTHON_VERSION
           - build a patch version pyenv does not already have:
                 PYTHON_VERSION=3.12.12 $0
           - keep it as it is, knowing the TLS layer will not work:
                 $0 --skip-python"
                ;;
        esac
    fi

    say "building CPython $PYTHON_VERSION against $PREFIX (-j$JOBS)"
    # --with-openssl-rpath=auto bakes the library path into the binary, so the
    # result works without LD_LIBRARY_PATH.
    CONFIGURE_OPTS="--with-openssl=$PREFIX --with-openssl-rpath=auto" \
    CPPFLAGS="-I$PREFIX/include" \
    LDFLAGS="-L$PREFIX/lib -Wl,-rpath,$PREFIX/lib" \
    MAKE_OPTS="-j$JOBS" \
        pyenv install --skip-existing "$PYTHON_VERSION"
}

[ "$SKIP_PYTHON" -eq 1 ] || build_python

PY="$PYENV_ROOT/versions/$PYTHON_VERSION/bin/python$(echo "$PYTHON_VERSION" | cut -d. -f1,2)"
[ -x "$PY" ] || die "$PY is missing - the CPython build did not finish"

# --- 5. the Python package --------------------------------------------------
# Installed rather than run from the tree, so that any project using this Python
# can `import mytls` without knowing where the repository is. Its dependencies -
# httpx pinned exactly, plus brotli and zstandard - come from python/pyproject.toml.
say "installing the mytls Python package"
# setuptools' build/ is incremental and never removes files that disappeared
# from the source tree, so a profile that was renamed - safari_ios.json ->
# ios18.json - comes back from the dead in the wheel and the self-test then
# fails on a brand that no longer exists. The captures are package data, which
# makes this failure mode specific to this package rather than theoretical.
rm -rf "$ROOT/python/build" "$ROOT/python/mytls.egg-info"
# PYTHONNOUSERSITE hides ~/.local/lib/pythonX.Y/site-packages from pip, which
# otherwise reports every dependency already satisfied from there and installs
# none of them into this interpreter. That leaves the pinned httpx and the
# httpcore whose internals browser_fp subclasses living in a directory this
# environment does not own and pip here will not manage - so `pip install -U
# httpx` under any *other* Python of the same minor version silently changes
# what the fingerprint interpreter loads. The version check in browser_fp
# would still fire, but only after the fact.
export PYTHONNOUSERSITE=1
"$PY" -m pip install --quiet --upgrade pip
"$PY" -m pip install --quiet "$ROOT/python"

# Optional, because it is ~25 further packages (cryptography, a Rust extension,
# tornado, flask, urwid) that nothing in mytls imports - only `capture-mitm`
# shells out to the `mitmdump` they provide. It goes into this interpreter
# rather than one of its own only because PYTHON_VERSION is now >= 3.12; the
# one shared dependency is h2, which mitmproxy pins at exactly 4.3.0 and which
# browser_fp has been measured against. mitmproxy's own TLS is unaffected by
# the fork - it goes through cryptography's statically linked OpenSSL and
# mitmproxy-rs, not through this Python's `ssl` - which is what you want: the
# proxy should look like a proxy, not like Chrome.
# A placeholder distribution for mitmproxy-linux, built and installed only if
# the honest install has already failed. mitmproxy-rs pins that package
# exactly, but it publishes manylinux wheels only - so on musl pip falls back to
# compiling its Rust/eBPF redirector, which wants a nightly toolchain and
# bpf-linker. Nothing in mitmproxy's Python imports it (only mitmproxy_rs'
# PyInstaller hook names it); it backs `mitmdump --mode local` alone, and
# capture-mitm uses --mode wireguard or a plain proxy. So the placeholder
# unblocks pip's resolver and raises NotImplementedError if anything ever does
# reach for the redirector, rather than pretending to be it.
install_mitmproxy_linux_placeholder() {
    local dir
    dir="$(mktemp -d)"
    trap 'rm -rf "$dir"' RETURN
    mkdir -p "$dir/mitmproxy_linux"
    cat > "$dir/pyproject.toml" <<'TOML'
[build-system]
requires = ["setuptools>=61"]
build-backend = "setuptools.build_meta"

[project]
name = "mitmproxy-linux"
version = "0.12.11"
description = "Placeholder: the real eBPF redirector has no musl wheel"
requires-python = ">=3.12"

[tool.setuptools.packages.find]
include = ["mitmproxy_linux"]
TOML
    cat > "$dir/mitmproxy_linux/__init__.py" <<'PY_EOF'
"""Placeholder installed by mytls' install-python.sh. Not the real package.

The real mitmproxy-linux ships a Rust/eBPF redirector and publishes manylinux
wheels only, so it cannot be installed on musl without a nightly toolchain and
bpf-linker. It serves `mitmdump --mode local` and nothing else, and no
mitmproxy Python module imports it. This exists to satisfy mitmproxy-rs' pinned
dependency, and fails loudly if the redirector is ever actually used.
"""

_WHY = ("mitmdump --mode local needs the real mitmproxy-linux, an eBPF "
        "redirector with no musl wheel. Use --mode wireguard or a plain proxy.")


class LocalRedirector:
    def __init__(self, *args, **kwargs):
        raise NotImplementedError(_WHY)

    @staticmethod
    def describe_spec(*args, **kwargs):
        return ""


def __getattr__(name):
    raise AttributeError(f"{name}: {_WHY}")
PY_EOF
    "$PY" -m pip install --quiet "$dir"
}

if [ "$WITH_MITMPROXY" -eq 1 ]; then
    say "installing mitmproxy into the same interpreter"
    mitm_ok=1
    if ! "$PY" -m pip install --quiet mitmproxy; then
        warn "the plain install failed. If it named mitmproxy-linux this is a
         musl system and that package has no musl wheel; retrying with a
         placeholder for it, which costs 'mitmdump --mode local' and nothing
         else."
        install_mitmproxy_linux_placeholder \
            && "$PY" -m pip install --quiet mitmproxy || mitm_ok=0
    fi
    if [ "$mitm_ok" -eq 1 ]; then
        printf '  mitmproxy %s at %s\n' \
            "$("$PY" -c 'from mitmproxy import version; print(version.VERSION)')" \
            "$(dirname "$PY")/mitmdump"
        printf '  h2        %s (mitmproxy pins this; browser_fp accepts it)\n' \
            "$("$PY" -c 'import h2; print(h2.__version__)')"
    else
        # Everything else in this script has already succeeded, so this warns
        # rather than dies - capture-mitm can be pointed at any mitmdump.
        warn "mitmproxy did not install. Put it in a venv of its own and use
         'capture-mitm --mitmdump /path/to/mitmdump'."
    fi
fi

# --- 6. check ---------------------------------------------------------------
# Linkage first, because getting this wrong is silent: a binary that resolves
# libssl somewhere else still runs, it just isn't our library, and the
# fingerprint is quietly the stock one. Both checks run with LD_LIBRARY_PATH
# unset on purpose - nothing here may depend on the caller's environment.
say "checking linkage"
check_links_to_prefix() {
    local what="$1" bin="$2" resolved
    if ! command -v ldd >/dev/null 2>&1; then
        return 0    # not Linux, or no ldd; the runtime checks below still apply
    fi
    resolved="$(libssl_of "$bin")"
    case "$resolved" in
        "$PREFIX"/*) printf '  %-9s: %s\n' "$what" "$resolved" ;;
        "")          die "$what does not link libssl at all ($bin)" ;;
        *)           die "$what resolves libssl to $resolved, not $PREFIX/lib.
         The build did not get its rpath - re-run without --skip-openssl." ;;
    esac
}

env -u LD_LIBRARY_PATH "$PREFIX/bin/openssl" version >/dev/null 2>&1 \
    || die "$PREFIX/bin/openssl cannot start without LD_LIBRARY_PATH set.
         Expected an rpath baked in; re-run without --skip-openssl."
check_links_to_prefix "cli" "$PREFIX/bin/openssl"
check_links_to_prefix "python" \
    "$("$PY" -c 'import _ssl; print(_ssl.__file__)')"

say "checking"
env -u LD_LIBRARY_PATH -u PYTHONNOUSERSITE "$PY" - <<'EOF'
import ssl
import sys
import sysconfig

print(f"  python  : {sys.version.split()[0]}")
print(f"  openssl : {ssl.OPENSSL_VERSION}")
if "3.4.0" not in ssl.OPENSSL_VERSION:
    sys.exit(f"  !! expected OpenSSL 3.4.0, this Python links {ssl.OPENSSL_VERSION}")

missing = []
for name in ("zlib", "_ctypes", "sqlite3", "lzma", "bz2"):
    try:
        __import__(name)
    except ImportError:
        missing.append(name)
print(f"  modules : {'all present' if not missing else 'MISSING ' + ', '.join(missing)}")

import mytls
from mytls import browser_fp

# Deliberately checked with the user site *visible*, the way anything running
# `python -m mytls` later will see it: an installed-but-shadowed dependency is
# a version this environment did not choose and pip here cannot update.
here = sysconfig.get_paths()["purelib"]
shadowed = []
for name in ("httpx", "httpcore", "h2", "hpack", "hyperframe"):
    mod = __import__(name)
    if mod.__file__ and not mod.__file__.startswith(here):
        shadowed.append(f"{name} from {mod.__file__.rsplit('/' + name, 1)[0]}")
if shadowed:
    print("  !! these load from outside this interpreter's site-packages, so "
          "pip here does\n     not manage them and another Python of the same "
          "minor version can change them:")
    for line in shadowed:
        print(f"       {line}")

print(f"  layers  : {mytls.check()}")

ctx = ssl.create_default_context()
names = [c["name"] for c in ctx.get_ciphers()]
print(f"  ciphers : {len(names)} ({'pinned OK' if len(names) == 15 else 'UNEXPECTED'})")

if not browser_fp.PROFILES:
    sys.exit(f"  !! no browser profiles in {browser_fp.PROFILES_DIR}")
# Building one per brand proves the httpcore subclassing still fits this httpx.
for brand, prof in sorted(browser_fp.PROFILES.items()):
    browser_fp.Transport(brand).close()
    print(f"  h2      : {brand} ({prof.label}) OK, akamai {prof.akamai_fingerprint}")
EOF

# --- 7. self-test -----------------------------------------------------------
# Linkage only proves we loaded the right library; this proves the library still
# emits the captured browsers' bytes. `hpack_probe.py selftest` stands up a
# local HTTP/2 server, drives our own client at it, and compares the
# ClientHello, the HTTP/2 frames and the HPACK block against every capture in
# python/profiles/. Entirely local: no network, no third-party service, and the
# same result on an air-gapped machine.
if [ "$SKIP_SELFTEST" -eq 1 ]; then
    warn "skipping the self-test; nothing has checked that the build still
         reproduces the captured browsers' bytes."
else
    say "self-test: our bytes vs every capture shipped in the package"
    ( "$PY" -m mytls.hpack_probe selftest \
        --openssl "$PREFIX/bin/openssl" ${PROBE_PORT:+--port "$PROBE_PORT"} ) \
        || die "this build does NOT reproduce the captured bytes - see the diff
         above. Every line should read OK and the HPACK block should be
         identical."
fi

cat <<EOF

$(say "done")
  python : $PY

  add to your shell rc if you want pyenv on PATH:
    export PYENV_ROOT="$PYENV_ROOT"
    export PATH="\$PYENV_ROOT/bin:\$PATH"
    eval "\$(pyenv init -)"

  the byte-level self-test above ran offline. the remaining check needs
  network, and is the only one that proves a real server agrees with us:
    "$PY" -m mytls.verify_fp            # h2 layer + header values
    "$PY" -m mytls.verify_fp --resume   # TLS layer incl. the PSK ext

  what is installed, and how to add a browser:
    "$PY" -m mytls                      # are both layers actually live?
    "$PY" -m mytls.hpack_probe serve    # then point any browser at it
EOF
