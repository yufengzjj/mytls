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
#   PREFIX=/opt/mytls PYTHON_VERSION=3.11.15 JOBS=8 ./install-python.sh
#
# Flags: --skip-deps --skip-openssl --skip-python --skip-selftest --yes
#
set -euo pipefail

PREFIX="${PREFIX:-$HOME/openssl}"
PYTHON_VERSION="${PYTHON_VERSION:-3.11.15}"
PYENV_ROOT="${PYENV_ROOT:-$HOME/.pyenv}"
JOBS="${JOBS:-$( (nproc || sysctl -n hw.ncpu || echo 4) 2>/dev/null )}"
# Leave empty to let Configure detect the platform (works for x86_64 and arm64).
OPENSSL_TARGET="${OPENSSL_TARGET:-}"

SKIP_DEPS=0 SKIP_OPENSSL=0 SKIP_PYTHON=0 SKIP_SELFTEST=0 ASSUME_YES=0
for arg in "$@"; do
    case "$arg" in
        --skip-deps)     SKIP_DEPS=1 ;;
        --skip-openssl)  SKIP_OPENSSL=1 ;;
        --skip-python)   SKIP_PYTHON=1 ;;
        --skip-selftest) SKIP_SELFTEST=1 ;;
        --yes|-y)        ASSUME_YES=1 ;;
        -h|--help)      sed -n '/^# Build/,/^# Flags/p' "$0" | sed 's/^# \?//'; exit 0 ;;
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
    find . -path ./.git -prune -o -type f -print0 \
        | xargs -0 -P"$JOBS" -n200 sed -i 's/\r$//'
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
    ./Configure $OPENSSL_TARGET shared enable-brotli \
        --prefix="$PREFIX" --libdir=lib --openssldir="$ssldir" \
        '-Wl,-rpath,$(LIBRPATH)'

    grep -q "OPENSSL_NO_BROTLI" include/openssl/configuration.h 2>/dev/null \
        && warn "brotli support did NOT get enabled - a server that compresses
         its certificate chain will fail the handshake. Install the brotli
         development package and re-run."

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

# --- 5. Python packages -----------------------------------------------------
# httpx is pinned: python/browser_fp.py subclasses httpcore internals, and
# checks the version it got.
say "installing Python packages"
"$PY" -m pip install --quiet --upgrade pip
# socks: browser_fp's transports support socks5:// proxies, which need socksio.
"$PY" -m pip install --quiet "httpx[http2,socks]==0.27.2" brotli zstandard

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
    resolved="$(env -u LD_LIBRARY_PATH ldd "$bin" 2>/dev/null \
                | awk '/libssl\.so/ {print $3}')"
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
env -u LD_LIBRARY_PATH "$PY" - <<'EOF'
import ssl
import sys
from pathlib import Path

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

sys.path.insert(0, str(Path.cwd() / "python"))
import browser_fp  # noqa: E402

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
    say "self-test: our bytes vs every capture in python/profiles"
    ( cd "$ROOT/python" && "$PY" hpack_probe.py selftest \
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
    cd python && "$PY" verify_fp.py            # h2 layer + header values
    cd python && "$PY" verify_fp.py --resume   # TLS layer incl. the PSK ext

  what is installed, and how to add a browser:
    cd python && "$PY" hpack_probe.py list
    cd python && "$PY" hpack_probe.py serve   # then point any browser at it
EOF
