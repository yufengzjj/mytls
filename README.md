# mytls — a customised OpenSSL

A **fork of OpenSSL 3.4.0**. The changes are confined to the client handshake: how a
ClientHello is built is no longer compiled in, it is selected by a **profile**. The
`python/` directory adds a matching HTTP/2 layer.

Only the client side is touched — **server behaviour is unchanged**.

## Profiles

A profile is one set of client handshake parameters: the cipher list and its order,
supported_groups, signature_algorithms, supported_versions, certificate compression
algorithms, how many key_share entries to send, plus a few switches (whether to shuffle
the extension order, and whether to send ALPS, a GREASE ECH, an empty session_ticket, or
padding).

`ssl/ssl_fp_profile.c` is the only file that spells any of this out. Three are built in:
`chrome`, `chrome_android` and `safari_ios`.

```c
int         SSL_CTX_set_fp_profile(SSL_CTX *ctx, const char *name);
const char *SSL_CTX_get_fp_profile(const SSL_CTX *ctx);
int         SSL_set_fp_profile(SSL *s, const char *name);
const char *SSL_get_fp_profile(const SSL *s);
const char *SSL_fp_profile_name(size_t idx);   /* walks the built-in list, NULL past the end */
```

A profile set on an `SSL` overrides the one on its `SSL_CTX`, so a single process can hold
connections using different profiles at the same time. With none set, `chrome` is used.
There is also an SSL_CONF command, `FingerprintProfile`, exposed by `s_client` and
`s_server` as `-fp_profile` and settable from `openssl.cnf`:

```bash
openssl s_client -connect example.com:443 -fp_profile safari_ios
```

```ini
# or from a config file, for anything that reads one
openssl_conf = init
[init]
ssl_conf = ssl_sect
[ssl_sect]
mytls = mytls_sect
[mytls_sect]
FingerprintProfile = safari_ios
```

An unknown name is an error, not a silent fallback.

From Python:

```python
import httpx
import mytls

with httpx.Client(transport=mytls.Transport("safari_ios")) as client:
    r = client.get("https://example.com/")
```

That one line configures both the TLS layer and the HTTP/2 layer. To set only the TLS
layer, use `mytls.tls_profile`.

The Python side is a package — `pip install ./python` — so other projects can use it
without carrying this repository around. **But it is only half the machine**: the
HTTP/2 half is pure Python and works anywhere, the TLS half is built inside OpenSSL and
needs a CPython linked against this fork. `python -m mytls` says which halves are live.

**For the details, the tunables, and how to add a profile, see
[python/README.md](python/README.md).**

---

## Installing

Needs a Linux/WSL environment that can build OpenSSL and CPython. The Python you use
**must** be linked against the OpenSSL in this repository; otherwise the TLS layer still
behaves like the system OpenSSL.

### One command

```bash
./install-python.sh
```

Installs the build dependencies, builds and installs this fork, fetches pyenv if it is
missing, builds CPython against the fork, installs the Python packages, and runs the
self-test. Overridable variables and skip switches:

```bash
PREFIX=/opt/mytls PYTHON_VERSION=3.11.15 JOBS=8 ./install-python.sh
./install-python.sh --skip-deps --skip-openssl --skip-python --skip-selftest --yes
```

Defaults are `PREFIX=$HOME/openssl`, `PYTHON_VERSION=3.11.15`, `JOBS=$(nproc)`.

### By hand

```bash
# 1. the tree is a CRLF checkout - convert first on Linux
find . -path ./.git -prune -o -type f -print0 | xargs -0 sed -i 's/\r$//'

# 2. build and install
./Configure linux-x86_64 shared enable-brotli enable-weak-ssl-ciphers \
    --prefix=$HOME/openssl --libdir=lib --openssldir=/etc/ssl \
    '-Wl,-rpath,$(LIBRPATH)'
make -j"$(nproc)" && make install_sw

# 3. build Python against it
export MYTLS=$HOME/openssl
CONFIGURE_OPTS="--with-openssl=$MYTLS --with-openssl-rpath=auto" \
CPPFLAGS="-I$MYTLS/include" \
LDFLAGS="-L$MYTLS/lib -Wl,-rpath,$MYTLS/lib" \
MAKE_OPTS="-j$(nproc)" \
pyenv install 3.11.15

# 4. the Python side, which pulls its own pinned dependencies
pip install ./python          # or -e ./python to work on it in place
```

All three Configure options are required by the profiles:

* **`enable-brotli`** — the `chrome` profile uses brotli for certificate compression;
  without it, a server that compresses its certificate chain fails the handshake.
* **`enable-weak-ssl-ciphers`** — the `safari_ios` profile's cipher list contains 3DES
  suites, which are silently dropped without it.
* **`--openssldir=/etc/ssl`** — so `ssl.create_default_context()` finds the root
  certificates.

**httpx is pinned to 0.27.2** in the package metadata: `browser_fp` subclasses httpcore
internals, so a range there would turn a loud warning into a silent behaviour change on
somebody else's `pip install -U`.

Check the result:

```bash
python -m mytls        # both halves, in one line, plus the installed profiles
```

```
both layers ready - TLS profiles chrome, chrome_android, safari_ios
(OpenSSL 3.4.0); HTTP/2 profiles chrome, chrome_android, safari_ios.
```

Anything other than `both layers ready` means the Python being used is not linked against
this fork, and every ClientHello it sends will be Python's own.

---

## Testing

### Offline self-test

```bash
mytls-probe selftest                  # every profile
mytls-probe selftest --brand chrome   # just one
```

Stands up a server and drives our own client at it inside one process, then compares the
bytes that arrived against the reference, byte for byte. Needs no network. **Run this
after every change to the C side** — it is the only check that catches "I thought that
worked".

```
=== summary ===
  chrome           PASS
  chrome_android   PASS
  safari_ios       PASS
```

### Online check

```bash
mytls-verify --brand safari_ios
mytls-verify --brand chrome
```

Compares against what a third-party service makes of us. The self-test only measures our
own bytes against our own reference, so it cannot catch a mistake that runs through both.

### Do not run `make test`

This fork pins the cipher list, the signature algorithms and the certificate compression
algorithms, so 16 of the 31 configurations in `test_ssl_new` **necessarily fail** (measured
with the Configure line above):

```
02-protocol-version  04-client_auth  05-sni  07-dtls-protocol-version  10-resumption
11-dtls_resumption  14-curves  16-dtls-certstatus  19-mac-then-encrypt  20-cert-select
22-compression  23-srp  25-cipher  26-tls13_client_auth  28-seclevel
29-dtls-sctp-label-bug
```

That is the cost of the change, not a bug. To use it as a regression test, run the same set
against the commit before the change and compare **which** tests fail, not whether any do —
the profile work was checked that way and the failing set came out identical.

---

## Layout

| Path | Contents |
|---|---|
| `ssl/ssl_fp_profile.c` | the profile table — the only place a profile's parameters are written down |
| `ssl/ssl_grease.c` | GREASE values and extension-order randomisation |
| `python/` | the `mytls` package: the HTTP/2 layer, the browser captures, and the capture and verification tools — see [python/README.md](python/README.md) |
| `install-python.sh` | installs everything from scratch |

---

## Relationship to upstream

Forked from **OpenSSL 3.4.0**. The changes are mostly in
`ssl/statem/extensions_clnt.c`, `ssl/statem/extensions.c`, `ssl/ssl_lib.c` and
`ssl/t1_lib.c`, plus the new `ssl/ssl_fp_profile.c` and `ssl/ssl_grease.c`; ML-KEM hybrid
key exchange was added as well.

The upstream documentation is still in the tree and still applies wherever it is unrelated
to the fork: [INSTALL.md](INSTALL.md), [NOTES-UNIX.md](NOTES-UNIX.md),
[README-PROVIDERS.md](README-PROVIDERS.md), [CHANGES.md](CHANGES.md). The licence is
unchanged — see [LICENSE.txt](LICENSE.txt).
