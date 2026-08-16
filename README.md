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

`ssl/ssl_fp_profile.c` is the only file that spells any of this out. Five are built in:
`chrome`, `chrome_android`, `ios18`, `ios16` and `ios26`.

The two iOS profiles are named for the **OS**, not for a browser, because none of this
belongs to a browser: every app that goes through NSURLSession or CFNetwork produces the
same ClientHello. That was checked rather than assumed — five unrelated clients captured on
one device (Safari, WhatsApp, the App Store, and Apple's telemetry and weather daemons)
produced no difference in the handshake at all, and no difference in the HTTP/2 fingerprint
either. `ios16` and `ios18` in turn differ in exactly one entry: `ios16` advertises
`ecdsa_sha1` (`0x0203`) among its signature algorithms and `ios18` does not.

`ios26` is the first Apple capture that is not a variation on those two. Its ClientHello is
1541 bytes where theirs are 517, and four things moved at once: the post-quantum hybrid
`X25519MLKEM768` leads its groups and carries a 1216-byte key share (two real shares now,
not one), TLSv1.1 and TLSv1.0 are no longer advertised, the three TLSv1.3 suites are
reordered with AES-256 first, and the padding extension is gone — at that size it would
never have fired. Its signature algorithms are iOS 18's, entry for entry.

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
openssl s_client -connect example.com:443 -fp_profile ios18
```

```ini
# or from a config file, for anything that reads one
openssl_conf = init
[init]
ssl_conf = ssl_sect
[ssl_sect]
mytls = mytls_sect
[mytls_sect]
FingerprintProfile = ios18
```

An unknown name is an error, not a silent fallback. To see the built-in list itself —
the same names `SSL_fp_profile_name()` walks, asked of the library rather than
hard-coded — run `mytls-probe list --tls`.

### One switch a profile does not get the last word on

A profile describes a *network stack*, and one extension turned out not to be the stack's
to decide. Measured on one iOS 16.7.12 device in a single capture session: connections
from the App Store's `amp-api-edge` and `xp.apple.com` sessions carry an **empty**
`session_ticket`, while the same device's connections to `is1-ssl.mzstatic.com`,
`fpinit.itunes.apple.com` and `weather-edge.apple.com` do not. Same OS, same cipher list,
same groups, same signature algorithms, identical HTTP/2 fingerprint — one extension
apart. That one extension moves the JA4 extension count from 14 to 15 and changes its
extension hash:

```
t13d2014h2_a09f3c656075_874d27d7ca63     without
t13d2015h2_a09f3c656075_8412ecd9826e     with
```

It is not resumption: the extension is zero bytes long, no session id is offered and no
`pre_shared_key` appears. It is only the *offer* to accept a TLSv1.2 ticket. So the caller,
who is the only one who knows which app is being imitated, gets to override the profile:

```c
# define SSL_FP_TICKET_PROFILE (-1)   /* whatever the profile says - the default */
# define SSL_FP_TICKET_OFF     0
# define SSL_FP_TICKET_ON      1

int SSL_CTX_set_fp_empty_ticket(SSL_CTX *ctx, int mode);
int SSL_CTX_get_fp_empty_ticket(const SSL_CTX *ctx);   /* the effective 0/1 */
int SSL_set_fp_empty_ticket(SSL *s, int mode);
int SSL_get_fp_empty_ticket(const SSL *s);
```

Like the profile itself, a value set on an `SSL` overrides its `SSL_CTX`, and the SSL_CONF
command `FingerprintEmptyTicket` exposes it to the CLI as `-fp_empty_ticket on|off|profile`:

```bash
openssl s_client -connect example.com:443 -fp_profile ios18 -fp_empty_ticket on
```

The getters report the effective answer — what the next ClientHello will do — rather than
the stored tri-state, since a caller that set the value already knows what it set.

### Every connection is a fresh handshake

A client built on this fork never resumes a TLS session. It is the one behaviour here
that is *not* a copy of a browser — every browser resumes — and it is deliberate: a
resumed ClientHello carries `pre_shared_key`, so the extension count moves and the JA4,
JA3 and peetprint hashes all change. That is a second fingerprint, and no capture in this
tree is of a resumed handshake, so there is nothing to check it against.

Rather than depend on the caller never asking, it is enforced in the library. The decision
sits in one place, `tls_construct_client_hello()`, so it covers all three ways to offer
resumption at once — TLSv1.3 `pre_shared_key`, a TLSv1.2 ticket, and a TLSv1.2 session id
— plus a second guard against an external PSK. Handing a session back explicitly does not
resume:

```python
c = ctx.wrap_socket(sock, server_hostname=host, session=earlier_session)
c.session_reused        # False
```

A profile can opt back in with `SSL_FP_ALLOW_RESUME`; none does today. Setting it is only
meaningful once a browser has actually been captured resuming, so that the resulting shape
has a capture to check against.

Note this is *not* done by turning tickets off. `SSL_OP_NO_TICKET` would drop the
`session_ticket` extension entirely, and Chrome sends an empty one on a fresh handshake —
that would cost an extension and change the very fingerprint being protected. The two are
separate settings on purpose: `SSL_CTX_set_fp_empty_ticket()` above decides whether that
empty extension is offered, and never enables resumption by doing so.

From Python:

```python
import httpx
import mytls

with httpx.Client(transport=mytls.Transport("ios18")) as client:
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
PREFIX=/opt/mytls PYTHON_VERSION=3.12.13 JOBS=8 ./install-python.sh
./install-python.sh --skip-deps --skip-openssl --skip-python --skip-selftest --yes
```

Defaults are `PREFIX=$HOME/openssl`, `PYTHON_VERSION=3.12.13`, `JOBS=$(nproc)`.

**If pyenv already has that version**, the script checks what it is linked against before
doing anything. Built by an earlier run of this script against the same prefix, it is
reused. Installed the ordinary way — linked against the system OpenSSL — it stops and says
so, because `pyenv install --skip-existing` would not rebuild it and the result would be a
client whose TLS layer is Python's own. Either `pyenv uninstall -f 3.12.13` and re-run, or
give `PYTHON_VERSION` a patch version pyenv does not already have.

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
pyenv install 3.12.13

# 4. the Python side, which pulls its own pinned dependencies
pip install ./python          # or -e ./python to work on it in place
```

All three Configure options are required by the profiles:

* **`enable-brotli`** — the `chrome` profile uses brotli for certificate compression;
  without it, a server that compresses its certificate chain fails the handshake.
* **`enable-weak-ssl-ciphers`** — the `ios18` profile's cipher list contains 3DES
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
both layers ready - TLS profiles chrome, chrome_android, ios18, ios16, ios26
(OpenSSL 3.4.0); HTTP/2 profiles chrome, chrome_android, ios16, ios18, ios26.
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
bytes that arrived against the stored capture — **as bytes, not as parsed fields**. The
HPACK block literally; the ClientHello outside the parts that are new on every connection
(client random, session id, key shares, GREASE values, the server name), each of which is
named in the output. Identical bytes make identical fingerprints, for every fingerprint,
so nothing here depends on how anyone computes one. Needs no network. **Run this after
every change to the C side** — it is the check that catches "I thought that worked".

```
=== summary ===
  chrome           PASS
  chrome_android   PASS
  ios16            SKIP (not replayable here)
  ios18            PASS
```

A profile whose capture came from a real site rather than from the local probe reports
`SKIP`: `ios16` was captured at `v.whatsapp.net:443`, which this machine neither holds nor
(unprivileged) can bind, so the request goes to localhost instead and the `:authority`
differs — which makes the HPACK block unable to match by construction. The HTTP/2 layer is
still compared in full; only the byte-exact half is skipped.

### Matching a raw capture against a profile

```bash
mytls-probe match ./captures                 # which profile produced each capture
mytls-probe match --brand ios16 ./captures   # only this one, and why it fails
```

Answers the other question from the self-test: not "is our client right" but **does this
recording come from the stack a profile describes**. Differences are split into ones that
mean a different stack (ciphers, extensions, SETTINGS, …) and ones an app chooses for
itself (the empty `session_ticket`), and the second kind never turns a match into a miss.
Offline.

Twenty captures from one iOS 16.7.12 phone — WhatsApp, the App Store, Apple's telemetry,
location and weather daemons — all match `ios16`, which is how the iOS profiles were shown
to belong to the OS rather than to Safari.

### SNI length sweep

```bash
mytls-probe sniscan                    # every profile, hostnames of 1..253 characters
```

The one thing the self-test cannot see. It compares against a capture taken at one
address, so it exercises one SNI length — but a padded profile computes its padding from
the total message length, which a longer hostname changes. Needs no server and no network.
The iOS profiles must land on exactly 517 bytes at every length that can reach it, and do:

```
  517B on the wire at every SNI length that can reach it: 1 to 205 chars
  (69 lengths), padding 205B down to 1B - OK
```

### Live check

```bash
mytls-verify                    # every installed profile
mytls-verify --brand ios18
```

Two things, neither of which is "is the fingerprint right" — the byte comparison above
settles that offline and better:

* **acceptance** — several real servers on unrelated TLS stacks complete the handshake and
  negotiate h2. A profile copies whatever the browser sent, a duplicate signature algorithm
  and three 3DES suites included, and loopback against our own OpenSSL never objects.
* **an outside parser** — tls.peet.ws and check.ja3.zone read the ClientHello we just sent
  and say what they made of it, compared against the same fingerprints computed from the
  capture's raw bytes.

Nothing is stored for it: the values to compare against are computed on the spot from
`profiles/<brand>.json`.

### Capturing a browser against a real site

`mytls-probe serve` captures a browser that visits us: it runs until Ctrl-C and dumps every
connection, and every request on it, into `./captures` for `mytls-probe import-mitm` to turn
into a profile. To capture a browser talking to a real site instead — where `referer`,
`cookie` and subresource priorities actually occur — there is a mitmproxy 12 addon that
relays the connection raw, below HTTP, so the HPACK bytes survive into the same kind of
dump:

```bash
mytls-probe capture-mitm --host 'example\.com' --brand chrome

# on a phone, also wave through what you are not capturing: pinned endpoints
# fail the handshake when intercepted, and the OS then retries and backs off
mytls-probe capture-mitm --brand ios16 --host 'whatsapp\.net$' \
    --ignore-hosts '.*\.apple\.com' --ignore-hosts '.*icloud\.com'
```

That starts `mitmdump` with the addon loaded (a separate process, though no longer a
separate Python — mitmproxy needs ≥ 3.12, which is what this script now builds), waits
while you browse, and imports the result on Ctrl-C. `./install-python.sh --with-mitmproxy` installs it into that same
interpreter; on musl one of its dependencies has no wheel and is stubbed out, which costs
`--mode local` only — see [python/README.md](python/README.md).

See [python/README.md](python/README.md) for what it can and cannot measure.

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
