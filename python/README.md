# The Python side: making httpx's HTTP/2 layer look like a real browser too

This OpenSSL fork takes care of the **TLS layer**. But once h2 is negotiated, a server can
still see two more fingerprints that have nothing to do with OpenSSL and are decided
entirely by Python:

* **The HTTP/2 frame layer** (the akamai fingerprint) — which SETTINGS are sent, in what
  order, with what values; the connection-level WINDOW_UPDATE; PRIORITY; the pseudo-header
  order. Decided by httpcore and h2.
* **The HPACK byte layer** — the same headers produce different bytes under different
  huffman/indexing policies. Decided by hpack.

Ignore those two and you get "the TLS half looks exactly like Chrome, and then h2 gives it
away in the first frame". This directory closes that gap.

**Not one line of code here is written for a particular browser.** Stand up a probe
address, visit it once with whichever browser you want, and that browser is stored as a
reference capture and gains a transport — nothing has to be named up front and no code
changes. To see what is currently installed:

```bash
mytls-probe list
```

The changes in here are **not equally important** — some can be verified against public
fingerprint hashes, others are done because they were cheap. Read
[three tiers of confidence](#three-tiers-of-confidence) before changing anything.

---

## Files

This directory is an installable package — `pip install ./python`, import name `mytls`.
The captures ship inside it, so a project that depends on it does not need this repository.

| File | Purpose |
|---|---|
| `pyproject.toml` | Package metadata. httpx is pinned exactly, and the captures are declared as package data |
| `mytls/__init__.py` | What `import mytls` gives you, plus `check()` — one line saying whether **both** layers are actually live |
| `mytls/browser_fp.py` | The main module. Provides a transport per brand; `catalog()` / `describe()` report what is installed and what each imitates |
| `mytls/hpack_probe.py` | Runs an h2 server that records the **raw ClientHello + h2 frames + HPACK bytes**; `serve` captures a visiting browser, `selftest` captures ourselves and diffs byte for byte. Installed as `mytls-probe` |
| `mytls/verify_fp.py` | The live check: real servers accept our handshake, and tls.peet.ws / check.ja3.zone are asked about us and compared against fingerprints computed on the spot from the profile's bytes. Nothing stored. Installed as `mytls-verify` |
| `mytls/mitm_addon.py` | A mitmproxy 12 addon that records the same raw bytes off a **real site** rather than off our own server. Runs under mitmproxy's interpreter, imports nothing from here; `mytls-probe import-mitm` turns its dumps into a profile |
| `mytls/tls_profile.py` | Selects the TLS-layer profile from Python (ctypes into libssl) |
| `mytls/fingerprints.py` | ja3 / ja4 / ja4_r / peetprint computed from a ClientHello's bytes — no service involved |
| `mytls/profiles/<brand>.json` | **One file per browser**; everything in `browser_fp` is derived from it |

**A brand is a browser (+ platform), not a browser version.** There is only
`chrome.json`, never `chrome150.json` — capturing again replaces it, and the version is
read off the capture's user-agent (`Profile.version`). Nobody ends up pinned to a stale
profile.

---

## Usage

```python
import mytls as fp
import httpx

with httpx.Client(transport=fp.transport("chrome")) as client:
    r = client.get("https://example.com/")
```

`fp.ChromeTransport()` is the same thing — the class name is synthesised from the brand
(`chrome_android` → `ChromeAndroidTransport`), and the async twins take an `Async` prefix:
`fp.AsyncChromeTransport()`, `fp.async_transport("chrome")`.

With only one profile installed the brand may be omitted (`fp.Transport()`). With several
installed and none named, it raises rather than guessing — guessing wrong means sending
the wrong fingerprint. To set a default:

```python
fp.DEFAULT_BRAND = "chrome"          # or the BROWSER_FP_BRAND environment variable
```

**Importing changes nothing by itself.** Only a client holding one of these transports
behaves like a browser; other clients in the same process are untouched, which makes a
direct comparison easy:

```python
httpx.Client(transport=fp.ChromeTransport())  # 1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p
httpx.Client(http2=True)                      # 1:4096;2:0;4:65535;5:16384;3:100;6:65536|16777216|0|m,a,s,p
```

### Proxies

Proxy arguments go on the **transport**, and the fingerprint still applies through one:

```python
transport = fp.ChromeTransport(proxy="http://user:pass@127.0.0.1:8080")
with httpx.Client(transport=transport) as client:
    client.get("https://example.com/")
```

`http://`, `https://` and `socks5://` all work, sync and async alike.

Measured: one request through a CONNECT proxy and one through a SOCKS5 proxy at the local
probe produced a ClientHello, h2 frames and HPACK block **identical to the direct
connection, all 455 bytes**; through both proxies to tls.peet.ws the akamai fingerprint
matched the direct one, while a client without the transport in the same process stayed
plain httpcore.

`socks5h://` **does not work** — httpx 0.27.2 itself rejects it (`Unknown scheme for proxy
URL`), which has nothing to do with this module. SOCKS5 needs `socksio`, which
`install-python.sh` installs (`httpx[http2,socks]`).

**One trap**: `verify`, `limits`, `proxy` and friends belong on the **transport**, not on
the Client — once httpx is given a transport it ignores its own:

```python
fp.ChromeTransport(verify=ctx, proxy=P)          # right
httpx.Client(transport=..., verify=ctx, proxy=P) # silently ignored
```

### Seeing what is being imitated

```python
>>> print(fp.catalog())
4 profile(s) in .../mytls/profiles:
  chrome          Chrome 150 on Windows        1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p
  chrome_android  Chrome 149 on Android        1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p
  ios16           iOS 16.7.12 network stack    4:2097152;3:100|10485760|0|m,s,p,a
  ios18           iOS 18.5 network stack       2:0;3:100;4:2097152;9:1|10420225|0|m,s,a,p

>>> print(fp.describe("chrome"))
chrome  (Chrome 150 on Windows)
  transport      : browser_fp.ChromeTransport() / transport('chrome')
  header values  : the caller's, none of its own
  ---- the capture, for reference / headers= ----
  user-agent     : Mozilla/5.0 (Windows NT 10.0; Win64; x64) ... Chrome/150.0.0.0 Safari/537.36
  sec-ch-ua      : "Not;A=Brand";v="8", "Chromium";v="150", "Google Chrome";v="150"
  platform       : Windows
  accept-language: en-US,en;q=0.9
  request kind   : navigate (captured_priority() reports 'navigate')
  captured prio  : navigate=w256/excl, xhr=w220/excl
  ---- what this transport imposes ----
  hpack          : quiche
  tls profile    : chrome
  session_ticket : whatever the OpenSSL profile does (the capture offered one)
  akamai         : 1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p
  akamai md5     : 52d84b11737d980aef856699f885ca86
  settings       : 1=65536, 2=0, 4=6291456, 6=262144
  window update  : 15663105
  headers prio   : none (no PRIORITY flag on HEADERS)
  derived from   : .../mytls/profiles/chrome.json
  captured at    : 2026-08-03T10:57:34+00:00
```

Same from the command line: `mytls-probe list`, `python -m mytls`.

The same content is available as a dict in `fp.profile("chrome").meta` (`brand`, `label`,
`browser`, `version`, `platform`, `user_agent`, `sec_ch_ua`, `akamai_fingerprint`,
`akamai_hash`, `source`, `captured_at`, …).

### Tunables

Three constructor arguments, plus one attribute. All of them land on the transport's own
copy of the profile, so setting one does not leak into other transports of the same brand:

```python
# 1. header values are the caller's; this is how you ask for the capture's own
t = fp.Transport("chrome", headers=fp.profile("chrome").headers)

# 2. the HEADERS frame's RFC 7540 priority
t = fp.Transport("ios18", priority=None)                    # never set the flag
t = fp.Transport("ios18", priority={"exclusive": False,     # or spell it out
                                         "depends_on": 0,
                                         "weight": 255})
t = fp.Transport("ios18")                                   # "capture" - the default

# 3. whether the ClientHello offers an empty session_ticket extension
t = fp.Transport("ios18", session_ticket=True)              # or False, or "capture"

# 4. which captured request describe() and captured_priority() report
t = fp.Transport("chrome")
t.profile.header_profile = "xhr"             # or "navigate" (the default)
```

Each of the first three is three-state, and the third state is not decoration. `"capture"`
(the module constant `fp.FROM_CAPTURE`) means *reproduce what was recorded*, which is a
different instruction from `None`/`False` meaning *send nothing*: "the browser sent no
PRIORITY flag" and "nobody measured whether it did" must not collapse into the same value.

To "put things back", simply do not use the transport.

**There are no version constants and no hardcoded akamai constants.** The SETTINGS, the
WINDOW_UPDATE, the HPACK policy and the pseudo-header order are all **derived** from
`profiles/<brand>.json` — see [adding a browser](#adding-a-browser). The headers are in
there too (the UA, `sec-ch-ua`, `accept`, `sec-fetch-*`, and their order) but purely as
*reference data*: the library sends none of it unless you hand it back via `headers=`.

#### Why priority and session_ticket are arguments and not profile data

Both were measured to vary **between apps on one device running one OS build**, which is
what disqualifies them from the profile: a profile records a network stack, and neither of
these belongs to the stack.

From one iOS 16.7.12 capture session, five different clients (App Store, its image loads,
Apple's telemetry and location daemons, Weather, WhatsApp) — every one of them produced
the identical akamai fingerprint `4:2097152;3:100|10485760|0|m,s,p,a`, and disagreed on:

| client | HEADERS flags | priority | empty `session_ticket` |
|---|---|---|---|
| `is1-ssl.mzstatic.com` (App Store icons) | `0x25` | excl=0 dep=0 **w=255** | no |
| `weather-edge.apple.com` | `0x24` | excl=0 dep=0 **w=24** | no |
| `amp-api-edge` / `xp.apple.com` | `0x04` | none | **yes** |
| `v.whatsapp.net` | `0x04` | none | no |

The weight tracks `URLSessionTask.priority`: image loads run at the top, a background
weather refresh near the bottom. So both the *presence* of the flag and the *weight* are
the app's, and are yours to set here.

Practical consequence: a stored profile reproduces any app on that OS version only once you
supply these two. Getting them is one capture of the app you actually want — see
[capturing from a real site](#capturing-from-a-real-site-instead-mitmproxy).

---

## Prerequisites

The Python you use **must** be linked against the OpenSSL in this repository; otherwise
only the h2 layer looks like a browser and the TLS layer is still the system OpenSSL's.
`./install-python.sh` builds the whole thing in one command. By hand:

```bash
# 1. build and install this repository (it is a CRLF checkout - convert first on Linux/WSL)
find . -path ./.git -prune -o -type f -print0 | xargs -0 sed -i 's/\r$//'
./Configure linux-x86_64 shared enable-brotli enable-weak-ssl-ciphers \
    --prefix=$HOME/openssl --libdir=lib --openssldir=/etc/ssl
make -j4 && make install_sw

# 2. build Python against it
export MYTLS=$HOME/openssl
CONFIGURE_OPTS="--with-openssl=$MYTLS --with-openssl-rpath=auto" \
CPPFLAGS="-I$MYTLS/include" \
LDFLAGS="-L$MYTLS/lib -Wl,-rpath,$MYTLS/lib" \
MAKE_OPTS="-j4" \
pyenv install 3.11.15

# 3. this package, which pulls its own pinned dependencies
pip install ./python
```

**`pip install` alone is not enough, and the package says so.** Installed against any other
Python it still sends the browser's frames, headers and HPACK bytes — and a ClientHello
that looks like Python's, which is worse than not pretending at all, because the two layers
then contradict each other. So check before trusting it:

```bash
python -m mytls
# both layers ready - TLS profiles chrome, chrome_android, ios18, ios16 (OpenSSL 3.4.0); ...
# TLS layer: NOT ACTIVE - OpenSSL 3.5.7 has no fingerprint profiles, so every
#            ClientHello will be Python's own. HTTP/2 layer: ready (...).
```

The same verdict is `mytls.check()`, and building a transport for a brand the C library has
no profile for warns on the spot. It is deliberately **not** an ImportError: `fingerprints`,
the capture tools and the whole h2 layer are genuinely useful on a stock Python.

* `enable-brotli` is required — the chrome profile advertises brotli certificate
  compression, and without it a server that compresses its certificate chain (some
  Cloudflare configurations) fails the handshake.
* `enable-weak-ssl-ciphers` is required too — **iOS still offers three 3DES suites**.
  Without them the ClientHello carries 17 cipher suites instead of 20 and the ja4 comes out
  `t13d1714` instead of `t13d2014`, which is a fingerprint of its own. Only a profile that
  lists them offers them (the chrome profile does not), but a server really could
  negotiate 3DES on an ios18 connection — exactly as it could with the real browser.
* `--openssldir=/etc/ssl` lets `ssl.create_default_context()` find the root certificates
  without passing `cafile=` everywhere.
* **httpx is pinned to 0.27.2.** This module reaches into httpcore internals, and a
  different version triggers `warnings.warn`.

Confirm the build:

```python
import ssl; print(ssl.OPENSSL_VERSION)   # should be OpenSSL 3.4.0
```

---

## Adding a browser

Start the server, visit it once with the browser you want, done. **Nothing has to be named
up front and no Python code changes**:

```bash
mytls-probe serve
```

```
:: visit it once with the target browser (Chrome on Windows, fresh profile so that
:: no cookies or extensions get in the way)
"C:\Program Files\Google\Chrome\Application\chrome.exe" ^
  --user-data-dir=%TEMP%\cfp --ignore-certificate-errors ^
  https://localhost:8443/api/all
```

Chrome shows a yellow `You are using an unsupported command-line flag` bar — that means
the flag **took effect**, it is not an error. A phone has to reach a LAN address and has a
few more pitfalls; see [phones](#phones).

```
listening on :8443 - waiting for any h2 client
  captured from 192.168.1.19: Mozilla/5.0 (Linux; Android 10; K) ... Chrome/149.0.0.0 Mobile Safari/537.36
  stored as .../profiles/chrome_android.json
  ...
chrome_android  (Chrome 149 on Android)
  transport      : browser_fp.ChromeAndroidTransport() / transport('chrome_android')
```

**One visit produces one file.** `profiles/<brand>.json` gets the raw bytes — the whole
ClientHello, every h2 frame, the HPACK blocks — and that is the entire capture. Opening the
page is the whole procedure; there is nothing to fetch, paste or read.

There used to be a second file, `references/<brand>.json`, holding what tls.peet.ws and
check.ja3.zone made of the same browser, collected in the same visit through a page that
asked the browser to fetch them and post the answers back. **That is gone**, along with
`--peet`, `--both`, the paste box and the CORS workarounds.

It went because of what the self-test became. The only property worth having is *the bytes
we emit are the bytes that were captured*, and that is now checked **as bytes**
([here](#all-three-layers-are-compared-as-bytes-not-as-fields)). Identical bytes make
identical fingerprints — every fingerprint — so a stored third-party opinion answers a
question nobody needs to ask.

What `mytls-verify` still wants from an outside service, it now asks **live**, of our own
client, and compares against fingerprints computed on the spot from the profile's raw
bytes. That needs nothing stored, and it fixed a hole: a brand captured through mitmproxy
could never have had a reference at all, because a third-party service behind an
intercepting proxy reports *mitmproxy's* TLS, not the phone's. `ios16` is such a brand and
now verifies like any other.

**The brand is whatever the client says it is**, read off the `user-agent` of the request
that just arrived:

| Who visited | Stored as |
|---|---|
| Desktop Chrome | `chrome` |
| Android Chrome | `chrome_android` |
| iPhone, iOS 18 | `ios18` |
| iPhone, iOS 16 | `ios16` |
| Firefox / Edge / Opera / Vivaldi / Samsung / Yandex | `firefox` / `edge` / `opera` / … |

If it cannot be identified (curl, say) the capture is left in `capture.json` and you are
asked to name it with `--brand`; `--brand` also simply overrides the automatic choice.
Right after capturing, the new brand is printed (the `describe()` output), and at that
point:

```python
fp.transport("chrome_android")     # already works
fp.ChromeAndroidTransport()        # already works
```

**Where a capture lands depends on how the package was installed.** `serve` writes into
`mytls/profiles/` *inside the installed package* — with `pip install ./python` that is
site-packages, and the new brand is invisible to git. Work on this repository with an
editable install so captures land in the tree:

```bash
pip install -e ./python
```

To try one out without committing it to the tree, point `BROWSER_FP_PROFILES` at another
directory — `serve` honours it too, so the capture lands straight there.

**What is derived automatically:**

| | Source |
|---|---|
| the header set and order (and, as reference data only, the UA / `sec-ch-ua` / `accept` / `sec-fetch-*` values) | the HPACK block of the HEADERS frame |
| browser name / version / platform (`label`, `meta`) | the UA and `sec-ch-ua-platform` |
| the HEADERS priority of an **xhr** (`captured_priority("xhr")`) | the page's own `/xhr-sample` request, which the capture keeps alongside the navigation |
| the SETTINGS ids / order / values | the SETTINGS frame |
| the connection-level WINDOW_UPDATE (0 = not sent) | the WINDOW_UPDATE frame |
| the HEADERS priority (absent → no PRIORITY flag) | the HEADERS frame's flags |
| the pseudo-header order (the last akamai field) | the `:`-prefixed fields in the HPACK block |

**What is *not* automatic: the TLS layer.** A new brand covers everything above without a
code change, but the ClientHello comes from the C library, which only knows the profiles
compiled into `ssl/ssl_fp_profile.c`. Capture a browser it has never heard of and
`describe()` says so —

```
tls profile : chrome_android - NOT IN OpenSSL (chrome, ios18); the ClientHello will be the default one
```

— and the two layers then disagree, which is worse than not pretending at all. Adding the
profile is usually small: `chrome_android` needed one signature-algorithm list and nothing
else. See [the TLS-layer profile switch](#the-tls-layer-profile-switch).

**The rest is done this way because hand-written constants rot.** Chromium permutes the
brand list in `sec-ch-ua` every major release — Chrome 150 leads with `"Not;A=Brand";v="8"`,
older versions had `"Not_A Brand";v="99"` at the end — and a mistyped akamai number is
invisible. Neither mistake is possible any more.

**The one thing that is guessed: the HPACK encoding policy.** A capture can tell you the
guess was wrong (the bytes differ) but not what the right rule is, so it is guessed from
the UA: everything Chromium gets `quiche`, everything else gets hpack's own (`stock`).
Override it in the capture json with `"meta": {"hpack": "quiche"}`. **The way to find out
is to run `selftest`** — a wrong guess shows up as a difference in the HPACK section while
every other layer is still right. Only quiche's rules are implemented; another engine has
to be added by hand.

### The TLS-layer profile switch

The C side is no longer "Chrome at compile time". `ssl/ssl_fp_profile.c` is the **only**
file that spells out what a given browser sends, and which one is in force is decided by
this API (a profile on an `SSL` overrides the one on its `SSL_CTX`, so one process can
hold Chrome connections and iOS connections at the same time):

```c
int         SSL_CTX_set_fp_profile(SSL_CTX *ctx, const char *name);
const char *SSL_CTX_get_fp_profile(const SSL_CTX *ctx);
int         SSL_set_fp_profile(SSL *s, const char *name);
const char *SSL_get_fp_profile(const SSL *s);
const char *SSL_fp_profile_name(size_t idx);   /* walks the built-in list, NULL past the end */
```

There is also an SSL_CONF command, `FingerprintProfile`, which `s_client` and `s_server`
expose as `-fp_profile` and which can equally come from `openssl.cnf` — C-side regression
testing does not have to drag Python in:

```bash
openssl s_client -connect localhost:8443 -fp_profile ios18
```

Verified against the probe: no flag sends 16 cipher suites in a 1744-byte ClientHello,
`-fp_profile ios18` sends 21 in a 517-byte one (the padding rule firing), and an
unknown name fails loudly rather than falling back.

**The Python side does not have to think about any of this**: `Transport("ios18")`
sets the TLS profile as well, and `transport.tls_profile` reads back what actually took
effect. `tls_profile.py` is only needed when driving OpenSSL by hand:

```python
import ssl
from mytls import tls_profile

ctx = ssl.create_default_context()
tls_profile.set_profile(ctx, "ios18")
print(tls_profile.available())        # ('chrome', 'chrome_android', 'ios18', 'ios16')

# the one profile setting the caller can override, see Tunables above
tls_profile.set_empty_ticket(ctx, True)          # or False, or PROFILE_DEFAULT
print(tls_profile.get_empty_ticket(ctx))         # the effective answer, not the override
```

CPython's `ssl` module has no SSL_CONF passthrough of any kind, so this is a direct ctypes
call. Two things matter: **dlopen the `_ssl` extension module itself**
(`ctypes.CDLL(_ssl.__file__)` — dlsym searches a handle's dependency chain, so this
reaches exactly the libssl `ssl` is linked against; loading one by name can find a
*different* OpenSSL, and reading our pointers with its API segfaults); and once the
`SSL_CTX*` is in hand, **cross-check it with `SSL_CTX_get_options` against `ctx.options`**
before writing through it, raising rather than proceeding if they disagree. When the C
library has no matching profile, `Transport` **warns loudly** rather than staying silent —
a client whose two layers disagree is more identifiable than one that never pretended.

A profile carries **only the fields that have been converted**; anything not yet converted
is still compiled in and therefore applies to every profile. So a new profile becomes true
gradually, and the number of ClientHello differences in `selftest` is the progress bar.

### Android Chrome's ClientHello (measured, Chrome 149 / Android)

It differs from the desktop capture in **exactly one field**: the signature algorithms.

```
desktop  0904,0905,0906,0403,0804,0401,0503,0805,0501,0806,0601   (11)
android               0403,0804,0401,0503,0805,0501,0806,0601   ( 8)
```

`0904`–`0906` are the ML-DSA codepoints. Everything else is the same list: fifteen cipher
suites, sixteen extensions including ALPS `44cd` and a GREASE ECH `fe0d`, groups led by
`X25519MLKEM768`, TLS 1.3 and 1.2 only, brotli certificate compression. The HTTP/2 layer is
identical too, down to `akamai_fingerprint_hash = 52d84b11737d980aef856699f885ca86`. So
`fp_profile_chrome_android` writes out its own signature algorithms and **references** the
desktop profile's other lists rather than copying them.

**Platform and version are confounded here**: the desktop capture is Chrome 140 and this
one Chrome 149, so whether those three codepoints are missing because it is Android or
because it is newer is not established. Reproducing the capture does not require knowing.

Verified by computing both ClientHellos' fingerprints (`fingerprints.py`) and comparing:
`ja4`, `ja4_r`, `peetprint` and `peetprint_hash` are identical to the phone's. `ja3_hash`
is not, and cannot be — Chrome shuffles its extension order per connection, so the phone's
own two visits disagree with each other as well. Field by field the ja3 differs only in
extension order; the extension *set* matches.

### The iOS ClientHello (measured, iOS 18.5 and iOS 16.7.12)

Captured four times, varying the SNI length to isolate the rules, as the specification for
the C side:

| | Value |
|---|---|
| ja4 | `t13d2014h2_a09f3c656075_7f0f34a4126d` |
| ciphers | 20 + GREASE, keeping CBC, static RSA and **3DES** (`c008`/`c012`/`000a`) |
| supported_groups | X25519, P-256, P-384, **P-521** (no ML-KEM) |
| key_share | **X25519 only**, one real share (+ GREASE, 1 byte) |
| supported_versions | 1.3, 1.2, **1.1, 1.0** (+ GREASE) |
| compress_certificate | **zlib** (Chrome uses brotli) |
| Never sent | ALPS, ECH; `session_ticket` by default — but see below |
| Unique to it | `padding` (21) |

**Nothing about this is Safari's.** The profiles are named `ios18` and `ios16` for the OS,
not for a browser, because every app on NSURLSession or CFNetwork produces the same
handshake. Checked, not assumed: five unrelated clients captured on one 16.7.12 device —
Safari, WhatsApp, the App Store (its API *and* its image loads), Apple's telemetry daemon
and Weather — agreed on every field of the ClientHello and on the akamai fingerprint.
An app that bundles its own stack (cronet, a private BoringSSL, Flutter) will **not** match,
and comparing its ja4 against the value below is how to find that out.

**One profile per iOS version, though.** Apple changes the signature algorithms between
releases: iOS 16.7.12 and iOS 18.1.1 both advertise 11 including `0203` (ecdsa_sha1),
iOS 18.5 advertises 10 without it — which is the *only* difference between the `ios16` and
`ios18` profiles, and the only difference found between the two captures at all: same 21
cipher suites in the same order, same five groups, same 16 extensions in the same order,
both padded to 512 bytes. **JA3 cannot see the difference at all**, because it
hashes the list of extension *types* and never looks at what is inside them; signature
algorithms are not part of JA3 in any form. JA4's third field is a hash over the sorted
extension list plus the signature algorithms in order, so it does change - see the table
below. Two captures with an identical JA3 can therefore be different builds, which is the
argument for capturing a profile rather than copying one out of a blog post, and for
re-capturing after the phone updates.

**But the version does not pin everything.** `session_ticket` varies *between apps on one
device*. Thirteen connections captured in one session on an iOS 16.7.12 phone split cleanly
in two, and the only difference anywhere in the ClientHello is extension `0x0023`:

```
t13d2014h2_a09f3c656075_874d27d7ca63   mzstatic, fpinit.itunes, iadsdk, weather-edge
t13d2015h2_a09f3c656075_8412ecd9826e   amp-api-edge, amp-api-search-edge, xp.apple.com ×6, gsp-ssl.ls
```

Same cipher hash, same groups, same signature algorithms, same akamai fingerprint — and it
is **not** resumption: the extension is zero bytes long, `session_id` is empty and no
`pre_shared_key` is offered. It is only the offer to accept a TLSv1.2 ticket, which the app's
`URLSession` configuration decides. It is stable per host: all six `xp.apple.com`
connections agree, both `amp-api` connections agree.

`Transport(session_ticket=True|False)` picks a side; the stored `ios18` and `ios16`
profiles are both in the *without* group, matching what Safari and WhatsApp were measured
doing. See [Tunables](#tunables).

**Only ever compare JA4 against JA4 from the same tool.** `tls.peet.ws` leaves the padding
extension out of the `ja4_r` extension list while still counting it in the `14` prefix;
Wireshark includes it in both. That alone changes the third field, independently of
anything the client did, and by more than a version bump does:

| third field | `ios16` (11 sigalgs) | `ios18` (10 sigalgs) |
|---|---|---|
| `tls.peet.ws` (no `0015`) | `874d27d7ca63` | **`7f0f34a4126d`** |
| Wireshark (`0015` included) | `14788d8d241b` | `e42f34c56612` |

The 11-sigalg column was first derived by hand from an iOS 18.1.1 capture and has since
been confirmed off the wire: the iOS 16.7.12 captures reproduce `874d27d7ca63` exactly, and
so does the `ios16` profile emitting its own ClientHello.

The bold value is what `fingerprints.of_client_hello()` reports as `ja4`; the cell below it
is its `ja4_padding_counted`, so whichever tool a capture came from, its answer is
available. All four were reproduced from `sha256(sorted_extensions + "_" + sigalgs)[:12]` — the
top row by hand, both 18.5 cells by `fingerprints.py` running on our own client's bytes — so
a mismatch is worth resolving to one of these cells before concluding the profile is wrong.

**The extension order is fixed, not shuffled** (Chrome has shuffled per connection since
110). Four independent connections to two different servers produced the identical order,
with `server_name` always second. That makes the iOS **JA3 hash stable and comparable** —
so `ossl_ssl_ext_permutation` on the C side has to be switchable per profile, and the "do
not compare the JA3 hash" exemption in `verify_fp.py` has to tighten into a real
comparison for the iOS profiles.

```
GREASE, server_name, extended_master_secret, renegotiation_info, supported_groups,
ec_point_formats, ALPN, status_request, signature_algorithms, SCT, key_share,
psk_key_exchange_modes, supported_versions, compress_certificate, GREASE[, padding]
```

**The padding rule: pad the handshake message to exactly 512 bytes (record 517) when it
would be shorter, and send no padding extension at all when it would be longer.** Four
points, measured with variable-length SNIs via `nip.io`:

| server_name length | SNI extension | padding | record total |
|---:|---:|---:|---:|
| 0 (an IP, no SNI) | 0B | 217B | 517B |
| 18 | 27B | 190B | 517B |
| 39 | 48B | 169B | 517B |
| 251 | 260B | **not sent** | **556B** |

The last row was predicted before it was measured: without padding the CH body is 547, so
the record should be 556 — measured 556, with the extension count dropping from 16 back to
15 and the padding gone entirely. **That boundary is reached in real use**: a return visit
carrying a session ticket adds a PSK extension of two or three hundred bytes, which pushes
the ClientHello past 512.

(The `padding_data_length: 394` reported by `tls.peet.ws` is not a byte count, it is the
length of the hex string — under the 512 rule that connection should have been 197 bytes,
exactly half. Do not compare against its number directly.)

### Phones

A phone cannot reach `localhost`, so it needs a LAN address, and the certificate has to
carry that address:

```bash
mytls-probe serve --host 192.168.1.7
```

`--host` does two things: it goes into the certificate's SAN, and it is printed as the URL
to open. This machine's own addresses are detected and added to the SAN automatically, so
`--host` is usually unnecessary; **give it when the address the phone sees is not an
address of this machine**, for instance under WSL2's default NAT mode where the phone can
only reach the Windows host's IP. In that case `serve` says so and prints the
`netsh interface portproxy` command (WSL2 can also be put into
`networkingMode=mirrored` in `.wslconfig`, after which this machine's address is the
Windows one and nothing needs forwarding).

The SAN **accumulates**: a later run without `--host` does not lose addresses an earlier
run added, because re-issuing the certificate means every phone that trusted it has to
trust it again. When it really is re-issued, a line says so.

**iOS is stricter about certificates than the desktop.** Since iOS 13 a server certificate
with no SAN (CN only), without `extendedKeyUsage=serverAuth`, or valid for more than 398
days is rejected outright — **without even offering "visit anyway"**. `ensure_cert` now
satisfies all three (30-day validity). To install it:

1. Open `http://<ip>:8000/cert.pem` in the iPhone's Safari (serve that file with any static
   server; it lives at `~/.cache/hpack_probe/cert.pem`) — it offers to download a profile;
2. Settings → General → VPN & Device Management → install it;
3. **And also** Settings → General → About → Certificate Trust Settings, and turn its
   switch on — skipping this step is the same as not installing it.

Installing is optional: Safari offers "Show Details → visit this website". The rejected
connection sends no HEADERS, so what gets captured is the one after you confirm, and the
fingerprint is unaffected.

**A phone needs no interaction beyond opening the page** — the capture is the bytes that
arrived, nothing else. Nothing asks the person holding it to fetch a service or paste JSON,
which used to be unavoidable on iOS (there is no `--disable-web-security` there).

**Note that the address used for the capture becomes part of the fingerprint.** The
`:authority` goes into the HPACK block verbatim, and its host half decides whether an SNI
is sent at all — an IP address carries none, a name does. So a capture taken at
`192.168.1.7:8443` can only be reproduced from `192.168.1.7:8443`:

```bash
mytls-probe where ios18     # → 192.168.1.7:8443
```

`selftest` goes to that address by itself. If the address is no longer on this machine
(DHCP moved it, or it was the Windows IP at the time), it says so and falls back to
localhost — the HPACK difference and the one SNI extension are then expected, and the h2
layer is still compared in full:

```
note: ios18 was captured at 192.168.1.7, which is not an address this machine
holds, so the request goes to localhost instead. :authority differs, so the HPACK
block cannot match, and the capture carried no SNI while this one does, so the
ClientHello will differ by one extension. The HTTP/2 layer is still compared in full.
```

Run the self-test after capturing; it compares all three layers at once:

```bash
mytls-probe selftest --brand firefox
```

```
=== ClientHello ===          ← differences here mean changing C and rebuilding
=== HTTP/2 frame layer ===   ← differences here mean the capture was not consumed
=== HPACK header block ===   ← byte for byte
```

### All three layers are compared as bytes, not as fields

The only property worth having is **the bytes we emit are the bytes that were captured**.
If that holds, every fingerprint computed from them — ja3, ja4, peetprint, or one nobody
has published — is equal by construction, and there is nothing to look up about how any
particular service computes anything.

The HTTP/2 half is literally that: the HPACK block is compared byte for byte.

A ClientHello cannot be, because parts of it are new on every connection. So the
comparison **blanks those parts and compares every remaining byte**, and prints exactly
what it blanked:

```
=== ClientHello ===
  ios18 517B, ours 517B
  not compared (ios18, 137B of 517): GREASE cipher 2B, GREASE codepoint 4B,
    GREASE extension id 4B, GREASE key_share group 2B, client_random 32B,
    handshake_length 3B, key_share key 33B, record_length 2B, server_name 23B,
    session_id 32B
  extension order  identical
  bytes            IDENTICAL outside the regions above
```

Two things are **asserted rather than blanked**, because blanking them would hide 190
bytes of an iOS ClientHello: `padding` must be all zeroes (RFC 7685), and a GREASE
extension's body must be empty or a single zero byte.

This replaced a comparison of a hand-written list of fields, which had the failure a
field list always has — it silently ignored anything nobody thought to list.
`compression_methods` was never compared by it. Measured, by mutating a stored capture one
byte at a time:

| mutation | old field list | byte comparison |
|---|---|---|
| one signature algorithm changed | caught | caught |
| one cipher suite changed | caught | caught |
| **`compression_methods` changed** | **missed** | **caught** |
| `padding` no longer all zeroes | missed | caught (assertion) |
| one ALPN byte flipped | caught | caught |
| `client_random` / `session_id` changed | ignored | ignored |

It also checks itself in a way a field comparison cannot. Finding the variable regions
means walking the message, and walking it wrongly blanks the wrong bytes — which makes the
comparison **fail loudly**, rather than making a difference invisible.

Extension *order* is reported on its own line instead of being sorted away, because Chrome
is meant to shuffle it and iOS is meant not to:

```
  extension order  SHUFFLED - same 18 extensions, different order. Correct only for
                   a profile that sets SSL_FP_SHUFFLE_EXTS (Chrome does; iOS does not)
  bytes            IDENTICAL as a multiset (order shuffled, see above)
```

### `match` — which stack produced a capture

`selftest` asks "is our client right". This asks the other question: **does this recording
come from the stack a profile describes?** Point it at a directory of raw captures — mitm
dumps, `serve` profiles, `--out` files — and it says which profile, if any, produced each.

```bash
mytls-probe match ./captures                 # every installed profile
mytls-probe match --brand ios16 ./captures   # only this one, and why it fails
mytls-probe match a.json b.json ./more       # any mix of files and directories
```

Offline, no server, no network.

```
amp-api-edge.apps.apple.com-d2a300e1.json
  amp-api-edge.apps.apple.com  alpn=h2
  ja3=fb3660676bafc9799c86bd51a1ea12f5  ja4=t13d2015h2_a09f3c656075_8412ecd9826e
  akamai=4:2097152;3:100|10485760|0|m,s,p,a
  ios16            MATCH [app-controlled: 0x0023 in the capture, not in the profile]

=== 20 file(s) ===
  ios16            20 match(es)
```

**The three fingerprints are reported, not compared.** The verdict comes from the fields
themselves — a hash could only be a lossier way of asking the same question. They are
printed because between them they place a capture at a glance, and because the ways they
*disagree* are informative:

```
ios16.json    ja3=773906b0efdefa24a7f2b8eb6985bf37  ja4=t13d2014h2_a09f3c656075_874d27d7ca63
ios18.json    ja3=773906b0efdefa24a7f2b8eb6985bf37  ja4=t13d2014h2_a09f3c656075_7f0f34a4126d
                  ^ identical                            ^ differs
```

Same JA3, different JA4: JA3 does not cover signature algorithms **in any form**, and one
`ecdsa_sha1` entry is the entire TLS difference between the two iOS versions. A JA3-only
check cannot tell an iOS 16 device from an iOS 18 one.

```
chrome.json          ja3=7a1441d2dbeaba319d9089e6b6262fd5
chrome_android.json  ja3=d3bd10e919ccd32e472be06999b1db0d
```

These two also differ by nothing but signature algorithms, so their JA3s ought to be equal
— and are not, because Chrome shuffles its extension order per connection and JA3 hashes
that order. The difference is noise from two different connections, not a property of
either client. `match` is unaffected either way: it compares the extension order itself and
knows the difference between a shuffle and a different set.

**Differences come in two kinds, and the tool keeps them apart**, because they answer
different questions:

* a **stack** difference — cipher list, extension order, groups, signature algorithms,
  SETTINGS, window, pseudo-header order — means a different network stack, or a different
  version of one. It is a miss.
* an **app-controlled** difference — currently the empty `session_ticket` (`0x0023`) —
  means the same stack configured differently by the app. It is reported and never turns a
  match into a miss. See [Tunables](#tunables) for how to reproduce it.

This is the tool that settles "is this app on the system stack or does it carry its own?".
All twenty captures taken from one iOS 16.7.12 phone — WhatsApp, the App Store's API and
its image loads, Apple's telemetry, location and weather daemons — match `ios16`, which is
what established that the iOS profiles belong to the OS and not to Safari. An app bundling
cronet or its own BoringSSL would not match at all.

It discriminates at the resolution of a single entry. Each stored profile matches itself
and nothing else, and the two pairs that differ by one field are correctly separated:

```
$ mytls-probe match --brand ios18 captures/v.whatsapp.net-19d1806f.json
  ios18            no - 0x000d body differs; akamai 2:0;3:100;4:2097152;9:1|10420225|0|m,s,a,p
                        vs 4:2097152;3:100|10485760|0|m,s,p,a
```

`0x000d` is signature_algorithms — the single `ecdsa_sha1` entry that is the only TLS
difference between iOS 16 and iOS 18.

**It is a shape comparison, not a byte comparison**, and that is forced rather than chosen.
`selftest` can compare bytes because it controls the SNI and can hold it equal to the
capture's. Two captures taken against *different* sites cannot be: the names differ, so the
padding that compensates for them differs, so every length in the message differs.
`server_name` and `padding` are therefore left out, and everything else — every remaining
extension body, byte for byte — is compared.

### `sniscan` — the one thing the self-test cannot see

The self-test compares against a capture taken at one address, so it exercises exactly one
SNI length. A padded profile computes its padding from the *total* message length, so a
longer hostname moves a byte count nothing else in the tree ever varies. A padding rule
that is off by one, or that gives up past some length, would pass the self-test every time
and then send a differently-shaped ClientHello to the first real site with a long name.

```bash
mytls-probe sniscan                    # every profile, hostnames of 1..253 chars
mytls-probe sniscan --brand ios18 --step 3
```

Needs no server, no certificate and no network — the ClientHello is the first thing on the
wire, so a bare socket that accepts and reads once is enough.

```
=== ios16 ===
  517B on the wire at every SNI length that can reach it: 1 to 205 chars
  (69 lengths), padding 205B down to 1B - OK
  208-208 chars: 512B is out of reach, sizes [520] - upstream's 1-byte fallback,
  unmeasured against a real client
  211 chars: 518B, no padding extension
=== chrome ===
  never padded; 1781B at 1 chars up to 2149B at 241, growing with the name: OK
```

That middle line is a real edge this found. Between roughly 206 and 210 characters the
unpadded message lands within 4 bytes of 512, leaving no room for the padding extension's
own header — and upstream OpenSSL's rule (`ssl/statem/extensions_clnt.c`, unchanged here)
emits a 1-byte padding extension anyway rather than none, overshooting the target. No
capture in this tree has an SNI anywhere near that long, so **there is nothing to say
whether a real client does the same**. It is reported and left alone; guessing differently
from OpenSSL is as likely to be wrong as matching it.

---

## Capturing from a real site instead (mitmproxy)

`serve` can only capture a browser that visits **us**, so the page, the certificate and
the request are all ours. That is enough for a ClientHello and one navigation, and it is
where every profile here came from. What it cannot show is a browser talking to a real
site — where `referer`, `cookie`, subresource `priority` and the full range of
`sec-fetch-site` actually occur.

`mytls/mitm_addon.py` does that, by making mitmproxy stop speaking HTTP:

```bash
pipx install mitmproxy       # 12.x; needs its own Python (>= 3.12), not the fork's 3.11

mytls-probe capture-mitm --host 'example\.com' --brand chrome
# browse to the site, then Ctrl-C - the import runs by itself
```

`capture-mitm` starts `mitmdump` with the addon loaded, waits, and hands the dumps to
`import-mitm` when you stop it. It prints where the CA certificate is, since the device
has to trust it. `--mode wireguard` suits phones and, unlike an explicit proxy, leaves the
browser resolving DNS itself — which is what GREASE ECH depends on. Anything after a `--`
goes to mitmdump unchanged.

#### `--host` and `--ignore-hosts` do different jobs

They sound alike and are not. Both are repeatable.

| | what it does |
|---|---|
| `--host REGEX` | intercept **everything**, then dump only the connections whose SNI matches |
| `--ignore-hosts REGEX` | do not intercept at all — mitmproxy tunnels the bytes through and never sees inside |

`--host` alone leaves the device's background chatter being decrypted and re-encrypted for
nothing. That is not merely wasteful on a phone: **certificate-pinned endpoints fail the
handshake when intercepted**, and the OS reacts by retrying and backing off. Apple's
daemons pin heavily, and the retries can crowd out the flow you are actually trying to
capture — a request that only happens once, at the end of a login, may simply never
arrive.

So on iOS, name what you want *and* wave the rest through:

```bash
mytls-probe capture-mitm --brand ios16 \
    --host 'whatsapp\.net$' \
    --ignore-hosts '.*\.apple\.com' \
    --ignore-hosts '.*icloud\.com' \
    --ignore-hosts '.*mzstatic\.com'
```

Several `--host` are combined into one alternation, so the caller never has to quote a `|`
past a shell.

Without `--brand` the dumps are only left on disk and the import command is printed, which
is what you want when a capture might need looking at first. The two steps are equally
usable on their own:

```bash
mitmdump -s "$(python -c 'import mytls; print(mytls.addon_path())')" \
         --set fp_out=./captures --set fp_hosts='example\.com'
mytls-probe import-mitm ./captures --brand chrome
```

**Why not just read mitmproxy's flows.** In its normal mode mitmproxy is an HTTP/2
endpoint: it decodes HPACK, keeps the decoded headers and re-encodes towards the server.
Names and values survive that; the *header block* does not, and the block is what this
package compares byte for byte. The addon's `next_layer` hook swaps the HTTP layer for a
raw `TCPLayer` — below HTTP, above TLS — so mitmproxy still terminates TLS, still relays
to the real server and pages still load, but what arrives is the decrypted stream with the
HTTP/2 frames intact.

It is also *more* faithful than the HTTP mode, not less: an HTTP/2 mitmproxy sends its own
SETTINGS, and `SETTINGS_HEADER_TABLE_SIZE` bounds the browser's HPACK encoder. Relayed
raw, the real server's SETTINGS pass through untouched.

The addon parses nothing. It writes the raw ClientHello and the raw byte stream, and
`import-mitm` feeds those to `parse_client_hello()` and `describe()` — the same parsers
that produced every existing profile, so there is only one implementation to be right.

### The ClientHello is taken off the wire, not from mitmproxy's parser

`mitmproxy.tls.ClientHello.raw_bytes()` rebuilds a *synthetic* record and always stamps
`0x0303` on it. Every browser measured here sends `0x0301` in that field, so taking
mitmproxy's word for it would record an artefact.

It does not have to be taken. A ClientHello is plaintext — it is the first thing on the
connection, before any key exchange — so the real bytes pass through `next_layer` before
TLS is set up, where `data_client()` hands them over. The addon keeps them and prefers
them; if only the record header arrived it splices that onto the parsed body, which is
equally exact since everything else in the header is derivable. Each dump records which it
got in `client_hello_exact`, and `import-mitm` stores `record_version: null` rather than a
guess on the fallback path.

### What it still cannot measure

| | |
|---|---|
| GREASE ECH | A browser behind an **explicit** proxy does not resolve DNS itself, and Chrome's GREASE ECH depends on a DNS HTTPS record. Transparent or WireGuard mode avoids this. Diff against the existing profile before believing a difference. |
| Session resumption | See below — it has to be handled on the browser side. |

### Session resumption, and why only the browser can prevent it

A resumed TLS 1.3 handshake puts `pre_shared_key` (`0x0029`) in the ClientHello, last.
Our client never resumes, so that is one extension of difference — which is not a subtle
drift:

```
chrome       fresh    t13d1516h2_8daaf6152771_806a8c22fdea
             resumed  t13d1517h2_8daaf6152771_a87ad97598a9    ← count and hash both move
ios18        fresh    t13d2014h2_a09f3c656075_7f0f34a4126d
             resumed  t13d2015h2_a09f3c656075_cfa2fb88e388
```

`serve` avoids it with `num_tickets = 0` (plus `OP_NO_TICKET` for TLS 1.2), which Python's
`ssl` exposes directly. mitmproxy uses pyOpenSSL, and there **is no equivalent lever
anywhere in that stack**:

| | |
|---|---|
| `Context.set_num_tickets` | does not exist in pyOpenSSL 26 |
| `SSL_CTX_set_num_tickets` via ctypes | cryptography's wheel links OpenSSL statically into `_rust.abi3.so` and does not export the symbol, so the trick `tls_profile.py` uses does not apply |
| `OP_NO_TICKET` | pyOpenSSL *does* expose this, and it does not help — measured below |
| `set_session_cache_mode` | server-side cache only, same problem |

`OP_NO_TICKET` looks like the answer and is not. Measured against a TLS 1.3 server:

| server setting | 2nd ClientHello carries PSK | server accepts resumption |
|---|---|---|
| default | **yes** | yes |
| `OP_NO_TICKET` | **yes** | no |
| `num_tickets = 0` | no | no |

It only makes the *server* refuse. The browser has already been given a ticket and still
offers it, and the offer is what lands in the capture. For the same reason **restarting
mitmproxy does not help** — nothing a server does after the fact changes what is already
in the client's ClientHello.

So the fix is on the browser: a fresh `--user-data-dir`, a browser restart (TLS tickets
are held in memory, not on disk), or a host it has not reached through the proxy yet. In
practice this is a nuisance rather than a blocker — the first connection of a session is
fresh, the addon dumps every connection, and `import-mitm` refuses the resumed ones and
picks a usable one. `--allow-resumed` overrides it if you know why you want to.

### The navigation and the xhr must come off one connection

An xhr's HPACK block is encoded against a table the navigation already filled — all three
stored profiles fail to decode with a fresh decoder and decode cleanly after their
navigation. Our own client is driven the same way, navigation then xhr on one connection,
so the encoders reach the same state and the bytes are comparable. `import-mitm` therefore
takes both from a single dump and prefers a connection that carried both; lifting a cors
request off a different connection would give a cold-table encoding that matches nothing.

This does **not** replace `serve`. `selftest` stands the server up and drives our own
client at it in one process, which is the regression check after every C-side change;
making that depend on an external proxy would be a loss.

---

## What is actually done

### 1. SETTINGS / WINDOW_UPDATE

```
Chrome  1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p   md5 52d84b11737d980aef856699f885ca86
httpx   1:4096;2:0;4:65535;5:16384;3:100;6:65536|16777216|0|m,a,s,p
```

These are **not hardcoded constants**; they are read verbatim out of the capture's SETTINGS
frame (`Profile.settings` is an ordered list of `(id, value)` pairs, never a dict — the
order is itself part of the fingerprint and must not be sorted away). The values above
match the Chromium source: `AddDefaultHttp2Settings()` in
`net/http/http_network_session.cc` and `SendInitialData()` in `net/spdy/spdy_session.cc`;
`spdy::SettingsMap` is a `std::map`, hence ascending id order 1,2,4,6 — with **no**
MAX_CONCURRENT_STREAMS(3) and no MAX_FRAME_SIZE(5). WINDOW_UPDATE = 15M − 65535 =
15663105.

Id 3 is put into `local_settings` even when it is not sent on the wire: httpcore sizes a
semaphore from it, and h2 returns 2³²+1 when the key is missing, which makes httpcore try
to acquire four billion times and no request ever goes out. What controls the wire content
is the `__iter__` of each profile's own `Settings` subclass, not deleting the key.

The pseudo-header order comes from the capture too (`Profile.pseudo_order`). Chrome's
`m,a,s,p` happens to match httpcore's, but other clients differ — switching brands changes
it automatically.

### 2. The HEADERS frame's priority

Derived from the capture by default, and **overridable**, unlike the four fields above.
Chrome sends no standalone PRIORITY frames (hence the `0` in the third akamai field) but
does put an RFC 7540 priority on its HEADERS frame: exclusive=1, depends_on=0, weight=256.
When the capture carries no priority, the PRIORITY flag is not set.

This one is not the network stack's. On iOS it follows `URLSessionTask.priority`, so two
apps on one device disagree: App Store icon loads send weight 255, a Weather refresh sends
24, and the App Store's own API calls send no PRIORITY flag at all. `Transport(priority=…)`
is how you pick — see [Tunables](#tunables).

The per-stream WINDOW_UPDATE that httpcore sends after HEADERS is **removed** — we already
announce a 6MB stream window in SETTINGS, and Chrome does not send that frame.

### 3. Request headers

**There are no templates.** The library sends no header of its own and imposes no order:
everything on the wire is what the caller passed, in the order they passed it.

```python
client.get(url)                                   # → 4 pseudo-headers, nothing else
client.get(url, headers={"User-Agent": "X"})      # → + user-agent, and nothing more
```

That is a deliberate narrowing, and it was measured rather than assumed. On one iPhone,
one iOS version and one network stack, Safari and WhatsApp sent different header sets in
different orders — and WhatsApp's own GET and POST disagreed with each other. So neither
the set, the order nor the values belong to the thing a profile describes, and imposing
any of them would stop the caller reproducing a request that is not the one we happened to
capture.

To send what the captured client sent, ask for it. `headers=` on the transport is the
caller speaking, applied to every request:

```python
mytls.Transport("chrome", headers=mytls.profile("chrome").headers)
```

That form is also what `selftest` uses: it hands the capture's own values back to the
client, so the byte comparison stays exact and can only ever fail on **ordering or HPACK
encoding** — never on a value the library happened to invent.

The merge rule, when both a transport and a request supply headers — **httpx's own layering,
nothing invented**:

| What the caller passed | Result |
|---|---|
| a name `headers=` already set | keeps the transport's position, takes the request's value |
| a name `headers=` did not set | appended after them, in the caller's own order |
| nothing | nothing is sent for that name |
| `host` / `connection` / `keep-alive` / `transfer-encoding` / `upgrade` | dropped (`host` becomes `:authority`, the rest are HTTP/1-only) |

The four headers httpx injects by itself (`accept: */*`, `accept-encoding`,
`connection: keep-alive`, `user-agent: python-httpx/x.y.z`) are removed first, or they
would be mistaken for the caller's intent. The match is on **(name, value) exactly**, so a
caller who genuinely wants `user-agent: python-httpx/0.27.2` on a request has it dropped —
pass it via the transport's `headers=` instead, which is not subject to that check. That
is also why the captured `accept-encoding`, byte-identical to httpx's own, has to go
through `headers=`.

### 4. HPACK encoding policy

Three engines. `Profile.hpack` picks one; it is guessed from the capture (iOS → Apple's,
Chromium → quiche, otherwise stock) and overridable with `{"meta": {"hpack": "..."}}`.

| | Chrome (`quiche`) | iOS (`cfnetwork`) | `stock` hpack |
|---|---|---|---|
| Huffman | only if **strictly shorter** | only if strictly shorter | always |
| dynamic table | no pseudo-header except `:authority` | the same, **and never `content-length`** | indexes everything |
| `authorization` | ordinary literal — quiche never emits the never-indexed opcode | **never-indexed opcode** | never-indexed |
| cookie | split on `;` into separate fields | split | not split |

`cfnetwork` is quiche's rules plus two names. Measured against **37 requests over 34
connections** captured from WhatsApp on one iOS 16.7.12 device:

```
  stock hpack     0/37
  quiche          3/37    ← the three GETs, which carry no content-length
  cfnetwork      36/37
```

**Neither rule is cosmetic.**

* `content-length` decides most blocks outright — its value differs on every request that
  has one, so an entry made for it can never be hit again and only evicts something
  reusable from a 4KB table.
* `authorization` decides far more than its own field. Indexing it adds a dynamic entry the
  real client never adds, so **every index in every later request on that connection comes
  out one too high**. One capture here carries four requests on one connection; getting the
  first wrong corrupted the other three:

  ```
  request 3   :authority   captured indexed idx=73    ours idx=74
              accept       captured indexed idx=70    ours idx=71
  ```

The `authorization` column is where the three engines genuinely disagree, and the reason
is worth knowing: **h2 marks it sensitive before the encoder sees it** (`_secure_headers`,
which its own source says follows "Firefox and nghttp2"). `stock` honours that flag,
`quiche` deliberately ignores it, and `cfnetwork` forces the opcode by name — so it comes
out right whether or not h2 happened to mark it.

Verified on the wire, not only by re-encoding a capture: a live request through
`Transport("ios16")` carrying an `Authorization` header, caught by the local probe, comes
back as

```
  :path            no-index
  authorization    never-index
  user-agent       incr-index
```

The rules generalise past the app that revealed them: the same encoder reproduces the
stored **Safari** capture too, navigation and xhr alike, so this belongs to iOS and not to
WhatsApp — like everything else measured on that device.

**Chrome is deliberately left on `quiche`.** Every Chrome capture in this tree is a GET
without an `authorization`, so none of them says what quiche does with either name; where
there is no measurement, quiche's own source is the better authority.

#### The one request that still differs is not an encoding rule

On the second request of that four-request connection, the client opens the block with a
**dynamic table size update to 4096**:

```
  captured[:6]  3f e1 1f  83 87 04
  ours[:6]                83 87 04 8d 62 51
  captured[3:] == ours  →  True
```

Strip those three bytes and the remaining 135 are identical. 4096 is what the server had
just advertised in `SETTINGS_HEADER_TABLE_SIZE` — and it is also the default, so hpack
considers the size unchanged and emits nothing, while Apple's stack acknowledges the peer
unconditionally (RFC 7541 §4.2 permits either). That is a response to the peer's SETTINGS
rather than a choice about how to encode, and in a live connection h2 owns it, so nothing
is done about it here.

#### Still unverified

Two claims in the table above rest on a capture set that is no longer in the tree, and the
current one cannot re-derive them — it has **no `cookie` and no `if-none-match` at all**:

* **cookie splitting for `cfnetwork`.** An earlier App Store capture from the same device
  carried ten and eleven *separate* `cookie` fields in one block, which is a crumbled
  cookie and nothing else. That is the whole basis for it.
* **`if-none-match`.** The same set showed it carrying the plain no-index opcode, which
  `cfnetwork` does not reproduce.

Re-capture a request carrying cookies before trusting either. `hpack_probe.py` prints the
opcode each field used, so a single capture settles it.

---

## Three tiers of confidence

The changes in this directory fall into three tiers whose **evidence differs a great
deal**. Do not treat them as equally important.

### Tier one: what goes into a fingerprint hash — evidenced

Only two things:

* **The TLS layer** (JA3 / JA4 / peetprint) — handled by the C library, not this directory
* **The akamai fingerprint** — SETTINGS, the connection-level WINDOW_UPDATE, PRIORITY and
  the **pseudo-header** order. Those four fields, nothing else.

Neither is checked by comparing hashes. Both are checked by comparing **bytes** against a
real browser capture in `profiles/` — the HPACK block literally, the ClientHello outside
the regions that are new on every connection. Identical bytes make identical hashes, for
every hash, including ones nobody has published; how peet or Wireshark or a vendor happens
to compute theirs stops being a question anyone has to answer. See
[the self-test](#all-three-layers-are-compared-as-bytes-not-as-fields).

Those four akamai fields are read straight from the capture rather than being constants
transcribed from source code, so transcription errors are impossible.

### Tier two: the set of headers — defensible, but in no hash at all

**Ordinary headers (names, values, order) are in none of the hashes above.** You can check
this yourself:

```python
# cut the headers down to three, shuffle the order, set the UA to totally-not-chrome/1.0
# → ja4 and akamai_fingerprint_hash do not change by a single character
```

Confirmed by measurement. So the headers contribute **zero** to any fingerprint hash.

Their value is elsewhere: a request whose UA says `Chrome/150` but which carries no
`sec-ch-ua`, no `sec-fetch-*` and no `accept-language` is self-contradictory, and one rule
catches it without any fingerprint database. That value is real — but it is **not** what
this library provides, because it sends no header values of its own. What it gives you is
the captured set, ready to hand back:
`Transport("chrome", headers=profile("chrome").headers)`. Whether to send it is yours.

### Tier three: header order and HPACK bytes — done, with no evidence of benefit

* **Header order**: the claim that anti-bot systems check header order is common in
  industry writing, but **this project has verified no vendor actually doing it**. Since
  the list is being built anyway, getting the order right costs nothing extra.
* **HPACK bytes**: the four encoding alignments (conditional huffman, no never-indexed
  opcode, pseudo-headers out of the dynamic table, cookie crumbling) really do produce
  **byte-identical** output to real Chrome (455 bytes; see the verification below). That is
  a fact. But **there is no evidence that anyone hashes the raw HEADERS bytes**, so the
  practical benefit may be near zero.

The reason to keep them is cost, not benefit: the code is written, the runtime overhead is
zero, and it is verified not to break anything. If the maintenance burden is not worth it
(especially having to re-capture `sec-ch-ua` across major versions), delete
`_build_headers` and `_QuicheEncoder` and keep only SETTINGS/WINDOW_UPDATE/priority — the
akamai and TLS fingerprints still match completely.

---

## Verification

All three layers have a real browser to compare against, and all of them pass. **Note that
"passing" is fingerprint evidence only for tier one**; tiers two and three mean "identical
to a real browser", which is not the same as "someone is checking".

### Confirming a build on a new machine

`install-python.sh` runs two checks automatically after installing, **neither of which
needs a network**:

| | What it checks | On failure |
|---|---|---|
| linkage check | whether the CLI and Python load the libssl in `$PREFIX/lib` | `die` |
| self-test | starts an h2 server locally, connects to itself, and compares the **ClientHello + h2 frames + HPACK bytes** against **every** brand in `profiles/` | prints the diff, then `die` |

The second one on its own:

```bash
mytls-probe selftest                  # every brand
mytls-probe selftest --brand chrome   # just one
```

Server and client live in the same process (the server runs in a thread), so no second
terminal and no network.

It sends **the kind of request the capture was**: if the capture carries `referer` /
`sec-fetch-site: cross-site` (arrived via a link), or `cache-control` (a reload), or is a
`sec-fetch-mode: cors` (the page's own fetch), our client sends the same. Otherwise a
capture taken any way but "type the address into a fresh tab" could never match — and that
has nothing to do with the fingerprint. Measured: the navigation iOS Safari makes after
you click through the certificate warning is `cross-site` with an **empty** `referer`, and
neither a fresh tab nor typing the address avoids it.

It is sensitive to **the address the capture was taken at** (the `:authority` goes into
the HPACK block verbatim, and the host half also decides whether an SNI is sent), so the
address is read out of the reference capture and **cannot simply be changed**:

```bash
mytls-probe where chrome    # → localhost:8443
```

`--skip-selftest` skips it, but then nothing has checked the fingerprint at all.

**Do not treat OpenSSL's own `make test` as an acceptance criterion.** This fork pins the
cipher list, the signature algorithms and the certificate compression algorithms, so 16 of
the 31 configurations in `test_ssl_new` necessarily fail — that is the **cost** of the
change, not a bug. To use it as a regression test, run the same set against the commit
before the change and compare **which** tests fail, not whether any do. Running the
comparison by hand, without building the whole test suite:

```bash
cd <build tree>
make -j"$(nproc)" test/ssl_test
export CTLOG_FILE=$PWD/test/ct/log_list.cnf TEST_CERTS_DIR=$PWD/test/certs
for cnf in test/ssl-tests/*.cnf; do
    test/ssl_test "$cnf" default >/dev/null 2>&1 || echo "FAIL $(basename "$cnf" .cnf)"
done
```

The failing set as of the profile work:

```
02-protocol-version  04-client_auth  05-sni  07-dtls-protocol-version  10-resumption
11-dtls_resumption  14-curves  16-dtls-certstatus  19-mac-then-encrypt  20-cert-select
22-compression  23-srp  25-cipher  26-tls13_client_auth  28-seclevel
29-dtls-sctp-label-bug
```

Identical before and after that work, measured by rebuilding the library from the previous
commit in the same tree with the same Configure options.

Once online, run `verify_fp.py` (below) as well; it is the only check that proves a real
server agrees.

### Live: acceptance + an outside opinion (online)

```bash
mytls-verify                    # every installed profile
mytls-verify --brand ios18      # just one
mytls-verify --skip-reach       # only ask the services
```

**Nothing is stored for this.** The values it compares against are computed on the spot by
`fingerprints.py` from `profiles/<brand>.json`, which holds the browser's raw ClientHello.
There is no `references/` directory any more.

Two things, and neither of them is "is the fingerprint right" — the byte comparison in
`selftest` settles that, offline and better:

**1. Acceptance.** Several real servers running unrelated TLS stacks complete the handshake
and negotiate h2. Nothing else in the tree checks this: a profile copies whatever the
browser sent, including a duplicate `rsa_pss_rsae_sha384` and three 3DES suites, and
loopback against our own OpenSSL will never object to any of it.

```
=== acceptance (real servers, real network) ===
  tls.peet.ws            OK     HTTP/2, status 200
  www.google.com         OK     HTTP/2, status 200
  www.cloudflare.com     OK     HTTP/2, status 200
```

**2. An outside parser.** peet and check.ja3.zone read the ClientHello we just sent off a
real network and say what they made of it; that is compared against what the same
functions make of the captured browser's bytes.

```
=== tls.peet.ws ===
  ja4                        OK
  ja4_r ciphers              OK
  ja4_r extensions           OK
  ja4_r sigalgs              OK
  peetprint_hash             OK
  akamai                     OK
```

**The JA3 hash is judged only where it can mean anything.** JA3 hashes the extension list
in **wire order**, and Chrome has shuffled that per connection since 110 — two connections
from one real Chrome do not share a JA3 either, and neither do two of ours. So the hash is
compared when the wire order matches (the iOS profiles, whose order is fixed) and skipped
with a note when it does not. What a shuffle cannot touch is compared either way: the
version, the ciphers in order, the extension set, the curves and the point formats. JA4
sorts, so `ja4` is always directly comparable.

`--resume` is gone. The fork refuses to resume unless a profile sets `SSL_FP_ALLOW_RESUME`,
and none does, so the option could only ever have measured an ordinary fresh handshake and
called it resumed.

### Raw bytes (ClientHello + HPACK)

peet.ws gives you its **interpretation**, not the exact bytes on the wire — it shows both
GREASE extensions as empty objects `{}`, for instance, so you cannot tell that the second
one actually carries a `00`. Only raw bytes answer that kind of question.

`hpack_probe.py` runs a minimal h2 server and records both layers:

* **The ClientHello** — sent in the clear before any key exchange, so `MSG_PEEK` is enough
  to look at it before handing it to the TLS layer: **no packet capture, no
  SSLKEYLOGFILE**.
* **The HPACK header block** — written out verbatim before anything decodes it.

`selftest` compares both against `profiles/<brand>.json`: the ClientHello (record and
legacy version, session_id length, cipher list, the type and length of every extension,
**and every extension's body**; GREASE *values* are wildcarded because they are meant to
change per connection, but their lengths are not), then the h2 frame layer, then the HPACK
block byte for byte.

Extension bodies are compared because lengths alone hide real differences: Chrome and
iOS both send a 12-byte supported_groups listing entirely different groups. Bodies that
are random by design are exempt — the ECH GREASE payload, a PSK — and key_share is compared
as `group:keylen` pairs, since the public keys beside them are fresh every time.

Only the first HEADERS frame of a connection is compared: the HPACK dynamic table is
stateful, and only at the start of a connection are both sides guaranteed to be empty.

Current result: all three installed brands pass all three layers — 455 identical HPACK bytes
for `chrome`, 472 for `chrome_android`, 290 for `ios18`.

Extension **order** is compared as a set plus the first and last positions, not as a
sequence, because Chrome (and we) shuffle it per connection. iOS does not shuffle, and
its fixed order is what makes its JA3 hash comparable in `verify_fp.py`.

To compare two files by hand, `diff` takes paths as well as brand names:

```bash
mytls-probe serve --out /tmp/ours.json &   # --out: do not register a brand
mytls-probe client --brand chrome
mytls-probe diff chrome /tmp/ours.json
```

The self-signed certificate and other generated files live in `~/.cache/hpack_probe/` and
never enter the repository; `HPACK_PROBE_DIR` moves them.

---

## Two headers that vary

Capturing showed that Chrome itself is not consistent about these two. Do not treat them as
constants:

* **`cache-control: max-age=0`** — sent on a reload or when re-entering the address bar,
  **not sent on a fresh navigation**. Both were seen in real captures.
* **`accept-language`** — follows the browser's UI language, so the capture's value is
  that machine's, not a constant (the current `chrome` capture came from a fresh profile:
  `en-US,en;q=0.9`).

Neither had an obvious right value, which is part of why the library now sends no values
at all: pass them if you want them, in the order you want them.

---

## Known non-goals / caveats

* **`mytls-verify` needs the internet and two third-party services.** They can be down or
  can change what they report; the check treats an unreachable service as a skip, not a
  failure. Everything that matters is settled offline by `selftest` and `sniscan`.
* **An xhr's HEADERS priority needs the page's own `/xhr-sample`.**
  Both arrive by themselves now, but a brand captured with javascript disabled has neither
  and falls back to the order inferred from navigate; measurement shows a real XHR moves
  the client hints to either side of `user-agent`, unlike the inference.
* **SETTINGS GREASE is not simulated.** Chrome can send a fifth, GREASE setting, but both
  its id and its value are random per connection, and `enable_http2_settings_grease`
  defaults to off. The "fixed value" circulating online is itself a tell — and if a client
  that really does send GREASE is ever captured, that random value would be stored in the
  profile as a constant, which is worse. Check `catalog()` after capturing. If a capture
  contains standalone PRIORITY frames, loading it warns: that part is not reproduced.
* **Only quiche's HPACK rules are implemented.** A non-Chromium brand falls back to
  hpack's own, so the byte layer will most likely not match (`selftest` says so), but
  akamai and TLS are unaffected.
* **This subclasses httpcore's internal classes.** httpcore imports its HTTP/2 class inside
  `handle_request()` with no hook available, so what is patched is the **assignment**: the
  connection object gets a `_connection` property that retags the freshly built
  `HTTP2Connection` as our subclass before the preface goes out. The upside is that **not
  one line of httpcore's connection logic is copied**, and the direct, proxy-tunnel and
  SOCKS paths all share the same hook. A change in httpx/httpcore/h2 can still break the
  fit, so building a transport checks the versions and warns. Re-run all of the
  verification above before upgrading.
* **h2 only.** `httpx.Client()` over HTTP/1.1 has no SETTINGS-style fingerprint surface,
  only header order, and everything in this module applies to the h2 path only.
