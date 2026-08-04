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
python hpack_probe.py list
```

The changes in here are **not equally important** — some can be verified against public
fingerprint hashes, others are done because they were cheap. Read
[three tiers of confidence](#three-tiers-of-confidence) before changing anything.

---

## Files

| File | Purpose |
|---|---|
| `browser_fp.py` | The main module. Provides a transport per brand; `catalog()` / `describe()` report what is installed and what each imitates |
| `hpack_probe.py` | Runs an h2 server that records the **raw ClientHello + h2 frames + HPACK bytes**; `serve` captures a visiting browser, `selftest` captures ourselves and diffs byte for byte |
| `verify_fp.py` | The online check: compares field by field against `references/<brand>.json` |
| `tls_profile.py` | Selects the TLS-layer profile from Python (ctypes into libssl) |
| `profiles/<brand>.json` | **One file per browser**; everything in `browser_fp` is derived from it |
| `references/<brand>.json` | What **tls.peet.ws + check.ja3.zone** made of that browser, collected in the same visit (automatically). The baseline for `verify_fp.py`, and the source of the header order for `browser_fp` |

**A brand is a browser (+ platform), not a browser version.** There is only
`chrome.json`, never `chrome150.json` — capturing again replaces it, and the version is
read off the capture's user-agent (`Profile.version`). Nobody ends up pinned to a stale
profile.

---

## Usage

```python
import browser_fp as fp
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
2 profile(s) in .../python/profiles:
  chrome      Chrome 150 on Windows    1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p
  safari_ios  Safari 604 on iOS        2:0;3:100;4:2097152;9:1|10420225|0|m,s,a,p

>>> print(fp.describe("chrome"))
chrome  (Chrome 150 on Windows)
  transport      : browser_fp.ChromeTransport() / transport('chrome')
  user-agent     : Mozilla/5.0 (Windows NT 10.0; Win64; x64) ... Chrome/150.0.0.0 Safari/537.36
  sec-ch-ua      : "Not;A=Brand";v="8", "Chromium";v="150", "Google Chrome";v="150"
  platform       : Windows
  accept-language: en-US,en;q=0.9
  cache-control  : not sent
  header profile : navigate (capture was sec-fetch-mode: navigate)
  header order   : navigate=reference, xhr=reference
  hpack          : quiche
  tls profile    : chrome
  akamai         : 1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p
  akamai md5     : 52d84b11737d980aef856699f885ca86
  settings       : 1=65536, 2=0, 4=6291456, 6=262144
  window update  : 15663105
  headers prio   : exclusive=True dep=0 weight=256
  derived from   : .../python/profiles/chrome.json
  captured at    : 2026-08-03T10:57:34+00:00
```

Same from the command line: `python hpack_probe.py list`, `python browser_fp.py`.

The same content is available as a dict in `fp.profile("chrome").meta` (`brand`, `label`,
`browser`, `version`, `platform`, `user_agent`, `sec_ch_ua`, `akamai_fingerprint`,
`akamai_hash`, `source`, `captured_at`, …).

### Tunables

Three, all on the profile. Changing one affects every transport built from that brand,
live connections included:

```python
prof = fp.profile("chrome")
prof.header_profile = "xhr"                  # or "navigate" (the default)
prof.accept_language = "zh-CN,zh;q=0.9"
prof.send_cache_control = True               # see "two headers that vary" below
```

To "put things back", simply do not use the transport.

**There are no version constants and no hardcoded akamai constants.** The version, the UA,
`sec-ch-ua`, `accept`, the `sec-fetch-*` headers, the header order, and the SETTINGS,
WINDOW_UPDATE, HEADERS priority and pseudo-header order are all **derived** from
`profiles/<brand>.json` — see [adding a browser](#adding-a-browser).

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

# 3. packages
pip install "httpx[http2,socks]==0.27.2" brotli zstandard
```

* `enable-brotli` is required — the chrome profile advertises brotli certificate
  compression, and without it a server that compresses its certificate chain (some
  Cloudflare configurations) fails the handshake.
* `enable-weak-ssl-ciphers` is required too — **Safari still offers three 3DES suites**.
  Without them the ClientHello carries 17 cipher suites instead of 20 and the ja4 comes out
  `t13d1714` instead of `t13d2014`, which is a fingerprint of its own. Only a profile that
  lists them offers them (the chrome profile does not), but a server really could
  negotiate 3DES on a safari_ios connection — exactly as it could with the real browser.
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
python hpack_probe.py serve
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
  captured from 192.168.1.7: Mozilla/5.0 (Linux; Android 14; Pixel 8) ... Chrome/150.0.0.0 Mobile Safari/537.36
  stored as .../profiles/chrome_android.json
  stored as .../references/chrome_android.json  (tls.peet.ws says ja4 t13d1516h2_...)
  ...
chrome_android  (Chrome 150 on Android)
  transport      : browser_fp.ChromeAndroidTransport() / transport('chrome_android')
```

**One visit produces two files.** After the browser's request is captured we serve it a
page whose javascript does `fetch('https://tls.peet.ws/api/all')` and POSTs the answer
back — so `profiles/` (the raw bytes) and `references/` (an outside party's reading of the
same browser) both arrive at once, and the baseline for the online check never has to be
saved by hand.

The page hits two services, because only one of them is reachable from every browser:

| | CORS | Contents |
|---|---|---|
| `check.ja3.zone` | **`*`**, any browser on any device can read it | JA3 only (hash + full string + ciphers + curves) |
| `tls.peet.ws` | **only on the OPTIONS preflight, never on the GET itself** | ja4 / peetprint / akamai / the full header order |

So where a flag cannot be passed (a phone), at least the JA3 half is reliable — and **JA3
is exactly what the self-test cannot check** (a ClientHello can never be compared byte for
byte, only against a "shape" I defined myself; a hash computed independently by someone
else is what can falsify it).

The peet half is blocked for a plain Chrome (`TypeError: Failed to fetch`, measured). Two
ways round it, both spelled out on the page:

1. Start the browser with `--disable-web-security` (which **requires** `--user-data-dir`,
   or Chrome ignores the flag). It only turns off the renderer's same-origin checks and
   **does not touch the network stack**, so the captured fingerprint is unaffected:

   ```
   chrome.exe --user-data-dir=%TEMP%\cfp --ignore-certificate-errors ^
              --disable-web-security https://localhost:8443/api/all
   ```

2. No flags at all: the page **always** shows a paste box. Open tls.peet.ws in a new tab
   via the link, copy the JSON and paste it back; or press `skip` to finish immediately.

### Both kinds of request

The page's own fetch is always an **XHR**, while a pasted response comes from a
**navigation** — a browser sends different headers for the two, and missing one leaves
half the templates guessed. Hence:

```bash
python hpack_probe.py serve --both     # do not finish until both kinds are in
```

One visit covers both: the automatic fetch gives the XHR one, the paste gives the
navigation one. The container **accumulates by kind** — a newly captured kind replaces the
same kind, and a kind not captured this time is kept, **but only if the user-agent matches
exactly** (a browser upgrade discards it; falling back to a guess beats using a stale
order).

A reference looks like this; whatever is missing simply was not obtained:

```json
{"brand": "chrome", "collected_at": "...",
 "peet": [ {...the cors one...}, {...the navigate one...} ],
 "ja3zone": {...}}
```

If the capture machine has no internet, add `--no-reference` (or let it time out; 25s by
default, and the profile is unaffected). A `--out` capture never collects a reference.

**The brand is whatever the client says it is**, read off the `user-agent` of the request
that just arrived:

| Who visited | Stored as |
|---|---|
| Desktop Chrome | `chrome` |
| Android Chrome | `chrome_android` |
| iPhone Safari | `safari_ios` |
| Firefox / Edge / Opera / Vivaldi / Samsung / Yandex | `firefox` / `edge` / `opera` / … |

If it cannot be identified (curl, say) the capture is left in `capture.json` and you are
asked to name it with `--brand`; `--brand` also simply overrides the automatic choice.
Right after capturing, the new brand is printed (the `describe()` output), and at that
point:

```python
fp.transport("chrome_android")     # already works
fp.ChromeAndroidTransport()        # already works
```

To try one out without committing it to the tree, point `BROWSER_FP_PROFILES` at another
directory (`serve` honours it too, so the capture lands straight there; the reference half
is `BROWSER_FP_REFERENCES`).

**What is derived automatically:**

| | Source |
|---|---|
| UA, `sec-ch-ua`, `accept`, `sec-fetch-*`, the header set and order | the HPACK block of the HEADERS frame |
| the default `accept-language`, whether to send `cache-control` | same |
| browser name / version / platform (`label`, `meta`) | the UA and `sec-ch-ua-platform` |
| **header order** (including exactly where `referer` / `cookie` go) | the real request to a real site in the reference |
| **the `xhr` template's order, values and priority** | the `sec-fetch-mode: cors` frame in the reference |
| the SETTINGS ids / order / values | the SETTINGS frame |
| the connection-level WINDOW_UPDATE (0 = not sent) | the WINDOW_UPDATE frame |
| the HEADERS priority (absent → no PRIORITY flag) | the HEADERS frame's flags |
| the pseudo-header order (the last akamai field) | the `:`-prefixed fields in the HPACK block |

**It is done this way because hand-written constants rot.** Chromium permutes the brand
list in `sec-ch-ua` every major release — Chrome 150 leads with `"Not;A=Brand";v="8"`,
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
hold Chrome connections and Safari connections at the same time):

```c
int         SSL_CTX_set_fp_profile(SSL_CTX *ctx, const char *name);
const char *SSL_CTX_get_fp_profile(const SSL_CTX *ctx);
int         SSL_set_fp_profile(SSL *s, const char *name);
const char *SSL_get_fp_profile(const SSL *s);
const char *SSL_fp_profile_name(size_t idx);   /* walks the built-in list, NULL past the end */
```

There is also an SSL_CONF command, `FingerprintProfile` / `-fp_profile`, so `openssl.cnf`
and the `openssl` command line can select one — C-side regression testing does not have to
drag Python in.

**The Python side does not have to think about any of this**: `Transport("safari_ios")`
sets the TLS profile as well, and `transport.tls_profile` reads back what actually took
effect. `tls_profile.py` is only needed when driving OpenSSL by hand:

```python
import ssl, tls_profile
ctx = ssl.create_default_context()
tls_profile.set_profile(ctx, "safari_ios")
print(tls_profile.available())        # ('chrome', 'safari_ios')
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

### iOS Safari's ClientHello (measured, iOS 18.5 / Safari 604.1)

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
| Never sent | `session_ticket`, ALPS, ECH |
| Unique to it | `padding` (21) |

**The extension order is fixed, not shuffled** (Chrome has shuffled per connection since
110). Four independent connections to two different servers produced the identical order,
with `server_name` always second. That makes Safari's **JA3 hash stable and comparable** —
so `ossl_ssl_ext_permutation` on the C side has to be switchable per profile, and the "do
not compare the JA3 hash" exemption in `verify_fp.py` has to tighten into a real
comparison for Safari.

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
python hpack_probe.py serve --host 192.168.1.7 --both
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

**On a phone the peet half can only be pasted** (iOS has nothing like
`--disable-web-security`); the `check.ja3.zone` half arrives automatically as usual.

**Note that the address used for the capture becomes part of the fingerprint.** The
`:authority` goes into the HPACK block verbatim, and its host half decides whether an SNI
is sent at all — an IP address carries none, a name does. So a capture taken at
`192.168.1.7:8443` can only be reproduced from `192.168.1.7:8443`:

```bash
python hpack_probe.py where safari_ios     # → 192.168.1.7:8443
```

`selftest` goes to that address by itself. If the address is no longer on this machine
(DHCP moved it, or it was the Windows IP at the time), it says so and falls back to
localhost — the HPACK difference and the one SNI extension are then expected, and the h2
layer is still compared in full:

```
note: safari_ios was captured at 192.168.1.7, which is not an address this machine
holds, so the request goes to localhost instead. :authority differs, so the HPACK
block cannot match, and the capture carried no SNI while this one does, so the
ClientHello will differ by one extension. The HTTP/2 layer is still compared in full.
```

Run the self-test after capturing; it compares all three layers at once:

```bash
python hpack_probe.py selftest --brand firefox
```

```
=== ClientHello ===          ← differences here mean changing C and rebuilding
=== HTTP/2 frame layer ===   ← differences here mean the capture was not consumed
=== HPACK header block ===   ← byte for byte
```

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

Also derived from the capture. Chrome sends no standalone PRIORITY frames (hence the `0`
in the third akamai field) but does put an RFC 7540 priority on its HEADERS frame:
exclusive=1, depends_on=0, weight=256. When the capture carries no priority, the PRIORITY
flag is not set.

The per-stream WINDOW_UPDATE that httpcore sends after HEADERS is **removed** — we already
announce a 6MB stream window in SETTINGS, and Chrome does not send that frame.

### 3. Request headers

Two templates, `navigate` (the default) and `xhr`, neither of whose order is written by
hand:

* **When a reference exists**, the order is taken straight from the real request to a real
  site in it (the navigation frame for `navigate`, the `sec-fetch-mode: cors` frame for
  `xhr`). **That is the only way to learn where `referer` and `cookie` go** — a capture
  taken against localhost has neither a referrer nor cookies. Measured: real Chrome puts
  `referer` after `sec-fetch-dest`, not after `accept` as originally guessed.
* **Without a reference** it falls back to inferring from the capture: the navigate order
  is real, and the xhr one is that rewritten by rule (`accept` → `*/*`, `sec-fetch-mode` →
  `cors`, `sec-fetch-dest` → `empty`, `priority` → `u=1, i`, dropping
  `upgrade-insecure-requests` and `sec-fetch-user`).

**Values always come from the capture, never from the reference** — the values in a
reference describe a request sent to somebody else's site. Per-request headers such as
`referer`, `cookie`, `origin` and `authorization` borrow only the position, and
`sec-fetch-site` uses the value typical of each kind (`none` / `same-origin`, overridable
with `prof.sec_fetch_site`).

The `header order : navigate=reference, xhr=derived` line in `describe()` tells you where
each template came from.

The HEADERS priority is per kind too: a navigation is weight=256, an **XHR is 220**
(measured), and the latter is only knowable when a reference provides it.

The merge rule — **the template decides which headers and in what order, the caller
decides the values and which extra headers to append**:

| What the caller passed | Result |
|---|---|
| a name already in the template | the value is overridden, **the position stays the template's** |
| a name not in the template | inserted at the `_EXTRA` slot, keeping the caller's relative order |
| `host` / `connection` / `keep-alive` / `transfer-encoding` / `upgrade` | dropped (`host` becomes `:authority`, the rest are HTTP/1-only) |

The four headers httpx injects by itself (`accept: */*`, `accept-encoding`,
`connection: keep-alive`, `user-agent: python-httpx/x.y.z`) are removed first, or they
would be mistaken for the caller's intent.

Two known quirks:

* The removal matches on **(name, value) exactly**, so a caller who *genuinely* wants to
  send `user-agent: python-httpx/0.27.2` has it dropped as httpx's default. No other value
  is affected.
* **A header in the template cannot be deleted.** Passing an empty value only makes it
  empty. Removing one means editing `_template()`, or switching
  `prof.header_profile = "xhr"`.

### 4. HPACK encoding policy

Aligned with quiche (`quiche/http2/hpack/hpack_encoder.cc`):

| | Chrome (quiche) | hpack as shipped |
|---|---|---|
| Huffman | encodes, then uses it only if **strictly shorter** | always |
| never-indexed | never emits that opcode | forces it for `authorization` and short `cookie` |
| dynamic table | indexes no pseudo-header except `:authority` | indexes everything |
| cookie | split on `;` into separate fields | not split |

The third matters most: putting `:path` into the dynamic table makes the table state
diverge from Chrome's for every later request on the connection.

hpack's own source comment says its never-indexed rule follows "Firefox and nghttp2" — it
was never Chrome's.

Which set is used is decided by `Profile.hpack`; see
[adding a browser](#adding-a-browser) above.

---

## Three tiers of confidence

The changes in this directory fall into three tiers whose **evidence differs a great
deal**. Do not treat them as equally important.

### Tier one: what goes into a fingerprint hash — evidenced

Only two things:

* **The TLS layer** (JA3 / JA4 / peetprint) — handled by the C library, not this directory
* **The akamai fingerprint** — SETTINGS, the connection-level WINDOW_UPDATE, PRIORITY and
  the **pseudo-header** order. Those four fields, nothing else.

Both can be compared field by field against a real browser capture in `profiles/`, and a
match is a match. Those four akamai fields are now read straight from the capture rather
than being constants transcribed from source code, so transcription errors are impossible.

### Tier two: the set of headers — defensible, but in no hash at all

**Ordinary headers (names, values, order) are in none of the hashes above.** You can check
this yourself:

```python
# cut the headers down to three, shuffle the order, set the UA to totally-not-chrome/1.0
# → ja4 and akamai_fingerprint_hash do not change by a single character
```

Confirmed by measurement. So the header templates contribute **zero** to any fingerprint
hash.

Their value is elsewhere: a request whose UA says `Chrome/150` but which carries no
`sec-ch-ua`, no `sec-fetch-*` and no `accept-language` is self-contradictory, and one rule
catches it without any fingerprint database. What the templates really buy you is **a
self-consistent set of browser headers without passing anything**. That value is real.

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
python hpack_probe.py selftest                  # every brand
python hpack_probe.py selftest --brand chrome   # just one
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
python hpack_probe.py where chrome    # → localhost:8443
```

`--skip-selftest` skips it, but then nothing has checked the fingerprint at all.

**Do not treat OpenSSL's own `make test` as an acceptance criterion.** This fork pins the
cipher list, the signature algorithms and the certificate compression algorithms, so 14
configurations in `test_ssl_new` necessarily fail (including `04-client_auth` and
`26-tls13_client_auth`) — that is the **cost** of the change, not a bug. To use it as a
regression test, run the same set against the commit before the change and compare
**which** tests fail, not whether any do.

Once online, run `verify_fp.py` (below) as well; it is the only check that proves a real
server agrees.

### TLS + h2 frames + headers (online)

```bash
python verify_fp.py                    # TLS (no PSK) + the whole h2 layer
python verify_fp.py --resume           # TLS with a PSK, matching that reference scenario
python verify_fp.py --brand chrome     # name the brand when several are installed
python verify_fp.py --xhr              # check the xhr template instead
```

The baseline is `references/<brand>.json`, saved automatically at capture time. Without the
peet half it exits with an error rather than comparing against some other brand's. When the
`ja3zone` half is present it runs an extra section: **ask check.ja3.zone again** and
compare its JA3 against the real browser's — a second implementation entirely independent
of peet.

It also aligns `accept-language`, `cache-control`, `sec-fetch-site` and `referer` to the
reference automatically, so `referer`'s position really is verified rather than merely
written correctly in the code. `--xhr` compares against the cors entry instead, which
verifies the xhr template (weight 220 included).

**The JA3 hash is judged automatically.** JA3 hashes the extension list in **wire order**,
and Chrome has shuffled that order per connection since 110 — two connections from the
same real Chrome do not share a JA3 either. So: if the hash matches, it is reported OK; if
every sorted field matches and only the hash differs, it reports "differs by extension
ORDER only", which is correct for a browser that shuffles and **wrong** for one that does
not (Safari, whose order is fixed — and whose hash does match). The comparable fields are
the version, the cipher list in order, the extension *set*, the curves and the point
formats. (JA4 sorts, so peet's ja4 is directly comparable.)

**This step checks what the self-test cannot.** A ClientHello can never be compared byte
for byte — the client random, the key_share public key, the session id, the GREASE values
and (for Chrome) the extension order change every time — so the self-test can only compare
a "shape", and the shape is defined by my own understanding of it. The peet half is a
**hash computed independently by a third party**, which catches the blind spot in checking
yourself against yourself; and the `--resume` path (the PSK extension) cannot be tested
offline at all, because our probe refuses to issue session tickets.

Incidentally, a reference collected automatically comes from the browser's `fetch()`, which
is an XHR rather than a navigation, so `verify_fp.py` switches to the `xhr` template when
it sees `sec-fetch-mode: cors` — currently the only way to verify the `xhr` template
against a real browser.

For chrome, `--resume` should be eight-for-eight, including
`ja4 = t13d1517h2_8daaf6152771_a87ad97598a9` and
`peetprint_hash = 35fc5e864929e3b01e9ba9eb41bc1360`. Without `--resume` the `ja4` is one
extension shorter (`0029` pre_shared_key) and the `peetprint_hash` differs accordingly —
**which is correct**, since a first connection from Chrome behaves the same way.

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
Safari both send a 12-byte supported_groups listing entirely different groups. Bodies that
are random by design are exempt — the ECH GREASE payload, a PSK — and key_share is compared
as `group:keylen` pairs, since the public keys beside them are fresh every time.

Only the first HEADERS frame of a connection is compared: the HPACK dynamic table is
stateful, and only at the start of a connection are both sides guaranteed to be empty.

Current result: both installed brands pass all three layers — 455 identical HPACK bytes for
`chrome`, 290 for `safari_ios`.

Extension **order** is compared as a set plus the first and last positions, not as a
sequence, because Chrome (and we) shuffle it per connection. Safari does not shuffle, and
its fixed order is what makes its JA3 hash comparable in `verify_fp.py`.

To compare two files by hand, `diff` takes paths as well as brand names:

```bash
python hpack_probe.py serve --out /tmp/ours.json &   # --out: do not register a brand
python hpack_probe.py client --brand chrome
python hpack_probe.py diff chrome /tmp/ours.json
```

The self-signed certificate and other generated files live in `~/.cache/hpack_probe/` and
never enter the repository; `HPACK_PROBE_DIR` moves them.

---

## Two headers that vary

Capturing showed that Chrome itself is not consistent about these two. Do not treat them as
constants:

* **`cache-control: max-age=0`** — sent on a reload or when re-entering the address bar,
  **not sent on a fresh navigation**. Both were seen in real captures. The switch is
  `prof.send_cache_control`.
* **`accept-language`** — follows the browser's UI language; the default is whatever the
  capture had (the current `chrome` capture came from a fresh profile: `en-US,en;q=0.9`).

`verify_fp.py` aligns both to what `references/<brand>.json` actually sent, so neither has
to be set by hand.

---

## Known non-goals / caveats

* **The `xhr` template's order is only measured when a reference exists.** A brand without
  one uses the order inferred from navigate; measurement shows a real XHR moves the client
  hints to either side of `user-agent`, unlike the inference. Getting the peet half at
  capture time avoids the problem entirely.
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
  only header order, and this module's header templates apply to the h2 path only.
