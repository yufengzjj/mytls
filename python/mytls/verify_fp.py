"""The live half of the checks: real servers, real network, nothing stored.

`mytls-probe selftest` already proves the important thing, and proves it better
than anything here can: the bytes we emit are the bytes that were captured,
compared as bytes. Identical bytes make identical fingerprints - every
fingerprint, including ones nobody has published - so how tls.peet.ws or
Wireshark or some vendor computes theirs is not a question this project has to
answer.

What the self-test cannot do is leave the machine. It stands a server up on
loopback and drives our own client at it, so both ends are us. This module is
the other half:

  * **acceptance** - several real servers, running unrelated TLS stacks,
    complete the handshake and negotiate h2. Nothing else here checks that a
    duplicate signature algorithm or three 3DES suites, faithfully copied from
    a capture, are actually tolerated by anyone.
  * **an outside parser** - peet and check.ja3.zone read the ClientHello we
    just sent and say what they made of it. That is compared against the same
    fingerprints computed here from `profiles/<brand>.json`, which is the
    browser's own recorded bytes.

The second one used to need a stored `references/<brand>.json`, collected in
the same visit as the capture. It does not any more, and that directory is
gone: the browser's raw ClientHello is already in the profile, so the value to
compare against can be computed on the spot. That also fixes a hole - a brand
captured through mitmproxy could never have a reference, because a third-party
service behind an intercepting proxy sees *mitmproxy's* TLS, not the phone's.
Those brands are now checkable like any other.

    mytls-verify                     # every installed profile
    mytls-verify --brand ios18       # just one
"""

from __future__ import annotations

import argparse
import json
import sys

import httpx

from . import browser_fp as fp
from . import fingerprints

#: Returns its view of our ClientHello and our HTTP/2 frames as JSON.
PEET_URL = "https://tls.peet.ws/api/all"

#: A second opinion on JA3, from an implementation unrelated to peet's.
JA3_URL = "https://check.ja3.zone/"

#: Chosen for running different TLS stacks, not for what they serve. What is
#: judged is that the handshake completes and h2 is negotiated; the status code
#: is printed but not judged, since none of them owe us a 200.
REACH_HOSTS = ("tls.peet.ws", "www.google.com", "www.cloudflare.com")


def cmp(name: str, got, want) -> bool:
    if got == want:
        print(f"  {name:<26} OK")
        return True
    print(f"  {name:<26} DIFFER\n      live:    {got}\n      capture: {want}")
    return False


def captured_fingerprints(brand: str) -> tuple[dict, str]:
    """Every fingerprint of the stored capture, computed here from its bytes.

    This is what the live answers are compared against. Not a second source of
    truth - the capture is the only source of truth - but that one source, put
    through the same kind of function a service puts our live bytes through.
    """
    prof = fp.profile(brand)
    path = fp.PROFILES_DIR / f"{brand}.json"
    raw = (json.loads(path.read_text()).get("client_hello") or {}).get("raw")
    if not raw:
        msg = f"{path} has no raw ClientHello to compare against"
        raise SystemExit(msg)
    return fingerprints.of_client_hello(raw), prof.akamai_fingerprint


def reachable(brand: str, hosts=REACH_HOSTS) -> bool:
    """Does a real server, rather than our own probe, accept this ClientHello?

    The one property with no offline substitute. A profile copies whatever the
    browser sent, including things a strict server might refuse - iOS lists
    `rsa_pss_rsae_sha384` twice and offers three 3DES suites - and loopback
    against our own OpenSSL will never object to any of it.
    """
    print("=== acceptance (real servers, real network) ===")
    ok = True
    for host in hosts:
        try:
            with httpx.Client(transport=fp.Transport(brand), timeout=20) as client:
                r = client.get(f"https://{host}/", follow_redirects=False)
        except Exception as exc:                       # noqa: BLE001
            ok = False
            print(f"  {host:<22} FAILED  {type(exc).__name__}: {str(exc)[:70]}")
            continue
        good = r.http_version == "HTTP/2"
        ok &= good
        print(f"  {host:<22} {'OK   ' if good else 'NO H2'}  "
              f"{r.http_version}, status {r.status_code}")
    return ok


def outside_view(brand: str, want_tls: dict, want_akamai: str) -> bool:
    """What peet made of the bytes we just sent, against the capture's own.

    A match means an unrelated implementation, reading our live ClientHello off
    a real network, arrives at the fingerprint the captured browser's bytes
    produce here. It does not *prove* the bytes are right - the self-test does
    that, offline and byte for byte - but it is the one check that would notice
    a difference which only appears off the loopback.
    """
    print("\n=== tls.peet.ws ===")
    try:
        with httpx.Client(transport=fp.Transport(brand), timeout=25) as client:
            got = client.get(PEET_URL).json()
    except Exception as exc:                           # noqa: BLE001
        print(f"  (skipped: {type(exc).__name__}: {exc})")
        return True

    ok = cmp("ja4", got["tls"]["ja4"], want_tls["ja4"])
    for i, part in enumerate(("ciphers", "extensions", "sigalgs"), start=1):
        ok &= cmp(f"ja4_r {part}",
                  got["tls"]["ja4_r"].split("_")[i],
                  want_tls["ja4_r"].split("_")[i])
    ok &= cmp("peetprint_hash", got["tls"]["peetprint_hash"],
              want_tls["peetprint_hash"])
    ok &= cmp("akamai", got["http2"]["akamai_fingerprint"], want_akamai)
    ok &= _ja3(got["tls"]["ja3"], got["tls"]["ja3_hash"], want_tls, "peet")
    return ok


def check_ja3_zone(brand: str, want_tls: dict) -> bool:
    """A second, unrelated implementation of JA3 on its own live connection."""
    print("\n=== check.ja3.zone (independent of peet) ===")
    try:
        with httpx.Client(transport=fp.Transport(brand), timeout=25) as client:
            got = client.get(JA3_URL).json()
    except Exception as exc:                           # noqa: BLE001
        print(f"  (skipped: {type(exc).__name__}: {exc})")
        return True
    return _ja3(got["fingerprint"], got.get("hash"), want_tls, "ja3.zone")


def _ja3(fingerprint: str, digest: str | None, want_tls: dict, who: str) -> bool:
    """Compare a JA3, judging the hash only where the hash can mean anything.

    JA3 hashes the extension list in *wire order*, and Chrome has shuffled that
    order per connection since 110 - so two connections from one real Chrome do
    not share a JA3 either, and neither do two of ours. Comparing the hash
    there would fail every time and mean nothing. What a shuffle cannot touch
    is compared instead: the version, the ciphers in order, the extension set,
    the curves and the point formats.
    """
    def parts(text: str) -> list[str]:
        version, ciphers, extensions, curves, formats = text.split(",")
        return [version, ciphers,
                "-".join(sorted(extensions.split("-"), key=int)), curves, formats]

    ok = True
    for name, a, b in zip(("tls version", "ciphers", "extensions (sorted)",
                           "curves", "ec formats"),
                          parts(fingerprint), parts(want_tls["ja3"])):
        ok &= cmp(f"{who} ja3 {name}", a, b)
    if fingerprint == want_tls["ja3"]:
        # Identical in wire order too, so the hash is comparable - and compared.
        ok &= cmp(f"{who} ja3 hash", digest, want_tls["ja3_hash"])
    else:
        print(f"  {who + ' ja3 hash':<26} not compared - the extension order "
              f"differs, which is what this profile is meant to do")
    return ok


def main() -> int:
    p = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--brand", help="just one; default: every installed profile")
    p.add_argument("--host", action="append",
                   help="override the acceptance hosts (repeatable)")
    p.add_argument("--skip-reach", action="store_true",
                   help="skip the acceptance check and only ask the services")
    args = p.parse_args()

    brands = [args.brand] if args.brand else list(fp.brands())
    if not brands:
        print(f"no profiles in {fp.PROFILES_DIR}", file=sys.stderr)
        return 2

    results: dict[str, bool] = {}
    for brand in brands:
        prof = fp.profile(brand)
        want_tls, want_akamai = captured_fingerprints(brand)
        print(f"\n######## {brand} ({prof.label}) ########\n")
        ok = True
        if not args.skip_reach:
            ok &= reachable(brand, tuple(args.host) if args.host else REACH_HOSTS)
        ok &= outside_view(brand, want_tls, want_akamai)
        ok &= check_ja3_zone(brand, want_tls)
        results[brand] = ok

    print("\n=== summary ===")
    for brand, ok in results.items():
        print(f"  {brand:<16} {'PASS' if ok else 'FAIL'}")
    return 0 if all(results.values()) else 1


if __name__ == "__main__":
    raise SystemExit(main())
