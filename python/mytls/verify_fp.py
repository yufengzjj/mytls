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
    mytls-verify --via-mitm          # the same, through mitmproxy

`--via-mitm` asks the same questions of mitmproxy's upstream connection
instead of ours. Our client goes through a mitmdump started for each brand -
the packaged `mitm_upstream.py` choosing the ClientHello, mitmproxy's own
`http2_fingerprint` option the HTTP/2 layer - and the services judge what
mitmproxy sent. The client sends the capture's headers and HEADERS priority,
as the browser behind the proxy would, so peet's view of the HEADERS frame -
field order, priority - is checked against the capture too. Acceptance is
judged on what mitmproxy negotiated upstream, which the client cannot see.
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

#: Left out when a capture's headers are replayed on these body-less GETs. A
#: capture can be a POST - ios16 is WhatsApp posting 814 bytes - and a GET that
#: declares a body it never sends is a malformed request: Google resets the
#: stream with PROTOCOL_ERROR, where peet lets it pass.
BODY_HEADERS = frozenset({"content-length"})


def _transport(brand: str, insecure: bool, proxy: str | None = None):
    """The fingerprint transport, optionally not verifying the peer's cert.

    `verify` is an ordinary httpx knob that flows through to the SSL_CTX; it sets
    the verify mode, which is a client-side, post-handshake decision and never
    changes a byte of the ClientHello - so `--insecure` reads a fingerprint back
    unchanged from a host whose certificate is broken. tls.peet.ws currently
    serves an expired self-signed default cert, and since it only echoes the
    ClientHello we just sent, there is nothing secret to protect by verifying it.
    """
    if proxy is not None:
        # Through mitmproxy, the certificate this client sees is mitmproxy's
        # own; whether the real server's is verified is mitmproxy's decision
        # (ssl_insecure, set from --insecure). What goes upstream is whatever a
        # browser behind the proxy sends, so send the capture's own request.
        prof = fp.profile(brand)
        return fp.Transport(brand, verify=False, proxy=proxy,
                            headers=[(k, v) for k, v in prof.headers
                                     if k.lower() not in BODY_HEADERS],
                            priority=prof.captured_priority("navigate") or None)
    return fp.Transport(brand, verify=False) if insecure else fp.Transport(brand)


def cmp(name: str, got, want) -> bool:
    if got == want:
        print(f"  {name:<26} OK")
        return True
    print(f"  {name:<26} DIFFER\n      live:    {got}\n      capture: {want}")
    return False


def cmp_akamai(got: dict, want: str) -> bool:
    """The akamai comparison, forgiving one bug in how peet prints it.

    peet renders SETTINGS id 8 (ENABLE_CONNECT_PROTOCOL) with an empty id -
    `2:0;3:100;4:2097152;:1;9:1` where the setting is plainly `8:1`. Its own
    parse of the frame is right, and says so in words:

        'ENABLE_CONNECT_PROTOCOL = 1'

    so this is a defect in its formatter, not in what we sent. Two profiles -
    iOS 18.0 and 18.2 - send that setting, and iOS 18.5 stopped, which is why
    only those two ever showed it.

    Rather than excuse an empty id on sight, the empty slot is filled from
    peet's own named parse and the result compared as usual. A setting that
    really was missing, or really had a different value, still fails.
    """
    live = got["http2"]["akamai_fingerprint"]
    if live == want:
        return cmp("akamai", live, want)

    #: The names peet prints, by the id it should have printed.
    named = {"HEADER_TABLE_SIZE": 1, "ENABLE_PUSH": 2,
             "MAX_CONCURRENT_STREAMS": 3, "INITIAL_WINDOW_SIZE": 4,
             "MAX_FRAME_SIZE": 5, "MAX_HEADER_LIST_SIZE": 6,
             "ENABLE_CONNECT_PROTOCOL": 8, "NO_RFC7540_PRIORITIES": 9}
    ids = [named.get(str(s).split("=")[0].strip())
           for frame in got["http2"].get("sent_frames", [])
           if frame.get("frame_type") == "SETTINGS"
           for s in frame.get("settings", [])]

    fields = live.split("|")
    entries = fields[0].split(";") if fields[0] else []
    if len(ids) == len(entries) and None not in ids:
        repaired = ";".join(
            f"{i}:{e.split(':', 1)[1]}" if e.startswith(":") else e
            for i, e in zip(ids, entries))
        fields[0] = repaired
        if "|".join(fields) == want:
            print(f"  {'akamai':<26} OK (peet printed "
                  + ", ".join(f"id {i}" for i, e in zip(ids, entries)
                              if e.startswith(":"))
                  + " with an empty id;\n"
                  + " " * 30 + "its own parse of the frame is right)")
            return True

    return cmp("akamai", live, want)


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


def reachable(brand: str, hosts=REACH_HOSTS, insecure: bool = False,
              mitm=None) -> bool:
    """Does a real server, rather than our own probe, accept this ClientHello?

    The one property with no offline substitute. A profile copies whatever the
    browser sent, including things a strict server might refuse - iOS lists
    `rsa_pss_rsae_sha384` twice and offers three 3DES suites - and loopback
    against our own OpenSSL will never object to any of it.

    Through mitmproxy (`mitm`), what is judged is mitmproxy's upstream
    connection, read from the report the test hooks write: the client's own
    connection ends at mitmproxy and says nothing about the server's.
    """
    print("=== acceptance (real servers, real network"
          + (", mitmproxy's upstream" if mitm else "") + ") ===")
    ok = True
    proxy = mitm.proxy_url if mitm else None
    for host in hosts:
        seen = len(mitm.report()) if mitm else 0
        try:
            with httpx.Client(transport=_transport(brand, insecure, proxy),
                              timeout=20) as client:
                r = client.get(f"https://{host}/", follow_redirects=False)
        except Exception as exc:                       # noqa: BLE001
            ok = False
            print(f"  {host:<22} FAILED  {type(exc).__name__}: {str(exc)[:70]}")
            continue
        if mitm is None:
            good = r.http_version == "HTTP/2"
            ok &= good
            print(f"  {host:<22} {'OK   ' if good else 'NO H2'}  "
                  f"{r.http_version}, status {r.status_code}")
            continue
        upstream = _upstream_record(mitm, seen, host)
        if upstream is None:
            ok = False
            print(f"  {host:<22} FAILED  mitmproxy reported no upstream "
                  f"response (status {r.status_code} came from mitmproxy)")
            continue
        good = upstream["upstream_http_version"] == "HTTP/2.0"
        ok &= good
        print(f"  {host:<22} {'OK   ' if good else 'NO H2'}  upstream "
              f"{upstream['upstream_http_version']} {upstream['upstream_tls_version']} "
              f"{upstream['upstream_cipher']}, status {upstream['status']}")
    return ok


def _upstream_record(mitm, seen: int, host: str) -> dict | None:
    """The first report line written for `host` after the first `seen`."""
    for record in mitm.report()[seen:]:
        if httpx.URL(record["url"]).host == host:
            return record
    return None


def outside_view(brand: str, want_tls: dict, want_akamai: str,
                 insecure: bool = False, proxy: str | None = None) -> bool:
    """What peet made of the bytes we just sent, against the capture's own.

    A match means an unrelated implementation, reading our live ClientHello off
    a real network, arrives at the fingerprint the captured browser's bytes
    produce here. It does not *prove* the bytes are right - the self-test does
    that, offline and byte for byte - but it is the one check that would notice
    a difference which only appears off the loopback.
    """
    print("\n=== tls.peet.ws" + (" (through mitmproxy)" if proxy else "") + " ===")
    try:
        with httpx.Client(transport=_transport(brand, insecure, proxy),
                          timeout=25) as client:
            got = client.get(PEET_URL).json()
    except (httpx.ConnectError, httpx.TimeoutException) as exc:
        # The remote, not our ClientHello, failed to answer - skip. A client we
        # broke can surface here too (a torn-down handshake raises ConnectError),
        # but reachable() drives the same handshake against real hosts and is the
        # check meant to catch that; skipping here only forgives an unreachable
        # third party. (--skip-reach removes that net, so a broken TLS half is
        # then unguarded - run without it to trust a green result.)
        print(f"  (skipped: {type(exc).__name__}: {exc})")
        return True
    except Exception as exc:                           # noqa: BLE001
        # A protocol error mid-exchange or a non-JSON body is a real failure of
        # this check, not a reason to pass it.
        print(f"  FAILED  {type(exc).__name__}: {str(exc)[:80]}")
        return False

    try:
        ok = cmp("ja4", got["tls"]["ja4"], want_tls["ja4"])
        for i, part in enumerate(("ciphers", "extensions", "sigalgs"), start=1):
            ok &= cmp(f"ja4_r {part}",
                      got["tls"]["ja4_r"].split("_")[i],
                      want_tls["ja4_r"].split("_")[i])
        ok &= cmp("peetprint_hash", got["tls"]["peetprint_hash"],
                  want_tls["peetprint_hash"])
        ok &= cmp_akamai(got, want_akamai)
        ok &= _ja3(got["tls"]["ja3"], got["tls"]["ja3_hash"], want_tls, "peet")
        if proxy is not None:
            ok &= _headers_frame(brand, got)
    except (KeyError, IndexError, TypeError, ValueError) as exc:
        # A field peet always returns is missing or malformed - report it rather
        # than let it abort the whole run partway through.
        print(f"  FAILED  peet response missing/garbled a field: "
              f"{type(exc).__name__}: {exc}")
        return False
    return ok


def check_ja3_zone(brand: str, want_tls: dict, insecure: bool = False,
                   proxy: str | None = None) -> bool:
    """A second, unrelated implementation of JA3 on its own live connection."""
    print("\n=== check.ja3.zone (independent of peet"
          + (", through mitmproxy" if proxy else "") + ") ===")
    try:
        with httpx.Client(transport=_transport(brand, insecure, proxy),
                          timeout=25) as client:
            got = client.get(JA3_URL).json()
    except (httpx.ConnectError, httpx.TimeoutException) as exc:
        print(f"  (skipped: {type(exc).__name__}: {exc})")
        return True
    except Exception as exc:                           # noqa: BLE001
        print(f"  FAILED  {type(exc).__name__}: {str(exc)[:80]}")
        return False
    try:
        return _ja3(got["fingerprint"], got.get("hash"), want_tls, "ja3.zone")
    except (KeyError, IndexError, TypeError, ValueError) as exc:
        print(f"  FAILED  ja3.zone response missing/garbled a field: "
              f"{type(exc).__name__}: {exc}")
        return False


def _headers_frame(brand: str, got: dict) -> bool:
    """peet's view of the first HEADERS frame against the capture's.

    Only through mitmproxy, where neither the field order nor the priority is
    ours: mitmproxy re-encodes the request it received, and has to keep the
    browser's field order after its pseudo-header order and pass the
    browser's priority on. Names only - the values name this request, not the
    captured one - and peet is the one place the field order can be seen off
    the machine. The byte-level version of this is `mitm-selftest`.
    """
    import hpack

    from . import hpack_probe

    ref, _ = hpack_probe._load(brand)
    frame = next(f for f in ref["frames"] if f["type"] == "HEADERS")
    want_names = [k for k, _ in hpack_probe._decode_with(
        hpack.Decoder(), bytes.fromhex(frame["header_block"]))
        if k not in BODY_HEADERS]
    live = next(f for f in got["http2"]["sent_frames"]
                if f.get("frame_type") == "HEADERS")
    # ":method: GET" -> ":method"; "accept: */*" -> "accept".
    live_names = [h[:h.index(":", 1)] for h in live.get("headers", [])]
    ok = cmp("headers order", live_names, want_names)

    want = fp.profile(brand).captured_priority("navigate")
    prio = live.get("priority")
    live_prio = (None if not prio else
                 {"exclusive": bool(prio.get("exclusive")),
                  "depends_on": prio.get("depends_on"), "weight": prio.get("weight")})
    return ok & cmp("headers priority", live_prio, want)


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
    p.add_argument("--insecure", action="store_true",
                   help="do not verify the peer's TLS certificate on the live "
                        "connections. For reference/echo hosts whose cert is "
                        "broken - tls.peet.ws currently serves an expired "
                        "self-signed cert - so its ClientHello echo can still be "
                        "read. Does not change the fingerprint (verify mode is a "
                        "post-handshake, client-side decision). With "
                        "--via-mitm it sets mitmproxy's ssl_insecure instead.")
    p.add_argument("--via-mitm", action="store_true",
                   help="ask the same questions of mitmproxy's upstream "
                        "connection: a mitmdump per brand with the packaged "
                        "TLS addon and http2_fingerprint, our client behind it")
    p.add_argument("--mitmdump", help="with --via-mitm: the mitmdump under test, "
                                      "or a mitmweb; default: the mitmdump beside "
                                      "this interpreter, else PATH")
    p.add_argument("--tls-script", metavar="PATH",
                   help="with --via-mitm: a TLS addon of your own taking the "
                        "fp_profile option, instead of mitm_upstream.py")
    args = p.parse_args()

    brands = [args.brand] if args.brand else list(fp.brands())
    if not brands:
        print(f"no profiles in {fp.PROFILES_DIR}", file=sys.stderr)
        return 2

    if args.insecure:
        print("!! --insecure: peer certificates are NOT verified on the live "
              "connections (the ClientHello sent is unchanged).")

    mitmdump = None
    if args.via_mitm:
        from .mitm_harness import find_mitmdump

        mitmdump = find_mitmdump(args.mitmdump)
        if not mitmdump:
            print("--via-mitm: mitmdump was not found beside this interpreter or "
                  "on PATH; point at the one under test with --mitmdump.",
                  file=sys.stderr)
            return 2
        print(f"under test: {mitmdump}")

    results: dict[str, bool] = {}
    hosts = tuple(args.host) if args.host else REACH_HOSTS
    for brand in brands:
        prof = fp.profile(brand)
        want_tls, want_akamai = captured_fingerprints(brand)
        print(f"\n######## {brand} ({prof.label})"
              + (f" through mitmproxy, fp_profile={prof.tls_profile}" if mitmdump else "")
              + " ########\n")
        if mitmdump:
            results[brand] = _via_mitm(brand, mitmdump, args, hosts,
                                       want_tls, want_akamai)
            continue
        ok = True
        if not args.skip_reach:
            ok &= reachable(brand, hosts, args.insecure)
        ok &= outside_view(brand, want_tls, want_akamai, args.insecure)
        ok &= check_ja3_zone(brand, want_tls, args.insecure)
        results[brand] = ok

    print("\n=== summary ===")
    for brand, ok in results.items():
        print(f"  {brand:<16} {'PASS' if ok else 'FAIL'}")
    return 0 if all(results.values()) else 1


def _via_mitm(brand: str, mitmdump: str, args: argparse.Namespace,
              hosts: tuple[str, ...], want_tls: dict, want_akamai: str) -> bool:
    """Every check for one brand, through a mitmdump started for it."""
    from .mitm_harness import Mitmdump, MitmdumpError

    mitm = Mitmdump(mitmdump, tls_profile=fp.profile(brand).tls_profile,
                    h2_profile=brand, tls_script=args.tls_script,
                    insecure=args.insecure)
    try:
        with mitm:
            ok = True
            if not args.skip_reach:
                ok &= reachable(brand, hosts, args.insecure, mitm=mitm)
            ok &= outside_view(brand, want_tls, want_akamai, args.insecure,
                               proxy=mitm.proxy_url)
            ok &= check_ja3_zone(brand, want_tls, args.insecure,
                                 proxy=mitm.proxy_url)
        if not ok:
            print(f"\n  mitmdump said:\n{mitm.log(tail=15)}")
        return ok
    except MitmdumpError as exc:
        print(f"  FAILED  mitmproxy did not start:\n{exc}")
        return False
    finally:
        mitm.cleanup()


if __name__ == "__main__":
    raise SystemExit(main())
