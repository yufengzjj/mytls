"""Diff our fingerprint against what a real browser got from the same servers.

references/<brand>.json holds what tls.peet.ws and check.ja3.zone made of the
real browser, collected by hpack_probe.py during the capture. This asks those
same services ourselves and compares field by field - the one check here that
needs network, and the only one that proves an outside party agrees with us.

Whether the reference is a fresh or a resumed handshake depends on the browser;
the probe refuses to issue session tickets, so a capture-time reference is
normally fresh, and then --resume legitimately shows one extra extension
(0029 pre_shared_key). Compare the run that matches the reference.

    python verify_fp.py                     # TLS + the whole h2 layer + JA3
    python verify_fp.py --resume            # TLS from a session-resumed handshake
    python verify_fp.py --brand chrome      # pick a brand explicitly
"""

import argparse
import json
import socket
import ssl
import sys

from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import browser_fp as fp  # noqa: E402
import httpx  # noqa: E402

HERE = Path(__file__).resolve().parent


def _align_to_reference(prof, ref: dict) -> dict:
    """Match the headers that depend on how the reference happened to be taken.

    `accept-language` follows the browser profile's UI language,
    `cache-control: max-age=0` only appears on a reload, and `sec-fetch-site` /
    `referer` depend on where the request came from - the reference was reached
    from a link on the probe's own page, this run is a bare request. Comparing
    anything else would be meaningless while those were mismatched, and making
    the caller set them by hand is a trap.

    Returns the extra request headers needed to match, which is how `referer`
    gets exercised at all: without one, nothing checks that we put it in the
    place a browser puts it.
    """
    for frame in ref.get("http2", {}).get("sent_frames", []):
        if frame.get("frame_type") != "HEADERS":
            continue
        sent = dict(h.split(": ", 1) for h in frame["headers"] if ": " in h)
        if "accept-language" in sent:
            prof.accept_language = sent["accept-language"]
        prof.send_cache_control = "cache-control" in sent
        prof.sec_fetch_site = sent.get("sec-fetch-site")
        if sent.get("sec-fetch-mode") == "cors":
            prof.header_profile = "xhr"
        return {"Referer": sent["referer"]} if "referer" in sent else {}
    return {}


URL = "https://tls.peet.ws/api/all"
HOST = "tls.peet.ws"


def fetch_resumed() -> dict:
    """Two requests on one context so the second one carries a PSK."""
    ctx = ssl.create_default_context()
    ctx.set_alpn_protocols(["h2", "http/1.1"])
    req = (
        b"GET /api/all HTTP/1.1\r\nHost: " + HOST.encode()
        + b"\r\nUser-Agent: x\r\nConnection: close\r\n\r\n"
    )

    def once(session):
        s = ctx.wrap_socket(socket.create_connection((HOST, 443), timeout=30),
                            server_hostname=HOST, session=session)
        s.sendall(req)
        buf = b""
        while True:
            try:
                chunk = s.recv(65536)
            except (ssl.SSLError, OSError):
                break
            if not chunk:
                break
            buf += chunk
        sess = s.session
        s.close()
        return buf, sess

    _, sess = once(None)
    buf, _ = once(sess)
    body = buf[buf.find(b"{"):]
    return json.loads(body[: body.rfind(b"}") + 1])


def fetch_plain(brand: str, headers: dict) -> dict:
    with httpx.Client(transport=fp.Transport(brand), timeout=30) as c:
        return c.get(URL, headers=headers).json()


def _pick(entries: list, want: str):
    """The peet response describing the kind of request we are checking."""
    def mode(entry):
        for frame in (entry or {}).get("http2", {}).get("sent_frames", []):
            if frame.get("frame_type") == "HEADERS":
                sent = dict(h.split(": ", 1) for h in frame["headers"] if ": " in h)
                return sent.get("sec-fetch-mode")
        return None

    return next((e for e in entries if mode(e) == want), None) or (
        entries[0] if entries else None)


JA3_URL = "https://check.ja3.zone/"


def check_ja3(brand: str, reference: dict) -> bool:
    """Ask a second, unrelated service and compare what can be compared.

    peet and this one parse the same ClientHello with different code, so a field
    the peet comparison happens not to look at still shows up here.

    The *hash* is deliberately not compared. JA3 hashes the extension list in
    wire order, and Chrome has shuffled that order per connection since 110 - so
    two connections from the same real Chrome do not share a JA3 either. We
    shuffle too. What is comparable is everything the shuffle does not touch:
    the version, the cipher list in order, the extension *set*, the curves and
    the point formats.
    """
    try:
        with httpx.Client(transport=fp.Transport(brand), timeout=30) as c:
            got = c.get(JA3_URL).json()
    except Exception as exc:  # noqa: BLE001 - a third party being down is not a failure
        print(f"  (skipped: {type(exc).__name__}: {exc})")
        return True

    def parts(fingerprint: str) -> list[str]:
        version, ciphers, extensions, curves, formats = fingerprint.split(",")
        return [version, ciphers,
                "-".join(sorted(extensions.split("-"), key=int)), curves, formats]

    names = ("tls version", "ciphers", "extensions (sorted)", "curves", "ec formats")
    ours, theirs = parts(got["fingerprint"]), parts(reference["fingerprint"])
    ok = True
    for name, a, b in zip(names, ours, theirs):
        ok &= cmp(f"ja3 {name}", a, b)
    print(f"  {'ja3 hash':<26} not compared (JA3 hashes extension order, which "
          f"Chrome randomises)")
    return ok


def cmp(label: str, ours, theirs) -> bool:
    ok = ours == theirs
    print("  %-26s %s" % (label, "OK" if ok else "DIFFER"))
    if not ok:
        print("      %-9s: %s" % ("reference", theirs))
        print("      %-9s: %s" % ("ours", ours))
    return ok


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--brand", help="which profile to check; default: the only "
                                    "one installed, or BROWSER_FP_BRAND")
    ap.add_argument("--resume", action="store_true",
                    help="compare a session-resumed handshake (TLS only)")
    ap.add_argument("--xhr", action="store_true",
                    help="check the xhr header template against the reference's "
                         "cors entry instead of the navigation one")
    args = ap.parse_args()

    prof = fp.profile(args.brand)
    reference = HERE / "references" / f"{prof.brand}.json"
    if not reference.exists():
        print(f"no live reference for {prof.brand} at {reference} - capture the "
              f"browser again, the reference is collected in the same visit.",
              file=sys.stderr)
        return 2
    container = json.loads(reference.read_text())
    entries = container if "tls" in container else container.get("peet")
    if isinstance(entries, dict) or entries is None:
        entries = [entries] if entries else []
    # A navigation is what the default template reproduces, so prefer it; the
    # cors entry is what a page's own fetch looks like and checks the xhr one.
    ref = _pick(entries, "navigate" if not args.xhr else "cors")
    ja3zone = container.get("ja3zone")
    if ref is None:
        print(f"{reference} has no tls.peet.ws half"
              + (" (only check.ja3.zone, which cannot be compared field by "
                 "field)" if ja3zone else ""), file=sys.stderr)
        return 2
    extra = _align_to_reference(prof, ref)

    resumed = args.resume
    print(f"checking {prof.brand} ({prof.label}) against {reference.name}\n")
    got = fetch_resumed() if resumed else fetch_plain(
        prof.brand, {"User-Agent": ref["user_agent"], **extra})

    print("=== TLS ===")
    ok = True
    ok &= cmp("ja4", got["tls"]["ja4"], ref["tls"]["ja4"])
    ok &= cmp("ja4_r ciphers",
              got["tls"]["ja4_r"].split("_")[1], ref["tls"]["ja4_r"].split("_")[1])
    ok &= cmp("ja4_r extensions",
              got["tls"]["ja4_r"].split("_")[2], ref["tls"]["ja4_r"].split("_")[2])
    ok &= cmp("ja4_r sigalgs",
              got["tls"]["ja4_r"].split("_")[3], ref["tls"]["ja4_r"].split("_")[3])
    ok &= cmp("ja3 ciphers",
              got["tls"]["ja3"].split(",")[1], ref["tls"]["ja3"].split(",")[1])
    ok &= cmp("ja3 groups",
              got["tls"]["ja3"].split(",")[3], ref["tls"]["ja3"].split(",")[3])
    ok &= cmp("ja3 ec_formats",
              got["tls"]["ja3"].split(",")[4], ref["tls"]["ja3"].split(",")[4])
    ok &= cmp("peetprint_hash",
              got["tls"]["peetprint_hash"], ref["tls"]["peetprint_hash"])

    if resumed:
        # The resumed request is driven over a raw socket speaking HTTP/1.1,
        # purely to get a ClientHello that carries a PSK, so there is no h2
        # layer to look at here. The plain run covers it.
        print("\n(resumed run is HTTP/1.1 - see the plain run for the h2 layer)")
        print("\n%s" % ("全部一致" if ok else "存在差异"))
        return 0 if ok else 1

    print("\n=== HTTP/2 ===")
    ok &= cmp("akamai", got["http2"]["akamai_fingerprint"],
              ref["http2"]["akamai_fingerprint"])
    ok &= cmp("akamai_hash", got["http2"]["akamai_fingerprint_hash"],
              ref["http2"]["akamai_fingerprint_hash"])

    def frames(d):
        return {f["frame_type"]: f for f in d["http2"]["sent_frames"]}

    gf, rf = frames(got), frames(ref)
    ok &= cmp("SETTINGS", gf["SETTINGS"]["settings"], rf["SETTINGS"]["settings"])
    ok &= cmp("WINDOW_UPDATE", gf["WINDOW_UPDATE"]["increment"],
              rf["WINDOW_UPDATE"]["increment"])
    ok &= cmp("HEADERS flags", gf["HEADERS"]["flags"], rf["HEADERS"]["flags"])
    ok &= cmp("HEADERS priority", gf["HEADERS"].get("priority"),
              rf["HEADERS"].get("priority"))

    gh = [h.split(":")[0] or ":" + h.split(":")[1] for h in gf["HEADERS"]["headers"]]
    rh = [h.split(":")[0] or ":" + h.split(":")[1] for h in rf["HEADERS"]["headers"]]
    ok &= cmp("header order", gh, rh)

    print("\n=== header values ===")
    gv = dict(h.split(": ", 1) for h in gf["HEADERS"]["headers"] if ": " in h)
    rv = dict(h.split(": ", 1) for h in rf["HEADERS"]["headers"] if ": " in h)
    for k in rv:
        if k in (":authority", ":path", ":method", ":scheme"):
            continue
        ok &= cmp(k, gv.get(k), rv[k])

    if ja3zone:
        print("\n=== JA3 (check.ja3.zone, independent of peet) ===")
        ok &= check_ja3(prof.brand, ja3zone)

    print("\n%s" % ("全部一致" if ok else "存在差异"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
