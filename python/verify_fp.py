"""Diff our fingerprint against a tls.peet.ws capture of real Chrome.

Fetches the same endpoint the reference came from and compares field by field.
Pass --resume to make the second (session-resumed) request the one that gets
compared, which is what references/chrome150_peet.json is - it carries a
pre_shared_key, so a plain request is legitimately one extension short.

    python verify_fp.py            # TLS (minus PSK) + the whole h2 layer
    python verify_fp.py --resume   # TLS including PSK
"""

import json
import socket
import ssl
import sys

from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import chrome_h2  # noqa: E402
import httpx  # noqa: E402

HERE = Path(__file__).resolve().parent
REFERENCE = HERE / "references" / "chrome150_peet.json"
REF = json.loads(REFERENCE.read_text())


def _align_to_reference() -> None:
    """Match the two headers that depend on how the reference was captured.

    `accept-language` follows the Chrome profile's UI language and
    `cache-control: max-age=0` only appears on a reload, so the two reference
    captures legitimately disagree on them. Comparing anything else would be
    meaningless if these were left mismatched, and making the caller remember
    to set them by hand is a trap.
    """
    for frame in REF.get("http2", {}).get("sent_frames", []):
        if frame.get("frame_type") != "HEADERS":
            continue
        sent = dict(h.split(": ", 1) for h in frame["headers"] if ": " in h)
        if "accept-language" in sent:
            chrome_h2.ACCEPT_LANGUAGE = sent["accept-language"]
        chrome_h2.SEND_CACHE_CONTROL = "cache-control" in sent
        return


_align_to_reference()
URL = "https://tls.peet.ws/api/all"
HOST = "tls.peet.ws"
UA = REF["user_agent"]


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


def fetch_plain() -> dict:
    with httpx.Client(transport=chrome_h2.ChromeTransport(), timeout=30) as c:
        return c.get(URL, headers={"User-Agent": UA}).json()


def cmp(label: str, ours, theirs) -> bool:
    ok = ours == theirs
    print("  %-26s %s" % (label, "OK" if ok else "DIFFER"))
    if not ok:
        print("      chrome150: %s" % (theirs,))
        print("      ours     : %s" % (ours,))
    return ok


def main() -> int:
    resumed = "--resume" in sys.argv
    got = fetch_resumed() if resumed else fetch_plain()

    print("=== TLS ===")
    ok = True
    ok &= cmp("ja4", got["tls"]["ja4"], REF["tls"]["ja4"])
    ok &= cmp("ja4_r ciphers",
              got["tls"]["ja4_r"].split("_")[1], REF["tls"]["ja4_r"].split("_")[1])
    ok &= cmp("ja4_r extensions",
              got["tls"]["ja4_r"].split("_")[2], REF["tls"]["ja4_r"].split("_")[2])
    ok &= cmp("ja4_r sigalgs",
              got["tls"]["ja4_r"].split("_")[3], REF["tls"]["ja4_r"].split("_")[3])
    ok &= cmp("ja3 ciphers",
              got["tls"]["ja3"].split(",")[1], REF["tls"]["ja3"].split(",")[1])
    ok &= cmp("ja3 groups",
              got["tls"]["ja3"].split(",")[3], REF["tls"]["ja3"].split(",")[3])
    ok &= cmp("ja3 ec_formats",
              got["tls"]["ja3"].split(",")[4], REF["tls"]["ja3"].split(",")[4])
    ok &= cmp("peetprint_hash",
              got["tls"]["peetprint_hash"], REF["tls"]["peetprint_hash"])

    if resumed:
        # The resumed request is driven over a raw socket speaking HTTP/1.1,
        # purely to get a ClientHello that carries a PSK, so there is no h2
        # layer to look at here. The plain run covers it.
        print("\n(resumed run is HTTP/1.1 - see the plain run for the h2 layer)")
        print("\n%s" % ("全部一致" if ok else "存在差异"))
        return 0 if ok else 1

    print("\n=== HTTP/2 ===")
    ok &= cmp("akamai", got["http2"]["akamai_fingerprint"],
              REF["http2"]["akamai_fingerprint"])
    ok &= cmp("akamai_hash", got["http2"]["akamai_fingerprint_hash"],
              REF["http2"]["akamai_fingerprint_hash"])

    def frames(d):
        return {f["frame_type"]: f for f in d["http2"]["sent_frames"]}

    gf, rf = frames(got), frames(REF)
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

    print("\n%s" % ("全部一致" if ok else "存在差异"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
