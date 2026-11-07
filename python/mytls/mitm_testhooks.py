"""mitmproxy hooks for the self-tests that go through mitmproxy. Not for deployment.

Loaded by `mytls-probe mitm-selftest` and `mytls-verify --via-mitm` beside the
TLS addon under test (`mitm_upstream.py`, or a script of your own that takes
the same `fp_profile` option). Both options are off unless set.

* `fp_connect_to` opens every upstream TCP connection to one `host:port`, while
  SNI and `:authority` stay what the client asked for. That is what lets the
  offline self-test replay a capture taken at `192-168-1-7.nip.io:8443`
  against a probe on loopback, and so compare *every* byte - `:authority` and
  the server_name extension included - where the direct self-test has to
  excuse them.
* `fp_report` appends one JSON line per HTTP response describing the upstream
  connection. Through a proxy the client only ever learns what it negotiated
  with mitmproxy, so this is the only way to see the other side.

Imports nothing from `mytls`: it runs in whichever interpreter mitmdump is.
"""

from __future__ import annotations

import json
import logging

from mitmproxy import ctx
from mitmproxy import exceptions
from mitmproxy import http
from mitmproxy.proxy import server_hooks


def _address(spec: str) -> tuple[str, int]:
    host, sep, port = spec.rpartition(":")
    if not sep or not port.isdigit():
        raise exceptions.OptionsError(f"fp_connect_to must be host:port, not {spec!r}")
    return host.strip("[]"), int(port)


class TestHooks:
    def load(self, loader) -> None:
        loader.add_option(
            "fp_connect_to", str, "",
            "Self-test only: open every upstream TCP connection to this "
            "host:port instead, keeping SNI and :authority unchanged.")
        loader.add_option(
            "fp_report", str, "",
            "Self-test only: append one JSON line per response, describing the "
            "upstream connection, to this file.")

    def configure(self, updated) -> None:
        if "fp_connect_to" in updated and ctx.options.fp_connect_to:
            _address(ctx.options.fp_connect_to)

    def server_connect(self, data: server_hooks.ServerConnectionHookData) -> None:
        if ctx.options.fp_connect_to:
            # server.sni was settled from what the client asked for; only where
            # the bytes go changes.
            data.server.address = _address(ctx.options.fp_connect_to)

    def response(self, flow: http.HTTPFlow) -> None:
        if not ctx.options.fp_report:
            return
        server = flow.server_conn
        record = {
            "url": flow.request.pretty_url,
            "status": flow.response.status_code if flow.response else None,
            "upstream_http_version": flow.response.http_version if flow.response else None,
            "upstream_alpn": server.alpn.decode(errors="replace") if server.alpn else None,
            "upstream_tls_version": server.tls_version,
            "upstream_cipher": server.cipher,
            "upstream_sni": server.sni,
        }
        try:
            with open(ctx.options.fp_report, "a", encoding="utf-8") as f:
                f.write(json.dumps(record) + "\n")
        except OSError as exc:
            logging.warning(f"fp_report: {exc}")


addons = [TestHooks()]
