"""Run mitmdump as a child process for the tests that go through mitmproxy.

`mytls-probe mitm-selftest` and `mytls-verify --via-mitm` both need the same
thing: a mitmdump with the upstream addon loaded and one brand's TLS and HTTP/2
profiles selected, listening on a free loopback port, gone again afterwards,
and its output kept for when something goes wrong. That is this module.

mitmproxy runs out of process, as `capture-mitm` already does, so this file
imports nothing from it: the mitmdump under test may be another interpreter.
mitmweb works the same way (pass its path where a mitmdump is expected): it is
the same proxy with a web UI on top, which gets a free port of its own here.
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from . import upstream_addon_path


class MitmdumpError(RuntimeError):
    """mitmdump did not come up. The message carries what it printed."""


def find_mitmdump(explicit: str | None) -> str | None:
    """`--mitmdump`, else the one beside this interpreter, else PATH.

    Beside first for the same reason as `capture-mitm`: a venv's or pyenv
    interpreter's bin/ is usually not on PATH, and it is the mitmdump that
    shares this interpreter's cryptography - the one actually under test.
    """
    if explicit:
        return explicit
    beside = Path(sys.executable).parent / "mitmdump"
    if beside.exists():
        return str(beside)
    return shutil.which("mitmdump")


def free_port(host: str = "127.0.0.1") -> int:
    with socket.socket() as s:
        s.bind((host, 0))
        return s.getsockname()[1]


class Mitmdump:
    """One mitmdump for one brand, as a context manager.

        with Mitmdump(mitmdump, tls_profile="ios18", h2_profile="ios18") as m:
            ... proxy=m.proxy_url ...
            m.report()      # what each upstream connection negotiated

    `tls_script` replaces the packaged upstream addon with one of your own -
    for instance the fp_profile.py a deployment already uses - provided it
    takes the same `fp_profile` option. `mitm_testhooks.py` is loaded beside
    whichever it is.
    """

    def __init__(self, mitmdump: str, *, tls_profile: str, h2_profile: str,
                 tls_script: str | None = None, connect_to: str | None = None,
                 insecure: bool = False, extra: tuple[str, ...] = (),
                 startup_timeout: float = 20.0) -> None:
        self.mitmdump = mitmdump
        self.tls_profile = tls_profile
        self.h2_profile = h2_profile
        self.tls_script = tls_script
        self.connect_to = connect_to
        self.insecure = insecure
        self.extra = extra
        self.startup_timeout = startup_timeout
        self.port = 0
        self.web_port = 0
        self.proc: subprocess.Popen | None = None
        self._dir = Path(tempfile.mkdtemp(prefix="mytls-mitm-"))
        self.log_path = self._dir / "mitmdump.log"
        self.report_path = self._dir / "report.jsonl"

    @property
    def proxy_url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def argv(self) -> list[str]:
        argv = [self.mitmdump, "--listen-host", "127.0.0.1",
                "--listen-port", str(self.port),
                # Our own home for the CA, so a test run neither needs nor
                # touches ~/.mitmproxy.
                "--set", f"confdir={self._dir / 'confdir'}",
                "--set", f"http2_fingerprint={self.h2_profile}",
                "--set", "http3=false",
                "-s", self.tls_script or upstream_addon_path(),
                "--set", f"fp_profile={self.tls_profile}",
                "-s", str(Path(upstream_addon_path()).with_name("mitm_testhooks.py")),
                "--set", f"fp_report={self.report_path}"]
        if self.connect_to:
            argv += ["--set", f"fp_connect_to={self.connect_to}"]
        if self.insecure:
            argv += ["--set", "ssl_insecure=true"]
        if self.is_mitmweb:
            # The web UI has a fixed default port of its own, which an earlier
            # mitmweb or something on the Windows side of WSL may hold - and
            # then mitmweb never starts, which reads like a fingerprint failure.
            # Nobody looks at the UI during a test, so no browser either.
            argv += ["--set", f"web_port={self.web_port}",
                     "--set", "web_open_browser=false"]
        return argv + list(self.extra)

    @property
    def is_mitmweb(self) -> bool:
        return Path(self.mitmdump).name.startswith("mitmweb")

    def __enter__(self) -> Mitmdump:
        self.port = free_port()
        if self.is_mitmweb:
            self.web_port = free_port()
        env = dict(os.environ, PYTHONUNBUFFERED="1")
        # mitmproxy ignores these itself, but the addon or a script might not.
        for name in ("http_proxy", "https_proxy", "all_proxy",
                     "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"):
            env.pop(name, None)
        log = self.log_path.open("wb")
        try:
            self.proc = subprocess.Popen(self.argv(), stdout=log,
                                         stderr=subprocess.STDOUT, env=env)
        finally:
            log.close()
        deadline = time.monotonic() + self.startup_timeout
        while time.monotonic() < deadline:
            if self.proc.poll() is not None:
                raise MitmdumpError(
                    f"mitmdump exited with {self.proc.returncode} before "
                    f"listening:\n{self.log()}")
            try:
                with socket.create_connection(("127.0.0.1", self.port), timeout=0.5):
                    return self
            except OSError:
                time.sleep(0.2)
        self.stop()
        raise MitmdumpError(f"mitmdump did not listen on :{self.port} within "
                            f"{self.startup_timeout:.0f}s:\n{self.log()}")

    def __exit__(self, *exc) -> None:
        self.stop()

    def stop(self) -> None:
        if self.proc is not None and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()

    def log(self, tail: int = 40) -> str:
        try:
            lines = self.log_path.read_text(errors="replace").splitlines()
        except OSError:
            return "(no output)"
        return "\n".join(f"    | {line}" for line in lines[-tail:]) or "(no output)"

    def report(self) -> list[dict]:
        """One record per response, as the upstream addon wrote them."""
        try:
            text = self.report_path.read_text(encoding="utf-8")
        except OSError:
            return []
        return [json.loads(line) for line in text.splitlines() if line.strip()]

    def cleanup(self) -> None:
        shutil.rmtree(self._dir, ignore_errors=True)
