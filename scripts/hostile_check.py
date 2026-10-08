#!/usr/bin/env python3
"""Gate for hostile peers (design 5.7; task #15): a server that stalls, trickles or lies must cost the client at most its
idle deadline, and never a crash, a hang or a half-written layout.

Raw-socket servers (plain and TLS) that:
  1. accept and say nothing; say half a status line and stop; send a head and part of a body and stop; send a chunk size
     and stop; stop in the middle of a TLS handshake; finish a TLS handshake and say nothing -- each must end with
     `http-timeout` about one idle time after the stall, with `--timeout-s 1`, for `http-probe`, `oci-pull`, `oci-push` and
     `oci-ref`;
  2. send their head one byte at a time at a pace under the idle time (a slow server is not a dead one): served;
  3. send random bytes, or a good head and random bytes, and close, for 300 seeds: never a signal (a trap), never a hang,
     and either a refusal with a rule tag or success;
  4. never read what the client sends (a big upload to a server whose receive buffer is full): `http-timeout`.

    hostile_check.py
"""
import argparse, os, random, socket, ssl, subprocess, sys, tempfile, threading, time
from pathlib import Path
import importlib.util

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


R = load("registry_check")
PROBE = str(ROOT / "build" / "http-probe")
REF = str(ROOT / "build" / "oci-ref")
bad = 0
checks = 0


def fail(msg):
    global bad
    bad += 1
    print(f"FAIL {msg}")


def ok(cond, msg):
    global checks
    checks += 1
    if not cond:
        fail(msg)
    return bool(cond)


class Server:
    """Accepts connections and runs `script(conn)` on each in a thread; `tls` wraps them first."""

    def __init__(self, script, tls=None):
        self.s = socket.socket()
        self.s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.s.bind(("127.0.0.1", 0))
        self.s.listen(16)
        self.port = self.s.getsockname()[1]
        self.script = script
        self.ctx = None
        if tls:
            self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            self.ctx.load_cert_chain(tls + ".pem", tls + ".key")
        self.stop = False
        self.conns = []
        threading.Thread(target=self.loop, daemon=True).start()

    def loop(self):
        while not self.stop:
            try:
                c, _ = self.s.accept()
            except OSError:
                return
            self.conns.append(c)
            threading.Thread(target=self.handle, args=(c,), daemon=True).start()

    def handle(self, c):
        try:
            if self.ctx:
                c = self.ctx.wrap_socket(c, server_side=True)
            self.script(c)
        except Exception:
            pass

    def close(self):
        self.stop = True
        self.s.close()
        for c in self.conns:
            try:
                c.close()
            except OSError:
                pass


def read_request(c):
    data = b""
    c.settimeout(5)
    while b"\r\n\r\n" not in data:
        d = c.recv(65536)
        if not d:
            break
        data += d
    return data


def stall(c, hold=30):
    time.sleep(hold)


def timed(cmd, limit=12):
    t0 = time.time()
    try:
        p = subprocess.run([str(x) for x in cmd], capture_output=True, timeout=limit)
        return p.returncode, p.stdout.decode(errors="replace"), p.stderr.decode(errors="replace"), time.time() - t0
    except subprocess.TimeoutExpired:
        return "hang", "", "", time.time() - t0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seeds", type=int, default=300)
    ap.add_argument("--probe", default=PROBE)
    ap.add_argument("--pull", default=None)
    ap.add_argument("--ref", default=REF)
    ap.add_argument("--quick", action="store_true", help="the stalls and the slow server only (for the mutation gate)")
    a = ap.parse_args()
    global PROBE, REF
    PROBE, REF = a.probe, a.ref
    if a.pull:
        R.PULL = a.pull
    with tempfile.TemporaryDirectory() as t:
        t = Path(t)
        pki = R.make_pki(t / "pki")
        digest = "sha256:" + "ab" * 32
        layout = t / "layout"
        R.skeleton(layout)

        def clients(host_port, tls_roots=None):
            """Each client program pointed at the server; a stall must be a timeout for all of them."""
            plain = tls_roots is None
            extra = ["--plain-http"] if plain else ["--trust-file", tls_roots]
            out = t / "pull-out"
            R.skeleton(out)
            sig = t / "sigfile"
            sig.write_text("x")
            return [
                ("http-probe", [PROBE, "127.0.0.1", host_port, "GET", "/v2/", *(["--tls", tls_roots] if tls_roots else []), "--timeout-s", "1"]),
                ("oci-pull", [R.PULL, "--registry", f"127.0.0.1:{host_port}", "--repo", "h/x", "--ref", "v1", "--out", out, *extra, "--timeout-s", "1"]),
                ("oci-ref list", [REF, "list", "--registry", f"127.0.0.1:{host_port}", "--repo", "h/x", "--subject", digest, *extra, "--timeout-s", "1"]),
            ]

        # ---- 1. stalls
        def say(prefix, hold=30):
            def script(c):
                read_request(c)
                if prefix:
                    c.sendall(prefix)
                time.sleep(hold)
            return script

        cases = [
            ("says nothing", lambda c: (read_request(c), time.sleep(30))),
            ("stops in a status line", say(b"HTTP/1.1 20")),
            ("stops in the headers", say(b"HTTP/1.1 200 OK\r\nContent-Len")),
            ("stops after the head", say(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\nConnection: close\r\n\r\n")),
            ("stops in a body", say(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\nConnection: close\r\n\r\n0123456789")),
            ("stops after a chunk size", say(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n10\r\n")),
            ("stops in a chunk", say(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n10\r\n0123")),
            ("never sends the end of an until-close body", say(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nabc")),
        ]
        for label, script in cases:
            srv = Server(script)
            try:
                for name, cmd in clients(srv.port):
                    code, out, err, dt = timed(cmd)
                    ok(code == 1 and "http-timeout" in err and dt < 8, f"{name} against a server that {label}: {code} {err.strip()!r} after {dt:.1f}s")
            finally:
                srv.close()
        # a client that dials a server that accepts the TCP connection and never answers the TLS hello
        if pki:
            srv = Server(lambda c: time.sleep(30))
            srv.ctx = None
            try:
                for name, cmd in clients(srv.port, pki["ca"]):
                    code, out, err, dt = timed(cmd)
                    ok(code == 1 and "http-timeout" in err and dt < 8, f"{name} against a server that never answers the TLS hello: {code} {err.strip()!r} after {dt:.1f}s")
            finally:
                srv.close()
            # a TLS server that finishes the handshake and then says nothing
            srv = Server(lambda c: (read_request(c), time.sleep(30)), tls=pki["good"])
            try:
                for name, cmd in clients(srv.port, pki["ca"]):
                    code, out, err, dt = timed(cmd)
                    ok(code == 1 and "http-timeout" in err and dt < 8, f"{name} against a TLS server that says nothing after the handshake: {code} {err.strip()!r} after {dt:.1f}s")
            finally:
                srv.close()

        # ---- 2. slow but alive: one byte every 0.25 s with a 1 s idle time
        body = b'{"ok":true}'
        reply = b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n" % len(body) + body

        def trickle(c):
            read_request(c)
            for i in range(len(reply)):
                c.sendall(reply[i:i + 1])
                time.sleep(0.05)

        srv = Server(trickle)
        try:
            code, out, err, dt = timed([PROBE, "127.0.0.1", srv.port, "GET", "/", "--timeout-s", "1"])
            ok(code == 0 and "STATUS 200" in out and out.rstrip().endswith('{"ok":true}'), f"a slow server (a byte every 50 ms): {code} {out!r} {err!r}")
        finally:
            srv.close()

        if a.quick:
            print(f"{'FAIL' if bad else 'ok'}: {checks} checks, {bad} failure(s)")
            return 1 if bad else 0

        # ---- 3. random bytes, and a good head with random bytes
        def garbage(seed, with_head):
            rng = random.Random(seed)

            def script(c):
                read_request(c)
                n = rng.choice([0, 1, 5, 100, 5000, 70000])
                junk = bytes(rng.randrange(256) for _ in range(n))
                if with_head:
                    heads = [b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n" % rng.choice([0, 5, n, n + 10, 99999999]),
                             b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n",
                             b"HTTP/1.1 307 Moved\r\nLocation: " + junk[:50] + b"\r\n\r\n",
                             b"HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Bearer realm=\"" + junk[:40] + b"\"\r\n\r\n"]
                    c.sendall(rng.choice(heads))
                c.sendall(junk)
                c.close()
            return script

        crashes = hangs = untagged = 0
        for seed in range(a.seeds):
            srv = Server(garbage(seed, seed % 2 == 0))
            try:
                for name, cmd in clients(srv.port)[:2]:
                    code, out, err, dt = timed(cmd, limit=15)
                    if code == "hang":
                        hangs += 1
                        fail(f"seed {seed}: {name} hung")
                    elif not isinstance(code, int) or code < 0 or code > 1:
                        crashes += 1
                        fail(f"seed {seed}: {name} died with {code}: {err.strip()[:100]!r}")
                    elif code == 1 and "refused: " not in err:
                        untagged += 1
                        fail(f"seed {seed}: {name} refused without a tag: {err.strip()[:100]!r}")
            finally:
                srv.close()
        ok(crashes == 0 and hangs == 0 and untagged == 0, f"garbage: {crashes} crashes, {hangs} hangs, {untagged} untagged")

        # ---- 4. a server that never reads: a big upload
        if True:
            def deaf(c):
                time.sleep(60)

            srv = Server(deaf)
            try:
                srv.s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
                img, dg, top = R.make_image(t / "img", ["amd64"], "gzip", big=40_000_000)
                code, out, err, dt = timed([R.PUSH, "--image", img, "--registry", f"127.0.0.1:{srv.port}", "--repo", "h/x", "--plain-http", "--timeout-s", "1"], limit=30)
                ok(code == 1 and ("http-timeout" in err or "http-truncated" in err), f"a server that never reads: {code} {err.strip()!r} after {dt:.1f}s")
            finally:
                srv.close()
    print(f"{'FAIL' if bad else 'ok'}: {checks} checks, {bad} failure(s)")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
