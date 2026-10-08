#!/usr/bin/env python3
"""A small OCI Distribution registry for testing `oci-push` and `oci-pull`, with deliberate faults.

It follows the Distribution spec v1.1 closely enough for a correct client (blob HEAD/GET, two-step and monolithic
uploads, manifest PUT/GET/HEAD by tag and by digest) and can misbehave on request, which is its point: real
registries do not return a wrong digest or redirect a blob upload to another host, and a client that will be pointed
at a registry it does not trust has to survive both. The real oracles (`crane registry serve`, `registry:2`) are run
in CI as well; this one is for what they will not do, and for developing without them.

    mock_registry.py [--auth user:password] [--bearer] [--tls-cert PEM --tls-key PEM] [--fault NAME]... [--port N]

`--bearer` makes it a registry that wants a token: the API answers 401 with a Bearer challenge whose realm is this host's
`/token`, which answers a token for the scope asked (with `--auth`, only to a request that carries those credentials as
Basic); the API takes only `Authorization: Bearer <that token>`, and a token that has no `push` is refused for writes.
`--tls-cert` and `--tls-key` serve https.

Prints `PORT <n>` on its first line. Faults (any number):
  location-absolute      the upload Location is an absolute URL on this host
  location-foreign       ... on another host (a client must refuse it)
  location-no-leading    the Location has no leading slash
  chunked-get            GET responses use Transfer-Encoding: chunked
  wrong-content-digest   Docker-Content-Digest on a manifest PUT/GET is a digest of something else
  wrong-blob             a GET of a blob returns different bytes (the client must notice)
  short-body             a GET response ends before Content-Length bytes
  long-headers           the response carries a 64 KiB header (the client must refuse, not crash)
  status-500             every PUT of a blob answers 500
  no-location            the upload POST answers 202 without a Location
  head-405               HEAD answers 405 (the client must fall back to uploading)
  manifest-400           a manifest PUT answers 400 with a JSON error body
  slow-start             the first byte of every response is delayed 1.5 s
  many-headers           600 small headers, more than the client will hold in total
  bad-status             every status line carries a status code that does not exist
  wrong-blob-digest      a blob PUT reports a Docker-Content-Digest of something else
  bearer-challenge       a 401 asks for a bearer token (the client does not do those)
  swap-manifest          a GET of a manifest by digest returns a different manifest
  bigger-blob            a GET of a blob returns 2 MB more than the digest names (Content-Length agrees)
  bigger-blob-chunked    the same, chunked, so no Content-Length warns the client
  bad-transfer-encoding  GET responses say `Transfer-Encoding: gzip`, which is not a framing this client knows
  blob-redirect          a blob GET answers 307 to an absolute URL on this host (the way a registry hands a blob to its CDN)
  blob-redirect-relative ... to a path on this host
  blob-redirect-other    ... to the same server under another name (localhost <-> 127.0.0.1), so another TLS connection
  blob-redirect-loop     ... to the same address, forever
  blob-redirect-downgrade ... to http:// although this server speaks https
  blob-redirect-userinfo ... to a URL with `user@` in front of the host
  blob-redirect-space    ... to a URL with a space in it
  blob-redirect-foreign  ... to another host name that does not exist
  until-close            GET responses have no Content-Length and end when the server closes (valid on plain HTTP; over TLS
                         the server closes without a close_notify, so a client cannot tell the body is whole)
With --bearer:
  token-foreign-realm    the challenge's realm is on another host (a client must not send credentials there)
  token-crlf             the token has a line break and a header in it
  token-bad-json         the token endpoint answers something that is not JSON
  token-pull-only        the token the endpoint gives has no push action
  token-denied           the token endpoint answers 401
  token-huge             the token is 40 KiB long
  token-access-token     the token is under `access_token`, not `token`
"""
import argparse, base64, hashlib, json, os, re, sys, threading, time, uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

STATE = {"blobs": {}, "manifests": {}, "uploads": {}, "log": [], "served": 0, "leaked": 0}
FAULTS = set()
AUTH = None
BEARER = False
SCHEME = "http"


def sha(b):
    return "sha256:" + hashlib.sha256(b).hexdigest()


class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *a):
        STATE["log"].append(fmt % a)

    # --- plumbing
    def reply(self, code, body=b"", headers=None, ctype=None):
        # the test-only /_state endpoint is exempt from every fault: the harness has to be able to look
        FAULTS_NOW = set() if self.path.startswith("/_state") else FAULTS
        if "slow-start" in FAULTS_NOW:
            time.sleep(1.5)
        self.send_response(999 if "bad-status" in FAULTS_NOW else code)
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        if ctype:
            self.send_header("Content-Type", ctype)
        if "long-headers" in FAULTS_NOW:
            self.send_header("X-Padding", "x" * 65536)
        if "many-headers" in FAULTS_NOW:
            for i in range(600):
                self.send_header(f"X-H{i}", "v" * 30)
        if "until-close" in FAULTS_NOW and self.command == "GET" and body:
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)
            STATE["served"] += len(body)
            self.close_connection = True
            return
        if "bad-transfer-encoding" in FAULTS_NOW and self.command == "GET" and body:
            self.send_header("Transfer-Encoding", "gzip")
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)
            self.close_connection = True
            return
        if ("chunked-get" in FAULTS_NOW or "bigger-blob-chunked" in FAULTS_NOW) and self.command == "GET" and body:
            self.send_header("Transfer-Encoding", "chunked")
            self.send_header("Connection", "close")
            self.end_headers()
            i = 0
            while i < len(body):
                n = min(7000, len(body) - i)
                self.wfile.write(b"%x\r\n" % n + body[i:i + n] + b"\r\n")
                i += n
            self.wfile.write(b"0\r\n\r\n")
            STATE["served"] += len(body)
        else:
            self.send_header("Content-Length", str(len(body) if "short-body" not in FAULTS_NOW else len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body[: len(body) // 2] if ("short-body" in FAULTS_NOW and body) else body)
                STATE["served"] += len(body)
        self.close_connection = True

    def token_endpoint(self, query):
        q = dict(p.split("=", 1) for p in query.split("&") if "=" in p)
        STATE["log"].append("token " + query)
        if "token-denied" in FAULTS:
            return self.reply(401, json.dumps({"errors": [{"code": "UNAUTHORIZED", "message": "no"}]}).encode(), None, "application/json")
        if AUTH and self.headers.get("Authorization") != "Basic " + base64.b64encode(AUTH.encode()).decode():
            return self.reply(401, json.dumps({"errors": [{"code": "UNAUTHORIZED", "message": "credentials needed"}]}).encode(), None, "application/json")
        scope = q.get("scope", "")
        if "token-pull-only" in FAULTS:
            scope = scope.replace(",push", "")
        if "token-bad-json" in FAULTS:
            return self.reply(200, b"<html>not json</html>", None, "text/html")
        token = "tok:" + scope
        if "token-crlf" in FAULTS:
            token = "tok:" + scope + "\r\nX-Evil: 1"
        if "token-huge" in FAULTS:
            token = "tok:" + scope + "A" * 40000
        key = "access_token" if "token-access-token" in FAULTS else "token"
        return self.reply(200, json.dumps({key: token, "expires_in": 300}).encode(), None, "application/json")

    def authed(self):
        if BEARER:
            m = re.match(r"^/v2/(.+?)/(?:blobs|manifests)/", self.path)
            repo = m.group(1) if m else None
            need = "push" if self.command in ("PUT", "POST", "PATCH", "DELETE") else "pull"
            got = self.headers.get("Authorization", "")
            if got.startswith("Bearer tok:repository:"):
                scope = got[len("Bearer tok:"):].split("\r")[0]
                parts = scope.split(":")
                if len(parts) == 3 and (repo is None or parts[1] == repo) and need in parts[2].split(","):
                    return True
            host = "auth.example" if "token-foreign-realm" in FAULTS else self.headers.get("Host", "")
            scope = f"repository:{repo}:pull" if repo else "registry:catalog:*"
            challenge = f'Bearer realm="{SCHEME}://{host}/token",service="mock",scope="{scope}"'
            self.reply(401, json.dumps({"errors": [{"code": "UNAUTHORIZED", "message": "authentication required"}]}).encode(),
                       {"WWW-Authenticate": challenge}, "application/json")
            return False
        if not AUTH:
            return True
        want = "Basic " + base64.b64encode(AUTH.encode()).decode()
        if self.headers.get("Authorization") == want:
            return True
        challenge = 'Bearer realm="https://auth.example/token",service="mock"' if "bearer-challenge" in FAULTS else 'Basic realm="mock"'
        self.reply(401, json.dumps({"errors": [{"code": "UNAUTHORIZED", "message": "authentication required"}]}).encode(),
                   {"WWW-Authenticate": challenge}, "application/json")
        return False

    def body(self):
        n = int(self.headers.get("Content-Length", "0"))
        return self.rfile.read(n) if n else b""

    # --- routing
    def route(self):
        path, _, query = self.path.partition("?")
        if path == "/_state":
            # for the tests, not part of the protocol: what does this registry hold?
            state = {"blobs": sorted(STATE["blobs"]), "manifests": {k: sorted(v) for k, v in STATE["manifests"].items()},
                     "served": STATE["served"], "log": STATE["log"], "leaked": STATE["leaked"]}
            return self.reply(200, json.dumps(state).encode(), None, "application/json")
        if path.startswith("/_cdn/"):
            return self.cdn(path[len("/_cdn/"):])
        if BEARER and path == "/token":
            return self.token_endpoint(query)
        if not self.authed():
            return
        if path == "/v2/" or path == "/v2":
            return self.reply(200, b"{}", {"Docker-Distribution-API-Version": "registry/2.0"}, "application/json")
        m = re.match(r"^/v2/(.+?)/(blobs|manifests)/(.+)$", path)
        if not m:
            return self.reply(404, json.dumps({"errors": [{"code": "NAME_UNKNOWN", "message": "no such route"}]}).encode(), None, "application/json")
        name, kind, rest = m.groups()
        if kind == "blobs" and rest.startswith("uploads/"):
            return self.uploads(name, rest[len("uploads/"):], query)
        if kind == "blobs":
            return self.blob(name, rest)
        return self.manifest(name, rest)

    def uploads(self, name, rest, query):
        if self.command == "POST" and rest == "":
            if "no-location" in FAULTS:
                return self.reply(202, b"", {"Docker-Upload-UUID": "x"})
            uid = uuid.uuid4().hex
            STATE["uploads"][uid] = bytearray()
            loc = f"/v2/{name}/blobs/uploads/{uid}"
            host = self.headers.get("Host", "")
            if "location-absolute" in FAULTS:
                loc = f"http://{host}{loc}"
            elif "location-foreign" in FAULTS:
                loc = f"http://evil.example{loc}"
            elif "location-no-leading" in FAULTS:
                loc = loc[1:]
            # monolithic upload by POST with ?digest=
            q = dict(p.split("=", 1) for p in query.split("&") if "=" in p)
            if "digest" in q:
                data = self.body()
                if sha(data) != q["digest"]:
                    return self.reply(400, json.dumps({"errors": [{"code": "DIGEST_INVALID", "message": "digest mismatch"}]}).encode(), None, "application/json")
                STATE["blobs"][q["digest"]] = data
                return self.reply(201, b"", {"Docker-Content-Digest": q["digest"], "Location": f"/v2/{name}/blobs/{q['digest']}"})
            return self.reply(202, b"", {"Location": loc, "Docker-Upload-UUID": uid, "Range": "0-0"})
        uid = rest.split("/")[0]
        if uid not in STATE["uploads"]:
            return self.reply(404, json.dumps({"errors": [{"code": "BLOB_UPLOAD_UNKNOWN", "message": "unknown upload"}]}).encode(), None, "application/json")
        if self.command == "PATCH":
            data = self.body()
            STATE["uploads"][uid] += data
            return self.reply(202, b"", {"Location": f"/v2/{name}/blobs/uploads/{uid}", "Range": f"0-{len(STATE['uploads'][uid]) - 1}"})
        if self.command == "PUT":
            if "status-500" in FAULTS:
                return self.reply(500, b"internal error", None, "text/plain")
            q = dict(p.split("=", 1) for p in query.split("&") if "=" in p)
            data = bytes(STATE["uploads"].pop(uid)) + self.body()
            if "digest" not in q or sha(data) != q["digest"]:
                return self.reply(400, json.dumps({"errors": [{"code": "DIGEST_INVALID", "message": "digest mismatch"}]}).encode(), None, "application/json")
            STATE["blobs"][q["digest"]] = data
            shown = q["digest"] if "wrong-blob-digest" not in FAULTS else sha(b"another blob")
            return self.reply(201, b"", {"Docker-Content-Digest": shown, "Location": f"/v2/{name}/blobs/{q['digest']}"})
        return self.reply(405, b"")

    def cdn(self, digest):
        """The 'CDN' behind a redirect: serves a blob to whoever holds the address, and notes any credentials sent to it."""
        if self.headers.get("Authorization"):
            STATE["leaked"] += 1
        data = STATE["blobs"].get(digest)
        if data is None:
            return self.reply(404, b"")
        return self.reply(200, data, {"Docker-Content-Digest": digest}, "application/octet-stream")

    def redirect(self, digest):
        host = self.headers.get("Host", "")
        name, _, port = host.partition(":")
        other = "localhost" if name == "127.0.0.1" else "127.0.0.1"
        target = f"/_cdn/{digest}"
        if "blob-redirect-loop" in FAULTS:
            target = self.path
            return self.reply(307, b"", {"Location": f"{SCHEME}://{host}{target}"})
        if "blob-redirect-relative" in FAULTS:
            loc = target
        elif "blob-redirect-other" in FAULTS:
            loc = f"{SCHEME}://{other}{':' + port if port else ''}{target}"
        elif "blob-redirect-downgrade" in FAULTS:
            loc = f"http://{host}{target}"
        elif "blob-redirect-userinfo" in FAULTS:
            loc = f"{SCHEME}://user@{host}{target}"
        elif "blob-redirect-space" in FAULTS:
            loc = f"{SCHEME}://{host}{target} x"
        elif "blob-redirect-foreign" in FAULTS:
            loc = f"{SCHEME}://cdn.invalid{target}"
        else:
            loc = f"{SCHEME}://{host}{target}"
        return self.reply(307, b"", {"Location": loc})

    def blob(self, name, digest):
        if self.command == "GET" and any(f.startswith("blob-redirect") for f in FAULTS) and digest in STATE["blobs"]:
            return self.redirect(digest)
        if self.command == "HEAD" and "head-405" in FAULTS:
            return self.reply(405, b"")
        data = STATE["blobs"].get(digest)
        if data is None:
            return self.reply(404, json.dumps({"errors": [{"code": "BLOB_UNKNOWN", "message": "blob unknown"}]}).encode(), None, "application/json")
        if self.command == "GET" and "wrong-blob" in FAULTS:
            data = data[:-1] + bytes([data[-1] ^ 1]) if data else b"x"
        if self.command == "GET" and ("bigger-blob" in FAULTS or "bigger-blob-chunked" in FAULTS):
            data = data + os.urandom(2_000_000)
        if self.command == "HEAD":
            self.send_response(200)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Docker-Content-Digest", digest)
            self.send_header("Connection", "close")
            self.end_headers()
            self.close_connection = True
            return
        return self.reply(200, data, {"Docker-Content-Digest": digest}, "application/octet-stream")

    def manifest(self, name, ref):
        store = STATE["manifests"].setdefault(name, {})
        if self.command == "PUT":
            if "manifest-400" in FAULTS:
                return self.reply(400, json.dumps({"errors": [{"code": "MANIFEST_INVALID", "message": "manifest invalid"}]}).encode(), None, "application/json")
            data = self.body()
            d = sha(data)
            if ref.startswith("sha256:") and ref != d:
                return self.reply(400, json.dumps({"errors": [{"code": "DIGEST_INVALID", "message": "digest mismatch"}]}).encode(), None, "application/json")
            media = self.headers.get("Content-Type", "")
            store[d] = (media, data)
            store[ref] = (media, data)
            shown = d if "wrong-content-digest" not in FAULTS else sha(b"something else")
            return self.reply(201, b"", {"Docker-Content-Digest": shown, "Location": f"/v2/{name}/manifests/{d}"})
        got = store.get(ref)
        if got is not None and ref.startswith("sha256:") and "swap-manifest" in FAULTS and self.command == "GET":
            media0, data0 = got
            got = (media0, data0.replace(b"schemaVersion", b"schemaversion", 1))
        if got is None:
            return self.reply(404, json.dumps({"errors": [{"code": "MANIFEST_UNKNOWN", "message": "manifest unknown"}]}).encode(), None, "application/json")
        media, data = got
        shown = sha(data) if "wrong-content-digest" not in FAULTS else sha(b"something else")
        if self.command == "HEAD":
            self.send_response(200)
            self.send_header("Content-Type", media)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Docker-Content-Digest", shown)
            self.send_header("Connection", "close")
            self.end_headers()
            self.close_connection = True
            return
        return self.reply(200, data, {"Docker-Content-Digest": shown}, media)

    do_GET = do_HEAD = do_POST = do_PUT = do_PATCH = route


def main():
    global AUTH, BEARER, SCHEME
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=0)
    ap.add_argument("--auth")
    ap.add_argument("--fault", action="append", default=[])
    ap.add_argument("--bearer", action="store_true")
    ap.add_argument("--tls-cert")
    ap.add_argument("--tls-key")
    a = ap.parse_args()
    AUTH = a.auth
    BEARER = a.bearer
    FAULTS.update(a.fault)
    srv = ThreadingHTTPServer(("127.0.0.1", a.port), H)
    if a.tls_cert:
        import ssl
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(a.tls_cert, a.tls_key)
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
        SCHEME = "https"
    print(f"PORT {srv.server_address[1]}", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
