#!/usr/bin/env python3
"""Mutation gate for `oci-push`, `oci-pull`, `oci.registry` and `oci.http` (design 2; task #9): break them on purpose
and require scripts/registry_check.py to notice. A survivor is a behaviour nothing tests.

    registry_mutants.py [--jobs N]     (N mutants at a time, default 4)

Each mutant is one textual edit of one source file, built into temporary oci-push and oci-pull. The edit must apply
exactly once. Exit 0 only if every mutant is killed.

Not covered, and said so: a 204 or 304 reply having no body (the mock never sends one, and a server that closes after
a body-less reply reads the same either way), and the truncated-length branch of the body reader (the short-body fault
reaches it through a different line).
"""
import subprocess, sys, tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LIBS = ["digest", "store", "image", "layout", "http", "secure", "registry"]
FILES = {"digest": "src/digest/digest.cho", "store": "src/store/store.cho", "image": "src/image/image.cho",
         "layout": "src/layout/layout.cho", "http": "src/http/http.cho", "secure": "src/secure/secure.cho", "registry": "src/registry/registry.cho",
         "pushcli": "src/pushcli/main.cho", "pullcli": "src/pullcli/main.cho", "targetmain": "tests/probe/target/main.cho"}

MUTANTS = [
    ("image", "the ref annotation dropped from a pulled layout index", '    if len(ref) > 0 {\n        w1 = json.put_key(heap, w1, "annotations");\n        w1 = json.begin_object(heap, w1);\n        w1 = json.put_key(heap, w1, "org.opencontainers.image.ref.name");\n        w1 = json.put_string(heap, w1, ref);\n        w1 = json.end_object(heap, w1);\n    }\n    w1 = json.end_object(heap, w1);\n    w1 = json.end_array(heap, w1);\n    w1 = json.end_object(heap, w1);\n    return (json.finish(w1), 0);\n}\n\n// Replace `<dir>/<name>` with', '    w1 = json.end_object(heap, w1);\n    w1 = json.end_array(heap, w1);\n    w1 = json.end_object(heap, w1);\n    return (json.finish(w1), 0);\n}\n\n// Replace `<dir>/<name>` with'),
    ("http", "a chunk one byte longer than it says", "s[7] = size;", "s[7] = size + 1;"),
    ("http", "Content-Length ignored", "                } else {\n                    mode = 0;\n                }\n            }\n            if len(te) > 0 {", "                } else {\n                    mode = 2;\n                }\n            }\n            if len(te) > 0 {"),
    ("http", "any Transfer-Encoding taken as chunked", 'if same_name(te, "chunked") {', "if true {"),
    ("http", "the head cap not enforced", "} else if used + n + 1 > len(h) {", "} else if false {"),
    ("http", "a status that does not exist accepted", "if sp + 4 > n || status < 100 || status > 599 {", "if sp + 4 > n {"),
    ("registry", "a HEAD reply read for a body", "var going = has_body;", "var going = true;"),
    ("registry", "a 405 on HEAD taken as an error", "} else if s == 404 || s == 405 {", "} else if s == 404 {"),
    ("registry", "an upload Location on another host followed", "            if !same {\n                code = refused_redirect();", "            if false {\n                code = refused_redirect();"),
    ("registry", "the digest of an uploaded blob not checked", "                            let shown = reply_digest(rr);\n                            if len(shown) > 0 && !digest.equal(shown, digest_text) {\n                                answer = refused_digest();", "                            let shown = reply_digest(rr);\n                            if false {\n                                answer = refused_digest();"),
    ("registry", "the digest of a pushed manifest not checked", "                    let shown = reply_digest(rr);\n                    if len(shown) > 0 && !digest.equal(shown, digest_text) {\n                        answer = refused_digest();", "                    let shown = reply_digest(rr);\n                    if false {\n                        answer = refused_digest();"),
    ("registry", "a bearer challenge read as a plain 401", '&& digest.equal(buffer.bytes(reply.challenge)[0..6], "Bearer") {', "&& false {"),
    ("registry", "a repeated separator in a name accepted", "if sep && prev_sep {", "if false {"),
    ("registry", "a name ending in a separator accepted", "return !prev_sep;", "return true;"),
    ("registry", "the digest a registry reports for a manifest not checked", "if len(reply_digest(rr)) > 0 && !digest.equal(reply_digest(rr), shown) {", "if false {"),
    ("registry", "the digest asked for not checked on a fetched manifest", '} else if len(reference) == 71 && digest.equal(reference[0..7], "sha256:") && !digest.equal(reference, shown) {', "} else if false {"),
    ("registry", "a blob longer than its descriptor accepted", "if size >= 0 && total > size {", "if false {"),
    ("registry", "base64 without padding after one byte", "        } else {\n            b = buffer.push(heap, b, byte_of('='));\n        }\n        if i + 2 < len(data) {", "        } else {\n            b = buffer.push(heap, b, byte_of('A'));\n        }\n        if i + 2 < len(data) {"),
    ("registry", "base64 without padding after two bytes", "        } else {\n            b = buffer.push(heap, b, byte_of('='));\n        }\n        i = i + 3;", "        } else {\n            b = buffer.push(heap, b, byte_of('A'));\n        }\n        i = i + 3;"),
    ("registry", "base64 alphabet: + wrong", "        return '+';", "        return '-';"),
    ("registry", "base64 alphabet: / wrong", "    return '/';\n}\n\n// RFC 4648", "    return '_';\n}\n\n// RFC 4648"),
    ("pushcli", "a bad repository name accepted", "    if !registry.name_ok(repo) {", "    if false {"),
    ("pushcli", "a bad tag accepted", "    if len(tag) > 0 && !registry.reference_ok(tag) {", "    if false {"),
    ("pushcli", "credentials sent over plain HTTP to any host", "    if plain && len(basic_file) > 0 && !registry.is_loopback(host) {", "    if plain && false {"),
    ("pullcli", "a bad repository name accepted", "    if !registry.name_ok(repo) {", "    if false {"),
    ("pullcli", "credentials sent over plain HTTP to any host", "    if plain && len(basic_file) > 0 && !registry.is_loopback(host) {", "    if plain && false {"),
    ("pullcli", "a blob already here fetched again", "    if have == 0 && actual == size {", "    if false {"),
    ("pullcli", "the architecture ignored when choosing a platform", "digest.equal(os, want[0..slash]) && digest.equal(arch, want[slash + 1..len(want)]);", "digest.equal(os, want[0..slash]);"),
    ("registry", "a token realm on another host followed", "    if !same {\n        return (out, refused_realm());", "    if false {\n        return (out, refused_realm());"),
    ("registry", "a token with a line break accepted", "if !token_char(int_of(token[k])) {", "if false {"),
    ("registry", "the push action left out of the token's scope", "        if push {\n            scope = buffer.append(heap, scope, \",push\");", "        if false {\n            scope = buffer.append(heap, scope, \",push\");"),
    ("registry", "a realm on https accepted for a plain registry", '    var scheme = "http://";', '    var scheme = "https://";'),
    ("registry", "access_token not read", '                                    token = layout.text_of(body, tape, 0, "access_token");', '                                    token = layout.text_of(body, tape, 0, "token");'),
    ("pushcli", "credentials refused over TLS to another host", "    if plain && len(basic_file) > 0 && !registry.is_loopback(host) {", "    if len(basic_file) > 0 && !registry.is_loopback(host) {"),
    ("pullcli", "credentials refused over TLS to another host", "    if plain && len(basic_file) > 0 && !registry.is_loopback(host) {", "    if len(basic_file) > 0 && !registry.is_loopback(host) {"),
    ("secure", "a roots file with no certificate trusted", "                if tls.trust(ew, contents(pw)[0..got]) < 1 {", "                if false {"),
    ("http", "ciphertext the engine did not take dropped", "            st[11] = st[11] + used;", "            st[11] = st[12];"),
    ("http", "a close without close_notify taken for the end", "                    tls.eof(eng, 0);\n                    let m = tls.recv(eng, 0, out);", "                    let m = 0;"),
    ("http", "the handshake not driven to the end", "        if ev == tls.event_established() {\n            return 0;\n        }", "        if rounds > 0 {\n            return 0;\n        }"),
    ("registry", "no port taken for https on any port", '            if port == 443 && digest.equal(scheme, "https") &&', '            if digest.equal(scheme, "https") &&'),
    ("registry", "no port taken for http on any port", '            if port == 80 && digest.equal(scheme, "http") &&', '            if digest.equal(scheme, "http") &&'),
    ("registry", "no port taken on https for a name that is not the host", '            if port == 443 && digest.equal(scheme, "https") && digest.equal(location[colon + 3..end], host) {', '            if port == 443 && digest.equal(scheme, "https") {'),
    ("registry", "credentials sent to a redirect target", '                    head = request_head(heap, "GET", rest[slash..len(rest)], name, next_port, "", "", 0 - 1);', '                    head = request_head(heap, "GET", rest[slash..len(rest)], name, next_port, auth, "", 0 - 1);'),
    ("registry", "the scheme of a redirect not enforced", '    var prefix = "http://";\n    if secure {\n        prefix = "https://";\n    }', '    var prefix = "http://";\n    if false {\n        prefix = "https://";\n    }'),
    ("registry", "a redirect to a non-loopback host followed over plain HTTP", "                if code == 0 && !secure && !is_loopback(name) {", "                if false {"),
    ("registry", "redirects followed without a small limit", "                    if hops > 3 {", "                    if hops > 30 {"),
    ("registry", "a redirect host name not checked", "                    if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '.') {", "                    if false {"),
    ("registry", "a redirect location with a control character accepted", "        if c < 33 || c > 126 {\n            code = refused_redirect();", "        if false {\n            code = refused_redirect();"),
    ("image", "a Docker manifest not recognised as a manifest", "    return digest.equal(media, media_manifest()) || digest.equal(media, media_docker_manifest());", "    return digest.equal(media, media_manifest());"),
    ("image", "a Docker list not recognised as an index", "    return digest.equal(media, media_index()) || digest.equal(media, media_docker_list());", "    return digest.equal(media, media_index());"),
    ("image", "a Docker manifest recorded as an OCI one", "    if digest.equal(media, media_docker_manifest()) {\n        return media_docker_manifest();", "    if digest.equal(media, media_docker_manifest()) {\n        return media_manifest();"),
]


def build(paths, out):
    deps = sorted(str(p) for p in (ROOT / "build" / "deps").glob("*.cho"))    # the TLS package, installed by `cancho install`
    return subprocess.run(["cancho", "build", *paths, *deps, "--std", "-o", str(out)], capture_output=True, text=True)


def try_mutant(i, sources, tmp):
    """Build one mutant and judge it. Returns (label, 'killed' | 'survived' | 'broken: why')."""
    which, label, old, new = MUTANTS[i]
    if sources[which].count(old) != 1:
        return label, f"broken: anchor found {sources[which].count(old)} times in {which}, expected once"
    m = tmp / f"m{i}"
    m.mkdir()
    written = {}
    for k, text in sources.items():
        f = m / f"{k}.cho"
        f.write_text(text.replace(old, new) if k == which else text)
        written[k] = str(f)
    push, pull = m / "oci-push", m / "oci-pull"
    b1 = build([written[k] for k in LIBS] + [written["pushcli"]], push)
    b2 = build([written[k] for k in LIBS] + [written["pullcli"]], pull)
    target = m / "target-probe"
    b3 = build([written[k] for k in LIBS] + [written["targetmain"]], target)
    if b1.returncode != 0 or b2.returncode != 0 or b3.returncode != 0:
        return label, f"broken: the mutant does not build ({(b1.stderr or b2.stderr or b3.stderr).strip()[:140]})"
    r = subprocess.run([sys.executable, str(ROOT / "scripts/registry_check.py"), "--push", str(push), "--pull", str(pull), "--target", str(target)], capture_output=True, text=True)
    return label, "killed" if r.returncode != 0 else "survived"


def main():
    jobs = int(sys.argv[sys.argv.index("--jobs") + 1]) if "--jobs" in sys.argv else 4
    sources = {k: (ROOT / p).read_text() for k, p in FILES.items()}
    survived, broken = [], []
    with tempfile.TemporaryDirectory() as d, ThreadPoolExecutor(max_workers=jobs) as pool:
        futures = [pool.submit(try_mutant, i, sources, Path(d)) for i in range(len(MUTANTS))]
        for f in futures:
            label, verdict = f.result()
            if verdict.startswith("broken"):
                broken.append(f"{label}: {verdict}")
            else:
                print(f"{'killed  ' if verdict == 'killed' else 'SURVIVED'} {label}", flush=True)
                if verdict == "survived":
                    survived.append(label)
    for line in broken:
        print(f"BROKEN   {line}")
    print(f"{len(MUTANTS) - len(survived) - len(broken)}/{len(MUTANTS)} mutants killed, {len(survived)} survived, {len(broken)} broken")
    return 1 if survived or broken else 0


if __name__ == "__main__":
    sys.exit(main())
