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
LIBS = ["digest", "store", "image", "layout", "http", "registry"]
FILES = {"digest": "src/digest/digest.cho", "store": "src/store/store.cho", "image": "src/image/image.cho",
         "layout": "src/layout/layout.cho", "http": "src/http/http.cho", "registry": "src/registry/registry.cho",
         "pushcli": "src/pushcli/main.cho", "pullcli": "src/pullcli/main.cho"}

MUTANTS = [
    ("image", "the ref annotation dropped from a pulled layout index", '    if len(ref) > 0 {\n        w1 = json.put_key(heap, w1, "annotations");\n        w1 = json.begin_object(heap, w1);\n        w1 = json.put_key(heap, w1, "org.opencontainers.image.ref.name");\n        w1 = json.put_string(heap, w1, ref);\n        w1 = json.end_object(heap, w1);\n    }\n    w1 = json.end_object(heap, w1);\n    w1 = json.end_array(heap, w1);\n    w1 = json.end_object(heap, w1);\n    return (json.finish(w1), 0);\n}\n\n// Replace `<dir>/<name>` with', '    w1 = json.end_object(heap, w1);\n    w1 = json.end_array(heap, w1);\n    w1 = json.end_object(heap, w1);\n    return (json.finish(w1), 0);\n}\n\n// Replace `<dir>/<name>` with'),
    ("http", "a chunk one byte longer than it says", "s[7] = size;", "s[7] = size + 1;"),
    ("http", "Content-Length ignored", "                } else {\n                    mode = 0;\n                }\n            }\n            if len(te) > 0 {", "                } else {\n                    mode = 2;\n                }\n            }\n            if len(te) > 0 {"),
    ("http", "any Transfer-Encoding taken as chunked", 'if same_name(te, "chunked") {', "if true {"),
    ("http", "the head cap not enforced", "} else if used + n + 1 > len(h) {", "} else if false {"),
    ("http", "a status that does not exist accepted", "if sp + 4 > n || status < 100 || status > 599 {", "if sp + 4 > n {"),
    ("registry", "a HEAD reply read for a body", "var going = has_body;", "var going = true;"),
    ("registry", "a 405 on HEAD taken as an error", "} else if s == 404 || s == 405 {", "} else if s == 404 {"),
    ("registry", "an upload Location on another host followed", "if !same {", "if false {"),
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
    ("pushcli", "plain HTTP not required", "    if !plain {", "    if false {"),
    ("pushcli", "a bad repository name accepted", "    if !registry.name_ok(repo) {", "    if false {"),
    ("pushcli", "a bad tag accepted", "    if len(tag) > 0 && !registry.reference_ok(tag) {", "    if false {"),
    ("pushcli", "credentials sent over plain HTTP to any host", "    if len(basic_file) > 0 && !registry.is_loopback(host) {", "    if false {"),
    ("pullcli", "plain HTTP not required", "    if !plain {", "    if false {"),
    ("pullcli", "a bad repository name accepted", "    if !registry.name_ok(repo) {", "    if false {"),
    ("pullcli", "credentials sent over plain HTTP to any host", "    if len(basic_file) > 0 && !registry.is_loopback(host) {", "    if false {"),
    ("pullcli", "a blob already here fetched again", "    if have == 0 && actual == size {", "    if false {"),
    ("pullcli", "the architecture ignored when choosing a platform", "digest.equal(os, want[0..slash]) && digest.equal(arch, want[slash + 1..len(want)]);", "digest.equal(os, want[0..slash]);"),
]


def build(paths, out):
    return subprocess.run(["cancho", "build", *paths, "--std", "-o", str(out)], capture_output=True, text=True)


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
    if b1.returncode != 0 or b2.returncode != 0:
        return label, f"broken: the mutant does not build ({(b1.stderr or b2.stderr).strip()[:140]})"
    r = subprocess.run([sys.executable, str(ROOT / "scripts/registry_check.py"), "--push", str(push), "--pull", str(pull)], capture_output=True, text=True)
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
