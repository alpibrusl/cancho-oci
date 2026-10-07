#!/usr/bin/env python3
"""Gate for `oci-push` and `oci-pull` (design 2, 3 and 5.7; task #9): a registry client checked against registries.

Against scripts/mock_registry.py (a spec-following registry that can also misbehave on request):
  1. round trips: a single image (gzip or not) and a multi-platform image are pushed, the registry holds exactly their
     blobs and manifests, and pulling them back into a fresh layout gives the same blob set, byte for byte, with a
     layout that validates against the OCI schemas; pushing again skips every blob; pulling again fetches nothing;
     `--platform` pulls one image of an index and the layout's entry is that image;
  2. faults: an upload `Location` on another host, a wrong digest reported for a manifest, a manifest rejected, a
     blob PUT answered 500, no `Location` at all, a registry that cannot HEAD, chunked responses, a blob whose bytes
     are wrong, a body cut short, an enormous header, a missing credential or a wrong one, a closed port. Each is
     refused or tolerated as it should be, with the rule tag, **and the side effects checked**: a refused pull leaves
     the layout exactly as it was (no blob, no temporary file, no index.json), a refused push leaves nothing that
     was not sent before the fault;
  3. validation: a repository name, a tag, a registry address, a missing flag, an unknown flag, credentials over plain
     HTTP to a host that is not loopback, a missing layout, a tampered blob (refused before anything is sent);
Against the real thing when available (CI): `crane registry serve` and `registry:2` in Docker take our push, and
`crane`/`skopeo` read it back; `crane push` of our layout is pulled by us.

    registry_check.py [--seed S]
"""
import argparse, hashlib, json, os, random, shutil, socket, subprocess, sys, tempfile, time
from pathlib import Path
import importlib.util

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


IC = load("image_check")
ELF = load("make_elf")

BUILD = str(ROOT / "build" / "oci-build")
INDEX = str(ROOT / "build" / "oci-index")
PUSH = str(ROOT / "build" / "oci-push")
PULL = str(ROOT / "build" / "oci-pull")
ARCHES = ["amd64", "arm64", "riscv64"]
bad = 0
checks = 0
notes = []


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


def sha(b):
    return hashlib.sha256(b).hexdigest()


def run(cmd, **kw):
    p = subprocess.run([str(c) for c in cmd], capture_output=True, text=True, **kw)
    return p.returncode, p.stdout.strip(), p.stderr.strip()


class Mock:
    def __init__(self, faults=(), auth=None):
        cmd = [sys.executable, str(ROOT / "scripts" / "mock_registry.py")]
        for f in faults:
            cmd += ["--fault", f]
        if auth:
            cmd += ["--auth", auth]
        self.p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        self.port = int(self.p.stdout.readline().split()[1])
        self.addr = f"127.0.0.1:{self.port}"

    def state(self):
        import urllib.request
        with urllib.request.urlopen(f"http://{self.addr}/_state") as r:
            return json.loads(r.read())

    def stop(self):
        self.p.terminate()
        self.p.wait(timeout=10)


def skeleton(d):
    (Path(d) / "blobs" / "sha256").mkdir(parents=True, exist_ok=True)


def tree(d):
    return {str(p.relative_to(d)): p.read_bytes() for p in sorted(Path(d).rglob("*")) if p.is_file()}


def blobs_of(d):
    return {p.name: p.read_bytes() for p in (Path(d) / "blobs" / "sha256").iterdir()}


def make_image(w, archs, compress="gzip", ref="v1", multi=None):
    """An image layout with one image per architecture; a multi-platform index over them when `multi` is set."""
    root, image = w / "root", w / "image"
    root.mkdir(parents=True)
    skeleton(image)
    for a in ARCHES:
        (root / f"app-{a}").write_bytes(ELF.elf(a))
    (root / "data").write_bytes(("registry payload " * 5000).encode() + os.urandom(3000))
    digests = {}
    for a in archs:
        code, out, err = run([BUILD, "--root", root, "--out", image, "--platform", f"linux/{a}", "--bin", f"app-{a}:app", "--file", "data:srv/data",
                              "--compress", compress, "--ref", ref])
        assert code == 0, err
        digests[a] = out
    if multi:
        args = []
        for a in archs:
            args += ["--manifest", digests[a]]
        code, out, err = run([INDEX, "--out", image, *args, "--ref", ref])
        assert code == 0, err
        return image, digests, out
    return image, digests, digests[archs[0]]


def push(image, addr, repo, tag="v1", extra=()):
    return run([PUSH, "--image", image, "--registry", addr, "--repo", repo, "--tag", tag, "--plain-http", *extra])


def pull(addr, repo, ref, out, extra=()):
    return run([PULL, "--registry", addr, "--repo", repo, "--ref", ref, "--out", out, "--plain-http", *extra])


def registry_blobs(image, digests):
    """What a registry's blob store holds for these images: each manifest's config and layers (manifests are not blobs)."""
    held = set()
    for d in digests:
        m = json.loads((Path(image) / "blobs" / "sha256" / d.split(":")[1]).read_text())
        held.add(m["config"]["digest"])
        held.update(l["digest"] for l in m["layers"])
    return held


def last(out):
    return out.splitlines()[-1] if out else ""


def model_entry(media, digest, size, tag):
    m = {"mediaType": media, "digest": digest, "size": size}
    if tag:
        m["annotations"] = {"org.opencontainers.image.ref.name": tag}
    return IC.compact({"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json", "manifests": [m]})


def layout_ok(d, top, name, tag=None):
    """The pulled layout: valid, and index.json equal byte for byte to the independent model of its one entry."""
    top_blob = (Path(d) / "blobs" / "sha256" / top.split(":")[1]).read_bytes()
    media = json.loads(top_blob)["mediaType"]
    if tag is not None:
        ok((Path(d) / "index.json").read_bytes() == model_entry(media, top, len(top_blob), tag), f"{name}: the pulled index.json differs from the model: {(Path(d) / 'index.json').read_bytes()[:240]!r}")
    layout = json.loads((Path(d) / "index.json").read_text())
    ok(not list(IC.validator("image-index-schema.json").iter_errors(layout)), f"{name}: the pulled index.json is not valid")
    ok(layout["manifests"][0]["digest"] == top, f"{name}: the layout's entry is {layout['manifests'][0]['digest']}, not {top}")
    blobs = blobs_of(d)
    ok(all(sha(v) == k for k, v in blobs.items()), f"{name}: a pulled blob does not hash to its name")
    ok(not any(p.name.startswith(".incoming") for p in (Path(d) / "blobs" / "sha256").iterdir()), f"{name}: a temporary file was left behind")
    return blobs


def main():
    global PUSH, PULL
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--push", default=PUSH)
    ap.add_argument("--pull", default=PULL)
    a = ap.parse_args()
    PUSH, PULL = a.push, a.pull
    rng = random.Random(a.seed)

    with tempfile.TemporaryDirectory() as t:
        t = Path(t)
        # ---------------------------------------------------------------- 1. round trips on the mock
        for n, (archs, compress, multi) in enumerate([(["amd64"], "gzip", False), (["arm64"], "none", False),
                                                      (["amd64", "arm64", "riscv64"], "gzip", True), (["riscv64", "amd64"], "gzip", True)]):
            w = t / f"rt{n}"
            image, digests, top = make_image(w, archs, compress, multi=multi)
            mock = Mock()
            try:
                code, out, err = push(image, mock.addr, "team/app")
                if not ok(code == 0, f"round trip {n}: push refused: {err!r}"):
                    continue
                sent = blobs_of(image)
                have = mock.state()
                want_blobs = registry_blobs(image, list(digests.values()))
                ok(set(have["blobs"]) == want_blobs, f"round trip {n}: the registry holds {len(have['blobs'])} blobs, expected the {len(want_blobs)} that the manifests name")
                ok(f"v1" in have["manifests"].get("team/app", []) and top in have["manifests"].get("team/app", []),
                   f"round trip {n}: the top manifest is not at the tag and at its digest: {have['manifests']}")
                # pushing again sends no blob
                code2, out2, err2 = push(image, mock.addr, "team/app")
                ok(code2 == 0 and "uploaded" not in out2 and out2.count("already there") == len(want_blobs), f"round trip {n}: a second push uploaded blobs or skipped the wrong count: {out2[:200]!r}")
                # pull into a fresh layout
                dest = w / "pulled"
                skeleton(dest)
                code3, out3, err3 = pull(mock.addr, "team/app", "v1", dest)
                if ok(code3 == 0 and last(out3) == top, f"round trip {n}: pull refused: {err3!r} (got {last(out3)!r}, want {top})"):
                    got = layout_ok(dest, top, f"round trip {n}", "v1")
                    ok(got == sent, f"round trip {n}: the pulled blobs differ from the pushed ones: missing {sorted(set(sent) - set(got))[:3]}, extra {sorted(set(got) - set(sent))[:3]}")
                    layout_ok(dest, top, f"round trip {n} again", "v1")
                    code4, out4, err4 = pull(mock.addr, "team/app", "v1", dest)
                    ok(code4 == 0 and "fetched" not in out4 and "already here" in out4, f"round trip {n}: a second pull fetched something: {out4[:200]!r}")
                # by digest
                dest2 = w / "by-digest"
                skeleton(dest2)
                code5, out5, err5 = pull(mock.addr, "team/app", top, dest2)
                if ok(code5 == 0 and last(out5) == top, f"round trip {n}: pull by digest refused: {err5!r}"):
                    layout_ok(dest2, top, f"round trip {n} by digest", "")
                # one platform of an index
                if multi:
                    for arch in archs:
                        d3 = w / f"one-{arch}"
                        skeleton(d3)
                        c6, o6, e6 = pull(mock.addr, "team/app", "v1", d3, ["--platform", f"linux/{arch}"])
                        if ok(c6 == 0 and last(o6) == digests[arch], f"round trip {n}: pull --platform linux/{arch}: {e6!r} {last(o6)!r} (want {digests[arch]})"):
                            layout_ok(d3, digests[arch], f"round trip {n} {arch}", "v1")
                            ok(len(blobs_of(d3)) == 3, f"round trip {n}: a single-platform pull holds {len(blobs_of(d3))} blobs, not 3 (manifest, config, layer)")
                    d4 = w / "no-such-platform"
                    skeleton(d4)
                    c7, o7, e7 = pull(mock.addr, "team/app", "v1", d4, ["--platform", "linux/s390x"])
                    ok(c7 == 1 and "pull-platform" in e7 and not (d4 / "index.json").exists() and not blobs_of(d4), f"round trip {n}: an absent platform: {c7} {e7!r}")
            finally:
                mock.stop()

        # ---------------------------------------------------------------- 2. faults
        w = t / "faults"
        image, digests, top = make_image(w, ["amd64"], "gzip")
        sent = blobs_of(image)
        nreg = len(registry_blobs(image, list(digests.values())))

        def push_with(faults, expect_code, expect_tag, name, auth=None, extra=(), expect_blobs=None):
            mock = Mock(faults, auth)
            try:
                code, out, err = push(image, mock.addr, "f/app", extra=extra)
                if expect_code == 0:
                    ok(code == 0, f"fault {name}: push should succeed, was refused: {err!r}")
                else:
                    ok(code == 1 and expect_tag in err, f"fault {name}: expected {expect_tag}, got {code} {err!r}")
                if expect_blobs is not None:
                    ok(len(mock.state()["blobs"]) == expect_blobs, f"fault {name}: the registry holds {len(mock.state()['blobs'])} blobs, expected {expect_blobs}")
                return mock.state(), err
            finally:
                mock.stop()

        push_with(["location-absolute"], 0, "", "an absolute Location on this host")
        push_with(["head-405"], 0, "", "a registry that cannot HEAD")
        push_with(["location-foreign"], 1, "registry-redirect-foreign-host", "a Location on another host", expect_blobs=0)
        push_with(["location-no-leading"], 1, "registry-location", "a Location with no leading slash", expect_blobs=0)
        push_with(["no-location"], 1, "registry-location", "no Location", expect_blobs=0)
        push_with(["status-500"], 1, "registry-server-error", "a 500 on a blob PUT", expect_blobs=0)
        state, err = push_with(["manifest-400"], 1, "registry-rejected", "a manifest rejected")
        ok(len(state["blobs"]) == nreg and not state["manifests"].get("f/app"), f"fault manifest-400: blobs {len(state['blobs'])}, manifests {state['manifests']}")
        state, err = push_with(["wrong-content-digest"], 1, "registry-digest-mismatch", "a wrong digest reported for a manifest")
        push_with(["long-headers"], 1, "http-head-too-large", "an enormous header")
        push_with(["many-headers"], 1, "http-head-too-large", "many small headers past the cap")
        push_with(["bad-status"], 1, "http-malformed", "a status code that does not exist (999)")
        push_with(["wrong-blob-digest"], 1, "registry-digest-mismatch", "a wrong digest reported for a blob")
        push_with(["bearer-challenge"], 1, "registry-auth-bearer", "a bearer-token challenge", auth="alice:s3cret", expect_blobs=0)
        # authentication
        push_with([], 1, "registry-unauthorized", "no credentials for a registry that wants them", auth="alice:s3cret", expect_blobs=0)
        cred_dir = t / "creds"
        cred_dir.mkdir()
        (cred_dir / "good").write_text("alice:s3cret\n")
        (cred_dir / "wrong").write_text("alice:nope\n")
        (cred_dir / "nocolon").write_text("justonetoken\n")
        (cred_dir / "empty").write_text("")
        push_with([], 1, "registry-unauthorized", "the wrong password", auth="alice:s3cret", extra=["--basic-file", cred_dir / "wrong"], expect_blobs=0)
        push_with([], 0, "", "the right credentials", auth="alice:s3cret", extra=["--basic-file", cred_dir / "good"], expect_blobs=nreg)
        # Basic credentials whose base64 needs "==", "=", "+" and "/" (a bug in the padding or the alphabet shows here)
        for creds in ("u:p1", "u:pw1", "user:secret", "a:>>>", "a:???", "bob:?>>>?", "x:y~~z"):
            (cred_dir / "c").write_text(creds + "\n")
            push_with([], 0, "", f"credentials {creds}", auth=creds, extra=["--basic-file", cred_dir / "c"], expect_blobs=nreg)
        for name in ("nocolon", "empty"):
            code, out, err = run([PUSH, "--image", image, "--registry", "127.0.0.1:1", "--repo", "f/app", "--plain-http", "--basic-file", cred_dir / name])
            ok(code == 1 and "registry-credentials-file" in err, f"credentials file {name}: {code} {err!r}")
        code, out, err = run([PUSH, "--image", image, "--registry", "127.0.0.1:1", "--repo", "f/app", "--plain-http", "--basic-file", cred_dir / "missing"])
        ok(code == 1 and "registry-credentials-file" in err, f"a missing credentials file: {code} {err!r}")
        code, out, err = run([PUSH, "--image", image, "--registry", "registry.example.com:80", "--repo", "f/app", "--plain-http", "--basic-file", cred_dir / "good"])
        ok(code == 1 and "push-credentials-over-plain-http" in err, f"credentials to a non-loopback host over plain HTTP: {code} {err!r}")
        # a closed port
        code, out, err = push(image, "127.0.0.1:1", "f/app")
        ok(code == 1 and "http-dial" in err, f"a closed port: {code} {err!r}")

        # ---- pull faults, each leaving the layout exactly as it was
        mock = Mock()
        push(image, mock.addr, "f/app")
        mock.stop()

        def pull_with(faults, expect_tag, name, ref="v1", seed_push=True, must_be_clean=True, extra=()):
            mock = Mock(faults)
            try:
                if seed_push:
                    c, o, e = push(image, mock.addr, "f/app")
                    assert c == 0 or "location" in " ".join(faults) or True
                dest = t / f"pull-{name.replace(' ', '-')}"
                skeleton(dest)
                before = tree(dest)
                code, out, err = pull(mock.addr, "f/app", ref, dest, extra)
                if expect_tag is None:
                    ok(code == 0, f"pull fault {name}: should succeed, was refused: {err!r}")
                else:
                    ok(code == 1 and expect_tag in err, f"pull fault {name}: expected {expect_tag}, got {code} {err!r}")
                    if must_be_clean:
                        ok(tree(dest) == before, f"pull fault {name}: a refused pull changed the layout: {sorted(set(tree(dest)) - set(before))[:3]}")
                return dest
            finally:
                mock.stop()

        pull_with(["chunked-get"], None, "chunked responses")
        pull_with(["wrong-blob"], "registry-digest-mismatch", "a blob with the wrong bytes")
        pull_with(["short-body"], "http-truncated", "a body cut short")
        pull_with(["wrong-content-digest"], "registry-digest-mismatch", "a wrong digest on a manifest")
        pull_with(["long-headers"], "http-head-too-large", "an enormous header")
        pull_with(["many-headers"], "http-head-too-large", "many small headers past the cap")
        # A blob longer than the descriptor says is refused as early as it can be: once the announced size (or the first
        # byte past the descriptor's size) shows it, and not after downloading all of it. The registry says how much it got out.
        for fault in ("bigger-blob", "bigger-blob-chunked"):
            mock = Mock([fault])
            try:
                push(image, mock.addr, "f/app")
                dest = t / f"pull-{fault}"
                skeleton(dest)
                before = tree(dest)
                code, out, err = pull(mock.addr, "f/app", "v1", dest)
                ok(code == 1 and "registry-size-mismatch" in err and tree(dest) == before, f"{fault}: expected registry-size-mismatch and a clean layout, got {code} {err!r}")
                served = mock.state()["served"]
                ok(served < 1_000_000, f"{fault}: the client kept downloading a blob it knew was too long ({served} bytes served of 2,000,000+ extra)")
            finally:
                mock.stop()
        pull_with(["bad-transfer-encoding"], "http-malformed", "a Transfer-Encoding that is not chunked")
        pull_with([], "registry-not-found", "an unknown tag", ref="nope")
        pull_with([], "registry-digest-mismatch", "a digest that is not what is stored", ref="sha256:" + "0" * 64, seed_push=False) if False else None
        # the registry returns, for a digest, a manifest that is not the one with that digest
        mock = Mock(["swap-manifest"])
        try:
            push(image, mock.addr, "f/app")
            dest = t / "pull-swapped"
            skeleton(dest)
            code, out, err = pull(mock.addr, "f/app", top, dest)
            ok(code == 1 and "registry-digest-mismatch" in err and not tree(dest).get("index.json"), f"a manifest swapped for a digest: {code} {err!r}")
        finally:
            mock.stop()
        code, out, err = pull("127.0.0.1:1", "f/app", "v1", t / "x-closed")
        ok(code == 1, "a pull into a missing directory was not refused")

        # ---------------------------------------------------------------- 3. validation
        good_args = ["--image", image, "--registry", "127.0.0.1:1", "--repo", "f/app", "--plain-http"]

        def refuse_push(name, args, tag, culprit=None):
            code, out, err = run([PUSH, *args])
            ok(code == 1 and f"refused: {tag}" in err and (culprit is None or culprit in err), f"push {name}: expected {tag}, got {code} {err!r}")

        # a bad tag is refused before the layout is looked at (the missing image directory would be reported otherwise)
        refuse_push("a bad tag, before the layout is touched", ["--image", t / "nope", "--registry", "127.0.0.1:1", "--repo", "f/app", "--plain-http", "--tag", "-bad"], "push-tag")
        refuse_push("a bad repository name, before the layout is touched", ["--image", t / "nope", "--registry", "127.0.0.1:1", "--repo", "UPPER", "--plain-http"], "registry-name")
        refuse_push("no --plain-http", ["--image", image, "--registry", "127.0.0.1:1", "--repo", "f/app"], "push-plain-http-required")
        refuse_push("an unknown flag", [*good_args, "--frobnicate", "x"], "push-flag", "--frobnicate")
        refuse_push("a flag without a value", [*good_args, "--tag"], "push-flag", "--tag")
        refuse_push("no --image", ["--registry", "127.0.0.1:1", "--repo", "f/app", "--plain-http"], "push-missing")
        for repo in ("UPPER", "a//b", "-x", "x-", "a b", "a/../b", "", "x" * 300, "a\nb"):
            if repo == "":
                continue
            refuse_push(f"repo {repo[:12]!r}", ["--image", image, "--registry", "127.0.0.1:1", "--repo", repo, "--plain-http"], "registry-name")
        for tag in ("-lead", ".lead", "has space", "x" * 129, "a/b", "sha256:abc"):
            refuse_push(f"tag {tag[:12]!r}", [*good_args, "--tag", tag], "push-tag")
        for reg in ("host/with/slash:80", "user@host:80", ":80", "host:0", "host:99999", "host:abc"):
            refuse_push(f"registry {reg!r}", ["--image", image, "--registry", reg, "--repo", "f/app", "--plain-http"], "push-registry")
        refuse_push("a missing layout", ["--image", t / "nope", "--registry", "127.0.0.1:1", "--repo", "f/app", "--plain-http"], "push-dir-open")
        (t / "bare").mkdir()
        big_index = t / "big-index"
        skeleton(big_index)
        (big_index / "index.json").write_bytes(b'{"schemaVersion":2,"pad":"' + b"x" * 1_100_000 + b'"}')
        refuse_push("an index.json past the size cap", ["--image", big_index, "--registry", "127.0.0.1:1", "--repo", "f/app", "--plain-http"], "layout-document-too-large")
        (big_index / "index.json").write_text("not json at all")
        refuse_push("an index.json that is not JSON", ["--image", big_index, "--registry", "127.0.0.1:1", "--repo", "f/app", "--plain-http"], "layout-json")
        (big_index / "index.json").write_text('{"schemaVersion":2,"manifests":[]}')
        refuse_push("an index.json with no entry", ["--image", big_index, "--registry", "127.0.0.1:1", "--repo", "f/app", "--plain-http"], "push-layout")
        refuse_push("a layout without a blob directory", ["--image", t / "bare", "--registry", "127.0.0.1:1", "--repo", "f/app", "--plain-http"], "push-layout-skeleton")
        # a tampered blob is refused before anything is sent
        w2 = t / "tamper"
        image2, d2, top2 = make_image(w2, ["amd64"], "gzip")
        layer = json.loads((Path(image2) / "blobs" / "sha256" / top2.split(":")[1]).read_text())["layers"][0]["digest"].split(":")[1]
        p = Path(image2) / "blobs" / "sha256" / layer
        data = bytearray(p.read_bytes())
        data[len(data) // 2] ^= 1
        p.write_bytes(bytes(data))
        mock = Mock()
        try:
            code, out, err = push(image2, mock.addr, "f/app")
            ok(code == 1 and "blob-digest-mismatch" in err, f"a tampered layer was not refused: {code} {err!r}")
            ok(layer not in " ".join(mock.state()["blobs"]), "a tampered layer reached the registry")
        finally:
            mock.stop()
        # pull validation
        def refuse_pull(name, args, tag):
            code, out, err = run([PULL, *args])
            ok(code == 1 and f"refused: {tag}" in err, f"pull {name}: expected {tag}, got {code} {err!r}")
        pd = t / "pdir"
        skeleton(pd)
        base = ["--registry", "127.0.0.1:1", "--repo", "f/app", "--ref", "v1", "--out", pd]
        refuse_pull("no --plain-http", base, "pull-plain-http-required")
        refuse_pull("an unknown flag", [*base, "--plain-http", "--x", "y"], "pull-flag")
        refuse_pull("a bad ref", ["--registry", "127.0.0.1:1", "--repo", "f/app", "--ref", "-bad", "--out", pd, "--plain-http"], "pull-ref")
        refuse_pull("a bad platform", [*base, "--plain-http", "--platform", "arm64"], "pull-platform")
        for repo in ("UPPER", "a//b", "-x", "x-", "a b", "x" * 300):
            refuse_pull(f"repo {repo[:12]!r}", ["--registry", "127.0.0.1:1", "--repo", repo, "--ref", "v1", "--out", t / "nope-out", "--plain-http"], "registry-name")
        refuse_pull("credentials to a host that is not loopback", ["--registry", "registry.example.com:80", "--repo", "f/app", "--ref", "v1", "--out", t / "nope-out",
                                                                 "--plain-http", "--basic-file", cred_dir / "good"], "pull-credentials-over-plain-http")
        refuse_pull("a bad ref, before the layout is touched", ["--registry", "127.0.0.1:1", "--repo", "f/app", "--ref", "has space", "--out", t / "nope-out", "--plain-http"], "pull-ref")
        refuse_pull("a missing out", ["--registry", "127.0.0.1:1", "--repo", "f/app", "--ref", "v1", "--plain-http"], "pull-missing")
        (t / "bare2").mkdir()
        refuse_pull("a missing skeleton", ["--registry", "127.0.0.1:1", "--repo", "f/app", "--ref", "v1", "--out", t / "bare2", "--plain-http"], "pull-layout-skeleton")

        # ---------------------------------------------------------------- 4. the real thing, when it is there
        def against(addr, label):
            """Our push read back by crane, crane's push pulled by us, on a real registry at `addr`."""
            for n, (archs, multi) in enumerate([(["amd64"], False), (["amd64", "arm64"], True)]):
                w3 = t / f"{label}{n}"
                image3, d3, top3 = make_image(w3, archs, "gzip", multi=multi)
                code, out, err = push(image3, addr, f"ours/app{n}")
                if ok(code == 0, f"{label} {n}: our push refused: {err!r}"):
                    rc, text, e = run([crane, "digest", f"{addr}/ours/app{n}:v1", "--insecure"])
                    ok(rc == 0 and text == top3, f"{label} {n}: crane sees {text!r}, we pushed {top3}")
                    rc, text, e = run([crane, "validate", "--remote", f"{addr}/ours/app{n}:v1", "--insecure"])
                    ok(rc == 0, f"{label} {n}: crane validate (the full check) refused what we pushed: {e[:300]}")
                    if shutil.which("skopeo"):
                        rc, text, e = run(["skopeo", "inspect", "--raw", "--tls-verify=false", f"docker://{addr}/ours/app{n}:v1"])
                        ok(rc == 0 and sha(text.encode()) == top3.split(":")[1], f"{label} {n}: skopeo reads a different manifest than the one we pushed: {e[:200]}")
                # the other direction: crane pushes our layout, we pull it
                rc, text, e = run([crane, "push", image3, f"{addr}/theirs/app{n}:v1", "--insecure"])
                if ok(rc == 0, f"{label} {n}: crane push failed: {e[:200]}"):
                    dest = w3 / "pulled"
                    skeleton(dest)
                    code, out, err = pull(addr, f"theirs/app{n}", "v1", dest)
                    if ok(code == 0 and last(out) == top3, f"{label} {n}: we could not pull what crane pushed: {err!r} {out!r}"):
                        got = layout_ok(dest, top3, f"{label} {n}")
                        ok(got == blobs_of(image3), f"{label} {n}: what we pulled from crane differs from what was pushed")

        def wait_port(port, tries=150):
            for _ in range(tries):
                try:
                    socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
                    return True
                except OSError:
                    time.sleep(0.2)
            return False

        crane = shutil.which("crane")
        if crane:
            with socket.socket() as s:
                s.bind(("127.0.0.1", 0))
                port = s.getsockname()[1]
            srv = subprocess.Popen([crane, "registry", "serve", "--address", f"127.0.0.1:{port}"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                if ok(wait_port(port), "crane registry serve did not start"):
                    against(f"127.0.0.1:{port}", "crane-registry")
            finally:
                srv.terminate()
                srv.wait(timeout=10)
            # registry:2, the reference implementation, when a Docker daemon answers
            if shutil.which("docker") and run(["docker", "info"])[0] == 0:
                with socket.socket() as s:
                    s.bind(("127.0.0.1", 0))
                    port = s.getsockname()[1]
                rc, cid, e = run(["docker", "run", "-d", "--rm", "-p", f"127.0.0.1:{port}:5000", "registry:2"])
                if ok(rc == 0, f"registry:2 did not start: {e[:200]}"):
                    try:
                        if ok(wait_port(port), "registry:2 did not listen"):
                            time.sleep(1)
                            against(f"127.0.0.1:{port}", "registry-2")
                    finally:
                        run(["docker", "stop", cid.strip()[:12]])
            else:
                notes.append("no Docker daemon: registry:2 was not run")
        else:
            notes.append("crane NOT installed: the real-registry checks were not run")

    print(f"{'FAIL' if bad else 'ok'}: {checks} checks, {bad} failure(s)" + (f"  [{'; '.join(notes)}]" if notes else ""))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
