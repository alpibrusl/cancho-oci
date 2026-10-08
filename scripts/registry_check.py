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
TARGET = str(ROOT / "build" / "target-probe")
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
    def __init__(self, faults=(), auth=None, bearer=False, tls=None):
        cmd = [sys.executable, str(ROOT / "scripts" / "mock_registry.py")]
        for f in faults:
            cmd += ["--fault", f]
        if auth:
            cmd += ["--auth", auth]
        if bearer:
            cmd += ["--bearer"]
        self.scheme = "http"
        if tls:
            cmd += ["--tls-cert", tls + ".pem", "--tls-key", tls + ".key"]
            self.scheme = "https"
        self.p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        self.port = int(self.p.stdout.readline().split()[1])
        self.addr = f"127.0.0.1:{self.port}"

    def state(self):
        import urllib.request, ssl
        ctx = ssl._create_unverified_context() if self.scheme == "https" else None
        with urllib.request.urlopen(f"{self.scheme}://{self.addr}/_state", context=ctx) as r:
            return json.loads(r.read())

    def log(self):
        return self.state()["log"]

    def stop(self):
        self.p.terminate()
        self.p.wait(timeout=10)


def skeleton(d):
    (Path(d) / "blobs" / "sha256").mkdir(parents=True, exist_ok=True)


def tree(d):
    return {str(p.relative_to(d)): p.read_bytes() for p in sorted(Path(d).rglob("*")) if p.is_file()}


def blobs_of(d):
    return {p.name: p.read_bytes() for p in (Path(d) / "blobs" / "sha256").iterdir()}


def make_image(w, archs, compress="gzip", ref="v1", multi=None, big=0):
    """An image layout with one image per architecture; a multi-platform index over them when `multi` is set."""
    root, image = w / "root", w / "image"
    root.mkdir(parents=True)
    skeleton(image)
    for a in ARCHES:
        (root / f"app-{a}").write_bytes(ELF.elf(a))
    (root / "data").write_bytes(("registry payload " * 5000).encode() + os.urandom(3000))
    if big:
        (root / "big").write_bytes(os.urandom(big))
    digests = {}
    for a in archs:
        code, out, err = run([BUILD, "--root", root, "--out", image, "--platform", f"linux/{a}", "--bin", f"app-{a}:app", "--file", "data:srv/data",
                              *(["--file", "big:srv/big"] if big else []), "--compress", compress, "--ref", ref])
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


def push(image, addr, repo, tag="v1", extra=(), plain=True):
    return run([PUSH, "--image", image, "--registry", addr, "--repo", repo, "--tag", tag, *(["--plain-http"] if plain else []), *extra])


def pull(addr, repo, ref, out, extra=(), plain=True):
    return run([PULL, "--registry", addr, "--repo", repo, "--ref", ref, "--out", out, *(["--plain-http"] if plain else []), *extra])


def make_pki(d):
    """A test CA and leaf certificates it signs (valid for 127.0.0.1 and localhost; one expired; one for another name),
    and a second, unrelated CA. Returns {} when there is no openssl to make them."""
    if not shutil.which("openssl"):
        return {}
    d = Path(d)
    d.mkdir(parents=True, exist_ok=True)

    def sh(*a):
        subprocess.run([str(x) for x in a], check=True, capture_output=True, cwd=d)

    for ca in ("ca", "other"):
        sh("openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", f"{ca}.key", "-out", f"{ca}.pem",
           "-days", "30", "-subj", f"/CN=oci test {ca}", "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign")
    (d / "index.txt").write_text("")
    (d / "serial.txt").write_text("1000\n")
    (d / "ca.cnf").write_text("[ca]\ndefault_ca=CA_default\n[CA_default]\ndir=.\ndatabase=index.txt\nnew_certs_dir=.\nserial=serial.txt\ndefault_md=sha256\npolicy=pol\nunique_subject=no\n[pol]\ncommonName=supplied\n")

    def leaf(name, san, start=None, end=None):
        (d / f"{name}.ext").write_text(f"subjectAltName={san}\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage=serverAuth\n")
        sh("openssl", "req", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", f"{name}.key", "-out", f"{name}.csr", "-subj", f"/CN={name}")
        args = ["openssl", "ca", "-config", "ca.cnf", "-batch", "-notext", "-in", f"{name}.csr", "-out", f"{name}.pem", "-cert", "ca.pem", "-keyfile", "ca.key", "-extfile", f"{name}.ext"]
        args += ["-startdate", start or "20240101000000Z", "-enddate", end or "20990101000000Z"]
        sh(*args)

    leaf("good", "DNS:localhost,IP:127.0.0.1")
    leaf("expired", "DNS:localhost,IP:127.0.0.1", "20200101000000Z", "20200102000000Z")
    leaf("wrongname", "DNS:registry.invalid")
    return {"ca": str(d / "ca.pem"), "other": str(d / "other.pem"), "good": str(d / "good"), "expired": str(d / "expired"), "wrongname": str(d / "wrongname")}


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
    global PUSH, PULL, TARGET
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--target", default=TARGET)
    ap.add_argument("--push", default=PUSH)
    ap.add_argument("--pull", default=PULL)
    a = ap.parse_args()
    PUSH, PULL, TARGET = a.push, a.pull, a.target
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
        push_with(["bearer-challenge"], 1, "registry-token-realm", "a bearer-token challenge naming another host", auth="alice:s3cret", expect_blobs=0)
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

        # ---------------------------------------------------------------- 3a. documents of every size
        # A JSON tape is 3 ints a byte at worst and a region is one 64 KiB chunk: a manifest of a few KB used to trap the
        # program (found while testing tokens). Manifests with many layers now go through, and one with too many nodes is
        # refused as JSON, not a crash.
        def fat_layout(d, layers, tag="v1"):
            skeleton(d)
            blobs = Path(d) / "blobs" / "sha256"
            def put(data):
                (blobs / sha(data)).write_bytes(data)
                return "sha256:" + sha(data)
            cfg = IC.compact({"architecture": "amd64", "os": "linux", "config": {}, "rootfs": {"type": "layers", "diff_ids": []}})
            cfg_d = put(cfg)
            layer_ds = [put(f"layer {i}".encode()) for i in range(layers)]
            man = IC.compact({"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
                              "config": {"mediaType": "application/vnd.oci.image.config.v1+json", "digest": cfg_d, "size": len(cfg)},
                              "layers": [{"mediaType": "application/vnd.oci.image.layer.v1.tar", "digest": ld, "size": len(f"layer {i}")} for i, ld in enumerate(layer_ds)]})
            top_d = put(man)
            (Path(d) / "index.json").write_bytes(model_entry("application/vnd.oci.image.manifest.v1+json", top_d, len(man), tag))
            (Path(d) / "oci-layout").write_text('{"imageLayoutVersion":"1.0.0"}')
            return top_d, len(man)

        for layers in (3, 40, 200):
            d = t / f"fat{layers}"
            top_d, size = fat_layout(d, layers)
            mock = Mock()
            try:
                code, out, err = push(d, mock.addr, "fat/app")
                if ok(code == 0, f"a manifest of {layers} layers ({size} bytes): push refused: {code} {err!r}"):
                    dest = t / f"fat{layers}-pulled"
                    skeleton(dest)
                    code, out, err = pull(mock.addr, "fat/app", "v1", dest)
                    ok(code == 0 and last(out) == top_d and blobs_of(dest) == blobs_of(d), f"a manifest of {layers} layers ({size} bytes): pull: {code} {err!r}")
            finally:
                mock.stop()
        d = t / "fat2000"
        top_d, size = fat_layout(d, 2000)
        mock = Mock()
        try:
            code, out, err = push(d, mock.addr, "fat/app")
            ok(code == 1 and "layout-json" in err and not mock.state()["blobs"], f"a manifest of 2000 layers ({size} bytes) should be refused as too big to read, with nothing sent: {code} {err!r}")
            # a registry holding one: pulling it is refused the same way and writes nothing
            import urllib.request
            man = (d / "blobs" / "sha256" / top_d.split(":")[1]).read_bytes()
            req = urllib.request.Request(f"http://{mock.addr}/v2/fat/app/manifests/v1", data=man, method="PUT", headers={"Content-Type": "application/vnd.oci.image.manifest.v1+json"})
            urllib.request.urlopen(req).read()
            dest = t / "fat2000-pulled"
            skeleton(dest)
            code, out, err = pull(mock.addr, "fat/app", "v1", dest)
            ok(code == 1 and "layout-json" in err and not blobs_of(dest) and not (dest / "index.json").exists(), f"pulling a manifest of 2000 layers: {code} {err!r}")
        finally:
            mock.stop()

        # ---------------------------------------------------------------- 3. validation
        good_args = ["--image", image, "--registry", "127.0.0.1:1", "--repo", "f/app", "--plain-http"]

        def refuse_push(name, args, tag, culprit=None):
            code, out, err = run([PUSH, *args])
            ok(code == 1 and f"refused: {tag}" in err and (culprit is None or culprit in err), f"push {name}: expected {tag}, got {code} {err!r}")

        # a bad tag is refused before the layout is looked at (the missing image directory would be reported otherwise)
        refuse_push("a bad tag, before the layout is touched", ["--image", t / "nope", "--registry", "127.0.0.1:1", "--repo", "f/app", "--plain-http", "--tag", "-bad"], "push-tag")
        refuse_push("a bad repository name, before the layout is touched", ["--image", t / "nope", "--registry", "127.0.0.1:1", "--repo", "UPPER", "--plain-http"], "registry-name")
        refuse_push("https with a roots file that is not there", ["--image", image, "--registry", "127.0.0.1:1", "--repo", "f/app", "--trust-file", t / "no-such-roots.pem"], "tls-roots")
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
        refuse_pull("https with a roots file that is not there", [*base, "--trust-file", t / "no-such-roots.pem"], "tls-roots")
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

        # ---------------------------------------------------------------- 3c. where an upload may go
        # (registry.upload_target, through target-probe: the rule that keeps credentials and bodies on the host asked for)
        up = "/v2/x/blobs/uploads/u"
        for location, host, port, want in [
            (up, "reg.example", 5000, up + "?digest=sha256:abc"),
            (up + "?_state=s", "reg.example", 5000, up + "?_state=s&digest=sha256:abc"),
            ("//other.example" + up, "reg.example", 5000, "//other.example" + up + "?digest=sha256:abc"),     # a path on this host, whatever it looks like
            ("http://reg.example:5000" + up, "reg.example", 5000, up + "?digest=sha256:abc"),
            ("https://reg.example" + up, "reg.example", 443, up + "?digest=sha256:abc"),
            ("https://reg.example:443" + up, "reg.example", 443, up + "?digest=sha256:abc"),
            ("http://reg.example" + up, "reg.example", 80, up + "?digest=sha256:abc"),
            ("https://reg.example" + up, "reg.example", 5000, "registry-redirect-foreign-host"),       # no port is 443 only for https on 443
            ("http://reg.example" + up, "reg.example", 443, "registry-redirect-foreign-host"),
            ("https://reg.example" + up, "reg.example", 80, "registry-redirect-foreign-host"),
            ("ftp://reg.example" + up, "reg.example", 80, "registry-redirect-foreign-host"),
            ("https://reg.example:444" + up, "reg.example", 443, "registry-redirect-foreign-host"),
            ("https://other.example" + up, "reg.example", 443, "registry-redirect-foreign-host"),
            ("https://reg.example.evil" + up, "reg.example", 443, "registry-redirect-foreign-host"),
            ("https://reg.example@other.example" + up, "reg.example", 443, "registry-redirect-foreign-host"),
            ("https://reg.example:443@other.example" + up, "reg.example", 443, "registry-redirect-foreign-host"),
            ("https://evil.example:443" + up, "reg.example", 443, "registry-redirect-foreign-host"),
            ("reg.example:5000" + up, "reg.example", 5000, "registry-location"),
            ("https://reg.example", "reg.example", 443, "registry-location"),
            ("", "reg.example", 443, "registry-location"),
            ("v2/x", "reg.example", 443, "registry-location"),
        ]:
            code, out, err = run([TARGET, location, host, port])
            if want.startswith("registry-"):
                ok(code == 1 and want in err, f"upload target {location!r} for {host}:{port}: expected {want}, got {code} {out!r} {err!r}")
            else:
                ok(code == 0 and out == want, f"upload target {location!r} for {host}:{port}: expected {want!r}, got {code} {out!r} {err!r}")

        # ---------------------------------------------------------------- 3b. https and tokens
        pki = make_pki(t / "pki")
        if not pki:
            notes.append("openssl NOT installed: the https checks were not run")
        else:
            w = t / "tls"
            image, digests, top = make_image(w, ["amd64"], "gzip")
            nreg = len(registry_blobs(image, list(digests.values())))
            roots = ["--trust-file", pki["ca"]]

            def secure_round(label, mock, host, extra_push=(), extra_pull=(), expect_push=0, expect_pull=0, push_tag=None, pull_tag=None, blobs=None):
                """Push `image` and pull it back over https (or plain, for a plain mock); check the outcome and what the registry holds."""
                plain = mock.scheme == "http"
                addr = f"{host}:{mock.port}"
                code, out, err = push(image, addr, "tls/app", extra=[*([] if plain else roots), *extra_push], plain=plain)
                if expect_push == 0:
                    if not ok(code == 0 and "pushed as v1" in out, f"{label}: push refused: {code} {err!r} {out!r}"):
                        return
                    ok(len(mock.state()["blobs"]) == nreg, f"{label}: the registry holds {len(mock.state()['blobs'])} blobs, expected {nreg}")
                    dest = w / f"pulled-{label.replace(' ', '-')}"
                    skeleton(dest)
                    code, out, err = pull(addr, "tls/app", "v1", dest, extra=[*([] if plain else roots), *extra_pull], plain=plain)
                    if ok(code == 0 and last(out) == top, f"{label}: pull refused: {code} {err!r}"):
                        got = layout_ok(dest, top, label, "v1")
                        ok(got == blobs_of(image), f"{label}: the pulled blobs differ from the pushed ones")
                else:
                    ok(code == 1 and push_tag in err, f"{label}: push: expected {push_tag}, got {code} {err!r}")
                    if blobs is not None:
                        ok(len(mock.state()["blobs"]) == blobs, f"{label}: the registry holds {len(mock.state()['blobs'])} blobs, expected {blobs}")

            for host in ("127.0.0.1", "localhost"):
                mock = Mock(tls=pki["good"])
                try:
                    secure_round(f"https {host}", mock, host)
                finally:
                    mock.stop()
            # a roots file with no certificate in it is refused, not trusted
            (t / "garbage.pem").write_text("-----BEGIN NOTHING-----\nAAAA\n-----END NOTHING-----\n")
            code, out, err = push(image, "127.0.0.1:1", "tls/app", extra=["--trust-file", t / "garbage.pem"], plain=False)
            ok(code == 1 and "tls-roots" in err, f"a roots file with no certificate: {code} {err!r}")
            # a layer of 2.5 MB over https: many records, the engine takes ciphertext only as it has room for the plaintext
            wbig = t / "tls-big"
            big_image, big_digests, big_top = make_image(wbig, ["amd64"], "gzip", big=2_500_000)
            mock = Mock(bearer=True, tls=pki["good"])
            try:
                code, out, err = push(big_image, mock.addr, "tls/big", extra=roots, plain=False)
                if ok(code == 0, f"a 2.5 MB layer over https: push refused: {err!r}"):
                    dest = wbig / "pulled"
                    skeleton(dest)
                    code, out, err = pull(mock.addr, "tls/big", "v1", dest, extra=roots, plain=False)
                    ok(code == 0 and last(out) == big_top and blobs_of(dest) == blobs_of(big_image), f"a 2.5 MB layer over https: pull: {code} {err!r}")
            finally:
                mock.stop()
            # https with credentials; with the wrong ones
            cd = t / "tls-creds"
            cd.mkdir()
            (cd / "good").write_text("alice:s3cret\n")
            (cd / "wrong").write_text("alice:nope\n")
            mock = Mock(auth="alice:s3cret", tls=pki["good"])
            try:
                secure_round("https with credentials", mock, "127.0.0.1", ["--basic-file", cd / "good"], ["--basic-file", cd / "good"])
            finally:
                mock.stop()
            mock = Mock(auth="alice:s3cret", tls=pki["good"])
            try:
                secure_round("https with the wrong credentials", mock, "127.0.0.1", ["--basic-file", cd / "wrong"], expect_push=1, push_tag="registry-unauthorized", blobs=0)
            finally:
                mock.stop()
            # what a client must not accept: each refused before a single request reaches the registry
            for label, cert, trust, tag in [("a certificate from an unknown authority", "good", pki["other"], "x509-unknown-issuer"),
                                            ("an expired certificate", "expired", pki["ca"], "x509-expired"),
                                            ("a certificate for another name", "wrongname", pki["ca"], "x509-name-mismatch")]:
                mock = Mock(tls=pki[cert])
                try:
                    code, out, err = push(image, mock.addr, "tls/app", extra=["--trust-file", trust], plain=False)
                    ok(code == 1 and tag in err, f"{label}: expected {tag}, got {code} {err!r}")
                    code2, out2, err2 = pull(mock.addr, "tls/app", "v1", w / "never", extra=["--trust-file", trust], plain=False)
                    ok(code2 == 1, f"{label}: pull should be refused: {code2} {err2!r}")
                    st = mock.state()
                    ok(not st["blobs"] and st["served"] == 0 and not [l for l in st["log"] if "GET" in l or "PUT" in l or "POST" in l or "HEAD" in l], f"{label}: a request reached the registry: {st['log']}")
                finally:
                    mock.stop()
            # https to a registry that speaks plain HTTP, and plain HTTP to one that speaks https
            mock = Mock()
            try:
                code, out, err = push(image, mock.addr, "tls/app", extra=roots, plain=False)
                ok(code == 1 and "http-" not in err.split("refused:")[-1][:6] and not mock.state()["blobs"], f"https to a plain registry: {code} {err!r}")
            finally:
                mock.stop()
            mock = Mock(tls=pki["good"])
            try:
                code, out, err = push(image, mock.addr, "tls/app")
                ok(code == 1 and not mock.state()["blobs"], f"plain HTTP to an https registry: {code} {err!r}")
            finally:
                mock.stop()
            # credentials are fine over https to any host (the rule is about plain HTTP); a non-loopback host that is not there
            code, out, err = run([PUSH, "--image", image, "--registry", "registry.invalid:443", "--repo", "tls/app", "--basic-file", cd / "good", *roots])
            ok(code == 1 and "push-credentials-over-plain-http" not in err and "http-dial" in err, f"credentials over https to another host: {code} {err!r}")
            skeleton(t / "tls-nowhere")
            code, out, err = run([PULL, "--registry", "registry.invalid:443", "--repo", "tls/app", "--ref", "v1", "--out", t / "tls-nowhere", "--basic-file", cd / "good", *roots])
            ok(code == 1 and "pull-credentials-over-plain-http" not in err and "http-dial" in err, f"pull: credentials over https to another host: {code} {err!r}")
            # a server that ends a body by closing, over https, without a close_notify: the body may be cut short, so it is refused;
            # the same server over plain HTTP is a valid until-close body
            for scheme_label, tls_cert in (("plain", None), ("https", pki["good"])):
                mock = Mock(["until-close"], tls=tls_cert)
                try:
                    plain = tls_cert is None
                    code, out, err = push(image, mock.addr, "uc/app", extra=[] if plain else roots, plain=plain)
                    dest = t / f"until-close-{scheme_label}"
                    skeleton(dest)
                    code, out, err = pull(mock.addr, "uc/app", "v1", dest, extra=[] if plain else roots, plain=plain)
                    if plain:
                        ok(code == 0, f"an until-close body over plain HTTP: {code} {err!r}")
                    else:
                        ok(code == 1 and "http-truncated" in err and not blobs_of(dest), f"an until-close body over https with no close_notify: {code} {err!r}")
                finally:
                    mock.stop()

            # the Bearer token flow, over https and over plain HTTP to loopback
            for scheme_label, tls_cert in (("https", pki["good"]), ("plain", None)):
                mock = Mock(bearer=True, tls=tls_cert)
                try:
                    secure_round(f"bearer {scheme_label}", mock, "127.0.0.1")
                    ok(sum("token" in l for l in mock.state()["log"]) >= 0, "no token log")
                finally:
                    mock.stop()
                mock = Mock(bearer=True, auth="alice:s3cret", tls=tls_cert)
                try:
                    secure_round(f"bearer {scheme_label} with credentials", mock, "127.0.0.1", ["--basic-file", cd / "good"], ["--basic-file", cd / "good"]) if scheme_label == "plain" else secure_round(f"bearer {scheme_label} with credentials", mock, "127.0.0.1", ["--basic-file", cd / "good"], ["--basic-file", cd / "good"])
                finally:
                    mock.stop()
                mock = Mock(bearer=True, auth="alice:s3cret", tls=tls_cert)
                try:
                    secure_round(f"bearer {scheme_label} without credentials", mock, "127.0.0.1", expect_push=1, push_tag="registry-unauthorized", blobs=0)
                finally:
                    mock.stop()
            for fault, tag, blobs in [("token-foreign-realm", "registry-token-realm", 0), ("token-crlf", "registry-token", 0), ("token-bad-json", "registry-token", 0),
                                      ("token-denied", "registry-unauthorized", 0), ("token-pull-only", "registry-auth-bearer", 0), ("token-huge", "registry-token", 0)]:
                mock = Mock([fault], bearer=True, tls=pki["good"])
                try:
                    secure_round(f"fault {fault}", mock, "127.0.0.1", expect_push=1, push_tag=tag, blobs=blobs)
                    st = mock.state()
                    if fault == "token-foreign-realm":
                        ok(not [l for l in st["log"] if "token" in l], f"{fault}: a token was asked for from this registry although the realm named another host")
                finally:
                    mock.stop()
            mock = Mock(["token-access-token"], bearer=True, tls=pki["good"])
            try:
                secure_round("token under access_token", mock, "127.0.0.1")
            finally:
                mock.stop()

        # ---------------------------------------------------------------- 3d. blob redirects
        # A registry may hand a blob to a CDN with a 307. Followed for a blob GET only, at most 3 times, only to the scheme the
        # registry itself speaks (plain HTTP only to loopback), never with the credentials, and the bytes are checked as always.
        pushed = t / "redirect-image"
        r_image, r_digests, r_top = make_image(pushed, ["amd64"], "gzip")
        def redirect_case(label, fault, tls_cert, want_ok, tag=None, auth=None, creds=None):
            mock = Mock([fault], auth=auth, tls=tls_cert)
            try:
                plain = tls_cert is None
                extra = [] if plain else ["--trust-file", pki["ca"]]
                if creds:
                    extra += ["--basic-file", creds]
                code, out, err = push(r_image, mock.addr, "r/app", extra=extra, plain=plain)
                if not ok(code == 0, f"{label}: push: {code} {err!r}"):
                    return
                dest = t / ("redirect-" + label.replace(" ", "-"))
                skeleton(dest)
                code, out, err = pull(mock.addr, "r/app", "v1", dest, extra=extra, plain=plain)
                st = mock.state()
                if want_ok:
                    ok(code == 0 and last(out) == r_top and blobs_of(dest) == blobs_of(r_image), f"{label}: pull: {code} {err!r}")
                else:
                    ok(code == 1 and tag in err, f"{label}: expected {tag}, got {code} {err!r}")
                    # whatever had been fetched before the refusal, no half-blob is left behind
                    ok(not [n for n in os.listdir(dest / "blobs" / "sha256") if n.startswith(".")], f"{label}: a temporary file was left behind")
                ok(st["leaked"] == 0, f"{label}: credentials reached the redirect target {st['leaked']} times")
                gets = len([l for l in st["log"] if "GET /v2/r/app/blobs/sha256" in l])
                ok(gets <= 5, f"{label}: the blob address was asked for {gets} times")
            finally:
                mock.stop()

        rc = t / "redirect-creds"
        rc.mkdir()
        (rc / "alice").write_text("alice:s3cret\n")
        for tls_cert, scheme_label in ((None, "plain"), (pki["good"] if pki else None, "https")):
            if scheme_label == "https" and not pki:
                continue
            redirect_case(f"{scheme_label} redirect to this host", "blob-redirect", tls_cert, True)
            redirect_case(f"{scheme_label} redirect to a path", "blob-redirect-relative", tls_cert, True)
            redirect_case(f"{scheme_label} redirect with credentials", "blob-redirect", tls_cert, True, auth="alice:s3cret", creds=rc / "alice")
            redirect_case(f"{scheme_label} redirect forever", "blob-redirect-loop", tls_cert, False, "registry-redirect-foreign-host")
            redirect_case(f"{scheme_label} redirect with a space in the address", "blob-redirect-space", tls_cert, False, "registry-redirect-foreign-host")
            redirect_case(f"{scheme_label} redirect with userinfo", "blob-redirect-userinfo", tls_cert, False, "registry-redirect-foreign-host")
            redirect_case(f"{scheme_label} redirect to a host that is not there", "blob-redirect-foreign", tls_cert, False, "http-dial" if scheme_label == "https" else "registry-redirect-foreign-host")
        if pki:
            redirect_case("https redirect to another name", "blob-redirect-other", pki["good"], True)
            redirect_case("https redirect to another name with credentials", "blob-redirect-other", pki["good"], True, auth="alice:s3cret", creds=rc / "alice")
            redirect_case("https redirect down to http", "blob-redirect-downgrade", pki["good"], False, "registry-redirect-foreign-host")

        # ---------------------------------------------------------------- 3e. Docker schema 2 images (what `docker build` pushes and ghcr.io serves)
        import urllib.request
        dm, dl = "application/vnd.docker.distribution.manifest.v2+json", "application/vnd.docker.distribution.manifest.list.v2+json"
        mock = Mock()
        try:
            def put(path, data, ctype):
                urllib.request.urlopen(urllib.request.Request(f"http://{mock.addr}{path}", data=data, method="PUT", headers={"Content-Type": ctype})).read()
            def blob(data):
                d = "sha256:" + sha(data)
                r = urllib.request.Request(f"http://{mock.addr}/v2/dk/app/blobs/uploads/?digest={d}", data=data, method="POST")
                urllib.request.urlopen(r).read()
                return d
            cfg = b'{"architecture":"amd64","os":"linux"}'
            lay = b"docker layer"
            cd_, ld_ = blob(cfg), blob(lay)
            man = IC.compact({"schemaVersion": 2, "mediaType": dm, "config": {"mediaType": "application/vnd.docker.container.image.v1+json", "size": len(cfg), "digest": cd_},
                              "layers": [{"mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip", "size": len(lay), "digest": ld_}]})
            md = "sha256:" + sha(man)
            lst = IC.compact({"schemaVersion": 2, "mediaType": dl, "manifests": [{"mediaType": dm, "digest": md, "size": len(man), "platform": {"architecture": "amd64", "os": "linux"}}]})
            ld = "sha256:" + sha(lst)
            put(f"/v2/dk/app/manifests/{md}", man, dm)
            put("/v2/dk/app/manifests/latest", lst, dl)
            # the list, whole
            dest = t / "docker-list"
            skeleton(dest)
            code, out, err = pull(mock.addr, "dk/app", "latest", dest)
            if ok(code == 0 and last(out) == ld, f"a Docker manifest list: {code} {err!r} {out!r}"):
                ok((dest / "index.json").read_bytes() == model_entry(dl, ld, len(lst), "latest"), "a Docker manifest list: the layout's index.json is not the model")
                ok(set(blobs_of(dest)) == {sha(x) for x in (lst, man, cfg, lay)} and blobs_of(dest)[sha(man)] == man, "a Docker manifest list: the blobs are not the four documents")
            # one platform of it
            dest = t / "docker-platform"
            skeleton(dest)
            code, out, err = pull(mock.addr, "dk/app", "latest", dest, ["--platform", "linux/amd64"])
            if ok(code == 0 and last(out) == md, f"a Docker manifest by platform: {code} {err!r}"):
                ok((dest / "index.json").read_bytes() == model_entry(dm, md, len(man), "latest"), "a Docker manifest by platform: the layout's index.json is not the model")
            # a single Docker manifest by digest
            dest = t / "docker-single"
            skeleton(dest)
            code, out, err = pull(mock.addr, "dk/app", md, dest)
            ok(code == 0 and last(out) == md and (dest / "index.json").read_bytes() == model_entry(dm, md, len(man), ""), f"a single Docker manifest: {code} {err!r}")
        finally:
            mock.stop()

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
