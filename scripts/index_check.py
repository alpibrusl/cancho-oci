#!/usr/bin/env python3
"""Gate for `oci-index` (design 2 and 3; task #8): a multi-platform image checked against independent models.

For random sets and orders of platforms it builds one image per platform into a shared layout directory with
oci-build, combines them with oci-index, and checks:
  1. the image index blob and the layout's index.json validate against the official OCI schemas and equal, byte for
     byte, what `json.dumps(model, separators=(",", ":"), ensure_ascii=False)` writes for an independent model:
     manifests in the order named, each with its blob's real size and the platform from its own config;
  2. the layout holds exactly the images' blobs and the index blob, nothing else;
  3. building twice in other directories gives identical bytes (G1), and running oci-index again changes nothing;
  4. `skopeo` and `crane` (when installed) read it: `skopeo inspect` picks the right manifest per architecture,
     `skopeo copy --all` re-verifies every digest, `crane push` + `crane validate --remote` check the index and every
     image under it, and the registry's digest is the index digest;
  5. every refusal names its rule: a platform twice, a missing blob, a tampered manifest or layer, a layer or a config
     given as a manifest, a hand-made manifest with a wrong layer size or config size, an architecture v1 does not
     build for, a malformed digest, no manifests, an unknown flag, a missing --out or skeleton. A refusal
     leaves the layout's index.json and blob set exactly as they were.

    index_check.py [--cases N] [--seed S] [--build build/oci-build] [--index build/oci-index]
"""
import argparse, hashlib, importlib.util, json, os, random, shutil, socket, subprocess, sys, tempfile, time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


IC = load("image_check")
ELF = load("make_elf")

bad = 0
checks = 0
ARCHES = ["amd64", "arm64", "riscv64"]


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


def run(cmd):
    p = subprocess.run([str(c) for c in cmd], capture_output=True, text=True)
    return p.returncode, p.stdout.strip(), p.stderr.strip()


def skeleton(d):
    (Path(d) / "blobs" / "sha256").mkdir(parents=True)


def tree(d):
    return {str(p.relative_to(d)): p.read_bytes() for p in sorted(Path(d).rglob("*")) if p.is_file()}


def blobset(image):
    return {p.name for p in (Path(image) / "blobs" / "sha256").iterdir()}


def build_image(exe, root, image, arch, tag, extra=()):
    code, out, err = run([exe, "--root", root, "--out", image, "--platform", f"linux/{arch}", "--bin", f"app-{arch}:app", "--file", "motd:etc/motd",
                          "--compress", "gzip", *extra])
    return out if code == 0 else None


def model_index(entries):
    return {"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json",
            "manifests": [{"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": d, "size": s,
                           "platform": {"architecture": a, "os": "linux"}} for d, s, a in entries]}


def model_layout_index(digest, size, ref):
    m = {"mediaType": "application/vnd.oci.image.index.v1+json", "digest": digest, "size": size}
    if ref:
        m["annotations"] = {"org.opencontainers.image.ref.name": ref}
    return {"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json", "manifests": [m]}


def prepare(w, tag, archs):
    """A root with one executable per architecture, and a layout holding an image per named architecture."""
    root, image = w / "root", w / "image"
    root.mkdir(parents=True)
    skeleton(image)
    for a in ARCHES:
        (root / f"app-{a}").write_bytes(ELF.elf(a))
    (root / "motd").write_bytes(f"hello {tag}\n".encode())
    return root, image, {a: build_image(BUILD, root, image, a, tag) for a in archs}


def manifests_args(digests):
    out = []
    for d in digests:
        out += ["--manifest", d]
    return out


def check_index(image, entries, ref, name):
    layout_bytes = (Path(image) / "index.json").read_bytes()
    layout = json.loads(layout_bytes)
    ok(not list(IC.validator("image-index-schema.json").iter_errors(layout)), f"{name}: index.json is not valid against the OCI schema")
    ok((Path(image) / "oci-layout").read_bytes() == b'{"imageLayoutVersion":"1.0.0"}', f"{name}: oci-layout changed")
    idesc = layout["manifests"][0]
    ihex = idesc["digest"].split(":")[1]
    blob = (Path(image) / "blobs" / "sha256" / ihex).read_bytes()
    ok(sha(blob) == ihex and len(blob) == idesc["size"], f"{name}: the layout's descriptor does not match the index blob")
    ok(not list(IC.validator("image-index-schema.json").iter_errors(json.loads(blob))), f"{name}: the image index is not valid against the OCI schema: "
       f"{[e.message for e in IC.validator('image-index-schema.json').iter_errors(json.loads(blob))][:2]}")
    sizes = [(d, (Path(image) / "blobs" / "sha256" / d.split(":")[1]).stat().st_size, a) for d, a in entries]
    ok(blob == IC.compact(model_index(sizes)), f"{name}: the image index differs from the model:\n  ours  {blob[:300]!r}\n  model {IC.compact(model_index(sizes))[:300]!r}")
    ok(layout_bytes == IC.compact(model_layout_index(idesc["digest"], len(blob), ref)), f"{name}: index.json differs from the model")
    return idesc["digest"]


def start_registry():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    srv = subprocess.Popen(["crane", "registry", "serve", "--address", f"127.0.0.1:{port}"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(100):
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
            return srv, f"127.0.0.1:{port}"
        except OSError:
            time.sleep(0.1)
    return srv, None


def write_blob(image, data):
    h = sha(data)
    (Path(image) / "blobs" / "sha256" / h).write_bytes(data)
    return f"sha256:{h}"


def hand_manifest(image, arch, *, layer_size_delta=0, config_size_delta=0, arch_in_config=None, layer_data=b"layer bytes"):
    """A manifest and config written by hand, so a field can be made wrong on purpose."""
    layer = write_blob(image, layer_data)
    cfg = IC.compact({"architecture": arch_in_config or arch, "os": "linux", "config": {}, "rootfs": {"type": "layers", "diff_ids": [layer]}})
    cdig = write_blob(image, cfg)
    man = IC.compact({"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
                      "config": {"mediaType": "application/vnd.oci.image.config.v1+json", "digest": cdig, "size": len(cfg) + config_size_delta},
                      "layers": [{"mediaType": "application/vnd.oci.image.layer.v1.tar", "digest": layer, "size": len(layer_data) + layer_size_delta}]})
    return write_blob(image, man), layer, cdig


BUILD = INDEX = None


def main():
    global BUILD, INDEX
    ap = argparse.ArgumentParser()
    ap.add_argument("--cases", type=int, default=16)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--build", default=str(ROOT / "build" / "oci-build"))
    ap.add_argument("--index", default=str(ROOT / "build" / "oci-index"))
    a = ap.parse_args()
    BUILD, INDEX = a.build, a.index
    rng = random.Random(a.seed)
    have_skopeo, have_crane = shutil.which("skopeo"), shutil.which("crane")
    server, registry = (None, None)
    if have_crane:
        server, registry = start_registry()
        if not registry:
            fail("the in-memory registry did not start")

    with tempfile.TemporaryDirectory() as t:
        t = Path(t)
        # ---- random multi-platform images
        for n in range(a.cases):
            archs = rng.sample(ARCHES, rng.choice([1, 2, 3]))      # the order is the order on the command line
            ref = rng.choice(["", "v1", "latest", "rc-2"])
            w = t / f"c{n}"
            root, image, digests = prepare(w, str(n), archs)
            if not ok(all(digests.values()), f"case {n}: building the per-platform images failed"):
                continue
            before = blobset(image)
            code, out, err = run([INDEX, "--out", image, *manifests_args([digests[x] for x in archs]), *(["--ref", ref] if ref else [])])
            if not ok(code == 0 and out.startswith("sha256:"), f"case {n}: oci-index refused: {err!r}"):
                continue
            top = check_index(image, [(digests[x], x) for x in archs], ref, f"case {n} {archs}")
            ok(top == out, f"case {n}: the printed digest is not the layout's")
            ok(blobset(image) == before | {out.split(":")[1]}, f"case {n}: the layout holds unexpected blobs: {sorted(blobset(image) - before - {out.split(':')[1]})}")
            # idempotent
            snapshot = tree(image)
            code2, out2, _ = run([INDEX, "--out", image, *manifests_args([digests[x] for x in archs]), *(["--ref", ref] if ref else [])])
            ok(code2 == 0 and out2 == out and tree(image) == snapshot, f"case {n}: running oci-index again changed the layout")
            # G1: another directory, the same bytes
            w2 = t / f"c{n}b"
            root2, image2, digests2 = prepare(w2, str(n), archs)
            code3, out3, _ = run([INDEX, "--out", image2, *manifests_args([digests2[x] for x in archs]), *(["--ref", ref] if ref else [])])
            ok(code3 == 0 and tree(image2) == snapshot, f"case {n}: another directory gave different bytes")
            if n < 4 and ref:
                target = f"oci:{image}:{ref}"
                if have_skopeo:
                    rc, text, _ = run(["skopeo", "inspect", "--raw", target])
                    ok(rc == 0 and json.loads(text)["mediaType"] == "application/vnd.oci.image.index.v1+json", f"case {n}: skopeo does not see an image index: {text[:150]}")
                    for x in archs:
                        rc, text, err = run(["skopeo", "inspect", "--override-os", "linux", "--override-arch", x, "--config", target])
                        ok(rc == 0 and json.loads(text).get("architecture") == x, f"case {n}: skopeo did not pick the {x} image: {text[:100]} {err[:100]}")
                    rc, text, err = run(["skopeo", "copy", "--all", target, f"dir:{w / 'copy'}"])
                    ok(rc == 0, f"case {n}: skopeo copy --all failed: {err[:250]}")
                if have_crane and registry:
                    r = f"{registry}/multi{n}:t"
                    rc, text, err = run(["crane", "push", image, r, "--insecure"])
                    if ok(rc == 0, f"case {n}: crane push failed: {err[:200]}"):
                        rc, text, err = run(["crane", "validate", "--remote", r, "--insecure"])
                        ok(rc == 0, f"case {n}: crane validate of the multi-platform image failed: {err[:300]}")
                        rc, text, err = run(["crane", "digest", r, "--insecure"])
                        ok(rc == 0 and text == out, f"case {n}: the registry's digest {text!r} is not the index digest {out!r}")

        # ---- a config of several KB (120 labels): a JSON tape of 3 ints a byte does not fit a 64 KiB region, which used to trap
        w = t / "fat"
        root, image, digests = prepare(w, "fat", ["amd64", "arm64"])
        labels = []
        for i in range(120):
            labels += ["--label", f"org.example.label{i:03d}=value-{i:03d}-" + "x" * 20]
        fat = [build_image(BUILD, root, image, x, "fat", labels) for x in ("amd64", "arm64")]
        code, out, err = run([INDEX, "--out", image, *manifests_args(fat)])
        if ok(code == 0 and out.startswith("sha256:"), f"an image config of 120 labels: oci-index refused or crashed: {code} {err!r}"):
            check_index(image, list(zip(fat, ("amd64", "arm64"))), "", "fat labels")

        # ---- refusals, each leaving the layout untouched
        w = t / "refusals"
        root, image, digests = prepare(w, "r", ARCHES)
        good = [digests[x] for x in ARCHES]
        base = tree(image)

        def refuse(name, extra, tag, culprit=None, img=None):
            img = img or image
            before = tree(img)
            code, out, err = run([INDEX, "--out", img, *extra])
            ok(code == 1 and f"refused: {tag}" in err and (culprit is None or culprit in err), f"refusal {name}: expected {tag}, got {code} {err!r}")
            ok(tree(img) == before, f"refusal {name}: a refused run changed the layout")

        refuse("no manifests", [], "index-no-manifests")
        refuse("only a ref", ["--ref", "v1"], "index-no-manifests")
        refuse("platform twice (same manifest)", manifests_args([good[0], good[0]]), "index-platform-twice", good[0])
        # a second image for the same platform, a different manifest
        d2 = build_image(BUILD, root, image, "amd64", "x", ["--user", "1000"])
        base = tree(image)
        refuse("platform twice (another image)", manifests_args([good[0], d2]), "index-platform-twice", d2)
        refuse("a control character in the ref", manifests_args(good) + ["--ref", "a\x01b"], "image-ref")
        refuse("a newline in the ref", manifests_args(good) + ["--ref", "a\nb"], "image-ref")
        refuse("malformed digest", ["--manifest", "sha256:XYZ"], "index-digest", "sha256:XYZ")
        refuse("wrong algorithm", ["--manifest", "sha512:" + "0" * 64], "index-digest")
        refuse("missing blob", ["--manifest", "sha256:" + "0" * 64], "blob-missing")
        refuse("unknown flag", ["--frobnicate", "x"], "index-flag", "--frobnicate")
        refuse("a trailing flag without a value", ["--manifest"], "index-flag", "--manifest")
        # more manifests than platforms can only repeat a platform: there is no separate "too many" rule
        refuse("four manifests", manifests_args([good[0], good[1], good[2], good[0]]), "index-platform-twice")
        code, out, err = run([INDEX, "--manifest", good[0]])
        ok(code == 1 and "index-missing" in err, f"refusal missing --out: {code} {err!r}")
        (t / "bare").mkdir()
        code, out, err = run([INDEX, "--out", t / "bare", *manifests_args(good)])
        ok(code == 1 and "index-layout-skeleton" in err, f"refusal missing skeleton: {code} {err!r}")
        code, out, err = run([INDEX, "--out", t / "no-such", *manifests_args(good)])
        ok(code == 1 and "index-dir-open" in err, f"refusal missing directory: {code} {err!r}")

        # a layer or a config given as a manifest
        man = json.loads((Path(image) / "blobs" / "sha256" / good[0].split(":")[1]).read_text())
        refuse("a layer given as a manifest", manifests_args([man["layers"][0]["digest"]]), "layout-json")
        refuse("a config given as a manifest", manifests_args([man["config"]["digest"]]), "index-manifest")
        # hand-made manifests with one field wrong
        for label, kw, tag in [("a layer size wrong", dict(layer_size_delta=1), "index-manifest"), ("a config size wrong", dict(config_size_delta=3), "index-manifest"),
                               ("an unsupported architecture", dict(arch="s390x"), "image-arch"),
                               ("an unsupported architecture (config)", dict(arch="amd64", arch_in_config="s390x"), "image-arch")]:
            arch = kw.pop("arch", "amd64")
            m, _, _ = hand_manifest(image, arch, layer_data=os.urandom(20), **kw)
            base = tree(image)
            refuse(label, manifests_args([m]), tag)
        # a manifest that is not what it says: another media type, another schema version, another OS, too large
        def odd_manifest(label, edit, tag):
            layer = write_blob(image, os.urandom(18))
            cfg = IC.compact({"architecture": "amd64", "os": edit.get("os", "linux"), "config": {}, "rootfs": {"type": "layers", "diff_ids": [layer]}})
            cdig = write_blob(image, cfg)
            doc = {"schemaVersion": edit.get("schema", 2), "mediaType": edit.get("media", "application/vnd.oci.image.manifest.v1+json"),
                   "config": {"mediaType": "application/vnd.oci.image.config.v1+json", "digest": cdig, "size": len(cfg)},
                   "layers": [{"mediaType": "application/vnd.oci.image.layer.v1.tar", "digest": layer, "size": 18}]}
            body = IC.compact(doc)
            if not edit.get("keep_layer_size"):
                pass
            m = write_blob(image, body)
            refuse(label, manifests_args([m]), tag)
        odd_manifest("a manifest with another media type", dict(media="application/vnd.example.manifest+json"), "index-manifest")
        odd_manifest("a manifest with schemaVersion 1", dict(schema=1), "index-manifest")
        odd_manifest("a config for another OS", dict(os="windows"), "image-os")
        # an oversized document (the reader caps what it will hold in memory)
        big = write_blob(image, b'{"schemaVersion":2,"pad":"' + b"x" * 1_100_000 + b'"}')
        refuse("an oversized document", manifests_args([big]), "layout-document-too-large")
        # a manifest with no layers, and one without a config
        real_cfg = (Path(image) / "blobs" / "sha256" / man["config"]["digest"].split(":")[1]).stat().st_size
        write_nolayers = write_blob(image, IC.compact({"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
                                                         "config": {"mediaType": "application/vnd.oci.image.config.v1+json", "digest": man["config"]["digest"], "size": real_cfg}, "layers": []}))
        refuse("a manifest with no layers", manifests_args([write_nolayers]), "index-manifest")
        write_noconfig = write_blob(image, IC.compact({"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json", "layers": []}))
        refuse("a manifest without a config", manifests_args([write_noconfig]), "index-manifest")
        write_notjson = write_blob(image, b"this is not json at all")
        refuse("a manifest that is not JSON", manifests_args([write_notjson]), "layout-json")
        # a manifest naming a layer that is not there
        layer_gone, lay, _ = hand_manifest(image, "arm64", layer_data=os.urandom(30))
        (Path(image) / "blobs" / "sha256" / lay.split(":")[1]).unlink()
        base = tree(image)
        refuse("a layer missing", manifests_args([layer_gone]), "blob-missing")
        # tampering with the blobs of a good image
        for what, path in [("the manifest", good[1]), ("the config", man["config"]["digest"]), ("a layer", man["layers"][0]["digest"])]:
            p = Path(image) / "blobs" / "sha256" / path.split(":")[1]
            orig = p.read_bytes()
            data = bytearray(orig)
            data[len(data) // 2] ^= 1
            p.write_bytes(bytes(data))
            refuse(f"{what} tampered", manifests_args([good[0] if what != "the manifest" else good[1]]), "blob-digest-mismatch")
            p.write_bytes(orig)
        # after all that, the originals still combine
        code, out, err = run([INDEX, "--out", image, *manifests_args(good)])
        ok(code == 0, f"the intact images no longer combine after the refusals: {err!r}")

    if server:
        server.terminate()
        server.wait(timeout=10)
    notes = []
    if not have_skopeo:
        notes.append("skopeo NOT installed: not run")
    if not have_crane:
        notes.append("crane NOT installed: not run")
    print(f"{'FAIL' if bad else 'ok'}: {checks} checks, {bad} failure(s)" + (f"  [{'; '.join(notes)}]" if notes else ""))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
