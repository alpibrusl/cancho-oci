#!/usr/bin/env python3
"""Gate for `oci.image` (design 2 and 3, task #5): the OCI image layout it writes is valid, consistent,
byte-reproducible and exactly what an independent model of the JSON says.

For random configs it builds a layout with image-probe (a layer from tar-probe) and checks:
  1. every JSON document validates against the official OCI image-spec v1.1.0 JSON Schemas (vendored);
  2. the chain is consistent: index -> manifest -> config and layer, every digest and size equal to
     the blob's own sha256 and length, `diff_ids` equal to the digest of the (uncompressed) layer, and the
     blob directory holds exactly those three blobs and nothing else;
  3. the config, manifest and index bytes equal what Python's `json.dumps(model, separators=(",", ":"),
     ensure_ascii=False)` writes for an independently built model: key order, escaping and all;
  4. building twice, in different directories, gives byte-identical files (G1);
  5. `skopeo` accepts it, and `crane` pushes it to an in-memory registry (`crane registry serve`), validates
     the pushed image, and the registry's manifest digest is the one we computed; a missing tool is printed,
     never silent;
  6. every refusal case names its rule tag, and a refusal writes no index.json.

    image_check.py [--cases N] [--seed S] [--probe build/image-probe] [--tar-probe build/tar-probe]
"""
import argparse, hashlib, json, os, random, shutil, subprocess, sys, tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCHEMAS = ROOT / "schemas" / "oci-image-spec-v1.1.0"
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


_validators = {}


def validator(name):
    """The OCI schemas are draft-04; two of the files carry no `$schema`, so say so. Refs are plain file names."""
    if name in _validators:
        return _validators[name]
    from jsonschema import Draft4Validator
    from referencing import Registry, Resource
    from referencing.jsonschema import DRAFT4

    def retrieve(uri):
        return Resource.from_contents(json.loads((SCHEMAS / uri.rsplit("/", 1)[-1]).read_text()), default_specification=DRAFT4)

    schema = json.loads((SCHEMAS / name).read_text())
    _validators[name] = Draft4Validator(schema, registry=Registry(retrieve=retrieve))
    return _validators[name]


def sha(b):
    return hashlib.sha256(b).hexdigest()


def compact(model):
    return json.dumps(model, separators=(",", ":"), ensure_ascii=False).encode()


def lines(text):
    return [l for l in text.split("\n") if l] if text else []


def model_config(arch, os_, entry, cmd, env, user, workdir, labels, ports, diff_id):
    c = {}
    if user:
        c["User"] = user
    if ports:
        c["ExposedPorts"] = {p: {} for p in lines(ports)}
    if env:
        c["Env"] = lines(env)
    if entry:
        c["Entrypoint"] = lines(entry)
    if cmd:
        c["Cmd"] = lines(cmd)
    if workdir:
        c["WorkingDir"] = workdir
    if labels:
        c["Labels"] = {l.split("=", 1)[0]: l.split("=", 1)[1] for l in lines(labels)}
    return {"architecture": arch, "os": os_, "config": c,
            "rootfs": {"type": "layers", "diff_ids": [diff_id]}, "history": [{"created_by": "cancho-oci"}]}


def model_manifest(cfg_digest, cfg_size, layer_digest, layer_size):
    return {"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {"mediaType": "application/vnd.oci.image.config.v1+json", "digest": cfg_digest, "size": cfg_size},
            "layers": [{"mediaType": "application/vnd.oci.image.layer.v1.tar", "digest": layer_digest, "size": layer_size}]}


def model_index(man_digest, man_size, arch, os_, ref):
    m = {"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": man_digest, "size": man_size,
         "platform": {"architecture": arch, "os": os_}}
    if ref:
        m["annotations"] = {"org.opencontainers.image.ref.name": ref}
    return {"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json", "manifests": [m]}


WORDS = ["alpha", "beta", "gamma", "delta", "app", "serve", "--port", "8080", "/bin/app", "x y", "naïve", "日本", "q\"uote", "back\\slash", "a/b", "tab\tx"]


def pick(rng, n):
    return "\n".join(rng.choice(WORDS) for _ in range(n)) if n else ""


def random_case(rng):
    env = "\n".join(f"{rng.choice(['PATH','HOME','MODE','LANG_X','A'])}={rng.choice(['/bin','/', 'x y', '日本', 'q\"t', ''])}" for _ in range(rng.choice([0, 0, 1, 3])))
    labels = "\n".join(f"org.example.k{i}={rng.choice(['v','a b','é','/p'])}" for i in range(rng.choice([0, 0, 1, 2])))
    ports = "\n".join(sorted({f"{rng.choice([80, 443, 8080, 65535, 1])}/{rng.choice(['tcp', 'udp'])}" for _ in range(rng.choice([0, 0, 1, 2]))}))
    # tab inside an item is a control character and is refused, so keep WORDS without it for accepted cases
    entry = pick(rng, rng.choice([0, 1, 2, 3])).replace("\t", " ")
    cmd = pick(rng, rng.choice([0, 0, 1, 2])).replace("\t", " ")
    return dict(arch=rng.choice(["amd64", "arm64", "riscv64"]), os_="linux", ref=rng.choice(["", "latest", "v1.2.3", "rc-1"]),
                entry=entry, cmd=cmd, env=env, user=rng.choice(["", "65532", "1000:1000", "app"]),
                workdir=rng.choice(["", "/", "/srv"]), labels=labels, ports=ports)


def probe(P, image, layer_dir, case):
    args = [P, image, layer_dir, "layer.tar", case["arch"], case["os_"], case["ref"], case["entry"], case["cmd"],
            case["env"], case["user"], case["workdir"], case["labels"], case["ports"]]
    p = subprocess.run(args, capture_output=True, text=True)
    return p.returncode, p.stdout.strip(), p.stderr.strip()


def make_layer(tar_probe, d, rng):
    spec = "\n".join(f"{k} {s} 0 {n}" for k, s, n in sorted([(rng.choice("FX"), rng.randint(0, 3000), f"f{i}") for i in range(rng.randint(1, 4))], key=lambda t: t[2])) + "\n"
    out = subprocess.run([tar_probe], input=spec.encode(), capture_output=True)
    (d / "layer.tar").write_bytes(out.stdout)
    return out.stdout


def skeleton(d):
    (d / "blobs" / "sha256").mkdir(parents=True)


def read_tree(d):
    return {str(p.relative_to(d)): p.read_bytes() for p in sorted(d.rglob("*")) if p.is_file()}


def check_layout(image, layer_bytes, case, tag):
    idx_bytes = (image / "index.json").read_bytes()
    index = json.loads(idx_bytes)
    ok(not list(validator("image-index-schema.json").iter_errors(index)), f"{tag}: index.json is not valid against the OCI schema: {[e.message for e in validator('image-index-schema.json').iter_errors(index)][:2]}")
    ok((image / "oci-layout").read_bytes() == b'{"imageLayoutVersion":"1.0.0"}', f"{tag}: oci-layout differs")
    ok(not list(validator("image-layout-schema.json").iter_errors(json.loads((image / "oci-layout").read_text()))), f"{tag}: oci-layout is not valid")
    blobs = {p.name: p.read_bytes() for p in (image / "blobs" / "sha256").iterdir()}
    mdesc = index["manifests"][0]
    mhex = mdesc["digest"].split(":", 1)[1]
    ok(mhex in blobs and sha(blobs[mhex]) == mhex and len(blobs[mhex]) == mdesc["size"], f"{tag}: the index descriptor does not match the manifest blob")
    manifest = json.loads(blobs[mhex])
    ok(not list(validator("image-manifest-schema.json").iter_errors(manifest)), f"{tag}: manifest is not valid: {[e.message for e in validator('image-manifest-schema.json').iter_errors(manifest)][:2]}")
    chex = manifest["config"]["digest"].split(":", 1)[1]
    lhex = manifest["layers"][0]["digest"].split(":", 1)[1]
    ok(chex in blobs and sha(blobs[chex]) == chex and len(blobs[chex]) == manifest["config"]["size"], f"{tag}: config descriptor does not match its blob")
    ok(lhex in blobs and sha(blobs[lhex]) == lhex and len(blobs[lhex]) == manifest["layers"][0]["size"], f"{tag}: layer descriptor does not match its blob")
    ok(blobs.get(lhex) == layer_bytes, f"{tag}: the stored layer is not the input layer")
    ok(set(blobs) == {mhex, chex, lhex}, f"{tag}: unexpected blobs in the store: {sorted(set(blobs) - {mhex, chex, lhex})}")
    config = json.loads(blobs[chex])
    ok(not list(validator("config-schema.json").iter_errors(config)), f"{tag}: config is not valid: {[e.message for e in validator('config-schema.json').iter_errors(config)][:2]}")
    ok(config["rootfs"]["diff_ids"] == [f"sha256:{sha(layer_bytes)}"], f"{tag}: diff_ids is not the digest of the layer")
    # the independent model, byte for byte
    mc = model_config(case["arch"], case["os_"], case["entry"], case["cmd"], case["env"], case["user"], case["workdir"],
                      case["labels"], case["ports"], f"sha256:{sha(layer_bytes)}")
    ok(blobs[chex] == compact(mc), f"{tag}: config bytes differ from the model:\n  ours  {blobs[chex][:300]!r}\n  model {compact(mc)[:300]!r}")
    mm = model_manifest(f"sha256:{chex}", len(blobs[chex]), f"sha256:{lhex}", len(layer_bytes))
    ok(blobs[mhex] == compact(mm), f"{tag}: manifest bytes differ from the model")
    mi = model_index(f"sha256:{mhex}", len(blobs[mhex]), case["arch"], case["os_"], case["ref"])
    ok(idx_bytes == compact(mi), f"{tag}: index bytes differ from the model")
    return index


def refusal_cases():
    base = dict(arch="arm64", os_="linux", ref="latest", entry="/app", cmd="", env="", user="", workdir="", labels="", ports="")
    def c(**kw):
        d = dict(base)
        d.update(kw)
        return d
    return [
        (c(arch="x86_64"), "image-arch"), (c(arch="arm"), "image-arch"), (c(arch=""), "image-arch"), (c(arch="AMD64"), "image-arch"),
        (c(os_="windows"), "image-os"), (c(os_="Linux"), "image-os"),
        (c(entry="/app\n\n/b"), "image-text"), (c(entry="/a\x01b"), "image-text"), (c(entry="/a\x7fb"), "image-text"), (c(cmd="a\n"), None),
        (c(env="NOEQUALS"), "image-env"), (c(env="=novalue"), "image-env"), (c(env="A=1\nB"), "image-env"),
        (c(labels="nolabel"), "image-label"), (c(labels="=x"), "image-label"),
        (c(labels="k=1\nk=2"), "image-label"), (c(labels="k=1\nk=1"), "image-label"), (c(ports="80/tcp\n80/tcp"), "image-port"),
        (c(ports="80"), "image-port"), (c(ports="80/sctp"), "image-port"), (c(ports="/tcp"), "image-port"), (c(ports="1234567/tcp"), "image-port"), (c(ports="8a/tcp"), "image-port"),
        (c(user="a\nb"), "image-text"), (c(workdir="/a\nb"), "image-text"), (c(user="a\x01"), "image-text"),
        (c(ref="a\nb"), "image-ref"), (c(ref="a\x01"), "image-ref"),
    ]


def tool(cmd, **kw):
    p = subprocess.run(cmd, capture_output=True, text=True, **kw)
    return p.returncode, (p.stdout + p.stderr).strip()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cases", type=int, default=60)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--probe", default=str(ROOT / "build" / "image-probe"))
    ap.add_argument("--tar-probe", default=str(ROOT / "build" / "tar-probe"))
    a = ap.parse_args()
    rng = random.Random(a.seed)
    have_skopeo, have_crane = shutil.which("skopeo"), shutil.which("crane")
    server, registry = None, None
    if have_crane:
        import socket, time
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        server = subprocess.Popen(["crane", "registry", "serve", "--address", f"127.0.0.1:{port}"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(100):
            try:
                socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
                registry = f"127.0.0.1:{port}"
                break
            except OSError:
                time.sleep(0.1)
        if not registry:
            fail("the in-memory registry (crane registry serve) did not start")

    with tempfile.TemporaryDirectory() as t:
        t = Path(t)
        for n in range(a.cases):
            case = random_case(rng)
            work = t / f"c{n}"
            src = work / "src"
            src.mkdir(parents=True)
            layer = make_layer(a.tar_probe, src, rng)
            image = work / "image"
            skeleton(image)
            code, out, err = probe(a.probe, image, src, case)
            if not ok(code == 0, f"case {n}: probe refused {err!r} for {case}"):
                continue
            index = check_layout(image, layer, case, f"case {n}")
            # G1: the same inputs elsewhere give the same bytes
            image2 = work / "again" / "image"
            skeleton(image2)
            code2, _, err2 = probe(a.probe, image2, src, case)
            ok(code2 == 0 and read_tree(image) == read_tree(image2), f"case {n}: building twice gave different bytes")
            # rebuilding in place is idempotent and replaces index.json
            code3, _, _ = probe(a.probe, image, src, case)
            ok(code3 == 0 and read_tree(image) == read_tree(image2), f"case {n}: rebuilding in the same directory changed the layout")
            if n < 6:
                if have_skopeo:
                    ref = case["ref"] or ""
                    target = f"oci:{image}" + (f":{ref}" if ref else "")
                    rc, text = tool(["skopeo", "inspect", "--raw", target])
                    ok(rc == 0, f"case {n}: skopeo refused the layout: {text[:200]}")
                    rc, text = tool(["skopeo", "copy", target, f"dir:{work / 'copy'}"])
                    ok(rc == 0, f"case {n}: skopeo copy (which re-verifies every digest) failed: {text[:200]}")
                if have_crane and registry:
                    ref = f"{registry}/case{n}:t"
                    rc, text = tool(["crane", "push", str(image), ref, "--insecure"])
                    if ok(rc == 0, f"case {n}: crane push of the layout failed: {text[:200]}"):
                        rc, text = tool(["crane", "validate", "--remote", ref, "--insecure"])
                        ok(rc == 0, f"case {n}: crane validate refused the pushed image: {text[:200]}")
                        rc, text = tool(["crane", "digest", ref, "--insecure"])
                        want = index["manifests"][0]["digest"]
                        ok(rc == 0 and text.strip() == want, f"case {n}: the registry's manifest digest {text.strip()!r} is not ours {want!r}")

        # refusals
        work = t / "refusals"
        src = work / "src"
        src.mkdir(parents=True)
        layer = make_layer(a.tar_probe, src, rng)
        for i, (case, tag) in enumerate(refusal_cases()):
            if tag is None:
                continue
            image = work / f"r{i}"
            skeleton(image)
            code, out, err = probe(a.probe, image, src, case)
            ok(code == 1 and tag in err, f"refusal {i} {case}: expected {tag}, got {code} {err!r}")
            ok(not (image / "index.json").exists(), f"refusal {i}: a refused build left an index.json")
        # missing skeleton, missing layer
        code, out, err = probe(a.probe, work / "no-skeleton", src, refusal_cases()[0][0] | {"arch": "arm64"})
        ok(code == 1, f"a missing image directory was not refused: {code} {err!r}")
        (work / "bare").mkdir()
        code, out, err = probe(a.probe, work / "bare", src, refusal_cases()[0][0] | {"arch": "arm64"})
        ok(code == 1 and "layout-skeleton" in err, f"a missing blobs/sha256 was not refused: {code} {err!r}")
        skeleton(work / "nolayer")
        case = dict(arch="arm64", os_="linux", ref="", entry="", cmd="", env="", user="", workdir="", labels="", ports="")
        args = [a.probe, str(work / "nolayer"), str(src), "absent.tar", "arm64", "linux", "", "", "", "", "", "", "", ""]
        p = subprocess.run(args, capture_output=True, text=True)
        ok(p.returncode == 1 and "blob-missing" in p.stderr, f"a missing layer was not refused: {p.returncode} {p.stderr!r}")

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
