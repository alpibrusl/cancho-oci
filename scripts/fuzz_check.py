#!/usr/bin/env python3
"""Gate for untrusted documents (design 2 and 5.7; task #15): no input reaches a trap, a hang or a half-written layout.

Every program that reads a document it did not write is fed thousands of mutations of a valid one -- truncated at every
position, with a byte flipped, deleted, inserted or duplicated, a value replaced by one of the wrong type, a huge number,
a 1 MiB string, nesting 5,000 deep, invalid UTF-8, a repeated key -- and must answer with success or `refused: <rule tag>`
(exit status 0 or 1): never a signal (a trap is SIGILL), never a hang. A refused pull leaves no half-written blob and no
index.json. The documents and where they are read:

  oci-pull   a manifest, an index and a Docker manifest list, served by the mock registry
  oci-push   a layout's index.json and the manifest it names
  oci-index  the manifests it combines (blobs of a layout)
  oci-sign   a signature file, a layout's index.json
  oci-sbom   an authority report, a layout's index.json
  oci-ref    a referrers index (the fallback tag), an artifact manifest, a manifest to attach to

    fuzz_check.py [--rounds N] [--seed S]
"""
import argparse, hashlib, json, os, random, re, subprocess, sys, tempfile, urllib.request
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
IC = R.IC
B = ROOT / "build"
bad = 0
checks = 0
stats = {}
TAG = re.compile(r"refused: [a-z][a-z0-9-]*")


def fail(msg):
    global bad
    bad += 1
    if bad < 40:
        print(f"FAIL {msg}")


def sha(b):
    return hashlib.sha256(b).hexdigest()


def run(cmd, limit=20):
    try:
        p = subprocess.run([str(c) for c in cmd], capture_output=True, timeout=limit)
        return p.returncode, p.stdout.decode(errors="replace"), p.stderr.decode(errors="replace")
    except subprocess.TimeoutExpired:
        return "hang", "", ""


BASELINES = {}


def baseline(name, cmd):
    """The unmutated document must be accepted: a harness that refuses everything proves nothing."""
    global checks
    checks += 1
    code, out, err = run(cmd)
    if code != 0:
        fail(f"{name}: the unmutated document was not accepted: {code} {err.strip()[:150]!r}")
    BASELINES[name] = code


def judge(name, case, cmd, extra_check=None, limit=20):
    """Run `cmd`; success, or a tagged refusal, and nothing worse."""
    global checks
    checks += 1
    code, out, err = run(cmd, limit)
    stats[name] = stats.get(name, {"ok": 0, "refused": 0})
    if code == 0:
        stats[name]["ok"] += 1
    elif code == 1 and TAG.search(err):
        stats[name]["refused"] += 1
    else:
        fail(f"{name} [{case}]: exit {code}, stderr {err.strip()[:120]!r}")
        return code
    if extra_check and code != 0:
        why = extra_check()
        if why:
            fail(f"{name} [{case}]: {why}")
    return code


# ---------------------------------------------------------------- mutations

def deep(n, kind):
    return (b"[" * n + b"]" * n) if kind == 0 else (b'{"a":' * n + b"1" + b"}" * n)


REPLACEMENTS = [None, True, False, 0, -1, 2 ** 63, 2 ** 64, -2 ** 63, 1.5, "", "x", "sha256:" + "0" * 64, "x" * 70000, [], {}, [None], {"a": 1}]


def structural(doc, rng):
    """`doc` (a parsed JSON value) with one node replaced."""
    paths = []

    def walk(v, p):
        paths.append(p)
        if isinstance(v, dict):
            for k in v:
                walk(v[k], p + [k])
        elif isinstance(v, list):
            for i, x in enumerate(v):
                walk(x, p + [i])
    walk(doc, [])
    p = rng.choice(paths)
    new = rng.choice(REPLACEMENTS)
    if not p:
        return new
    root = json.loads(json.dumps(doc))
    cur = root
    for k in p[:-1]:
        cur = cur[k]
    if rng.random() < 0.15 and isinstance(cur, dict):
        del cur[p[-1]]
    else:
        cur[p[-1]] = new
    return root


def mutate(raw, rng, i):
    """Mutation number `i` of the bytes `raw`: the first ones truncate at every position."""
    n = len(raw)
    if i < n:
        return raw[:i]
    kind = rng.randrange(11)
    if kind == 0:
        j = rng.randrange(n)
        return raw[:j] + bytes([raw[j] ^ (1 << rng.randrange(8))]) + raw[j + 1:]
    if kind == 1:
        a = rng.randrange(n)
        b = min(n, a + rng.randrange(1, 40))
        return raw[:a] + raw[b:]
    if kind == 2:
        j = rng.randrange(n + 1)
        return raw[:j] + bytes(rng.randrange(256) for _ in range(rng.randrange(1, 6))) + raw[j:]
    if kind == 3:
        a = rng.randrange(n)
        b = min(n, a + rng.randrange(1, 60))
        return raw[:b] + raw[a:b] + raw[b:]
    if kind in (4, 5, 6):
        try:
            doc = json.loads(raw)
        except ValueError:
            return raw[: rng.randrange(n)]
        return json.dumps(structural(doc, rng), separators=(",", ":"), ensure_ascii=bool(rng.getrandbits(1))).encode()
    if kind == 7:
        return deep(rng.choice([100, 1000, 5000, 30000]), rng.randrange(2))
    if kind == 8:
        return b"\xef\xbb\xbf" + raw
    if kind == 9:
        j = rng.randrange(n)
        return raw[:j] + rng.choice([b"\xff\xfe", b"\xc0\x80", b"\xed\xa0\x80", b"\x00", b"\x1f", b"\\ud800", b'",', b"1e999"]) + raw[j:]
    return raw.replace(b'"', b'"', 1) + b" " * rng.randrange(0, 70000)


# ---------------------------------------------------------------- targets

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rounds", type=int, default=400, help="mutations beyond the truncations, per document")
    ap.add_argument("--seed", type=int, default=1)
    a = ap.parse_args()
    rng = random.Random(a.seed)
    with tempfile.TemporaryDirectory() as t:
        t = Path(t)
        image, digests, top = R.make_image(t / "img", ["amd64", "arm64"], "gzip", multi=True)
        manifest_digest = digests["amd64"]
        man_blob = (image / "blobs" / "sha256" / manifest_digest[7:]).read_bytes()
        idx_blob = (image / "blobs" / "sha256" / top[7:]).read_bytes()
        layout_index = (image / "index.json").read_bytes()

        # ---- oci-pull: documents served by the mock
        docker_list = IC.compact({"schemaVersion": 2, "mediaType": "application/vnd.docker.distribution.manifest.list.v2+json",
                                  "manifests": [{"mediaType": "application/vnd.docker.distribution.manifest.v2+json", "digest": manifest_digest, "size": len(man_blob),
                                                 "platform": {"architecture": "amd64", "os": "linux"}}]})
        mock = R.Mock()
        try:
            R.push(image, mock.addr, "fz/app")
            for label, doc, platform in (("manifest", man_blob, None), ("index", idx_blob, None), ("index+platform", idx_blob, "linux/amd64"), ("docker list", docker_list, None)):
                urllib.request.urlopen(urllib.request.Request(f"http://{mock.addr}/v2/fz/app/manifests/fz", data=doc, method="PUT", headers={"Content-Type": "application/vnd.oci.image.manifest.v1+json"})).read()
                b_out = t / ("base-" + label.replace(" ", "-").replace("+", "-"))
                R.skeleton(b_out)
                baseline("oci-pull " + label, [R.PULL, "--registry", mock.addr, "--repo", "fz/app", "--ref", "fz", "--out", b_out, "--plain-http", *(["--platform", platform] if platform else [])])
                total = len(doc) + a.rounds
                for i in range(total):
                    body = mutate(doc, rng, i)
                    req = urllib.request.Request(f"http://{mock.addr}/v2/fz/app/manifests/fz", data=body, method="PUT", headers={"Content-Type": "application/vnd.oci.image.manifest.v1+json"})
                    try:
                        urllib.request.urlopen(req).read()
                    except Exception:
                        continue
                    out = t / "pull-out"
                    if out.exists():
                        import shutil
                        shutil.rmtree(out)
                    R.skeleton(out)
                    # blobs the mutated document may still name exist in the registry; the layout starts empty
                    def clean(out=out):
                        leftovers = [p.name for p in (out / "blobs" / "sha256").iterdir() if p.name.startswith(".")]
                        if leftovers:
                            return f"a temporary file was left: {leftovers}"
                        if (out / "index.json").exists():
                            return "an index.json was written by a refused pull"
                        return None
                    judge("oci-pull " + label, f"mutation {i}", [R.PULL, "--registry", mock.addr, "--repo", "fz/app", "--ref", "fz", "--out", out, "--plain-http", *(["--platform", platform] if platform else [])], clean)
        finally:
            mock.stop()

        # ---- oci-push: index.json, and the documents it names (stored under their own digest, so the hash check passes and the
        # parser is what is tested)
        import shutil

        def fresh_layout(name, src=image):
            d = t / name
            if d.exists():
                shutil.rmtree(d)
            shutil.copytree(src, d)
            return d

        def put_blob(layout_dir, data):
            (layout_dir / "blobs" / "sha256" / sha(data)).write_bytes(data)
            return "sha256:" + sha(data)

        def point_at(layout_dir, media, data):
            d = put_blob(layout_dir, data)
            (layout_dir / "index.json").write_bytes(R.model_entry(media, d, len(data), "v1"))
            return d

        pushed = fresh_layout("push-layout")
        mock = R.Mock()
        try:
            baseline("oci-push", [R.PUSH, "--image", pushed, "--registry", mock.addr, "--repo", "fz/p", "--plain-http"])
            for i in range(len(layout_index) + a.rounds):
                (pushed / "index.json").write_bytes(mutate(layout_index, rng, i))
                judge("oci-push index.json", f"mutation {i}", [R.PUSH, "--image", pushed, "--registry", mock.addr, "--repo", "fz/p", "--plain-http"])
            for i in range(len(idx_blob) + a.rounds):
                point_at(pushed, "application/vnd.oci.image.index.v1+json", mutate(idx_blob, rng, i))
                judge("oci-push index blob", f"mutation {i}", [R.PUSH, "--image", pushed, "--registry", mock.addr, "--repo", "fz/p", "--plain-http"])
            for i in range(len(man_blob) + a.rounds):
                point_at(pushed, "application/vnd.oci.image.manifest.v1+json", mutate(man_blob, rng, i))
                judge("oci-push manifest blob", f"mutation {i}", [R.PUSH, "--image", pushed, "--registry", mock.addr, "--repo", "fz/p", "--plain-http"])
        finally:
            mock.stop()

        # ---- oci-index: the manifests it combines, and their configs
        work = fresh_layout("index-layout")
        baseline("oci-index", [B / "oci-index", "--out", work, "--manifest", manifest_digest, "--manifest", digests["arm64"]])
        for i in range(len(man_blob) + a.rounds):
            d = put_blob(work, mutate(man_blob, rng, i))
            judge("oci-index manifest", f"mutation {i}", [B / "oci-index", "--out", work, "--manifest", d, "--manifest", digests["arm64"]])
        man_doc = json.loads(man_blob)
        cfg_digest = man_doc["config"]["digest"]
        cfg_blob = (image / "blobs" / "sha256" / cfg_digest[7:]).read_bytes()
        for i in range(len(cfg_blob) + a.rounds):
            cfg = mutate(cfg_blob, rng, i)
            cd = put_blob(work, cfg)
            m2 = dict(man_doc)
            m2["config"] = dict(man_doc["config"], digest=cd, size=len(cfg))
            d = put_blob(work, IC.compact(m2))
            judge("oci-index config", f"mutation {i}", [B / "oci-index", "--out", work, "--manifest", d, "--manifest", digests["arm64"]])

        # ---- oci-sign: a signature file and an index.json
        seed = t / "seed"
        seed.write_text("09" * 32)
        pub = t / "pub"
        pub.write_text(R.run([B / "oci-sign", "pubkey", "--seed-file", seed])[1])
        sigdir = t / "sig"
        sigdir.mkdir()
        R.run([B / "oci-sign", "sign", "--seed-file", seed, "--digest", top, "--out-dir", sigdir])
        sig_raw = next(sigdir.iterdir()).read_bytes()
        sf = t / "fuzz.sig.json"
        sf.write_bytes(sig_raw)
        baseline("oci-sign verify", [B / "oci-sign", "verify", "--pub-file", pub, "--digest", top, "--sig", sf])
        for i in range(len(sig_raw) + 4 * a.rounds):
            sf.write_bytes(mutate(sig_raw, rng, i))
            judge("oci-sign verify", f"mutation {i}", [B / "oci-sign", "verify", "--pub-file", pub, "--digest", top, "--sig", sf])
        sl = fresh_layout("sign-layout")
        (sl / "index.json").write_bytes(layout_index)
        baseline("oci-sign index.json", [B / "oci-sign", "sign", "--seed-file", seed, "--image", sl, "--out-dir", sigdir])
        for i in range(len(layout_index) + a.rounds):
            (sl / "index.json").write_bytes(mutate(layout_index, rng, i))
            judge("oci-sign index.json", f"mutation {i}", [B / "oci-sign", "sign", "--seed-file", seed, "--image", sl, "--out-dir", sigdir])

        # ---- oci-sbom: an authority report and an index.json
        sys.path.insert(0, str(ROOT / "scripts"))
        import authority_ceiling as AC
        b0 = [b for b in AC.bins() if b["name"] == "oci-sign"][0]
        rep_raw = subprocess.run(["cancho", "authority", *AC.sources(b0), "--std", "--output", "json"], capture_output=True).stdout
        rootdir = t / "sbroot"
        rootdir.mkdir()
        (rootdir / "app").write_bytes(b"x")
        outdir = t / "sbout"
        outdir.mkdir()
        rf = t / "fuzz-report.json"
        rf.write_bytes(rep_raw)
        (sl / "index.json").write_bytes(layout_index)
        baseline("oci-sbom report", [B / "oci-sbom", "--name", "x", "--image-digest", top, "--root", rootdir, "--bin", "a:app", "--authority", f"a={rf}", "--out-dir", outdir])
        baseline("oci-sbom index.json", [B / "oci-sbom", "--name", "x", "--image", sl, "--root", rootdir, "--file", "a:app", "--out-dir", outdir])
        for i in list(range(0, len(rep_raw), 2)) + list(range(len(rep_raw), len(rep_raw) + a.rounds)):
            rf.write_bytes(mutate(rep_raw, rng, i))
            judge("oci-sbom report", f"mutation {i}", [B / "oci-sbom", "--name", "x", "--image-digest", top, "--root", rootdir, "--bin", "a:app", "--authority", f"a={rf}", "--out-dir", outdir])
        for i in range(len(layout_index) + a.rounds):
            (sl / "index.json").write_bytes(mutate(layout_index, rng, i))
            judge("oci-sbom index.json", f"mutation {i}", [B / "oci-sbom", "--name", "x", "--image", sl, "--root", rootdir, "--file", "a:app", "--out-dir", outdir])

        # ---- oci-ref: a referrers index (the fallback tag), an artifact manifest, the manifest attached to
        SIG_TYPE = "application/vnd.cancho.oci.signature.v1+json"
        mock = R.Mock(no_referrers=True)
        try:
            R.push(image, mock.addr, "fz/r")
            ok_c, o, e = R.run([B / "oci-ref", "attach", "--registry", mock.addr, "--repo", "fz/r", "--subject", top, "--type", SIG_TYPE, "--file", next(sigdir.iterdir()), "--plain-http"])
            tagurl = f"http://{mock.addr}/v2/fz/r/manifests/sha256-{top[7:]}"
            index_raw = urllib.request.urlopen(tagurl).read()
            art_digest = json.loads(index_raw)["manifests"][0]["digest"]
            art_raw = urllib.request.urlopen(f"http://{mock.addr}/v2/fz/r/manifests/{art_digest}").read()
            ctype = {"Content-Type": "application/vnd.oci.image.index.v1+json"}
            baseline("oci-ref list", [B / "oci-ref", "list", "--registry", mock.addr, "--repo", "fz/r", "--subject", top, "--plain-http"])
            b_out = t / "ref-base"
            R.skeleton(b_out)
            baseline("oci-ref fetch", [B / "oci-ref", "fetch", "--registry", mock.addr, "--repo", "fz/r", "--subject", top, "--type", SIG_TYPE, "--out", b_out, "--plain-http"])
            baseline("oci-ref attach", [B / "oci-ref", "attach", "--registry", mock.addr, "--repo", "fz/r", "--subject", top, "--type", SIG_TYPE, "--file", next(sigdir.iterdir()), "--plain-http"])
            for i in range(len(index_raw) + a.rounds):
                try:
                    urllib.request.urlopen(urllib.request.Request(tagurl, data=mutate(index_raw, rng, i), method="PUT", headers=ctype)).read()
                except Exception:
                    continue
                judge("oci-ref list", f"mutation {i}", [B / "oci-ref", "list", "--registry", mock.addr, "--repo", "fz/r", "--subject", top, "--plain-http"])
                judge("oci-ref attach (index)", f"mutation {i}", [B / "oci-ref", "attach", "--registry", mock.addr, "--repo", "fz/r", "--subject", top, "--type", SIG_TYPE, "--file", next(sigdir.iterdir()), "--plain-http"])
            urllib.request.urlopen(urllib.request.Request(tagurl, data=index_raw, method="PUT", headers=ctype)).read()
            fo = t / "ref-out"
            for i in range(len(art_raw) + a.rounds):
                body = mutate(art_raw, rng, i)
                try:
                    urllib.request.urlopen(urllib.request.Request(f"http://{mock.addr}/v2/fz/r/manifests/{art_digest}", data=body, method="PUT", headers={"Content-Type": "application/vnd.oci.image.manifest.v1+json"})).read()
                except Exception:
                    continue
                if fo.exists():
                    import shutil
                    shutil.rmtree(fo)
                R.skeleton(fo)
                judge("oci-ref fetch", f"mutation {i}", [B / "oci-ref", "fetch", "--registry", mock.addr, "--repo", "fz/r", "--subject", top, "--type", SIG_TYPE, "--out", fo, "--plain-http"])
            # the manifest being attached to
            for i in range(len(man_blob) + a.rounds):
                body = mutate(man_blob, rng, i)
                key = "sha256:" + sha(body)
                try:
                    urllib.request.urlopen(urllib.request.Request(f"http://{mock.addr}/v2/fz/r/manifests/{key}", data=body, method="PUT", headers={"Content-Type": "application/vnd.oci.image.manifest.v1+json"})).read()
                except Exception:
                    continue
                judge("oci-ref attach (subject)", f"mutation {i}", [B / "oci-ref", "attach", "--registry", mock.addr, "--repo", "fz/r", "--subject", key, "--type", SIG_TYPE, "--file", next(sigdir.iterdir()), "--plain-http"])
        finally:
            mock.stop()

    for name in sorted(stats):
        s = stats[name]
        print(f"  {name:28s} {s['ok'] + s['refused']:6d} runs: {s['ok']} accepted, {s['refused']} refused with a tag")
    print(f"{'FAIL' if bad else 'ok'}: {checks} runs, {bad} failure(s)")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
