#!/usr/bin/env python3
"""Gate for `oci-sbom` (design 5.8; task #12): a CycloneDX 1.5 bill of materials checked against the official schema and
an independent byte-level model.

  1. every document validates against the vendored CycloneDX 1.5 JSON schema (schemas/cyclonedx-1.5, draft-07, with the
     SPDX and JSF schemas it refers to);
  2. every document equals, byte for byte, the one a Python model builds from the same inputs: hashes from `hashlib`,
     sizes from the files, authority properties from the report, pins from the flags, components in flag order;
  3. the inputs include the real authority reports of every program of this project (`cancho authority --output json`),
     files of 0, 1, 64 KiB-1, 64 KiB, 64 KiB+1 bytes and 5 MiB (streamed), nested paths, 0 to 3 pins;
  4. the same inputs give the same bytes in another directory (no timestamp, no serial number);
  5. refusals, each with its rule tag and **nothing written**: a missing file, a report that is not JSON, lacks a member,
     has a wrong type or is over the cap; an authority report for a path that is not a component; names with spaces,
     quotes, non-ASCII or over 200 bytes; a pin with a short revision, no URL or no name; an unknown flag; `--image` with
     no entry; a missing or bad digest.

    sbom_check.py [--sbom build/oci-sbom]
"""
import argparse, hashlib, json, os, random, subprocess, sys, tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCHEMAS = ROOT / "schemas" / "cyclonedx-1.5"
sys.path.insert(0, str(ROOT / "scripts"))
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


def run(cmd, **kw):
    p = subprocess.run([str(c) for c in cmd], capture_output=True, text=True, **kw)
    return p.returncode, p.stdout.strip(), p.stderr.strip()


_validator = None


def validate(doc):
    global _validator
    if _validator is None:
        from jsonschema import Draft7Validator
        from referencing import Registry, Resource
        from referencing.jsonschema import DRAFT7

        def retrieve(uri):
            return Resource.from_contents(json.loads((SCHEMAS / uri.rsplit("/", 1)[-1]).read_text()), default_specification=DRAFT7)

        _validator = Draft7Validator(json.loads((SCHEMAS / "bom-1.5.schema.json").read_text()), registry=Registry(retrieve=retrieve))
    errors = sorted(_validator.iter_errors(doc), key=lambda e: list(e.path))
    return [f"{'/'.join(map(str, e.path))}: {e.message[:120]}" for e in errors[:3]]


def compact(model):
    return json.dumps(model, separators=(",", ":"), ensure_ascii=False).encode()


def model(name, version, subject, components, deps, reports):
    """The document the tool must write. `components`: [(kind, in_image, bytes)] in flag order."""
    img = {"type": "container", "bom-ref": "image", "name": name}
    if version:
        img["version"] = version
    img["hashes"] = [{"alg": "SHA-256", "content": subject[7:]}]
    img["properties"] = [{"name": "oci:manifest-digest", "value": subject}]
    comps = []
    for kind, in_image, data in components:
        props = [{"name": "oci:size", "value": str(len(data))}]
        rep = reports.get(in_image)
        if rep is not None:
            props.append({"name": "cancho:authority:bounded", "value": "true" if rep["bounded"] else "false"})
            for l in rep["labels"]:
                arg = l.get("argument")
                props.append({"name": "cancho:authority:effect", "value": l["name"] + (f"({arg})" if isinstance(arg, str) and arg else "")})
            for s in rep["foreign_symbols"]:
                props.append({"name": "cancho:authority:foreign-symbol", "value": s})
        comps.append({"type": "application" if kind == "bin" else "file", "bom-ref": "file:" + in_image, "name": in_image,
                      "hashes": [{"alg": "SHA-256", "content": hashlib.sha256(data).hexdigest()}], "properties": props})
    refs = ["file:" + c[1] for c in components]
    for d in deps:
        n, rest = d.split("=", 1)
        url, rev = rest.rsplit("@", 1)
        comps.append({"type": "library", "bom-ref": "dep:" + n, "name": n, "version": rev, "externalReferences": [{"type": "vcs", "url": url}]})
        refs.append("dep:" + n)
    return {"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1, "metadata": {"component": img}, "components": comps,
            "dependencies": [{"ref": "image", "dependsOn": refs}]}


def real_reports():
    import authority_ceiling as A
    out = {}
    for b in A.bins():
        r = subprocess.run(["cancho", "authority", *A.sources(b), "--std", "--output", "json"], capture_output=True, text=True)
        if r.returncode == 0:
            out[b["name"]] = r.stdout
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sbom", default=str(ROOT / "build" / "oci-sbom"))
    ap.add_argument("--seed", type=int, default=1)
    a = ap.parse_args()
    S = a.sbom
    rng = random.Random(a.seed)
    reports_text = real_reports()
    ok(len(reports_text) >= 10, f"only {len(reports_text)} real authority reports could be made")
    with tempfile.TemporaryDirectory() as t:
        t = Path(t)
        root = t / "root"
        root.mkdir()
        sizes = [0, 1, 65535, 65536, 65537, 200000, 5 * 1024 * 1024]
        files = {}
        for i, n in enumerate(sizes):
            data = os.urandom(n)
            rel = f"d{i}/sub/f{i}" if i % 2 else f"f{i}"
            (root / rel).parent.mkdir(parents=True, exist_ok=True)
            (root / rel).write_bytes(data)
            files[rel] = data
        rep_dir = t / "reports"
        rep_dir.mkdir()
        for name, text in reports_text.items():
            (rep_dir / f"{name}.json").write_text(text)
        pins = ["log=https://github.com/alpibrusl/cancho-log@71128de72692427b094429fc729d82435144b2e9",
                "tls=https://github.com/alpibrusl/cancho@25448b8f0d1e1b1d2cd0a1f4d3ef5d6d3da3b0e1",
                "web=https://github.com/alpibrusl/cancho-web@7f261354f74c322cecce9449650899091a2482a5"]
        pins[1] = pins[1][:-1] + "1" if len(pins[1].rsplit("@", 1)[1]) == 40 else pins[1]
        cases = 0
        for n in range(14):
            names = rng.sample(sorted(files), rng.randint(1, 5))
            bins = names[: rng.randint(0, len(names))]
            comps, flags, rmap = [], [], {}
            for k, rel in enumerate(names):
                in_image = ("usr/bin/" if rel in bins else "srv/") + rel.replace("/", "_")
                kind = "bin" if rel in bins else "file"
                comps.append((kind, in_image, files[rel]))
                flags += [f"--{kind}", f"{in_image}:{rel}"]
                if kind == "bin" and rng.random() < 0.8 and reports_text:
                    rn = rng.choice(sorted(reports_text))
                    flags += ["--authority", f"{in_image}={rep_dir / (rn + '.json')}"]
                    rmap[in_image] = json.loads(reports_text[rn])
            deps = rng.sample(pins, rng.randint(0, 3))
            for d in deps:
                flags += ["--dep", d]
            subject = "sha256:" + hashlib.sha256(bytes([n])).hexdigest()
            name = rng.choice(["app", "hooks-server", "a.b_c-d"])
            version = rng.choice(["", "1.2.3", "v0-rc.1"])
            vflags = ["--version", version] if version else []
            out = t / f"out{n}"
            out.mkdir()
            c, o, e = run([S, "--name", name, *vflags, "--image-digest", subject, "--root", root, *flags, "--out-dir", out])
            doc_path = out / f"sha256-{subject[7:]}.sbom.cdx.json"
            if not ok(c == 0 and doc_path.exists(), f"case {n}: refused: {e!r}"):
                continue
            raw = doc_path.read_bytes()
            want = compact(model(name, version, subject, comps, deps, rmap))
            ok(raw == want, f"case {n}: the document is not the model:\n   got  {raw[:300]!r}\n   want {want[:300]!r}")
            errs = validate(json.loads(raw))
            ok(not errs, f"case {n}: schema: {errs}")
            ok(o == f"sbom sha256:{hashlib.sha256(raw).hexdigest()} {doc_path.name}", f"case {n}: printed {o!r}")
            out2 = t / f"out{n}b"
            out2.mkdir()
            c, o2, e = run([S, "--name", name, *vflags, "--image-digest", subject, "--root", root, *flags, "--out-dir", out2])
            ok(c == 0 and (out2 / doc_path.name).read_bytes() == raw, f"case {n}: another directory gave other bytes")
            cases += 1
        ok(cases >= 12, f"only {cases} cases ran")

        # --image: the digest from a layout
        lay = t / "layout"
        (lay / "blobs" / "sha256").mkdir(parents=True)
        subj = "sha256:" + "ab" * 32
        (lay / "index.json").write_text(json.dumps({"schemaVersion": 2, "manifests": [{"digest": subj}]}))
        out = t / "out-image"
        out.mkdir()
        c, o, e = run([S, "--name", "x", "--image", lay, "--root", root, "--file", "a:f0", "--out-dir", out])
        ok(c == 0 and (out / f"sha256-{'ab' * 32}.sbom.cdx.json").exists(), f"--image: {c} {e!r}")

        # ---- refusals
        good = ["--name", "x", "--image-digest", "sha256:" + "cd" * 32, "--root", root, "--file", "a:f0"]
        rout = t / "rout"
        rout.mkdir()

        def refuse(label, args, tag):
            c, o, e = run([S, *args])
            ok(c == 1 and f"refused: {tag}" in e, f"refusal {label}: expected {tag}, got {c} {o!r} {e!r}")
            ok(not list(rout.iterdir()), f"refusal {label}: wrote {list(rout.iterdir())}")

        def with_out(args):
            return [*args, "--out-dir", rout]

        report0 = rep_dir / sorted(reports_text)[0]
        report0 = Path(str(report0) + ".json")
        refuse("an unknown flag", with_out([*good, "--frob", "x"]), "sbom-flag")
        refuse("a trailing flag", with_out([*good, "--dep"]), "sbom-flag")
        refuse("no name", with_out(["--image-digest", "sha256:" + "cd" * 32, "--root", root]), "sbom-missing")
        refuse("no image", with_out(["--name", "x", "--root", root]), "sbom-missing")
        refuse("no root", with_out(["--name", "x", "--image-digest", "sha256:" + "cd" * 32]), "sbom-missing")
        refuse("no out dir", [*good], "sbom-missing")
        refuse("both image forms", with_out([*good, "--image", lay]), "sbom-flag")
        refuse("a bad digest", with_out(["--name", "x", "--image-digest", "sha256:xyz", "--root", root]), "sign-digest")
        refuse("an upper-case digest", with_out(["--name", "x", "--image-digest", "sha256:" + "AB" * 32, "--root", root]), "sign-digest")
        refuse("a layout that is not there", with_out(["--name", "x", "--image", t / "nowhere", "--root", root]), "sbom-image")
        (t / "l2" / "blobs").mkdir(parents=True)
        (t / "l2" / "index.json").write_text('{"schemaVersion":2,"manifests":[]}')
        refuse("a layout with no entry", with_out(["--name", "x", "--image", t / "l2", "--root", root]), "sbom-image")
        refuse("a root that is not there", with_out(["--name", "x", "--image-digest", "sha256:" + "cd" * 32, "--root", t / "nowhere", "--file", "a:f0"]), "sbom-io")
        refuse("a file that is not there", with_out([*good[:-2], "--file", "a:nope"]), "sbom-file")
        refuse("a file below a directory that is not there", with_out([*good[:-2], "--file", "a:nope/f"]), "sbom-file")
        refuse("a path that climbs out of the root", with_out([*good[:-2], "--file", "a:../x"]), "sbom-file")
        refuse("a name with a space", with_out(["--name", "a b", *good[2:]]), "sbom-spec")
        refuse("a name with a quote", with_out(["--name", 'a"b', *good[2:]]), "sbom-spec")
        refuse("a non-ASCII name", with_out(["--name", "café", *good[2:]]), "sbom-spec")
        refuse("a name over 200 bytes", with_out(["--name", "a" * 201, *good[2:]]), "sbom-spec")
        refuse("a version with a space", with_out([*good, "--version", "1 2"]), "sbom-spec")
        refuse("a component spec with no colon", with_out([*good[:-2], "--file", "nocolon"]), "sbom-spec")
        refuse("a component with an empty path", with_out([*good[:-2], "--file", ":f0"]), "sbom-spec")
        refuse("a component path with a space", with_out([*good[:-2], "--file", "a b:f0"]), "sbom-spec")
        for label, dep in [("a short revision", "x=https://h/r@abc"), ("an upper-case revision", "x=https://h/r@" + "AB" * 20), ("no revision", "x=https://h/r"),
                           ("no name", "=https://h/r@" + "ab" * 20), ("no url", "x=@" + "ab" * 20), ("a url with a space", "x=https://h/r s@" + "ab" * 20),
                           ("a long revision", "x=https://h/r@" + "ab" * 21)]:
            refuse(f"a pin with {label}", with_out([*good, "--dep", dep]), "sbom-spec")
        bin_good = [*good[:-2], "--bin", "usr/bin/app:f0"]
        refuse("an authority report for nothing", with_out([*bin_good, "--authority", f"other={report0}"]), "sbom-authority-without-component")
        refuse("an authority flag with no file", with_out([*bin_good, "--authority", "usr/bin/app="]), "sbom-authority-without-component")
        refuse("an authority flag with no path", with_out([*bin_good, "--authority", f"={report0}"]), "sbom-authority-without-component")
        refuse("an authority report that is not there", with_out([*bin_good, "--authority", f"usr/bin/app={t / 'nope.json'}"]), "sbom-authority-report")
        realrep = json.loads(reports_text[sorted(reports_text)[0]])
        for label, content in [("not JSON", "not json"), ("an array", "[]"), ("empty", ""),
                               ("no bounded", json.dumps({k: v for k, v in realrep.items() if k != "bounded"})),
                               ("a string for bounded", json.dumps({**realrep, "bounded": "yes"})),
                               ("no labels", json.dumps({k: v for k, v in realrep.items() if k != "labels"})),
                               ("labels that are not an array", json.dumps({**realrep, "labels": {}})),
                               ("no foreign_symbols", json.dumps({k: v for k, v in realrep.items() if k != "foreign_symbols"})),
                               ("a label without a name", json.dumps({**realrep, "labels": [{"argument": None}]})),
                               ("a label name with a space", json.dumps({**realrep, "labels": [{"name": "a b", "argument": None}]})),
                               ("a foreign symbol with a space", json.dumps({**realrep, "foreign_symbols": ["a b"]})),
                               ("a report past the cap", json.dumps({**realrep, "pad": "x" * 140000}))]:
            f = t / "badreport.json"
            f.write_text(content)
            refuse(f"an authority report that is {label}", with_out([*bin_good, "--authority", f"usr/bin/app={f}"]), "sbom-authority-report" if "cap" not in label else "sbom-authority-report")
        # a report with more nodes than a tape holds is refused, not a crash
        f = t / "bigreport.json"
        f.write_text(json.dumps({**realrep, "functions": list(range(4000))}))
        c, o, e = run([S, *bin_good, "--authority", f"usr/bin/app={f}", "--out-dir", rout])
        ok(c == 1 and "sbom-authority-report" in e and not list(rout.iterdir()), f"a report of 4000 nodes: {c} {e!r}")
        refuse("a nonexistent out dir", [*good, "--out-dir", t / "none"], "sbom-io")
    print(f"{'FAIL' if bad else 'ok'}: {checks} checks, {bad} failure(s)")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
