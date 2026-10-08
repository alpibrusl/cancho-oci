#!/usr/bin/env python3
"""Gate for `oci-ref` (design 5.8; task #12): signatures and SBOMs attached to an image in a registry as OCI artifacts.

Against scripts/mock_registry.py, once with the referrers API and once without it (the fallback tag `sha256-<hex>`, as
`registry:2` is):
  1. the full path: push an image, sign it (`oci-sign`), make its SBOM (`oci-sbom`), attach both, list them (all, and by
     type), fetch them back byte for byte, and verify the fetched signature with `oci-sign verify`;
  2. the artifact manifest the registry holds equals, byte for byte, the one a Python model builds, and validates against the
     OCI image-manifest schema; the config is the empty descriptor `{}`, the layer the file, the subject the image;
  3. attaching the same file twice makes one artifact and one listing; a different file, a second one;
  4. in the fallback, the tag's index holds exactly the descriptors (with `artifactType`); an entry with annotations that this
     tool cannot rewrite is refused and left alone;
  5. refusals with tags and nothing sent: an unreadable, empty or oversized file, a bad type, a bad subject, a subject the
     registry does not have, flags and modes, credentials over plain HTTP to another host; and over https with a Bearer token.

    ref_check.py [--ref build/oci-ref]
"""
import argparse, hashlib, json, os, sys, tempfile, urllib.request
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
SIGN = str(ROOT / "build" / "oci-sign")
SBOM = str(ROOT / "build" / "oci-sbom")
REF = str(ROOT / "build" / "oci-ref")
SIG_TYPE = "application/vnd.cancho.oci.signature.v1+json"
SBOM_TYPE = "application/vnd.cyclonedx+json"
EMPTY = "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"
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


def sha(b):
    return hashlib.sha256(b).hexdigest()


def ref(mock, mode, *args, plain=True, extra=()):
    return R.run([REF, mode, "--registry", mock.addr, "--repo", "r/app", *(["--plain-http"] if plain else []), *args, *extra])


def model_artifact(atype, blob, subject_media, subject_digest, subject_size):
    return IC.compact({"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json", "artifactType": atype,
                       "config": {"mediaType": "application/vnd.oci.empty.v1+json", "digest": EMPTY, "size": 2},
                       "layers": [{"mediaType": atype, "digest": "sha256:" + sha(blob), "size": len(blob)}],
                       "subject": {"mediaType": subject_media, "digest": subject_digest, "size": subject_size}})


def http_get(mock, path):
    ctx = None
    if mock.scheme == "https":
        import ssl
        ctx = ssl._create_unverified_context()
    with urllib.request.urlopen(f"{mock.scheme}://{mock.addr}{path}", context=ctx) as r:
        return r.read()


_validator = None


def manifest_errors(doc):
    global _validator
    if _validator is None:
        from jsonschema import Draft4Validator
        from referencing import Registry, Resource
        from referencing.jsonschema import DRAFT4
        d = ROOT / "schemas" / "oci-image-spec-v1.1.0"

        def retrieve(uri):
            return Resource.from_contents(json.loads((d / uri.rsplit("/", 1)[-1]).read_text()), default_specification=DRAFT4)

        _validator = Draft4Validator(json.loads((d / "image-manifest-schema.json").read_text()), registry=Registry(retrieve=retrieve))
    return [e.message[:100] for e in _validator.iter_errors(doc)][:3]


def main():
    global REF
    ap = argparse.ArgumentParser()
    ap.add_argument("--ref", default=REF)
    a = ap.parse_args()
    REF = a.ref
    with tempfile.TemporaryDirectory() as t:
        t = Path(t)
        image, digests, top = R.make_image(t / "img", ["amd64"], "gzip")
        top_blob = (image / "blobs" / "sha256" / top[7:]).read_bytes()
        seed = t / "seed"
        seed.write_text("07" * 32)
        pubf = t / "pub"
        pubf.write_text(R.run([SIGN, "pubkey", "--seed-file", seed])[1])
        sigdir = t / "sig"
        sigdir.mkdir()
        c, o, e = R.run([SIGN, "sign", "--seed-file", seed, "--image", image, "--out-dir", sigdir])
        ok(c == 0, f"oci-sign: {e}")
        sigfile = next(sigdir.iterdir())
        sig_bytes = sigfile.read_bytes()
        rootdir = t / "sbroot"
        rootdir.mkdir()
        (rootdir / "app").write_bytes(b"program bytes")
        sbomdir = t / "sbom"
        sbomdir.mkdir()
        c, o, e = R.run([SBOM, "--name", "app", "--image", image, "--root", rootdir, "--bin", "usr/bin/app:app", "--out-dir", sbomdir])
        ok(c == 0, f"oci-sbom: {e}")
        sbomfile = next(sbomdir.iterdir())
        sbom_bytes = sbomfile.read_bytes()

        for label, flags in (("with the referrers API", []), ("without it (fallback tag)", ["--no-referrers"])):
            mock = R.Mock(no_referrers=bool(flags))
            try:
                mock.scheme = "http"
                c, o, e = R.push(image, mock.addr, "r/app")
                if not ok(c == 0, f"{label}: push: {e}"):
                    continue
                # nothing attached yet
                c, o, e = ref(mock, "list", "--subject", top)
                ok(c == 0 and o == "", f"{label}: an image with nothing attached lists {o!r} {e!r}")
                # attach the signature and the SBOM
                c, o, e = ref(mock, "attach", "--subject", top, "--type", SIG_TYPE, "--file", sigfile)
                sig_art = o.split()[1] if o.startswith("attached ") else ""
                ok(c == 0 and sig_art.startswith("sha256:") and o == f"attached {sig_art} to {top} as {SIG_TYPE}", f"{label}: attach signature: {c} {o!r} {e!r}")
                c, o, e = ref(mock, "attach", "--subject", top, "--type", SBOM_TYPE, "--file", sbomfile)
                sbom_art = o.split()[1] if o.startswith("attached ") else ""
                ok(c == 0 and sbom_art.startswith("sha256:"), f"{label}: attach SBOM: {c} {o!r} {e!r}")
                # the manifests the registry holds
                for atype, blob, art in ((SIG_TYPE, sig_bytes, sig_art), (SBOM_TYPE, sbom_bytes, sbom_art)):
                    if not art:
                        continue
                    held = http_get(mock, f"/v2/r/app/manifests/{art}")
                    want = model_artifact(atype, blob, "application/vnd.oci.image.manifest.v1+json", top, len(top_blob))
                    ok(held == want and "sha256:" + sha(held) == art, f"{label}: the artifact manifest of {atype} is not the model:\n   got  {held!r}\n   want {want!r}")
                    errs = manifest_errors(json.loads(held))
                    ok(not errs, f"{label}: {atype} manifest fails the OCI schema: {errs}")
                    ok(http_get(mock, f"/v2/r/app/blobs/sha256:{sha(blob)}") == blob, f"{label}: the registry's blob is not the file")
                ok(http_get(mock, f"/v2/r/app/blobs/{EMPTY}") == b"{}", f"{label}: the empty config blob is not '{{}}'")
                # list
                c, o, e = ref(mock, "list", "--subject", top)
                lines = sorted(o.splitlines())
                ok(c == 0 and lines == sorted([f"{sig_art} {SIG_TYPE} {len(model_artifact(SIG_TYPE, sig_bytes, 'application/vnd.oci.image.manifest.v1+json', top, len(top_blob)))}",
                                               f"{sbom_art} {SBOM_TYPE} {len(model_artifact(SBOM_TYPE, sbom_bytes, 'application/vnd.oci.image.manifest.v1+json', top, len(top_blob)))}"]),
                   f"{label}: list: {c} {o!r} {e!r}")
                c, o, e = ref(mock, "list", "--subject", top, "--type", SIG_TYPE)
                ok(c == 0 and len(o.splitlines()) == 1 and o.startswith(sig_art), f"{label}: list by type: {c} {o!r}")
                if not flags:
                    ok(any("referrers/" + top + "?artifactType=application/vnd.cancho.oci.signature.v1%2Bjson" in l for l in mock.state()["log"]), f"{label}: the type filter was not sent to the referrers API")
                c, o, e = ref(mock, "list", "--subject", top, "--type", "application/vnd.nothing")
                ok(c == 0 and o == "", f"{label}: list of a type nobody attached: {o!r}")
                # fetch and verify
                got = t / ("fetched-" + label[:4].strip())
                R.skeleton(got)
                c, o, e = ref(mock, "fetch", "--subject", top, "--type", SIG_TYPE, "--out", got)
                if ok(c == 0 and o == f"{sig_art} sha256:{sha(sig_bytes)}", f"{label}: fetch: {c} {o!r} {e!r}"):
                    fetched = got / "blobs" / "sha256" / sha(sig_bytes)
                    ok(fetched.read_bytes() == sig_bytes, f"{label}: the fetched signature differs")
                    c, o, e = R.run([SIGN, "verify", "--pub-file", pubf, "--image", image, "--sig", fetched])
                    ok(c == 0 and o.startswith("verified " + top), f"{label}: the fetched signature does not verify: {c} {o!r} {e!r}")
                got2 = t / ("fetched2-" + label[:4].strip())
                R.skeleton(got2)
                c, o, e = ref(mock, "fetch", "--subject", top, "--type", SBOM_TYPE, "--out", got2)
                ok(c == 0 and (got2 / "blobs" / "sha256" / sha(sbom_bytes)).read_bytes() == sbom_bytes, f"{label}: the fetched SBOM differs: {c} {o!r} {e!r}")
                # twice: one artifact
                c, o, e = ref(mock, "attach", "--subject", top, "--type", SIG_TYPE, "--file", sigfile)
                ok(c == 0 and sig_art in o, f"{label}: attaching again: {c} {o!r} {e!r}")
                c, o, e = ref(mock, "list", "--subject", top, "--type", SIG_TYPE)
                ok(c == 0 and len(o.splitlines()) == 1, f"{label}: attaching twice listed {len(o.splitlines())} signatures")
                # another signature (another file) is another artifact
                other = t / "other.sig"
                other.write_bytes(sig_bytes + b" ")
                c, o, e = ref(mock, "attach", "--subject", top, "--type", SIG_TYPE, "--file", other)
                c2, o2, e2 = ref(mock, "list", "--subject", top, "--type", SIG_TYPE)
                ok(c == 0 and len(o2.splitlines()) == 2, f"{label}: a second signature: {c} {e!r}; lists {o2!r}")
                if flags:
                    tag = json.loads(http_get(mock, f"/v2/r/app/manifests/sha256-{top[7:]}"))
                    ok(tag.get("mediaType") == "application/vnd.oci.image.index.v1+json" and tag.get("schemaVersion") == 2 and len(tag["manifests"]) == 3
                       and all(set(m) == {"mediaType", "digest", "size", "artifactType"} for m in tag["manifests"]), f"{label}: the fallback index: {tag}")
                else:
                    ok(not [l for l in mock.state()["manifests"].get("r/app", {}) if l.startswith("sha256-")], f"{label}: a fallback tag was written although the registry has the API")
                # a subject the registry does not have, and other refusals (nothing is written by them)
                before = sorted(mock.state()["blobs"])
                nope = "sha256:" + "ee" * 32
                c, o, e = ref(mock, "attach", "--subject", nope, "--type", SIG_TYPE, "--file", sigfile)
                ok(c == 1 and "registry-not-found" in e, f"{label}: a subject that is not there: {c} {e!r}")
                ok(sorted(mock.state()["blobs"]) == before, f"{label}: a refused attach left blobs")
                if flags:
                    # an entry in the fallback index that carries annotations is not rewritten
                    idx = {"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json",
                           "manifests": [{"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": sig_art, "size": 1, "artifactType": SIG_TYPE, "annotations": {"a": "b"}}]}
                    body = json.dumps(idx).encode()
                    urllib.request.urlopen(urllib.request.Request(f"http://{mock.addr}/v2/r/app/manifests/sha256-{top[7:]}", data=body, method="PUT",
                                                                  headers={"Content-Type": "application/vnd.oci.image.index.v1+json"})).read()
                    newfile = t / "new.sig"
                    newfile.write_bytes(b"a new one")
                    c, o, e = ref(mock, "attach", "--subject", top, "--type", SIG_TYPE, "--file", newfile)
                    ok(c == 1 and "registry-referrers-unreadable" in e, f"{label}: an index entry with annotations: {c} {o!r} {e!r}")
                    ok(http_get(mock, f"/v2/r/app/manifests/sha256-{top[7:]}") == body, f"{label}: the index with annotations was changed")
            finally:
                mock.stop()

        # ---- refusals that need no registry state
        mock = R.Mock()
        try:
            def refuse(label, args, tag, mode="attach"):
                c, o, e = ref(mock, mode, *args)
                ok(c == 1 and f"refused: {tag}" in e, f"refusal {label}: expected {tag}, got {c} {o!r} {e!r}")

            before_log = len([l for l in mock.state()["log"] if "_state" not in l])
            refuse("no file", ["--subject", top, "--type", SIG_TYPE], "ref-missing")
            refuse("a file that is not there", ["--subject", top, "--type", SIG_TYPE, "--file", t / "none"], "ref-file")
            empty = t / "empty"
            empty.write_bytes(b"")
            refuse("an empty file", ["--subject", top, "--type", SIG_TYPE, "--file", empty], "ref-file")
            huge = t / "huge"
            huge.write_bytes(b"x" * (8 * 1024 * 1024 + 1))
            refuse("a file over 8 MiB", ["--subject", top, "--type", SIG_TYPE, "--file", huge], "ref-file")
            refuse("a bad type", ["--subject", top, "--type", "not a type", "--file", sigfile], "ref-type")
            refuse("a type with two slashes", ["--subject", top, "--type", "a/b/c", "--file", sigfile], "ref-type")
            refuse("a type with a quote", ["--subject", top, "--type", 'a/"b', "--file", sigfile], "ref-type")
            refuse("a bad subject", ["--subject", "sha256:xyz", "--type", SIG_TYPE, "--file", sigfile], "ref-subject")
            refuse("an upper-case subject", ["--subject", "sha256:" + "AB" * 32, "--type", SIG_TYPE, "--file", sigfile], "ref-subject")
            refuse("no subject", ["--type", SIG_TYPE, "--file", sigfile], "ref-missing")
            refuse("no type", ["--subject", top, "--file", sigfile], "ref-missing")
            refuse("an unknown flag", ["--subject", top, "--frob", "x"], "ref-flag", mode="list")
            refuse("a fetch without --out", ["--subject", top, "--type", SIG_TYPE], "ref-missing", mode="fetch")
            refuse("a fetch into a directory that is not there", ["--subject", top, "--type", SIG_TYPE, "--out", t / "none"], "ref-layout-skeleton", mode="fetch")
            c, o, e = R.run([REF])
            ok(c == 1 and "ref-mode" in e, f"no mode: {c} {e!r}")
            c, o, e = R.run([REF, "frobnicate"])
            ok(c == 1 and "ref-mode" in e, f"an unknown mode: {c} {e!r}")
            c, o, e = R.run([REF, "list", "--registry", "127.0.0.1:1", "--repo", "UPPER", "--subject", top, "--plain-http"])
            ok(c == 1 and "registry-name" in e, f"a bad repository: {c} {e!r}")
            cred = t / "cred"
            cred.write_text("a:b\n")
            c, o, e = R.run([REF, "list", "--registry", "registry.example.com:80", "--repo", "r/app", "--subject", top, "--plain-http", "--basic-file", cred])
            ok(c == 1 and "ref-credentials-over-plain-http" in e, f"credentials over plain HTTP to another host: {c} {e!r}")
            ok(len([l for l in mock.state()["log"] if "_state" not in l]) == before_log, "a refusal before the network sent a request")
        finally:
            mock.stop()


        # ---- a subject that is not a manifest; an artifact with two files; a registry that lies about its index; a wrong digest reported
        mock = R.Mock()
        try:
            c, o, e = R.push(image, mock.addr, "r/app")
            weird = json.dumps({"schemaVersion": 2, "mediaType": "application/x-weird"}).encode()
            urllib.request.urlopen(urllib.request.Request(f"http://{mock.addr}/v2/r/app/manifests/weird", data=weird, method="PUT", headers={"Content-Type": "application/x-weird"})).read()
            c, o, e = ref(mock, "attach", "--subject", "sha256:" + sha(weird), "--type", SIG_TYPE, "--file", sigfile)
            ok(c == 1 and "registry-media-type" in e, f"a subject of an unknown media type: {c} {e!r}")
            two = IC.compact({"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json", "artifactType": SIG_TYPE,
                              "config": {"mediaType": "application/vnd.oci.empty.v1+json", "digest": EMPTY, "size": 2},
                              "layers": [{"mediaType": SIG_TYPE, "digest": "sha256:" + sha(b"a"), "size": 1}, {"mediaType": SIG_TYPE, "digest": "sha256:" + sha(b"b"), "size": 1}],
                              "subject": {"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": top, "size": len(top_blob)}})
            urllib.request.urlopen(urllib.request.Request(f"http://{mock.addr}/v2/r/app/manifests/sha256:{sha(two)}", data=two, method="PUT", headers={"Content-Type": "application/vnd.oci.image.manifest.v1+json"})).read()
            d2 = t / "twofiles"
            R.skeleton(d2)
            c, o, e = ref(mock, "fetch", "--subject", top, "--type", SIG_TYPE, "--out", d2)
            ok(c == 1 and "ref-document" in e and not R.blobs_of(d2), f"an artifact with two files: {c} {o!r} {e!r}")
        finally:
            mock.stop()
        mock = R.Mock(["referrers-forget"])
        try:
            R.push(image, mock.addr, "r/app")
            c, o, e = ref(mock, "attach", "--subject", top, "--type", SIG_TYPE, "--file", sigfile)
            ok(c == 1 and "registry-referrers-unreadable" in e, f"a registry whose index does not list what was pushed: {c} {o!r} {e!r}")
        finally:
            mock.stop()
        mock = R.Mock(["wrong-blob-digest"])
        try:
            urllib.request.urlopen(urllib.request.Request(f"http://{mock.addr}/v2/r/app/manifests/{top}", data=top_blob, method="PUT",
                                                          headers={"Content-Type": "application/vnd.oci.image.manifest.v1+json"})).read()
            c, o, e = ref(mock, "attach", "--subject", top, "--type", SIG_TYPE, "--file", sigfile)
            ok(c == 1 and "registry-digest-mismatch" in e, f"a wrong digest reported for the attached file: {c} {o!r} {e!r}")
        finally:
            mock.stop()

        # ---- a registry that wants a token, over https (push scope for attach)
        pki = R.make_pki(t / "pki")
        if pki:
            mock = R.Mock(bearer=True, tls=pki["good"])
            try:
                c, o, e = R.push(image, mock.addr, "r/app", extra=["--trust-file", pki["ca"]], plain=False)
                ok(c == 0, f"https bearer push: {e}")
                c, o, e = ref(mock, "attach", "--subject", top, "--type", SIG_TYPE, "--file", sigfile, plain=False, extra=["--trust-file", pki["ca"]])
                ok(c == 0 and o.startswith("attached "), f"https bearer attach: {c} {o!r} {e!r}")
                c, o, e = ref(mock, "list", "--subject", top, plain=False, extra=["--trust-file", pki["ca"]])
                ok(c == 0 and len(o.splitlines()) == 1, f"https bearer list: {c} {o!r} {e!r}")
            finally:
                mock.stop()
        else:
            print("note: openssl not installed, the https case was not run")
    print(f"{'FAIL' if bad else 'ok'}: {checks} checks, {bad} failure(s)")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
