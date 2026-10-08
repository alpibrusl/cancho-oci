#!/usr/bin/env python3
"""Mutation gate for `oci-ref` (design 5.8; task #12): break oci.sign and the CLI on purpose and require
scripts/ref_check.py to notice. A survivor is a behaviour nothing tests.

    sign_mutants.py [--jobs N]

Each mutant is one textual edit of one source file, built into a temporary oci-ref; the edit must apply exactly once.
"""
import subprocess, sys, tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LIBS = ["digest", "store", "image", "layout", "http", "secure", "registry", "sign", "refcli"]
FILES = {"digest": "src/digest/digest.cho", "store": "src/store/store.cho", "image": "src/image/image.cho", "layout": "src/layout/layout.cho",
         "http": "src/http/http.cho", "secure": "src/secure/secure.cho", "registry": "src/registry/registry.cho", "sign": "src/sign/sign.cho",
         "refcli": "src/refcli/main.cho"}

MUTANTS = [
    ("image", "a type with any number of slashes accepted", "    return slashes == 1 &&", "    return slashes > 0 &&"),
    ("image", "the subject left out of the artifact", '    w1 = json.put_key(heap, w1, "subject");\n    w1 = put_descriptor(heap, w1, subject_media, subject_digest, subject_size);\n    w1 = json.end_object(heap, w1);\n    return (json.finish(w1), 0);\n}\n\n// The image config', '    w1 = json.end_object(heap, w1);\n    return (json.finish(w1), 0);\n}\n\n// The image config'),
    ("image", "the artifact type left out of the manifest", '    w1 = json.put_key(heap, w1, "artifactType");\n    w1 = json.put_string(heap, w1, artifact_type);\n    w1 = json.put_key(heap, w1, "config");\n    w1 = put_descriptor(heap, w1, media_empty()', '    w1 = json.put_key(heap, w1, "config");\n    w1 = put_descriptor(heap, w1, media_empty()'),
    ("registry", "a filter not sent to the referrers API", '    if len(filter) > 0 {\n        path = buffer.append(heap, path, "?artifactType=");', '    if false {\n        path = buffer.append(heap, path, "?artifactType=");'),
    ("registry", "a 404 from the referrers API taken for an error", "                    } else if s2 != 404 {", "                    } else {"),
    ("registry", "the fallback tag ignored", "    if code == 0 && !found {\n        // the fallback tag: sha256-<hex>", "    if false {\n        // the fallback tag: sha256-<hex>"),
    ("registry", "the fallback written although the registry has the API", "    if code == 0 && from_api {", "    if false {"),
    ("registry", "an artifact listed twice in the fallback", "        if code == 0 && !present {", "        if code == 0 {"),
    ("registry", "an entry with annotations rewritten", "json.count(tape, entry) != members {", "json.count(tape, entry) < 3 {"),
    ("registry", "the artifact type left out of a fallback entry", '            w1 = json.put_key(heap, w1, "artifactType");\n            w1 = json.put_string(heap, w1, artifact_type);\n            w1 = json.end_object(heap, w1);', '            w1 = json.end_object(heap, w1);'),
    ("registry", "an API listing that lacks the artifact accepted", "        if !there {\n            code = refused_referrers();", "        if false {\n            code = refused_referrers();"),
    ("registry", "the digest reported for a blob uploaded from memory not checked", '"application/octet-stream", bytes);\n            if code != 0 {\n                answer = code;\n            } else {\n                borrow reply as &rr in {\n                    answer = upload_done(rr, digest_text);', '"application/octet-stream", bytes);\n            if code != 0 {\n                answer = code;\n            } else {\n                borrow reply as &rr in {\n                    answer = 0;'),
    ("refcli", "the empty config not uploaded", "                            if code == 0 {\n                                code = registry.blob_upload_bytes(heap, net, eng, now_ms, host, port, auth, repo, image.empty_digest(), \"{}\");\n                            }", "                            if code == 0 {\n                            }"),
    ("refcli", "the artifact not made findable", "                                        if code == 0 {\n                                            code = registry.referrers_register(", "                                        if code == 0 && false {\n                                            code = registry.referrers_register("),
    ("refcli", "a subject that is not a manifest accepted", "                        if !(image.is_manifest(media) || image.is_index(media)) {\n                            code = registry.refused_media();", "                        if false {\n                            code = registry.refused_media();"),
    ("refcli", "an artifact with several files accepted", "json.count(tape, layers) != 1 {\n                            code = rf_document();", "json.count(tape, layers) < 1 {\n                            code = rf_document();"),
    ("refcli", "a file past the cap accepted", "if length <= 0 || length > max_file() {", "if length <= 0 {"),
    ("refcli", "a type filter ignored when listing", "} else if len(atype) == 0 || digest.equal(et, atype) {\n                            io.write_all(io, ed);", "} else {\n                            io.write_all(io, ed);"),
    ("refcli", "the fetch directory not checked first", '    if digest.equal(mode, "fetch") && !skeleton_ok(fs, out_path) {', '    if false {'),
    ("refcli", "credentials over plain HTTP to any host", "    if plain && len(basic_file) > 0 && !registry.is_loopback(host) {", "    if len(basic_file) > 99999 {"),
    ("refcli", "push scope not asked for an attach", 'digest.equal(mode, "attach"));\n                buffer.drop(heap, line);', 'false);\n                buffer.drop(heap, line);'),
]


def build(paths, out):
    deps = sorted(str(p) for p in (ROOT / "build" / "deps").glob("*.cho"))    # the TLS package, installed by `cancho install`
    return subprocess.run(["cancho", "build", *paths, *deps, "--std", "-o", str(out)], capture_output=True, text=True)


def try_mutant(i, sources, tmp):
    which, label, old, new = MUTANTS[i]
    if sources[which].count(old) != 1:
        return label, f"broken: anchor found {sources[which].count(old)} times in {which}, expected once"
    m = tmp / f"m{i}"
    m.mkdir()
    written = []
    for k in LIBS:
        f = m / f"{k}.cho"
        f.write_text(sources[k].replace(old, new) if k == which else sources[k])
        written.append(str(f))
    exe = m / "oci-ref"
    b = build(written, exe)
    if b.returncode != 0:
        return label, f"broken: the mutant does not build ({b.stderr.strip()[:140]})"
    r = subprocess.run([sys.executable, str(ROOT / "scripts/ref_check.py"), "--ref", str(exe)], capture_output=True, text=True)
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
