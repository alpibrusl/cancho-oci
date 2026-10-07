#!/usr/bin/env python3
"""Mutation gate for `oci-index`, the layout reader and the index builders (design 2; task #8): break them on
purpose and require scripts/index_check.py to notice. A survivor is a behaviour nothing tests.

    index_mutants.py [--cases N]

Each mutant is one textual edit of one source file, built into a temporary oci-index. The edit must apply exactly
once, so the list cannot rot silently. Exit 0 only if every mutant is killed.
"""
import argparse, subprocess, sys, tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ORDER = ["digest", "store", "image", "layout", "indexcli"]
FILES = {"digest": "src/digest/digest.cho", "store": "src/store/store.cho", "image": "src/image/image.cho",
         "layout": "src/layout/layout.cho", "indexcli": "src/indexcli/main.cho"}

MUTANTS = [
    ("layout", "a blob is not re-hashed when read", "if !digest.equal(raw, expected) {", "if false {"),
    ("layout", "no cap on a document", "if held > cap {", "if false {"),
    ("layout", "a number that does not fit is accepted", "if n < 0 || !json.is_int(tape, n) || !json.fits_int(src, tape, n) {", "if n < 0 || !json.is_int(tape, n) {"),
    ("layout", "a digest with a wrong prefix is accepted", "ok = digest.parse_into(text, scratch) == 0;", "ok = digest.parse_hex_into(text[7..len(text)], scratch) == 0;"),
    ("indexcli", "a repeated platform accepted", "if platforms[k] == platform {", "if false {"),
    ("indexcli", "the manifest media type not checked", '} else if !digest.equal(layout.text_of(src, tape, 0, "mediaType"), image.media_manifest()) || layout.number_of(src, tape, 0, "schemaVersion") != 2 {', '} else if layout.number_of(src, tape, 0, "schemaVersion") != 2 {'),
    ("indexcli", "the schema version not checked", '|| layout.number_of(src, tape, 0, "schemaVersion") != 2 {', '|| false {'),
    ("indexcli", "a manifest without layers accepted", "|| json.count(tape, layers) < 1 {", "|| false {"),
    ("indexcli", "the config size not checked", "if len(csrc) != csize {", "if false {"),
    ("indexcli", "an unsupported architecture accepted", "if !image.arch_ok(arch) {", "if false {"),
    ("indexcli", "an unsupported OS accepted", "} else if !image.os_ok(os) {", "} else if false {"),
    ("indexcli", "a layer size not checked", "} else if actual != lsize {", "} else if false {"),
    ("indexcli", "a layer not verified", "let (vc, actual) = store.verify_sized(heap, blobs, lhex);", "let (vc, actual) = (0, lsize);"),
    ("indexcli", "the order of platforms reversed", "w = image.add_manifest(heap, w, texts[k * 71..k * 71 + 71], sizes[k], arch_name(platforms[k]), \"linux\");", "w = image.add_manifest(heap, w, texts[k * 71..k * 71 + 71], sizes[k], arch_name(platforms[count - 1 - k]), \"linux\");"),
    ("indexcli", "the manifest size not recorded", "size = len(src);", "size = 0;"),
    ("indexcli", "no manifests accepted", "if code == 0 && count == 0 {", "if false {"),
    ("indexcli", "an unknown flag accepted", '} else if !digest.equal(flag, "--manifest") {', '} else if false {'),
    ("indexcli", "arm64 named as amd64", 'if id == 1 {\n        return "arm64";', 'if id == 1 {\n        return "amd64";'),
    ("indexcli", "riscv64 recognised as arm64", 'if digest.equal(arch, "riscv64") {\n        return 2;', 'if digest.equal(arch, "riscv64") {\n        return 1;'),
    ("image", "the ref annotation dropped from the layout index", '    if len(ref) > 0 {\n        w1 = json.put_key(heap, w1, "annotations");\n        w1 = json.begin_object(heap, w1);\n        w1 = json.put_key(heap, w1, "org.opencontainers.image.ref.name");\n        w1 = json.put_string(heap, w1, ref);\n        w1 = json.end_object(heap, w1);\n    }\n    w1 = json.end_object(heap, w1);\n    w1 = json.end_array(heap, w1);\n    w1 = json.end_object(heap, w1);\n    return (json.finish(w1), 0);\n}\n\n// Replace', '    w1 = json.end_object(heap, w1);\n    w1 = json.end_array(heap, w1);\n    w1 = json.end_object(heap, w1);\n    return (json.finish(w1), 0);\n}\n\n// Replace'),
    ("image", "the platform left out of an index entry", '    w1 = json.put_key(heap, w1, "platform");\n    w1 = json.begin_object(heap, w1);\n    w1 = json.put_key(heap, w1, "architecture");\n    w1 = json.put_string(heap, w1, arch);\n    w1 = json.put_key(heap, w1, "os");\n    w1 = json.put_string(heap, w1, os);\n    w1 = json.end_object(heap, w1);\n    return json.end_object(heap, w1);', '    return json.end_object(heap, w1);'),
    ("store", "a layer size miscounted by verify_sized", "                        size = got;", "                        size = got + 0 * got + 1;"),
]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cases", type=int, default=5)
    a = ap.parse_args()
    sources = {k: (ROOT / p).read_text() for k, p in FILES.items()}
    survived, broken = [], []
    with tempfile.TemporaryDirectory() as d:
        d = Path(d)
        for i, (which, label, old, new) in enumerate(MUTANTS):
            if sources[which].count(old) != 1:
                broken.append(f"{label}: anchor found {sources[which].count(old)} times in {which}, expected once")
                continue
            m = d / f"m{i}"
            m.mkdir()
            paths = []
            for k in ORDER:
                f = m / f"{k}.cho"
                f.write_text(sources[k].replace(old, new) if k == which else sources[k])
                paths.append(str(f))
            exe = m / "oci-index"
            b = subprocess.run(["cancho", "build", *paths, "--std", "-o", str(exe)], capture_output=True, text=True)
            if b.returncode != 0:
                broken.append(f"{label}: the mutant does not build ({b.stderr.strip()[:160]})")
                continue
            r = subprocess.run([sys.executable, str(ROOT / "scripts/index_check.py"), "--cases", str(a.cases), "--index", str(exe)], capture_output=True, text=True)
            killed = r.returncode != 0
            if not killed and which == "layout":
                # a helper's own contract (a number that is not exact is -1) may be invisible from the CLI, where a later
                # check also refuses it; its unit test sees it
                u = subprocess.run(["cancho", "test", paths[0], paths[1], paths[3], str(ROOT / "tests/layout_test.cho"), "--std"], capture_output=True, text=True)
                killed = u.returncode != 0
            print(f"{'killed  ' if killed else 'SURVIVED'} {label}", flush=True)
            if not killed:
                survived.append(label)
    for line in broken:
        print(f"BROKEN   {line}")
    print(f"{len(MUTANTS) - len(survived) - len(broken)}/{len(MUTANTS)} mutants killed, {len(survived)} survived, {len(broken)} broken")
    return 1 if survived or broken else 0


if __name__ == "__main__":
    sys.exit(main())
