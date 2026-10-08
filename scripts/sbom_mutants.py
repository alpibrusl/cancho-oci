#!/usr/bin/env python3
"""Mutation gate for `oci-sbom` (design 5.8; task #12): break oci.sign and the CLI on purpose and require
scripts/sbom_check.py to notice. A survivor is a behaviour nothing tests.

    sign_mutants.py [--jobs N]

Each mutant is one textual edit of one source file, built into a temporary oci-sbom; the edit must apply exactly once.
"""
import subprocess, sys, tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LIBS = ["digest", "store", "image", "layout", "place", "sign", "sbom", "sbomcli"]
FILES = {"digest": "src/digest/digest.cho", "store": "src/store/store.cho", "image": "src/image/image.cho", "layout": "src/layout/layout.cho",
         "place": "src/place/place.cho", "sign": "src/sign/sign.cho", "sbom": "src/sbom/sbom.cho", "sbomcli": "src/sbomcli/main.cho"}

MUTANTS = [
    ("sbom", "bounded read as false when true", "if json.kind(tape, bounded) == json.kind_true() {", "if json.kind(tape, bounded) == json.kind_false() {"),
    ("sbom", "the bounded property left out", '                if yes {\n                    w1 = put_property(heap, w1, "cancho:authority:bounded", "true");\n                } else {', '                if yes {\n                } else {'),
    ("sbom", "the effect argument left out", '                        if len(arg) > 0 {\n                            value = buffer.append(heap, value, "(");', '                        if false {\n                            value = buffer.append(heap, value, "(");'),
    ("sbom", "foreign symbols left out", "                while code == 0 && j < json.count(tape, symbols) {", "                while code == 0 && j < 0 {"),
    ("sbom", "effects left out", "                while code == 0 && i < json.count(tape, labels) {", "                while code == 0 && i < 0 {"),
    ("sbom", "a label name not checked", "                    if len(name) == 0 || !plain(name) {", "                    if false {"),
    ("sbom", "a symbol not checked", "                    if !plain(sym) {", "                    if false {"),
    ("sbom", "a report that is not an object accepted", "if json.parse(report, tape) < 0 || !json.is_object(tape, 0) {", "if json.parse(report, tape) < 0 {"),
    ("sbom", "a report without bounded accepted", "if bounded < 0 || !json.is_bool(tape, bounded) ||", "if "),
    ("sbom", "plain accepts a space", "if c <= 32 || c >= 127 || c == '\"' || c == '\\\\' {", "if c < 32 || c >= 127 || c == '\"' || c == '\\\\' {"),
    ("sbom", "plain accepts a quote", "|| c == '\"' || c == '\\\\' {", "|| c == '\\\\' {"),
    ("sbom", "plain accepts a long name", "if len(text) == 0 || len(text) > 200 {", "if len(text) == 0 {"),
    ("sbom", "a file's size miscounted", "                                total = total + n;", "                                total = total + n + 0 * n + 1;"),
    ("sbom", "a file's first chunk skipped", "                                crypto.sha256_update(state, chunk[0..n]);", "                                if total > 0 {\n                                    crypto.sha256_update(state, chunk[0..n]);\n                                }"),
    ("sbomcli", "a pin with a short revision accepted", "|| !hex_ok(rev, 40) {", "|| !hex_ok(rev, 40) && len(rev) < 1 {"),
    ("sbomcli", "the pins left out of the dependencies", '        } else if digest.equal(flag, "--dep") {\n            let eq = split_at(spec, \'=\');\n            var ref', '        } else if false {\n            let eq = split_at(spec, \'=\');\n            var ref'),
    ("sbomcli", "a program typed as a file", 'if is_bin {\n                w1 = json.put_string(heap, w1, "application");', 'if !is_bin {\n                w1 = json.put_string(heap, w1, "application");'),
    ("sbomcli", "an authority report for nothing accepted", "if eq < 1 || eq + 1 >= len(spec) || !found {", "if eq < 1 || eq + 1 >= len(spec) {"),
    ("sbomcli", "both image forms accepted", 'if len(image_path) > 0 && len(image_digest) > 0 {\n        return refuse(io, sb_flag(), "--image and --image-digest are alternatives");', 'if false {\n        return refuse(io, sb_flag(), "--image and --image-digest are alternatives");'),
    ("sbomcli", "a report past the cap accepted", "if n <= 0 || n > sbom.max_report() {", "if n <= 0 {"),
    ("sbomcli", "the version dropped", "    if len(version) > 0 {\n        w1 = json.put_key(heap, w1, \"version\");", "    if false {\n        w1 = json.put_key(heap, w1, \"version\");"),
    ("sbomcli", "the dependencies member dropped", "    if code == 0 {\n        w1 = emit_dependencies(heap, w1, args);\n    }", "    if code != 0 {\n        w1 = emit_dependencies(heap, w1, args);\n    }"),
]


def build(paths, out):
    return subprocess.run(["cancho", "build", *paths, "--std", "-o", str(out)], capture_output=True, text=True)


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
    exe = m / "oci-sbom"
    b = build(written, exe)
    if b.returncode != 0:
        return label, f"broken: the mutant does not build ({b.stderr.strip()[:140]})"
    r = subprocess.run([sys.executable, str(ROOT / "scripts/sbom_check.py"), "--sign", str(exe)], capture_output=True, text=True)
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
