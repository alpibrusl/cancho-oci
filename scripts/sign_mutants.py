#!/usr/bin/env python3
"""Mutation gate for `oci-sign` (design 5.8; task #12): break oci.sign and the CLI on purpose and require
scripts/sign_check.py to notice. A survivor is a behaviour nothing tests.

    sign_mutants.py [--jobs N]

Each mutant is one textual edit of one source file, built into a temporary oci-sign; the edit must apply exactly once.
"""
import subprocess, sys, tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LIBS = ["digest", "store", "image", "layout", "sign", "signcli"]
FILES = {"digest": "src/digest/digest.cho", "store": "src/store/store.cho", "image": "src/image/image.cho", "layout": "src/layout/layout.cho",
         "sign": "src/sign/sign.cho", "signcli": "src/signcli/main.cho"}

MUTANTS = [
    ("sign", "the domain prefix changed", 'let head = "cancho-oci signature v1\\n";', 'let head = "cancho-oci signature v2\\n";'),
    ("sign", "the newline after the digest dropped from the message", "    out[n] = byte_of('\\n');\n    return 0;", "    out[n] = byte_of(' ');\n    return 0;"),
    ("sign", "the key id not compared", "} else if !digest.equal(keyid, want) {", "} else if false {"),
    ("sign", "the digest named in the file not compared", "} else if !digest.equal(claimed, subject) {", "} else if false {"),
    ("sign", "the signature not verified", "if ed25519.verify(pub_key, msg, sig) != 1 {", "if false {"),
    ("sign", "any number of members accepted", "|| json.count(tape, 0) != 5 {", "|| false {"),
    ("sign", "the type not checked", "} else if !digest.equal(layout.text_of(doc, tape, 0, \"type\"), type_text()) ||", "} else if false ||"),
    ("sign", "the algorithm not checked", "!digest.equal(layout.text_of(doc, tape, 0, \"alg\"), \"ed25519\") {", "false {"),
    ("sign", "upper-case hex accepted", "    if c >= 'a' && c <= 'f' {\n        return c - 'a' + 10;\n    }", "    if c >= 'a' && c <= 'f' {\n        return c - 'a' + 10;\n    }\n    if c >= 'A' && c <= 'F' {\n        return c - 'A' + 10;\n    }"),
    ("sign", "a signature of the wrong length accepted", "    if len(hex) != 2 * len(raw) {\n        return 0 - 1;\n    }", "    if len(hex) < 2 * len(raw) {\n        return 0 - 1;\n    }"),
    ("sign", "a malformed digest accepted for verifying", "    if !digest_ok(subject) {\n        return refused_digest_text();\n    }\n    var code = 0;", "    var code = 0;"),
    ("sign", "a malformed digest accepted for signing", "    if !digest_ok(subject) || len(seed) != 32 {", "    if len(seed) != 32 {"),
    ("sign", "the key id taken from something else", "        crypto.sha256(pub_key, raw);", "        crypto.sha256(pub_key[0..31], raw);"),
    ("signcli", "an image with two entries accepted", "|| json.count(tape, manifests) != 1 {", "|| json.count(tape, manifests) < 1 {"),
    ("signcli", "both --image and --digest accepted", "if len(digest_text) > 0 && len(image_path) > 0 {\n                code = sg_flag();", "if false {\n                code = sg_flag();"),
    ("signcli", "a seed file of the wrong length accepted", "if end == 2 * len(raw) && sign.raw_of_hex(text[0..end], raw) == 0 {", "if sign.raw_of_hex(text[0..end], raw) == 0 || end > 2 * len(raw) {"),
    ("signcli", "a signature file past the cap accepted", "if n <= 0 || n > sign.max_document() {", "if n <= 0 {"),
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
    exe = m / "oci-sign"
    b = build(written, exe)
    if b.returncode != 0:
        return label, f"broken: the mutant does not build ({b.stderr.strip()[:140]})"
    r = subprocess.run([sys.executable, str(ROOT / "scripts/sign_check.py"), "--sign", str(exe)], capture_output=True, text=True)
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
