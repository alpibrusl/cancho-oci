#!/usr/bin/env python3
"""Mutation gate for `oci.image` (design 2; task #5): break it on purpose and require scripts/image_check.py
(or the unit tests) to notice. A survivor is a behaviour nothing tests.

    image_mutants.py [--cases N]

Each mutant is one textual edit of src/image/image.cho, built into a temporary image-probe. The edit must apply
exactly once. Exit 0 only if every mutant is killed.
"""
import argparse, subprocess, sys, tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = (ROOT / "src/image/image.cho").read_text()

MUTANTS = [
    ("config keys in another order", 'var w1 = json.writer(heap, 512);\n    w1 = json.begin_object(heap, w1);\n    w1 = json.put_key(heap, w1, "architecture");\n    w1 = json.put_string(heap, w1, arch);\n    w1 = json.put_key(heap, w1, "os");',
     'var w1 = json.writer(heap, 512);\n    w1 = json.begin_object(heap, w1);\n    w1 = json.put_key(heap, w1, "os");\n    w1 = json.put_string(heap, w1, os);\n    w1 = json.put_key(heap, w1, "architecture");'),
    ("an unknown architecture accepted", 'digest.equal(arch, "riscv64")', 'digest.equal(arch, "arm")'),
    ("another OS accepted", 'return digest.equal(os, "linux");', 'return digest.equal(os, "linux") || digest.equal(os, "windows");'),
    ("control characters accepted", "if c < 32 || c == 127 {", "if c < 0 || c == 1000 {"),
    ("DEL accepted", "if c < 32 || c == 127 {", "if c < 32 {"),
    ("an env item without a name accepted", "if eq < 1 {\n                return 1;", "if eq < 0 {\n                return 1;"),
    ("an env item without = accepted", "if eq < 1 {\n                return 1;", "if eq < 0 - 1 {\n                return 1;"),
    ("a long port number accepted", "if slash < 1 || slash > 5 {", "if slash < 1 || slash > 9 {"),
    ("any port protocol accepted", 'return digest.equal(proto, "tcp") || digest.equal(proto, "udp");', "return true;"),
    ("a port without digits accepted", "if int_of(item[k]) < '0' || int_of(item[k]) > '9' {", "if int_of(item[k]) < '0' || int_of(item[k]) > 'z' {"),
    ("duplicate keys accepted", "if digest.equal(key, key_of(text[other..other_end], kind)) {", "if false {"),
    ("the user is dropped", 'w1 = json.put_key(heap, w1, "User");', 'w1 = json.put_key(heap, w1, "WorkingDir");'),
    ("the layer and config sizes swapped", "w1 = put_descriptor(heap, w1, layer_media, layer_digest, layer_size);", "w1 = put_descriptor(heap, w1, layer_media, layer_digest, config_size);"),
    ("the ref annotation always written", "    w1 = json.end_object(heap, w1);\n    if len(ref) > 0 {\n        w1 = json.put_key(heap, w1, \"annotations\");", "    w1 = json.end_object(heap, w1);\n    if len(ref) >= 0 {\n        w1 = json.put_key(heap, w1, \"annotations\");"),
    ("the layout marker changed", '{\\"imageLayoutVersion\\":\\"1.0.0\\"}', '{\\"imageLayoutVersion\\":\\"1.0.1\\"}'),
    ("index.json written without replacing", "match dir_rename(dir, tmp, name) {", "match dir_rename_new(dir, tmp, name) {"),
    ("history text changed", 'w1 = json.put_string(heap, w1, "cancho-oci");', 'w1 = json.put_string(heap, w1, "cancho-oci 1");'),
    ("a control character in the ref accepted", "} else if !os_ok(os) {\n        code = refused_os();\n    } else if !plain(ref) {", "} else if !os_ok(os) {\n        code = refused_os();\n    } else if false {"),
    ("a control character in a layout index ref accepted", "    if !digest_ok(index_digest) || index_size < 0 {\n        code = refused_text();\n    } else if !plain(ref) {", "    if !digest_ok(index_digest) || index_size < 0 {\n        code = refused_text();\n    } else if false {"),
    ("a control character in the user accepted", "} else if !plain(user) || !plain(workdir) {", "} else if !plain(workdir) {"),
    ("a control character in the working directory accepted", "} else if !plain(user) || !plain(workdir) {", "} else if !plain(user) {"),
]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cases", type=int, default=30)
    a = ap.parse_args()
    survived, broken = [], []
    with tempfile.TemporaryDirectory() as d:
        d = Path(d)
        for i, (label, old, new) in enumerate(MUTANTS):
            if SRC.count(old) != 1:
                broken.append(f"{label}: anchor found {SRC.count(old)} times, expected once")
                continue
            m = d / f"m{i}"
            m.mkdir()
            (m / "image.cho").write_text(SRC.replace(old, new))
            probe = m / "probe"
            b = subprocess.run(["cancho", "build", str(ROOT / "src/digest/digest.cho"), str(ROOT / "src/store/store.cho"), str(m / "image.cho"),
                                str(ROOT / "tests/probe/image/main.cho"), "--std", "-o", str(probe)], capture_output=True, text=True)
            if b.returncode != 0:
                broken.append(f"{label}: the mutant does not build ({b.stderr.strip()[:140]})")
                continue
            r = subprocess.run([sys.executable, str(ROOT / "scripts/image_check.py"), "--cases", str(a.cases), "--probe", str(probe)], capture_output=True, text=True)
            killed = r.returncode != 0
            if not killed:
                # `layout_index_json` and the index builders are used only by oci-index, whose gate is the one that sees them
                idx = m / "oci-index"
                bx = subprocess.run(["cancho", "build", str(ROOT / "src/digest/digest.cho"), str(ROOT / "src/store/store.cho"), str(m / "image.cho"),
                                     str(ROOT / "src/layout/layout.cho"), str(ROOT / "src/indexcli/main.cho"), "--std", "-o", str(idx)],
                                    capture_output=True, text=True)
                if bx.returncode == 0:
                    rx = subprocess.run([sys.executable, str(ROOT / "scripts/index_check.py"), "--cases", "5", "--index", str(idx)],
                                        capture_output=True, text=True)
                    killed = rx.returncode != 0
            print(f"{'killed  ' if killed else 'SURVIVED'} {label}", flush=True)
            if not killed:
                survived.append(label)
    for line in broken:
        print(f"BROKEN   {line}")
    print(f"{len(MUTANTS) - len(survived) - len(broken)}/{len(MUTANTS)} mutants killed, {len(survived)} survived, {len(broken)} broken")
    return 1 if survived or broken else 0


if __name__ == "__main__":
    sys.exit(main())
