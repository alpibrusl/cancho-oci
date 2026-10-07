#!/usr/bin/env python3
"""Mutation gate for `oci-build` (design 2; task #7): break the ELF check, the layer table, the CLI and the
confined open on purpose, and require scripts/build_check.py to notice. A survivor is a behaviour nothing tests.

    build_mutants.py [--cases N]

Each mutant is one textual edit of one source file, built into a temporary oci-build. The edit must apply
exactly once, so the list cannot rot silently. An `oci.elf` mutant is also run against tests/elf_test.cho. Exit 0 only if every mutant is killed.

Not covered, and said so: `layer-source-changed` (a source that changes between measuring and writing) cannot
be provoked from outside, so the size and total checks of `put_file` have no mutants here.
"""
import argparse, subprocess, sys, tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ORDER = ["digest", "tar", "elf", "place", "store", "image", "layer", "build"]
FILES = {"digest": "src/digest/digest.cho", "tar": "src/tar/tar.cho", "elf": "src/elf/elf.cho", "place": "src/place/place.cho",
         "store": "src/store/store.cho", "image": "src/image/image.cho", "layer": "src/layer/layer.cho", "build": "src/build/main.cho"}

MUTANTS = [
    ("elf", "a dynamic executable accepted", "if le(table, i * 56, 4) == 3 {", "if le(table, i * 56, 4) == 99 {"),
    ("elf", "amd64 reported as arm64", 'if m == 62 {\n        return "amd64";', 'if m == 62 {\n        return "arm64";'),
    ("elf", "riscv64 reported as amd64", 'if m == 243 {\n        return "riscv64";', 'if m == 243 {\n        return "amd64";'),
    ("elf", "big-endian ELF accepted", "if int_of(head[4]) != 2 || int_of(head[5]) != 1 || int_of(head[6]) != 1 {", "if int_of(head[4]) != 2 || int_of(head[6]) != 1 {"),
    ("elf", "32-bit ELF accepted", "if int_of(head[4]) != 2 || int_of(head[5]) != 1 || int_of(head[6]) != 1 {", "if int_of(head[5]) != 1 || int_of(head[6]) != 1 {"),
    ("elf", "a relocatable file accepted", "if kind != 2 && kind != 3 {", "if kind != 2 && kind != 3 && kind != 1 {"),
    ("elf", "an unknown machine accepted", "if len(arch_name(head)) == 0 {", "if false {"),
    ("elf", "a wrong program header size accepted", "if le(head, 54, 2) != 56 {", "if false {"),
    ("elf", "an empty program header table accepted", "if n < 1 || n > max_phnum() {", "if n > max_phnum() {"),
    ("elf", "an unbounded program header count", "if n < 1 || n > max_phnum() {", "if n < 1 {"),
    ("elf", "a huge program header offset accepted", "if int_of(buf[at + 7]) != 0 {", "if false {"),
    ("elf", "not-ELF checked after truncation", "    if len(head) < 4 {\n        return refused_short();\n    }\n    if int_of(head[0]) != 127", "    if len(head) < 64 {\n        return refused_short();\n    }\n    if int_of(head[0]) != 127"),
    ("layer", "entries sorted backwards", "tar.compare(name_of(names, meta, j - 1), name_of(names, meta, j)) > 0", "tar.compare(name_of(names, meta, j - 1), name_of(names, meta, j)) < 0"),
    ("layer", "parent directories not added", "if int_of(dest[j]) == '/' {", "if int_of(dest[j]) == 0 {"),
    ("layer", "executables lose their mode", "if is_bin {\n                exec = 1;", "if is_bin {\n                exec = 0;"),
    ("layer", "binaries not inspected", "} else if meta[e * 6 + 3] == 1 {\n                            code = inspect(f, arch);", "} else if false {\n                            code = inspect(f, arch);"),
    ("layer", "duplicates accepted", "state[2] = e;\n            return refused_duplicate();", "return 0;"),
    ("layer", "file padding dropped", "let pad = tar.padding(size);", "let pad = 0;"),
    ("layer", "the end-of-archive blocks short by one", "let (last, errno2) = store.write(next, contents(zr));\n                    blob = last;\n                    written = written + 1024;\n                    if errno != 0 || errno2 != 0 {", "blob = next;\n                    written = written + 1024;\n                    if errno != 0 {"),
    ("layer", "the time ignored in headers", "kind, meta[e * 6 + 5], meta[e * 6 + 3] == 1, mtime);\n                    if code == 0 {\n                        let (next, errno) = store.write(blob, contents(hw));", "kind, meta[e * 6 + 5], meta[e * 6 + 3] == 1, 0);\n                    if code == 0 {\n                        let (next, errno) = store.write(blob, contents(hw));"),
    ("layer", "source and destination swapped", "return spec[0..split_at(spec)];", "return spec[split_at(spec) + 1..len(spec)];"),
    ("layer", "an empty destination accepted", "if k < 1 || k >= len(spec) - 1 {", "if k < 1 {"),
    ("layer", "no limit on entries", "if count >= max_entries() {", "if count >= 100000 {"),
    ("layer", "the first of two same-named entries wins silently", "if meta[e * 6 + 2] == 1 && kind == 1 {\n                return 0;", "if meta[e * 6 + 2] == 1 {\n                return 0;"),
    ("place", "nested paths not walked", "let k = index_of_byte(rel, byte_of('/'));\n    if k < 0 {", "let k = index_of_byte(rel, byte_of('/'));\n    if true {"),
    ("build", "no default entrypoint", "        if no_entrypoint {", "        if false {"),
    ("build", "the epoch ignored", "mtime = number(epoch);", "mtime = 0;"),
    ("build", "the platform architecture not checked first", "} else if !image.arch_ok(platform[slash + 1..len(platform)]) {\n        status = refuse(io, image.refused_arch(), platform);", "} else if false {\n        status = refuse(io, image.refused_arch(), platform);"),
    ("build", "the platform OS not checked first", "} else if !image.os_ok(platform[0..slash]) {\n        status = refuse(io, image.refused_os(), platform);", "} else if false {\n        status = refuse(io, image.refused_os(), platform);"),
    ("build", "unknown flags accepted", '} else if !digest.equal(flag, "--bin") && !digest.equal(flag, "--file") {\n                bad = flag;', '} else if false {\n                bad = flag;'),
    ("build", "a bad epoch accepted", "} else if mtime < 0 {\n        status = refuse(io, build_epoch(), epoch);", "} else if false {\n        status = refuse(io, build_epoch(), epoch);"),
]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cases", type=int, default=9)
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
            exe = m / "oci-build"
            b = subprocess.run(["cancho", "build", *paths, "--std", "-o", str(exe)], capture_output=True, text=True)
            if b.returncode != 0:
                broken.append(f"{label}: the mutant does not build ({b.stderr.strip()[:160]})")
                continue
            r = subprocess.run([sys.executable, str(ROOT / "scripts/build_check.py"), "--cases", str(a.cases), "--build", str(exe)], capture_output=True, text=True)
            killed = r.returncode != 0
            if not killed and which == "elf":
                # A bound that is also enforced downstream is invisible from outside; its unit test sees it.
                u = subprocess.run(["cancho", "test", paths[2], str(ROOT / "tests/elf_test.cho"), "--std"], capture_output=True, text=True)
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
