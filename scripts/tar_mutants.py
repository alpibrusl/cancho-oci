#!/usr/bin/env python3
"""Mutation gate for `oci.tar` (design 2, G1; task #3): break the writer on purpose and require
scripts/tar_diff.py to notice. A mutant that survives means a behaviour nothing tests.

    tar_mutants.py [--cases N]

Each mutant is one textual edit of src/tar/tar.cho, built into a temporary probe with the same program
that the real gate uses. The edit must apply exactly once (a vanished anchor fails loudly, so the list
cannot rot silently when tar.cho changes). Exit 0 only if every mutant is killed.
"""
import argparse, subprocess, sys, tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = (ROOT / "src/tar/tar.cho").read_text()

MUTANTS = [
    ("order reversed in compare", "if p < q {\n            return 0 - 1;", "if p > q {\n            return 0 - 1;"),
    ("duplicate no longer detected", "    if c == 0 {\n        return refused_duplicate();", "    if c == 99 {\n        return refused_duplicate();"),
    ("mtime ignored", "put_octal(out, 136, 11, mtime);", "put_octal(out, 136, 11, 0);"),
    ("size field one digit short", "put_octal(out, 124, 11, size);", "put_octal(out, 124, 10, size);"),
    ("checksum off by one", "put_octal(out, 148, 6, sum);", "put_octal(out, 148, 6, sum + 1);"),
    ("executable bit lost", "if executable || dir {\n        mode = 493;", "if dir {\n        mode = 493;"),
    ("uid leaks", "put_octal(out, 108, 7, 0);", "put_octal(out, 108, 7, 1000);"),
    ("directory not marked", "out[156] = byte_of('5');", "out[156] = byte_of('0');"),
    ("directory slash dropped", "    return '/';\n}\n\n// Where the stored name", "    return 'x';\n}\n\n// Where the stored name"),
    ("prefix limit off by one", "p <= 155", "p <= 154"),
    ("padding always a full block", "return (512 - size % 512) % 512;", "return 512 - size % 512;"),
    ("`..` component allowed", "if width == 2 && int_of(name[start]) == '.' && int_of(name[start + 1]) == '.' {", "if width == 99 && int_of(name[start]) == '.' && int_of(name[start + 1]) == '.' {"),
    ("absolute path allowed", "if int_of(name[0]) == '/' {", "if int_of(name[0]) == 0 - 5 {"),
    ("invalid UTF-8 allowed", "if !utf8.is_valid(name) {", "if utf8.is_valid(name) && false {"),
    ("size ceiling lifted", "if size < 0 || size > max_field() {", "if size < 0 {"),
]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cases", type=int, default=120)
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
            (m / "tar.cho").write_text(SRC.replace(old, new))
            probe = m / "probe"
            b = subprocess.run(["cancho", "build", str(m / "tar.cho"), str(ROOT / "tests/probe/main.cho"), "--std", "-o", str(probe)],
                               capture_output=True, text=True)
            if b.returncode != 0:
                broken.append(f"{label}: the mutant does not build ({b.stderr.strip()[:120]})")
                continue
            r = subprocess.run([sys.executable, str(ROOT / "scripts/tar_diff.py"), "--cases", str(a.cases), "--probe", str(probe)],
                               capture_output=True, text=True)
            killed = r.returncode != 0
            print(f"{'killed  ' if killed else 'SURVIVED'} {label}", flush=True)
            if not killed:
                survived.append(label)
    for line in broken:
        print(f"BROKEN   {line}")
    print(f"{len(MUTANTS) - len(survived) - len(broken)}/{len(MUTANTS)} mutants killed, "
          f"{len(survived)} survived, {len(broken)} broken")
    return 1 if survived or broken else 0


if __name__ == "__main__":
    sys.exit(main())
