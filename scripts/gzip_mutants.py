#!/usr/bin/env python3
"""Mutation gate for `oci.gzip` (design 2; task #6): break the encoder on purpose and require
scripts/gzip_check.py to notice. A survivor is a behaviour nothing tests.

    gzip_mutants.py

Each mutant is one textual edit of src/gzip/gzip.cho, built into a temporary gzip-probe. The edit must apply
exactly once, so the list cannot rot silently. Exit 0 only if every mutant is killed.

Not covered, and said so: a change that keeps the stream valid but compresses worse (a shorter hash chain, no
lazy matching) is not a correctness bug and the ratio criterion is loose by design (1.35x or 1% of the input),
so such mutants are not listed; the measured ratios are printed by gzip_check.py instead.
"""
import subprocess, sys, tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = (ROOT / "src/gzip/gzip.cho").read_text()

MUTANTS = [
    ("the CRC polynomial", "c = 0xEDB88320 ^ c >> 1;", "c = 0xEDB88321 ^ c >> 1;"),
    ("the CRC start value", "s[3] = 0xFFFFFFFF;", "s[3] = 0;"),
    ("the CRC final inversion", "let crc = s[3] ^ 0xFFFFFFFF;", "let crc = s[3];"),
    ("the length trailer truncated to 16 bits", "let size = s[4] & 0xFFFFFFFF;", "let size = s[4] & 0xFFFF;"),
    ("the length not counted", "s[4] = s[4] + taken;", "s[4] = s[4] + 0;"),
    ("the OS byte", "o[9] = byte_of(255);", "o[9] = byte_of(3);"),
    ("the gzip magic", "o[1] = byte_of(139);", "o[1] = byte_of(138);"),
    ("the longest length code", "t[28] = 258;", "t[28] = 257;"),
    ("the length code table", "t[i] = t[i - 1] + (1 << len_extra[i - 1]);", "t[i] = t[i - 1] + (1 << (len_extra[i - 1] + 1));"),
    ("the distance extra bits", "t[i] = (i - 2) / 2;", "t[i] = (i - 3) / 2;"),
    ("the window one past 32768", "if d > 32768 {", "if d > 32769 {"),
    ("matches reach beyond the window", "if d > 32768 {", "if d > 40000 {"),
    ("the stored-block fallback off", "if produced > n * 8 + 48 {", "if false {"),
    ("the stored-block length complement", "out[o + 2] = byte_of(65535 - chunk & 255);", "out[o + 2] = byte_of(chunk & 255);"),
    ("the final block flag", "put(s, o, 3, 3);", "put(s, o, 2, 3);"),
    ("the end-of-block symbol", "    // End of block: symbol 256.\n    put_literal(st, out, 256);", "    // End of block: symbol 256.\n"),
    ("the padding before the trailer", "            if s[1] > 0 {\n                put(s, o, 0, 8 - s[1]);\n            }", ""),
    ("bits packed without the shift", "var buf = st[0] | value << st[1];", "var buf = st[0] | value;"),
    ("a literal's Huffman code reversed wrongly", "t[v] = rev(0x30 + v, 8);", "t[v] = 0x30 + v;"),
    ("the distance code not reversed", "put(st, out, rev(di, 5), 5);", "put(st, out, di, 5);"),
    ("the match length limit", "while l < 258 && i + l < n", "while l < 259 && i + l < n"),
    ("the match runs past the block", "while l < 258 && i + l < n", "while l < 258"),
]


def main():
    survived, broken = [], []
    with tempfile.TemporaryDirectory() as d:
        d = Path(d)
        for i, (label, old, new) in enumerate(MUTANTS):
            if SRC.count(old) != 1:
                broken.append(f"{label}: anchor found {SRC.count(old)} times, expected once")
                continue
            m = d / f"m{i}"
            m.mkdir()
            (m / "gzip.cho").write_text(SRC.replace(old, new))
            probe = m / "probe"
            b = subprocess.run(["cancho", "build", str(m / "gzip.cho"), str(ROOT / "tests/probe/gzip/main.cho"), "--std", "-o", str(probe)], capture_output=True, text=True)
            if b.returncode != 0:
                broken.append(f"{label}: the mutant does not build ({b.stderr.strip()[:140]})")
                continue
            r = subprocess.run([sys.executable, str(ROOT / "scripts/gzip_check.py"), "--probe", str(probe), "--quick"], capture_output=True, text=True)
            killed = r.returncode != 0
            print(f"{'killed  ' if killed else 'SURVIVED'} {label}", flush=True)
            if not killed:
                survived.append(label)
    for line in broken:
        print(f"BROKEN   {line}")
    print(f"{len(MUTANTS) - len(survived) - len(broken)}/{len(MUTANTS)} mutants killed, {len(survived)} survived, {len(broken)} broken")
    return 1 if survived or broken else 0


if __name__ == "__main__":
    sys.exit(main())
