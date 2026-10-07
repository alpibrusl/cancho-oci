#!/usr/bin/env python3
"""Mutation gate for `oci.digest` and `oci.store` (design 2; task #4): break them on purpose and require
scripts/store_diff.py to notice. A survivor is a behaviour nothing tests.

    store_mutants.py

Each mutant is one textual edit of one source file, built into a temporary store-probe. The edit must apply
exactly once, so the list cannot rot silently when a source changes. A digest mutant is also run against
tests/digest_test.cho: it is killed if either the store gate or the unit tests fail. A store mutant is also
run through scripts/image_check.py (a manifest records the sizes the store reports) and scripts/index_check.py
(oci-index verifies layers with `verify_sized`). Exit 0 only if every
mutant is killed.

Not covered, and said so: a failing fsync or a failing write cannot be provoked from outside, so the
`!synced` and write-error branches of `oci.store` are untested here (they need fault injection).
"""
import subprocess, sys, tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FILES = {"digest": ROOT / "src/digest/digest.cho", "store": ROOT / "src/store/store.cho"}

MUTANTS = [
    ("store", "a rename that replaces: a blob is rewritten", "match dir_rename_new(root, tmp, name) {", "match dir_rename(root, tmp, name) {"),
    ("store", "the duplicate's temporary is left behind", "                if e == eexist() {\n                    dir_remove(root, tmp);\n                    outcome = existed();", "                if e == eexist() {\n                    outcome = existed();"),
    ("store", "a stale temporary is not removed", "                dir_remove(root, tmp);\n            }\n        }\n        attempt = attempt + 1;", "            }\n        }\n        attempt = attempt + 1;"),
    ("store", "verify never compares", "} else if !digest.equal(raw, expected) {\n                        want = refused_mismatch();\n                    }\n                }\n            }\n        }\n    }\n    return want;", "} else if false {\n                        want = refused_mismatch();\n                    }\n                }\n            }\n        }\n    }\n    return want;"),
    ("store", "verify_sized never compares", "} else if !digest.equal(raw, expected) {\n                        want = refused_mismatch();\n                    } else {\n                        size = got;", "} else if false {\n                        want = refused_mismatch();\n                    } else {\n                        size = got;"),
    ("store", "a missing blob is not reported by verify", "pub fn verify[&h, &d, &n](heap: &!h Heap, root: &d Dir, hex: &n [byte]) -> [heap, dir_read, file_read] int {\n    var want = 0;\n    region a {\n        let expected = alloc_slice[a](32, byte_of(0));\n        want = digest.parse_hex_into(hex, expected);\n        if want == 0 {\n            match dir_open_read(root, hex) {\n                Opened::Failed(errno) => {\n                    want = refused_missing();", "pub fn verify[&h, &d, &n](heap: &!h Heap, root: &d Dir, hex: &n [byte]) -> [heap, dir_read, file_read] int {\n    var want = 0;\n    region a {\n        let expected = alloc_slice[a](32, byte_of(0));\n        want = digest.parse_hex_into(hex, expected);\n        if want == 0 {\n            match dir_open_read(root, hex) {\n                Opened::Failed(errno) => {\n                    want = 0;"),
    ("store", "a missing blob is not reported by verify_sized", "pub fn verify_sized[&h, &d, &n](heap: &!h Heap, root: &d Dir, hex: &n [byte]) -> [heap, dir_read, file_read] (int, int) {\n    var want = 0;\n    var size = 0;\n    region a {\n        let expected = alloc_slice[a](32, byte_of(0));\n        want = digest.parse_hex_into(hex, expected);\n        if want == 0 {\n            match dir_open_read(root, hex) {\n                Opened::Failed(errno) => {\n                    want = refused_missing();", "pub fn verify_sized[&h, &d, &n](heap: &!h Heap, root: &d Dir, hex: &n [byte]) -> [heap, dir_read, file_read] (int, int) {\n    var want = 0;\n    var size = 0;\n    region a {\n        let expected = alloc_slice[a](32, byte_of(0));\n        want = digest.parse_hex_into(hex, expected);\n        if want == 0 {\n            match dir_open_read(root, hex) {\n                Opened::Failed(errno) => {\n                    want = 0;"),
    ("store", "hash size miscounted", "crypto.sha256_update(contents(s), room[0..n]);\n                    }\n                    total = total + n;", "crypto.sha256_update(contents(s), room[0..n]);\n                    }\n                    total = total + 1;"),
    ("store", "streamed size miscounted (it goes into a manifest)", "total = total + n;\n                            if errno != 0 {", "total = total + 1;\n                            if errno != 0 {"),
    ("store", "the last byte of each read is not hashed", "crypto.sha256_update(contents(s), room[0..n]);", "crypto.sha256_update(contents(s), room[0..n - 1]);"),
    ("store", "the write is not hashed", "        borrow mut state as &!s in {\n            crypto.sha256_update(contents(s), bytes);\n        }", "        borrow mut state as &!s in {\n            crypto.sha256_update(contents(s), bytes[0..0]);\n        }"),
    ("digest", "hex written in upper case", "return 'a' + n - 10;", "return 'A' + n - 10;"),
    ("digest", "upper case accepted when parsing", "if c >= 'a' && c <= 'f' {", "if c >= 'A' && c <= 'f' {"),
    ("digest", "a long hex string accepted", "if len(hex) != 64 {", "if len(hex) < 64 {"),
    ("digest", "a non-hex digit accepted", "if nibble(int_of(hex[i])) < 0 {", "if nibble(int_of(hex[i])) < 0 - 1 {"),
    ("digest", "another algorithm accepted", "if text[i] != prefix[i] {", "if false {"),
]


def main():
    sources = {k: p.read_text() for k, p in FILES.items()}
    survived, broken = [], []
    with tempfile.TemporaryDirectory() as d:
        d = Path(d)
        for i, (which, label, old, new) in enumerate(MUTANTS):
            if sources[which].count(old) != 1:
                broken.append(f"{label}: anchor found {sources[which].count(old)} times in {which}.cho, expected once")
                continue
            m = d / f"m{i}"
            m.mkdir()
            paths = {}
            for k, text in sources.items():
                paths[k] = m / f"{k}.cho"
                paths[k].write_text(text.replace(old, new) if k == which else text)
            probe = m / "probe"
            b = subprocess.run(["cancho", "build", str(paths["digest"]), str(paths["store"]),
                                str(ROOT / "tests/probe/store/main.cho"), "--std", "-o", str(probe)], capture_output=True, text=True)
            if b.returncode != 0:
                broken.append(f"{label}: the mutant does not build ({b.stderr.strip()[:140]})")
                continue
            r = subprocess.run([sys.executable, str(ROOT / "scripts/store_diff.py"), "--probe", str(probe)], capture_output=True, text=True)
            killed = r.returncode != 0
            if not killed and which == "store":
                # The image gate also depends on the store (a manifest records each blob's size), so a store
                # mutant may be caught there rather than here.
                img = m / "image-probe"
                bi = subprocess.run(["cancho", "build", str(paths["digest"]), str(paths["store"]), str(ROOT / "src/image/image.cho"),
                                     str(ROOT / "tests/probe/image/main.cho"), "--std", "-o", str(img)], capture_output=True, text=True)
                if bi.returncode == 0:
                    ri = subprocess.run([sys.executable, str(ROOT / "scripts/image_check.py"), "--cases", "12", "--probe", str(img)],
                                        capture_output=True, text=True)
                    killed = ri.returncode != 0
            if not killed and which == "store":
                # `verify_sized` is used by oci-index, whose gate is the one that can see it
                idx = m / "oci-index"
                bx = subprocess.run(["cancho", "build", str(paths["digest"]), str(paths["store"]), str(ROOT / "src/image/image.cho"),
                                     str(ROOT / "src/layout/layout.cho"), str(ROOT / "src/indexcli/main.cho"), "--std", "-o", str(idx)],
                                    capture_output=True, text=True)
                if bx.returncode == 0:
                    rx = subprocess.run([sys.executable, str(ROOT / "scripts/index_check.py"), "--cases", "5", "--index", str(idx)],
                                        capture_output=True, text=True)
                    killed = rx.returncode != 0
            if not killed and which == "digest":
                t = subprocess.run(["cancho", "test", str(paths["digest"]), str(ROOT / "tests/digest_test.cho"), "--std"],
                                   capture_output=True, text=True)
                killed = t.returncode != 0
            print(f"{'killed  ' if killed else 'SURVIVED'} {label}", flush=True)
            if not killed:
                survived.append(label)
    for line in broken:
        print(f"BROKEN   {line}")
    print(f"{len(MUTANTS) - len(survived) - len(broken)}/{len(MUTANTS)} mutants killed, {len(survived)} survived, {len(broken)} broken")
    return 1 if survived or broken else 0


if __name__ == "__main__":
    sys.exit(main())
