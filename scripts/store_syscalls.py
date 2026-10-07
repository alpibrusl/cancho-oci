#!/usr/bin/env python3
"""Durability, observed (design 3, task #4): a `put` must sync the file, publish it with a rename that
cannot replace, and sync the directory, in that order. Linux only, with `strace`; elsewhere it says it was
skipped and exits 0, so it is never mistaken for a pass on a platform it did not run on.

    store_syscalls.py [--probe build/store-probe]
"""
import argparse, re, shutil, subprocess, sys, tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--probe", default=str(ROOT / "build" / "store-probe"))
    a = ap.parse_args()
    if sys.platform != "linux" or not shutil.which("strace"):
        print("SKIPPED: needs Linux and strace (the syscall order was not observed on this platform)")
        return 0
    with tempfile.TemporaryDirectory() as d:
        d = Path(d)
        (d / "store").mkdir()
        (d / "src").mkdir()
        (d / "src" / "f").write_bytes(b"durable\n")
        log = d / "strace.log"
        p = subprocess.run(["strace", "-f", "-o", str(log), "-e", "trace=fsync,fdatasync,rename,renameat,renameat2,unlink,unlinkat,openat",
                            a.probe, "put", str(d / "store"), str(d / "src"), "f"], capture_output=True, text=True)
        if p.returncode != 0 or not p.stdout.startswith("created"):
            print(f"FAIL: put did not succeed under strace: {p.returncode} {p.stdout!r} {p.stderr!r}")
            return 1
        lines = log.read_text().splitlines()
    ops = []
    for line in lines:
        body = re.sub(r"^\d+\s+", "", line)
        if re.match(r"(fsync|fdatasync)\(", body):
            ops.append("fsync")
        elif re.match(r"renameat2\(", body):
            ops.append("renameat2:noreplace" if "RENAME_NOREPLACE" in body else "renameat2:REPLACING")
        elif re.match(r"rename(at)?\(", body):
            ops.append("rename:REPLACING")
    print("observed:", " -> ".join(ops))
    want = ["fsync", "renameat2:noreplace", "fsync"]
    if ops != want:
        print(f"FAIL: expected exactly {' -> '.join(want)}")
        return 1
    print("ok: file synced, published by a rename that cannot replace, then the directory synced")
    return 0


if __name__ == "__main__":
    sys.exit(main())
