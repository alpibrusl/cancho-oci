#!/usr/bin/env python3
"""Differential test of `oci.tar` against independent readers and writers (design 3.1, task #3).

For random archives it checks, in order:
  1. the bytes tar-probe writes are *identical* to what Python's `tarfile` writes in USTAR_FORMAT for
     the same entries (uid = gid = 0, empty names, caller-chosen modes and times);
  2. GNU `tar -tvf` lists exactly those entries;
  3. Python reads every file's data back as the fixed pattern;
  4. the same input twice gives the same bytes (G1, on layers alone);
  5. every refusal case names the rule tag the design promises.

    tar_diff.py [--cases N] [--seed S] [--probe build/tar-probe]

Exit 0 only if every check passes. A mismatch prints the first differing header field.
"""
import argparse, io, random, subprocess, sys, tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MAX_FIELD = 8589934591
DATA_LIMIT = 1_000_000


def pattern(n):
    return bytes((i * 7 + 3) % 251 for i in range(n))


def run_probe(probe, lines):
    p = subprocess.run([probe], input=b"".join(l + b"\n" for l in lines), capture_output=True)
    return p.returncode, p.stdout, p.stderr.decode(errors="replace").strip()


def normalize(head):
    """Make the one Python-version-dependent field the same on every Python: device numbers are zeros.
    Older tarfile writes "0000000\\0" there, newer writes NULs; they mean nothing for files or directories.
    The checksum is recomputed with tarfile's own routine."""
    b = bytearray(head)
    b[329:345] = b"\0" * 16
    b[148:156] = b"        "
    chk = sum(b)
    b[148:156] = b"%06o\0 " % chk
    return bytes(b)


def expected(entries):
    """What Python's tarfile writes for `entries`, or raises ValueError for a name it cannot hold."""
    out = bytearray()
    for kind, size, mtime, path in entries:
        ti = tarfile.TarInfo(path.decode("utf-8"))
        ti.type = tarfile.DIRTYPE if kind == "D" else tarfile.REGTYPE
        ti.size = 0 if kind == "D" else size
        ti.mode = 0o755 if kind in "DX" else 0o644
        ti.mtime = mtime
        ti.uid = ti.gid = 0
        ti.uname = ti.gname = ""
        head = ti.tobuf(tarfile.USTAR_FORMAT, "utf-8", "strict")
        if head[0] == 0:
            # tarfile can hold this name only as prefix = the whole path and an empty name field. That header is
            # legal but readers disagree about it, so oci.tar refuses it (design 5.3): not a mismatch.
            raise ValueError("empty name field")
        out += normalize(head)
        if kind != "D" and size <= DATA_LIMIT:
            out += pattern(size)
            out += b"\0" * ((512 - size % 512) % 512)
    return bytes(out + b"\0" * 1024)


def first_diff(a, b):
    n = min(len(a), len(b))
    for i in range(n):
        if a[i] != b[i]:
            blk, off = divmod(i, 512)
            fields = [(0, 100, "name"), (100, 108, "mode"), (108, 116, "uid"), (116, 124, "gid"), (124, 136, "size"),
                      (136, 148, "mtime"), (148, 156, "chksum"), (156, 157, "typeflag"), (157, 257, "linkname"),
                      (257, 263, "magic"), (263, 265, "version"), (265, 297, "uname"), (297, 329, "gname"),
                      (329, 337, "devmajor"), (337, 345, "devminor"), (345, 500, "prefix"), (500, 512, "pad")]
            name = next((f for lo, hi, f in fields if lo <= off < hi), "?")
            return f"byte {i} (block {blk}, offset {off}, field {name}): ours {a[i]:#04x}, tarfile {b[i]:#04x}"
    return f"lengths differ: ours {len(a)}, tarfile {len(b)}"


CHARS = "abcdefghijklmnopqrstuvwxyz0123456789-_.+ ABCZ"
UNI = ["é", "日", "ß", "😀", "ñ"]


def component(rng, width):
    s = "".join(rng.choice(CHARS) if rng.random() > 0.08 else rng.choice(UNI) for _ in range(width))
    s = s.strip() or "x"
    # "." and ".." are refused names, and a basename starting "._" is AppleDouble metadata to macOS bsdtar, which
    # hides it from `tar -t` (Python and GNU tar list it): neither says anything about oci.tar, so keep them out.
    return "x" + s if s in (".", "..") or s.startswith("._") else s


def random_path(rng):
    """Mostly names that fit (under 100 bytes), some that need the prefix split, a few that fit nowhere."""
    depth = rng.choice([1, 1, 2, 3, 3, 4, 5, 7])
    widths = [rng.choice([1, 2, 3, 5, 8, 12, 20]) for _ in range(depth)]
    roll = rng.random()
    if roll < 0.25:
        widths[rng.randrange(depth)] = rng.choice([30, 45, 60, 80, 99])
    elif roll < 0.30:
        widths[rng.randrange(depth)] = rng.choice([100, 118, 140])
    return "/".join(component(rng, w) for w in widths)


def boundary_paths(rng):
    """Names at the edges of the 100-byte name field and the 155 + 100 split."""
    out = []
    for width in (99, 100, 101, 154, 155, 156):
        out.append("n" * width)
    for prefix in (1, 50, 154, 155, 156):
        for rest in (1, 99, 100, 101):
            out.append("p" * prefix + "/" + "r" * rest)
    out.append("a/" * 40 + "z")          # many components, 81 bytes
    out.append("a/" * 70 + "end")         # 143 bytes: needs a split
    return out


def random_archive(rng, boundary=False):
    """A boundary archive is one entry at an edge of the name field, so a name that fits nowhere refuses
    only itself and does not hide the other entries from the comparison."""
    paths = {rng.choice(boundary_paths(rng))} if boundary else {random_path(rng) for _ in range(rng.randint(1, 12))}
    entries = []
    for p in sorted(paths, key=lambda s: s.encode()):
        kind = rng.choice("FFFXD")
        size = 0 if kind == "D" else rng.choice([0, 1, 7, 511, 512, 513, 1024, rng.randint(0, 3000)])
        mtime = rng.choice([0, 0, 1, 1700000000, rng.randint(0, MAX_FIELD), MAX_FIELD])
        entries.append((kind, size, mtime, p.encode()))
    return entries


def lines_of(entries):
    return [f"{k} {s} {m} ".encode() + p for k, s, m, p in entries]


def refusal_cases():
    """(input lines, expected rule tag). One fault per case."""
    big = MAX_FIELD + 1
    return [
        ([b"F 1 0 /etc/passwd"], "tar-name-absolute"),
        ([b"F 1 0 a//b"], "tar-name-component"),
        ([b"F 1 0 a/./b"], "tar-name-component"),
        ([b"F 1 0 a/../b"], "tar-name-component"),
        ([b"F 1 0 ."], "tar-name-component"),
        ([b"F 1 0 .."], "tar-name-component"),
        ([b"F 1 0 a/"], "tar-name-component"),
        ([b"F 1 0 a\xffb"], "tar-name-not-utf8"),
        ([b"F 1 0 a\xc3"], "tar-name-not-utf8"),
        ([b"F 1 0 a\0b"], "tar-name-nul"),
        ([b"F 1 0 " + b"x" * 300], "tar-name-too-long"),
        ([b"F 1 0 " + b"x" * 156 + b"/y"], "tar-name-too-long"),
        ([b"F 1 0 " + b"x" * 101 + b"/" + b"y" * 101], "tar-name-too-long"),
        ([f"F {big} 0 big".encode()], "tar-size-too-large"),
        ([f"F 1 {big} t".encode()], "tar-time-out-of-range"),
        ([b"D 5 0 dir"], "tar-dir-has-size"),
        ([b"F 1 0 b", b"F 1 0 a"], "tar-order"),
        ([b"F 1 0 a", b"F 1 0 a"], "tar-duplicate"),
        ([b"F 1 0 a", b"D 0 0 a"], "tar-duplicate"),
        ([b"F 1 0 a/b", b"F 1 0 a"], "tar-order"),
    ]


def gnu_tar_check(tar_bytes, entries):
    p = subprocess.run(["tar", "-tvf", "-"], input=tar_bytes, capture_output=True)
    if p.returncode != 0:
        return f"GNU tar refused the archive: {p.stderr.decode(errors='replace').strip()}"
    listed = [l.split(None, 5)[-1] if l else "" for l in p.stdout.decode().splitlines()]
    want = [e[3].decode() + ("/" if e[0] == "D" else "") for e in entries]
    if len(listed) != len(want):
        return f"GNU tar lists {len(listed)} entries, expected {len(want)}"
    for got, w in zip(listed, want):
        if not got.endswith(w):
            return f"GNU tar lists {got!r}, expected {w!r}"
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cases", type=int, default=300)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--probe", default=str(ROOT / "build" / "tar-probe"))
    a = ap.parse_args()
    rng = random.Random(a.seed)
    bad = 0
    compared = 0
    refused_alike = 0

    for n in range(a.cases):
        entries = random_archive(rng, boundary=(n % 3 == 0))
        try:
            want = expected(entries)
        except ValueError:
            want = None
        code, got, err = run_probe(a.probe, lines_of(entries))
        if want is None:
            # tarfile cannot hold the name; we must refuse it with the tag, not write something else.
            if code != 1 or "tar-name-too-long" not in err:
                bad += 1
                print(f"FAIL case {n}: tarfile refuses a name, we answered exit {code} {err!r}")
            else:
                refused_alike += 1
            continue
        if code != 0:
            bad += 1
            print(f"FAIL case {n}: probe refused ({err}) an archive tarfile accepts: {entries[:3]}")
            continue
        compared += 1
        if got != want:
            bad += 1
            print(f"FAIL case {n} (seed {a.seed}): {first_diff(got, want)}")
            continue
        code2, again, _ = run_probe(a.probe, lines_of(entries))
        if again != got:
            bad += 1
            print(f"FAIL case {n}: the same input gave different bytes (G1)")
            continue
        small = [e for e in entries if e[0] != "D" and e[1] <= DATA_LIMIT]
        if len(small) == len([e for e in entries if e[0] != "D"]):
            msg = gnu_tar_check(got, entries)
            if msg:
                bad += 1
                print(f"FAIL case {n}: {msg}")
                continue
            tf = tarfile.open(fileobj=io.BytesIO(got))
            for m in tf:
                if m.isfile() and tf.extractfile(m).read() != pattern(m.size):
                    bad += 1
                    print(f"FAIL case {n}: data of {m.name!r} is not the pattern")
                    break

    for lines, tag in refusal_cases():
        code, out, err = run_probe(a.probe, lines)
        if code != 1 or tag not in err:
            bad += 1
            print(f"FAIL refusal {lines[-1][:40]!r}: expected {tag}, got exit {code} {err!r}")

    total = a.cases
    print(f"{'FAIL' if bad else 'ok'}: {compared}/{total} archives byte-identical to tarfile "
          f"({refused_alike} more refused by both), {len(refusal_cases())} refusal cases, {bad} failure(s)")
    if compared < total * 0.5:
        print(f"FAIL: only {compared}/{total} archives were compared; the generator is not exercising the writer")
        bad += 1
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
