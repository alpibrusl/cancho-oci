#!/usr/bin/env python3
"""Gate for `oci.gzip` (design 2, 3 and 5.6; task #6): a deterministic gzip encoder checked against independent decoders.

For a corpus of inputs it checks:
  1. the stream decodes, to exactly the input, with Python's `gzip`, Python's `zlib` (wbits=31), and the system
     `gzip -dc`; its trailer is the input's CRC-32 and length; its header is the fixed 10 bytes (no time, no name,
     OS 255), so it carries nothing about the machine;
  2. the same input gives the same bytes on a second run, and **whatever size the input is offered in** (1 byte,
     7, 4096, 65536 at a time): the output is a function of the data, not of how it was fed;
  3. incompressible data costs at most 0.1% + 64 bytes (stored blocks); compressible data at most 1.35x what
     zlib level 9 makes of it, or at most 1% of the input size more (for highly repetitive data, where a large
     ratio of two small numbers means little); the loss against the best common encoder is printed, never hidden;
  4. edge inputs: lengths around the 64 KiB block, matches exactly at the 32768-byte window edge and one past
     it, a 258-byte maximum-length match, and runs.

    gzip_check.py [--probe build/gzip-probe] [--seed S] [--big-mib N]
"""
import argparse, gzip, os, random, shutil, subprocess, sys, zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
bad = 0
checks = 0
rows = []


def fail(msg):
    global bad
    bad += 1
    print(f"FAIL {msg}")


def ok(cond, msg):
    global checks
    checks += 1
    if not cond:
        fail(msg)
    return bool(cond)


def run(probe, data, step=None):
    args = [probe] + ([str(step)] if step else [])
    p = subprocess.run(args, input=data, capture_output=True)
    return p.returncode, p.stdout


HEADER = bytes([0x1F, 0x8B, 0x08, 0, 0, 0, 0, 0, 0, 0xFF])


def check_stream(name, data, out):
    """Decode with three independent decoders and check the framing."""
    ok(out[:10] == HEADER, f"{name}: the gzip header is not the fixed 10 bytes: {out[:10].hex()}")
    try:
        ok(gzip.decompress(out) == data, f"{name}: Python gzip decoded something other than the input")
    except Exception as e:
        ok(False, f"{name}: Python gzip refused the stream: {e}")
        return False
    try:
        d = zlib.decompressobj(31)
        ok(d.decompress(out) + d.flush() == data and d.eof and not d.unused_data, f"{name}: zlib (wbits=31) decoded something else, stopped early or found trailing bytes")
    except Exception as e:
        ok(False, f"{name}: zlib refused the stream: {e}")
        return False
    crc = zlib.crc32(data) & 0xFFFFFFFF
    ok(out[-8:-4] == crc.to_bytes(4, "little") and out[-4:] == (len(data) & 0xFFFFFFFF).to_bytes(4, "little"),
       f"{name}: the trailer is not the CRC-32 and length of the input")
    if shutil.which("gzip"):
        p = subprocess.run(["gzip", "-dc"], input=out, capture_output=True)
        ok(p.returncode == 0 and p.stdout == data, f"{name}: system gzip refused or changed it (exit {p.returncode}) {p.stderr[:80]!r}")
    return True


def corpus(rng, big_mib):
    text = (ROOT / "docs" / "design.md").read_bytes()
    elf_like = b"".join(rng.choice([b"\x00" * rng.randint(1, 40), os.urandom(rng.randint(1, 20)), b"\x48\x89\xe5\x48\x83\xec\x10"]) for _ in range(4000))
    items = [("empty", b""), ("1 byte", b"a")]
    items += [(f"random {n}", os.urandom(n)) for n in (2, 3, 4, 17, 255, 256, 1000)]
    items += [(f"len {n} text", text[:n]) for n in (5, 100, 4095, 4096, 4097, 20000)]
    # around the 64 KiB block: where one block ends and the next begins
    for n in (65534, 65535, 65536, 65537, 65538, 131071, 131072, 131073):
        items.append((f"text {n}", (text * 8)[:n]))
        items.append((f"random {n}", os.urandom(n)))
    items += [("zeros 1 MiB", bytes(1 << 20)), ("elf-like", elf_like), ("text x40", text * 40)]
    # matches at the window edge: the same 300 bytes repeated at distance exactly 32768 and one more
    # The filler uses byte values below 128 only, which cost eight bits each in the fixed code, so the block stays
    # compressed (not stored) and the encoder's match search actually runs at the window edge. With uniformly random
    # bytes the encoder rightly stores the block and this case would test nothing.
    low = lambda n: bytes(rng.randrange(128) for _ in range(n))
    pat = low(300)
    for gap in (32768, 32769, 32767, 300, 258, 259):
        items.append((f"repeat at distance {gap}", pat + low(max(gap - 300, 0)) + pat))
    items.append(("max-length match 258", b"x" + b"ab" * 129 + b"y" + b"ab" * 129 + b"z"))
    items.append(("run of 1000 'a'", b"a" * 1000))
    items.append(("run of 258 then 3", b"a" * 258 + b"b" + b"a" * 3))
    items.append(("every byte value", bytes(range(256)) * 300))
    if big_mib:
        items.append((f"{big_mib} MiB text+random", (text * 300)[: (big_mib << 20) // 2] + os.urandom((big_mib << 20) // 2)))
    return items


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--probe", default=str(ROOT / "build" / "gzip-probe"))
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--big-mib", type=int, default=0)
    ap.add_argument("--quick", action="store_true", help="every edge case, but not the largest inputs or every chunk size (for the mutation gate)")
    a = ap.parse_args()
    rng = random.Random(a.seed)
    worst = 0.0
    for name, data in corpus(rng, a.big_mib):
        if a.quick and len(data) > 200000 and not name.startswith("text 131"):
            continue
        code, out = run(a.probe, data)
        if not ok(code == 0, f"{name}: the probe failed (exit {code})"):
            continue
        if not check_stream(name, data, out):
            continue
        z9 = len(zlib.compress(data, 9)) + 12      # gzip framing is zlib's + 12 bytes
        incompressible = len(data) > 2000 and len(zlib.compress(data, 9)) > 0.98 * len(data)
        if incompressible:
            ok(len(out) <= len(data) * 1.001 + 64, f"{name}: incompressible input grew from {len(data)} to {len(out)}")
        elif len(data) > 2000:
            ratio = len(out) / z9
            worst = max(worst, ratio) if len(out) - z9 > 0.01 * len(data) else worst
            # The criterion, stated: within 1.35x of zlib -9, OR no more than 1% of the input size larger. The second
            # clause is for highly repetitive data (a run of zeros, a repeating cycle), where the fixed code spends
            # ~13 bits per 258-byte match that a dynamic code spends 2 on: a large ratio of two small numbers.
            ok(ratio <= 1.35 or len(out) - z9 <= 0.01 * len(data), f"{name}: {len(out)} bytes is {ratio:.2f}x what zlib -9 makes ({z9}), {len(out) - z9} more")
            rows.append((name, len(data), len(out), z9, ratio))
        if name.startswith("repeat at distance"):
            gap = int(name.rsplit(" ", 1)[1])
            # the repeat must have been used when it is within the window, and must not be used (it cannot be
            # encoded) one byte beyond: the compressed size shows which
            saved = len(data) - len(out)
            if gap <= 32768:
                ok(saved > 150, f"{name}: the repeat inside the window was not used (saved {saved} bytes)")
            else:
                ok(saved < 150, f"{name}: a match beyond the 32768-byte window was used (saved {saved} bytes)")
        # determinism, and independence from how the data is offered
        code2, out2 = run(a.probe, data)
        ok(out2 == out, f"{name}: a second run gave different bytes")
        if 100 < len(data) <= 300000:
            for step in ((1, 4096) if a.quick else (1, 7, 4096, 65536, 100003)):
                code3, out3 = run(a.probe, data, step)
                ok(code3 == 0 and out3 == out, f"{name}: offering the data {step} bytes at a time changed the output")
    print(f"{'input':28s}{'bytes':>10s}{'ours':>10s}{'zlib -9':>10s}{'ratio':>8s}")
    for name, n, o, z, r in sorted(rows, key=lambda r: -r[4])[:8]:
        print(f"{name:28s}{n:10d}{o:10d}{z:10d}{r:8.2f}")
    print(f"{'FAIL' if bad else 'ok'}: {checks} checks, {bad} failure(s); the worst compressible ratio against zlib -9 is {worst:.2f}x")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
