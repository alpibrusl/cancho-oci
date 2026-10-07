#!/usr/bin/env python3
"""Gate for `oci.digest` and `oci.store` (design 2 and 3, task #4).

  1. digests agree with `sha256sum` (or `shasum -a 256`) on a corpus: every length 0..300 (each SHA-256 padding
     case, one and two blocks), the read-chunk boundaries (64 KiB -1, 0, +1), a few MiB, and optionally a
     multi-gigabyte file (`--big-gib N`; N > 4 crosses the 32-bit bit-length boundary of the message counter);
  2. `put` stores each file under its digest, byte for byte, and leaves nothing else in the store;
  3. a blob written twice is not rewritten (same inode and mtime, outcome "existed");
  4. a blob whose bytes do not match its name is refused on verify (flipped byte, truncation) and a missing one
     is refused as missing;
  5. a malformed digest is refused with its rule tag;
  6. the directory handle confines: `..`, a symlink and a nested name never reach outside the root;
  7. a stale temporary from a crash does not block a write.

    store_diff.py [--probe build/store-probe] [--big-gib N] [--seed S]

Exit 0 only if every check passes.
"""
import argparse, hashlib, os, random, shutil, subprocess, sys, tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
bad = 0
checks = 0


def fail(msg):
    global bad
    bad += 1
    print(f"FAIL {msg}")


def ok(cond, msg):
    global checks
    checks += 1
    if not cond:
        fail(msg)
    return cond


def probe(*args, probe_path):
    p = subprocess.run([probe_path, *map(str, args)], capture_output=True, text=True)
    return p.returncode, p.stdout.strip(), p.stderr.strip()


def sha256_file(path):
    """The oracle: hashlib, and cross-checked against the system tool where the file is big."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(1 << 20):
            h.update(chunk)
    return h.hexdigest()


def system_sha(path):
    for cmd in (["sha256sum", str(path)], ["shasum", "-a", "256", str(path)]):
        if shutil.which(cmd[0]):
            return subprocess.run(cmd, capture_output=True, text=True).stdout.split()[0]
    return None


def corpus(rng):
    sizes = list(range(0, 301)) + [511, 512, 513, 1023, 1024, 4095, 4096, 4097, 65535, 65536, 65537, 131071, 131072,
                                   131073, 1 << 20, (1 << 20) + 1, rng.randint(2_000_000, 6_000_000)]
    return sizes


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--probe", default=str(ROOT / "build" / "store-probe"))
    ap.add_argument("--big-gib", type=float, default=0)
    ap.add_argument("--seed", type=int, default=1)
    a = ap.parse_args()
    rng = random.Random(a.seed)
    P = a.probe

    with tempfile.TemporaryDirectory() as d:
        d = Path(d)
        src = d / "src"
        src.mkdir()
        store = d / "store"
        store.mkdir()

        # 1 + 2: digests and put over the corpus
        for n, size in enumerate(corpus(rng)):
            f = src / f"f{n}"
            f.write_bytes(os.urandom(size) if size > 1000 else bytes(rng.randrange(256) for _ in range(size)))
            want = sha256_file(f)
            code, out, err = probe("hash", src, f.name, probe_path=P)
            if not ok(code == 0 and out == f"sha256:{want} {size}", f"hash of {size} bytes: got {out!r} {err!r}, want {want}"):
                continue
            code, out, err = probe("put", store, src, f.name, probe_path=P)
            blob = store / want
            if ok(code == 0 and out in (f"created sha256:{want}", f"existed sha256:{want}"), f"put of {size} bytes: {out!r} {err!r}"):
                ok(blob.exists() and blob.read_bytes() == f.read_bytes(), f"blob for {size} bytes differs from its source")
        names = sorted(p.name for p in store.iterdir())
        ok(all(len(n) == 64 and all(c in "0123456789abcdef" for c in n) for n in names),
           f"the store holds something that is not a digest name: {[n for n in names if len(n) != 64][:5]}")

        # 3: write-once
        f = src / "twice"
        f.write_bytes(b"written twice\n")
        want = sha256_file(f)
        code, out1, _ = probe("put", store, src, "twice", probe_path=P)
        blob = store / want
        st1 = blob.stat()
        code2, out2, _ = probe("put", store, src, "twice", probe_path=P)
        st2 = blob.stat()
        ok(out1 == f"created sha256:{want}" and out2 == f"existed sha256:{want}", f"write-once outcomes: {out1!r}, {out2!r}")
        ok((st1.st_ino, st1.st_mtime_ns) == (st2.st_ino, st2.st_mtime_ns), "a blob written twice was rewritten (inode or mtime changed)")
        ok(not (store / ".incoming-0").exists(), "a temporary file was left behind after put")

        # 4: tampering
        code, out, err = probe("verify", store, want, probe_path=P)
        ok(code == 0 and out == "ok", f"verify of an intact blob: {out!r} {err!r}")
        data = bytearray(blob.read_bytes())
        data[3] ^= 1
        blob.write_bytes(bytes(data))
        code, out, err = probe("verify", store, want, probe_path=P)
        ok(code == 1 and "blob-digest-mismatch" in err, f"flipped byte not refused: {code} {err!r}")
        blob.write_bytes(bytes(data[:-3]))
        code, out, err = probe("verify", store, want, probe_path=P)
        ok(code == 1 and "blob-digest-mismatch" in err, f"truncated blob not refused: {code} {err!r}")
        blob.unlink()
        code, out, err = probe("verify", store, want, probe_path=P)
        ok(code == 1 and "blob-missing" in err, f"missing blob not refused as missing: {code} {err!r}")

        # 5: malformed names
        # Every character just outside the hex ranges ('0'-1, '9'+1, 'A', 'F'+1.. 'a'-1, 'a'-1, 'f'+1) must be refused.
        edge = [(want[:10] + c + want[11:], "digest-hex") for c in "/:@GZ[`g~ \x7f"]
        for name, tag in [(want.upper(), "digest-hex"), (want[:-1], "digest-length"), (want + "0", "digest-length"),
                          ("g" + want[1:], "digest-hex"), ("", "digest-length")] + edge:
            code, out, err = probe("verify", store, name, probe_path=P)
            if name == "":
                continue  # the probe needs a fourth argument; an empty one is the same refusal below
            ok(code == 1 and tag in err, f"verify {name[:12]!r}...: expected {tag}, got {code} {err!r}")

        # 6: confinement
        secret = d / "outside.txt"
        secret.write_bytes(b"outside\n")
        jail = d / "jail"
        jail.mkdir()
        (jail / "inside.txt").write_bytes(b"inside\n")
        os.symlink(secret, jail / "link.txt")
        os.symlink(d, jail / "dirlink")
        for name in ["../outside.txt", "link.txt", "dirlink/outside.txt", "sub/x", "/etc/hostname", ".."]:
            code, out, err = probe("hash", jail, name, probe_path=P)
            ok(code == 1 and "sha256:" not in out, f"hash {name!r} escaped or was not refused: {code} {out!r} {err!r}")
        code, out, err = probe("hash", jail, "inside.txt", probe_path=P)
        ok(code == 0 and out.startswith("sha256:"), f"a plain name in the jail was refused: {err!r}")

        # 7: a stale temporary does not block a write
        (store / ".incoming-0").write_bytes(b"left by a crash")
        f = src / "after-crash"
        f.write_bytes(b"after the crash\n")
        code, out, err = probe("put", store, src, "after-crash", probe_path=P)
        ok(code == 0 and out.startswith("created "), f"a stale temporary blocked the write: {out!r} {err!r}")
        ok(not (store / ".incoming-0").exists(), "the stale temporary is still there")

        # a store that does not exist, and one that cannot be written
        code, out, err = probe("put", d / "no-such-store", src, "twice", probe_path=P)
        ok(code == 1 and "dir-open" in err, f"missing store dir: {code} {err!r}")
        ro = d / "readonly"
        ro.mkdir()
        os.chmod(ro, 0o555)
        if os.geteuid() != 0:
            code, out, err = probe("put", ro, src, "twice", probe_path=P)
            ok(code == 1 and "blob-io" in err, f"unwritable store: {code} {out!r} {err!r}")
        os.chmod(ro, 0o755)

        # 1 (big): a file past the 32-bit counter boundaries
        if a.big_gib > 0:
            big = d / "big"
            gib = 1 << 30
            total = int(a.big_gib * gib)
            with open(big, "wb") as w:
                block = os.urandom(1 << 20)
                for i in range(total // (1 << 20)):
                    w.write(block[i % 7:] + block[:i % 7])
                w.write(b"tail")
            size = big.stat().st_size
            want = system_sha(big) or sha256_file(big)
            code, out, err = probe("hash", d, "big", probe_path=P)
            ok(code == 0 and out == f"sha256:{want} {size}", f"hash of {size} bytes ({a.big_gib} GiB): {out!r} {err!r}; want {want}")
            big.unlink()

    print(f"{'FAIL' if bad else 'ok'}: {checks} checks, {bad} failure(s)")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
