#!/usr/bin/env python3
"""G1 across machines (design 2; task #11): the same inputs give the same digests on every platform.

A fixed set of images is built from deterministic inputs (hand-made static ELF executables and files whose bytes
come from a hash chain, never from the OS or the Python version) and every digest of every image is compared with
`tests/golden/digests.json`, which is committed. The same file is checked on macOS/arm64 with Python 3.14, on
Linux/x86-64 with whatever Python the runner has, and on a macOS runner in CI: three machines, two operating
systems, two CPU architectures, two compilers' backends' worth of code generation, and one answer.

That is a statement about reproducibility, not about correctness: a wrong digest can be wrong everywhere. So each
case's `diff_id` is also compared with the digest of the tar that Python's `tarfile` writes for the same entries,
an oracle that shares no code with oci-build (the correctness gates are scripts/build_check.py and friends).

    golden_check.py            check against tests/golden/digests.json
    golden_check.py --update   rewrite it (a deliberate act: the diff is the review)
"""
import argparse, hashlib, importlib.util, json, os, shutil, subprocess, sys, tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
GOLDEN = ROOT / "tests" / "golden" / "digests.json"
sys.path.insert(0, str(ROOT / "scripts"))


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


ELF = load("make_elf")
BC = load("build_check")

WORDS = ["layer", "image", "digest", "manifest", "config", "blob", "tar", "gzip", "static", "binary", "scratch", "authority",
         "capability", "ownership", "effect", "region", "linear", "borrow", "release", "split", "world", "reproducible"]


def noise(label, n):
    """n bytes from a SHA-256 hash chain: the same on every platform and every Python."""
    out, i = bytearray(), 0
    while len(out) < n:
        out += hashlib.sha256(f"{label}:{i}".encode()).digest()
        i += 1
    return bytes(out[:n])


def prose(label, n):
    """Compressible text from a hash chain: words picked by hash bytes."""
    out, i = bytearray(), 0
    while len(out) < n:
        h = hashlib.sha256(f"{label}:{i}".encode()).digest()
        out += b" ".join(WORDS[b % len(WORDS)].encode() for b in h[:8]) + (b"\n" if h[8] % 5 == 0 else b" ")
        i += 1
    return bytes(out[:n])


def records(label, n):
    """Structured, repetitive binary-ish data: fixed-width records with a counter, like a table or a symbol table."""
    out, i = bytearray(), 0
    while len(out) < n:
        h = hashlib.sha256(f"{label}:{i % 7}".encode()).digest()
        out += i.to_bytes(4, "little") + h[:12] + bytes(8)
        i += 1
    return bytes(out[:n])


# name -> (platform, extra flags, [(src, dest, exec, content)], config for the model)
def cases():
    return {
        "amd64-gzip-small": dict(
            arch="amd64", compress="gzip", epoch=0, ref="latest", flags=["--user", "65532", "--env", "MODE=prod", "--port", "8080/tcp"],
            files=[("app", "app", True, ELF.elf("amd64")), ("motd", "etc/motd", False, b"hello\n")],
            cfg=dict(user="65532", env="MODE=prod", ports="8080/tcp", workdir="", labels="", cmd="", entry="/app")),
        "arm64-none": dict(
            arch="arm64", compress="none", epoch=0, ref="", flags=[],
            files=[("app", "bin/app", True, ELF.elf("arm64")), ("a", "data/a", False, prose("a", 5000)), ("b", "data/b/c", False, b"")],
            cfg=dict(user="", env="", ports="", workdir="", labels="", cmd="", entry="/bin/app")),
        "riscv64-gzip-two-bins-multiblock": dict(
            arch="riscv64", compress="gzip", epoch=0, ref="v1", flags=[],
            files=[("one", "usr/bin/one", True, ELF.elf("riscv64")), ("two", "usr/bin/two", True, ELF.elf("riscv64")),
                   ("big", "srv/big.txt", False, prose("big", 200_000)), ("noise", "srv/noise.bin", False, noise("noise", 70_000))],
            cfg=dict(user="", env="", ports="", workdir="", labels="", cmd="", entry="/usr/bin/one")),
        "amd64-gzip-epoch-and-config": dict(
            arch="amd64", compress="gzip", epoch=1700000000, ref="rc",
            flags=["--user", "1000:1000", "--workdir", "/srv", "--label", "org.example.a=1", "--label", "org.example.b=two words",
                   "--env", "A=1", "--env", "B=ünïcode 日本", "--port", "443/tcp", "--port", "53/udp", "--entrypoint", "/app", "--entrypoint", "--serve", "--cmd", "-v"],
            files=[("app", "app", True, ELF.elf("amd64")), ("cert", "etc/ssl/certs/ca.pem", False, prose("cert", 1800))],
            cfg=dict(user="1000:1000", env="A=1\nB=ünïcode 日本", ports="443/tcp\n53/udp", workdir="/srv", labels="org.example.a=1\norg.example.b=two words", cmd="-v", entry="/app\n--serve")),
        "amd64-gzip-records-multiblock": dict(
            arch="amd64", compress="gzip", epoch=0, ref="", flags=[],
            files=[("app", "app", True, ELF.elf("amd64")), ("t", "var/table.dat", False, records("t", 330_000))],
            cfg=dict(user="", env="", ports="", workdir="", labels="", cmd="", entry="/app")),
    }


def build_case(exe, name, case, work):
    root, out = work / "root", work / "image"
    root.mkdir(parents=True)
    (out / "blobs" / "sha256").mkdir(parents=True)
    extra = []
    for src, dest, is_exec, data in case["files"]:
        (root / src).write_bytes(data)
        extra += ["--bin" if is_exec else "--file", f"{src}:{dest}"]
    if case["epoch"]:
        extra += ["--source-date-epoch", str(case["epoch"])]
    if case["ref"]:
        extra += ["--ref", case["ref"]]
    extra += ["--compress", case["compress"]] + case["flags"]
    p = subprocess.run([exe, "--root", str(root), "--out", str(out), "--platform", f"linux/{case['arch']}"] + extra, capture_output=True, text=True)
    if p.returncode != 0:
        return None, f"{name}: oci-build refused: {p.stderr.strip()}"
    index = json.loads((out / "index.json").read_text())
    mdig = index["manifests"][0]["digest"]
    manifest = json.loads((out / "blobs" / "sha256" / mdig.split(":")[1]).read_text())
    config = json.loads((out / "blobs" / "sha256" / manifest["config"]["digest"].split(":")[1]).read_text())
    return dict(manifest=mdig, config=manifest["config"]["digest"], layer=manifest["layers"][0]["digest"],
                layer_size=manifest["layers"][0]["size"], diff_id=config["rootfs"]["diff_ids"][0]), None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--build", default=str(ROOT / "build" / "oci-build"))
    ap.add_argument("--update", action="store_true")
    a = ap.parse_args()
    got, bad = {}, 0
    with tempfile.TemporaryDirectory() as t:
        for name, case in cases().items():
            res, err = build_case(a.build, name, case, Path(t) / name)
            if err:
                print(f"FAIL {err}")
                bad += 1
                continue
            got[name] = res
            # the independent oracle for the diff_id: Python's tarfile on the same entries
            entries = [(dest, is_exec, data) for _, dest, is_exec, data in case["files"]]
            tar = BC.expected_layer(entries, case["epoch"])
            want = "sha256:" + hashlib.sha256(tar).hexdigest()
            if res["diff_id"] != want:
                print(f"FAIL {name}: diff_id {res['diff_id']} is not the digest of the tarfile oracle's layer {want}")
                bad += 1
    if a.update:
        if bad:
            print("not updating: a case failed")
            return 1
        GOLDEN.write_text(json.dumps(got, indent=2, sort_keys=True) + "\n")
        print(f"wrote {GOLDEN.relative_to(ROOT)} ({len(got)} images)")
        return 0
    want_all = json.loads(GOLDEN.read_text())
    for name in sorted(set(want_all) | set(got)):
        if name not in got or name not in want_all:
            print(f"FAIL {name}: present in only one of the build and the golden file")
            bad += 1
            continue
        for k in sorted(want_all[name]):
            if got[name].get(k) != want_all[name][k]:
                print(f"FAIL {name}.{k}: this machine built {got[name].get(k)}, the golden file says {want_all[name][k]}")
                bad += 1
    import platform
    print(f"{'FAIL' if bad else 'ok'}: {len(got)} images, every digest equal to the golden file, on {sys.platform}/{platform.machine()} with Python {platform.python_version()}"
          if not bad else f"FAIL: {bad} difference(s) on {sys.platform}/{platform.machine()}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
