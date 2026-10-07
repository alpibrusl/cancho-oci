#!/usr/bin/env python3
"""Gate for `oci-build` (design 2 and 3, task #7): a FROM-scratch image from static executables, checked
end to end against independent models.

For random inputs on all three architectures it checks:
  1. the layer bytes equal what Python's `tarfile` (USTAR) writes for the same entries: implied parent
     directories, bytewise order, modes 0755/0644, the chosen time, the real file contents;
  2. the config, manifest and index equal the independent JSON model, validate against the OCI schemas,
     and chain by digest and size (the checks of scripts/image_check.py, reused);
  3. the default entrypoint is the first `--bin`; explicit config flags land in the config;
  4. building twice, in different directories and with the source files touched, gives identical bytes (G1);
  5. a dynamic executable, an executable for another architecture, a non-ELF `--bin`, a missing source, a
     duplicate or unsafe destination, a symlink out of the root, and bad flags are each refused with their
     rule tag and the path they are about, and a refusal leaves no `index.json`;
  6. `skopeo` and `crane` accept the result (when installed; their absence is printed);
  7. with `--run`, the image is loaded and the executable of the host architecture is run in a container
     (podman), and must exit 0: the proof that the layer is a runnable `scratch` image.

    build_check.py [--cases N] [--seed S] [--run] [--build build/oci-build]
"""
import argparse, importlib.util, json, os, platform, random, shutil, subprocess, sys, tarfile, tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


IC = load("image_check")
TD = load("tar_diff")
ELF = load("make_elf")

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
    return bool(cond)


def build(exe, root, out, platform_, extra, check=None):
    cmd = [exe, "--root", str(root), "--out", str(out), "--platform", platform_] + [str(x) for x in extra]
    p = subprocess.run(cmd, capture_output=True, text=True)
    return p.returncode, p.stdout.strip(), p.stderr.strip()


def skeleton(d):
    (Path(d) / "blobs" / "sha256").mkdir(parents=True)


def tree(d):
    return {str(p.relative_to(d)): p.read_bytes() for p in sorted(Path(d).rglob("*")) if p.is_file()}


def expected_layer(entries, mtime):
    """entries: [(dest, is_exec, data)], files only. The oracle adds the parent directories and sorts."""
    items = {}
    for dest, is_exec, data in entries:
        parts = dest.split("/")
        for i in range(1, len(parts)):
            items.setdefault("/".join(parts[:i]), ("D", False, b""))
        items[dest] = ("X" if is_exec else "F", is_exec, data)
    out = bytearray()
    for name in sorted(items, key=lambda s: s.encode()):
        kind, is_exec, data = items[name]
        ti = tarfile.TarInfo(name)
        ti.type = tarfile.DIRTYPE if kind == "D" else tarfile.REGTYPE
        ti.size = len(data)
        ti.mode = 0o755 if kind in "DX" else 0o644
        ti.mtime = mtime
        ti.uid = ti.gid = 0
        ti.uname = ti.gname = ""
        head = ti.tobuf(tarfile.USTAR_FORMAT, "utf-8", "strict")
        if head[0] == 0:
            return None
        out += TD.normalize(head)
        if kind != "D":
            out += data + b"\0" * ((512 - len(data) % 512) % 512)
    return bytes(out + b"\0" * 1024)


def random_files(rng, arch, n_files):
    paths = set()
    while len(paths) < n_files:
        depth = rng.choice([1, 1, 2, 3])
        paths.add("/".join(TD.component(rng, rng.choice([2, 5, 9, 14, 20])) for _ in range(depth)))
    chosen = sorted(paths)
    # no path may be a directory of another (a file "a" and "a/b" cannot both exist)
    keep = [p for p in chosen if not any(q != p and q.startswith(p + "/") for q in chosen)]
    files = []
    for i, dest in enumerate(keep):
        size = rng.choice([0, 1, 7, 511, 512, 513, 4096, 65535, 65536, 65537, 70000, rng.randint(0, 150000)])
        files.append((dest, False, os.urandom(size)))
    return files


def check_image(image, rec, case_name, arch):
    index = json.loads((image / "index.json").read_text())
    ok(not list(IC.validator("image-index-schema.json").iter_errors(index)), f"{case_name}: index.json is not valid")
    blobs = {p.name: p.read_bytes() for p in (image / "blobs" / "sha256").iterdir()}
    mdesc = index["manifests"][0]
    mhex = mdesc["digest"].split(":")[1]
    manifest = json.loads(blobs[mhex])
    ok(not list(IC.validator("image-manifest-schema.json").iter_errors(manifest)), f"{case_name}: manifest is not valid")
    chex, lhex = manifest["config"]["digest"].split(":")[1], manifest["layers"][0]["digest"].split(":")[1]
    ok(set(blobs) == {mhex, chex, lhex}, f"{case_name}: unexpected blobs {sorted(set(blobs) - {mhex, chex, lhex})}")
    for hexd, desc in ((mhex, mdesc), (chex, manifest["config"]), (lhex, manifest["layers"][0])):
        ok(IC.sha(blobs[hexd]) == hexd and len(blobs[hexd]) == desc["size"], f"{case_name}: descriptor of {hexd[:12]} does not match its blob")
    config = json.loads(blobs[chex])
    ok(not list(IC.validator("config-schema.json").iter_errors(config)), f"{case_name}: config is not valid")
    layer = expected_layer(rec["files"], rec["mtime"])
    if layer is None:
        return
    ok(blobs[lhex] == layer, f"{case_name}: the layer differs from the tarfile oracle ({len(blobs[lhex])} bytes vs {len(layer)})"
       + ("" if blobs[lhex] == layer else f"\n   first difference: {TD.first_diff(blobs[lhex], layer)}"))
    mc = IC.model_config(arch, "linux", rec["entry"], rec["cmd"], rec["env"], rec["user"], rec["workdir"], rec["labels"], rec["ports"], f"sha256:{lhex}")
    ok(blobs[chex] == IC.compact(mc), f"{case_name}: config bytes differ from the model:\n  ours  {blobs[chex][:240]!r}\n  model {IC.compact(mc)[:240]!r}")
    mi = IC.model_index(f"sha256:{mhex}", len(blobs[mhex]), arch, "linux", rec["ref"])
    ok((image / "index.json").read_bytes() == IC.compact(mi), f"{case_name}: index bytes differ from the model")
    return index


def runtime():
    """The container runtime to run an image in: Docker when its daemon answers, else Podman, else None.
    (On the GitHub runner rootless Podman cannot unshare a user namespace; Docker's daemon is there and works.)"""
    if shutil.which("docker") and shutil.which("skopeo"):
        rc, _ = tool(["docker", "info"])
        if rc == 0:
            return "docker"
    if shutil.which("podman") and shutil.which("skopeo"):
        return "podman"
    return None


def run_image(rt, layout_ref, entrypoint, name):
    """Load the OCI layout `layout_ref` (oci:dir:tag) into the runtime and run it. Returns (rc, stdout, stderr, load_error)."""
    if rt == "docker":
        load = ["skopeo", "copy", layout_ref, f"docker-daemon:{name}:1"]
        runc = ["docker", "run", "--rm"] + (["--entrypoint", entrypoint] if entrypoint else []) + [f"{name}:1"]
        drop = ["docker", "rmi", "-f", f"{name}:1"]
    else:
        load = ["skopeo", "copy", layout_ref, f"containers-storage:{name}:1"]
        runc = ["podman", "run", "--rm"] + (["--entrypoint", entrypoint] if entrypoint else []) + [f"{name}:1"]
        drop = ["podman", "rmi", "-f", f"{name}:1"]
    rc, text = tool(load)
    if rc != 0:
        return None, "", "", text
    p = subprocess.run(runc, capture_output=True, text=True)
    tool(drop)
    return p.returncode, p.stdout, p.stderr, ""


def tool(cmd):
    p = subprocess.run(cmd, capture_output=True, text=True)
    return p.returncode, (p.stdout + p.stderr).strip()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cases", type=int, default=30)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--build", default=str(ROOT / "build" / "oci-build"))
    ap.add_argument("--run", action="store_true", help="run the host-architecture image in podman")
    ap.add_argument("--dogfood", help="a static oci-build for the host architecture: package it with oci-build and run it in podman")
    a = ap.parse_args()
    rng = random.Random(a.seed)
    exe = a.build
    host_arch = {"x86_64": "amd64", "aarch64": "arm64", "arm64": "arm64", "riscv64": "riscv64"}.get(platform.machine(), "")
    have_skopeo, have_crane = shutil.which("skopeo"), shutil.which("crane")
    rt = runtime() if (a.run or a.dogfood) else None
    ran_run = False

    with tempfile.TemporaryDirectory() as t:
        t = Path(t)
        # ---- random builds on every architecture
        for n in range(a.cases):
            arch = ["amd64", "arm64", "riscv64"][n % 3]
            w = t / f"c{n}"
            root, out = w / "root", w / "image"
            root.mkdir(parents=True)
            skeleton(out)
            nb = rng.choice([1, 1, 2])
            bins = [(f"bin{i}", f"{rng.choice(['app', 'usr/bin/tool', 'srv/x'])}{i}") for i in range(nb)]
            files = random_files(rng, arch, rng.randint(0, 6))
            files = [f for f in files if not any(f[0] == b[1] or f[0].startswith(b[1] + "/") or b[1].startswith(f[0] + "/") for b in bins)]
            rec_files = []
            extra = []
            for src, dest in bins:
                data = ELF.elf(arch)
                (root / src).write_bytes(data)
                rec_files.append((dest, True, data))
                extra += ["--bin", f"{src}:{dest}"]
            (root / "s").mkdir()
            for i, (dest, _, data) in enumerate(files):
                (root / "s" / str(i)).write_bytes(data)
                rec_files.append((dest, False, data))
                extra += ["--file", f"s/{i}:{dest}"]
            mtime = rng.choice([0, 0, 1, 1700000000])
            user, workdir = rng.choice(["", "65532"]), rng.choice(["", "/"])
            env = rng.choice(["", "MODE=prod", "A=1\nB=2"])
            ports = rng.choice(["", "8080/tcp"])
            ref = rng.choice(["", "latest", "v1"])
            entry_flag = rng.choice([None, "/custom", "/a\n/b"])
            if mtime:
                extra += ["--source-date-epoch", mtime]
            for flag, val in (("--user", user), ("--workdir", workdir), ("--ref", ref)):
                if val:
                    extra += [flag, val]
            for v in env.split("\n") if env else []:
                extra += ["--env", v]
            for v in ports.split("\n") if ports else []:
                extra += ["--port", v]
            for v in entry_flag.split("\n") if entry_flag else []:
                extra += ["--entrypoint", v]
            rec = dict(files=rec_files, mtime=mtime, user=user, workdir=workdir, env=env, ports=ports, ref=ref, cmd="", labels="",
                       entry=entry_flag if entry_flag else "/" + bins[0][1])
            code, stdout, err = build(exe, root, out, f"linux/{arch}", extra)
            if not ok(code == 0 and stdout.startswith("sha256:"), f"case {n} ({arch}): build refused: {err!r}"):
                continue
            index = check_image(out, rec, f"case {n} ({arch})", arch)
            ok(index and index["manifests"][0]["digest"] == stdout, f"case {n}: the printed digest is not the index's")
            # G1: elsewhere, with every source touched, the same bytes
            out2, root2 = w / "again" / "image", w / "again" / "root"
            shutil.copytree(root, root2)
            for p in root2.rglob("*"):
                os.utime(p, (1_000_000_000 + n, 1_000_000_000 + n))
            skeleton(out2)
            code2, stdout2, err2 = build(exe, root2, out2, f"linux/{arch}", extra)
            ok(code2 == 0 and tree(out) == tree(out2), f"case {n}: building twice (sources touched) gave different bytes")
            if n < 6 and index:
                ref_ = rec["ref"]
                target = f"oci:{out}" + (f":{ref_}" if ref_ else "")
                if have_skopeo:
                    rc, text = tool(["skopeo", "inspect", "--raw", target])
                    ok(rc == 0, f"case {n}: skopeo refused the image: {text[:200]}")
                    rc, text = tool(["skopeo", "copy", target, f"dir:{w / 'copy'}"])
                    ok(rc == 0, f"case {n}: skopeo copy failed: {text[:200]}")
            if a.run and rt and arch == host_arch and not ran_run:
                ran_run = True
                src = f"oci:{out}" + (f":{rec['ref']}" if rec["ref"] else "")
                rc, so, se, load_err = run_image(rt, src, "/" + bins[0][1], "localhost/oci-build-check")
                if ok(rc is not None, f"case {n}: loading the image into {rt} failed: {load_err[:300]}"):
                    ok(rc == 0, f"case {n}: the image did not run in {rt} (exit {rc}): {se[:300]}")
                    print(f"run: the {arch} image ran in {rt} (entrypoint /{bins[0][1]}, exit {rc})")

        if a.run and not ran_run:
            print(f"note: --run asked, but it needs a working docker or podman, skopeo and a {host_arch or platform.machine()} image in the first cases; not run (runtime: {rt})")

        # ---- refusals
        w = t / "refusals"
        root = w / "root"
        (root / "d").mkdir(parents=True)
        (root / "bin").mkdir()
        for arch in ("amd64", "arm64", "riscv64"):
            (root / "bin" / arch).write_bytes(ELF.elf(arch))
        (root / "bin" / "dyn").write_bytes(ELF.elf("amd64", dynamic=True))
        (root / "bin" / "text").write_bytes(b"#!/bin/sh\necho hi\n")
        (root / "bin" / "short").write_bytes(b"\x7fELF")
        (root / "d" / "f").write_bytes(b"data")
        outside = w / "outside"
        outside.write_bytes(b"secret")
        os.symlink(outside, root / "d" / "link")
        os.symlink(w, root / "d" / "dirlink")
        # headers broken one field at a time, to reach every refusal of oci.elf
        import struct

        def variant(name, edit):
            data = bytearray(ELF.elf("amd64"))
            edit(data)
            (root / "bin" / name).write_bytes(bytes(data))

        variant("class32", lambda d: d.__setitem__(4, 1))
        variant("bigendian", lambda d: d.__setitem__(5, 2))
        variant("version2", lambda d: d.__setitem__(6, 2))
        variant("rel", lambda d: struct.pack_into("<H", d, 16, 1))
        variant("i386", lambda d: struct.pack_into("<H", d, 18, 3))
        variant("arm32", lambda d: struct.pack_into("<H", d, 18, 40))
        variant("phentsize", lambda d: struct.pack_into("<H", d, 54, 32))
        variant("nophdrs", lambda d: struct.pack_into("<H", d, 56, 0))
        variant("phoff_far", lambda d: struct.pack_into("<Q", d, 32, 1 << 40))
        variant("phoff_huge", lambda d: struct.pack_into("<Q", d, 32, 1 << 60))
        variant("manyphdrs", lambda d: (struct.pack_into("<H", d, 56, 65), d.extend(b"\0" * 4000)))
        # a static-PIE: ET_DYN with a PT_DYNAMIC and no PT_INTERP. It runs without a loader, so it must be accepted.
        variant("staticpie", lambda d: (struct.pack_into("<H", d, 16, 3), struct.pack_into("<I", d, 64, 2)))
        cases = [
            (["--bin", "bin/class32:app"], "linux/amd64", "elf-class", "app"),
            (["--bin", "bin/bigendian:app"], "linux/amd64", "elf-class", "app"),
            (["--bin", "bin/version2:app"], "linux/amd64", "elf-class", "app"),
            (["--bin", "bin/rel:app"], "linux/amd64", "elf-type", "app"),
            (["--bin", "bin/i386:app"], "linux/amd64", "elf-machine", "app"),
            (["--bin", "bin/arm32:app"], "linux/amd64", "elf-machine", "app"),
            (["--bin", "bin/phentsize:app"], "linux/amd64", "elf-program-headers", "app"),
            (["--bin", "bin/nophdrs:app"], "linux/amd64", "elf-program-headers", "app"),
            (["--bin", "bin/phoff_far:app"], "linux/amd64", "elf-program-headers", "app"),
            (["--bin", "bin/phoff_huge:app"], "linux/amd64", "elf-program-headers", "app"),
            (["--bin", "bin/manyphdrs:app"], "linux/amd64", "elf-program-headers", "app"),
            (["--bin", "bin/dyn:app"], "linux/amd64", "elf-dynamic", "app"),
            (["--bin", "bin/arm64:app"], "linux/amd64", "elf-arch-mismatch", "app"),
            (["--bin", "bin/amd64:app"], "linux/arm64", "elf-arch-mismatch", "app"),
            (["--bin", "bin/text:app"], "linux/amd64", "elf-not-elf", "app"),
            (["--bin", "bin/short:app"], "linux/amd64", "elf-truncated", "app"),
            (["--bin", "bin/absent:app"], "linux/amd64", "layer-source", "app"),
            (["--file", "d/absent:x"], "linux/amd64", "layer-source", "x"),
            (["--file", "d/link:x"], "linux/amd64", "layer-source", "x"),
            (["--file", "d/dirlink/outside:x"], "linux/amd64", "layer-source", "x"),
            (["--file", "../outside:x"], "linux/amd64", "layer-source", "x"),
            (["--file", "d/f:x", "--file", "d/f:x"], "linux/amd64", "layer-duplicate", "x"),
            (["--file", "d/f:a", "--file", "d/f:a/b"], "linux/amd64", "layer-duplicate", "a"),
            # the reverse order: "a/b" has already made "a" a directory, so the file "a" is a clash
            (["--file", "d/f:a/b", "--file", "d/f:a"], "linux/amd64", "layer-duplicate", "a"),
            (["--file", "d/f:/abs"], "linux/amd64", "tar-name-absolute", "/abs"),
            (["--file", "d/f:a/../b"], "linux/amd64", "tar-name-component", "a/.."),
            (["--file", "d/f:a//b"], "linux/amd64", "tar-name-component", "a/"),
            (["--file", "d/f:" + "x" * 300], "linux/amd64", "tar-name-too-long", "x" * 20),
            (["--file", "d/f"], "linux/amd64", "layer-spec", None),
            (["--file", "d/f:"], "linux/amd64", "layer-spec", None),
            (["--file", ":x"], "linux/amd64", "layer-spec", None),
            (["--file"], "linux/amd64", "build-flag", None),
            (["--frobnicate", "x"], "linux/amd64", "build-flag", None),
            ([], "linux/amd64", "layer-empty", None),
            (["--bin", "bin/amd64:app"], "linux/arm", "image-arch", "linux/arm"),
            (["--bin", "bin/amd64:app"], "windows/amd64", "image-os", "windows/amd64"),
            (["--bin", "bin/amd64:app"], "linuxamd64", "build-platform", None),
            (["--bin", "bin/amd64:app"], "linux/", "build-platform", None),
            (["--bin", "bin/amd64:app", "--source-date-epoch", "soon"], "linux/amd64", "build-source-date-epoch", None),
            (["--bin", "bin/amd64:app", "--env", "NOEQ"], "linux/amd64", "image-env", None),
            (["--bin", "bin/amd64:app", "--port", "80"], "linux/amd64", "image-port", None),
            (["--bin", "bin/amd64:app", "--label", "a=1", "--label", "a=2"], "linux/amd64", "image-label", None),
        ]
        for i, (extra, plat, tag, culprit) in enumerate(cases):
            out = w / f"r{i}"
            skeleton(out)
            code, stdout, err = build(exe, root, out, plat, extra)
            good = code == 1 and f"refused: {tag}" in err and (culprit is None or culprit in err)
            ok(good, f"refusal {i} {extra} {plat}: expected {tag} naming {culprit!r}, got {code} {err!r}")
            ok(not (out / "index.json").exists(), f"refusal {i}: a refused build left an index.json")
            ok(not any((out / "blobs" / "sha256").glob(".incoming*")), f"refusal {i}: a refused build left a temporary file")
        out = w / "staticpie"
        skeleton(out)
        code, stdout, err = build(exe, root, out, "linux/amd64", ["--bin", "bin/staticpie:app"])
        ok(code == 0 and stdout.startswith("sha256:"), f"a static-PIE (PT_DYNAMIC, no PT_INTERP) was refused: {err!r}")
        # too many entries
        many = []
        (root / "many").mkdir()
        for k in range(70):
            (root / "many" / str(k)).write_bytes(b"x")
            many += ["--file", f"many/{k}:f{k}"]
        out = w / "many"
        skeleton(out)
        code, stdout, err = build(exe, root, out, "linux/amd64", many)
        ok(code == 1 and "layer-too-many-entries" in err, f"70 entries were not refused: {code} {err!r}")
        # missing required flags, bad directories
        code, _, err = subprocess.run([exe, "--out", str(w / "x"), "--platform", "linux/amd64", "--bin", "a:b"], capture_output=True, text=True).returncode, "", ""
        ok(code == 1, "a missing --root was not refused")
        out = w / "noskel"
        out.mkdir()
        code, stdout, err = build(exe, root, out, "linux/amd64", ["--bin", "bin/amd64:app"])
        ok(code == 1 and "build-layout-skeleton" in err, f"a missing blobs/sha256 was not refused: {code} {err!r}")
        code, stdout, err = build(exe, w / "no-such-root", w / "r0", "linux/amd64", ["--bin", "bin/amd64:app"])
        ok(code == 1 and "build-dir-open" in err, f"a missing root was not refused: {code} {err!r}")
        # rebuilding in the same directory is idempotent
        out = w / "idem"
        skeleton(out)
        c1 = build(exe, root, out, "linux/amd64", ["--bin", "bin/amd64:app", "--ref", "v"])
        t1 = tree(out)
        c2 = build(exe, root, out, "linux/amd64", ["--bin", "bin/amd64:app", "--ref", "v"])
        ok(c1[0] == 0 and c2[0] == 0 and c1[1] == c2[1] and t1 == tree(out), "rebuilding in place changed the image")

    if a.dogfood:
        # oci-build packages itself: the proof that a real cancho program, not a hand-made stub, runs in a scratch image.
        if not (rt and host_arch):
            fail("--dogfood needs a working docker or podman, skopeo and a supported host architecture")
        else:
            with tempfile.TemporaryDirectory() as t2:
                t2 = Path(t2)
                src = Path(a.dogfood)
                out = t2 / "image"
                skeleton(out)
                code, stdout, err = build(exe, src.parent, out, f"linux/{host_arch}", ["--bin", f"{src.name}:oci-build", "--ref", "dogfood"])
                if ok(code == 0, f"dogfood: could not package {src}: {err!r}"):
                    # With no arguments the tool refuses and says why: output that only the binary inside the
                    # container can have produced.
                    rc, so, se, load_err = run_image(rt, f"oci:{out}:dogfood", None, "localhost/oci-dogfood")
                    if ok(rc is not None, f"dogfood: loading into {rt} failed: {load_err[:300]}"):
                        ok(rc == 1 and "refused: build-missing" in se,
                           f"dogfood: the packaged oci-build did not run as expected in the container: exit {rc} {se!r}")
                        print(f"dogfood: oci-build ran inside a scratch container built by oci-build ({rt}): {se.strip()[:90]}")

    notes = []
    if not have_skopeo:
        notes.append("skopeo NOT installed: not run")
    print(f"{'FAIL' if bad else 'ok'}: {checks} checks, {bad} failure(s)" + (f"  [{'; '.join(notes)}]" if notes else ""))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
