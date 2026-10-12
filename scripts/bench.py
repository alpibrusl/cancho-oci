#!/usr/bin/env python3
"""The benchmark of issue #16, to the cells pre-registered in docs/design.md section "Benchmark cells":
(a) one 5 MB static binary; (b) one 50 MB static binary; (c) 500 files totalling 20 MB. Wall time and
peak memory, cold and warm file cache, and reproducibility (do two builds agree), for every tool
that is present. Losses are reported as plainly as wins, and a tool that is not installed is named
as absent, never skipped silently.

    python3 scripts/bench.py [--out results.json] [--runs N]
    python3 scripts/bench.py --check    # nothing is measured; exit 1 if a tool's flags cannot be built

The cells' inputs are made here, deterministically, from scripts/make_elf.py (a static ELF for the
host platform) and fixed-width generated records: nothing about the machine leaks into the inputs,
so two runs differ only in time and memory. Each cell is built by every tool that can build it; the
comparison is like for like where the tools have a comparable mode (crane app append builds a
FROM-scratch layer from files; ko needs Go sources, so its cells say "not comparable" rather than
quote a number, per the design: where there is no comparable mode, the table says so).

Wall time is measured around the whole process (fork to exit) with time.monotonic; peak memory is that
one process's own ru_maxrss, from wait4 on its pid (getrusage(RUSAGE_CHILDREN) is the largest child the
harness ever had, its own input generators included, so it is not used).
Cold cache: echo 3 > /proc/sys/vm/drop_caches needs root. When it can be written, each cell gets one
cold run (caches dropped just before it) besides the warm runs; when it cannot, the results say "needs
root: not run" instead of pretending.
"""
import hashlib
import json
import os
import pathlib
import platform
import shutil
import subprocess
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parent.parent
WORK = ROOT / "bench" / "work"
OUT_DEFAULT = ROOT / "bench" / "results" / "bench.json"
RUNS = 3

def have(binary):
    return shutil.which(binary) is not None


def make_cells():
    """The three pre-registered cells, deterministic inputs only (design: cells are fixed)."""
    cells = []
    # (a) one 5 MB static binary
    a = WORK / "a"
    a.mkdir(parents=True, exist_ok=True)
    elf5 = a / "prog"
    if not elf5.exists():
        subprocess.run([sys.executable, str(ROOT / "scripts" / "make_elf.py"), host_arch(), str(elf5)], check=True)
    if elf5.stat().st_size < (5 << 20):
        pad = (5 << 20) - elf5.stat().st_size
        elf5.write_bytes(elf5.read_bytes() + bytes(range(256)) * (pad // 256) + b"\x00" * (pad % 256))
    cells.append(("a-one-5mb-binary", a, [str(elf5)]))
    # (b) one 50 MB static binary
    b = WORK / "b"
    b.mkdir(parents=True, exist_ok=True)
    elf50 = b / "prog"
    if not elf50.exists():
        subprocess.run([sys.executable, str(ROOT / "scripts" / "make_elf.py"), host_arch(), str(elf50)], check=True)
        rng = 12345
        chunk = bytearray()
        while len(chunk) < (50 << 20):
            rng = (1103515245 * rng + 12345) % (1 << 31)
            chunk += bytes([rng & 0xFF, (rng >> 8) & 0xFF, (rng >> 16) & 0xFF])
        elf50.write_bytes(elf50.read_bytes() + bytes(chunk[:(50 << 20) - elf50.stat().st_size]))
    cells.append(("b-one-50mb-binary", b, [str(elf50)]))
    # (c) 500 files totalling 20 MB, as pre-registered -- and a 64-file variant, because
    # oci-build's layer refuses more than 64 entries (src/layer/layer.cho max_entries): the
    # pre-registered cell is a FINDING (the tool cannot build it), the variant is measured.
    c = WORK / "c"
    c.mkdir(parents=True, exist_ok=True)
    if not list(c.glob("f*")):
        rng = 999
        for i in range(500):
            data = bytearray()
            while len(data) < (20 << 20) // 500 + 1:
                rng = (1103515245 * rng + 12345) % (1 << 31)
                data += bytes([rng & 0xFF, (rng >> 8) & 0xFF, (rng >> 16) & 0xFF, (rng >> 24) & 0xFF])
            (c / ("f%03d" % i)).write_bytes(bytes(data[: (20 << 20) // 500]))
    cells.append(("c-500-files-20mb-as-registered", c, sorted(str(p) for p in c.glob("f*"))))
    c64 = WORK / "c64"
    c64.mkdir(parents=True, exist_ok=True)
    if not list(c64.glob("f*")):
        for i in range(64):
            shutil.copyfile(c / ("f%03d" % i), c64 / ("f%03d" % i))
    cells.append(("c-64-files-2.5mb-at-the-layer-limit", c64, sorted(str(p) for p in c64.glob("f*"))))
    return cells


def host_arch():
    out = subprocess.run(["uname", "-m"], capture_output=True, text=True).stdout.strip()
    return {"x86_64": "amd64", "aarch64": "arm64", "riscv64": "riscv64"}.get(out, "amd64")


def run_measured(cmd, cwd=None):
    """Run one process; its wall time, its own peak resident memory (KiB, from wait4), its exit status and the start of its output."""
    t0 = time.monotonic()
    proc = subprocess.Popen(cmd, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out = proc.stdout.read()
    err = proc.stderr.read()
    _, status, usage = os.wait4(proc.pid, 0)
    elapsed = time.monotonic() - t0
    proc.returncode = os.waitstatus_to_exitcode(status)
    return elapsed, usage.ru_maxrss, proc.returncode, out.decode()[:200], err.decode()[:200]


def build_with(build_tool, cell, cell_dir, inputs, image_dir):
    if build_tool == "oci-build":
        cmd = [str(ROOT / "build" / "oci-build"), "--root", str(cell_dir), "--out", str(image_dir),
               "--platform", "linux/" + host_arch()]
        for path in inputs:
            rel = pathlib.Path(path).relative_to(cell_dir)
            cmd += ["--bin" if rel.name == "prog" else "--file", "%s:%s" % (rel, rel)]
        return cmd
    return None


def drop_caches():
    """Drop the page cache (needs root). True when it was dropped."""
    try:
        with open("/proc/sys/vm/drop_caches", "w") as f:
            f.write("3\n")
        return True
    except OSError:
        return False


def machine():
    model = ""
    try:
        for line in open("/proc/cpuinfo"):
            if line.startswith(("model name", "Model")):
                model = line.split(":", 1)[1].strip()
                break
    except OSError:
        pass
    def git(*a):
        r = subprocess.run(["git", "-C", str(ROOT), *a], capture_output=True, text=True)
        return r.stdout.strip() if r.returncode == 0 else "unknown"
    return {"cpu": model, "cores": os.cpu_count(), "kernel": platform.release(), "system": platform.system(), "machine": platform.machine(),
            "loadavg_start": os.getloadavg(), "commit": git("rev-parse", "HEAD"), "dirty": bool(git("status", "--porcelain")),
            "date": time.strftime("%Y-%m-%d %H:%M:%S %z")}


def main():
    if "--check" in sys.argv[1:]:
        missing = [t for t in ("oci-build",) if not (ROOT / "build" / t).exists() and not have(t)]
        print("missing: " + ", ".join(missing) if missing else "the tools this harness measures are present")
        return 1 if missing else 0

    out_path = OUT_DEFAULT
    if "--out" in sys.argv[1:]:
        out_path = pathlib.Path(sys.argv[sys.argv.index("--out") + 1])

    cells = make_cells()
    # Only the builders that can build this cell shape; docker build interprets Dockerfiles and
    # ko needs Go sources, so both are "not comparable" for these cells (design: benchmark cells),
    # listed in the results without pretending a run happened.
    tools = {"oci-build": have("oci-build") or (ROOT / "build" / "oci-build").exists(),
             "crane": have("crane"),
             "ko": have("ko"),
             "buildah": have("buildah")}
    cold_possible = drop_caches()
    results = {"machine": machine(), "cells": {}, "tools": {k: v for k, v in tools.items()},
               "cold-cache": "one cold run per cell, the page cache dropped just before it" if cold_possible else "needs root: not run; warm only",
               "runs": RUNS, "host-arch": host_arch()}

    for name, cell_dir, inputs in cells:
        results["cells"][name] = {"inputs": len(inputs), "bytes": sum(pathlib.Path(i).stat().st_size for i in inputs)}
        for tool, present in tools.items():
            entry = results["cells"][name].setdefault(tool, {})
            if not present:
                entry["status"] = "absent"
                continue
            if tool == "oci-build":
                timings, peaks, digests, cold = [], [], [], None
                runs = (["cold"] if cold_possible else []) + ["warm"] * RUNS
                for run, kind in enumerate(runs):
                    image_dir = WORK / ("image-%s-%d" % (name, run))
                    if image_dir.exists():
                        shutil.rmtree(image_dir)
                    (image_dir / "blobs" / "sha256").mkdir(parents=True)
                    cmd = build_with("oci-build", name, cell_dir, inputs, image_dir)
                    if kind == "cold":
                        drop_caches()
                    seconds, peak, rc, out, err = run_measured(cmd)
                    if rc != 0:
                        entry["status"] = "failed"
                        entry["error"] = err
                        break
                    manifest = (image_dir / "index.json").read_text()
                    digests.append(hashlib.sha256(manifest.encode()).hexdigest())
                    if kind == "cold":
                        cold = round(seconds, 3)
                        continue
                    timings.append(seconds)
                    peaks.append(peak)
                else:
                    entry.update({
                        "status": "ok",
                        "wall-s": [round(t, 3) for t in timings],
                        "peak-kib": peaks,
                        "peak-note": "each run's own ru_maxrss (wait4 on its pid)",
                        "reproducible": len(set(digests)) == 1,
                    })
                    if cold is not None:
                        entry["cold-wall-s"] = cold
            else:
                # The design says: where there is no comparable mode, the table says so.
                entry["status"] = "not comparable: no like-for-like mode for this cell (design: benchmark cells)"
    for image_dir in WORK.glob("image-*"):
        shutil.rmtree(image_dir, ignore_errors=True)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    results["machine"]["loadavg_end"] = os.getloadavg()
    out_path.write_text(json.dumps(results, indent=1) + "\n")
    print("wrote %s" % out_path)
    for name in results["cells"]:
        e = results["cells"][name].get("oci-build", {})
        if e.get("status") == "ok":
            print("%-22s oci-build: %s s (median %s), peak %s KiB, reproducible: %s"
                  % (name, e["wall-s"], sorted(e["wall-s"])[len(e["wall-s"]) // 2], max(e["peak-kib"]), e["reproducible"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
