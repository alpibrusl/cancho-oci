#!/usr/bin/env python3
"""Mutation gate for `oci-hostile` (design 5.8; task #12): break oci.sign and the CLI on purpose and require
scripts/hostile_check.py to notice. A survivor is a behaviour nothing tests.

    sign_mutants.py [--jobs N]

Each mutant is one textual edit of one source file, built into a temporary oci-hostile; the edit must apply exactly once.
"""
import subprocess, sys, tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LIBS = ["digest", "store", "image", "layout", "http", "secure", "registry", "sign"]
FILES = {"digest": "src/digest/digest.cho", "store": "src/store/store.cho", "image": "src/image/image.cho", "layout": "src/layout/layout.cho",
         "http": "src/http/http.cho", "secure": "src/secure/secure.cho", "registry": "src/registry/registry.cho", "sign": "src/sign/sign.cho",
         "refcli": "src/refcli/main.cho", "pullcli": "src/pullcli/main.cho", "probemain": "tests/probe/http/main.cho"}

MUTANTS = [
    ("http", "a timed-out wait taken for ready", "        } else if n == 0 {\n            answer = 0;", "        } else if n == 0 {\n            answer = 1;"),
    ("http", "a read that would wait gives up at once", "                Received::Again => {\n                    let w = wait_for(conn, 1);\n                    if w == 0 {\n                        st[10] = refused_timeout();\n                        return 0 - 1;\n                    }\n                    if w < 0 {\n                        return 0 - 1;\n                    }\n                }\n                Received::Failed(errno) => {\n                    return 0 - 1;\n                }\n            }\n        }\n        return 0 - 1;", "                Received::Again => {\n                    return 0 - 1;\n                }\n                Received::Failed(errno) => {\n                    return 0 - 1;\n                }\n            }\n        }\n        return 0 - 1;"),
    ("http", "a timeout while reading the head reported as truncation", "            if contents(tr)[10] == refused_timeout() {\n                code = refused_timeout();", "            if contents(tr)[10] == 12345 {\n                code = refused_timeout();"),
    ("http", "a timeout while reading a body reported as truncation", "            if contents(tr)[10] == refused_timeout() {\n                result = refused_timeout();", "            if contents(tr)[10] == 12345 {\n                result = refused_timeout();"),
    ("http", "the idle time ignored", "        let n = poller_wait(conn.poller, out, conn.idle);", "        let n = poller_wait(conn.poller, out, 100000);"),
]


def build(paths, out):
    deps = sorted(str(p) for p in (ROOT / "build" / "deps").glob("*.cho"))
    return subprocess.run(["cancho", "build", *paths, *deps, "--std", "-o", str(out)], capture_output=True, text=True)


def try_mutant(i, sources, tmp):
    which, label, old, new = MUTANTS[i]
    if sources[which].count(old) != 1:
        return label, f"broken: anchor found {sources[which].count(old)} times in {which}, expected once"
    m = tmp / f"m{i}"
    m.mkdir()
    written = {}
    for k in FILES:
        f = m / f"{k}.cho"
        f.write_text(sources[k].replace(old, new) if k == which else sources[k])
        written[k] = str(f)
    probe, pull, ref = m / "http-probe", m / "oci-pull", m / "oci-ref"
    builds = [build([written[k] for k in LIBS] + [written["probemain"]], probe), build([written[k] for k in LIBS] + [written["pullcli"]], pull), build([written[k] for k in LIBS] + [written["refcli"]], ref)]
    bad = [b for b in builds if b.returncode != 0]
    if bad:
        return label, f"broken: the mutant does not build ({bad[0].stderr.strip()[:140]})"
    try:
        r = subprocess.run([sys.executable, str(ROOT / "scripts/hostile_check.py"), "--quick", "--probe", str(probe), "--pull", str(pull), "--ref", str(ref)], capture_output=True, text=True, timeout=400)
    except subprocess.TimeoutExpired:
        return label, "killed"
    return label, "killed" if r.returncode != 0 else "survived"


def main():
    jobs = int(sys.argv[sys.argv.index("--jobs") + 1]) if "--jobs" in sys.argv else 4
    sources = {k: (ROOT / p).read_text() for k, p in FILES.items()}
    survived, broken = [], []
    with tempfile.TemporaryDirectory() as d, ThreadPoolExecutor(max_workers=jobs) as pool:
        futures = [pool.submit(try_mutant, i, sources, Path(d)) for i in range(len(MUTANTS))]
        for f in futures:
            label, verdict = f.result()
            if verdict.startswith("broken"):
                broken.append(f"{label}: {verdict}")
            else:
                print(f"{'killed  ' if verdict == 'killed' else 'SURVIVED'} {label}", flush=True)
                if verdict == "survived":
                    survived.append(label)
    for line in broken:
        print(f"BROKEN   {line}")
    print(f"{len(MUTANTS) - len(survived) - len(broken)}/{len(MUTANTS)} mutants killed, {len(survived)} survived, {len(broken)} broken")
    return 1 if survived or broken else 0


if __name__ == "__main__":
    sys.exit(main())
