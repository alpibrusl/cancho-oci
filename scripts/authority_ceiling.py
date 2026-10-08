#!/usr/bin/env python3
"""G5: each binary's authority report against its committed ceiling (docs/design.md, section 2).

    authority_ceiling.py            check every [[bin]] of cancho.toml against ceilings/<name>.json
    authority_ceiling.py --update   rewrite the ceilings from the current reports (a deliberate act)
    authority_ceiling.py --selftest prove the gate can fail: a program that reads files must be refused

A report may be narrower than its ceiling, never wider: a new effect, a label whose argument is not
the ceiling's, or `bounded` turning false (foreign code reachable) fails. Widening the ceiling is a
change to ceilings/<name>.json in the same PR, so a reviewer sees it.
"""
import json, re, subprocess, sys, tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def bins():
    out, cur = [], None
    for line in (ROOT / "cancho.toml").read_text().splitlines():
        if line.strip() == "[[bin]]":
            cur = {}
            out.append(cur)
        elif line.strip().startswith("[["):
            cur = None
        elif cur is not None:
            m = re.match(r'\s*(\w+)\s*=\s*(.+?)\s*(#.*)?$', line)
            if m:
                cur[m.group(1)] = json.loads(m.group(2).replace("true", "true"))
    return out


def sources(b):
    files = []
    for s in b["sources"]:
        p = ROOT / s
        files += sorted(p.rglob("*.cho")) if p.is_dir() else [p]
    # A program that imports the TLS package is compiled with the project's installed libraries (`cancho install`
    # puts them in build/deps), so the report must be made over them too.
    if any(re.search(r"^import tls;", f.read_text(), re.M) for f in files):
        subprocess.run(["cancho", "install"], cwd=ROOT, capture_output=True, check=True)
        files += sorted((ROOT / "build" / "deps").glob("*.cho"))
    return [str(f) for f in files]


def report(files, std=True):
    cmd = ["cancho", "authority", *files] + (["--std"] if std else []) + ["--output", "json"]
    p = subprocess.run(cmd, capture_output=True, text=True, cwd=ROOT)
    if p.returncode not in (0,):
        sys.exit(f"cancho authority failed ({p.returncode}): {p.stderr.strip() or p.stdout.strip()}")
    return json.loads(p.stdout)


def snapshot(r):
    return {"bounded": r["bounded"], "effects": sorted(r["effects"]),
            "labels": sorted(({"name": l["name"], "argument": l["argument"]} for l in r["labels"]),
                             key=lambda l: (l["name"], str(l["argument"]))),
            "foreign_symbols": sorted(r["foreign_symbols"])}


def widened(cur, ceil):
    why = []
    if ceil["bounded"] and not cur["bounded"]:
        why.append("the report is no longer bounded (foreign code is reachable)")
    for e in cur["effects"]:
        if e not in ceil["effects"]:
            why.append(f"new effect `{e}`")
    allowed = {(l["name"], str(l["argument"])) for l in ceil["labels"]}
    for l in cur["labels"]:
        if (l["name"], str(l["argument"])) not in allowed:
            why.append(f"label `{l['name']}` with argument {l['argument']!r} is not in the ceiling")
    for s in cur["foreign_symbols"]:
        if s not in ceil["foreign_symbols"]:
            why.append(f"new foreign symbol `{s}`")
    return why


def check():
    bad = 0
    for b in bins():
        ceil_path = ROOT / "ceilings" / f"{b['name']}.json"
        if not ceil_path.exists():
            print(f"FAIL {b['name']}: no ceiling at {ceil_path.relative_to(ROOT)} (run with --update, then review it)")
            bad += 1
            continue
        cur = snapshot(report(sources(b), b.get("std", False)))
        why = widened(cur, json.loads(ceil_path.read_text()))
        if why:
            bad += 1
            print(f"FAIL {b['name']}: authority widened past its ceiling")
            for w in why:
                print(f"     {w}")
        else:
            print(f"ok   {b['name']}: effects {cur['effects'] or '[]'}, bounded={cur['bounded']}")
    return bad


def update():
    (ROOT / "ceilings").mkdir(exist_ok=True)
    for b in bins():
        snap = snapshot(report(sources(b), b.get("std", False)))
        (ROOT / "ceilings" / f"{b['name']}.json").write_text(json.dumps(snap, indent=2) + "\n")
        print(f"wrote ceilings/{b['name']}.json")


MUTANT = '''edition 5;
import std.io;
fn main(world: World) -> [] int {
    let Split { io, ffi, fs, heap, args, net, clock } = split(world);
    release(ffi); release(heap); release(args); release(net); release(clock); release(io);
    var n = 0;
    borrow fs as &f in {
        region a {
            let buf = alloc_slice[a](8, byte_of(0));
            n = fs_read(f, "/etc/hostname", buf);
        }
    }
    release(fs);
    return n;
}
'''


# No ceiling may ever grant these, whatever the JSON says: the tools build and inspect images, they do not
# listen on a network, run other programs, read the clock, handle signals, call foreign code or open files by path
# for writing (writes go through directory handles). Granting one means editing this list in the same PR.
FORBIDDEN = ("net", "conn_", "listen", "accept", "exec", "clock", "signals", "ffi", "fs_write", "udp", "poller")

# The only programs that may speak to a network, and the only effects they may have beyond the rest: dial out, read and
# write on what they dialled, and read the clock (a certificate's dates are checked against it). They may not listen,
# accept, resolve through a poller, or do anything else on the list.
NETWORK_CLIENTS = {"oci-push", "oci-pull", "oci-ref", "http-probe"}
CLIENT_EFFECTS = {"net_out", "conn_read", "conn_write", "clock"}


def forbidden_in(ceil, name=""):
    out = []
    for e in ceil["effects"]:
        if any(e.startswith(f) for f in FORBIDDEN):
            if name in NETWORK_CLIENTS and e in CLIENT_EFFECTS:
                continue
            out.append(e)
    return out


def selftest():
    """The gate must be able to fail: a program that reads a file is wider than tar-probe's console-only ceiling,
    and no committed ceiling grants a forbidden effect."""
    bad = 0
    for b in bins():
        ceil_b = json.loads((ROOT / "ceilings" / f"{b['name']}.json").read_text())
        forbidden = forbidden_in(ceil_b, b['name'])
        if forbidden:
            print(f"SELFTEST FAIL: the ceiling of {b['name']} grants forbidden effects {forbidden}")
            bad = 1
    # the network row of a client is allowed and must be visible in its ceiling: the reviewer sees `net_out ""`
    for b in bins():
        if b["name"] in NETWORK_CLIENTS:
            labels = json.loads((ROOT / "ceilings" / f"{b['name']}.json").read_text())["labels"]
            if not any(l["name"] == "net_out" for l in labels):
                print(f"SELFTEST FAIL: {b['name']} is a network client but its ceiling has no net_out row")
                bad = 1
    if bad:
        return 1
    ceil = json.loads((ROOT / "ceilings" / "tar-probe.json").read_text())
    with tempfile.TemporaryDirectory() as d:
        f = Path(d) / "mutant.cho"
        f.write_text(MUTANT)
        cur = snapshot(report([str(f)], True))
    why = widened(cur, ceil)
    if not why:
        print("SELFTEST FAIL: a program that reads a file was NOT refused; the gate cannot fail")
        return 1
    print("selftest ok: a file-reading program is refused:")
    for w in why:
        print(f"     {w}")
    return 0


if __name__ == "__main__":
    a = sys.argv[1:]
    if a == ["--update"]:
        update()
    elif a == ["--selftest"]:
        sys.exit(selftest())
    elif a == []:
        sys.exit(1 if check() else 0)
    else:
        sys.exit(__doc__)
