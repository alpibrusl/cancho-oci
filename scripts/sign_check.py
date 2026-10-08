#!/usr/bin/env python3
"""Gate for `oci-sign` (design 5.8; task #12): Ed25519 signatures over a manifest digest, checked against OpenSSL.

  1. public keys: `oci-sign pubkey` equals OpenSSL's for the same seed (PKCS#8 built from the seed);
  2. signatures: ours are **byte for byte** the signature OpenSSL makes over the same message (Ed25519 is deterministic),
     and OpenSSL's `pkeyutl -verify` accepts ours; a signature file made by OpenSSL is accepted by `verify`;
  3. determinism: the same key and digest give the same file, in another directory;
  4. refusals, each with its rule tag and **nothing written**: a signature file that is not JSON, has a member missing,
     added or repeated, has a wrong type, algorithm, key id or digest, signs another digest, was made by another key,
     has a flipped bit anywhere in its signature (every one of 512), upper-case or short hex, is empty or over 4 KiB;
     a bad seed or public key file; an unknown flag or mode; `--image` and `--digest` together or neither; a layout with
     no entry or two;
  5. the message is domain-separated: a signature over the bare digest does not verify.

    sign_check.py [--sign build/oci-sign] [--seed S]
"""
import argparse, hashlib, json, os, random, shutil, subprocess, sys, tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
bad = 0
checks = 0
notes = []


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


def run(cmd, **kw):
    p = subprocess.run([str(c) for c in cmd], capture_output=True, **kw)
    return p.returncode, p.stdout, p.stderr


def text(cmd, **kw):
    c, o, e = run(cmd, text=True, **kw)
    return c, o.strip(), e.strip()


PKCS8 = bytes.fromhex("302e020100300506032b657004220420")
SPKI = bytes.fromhex("302a300506032b6570032100")


def pem(label, der):
    import base64
    b = base64.b64encode(der).decode()
    return f"-----BEGIN {label}-----\n" + "\n".join(b[i:i + 64] for i in range(0, len(b), 64)) + f"\n-----END {label}-----\n"


def message(digest):
    return b"cancho-oci signature v1\n" + digest.encode() + b"\n"


def doc(digest, keyid, sig, **over):
    d = {"type": "cancho-oci.signature.v1", "digest": digest, "alg": "ed25519", "keyid": keyid, "signature": sig}
    d.update(over)
    return json.dumps(d, separators=(",", ":"))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sign", default=str(ROOT / "build" / "oci-sign"))
    ap.add_argument("--seed", type=int, default=1)
    a = ap.parse_args()
    S = a.sign
    rng = random.Random(a.seed)
    if not shutil.which("openssl"):
        print("SKIP: openssl is needed as the independent oracle")
        return 1
    with tempfile.TemporaryDirectory() as t:
        t = Path(t)

        def openssl_sign(seed, msg):
            (t / "k.pem").write_text(pem("PRIVATE KEY", PKCS8 + seed))
            (t / "m.bin").write_bytes(msg)
            c, o, e = run(["openssl", "pkeyutl", "-sign", "-rawin", "-inkey", t / "k.pem", "-in", t / "m.bin"])
            assert c == 0, e
            return o

        def openssl_pub(seed):
            (t / "k.pem").write_text(pem("PRIVATE KEY", PKCS8 + seed))
            c, o, e = run(["openssl", "pkey", "-in", t / "k.pem", "-pubout", "-outform", "DER"])
            assert c == 0, e
            return o[-32:]

        def openssl_verify(pub, msg, sig):
            (t / "p.pem").write_text(pem("PUBLIC KEY", SPKI + pub))
            (t / "m.bin").write_bytes(msg)
            (t / "s.bin").write_bytes(sig)
            c, o, e = run(["openssl", "pkeyutl", "-verify", "-rawin", "-pubin", "-inkey", t / "p.pem", "-in", t / "m.bin", "-sigfile", t / "s.bin"])
            return c == 0

        for n in range(24):
            seed = rng.randbytes(32) if hasattr(rng, "randbytes") else bytes(rng.randrange(256) for _ in range(32))
            if n == 0:
                seed = bytes(32)
            if n == 1:
                seed = b"\xff" * 32
            d = f"c{n}"
            (t / d).mkdir()
            sf, pf = t / d / "seed", t / d / "pub"
            sf.write_text(seed.hex() + ("\n" if n % 2 else ""))
            digest = "sha256:" + hashlib.sha256(bytes([n])).hexdigest()
            c, out, err = text([S, "pubkey", "--seed-file", sf])
            pub = openssl_pub(seed)
            if not ok(c == 0 and out == pub.hex(), f"key {n}: pubkey {out!r} != OpenSSL's {pub.hex()!r} {err!r}"):
                continue
            pf.write_text(out + "\n")
            keyid = hashlib.sha256(pub).hexdigest()
            outdir = t / d / "out"
            outdir.mkdir()
            c, out, err = text([S, "sign", "--seed-file", sf, "--digest", digest, "--out-dir", outdir])
            sigfile = outdir / f"sha256-{digest[7:]}.sig.json"
            if not ok(c == 0 and sigfile.exists(), f"key {n}: sign refused: {err!r}"):
                continue
            raw = sigfile.read_bytes()
            parsed = json.loads(raw)
            sig = bytes.fromhex(parsed["signature"])
            ok(list(parsed) == ["type", "digest", "alg", "keyid", "signature"] and raw == doc(digest, keyid, sig.hex()).encode(), f"key {n}: the file is not the model: {raw!r}")
            ok(sig == openssl_sign(seed, message(digest)), f"key {n}: our signature is not OpenSSL's, byte for byte")
            ok(openssl_verify(pub, message(digest), sig), f"key {n}: OpenSSL refuses our signature")
            c, out, err = text([S, "verify", "--pub-file", pf, "--digest", digest, "--sig", sigfile])
            ok(c == 0 and out == f"verified {digest} by {keyid}", f"key {n}: verify of our own file: {c} {out!r} {err!r}")
            # a file made by OpenSSL
            ofile = t / d / "openssl.json"
            ofile.write_text(doc(digest, keyid, openssl_sign(seed, message(digest)).hex()))
            c, out, err = text([S, "verify", "--pub-file", pf, "--digest", digest, "--sig", ofile])
            ok(c == 0, f"key {n}: a signature OpenSSL made was refused: {err!r}")
            # determinism: another directory, the same bytes
            outdir2 = t / d / "out2"
            outdir2.mkdir()
            text([S, "sign", "--seed-file", sf, "--digest", digest, "--out-dir", outdir2])
            ok((outdir2 / sigfile.name).read_bytes() == raw, f"key {n}: signing twice gave different bytes")

            if n != 0:
                continue
            # ---- refusals, on key 0
            def refuse(label, tag, sigtext=None, digest_arg=digest, pub_file=pf, raw_bytes=None):
                f = t / "case.json"
                f.write_bytes(raw_bytes if raw_bytes is not None else sigtext.encode())
                c, o, e = text([S, "verify", "--pub-file", pub_file, "--digest", digest_arg, "--sig", f])
                ok(c == 1 and f"refused: {tag}" in e, f"refusal {label}: expected {tag}, got {c} {o!r} {e!r}")

            good_sig = sig.hex()
            refuse("not JSON", "sign-format", "not json")
            refuse("empty", "sign-signature-file", raw_bytes=b"")
            refuse("over 4 KiB", "sign-signature-file", raw_bytes=b" " * 5000)
            refuse("a member missing", "sign-format", json.dumps({"type": "cancho-oci.signature.v1", "digest": digest, "alg": "ed25519", "keyid": keyid}))
            refuse("a member added", "sign-format", doc(digest, keyid, good_sig, extra="x"))
            refuse("a member repeated", "sign-format", '{"type":"cancho-oci.signature.v1","digest":"%s","alg":"ed25519","keyid":"%s","keyid":"%s"}' % (digest, keyid, keyid))
            refuse("a wrong type", "sign-format", doc(digest, keyid, good_sig, type="cosign"))
            refuse("a wrong algorithm", "sign-format", doc(digest, keyid, good_sig, alg="ecdsa"))
            refuse("a wrong key id", "sign-keyid", doc(digest, "0" * 64, good_sig))
            refuse("upper-case key id", "sign-keyid", doc(digest, keyid.upper(), good_sig))
            other = "sha256:" + hashlib.sha256(b"another").hexdigest()
            refuse("a file for another digest", "sign-subject", doc(other, keyid, good_sig))
            refuse("the right file for another digest asked", "sign-subject", doc(digest, keyid, good_sig), digest_arg=other)
            refuse("upper-case signature", "sign-format", doc(digest, keyid, good_sig.upper()))
            refuse("a short signature", "sign-format", doc(digest, keyid, good_sig[:-2]))
            refuse("a long signature", "sign-format", doc(digest, keyid, good_sig + "00"))
            refuse("a non-hex signature", "sign-format", doc(digest, keyid, "zz" + good_sig[2:]))
            refuse("the signature over the bare digest (no domain separation)", "sign-bad-signature",
                   doc(digest, keyid, openssl_sign(seed, digest.encode()).hex()))
            refuse("the signature of another message", "sign-bad-signature", doc(digest, keyid, openssl_sign(seed, message(other)).hex()))
            # another key
            seed2 = bytes([7]) * 32
            (t / "seed2").write_text(seed2.hex())
            c, pub2, e = text([S, "pubkey", "--seed-file", t / "seed2"])
            (t / "pub2").write_text(pub2)
            refuse("a file signed by another key, read with the first key", "sign-keyid", doc(digest, hashlib.sha256(bytes.fromhex(pub2)).hexdigest(), openssl_sign(seed2, message(digest)).hex()))
            refuse("the first key's file, read with another key", "sign-keyid", doc(digest, keyid, good_sig), pub_file=t / "pub2")
            # every bit of the signature
            flipped = 0
            for bit in range(512):
                s = bytearray(sig)
                s[bit // 8] ^= 1 << (bit % 8)
                f = t / "flip.json"
                f.write_text(doc(digest, keyid, bytes(s).hex()))
                c, o, e = text([S, "verify", "--pub-file", pf, "--digest", digest, "--sig", f])
                if c == 1 and "sign-bad-signature" in e:
                    flipped += 1
            ok(flipped == 512, f"only {flipped} of 512 single-bit changes of the signature were refused as a bad signature")

            # ---- the layout form
            lay = t / "layout"
            (lay / "blobs" / "sha256").mkdir(parents=True)
            (lay / "index.json").write_text(json.dumps({"schemaVersion": 2, "manifests": [{"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": digest, "size": 1}]}))
            c, o, e = text([S, "verify", "--pub-file", pf, "--image", lay, "--sig", sigfile])
            ok(c == 0, f"verify with --image: {e!r}")
            od = t / "lay-out"
            od.mkdir()
            c, o, e = text([S, "sign", "--seed-file", sf, "--image", lay, "--out-dir", od])
            ok(c == 0 and (od / sigfile.name).read_bytes() == raw, f"sign with --image: {e!r}")
            for label, content in [("no entry", {"schemaVersion": 2, "manifests": []}), ("two entries", {"schemaVersion": 2, "manifests": [{"digest": digest}, {"digest": other}]}),
                                   ("a bad digest", {"schemaVersion": 2, "manifests": [{"digest": "sha256:xyz"}]}), ("no manifests", {"schemaVersion": 2})]:
                (lay / "index.json").write_text(json.dumps(content))
                od2 = t / "lay-out2"
                od2.mkdir(exist_ok=True)
                c, o, e = text([S, "sign", "--seed-file", sf, "--image", lay, "--out-dir", od2])
                ok(c == 1 and "refused: sign-image" in e and not list(od2.iterdir()), f"a layout with {label}: {c} {e!r} {list(od2.iterdir())}")
            (lay / "index.json").write_text("{bad")
            c, o, e = text([S, "sign", "--seed-file", sf, "--image", lay, "--out-dir", od2])
            ok(c == 1 and "refused:" in e and not list(od2.iterdir()), f"a layout with a broken index.json: {c} {e!r}")
            c, o, e = text([S, "sign", "--seed-file", sf, "--image", t / "nowhere", "--out-dir", od2])
            ok(c == 1 and "sign-image" in e, f"a missing layout: {c} {e!r}")

            # ---- command line and key files
            empty = t / "empty-out"
            empty.mkdir()
            def cli(label, args, tag):
                c, o, e = text([S, *args])
                ok(c == 1 and f"refused: {tag}" in e, f"{label}: expected {tag}, got {c} {o!r} {e!r}")
            cli("no mode", [], "sign-mode")
            cli("an unknown mode", ["frobnicate"], "sign-mode")
            cli("an unknown flag", ["sign", "--frob", "x"], "sign-flag")
            cli("a trailing flag", ["sign", "--seed-file"], "sign-flag")
            cli("both --image and --digest", ["sign", "--seed-file", sf, "--image", lay, "--digest", digest, "--out-dir", empty], "sign-flag")
            cli("neither --image nor --digest", ["sign", "--seed-file", sf, "--out-dir", empty], "sign-missing")
            cli("a bad digest", ["sign", "--seed-file", sf, "--digest", "sha256:xyz", "--out-dir", empty], "sign-digest")
            cli("verify of a bad digest", ["verify", "--pub-file", pf, "--digest", "sha256:xyz", "--sig", sigfile], "sign-digest")
            cli("verify of an upper-case digest", ["verify", "--pub-file", pf, "--digest", "sha256:" + "A" * 64, "--sig", sigfile], "sign-digest")
            cli("an upper-case digest", ["sign", "--seed-file", sf, "--digest", "sha256:" + "A" * 64, "--out-dir", empty], "sign-digest")
            cli("no seed file", ["sign", "--digest", digest, "--out-dir", empty], "sign-missing")
            cli("no out dir", ["sign", "--seed-file", sf, "--digest", digest], "sign-missing")
            cli("pubkey without a seed", ["pubkey"], "sign-missing")
            cli("verify without a signature", ["verify", "--pub-file", pf, "--digest", digest], "sign-missing")
            cli("an out dir that is not there", ["sign", "--seed-file", sf, "--digest", digest, "--out-dir", t / "none"], "sign-io")
            cli("a signature file that is not there", ["verify", "--pub-file", pf, "--digest", digest, "--sig", t / "none"], "sign-signature-file")
            for label, content in [("empty", ""), ("short", "ab" * 31), ("long", "ab" * 33), ("upper-case", "AB" * 32), ("non-hex", "zz" * 32), ("spaces inside", "ab " * 21 + "ab")]:
                bf = t / "badkey"
                bf.write_text(content)
                cli(f"a seed file that is {label}", ["pubkey", "--seed-file", bf], "sign-key-file")
                cli(f"a public key file that is {label}", ["verify", "--pub-file", bf, "--digest", digest, "--sig", sigfile], "sign-key-file")
            cli("a missing seed file", ["pubkey", "--seed-file", t / "none"], "sign-key-file")
            ok(not list(empty.iterdir()), f"a refused sign wrote files: {list(empty.iterdir())}")
    print(f"{'FAIL' if bad else 'ok'}: {checks} checks, {bad} failure(s)")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
