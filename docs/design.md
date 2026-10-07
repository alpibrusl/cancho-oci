# cancho-oci: a deterministic OCI image builder in cancho

Status: **design, before any code** (epic #19, task #1). Every decision below gives the alternatives and the reason. Every claim about existing code names the file it was read from; a claim about an outside tool or standard is marked **(from memory of the spec, re-read in the task named)** and is not settled until that task reads the source. Things only the maintainer can decide are collected in section 10 and are not settled by default.

## 1. What this is for, and the claim it must survive

An OCI image is a tar archive per layer, a JSON config and a JSON manifest, each addressed by its SHA-256, plus an index. A `FROM scratch` image around one static binary is therefore a small pure function of its inputs. This project is that function, written in cancho, with no daemon, no shell, no `RUN` step and an authority report for each binary.

**The claim to survive, stated honestly:** two builds of the same inputs give the same digests, on any machine, *and* the `build` binary provably cannot reach the network.

**What is not unique about it (checked by reasoning, to be confirmed by measurement in #16):** `ko` and `crane` (go-containerregistry) already produce reproducible layers for `FROM scratch` images, and recent BuildKit can rewrite timestamps. Reproducibility alone is therefore **not** a differentiator against them, and this document does not claim it is. What is different:

1. **No Go toolchain and no dependency tree.** go-containerregistry is a large third-party tree; this is cancho code, pinned by content hash. This is the autonomy argument, not a quality argument.
2. **A bounded authority per binary.** `build` reaches files and no network; `push` reaches one registry. A bug in a manifest parser cannot turn into a reach to arbitrary hosts.
3. **Agent-operable by construction:** errors as data with rule tags, a `check` that says what a build would produce without writing.

If, when measured, none of these matters to anyone and `crane` is simply better, section 7 says the project stops.

## 2. The gates, fixed before the code

A gate is fixed before the code it judges and must be able to fail. The numbers below are **criteria**, not measurements; the baselines are measured in #16 *before* the `build` command (#7) is judged.

| # | Gate | Criterion | Can fail because |
|---|---|---|---|
| G1 | Reproducible | Same inputs: identical layer, config, manifest and index digests across **3 runs, 2 different runners, and a reordered input list** | a leaked timestamp, hash-ordered iteration or a locale-dependent sort changes a byte (mutants in #11) |
| G2 | Valid | `skopeo inspect oci:<dir>` and `crane validate --path <dir>` accept every output; `podman load` loads it and the entrypoint runs; `docker load` is **tested, not assumed** | any of the tools rejects it |
| G3 | Refuses by rule | Every refusal has a rule tag and a test that triggers exactly it | an untagged or untested refusal fails CI |
| G4 | No panic | A mutation fuzz over `pull`/`verify` input: truncated and oversized manifests, deep JSON, bad tar headers, path traversal in a layer, lying digests and sizes. Zero panics, every limit explicit | any input reaches a trap |
| G5 | Authority ceiling | Each binary's `cancho authority` output is compared to a committed ceiling; widening fails CI unless the ceiling changes in the same PR | the report grows |
| G6 | Speed (not a headline) | Median of **at least 5 runs, interleaved with the incumbent in the same session**, build wall time at most **1.5x** `crane append` and `ko build` on each cell below, **uncompressed-to-uncompressed**; peak RSS reported, not gated | any cell misses; the result then says which and by how much |

**Benchmark cells (pre-registered):** (a) one 5 MB static binary; (b) one 50 MB static binary; (c) 500 files totalling 20 MB. Cold and warm file cache. Same machine, configurations published. `crane` compresses with gzip by default, so the like-for-like comparison is against its uncompressed mode if it has one; where it does not, the table says "not comparable" instead of quoting a ratio. A gate's regression bound is measured against the build-to-build noise of identical sources (cancho-table `docs/numbers.md`), not guessed.

**Not compared:** registry push speed against a real registry over the internet (network-bound, not ours) and build speed of Dockerfiles (we do not interpret them).

## 3. Correctness gates (these come first)

1. **Differential tests against independent readers.** Every output is read by `skopeo`, `crane`, `oras` and `umoci`, and its layers by GNU `tar` and Python `tarfile`. A disagreement between them and us is a bug until shown to be theirs.
2. **Digests agree with `sha256sum`** on a corpus including empty, one-block and multi-gigabyte inputs (#4).
3. **Round trip against `registry:2`** (the reference registry): push, then `skopeo copy` back, compare digests (#9).
4. **The OCI Distribution conformance suite** run against our client (#14).

## 4. Scope of v1

In: a `FROM scratch` image from one or more static binaries and a few files, with entrypoint, cmd, env, user, workdir, labels and exposed ports; a deterministic layer; the OCI image layout on disk; multi-architecture indexes; push and pull; an SBOM and a signature as OCI artifacts; operable by an agent.

Out, each with a decision record in #18: a container runtime, a Dockerfile interpreter and any `RUN` step (it would turn a pure function into arbitrary code execution, and the reproducibility claim depends on refusing it), a daemon, Windows images, lazy-pulling formats, keyless signing, building on a base image (stage 2, #17).

## 5. Design

### 5.1 What cancho gives and does not give today (read from the code)

| Need | Status | Read from |
|---|---|---|
| SHA-256, streaming | **built**: `sha256_init`, `sha256_update`, `sha256_final`, plus one-shot `sha256` | `std/crypto.cho` |
| SHA-512 / SHA-384, streaming | built | `std/crypto.cho` |
| AES-GCM, ChaCha20-Poly1305 | built (relevant to TLS, not to this tool directly) | `std/aes.cho`, `std/gcm.cho`, `std/chacha20.cho` |
| ECDSA P-256 sign, Ed25519 | built | `std/ecdsa_sign.cho`, `std/ed25519.cho` |
| JSON parse (tape) and **writer** | built | `std/json.cho` (`writer`, `begin_object`, ...) |
| Directory handles, per-name kind (file, directory, link, other), dir-relative open | built | `std/dirs.cho` (`open_file`, `enter`, `kind_*`) |
| File reads and writes, append, fsync, atomic rename | built (slices 1 and 2) | `docs/file-writes.md` |
| HTTP request and response, TLS, X.509 | packages | `packages/http-request`, `packages/tls`, `packages/x509` |
| **tar** | **does not exist** | searched `std/`, `packages/`: no match |
| **DEFLATE / gzip** | **does not exist** | searched `std/`, `packages/`, `docs/`: only an incidental mention in `docs/wasm.md` |
| Create a directory | **does not exist** (no `mkdir` among the `dir_*` or `fs_*` builtins; the layout skeleton is the caller's) | `docs/directory-handles.md`, the builtin list in `examples/selfhost/tables.cho` |
| Read a file's mode / ELF header | **not checked** | an ELF parser is plain byte code; the file-mode read is a question for #3 |

A file written through `fs_write` gets mode `0644` (`docs/filesystem.md`), which does not matter here: modes in a layer are **decided by the builder**, not read from disk (5.3).

### 5.2 The image layout we write (from memory of the OCI image-spec 1.1, re-read in #5)

```
<out>/oci-layout            {"imageLayoutVersion":"1.0.0"}
<out>/index.json            the index: descriptors of manifests
<out>/blobs/sha256/<hex>    config, manifest(s), layer(s): every blob named by its digest
```

Media types in v1: `application/vnd.oci.image.manifest.v1+json`, `application/vnd.oci.image.config.v1+json`, `application/vnd.oci.image.index.v1+json`, and `application/vnd.oci.image.layer.v1.tar` (uncompressed) in M1; `.tar+gzip` after the DEFLATE task. `diff_ids` in the config are digests of the **uncompressed** layer, which matters once gzip exists.

**Canonical JSON.** The spec does not require a canonical form for manifests: a digest is over the exact bytes written. So determinism is *our* obligation: a fixed key order per object, no insignificant whitespace, integers only, no floats, UTF-8 without escapes beyond the required. We write through `std.json`'s writer; whether it preserves insertion order is read in #5 and, if not, we write the fixed order ourselves.

### 5.3 Determinism: exactly what is fixed

| Layer field | Value | Why |
|---|---|---|
| Entry order | byte-wise sorted by path, directories before their children | filesystem order is not stable |
| mtime | `0`, or `SOURCE_DATE_EPOCH` if set | any real time breaks G1 |
| uid / gid, names | `0` / `0`, empty | the build machine's user must not leak |
| mode | `0755` for entries named executable on the command line, `0644` for files, `0755` for directories | decided here, not read from disk |
| Header format | **ustar only**; names up to 100 bytes, or up to 155 + "/" + 100 with the prefix field | PAX headers add variable fields; v1 refuses a path that needs one (see 10) |
| Entry types | regular files and directories | a symlink or device in the input is refused, not followed |
| Duplicate paths | refused | |
| Padding and end of archive | two zero blocks, no extra padding | the spec for tar allows variation, so we pin it |

The config's `created` is omitted or fixed to the epoch value; `history` entries carry no time. These are the decisions G1's mutants attack: a swapped sort, a leaked mtime, a locale-dependent comparison, a hash-ordered map.

**Built and measured (task #3, `src/tar/tar.cho`).** The writer is a pure function, one 512-byte header at a time (`oci.tar.header`), with every function's effect row empty. It is held to three things:

- **Byte-identical to Python's `tarfile`** (`scripts/tar_diff.py`): about 1,000 random archives over four seeds, names at the edges of the 100-byte field and the 155 + 100 split, sizes and times up to the 11-digit ceiling, directories and executables. Python's `USTAR_FORMAT` is the independent writer; GNU or bsd `tar -t` and Python read every archive back, and file data is checked against its fixed pattern.
- **Twenty refusal cases**, each naming its rule tag (`tar-name-absolute`, `tar-name-component`, `tar-name-not-utf8`, `tar-name-nul`, `tar-name-too-long`, `tar-size-too-large`, `tar-time-out-of-range`, `tar-dir-has-size`, `tar-order`, `tar-duplicate`).
- **Fifteen mutants killed** (`scripts/tar_mutants.py`): a reversed sort, a leaked uid, a lost executable bit, a dropped directory slash, an off-by-one prefix limit, a checksum off by one, a lifted size ceiling, and the path-safety checks removed one at a time.

What building it found, each of which changed the design:

1. **Two deliberate differences from `tarfile`.** The device fields (`devmajor`, `devminor`) are zeros: older Pythons write `0000000` there and Python 3.14 writes NULs, and they mean nothing for a file or a directory, so the oracle normalises that one field and recomputes the checksum. And a name that `tarfile` can hold only as *the whole path in `prefix` with an empty `name` field* (a directory whose last component is longer than 99 bytes) is **refused** with `tar-name-too-long`: the header is legal but readers disagree about it.
2. **The split rule is `tarfile`'s:** the first `/` that leaves a prefix of at most 155 bytes and a non-empty rest of at most 100. Any valid split would do for a reader; this one is chosen so the oracle can compare bytes.
3. **macOS `bsdtar` hides a file whose basename starts with `._`** (AppleDouble metadata) from `tar -t`. Python and GNU tar list it. The generator avoids such names; it says nothing about `oci.tar`, but it is a trap for anyone verifying on a Mac.
4. **A one-shot `std.crypto.sha256` traps above about 64 KiB** (its message is copied into a 64 KiB arena; `std/crypto.cho` now also has `sha256_init`/`update`/`final`, which #4 uses). cancho-tools carries its own incremental hasher for the same reason.

**Built and measured (task #4, `src/digest/digest.cho`, `src/store/store.cho`).** `oci.digest` spells and parses `sha256:<64 lowercase hex>` strictly; `oci.store` is a write-once blob store under one `Dir`: `begin` creates a temporary name with `dir_open_new`, `write` appends and hashes the same bytes, `finish` syncs, closes and publishes with `dir_rename_new`, then syncs the directory. A digest already stored leaves the old blob untouched (same inode and mtime) and removes the new copy. The gate (`scripts/store_diff.py`, 988 checks):

- digests equal `sha256sum`'s for every length 0 to 300 (each padding case), the 64 KiB read-chunk boundaries, a few MiB, and a **4.5 GiB** file, past the 2^32-byte point where a 32-bit length counter would fail;
- `put` stores each file under its digest byte for byte and leaves nothing else in the store; a second `put` answers "existed" and rewrites nothing; a stale temporary from a crash does not block a write;
- `verify` refuses a flipped byte and a truncation (`blob-digest-mismatch`) and a missing blob (`blob-missing`); a malformed name is refused with `digest-hex` or `digest-length`, including every character just outside the hex ranges;
- `..`, a symlink, a link to a directory, a nested name and an absolute path never reach outside the root;
- 13 of 13 mutants killed (`scripts/store_mutants.py`); on Linux, `strace` shows `fsync -> renameat2(RENAME_NOREPLACE) -> fsync` (`scripts/store_syscalls.py`).

What building it found:

1. **`Split` has nine fields under `edition 7`** (`io, ffi, fs, heap, args, net, clock, signals, exec`), and `dir_rename_new` is edition 7. Releasing `exec` unused is a mechanical proof the binary cannot start another program, as releasing `net` is for the network. Editions are per file: `tar.cho` stays on 5 and the store on 7.
2. **`dir_rename_new` answers `ENOTSUP` on a filesystem that cannot do a no-replace rename** (95 on Linux, 45 on macOS). The store reports it as its own rule, `blob-publish-unsupported`, and publishes nothing, rather than risk replacing a blob.
3. **Speed, a number for #16.** Hashing 100 MiB takes about 0.43 s (about 240 MiB/s), against 0.22 s for `shasum -a 256` and 0.06 s for `openssl dgst -sha256` on the same Mac (hardware-accelerated). It is correct and fast enough for this task; it is not a win.
4. **Language facts that cost a compile each:** a variant of another module's enum is written `store.Began::Ok(...)`; byte slices cannot be compared with `==` (`digest.equal`); `copy_into` and other builtin names cannot be redefined; the one-shot `std.crypto.sha256` traps above about 64 KiB, so everything here uses `sha256_init`/`update`/`final`.

Not tested, and said so: a failing `fsync` or a failing `write` cannot be provoked from outside, so those branches need fault injection; the syscall order is observed on Linux only.

**Built and measured (task #5, `src/image/image.cho`).** `oci.image` writes the config, manifest, index and `oci-layout` as pure functions of their arguments: a fixed key order (the order of the calls), no whitespace, integers only, no `created` field. Lists reach it as one text, one item per line; a control character, an empty item, a bad `NAME=value`, a bad port, a repeated label name or port, an architecture other than `amd64`/`arm64`/`riscv64` and an OS other than `linux` are each refused with a rule tag. The gate (`scripts/image_check.py`, 1,417 checks over 80 random layouts, two seeds in CI):

- every document validates against the **official OCI image-spec v1.1.0 JSON Schemas**, vendored under `schemas/` (Apache-2.0);
- the chain is consistent: index to manifest to config and layer, each digest and size equal to the blob's own sha256 and length, `diff_ids` equal to the digest of the layer, and the store holds exactly those three blobs;
- the bytes equal what Python's `json.dumps(model, separators=(",", ":"), ensure_ascii=False)` writes for an independently built model, including Unicode and quote and backslash escaping;
- building twice in different directories gives identical files, and rebuilding in place replaces `index.json` atomically and changes nothing;
- `skopeo inspect` and `skopeo copy` (which re-verifies every digest) accept it, and `crane push` sends it to an in-memory registry (`crane registry serve`) where `crane validate --remote` accepts it and the registry's manifest digest equals the one we computed (CI; neither tool is installed on the Mac this was written on, so their first run is the Linux CI);
- 20 of 20 mutants killed (`scripts/image_mutants.py`).

What building it found:

1. **A real bug, caught by the byte-level model and by nothing else.** Two identical ports produced `{"1/udp":{},"1/udp":{}}`, a JSON object with a duplicate key. The schema validator accepted it (a parsed object silently drops the repeat) but readers disagree about such JSON. A repeated port or label name is now refused (`image-port`, `image-label`).
2. **cancho has no `mkdir`.** The `dir_*` builtins open, create files, rename, remove and sync, but nothing creates a directory, so `<image>/blobs/sha256` must exist before the tool runs (`refused: layout-skeleton` otherwise). `build` (#7) will need either that precondition, documented, or an upstream `dir_mkdir`. This is a gap to fix in cancho, not to work around with foreign code, which would make the authority report unbounded.
3. **cancho binaries are dynamic by default** (linked to libc only); a static one builds with a linker wrapper that adds `-static` (1.2 MB, "not a dynamic executable", per cancho's `docs/package-system.md`). The end-to-end gate of #7 builds `cancho-hooks` that way, because a `scratch` image has no libc.
4. **Owning a `File` discharges `file_write`** (and `dir_*` writes need `dir_write`): the compiler refused my first row for `write_file` as "declared but never performed". Rows are exact in both directions.
5. **`write_file` does not mint a heap**: the helper took a `Heap` it never used, which the compiler also refused; removing it made the function's authority smaller, not larger.

6. **`crane` cannot validate an uncompressed layer.** `crane validate --remote` opens each layer and assumes gzip, so our uncompressed `application/vnd.oci.image.layer.v1.tar` (which the spec allows and `skopeo` accepts) fails with `validating layers: gzip: invalid header`, while `--fast` (manifest, config and digest chain) passes and the registry reports our manifest digest unchanged. It is a limitation of that tool, but the most widely used one: **gzip is therefore not optional for v1** (#6), and design 5.6's "likely in v1" is now "in v1". The gate accepts exactly that message and no other, so it flips on its own when #6 lands.
7. **`crane validate --path` does not exist** (my memory of its flags was wrong; its docs say `--remote` and `--tarball`). `crane push PATH IMAGE` is what reads an OCI layout directory, so the check became a push to an in-memory registry followed by a remote validation: a stronger test than the one I first wrote, and a rehearsal of #9's round trip.

Not done, and said so: one layer only; no `created` time, no `author`, no `architecture` variants (design 5.4); the `docker load` and `podman` checks are task #7's, where a runnable binary exists.

**Built and measured (task #7: `src/elf`, `src/place`, `src/layer`, `src/build`).** `oci-build` turns static executables and files into a `FROM scratch` image:

```
oci-build --root <dir> --out <image-dir> --platform linux/<arch> --bin <src>:<dest> [--file <src>:<dest>]...
          [--entrypoint W]... [--cmd W]... [--env N=V]... [--label k=v]... [--port P/tcp]...
          [--user U] [--workdir D] [--ref TAG] [--source-date-epoch N]
```

Every `<src>` is opened beneath `--root` through a directory handle, so a path, a `..` or a symlink cannot reach outside it; the layer is streamed into the blob store (sources are measured first, so a bad path is refused before anything is written); the first `--bin` is the entrypoint unless one is given. The gate (`scripts/build_check.py`, 444 checks at 24 cases, 30 per seed in CI):

- **The layer equals Python's `tarfile`** (USTAR) for the same entries, byte for byte: implied parent directories, bytewise order, 0755 for executables and directories and 0644 for files, the chosen time, the real file contents including sizes at and around the 64 KiB read chunk, on all three architectures;
- the config, manifest and index equal the independent JSON model and validate against the OCI schemas; the digest chain is consistent; the printed digest is the index's;
- **building twice, in another directory and with every source file's time changed, gives identical bytes**: nothing about the build machine leaks;
- 46 refusal cases, each with its rule tag and the path it is about, and a refusal leaves no `index.json` and no temporary file: a dynamic executable, an executable for another architecture, a non-ELF `--bin`, a truncated ELF, 32-bit and big-endian ELF, a relocatable file, an unknown machine, a bad program-header size, count or offset, a missing source, a symlink or `..` out of the root, a duplicate or unsafe destination, a malformed `--bin`, an unknown flag, a bad platform or epoch, more than 64 entries, a missing layout skeleton. A **static-PIE** (an `ET_DYN` with a `PT_DYNAMIC` and no `PT_INTERP`) is accepted, because it runs without a loader;
- 31 of 31 mutants killed (`scripts/build_mutants.py`);
- **authority** (G5): the report of `oci-build` is bounded and lists only `args`, `dir_read`, `dir_write`, `err_write`, `file_read`, `file_write`, `fs_read("")` (to open the two roots), `heap` and `io_write`: **no network, no `exec`, no clock, no signals, no foreign code, and no path-based `fs_write`.** No committed ceiling may grant any of those; widening that list means editing `scripts/authority_ceiling.py` itself;
- in CI, on x86-64 Linux: the host-architecture image is loaded into Podman and run, and `oci-build` is linked statically (`scripts/static-cc`, cancho's own `-static` wrapper), packaged by itself, and run in a `scratch` container where it prints its own refusal.

What building it found:

1. **A loader is the test, not `PT_DYNAMIC`.** A static-PIE has a dynamic section and no interpreter and runs in `scratch`; refusing on `PT_DYNAMIC` would have rejected valid binaries.
2. **Order of checks matters for the message.** A short script is "not ELF", not "truncated" (the magic is checked as soon as four bytes exist), and an unsupported platform is refused before any source is read.
3. **For a bad destination the refusal names the first bad entry**, which may be an implied parent directory (`a/..`), not the whole argument.
4. **The mutation gate found a real hole in my tests twice:** a nested path after an implied directory (`a/b` then `a`) was untested, and an ELF bound that the next check also enforces was invisible from outside and needed the unit test. One mutant, `layer-source-changed` (a source changing between measuring and writing), cannot be provoked from outside and has none.
5. **Hand-made ELF executables** (`scripts/make_elf.py`: `exit(0)` as raw syscalls, no libc, one per architecture, plus dynamic and corrupted variants) made every ELF case testable without a Linux toolchain on a Mac, and are small enough to run in a real `scratch` container.
6. **Limits, chosen and enforced:** 64 entries and 8 KiB of names per layer, one layer, sources read twice (once to measure, once to write); an insertion sort is fine at that size.

Not run on the Mac this was written on, so CI is their first run: `skopeo` and `crane` on `oci-build`'s output, the Podman run, and the static self-packaging.

### 5.4 The static-binary check, and architecture

`build` reads the input binary's **ELF header** and program headers (plain byte parsing, no foreign code) and refuses a dynamic binary: a `PT_INTERP` means it needs a loader a `scratch` image does not have. (Built in task #7: the refusal `elf-dynamic` names the *entry*; naming the loader path and the `DT_NEEDED` libraries is not built.) `e_machine` gives the architecture (`x86-64` is `amd64`, `AArch64` is `arm64`, `RISC-V` is `riscv64`), so a binary that does not match `--platform` is refused. The builder is **architecture-independent**: it can package any ELF it can read, not only what cancho compiles to. cancho's compiler reaches `aarch64`, `riscv64` and `x64` (`docs/backend-limits.md` §1.3); a 32-bit ARM binary from another toolchain needs a variant (`v6`/`v7`) that is not in `e_machine`, so v1 refuses it unless `--variant` is given. Edge and IoT gateways are mostly `arm64` or `riscv64`, so multi-architecture (#8) is first-class, not an afterthought.

A non-root user needs a numeric `User` in the config (`65532`, say); an `/etc/passwd` entry is optional and supplied by the user as a file. **CA certificates are never bundled**: they come from a file the caller names, because a bundled bundle is a third-party dependency this project exists to avoid, and what to trust is a policy decision for the deployment.

### 5.5 Authority rows

`cancho authority` can narrow a capability to a **literal** only (`docs/authority.md` §2.3). Two consequences:

- **`build`.** Input and output paths are chosen at run time, so a report cannot say "only these files", the same point `docs/authority.md` makes for `lines.cho`. The better structure is a **directory capability**: `build` takes `--root <dir>` and reads through a `Dir` handle (`std/dirs.cho`: functions carry `[dir_read]` and open relative to the handle), so its reach is meant to be one directory tree, not the filesystem. A path like `../x`, a symlink inside the root, a link to a directory and a nested name are all **refused** (checked in task #4, `scripts/store_diff.py`, section 6 of the gate). A `Dir` **can** write (checked in task #4): `dir_open_new` (create, fails if present), `dir_rename`, `dir_rename_new` (a rename that never replaces), `dir_remove` and `dir_sync`, all `[dir_write]`. So the output directory is a `Dir` too, and `store-probe`'s report has `fs_read("")` only to open the root and **no `fs_write` at all**. **No network capability at all** in `build`: the report must not contain it, which is G5's ceiling.
- **`push` / `pull`.** The registry host and port are run-time values, so narrowing to one host is not provable from the report. This is exactly cancho-dns#1's open question (its design doc is not written yet). The options: (a) **generated, compiled-in registry** (one small binary per registry: an exact proof, many binaries); (b) **coarse `net_out` plus an allowlist enforced in code** (one binary, the report is honest but weaker); (c) both, with (b) as the default and (a) available. **Recommendation: (c)**, decided together with cancho-dns so the two projects say the same thing.

`build` and `push` are separate binaries, so the one that touches the network never sees file paths it does not need, and the one that touches files never reaches the network.

### 5.6 Compression

`std` has no DEFLATE. Uncompressed layers are valid OCI (`application/vnd.oci.image.layer.v1.tar`), so **M1 ships uncompressed** and everything else (G1, G2, signatures, push) can be built and measured without a compressor. A DEFLATE encoder is a separate, gated task (#6): stored blocks first (trivially correct, no size gain, needed for the gzip framing), then fixed Huffman, then dynamic only if measured size justifies it, always deterministic (no timestamp in the gzip header, fixed OS byte). Size matters for the intended edge targets, where bandwidth is the constraint, and `crane` rejects uncompressed layers in a full validation (5.3, task #5), so #6 is **in v1, not optional**, but it must not block the core. Its gate states the loss against `gzip -9` and `zopfli` plainly; a first encoder will lose.

### 5.7 Registry client (from memory of the Distribution spec 1.1, re-read in #9)

Push and pull over HTTPS using `packages/http-request` on `packages/tls`: bearer-token flow (the registry answers 401 with a realm, the client fetches a token, retries), `HEAD` for blob existence, monolithic upload for small blobs and chunked for large, cross-repository mount, `Content-Digest` checked on **every** blob read, a manifest size cap before parsing. Refusals: digest mismatch, a redirect to another host unless decided otherwise (see 10), a token endpoint on another host, an oversized manifest.

**The TLS question.** cancho has its own TLS (`packages/tls`, `packages/x509`, on `std` crypto), so `push` can have **no foreign code and a bounded authority report**. It has **not had its independent review** (cancho's #209): until it does, the doc and README may say "no foreign code" and must not say "audited". Interop with a real registry (`ghcr.io`) is part of G2/#9, not assumed.

### 5.8 Provenance

An SBOM and a signature are attached to an image as OCI artifacts, through the **referrers API** (a manifest with a `subject` field, listed by `GET /v2/<name>/referrers/<digest>`), with the **tag-schema fallback** for registries that lack it. The SBOM's content comes from the binary's **authority report** and the dependency hashes the project pins, which is something no other image tool can say about a cancho program. Signature: over the manifest digest, **ECDSA P-256 or Ed25519** (both in `std`; see 10), with a `verify` command that needs no network. Interoperability with `cosign` is a goal **only if tested**; until then the doc says what interoperates and what does not.

## 6. Plan, each step with its own gate

| Step | Issue | Gate |
|---|---|---|
| M0 | #2 scaffold | CI green on an empty program that prints its authority report |
| M1a | #3 tar | G1 on layers alone; GNU `tar` and Python `tarfile` list exactly the entries; mutants killed |
| M1b | #4 digests | agree with `sha256sum` on the corpus |
| M1c | #5 layout | G2: `skopeo`, `crane`, `podman load` accept; manifest digest stable |
| M1d | #7 build | G1 end to end; run the `cancho-hooks` release binary in `podman` and its health endpoint answers |
| M2 | #6 gzip | round trip exact on the corpus; sizes vs `gzip -9`, stated |
| M3 | #8 index | `crane manifest` shows both platforms |
| M4 | #9 push/pull | round trip with `registry:2`, then `ghcr.io` |
| M5 | #10 #11 | G5 ceiling and G1 across two runners in CI |
| M6 | #12 | SBOM validates against its format's schema; `verify` works offline |
| M7 | #13 #14 #15 | agent contract, conformance table, G4 |
| M8 | #16 | G6 measured, results published including losses |

## 7. What would make this project not worth continuing

- `crane` or `ko` already do everything this does, and the autonomy and authority arguments in section 1 interest nobody (including the maintainer). Then the honest end state is "use `crane`" and a short note saying so.
- Reproducibility cannot be made to hold across two runners after the obvious sources are removed: that would mean something in the toolchain, not the design, is non-deterministic, and the headline claim is not ours to make.
- `cancho` TLS never passes review and OpenSSL stays: `push` is then unbounded and loses half its point, though `build` still stands.
- The DEFLATE encoder cannot get within a stated factor of `gzip -9` and size matters for the target devices: then v1 ships uncompressed and says so.

## 8. Risks

- **A moving compiler.** The compiler revision is part of the contract (as in `cancho-cache`); `cancho.toml` pins it and CI checks they agree. Reproducibility of the *image* does not imply reproducibility of the *binary*: the second is cancho's, not ours.
- **Spec drift.** The image-spec and distribution-spec move; every spec statement here is re-read from the pinned version in the task that uses it.
- **Registry quirks.** Real registries diverge from the spec; the conformance table (#14) will list them.

## 9. Decisions this document makes, and why

1. **Separate `build` and `push` binaries**: the authority of one must not include the other's.
2. **Modes, owners and times are set by the builder, never read from disk.**
3. **ustar only in v1**, refusing what needs PAX, to keep the byte layout pinned.
4. **Uncompressed first, gzip second**, so nothing waits on a compressor.
5. **No bundled CA certificates and no base image.**
6. **ELF check in `build`**: a dynamic binary is refused with the missing libraries named.

## 10. For the maintainer to decide (not settled here)

1. **Registry address and capability narrowing**: (a) generated per-registry binary, (b) coarse plus in-code allowlist, (c) both. Recommended (c); decide together with cancho-dns#1.
2. **PAX headers**: refuse long paths in v1 (recommended) or support PAX for them.
3. **SBOM format**: SPDX or CycloneDX. Recommended CycloneDX (smaller JSON, room for authority properties); SPDX is the more widely required by procurement.
4. **Signature algorithm**: ECDSA P-256 (the likely `cosign` interop path) or Ed25519 (simpler). Recommended P-256 if interop is a goal, otherwise Ed25519.
5. **Redirects on blob download**: registries commonly redirect to a CDN on another host; allow with the digest check as the safeguard (recommended) or refuse.
6. **`docker load` as a gate or a best effort**: support for loading OCI layouts has varied across Docker versions; recommended best effort, with `podman` as the gate.
7. **Whether the first real consumer is `cancho-hooks`** (its release workflow already builds tarballs and an image), recommended, so the first gate runs on something real.
