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
| Header format | **ustar only**; names up to 100 bytes, or 255 with the prefix field | PAX headers add variable fields; v1 refuses a path that needs one (see 10) |
| Entry types | regular files and directories | a symlink or device in the input is refused, not followed |
| Duplicate paths | refused | |
| Padding and end of archive | two zero blocks, no extra padding | the spec for tar allows variation, so we pin it |

The config's `created` is omitted or fixed to the epoch value; `history` entries carry no time. These are the decisions G1's mutants attack: a swapped sort, a leaked mtime, a locale-dependent comparison, a hash-ordered map.

### 5.4 The static-binary check, and architecture

`build` reads the input binary's **ELF header** and program headers (plain byte parsing, no foreign code) and refuses a dynamic binary: a `PT_INTERP` or a `DT_NEEDED` entry means it would need libraries a `scratch` image does not have, and the refusal names them. `e_machine` gives the architecture (`x86-64` is `amd64`, `AArch64` is `arm64`, `RISC-V` is `riscv64`), so a binary that does not match `--platform` is refused. The builder is **architecture-independent**: it can package any ELF it can read, not only what cancho compiles to. cancho's compiler reaches `aarch64`, `riscv64` and `x64` (`docs/backend-limits.md` §1.3); a 32-bit ARM binary from another toolchain needs a variant (`v6`/`v7`) that is not in `e_machine`, so v1 refuses it unless `--variant` is given. Edge and IoT gateways are mostly `arm64` or `riscv64`, so multi-architecture (#8) is first-class, not an afterthought.

A non-root user needs a numeric `User` in the config (`65532`, say); an `/etc/passwd` entry is optional and supplied by the user as a file. **CA certificates are never bundled**: they come from a file the caller names, because a bundled bundle is a third-party dependency this project exists to avoid, and what to trust is a policy decision for the deployment.

### 5.5 Authority rows

`cancho authority` can narrow a capability to a **literal** only (`docs/authority.md` §2.3). Two consequences:

- **`build`.** Input and output paths are chosen at run time, so a report cannot say "only these files", the same point `docs/authority.md` makes for `lines.cho`. The better structure is a **directory capability**: `build` takes `--root <dir>` and reads through a `Dir` handle (`std/dirs.cho`: functions carry `[dir_read]` and open relative to the handle), so its reach is meant to be one directory tree, not the filesystem. **Not checked:** whether a path like `../x` is refused by `open_file`/`enter`; #3 reads it before this is claimed. Whether a `Dir` can also write, for the output directory, is **not checked**; if not, the output uses `fs_write` and the report says so. **No network capability at all** in `build`: the report must not contain it, which is G5's ceiling.
- **`push` / `pull`.** The registry host and port are run-time values, so narrowing to one host is not provable from the report. This is exactly cancho-dns#1's open question (its design doc is not written yet). The options: (a) **generated, compiled-in registry** (one small binary per registry: an exact proof, many binaries); (b) **coarse `net_out` plus an allowlist enforced in code** (one binary, the report is honest but weaker); (c) both, with (b) as the default and (a) available. **Recommendation: (c)**, decided together with cancho-dns so the two projects say the same thing.

`build` and `push` are separate binaries, so the one that touches the network never sees file paths it does not need, and the one that touches files never reaches the network.

### 5.6 Compression

`std` has no DEFLATE. Uncompressed layers are valid OCI (`application/vnd.oci.image.layer.v1.tar`), so **M1 ships uncompressed** and everything else (G1, G2, signatures, push) can be built and measured without a compressor. A DEFLATE encoder is a separate, gated task (#6): stored blocks first (trivially correct, no size gain, needed for the gzip framing), then fixed Huffman, then dynamic only if measured size justifies it, always deterministic (no timestamp in the gzip header, fixed OS byte). Size matters for the intended edge targets, where bandwidth is the constraint, so #6 is **likely in v1, not optional**, but it must not block the core. Its gate states the loss against `gzip -9` and `zopfli` plainly; a first encoder will lose.

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
