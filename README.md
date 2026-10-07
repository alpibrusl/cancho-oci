# cancho-oci

**Container images without a container daemon.** A tool written in [cancho](https://github.com/alpibrusl/cancho) that assembles an [OCI image](https://github.com/opencontainers/image-spec) from a static binary: a deterministic layer, a config, a manifest and an image layout, byte-for-byte the same every time it is built from the same inputs, and optionally pushed to a registry. No Docker, no shell, no `RUN` steps, and an authority report that says what the tool can reach.

**Status: alpha; `oci-build` works.** It builds a `FROM scratch` image from static executables and files, reproducibly, with an authority report that has no network. The pieces under it (the deterministic tar writer, the digest and write-once blob store, the image JSON writer, the ELF check) are each held to a differential test against an independent implementation and a mutation gate. Not yet: gzip layers (needed for full `crane` validation), multi-architecture indexes, a registry client, SBOM and signatures. There is no benchmark yet and no claim beyond what is written in `docs/design.md`. The plan and its tasks are in the epic (see the issues).

## Why

A cancho program is a static executable with a checkable authority report. The last step of shipping it, wrapping it in an image, usually means a daemon with root access, a base image pulled from a third party, and a build that is not reproducible. An OCI image is only a tar archive and a few JSON files addressed by their SHA-256, which is the same content-addressed shape cancho already uses. A small, auditable tool can produce it.

This is also a step in owning the whole path from source to a running service: compiler, libraries, product and now the artifact.

## Intended scope (v1)

- build a `FROM scratch` image from one or more static binaries and a few files (config, CA certificates), with an entrypoint, environment, user and labels;
- a deterministic tar layer: sorted entries, fixed timestamps, numeric owner zero, normalised modes;
- the OCI image layout on disk (`oci-layout`, `index.json`, `blobs/sha256/`), loadable by `skopeo`, `podman` and `docker load`;
- multi-architecture image indexes;
- push to and pull from a registry (OCI Distribution spec), with TLS and token authentication;
- provenance: an SBOM taken from the binary's authority report, and a signature, stored as OCI artifacts;
- operable by an agent: `introspect` and `skill`, errors as data with rule tags and repairs, and a `check` command that says what a build would produce without writing anything.

Not in v1: a container runtime, a Dockerfile interpreter or any `RUN` step, a daemon, Windows images, lazy-pulling formats, and keyless signing. The epic records each decision.

## What we expect, stated before measuring

Building an image is I/O and hashing, so the aim is parity with `crane` and `ko` on speed, and a result that is byte-identical across machines, which `docker build` does not give. We will measure against them with the cells fixed before the code, and report losses as plainly as wins.

## Open questions that the design must settle

- Layer compression: uncompressed tar is valid but large; gzip needs a DEFLATE encoder that cancho does not have yet; zstd comes later.
- The push path needs a TLS client; cancho's own TLS has not had its independent review, so the authority report for `push` may be unbounded until it has.
- How a registry address becomes a literal for capability narrowing (the same question as in cancho-dns).

## Building

```sh
git clone https://github.com/alpibrusl/cancho && git clone https://github.com/alpibrusl/cancho-oci
REV=$(sed -n 's/^cancho *= *"\([0-9a-f]*\)".*/\1/p' cancho-oci/cancho.toml)   # the compiler these sources were written for
(cd cancho && git checkout "$REV" && cargo build --release -p cancho)
export PATH="$PWD/cancho/target/release:$PATH"
cd cancho-oci && cancho build && cancho test
python3 scripts/authority_ceiling.py            # G5: authority within its committed ceiling
```

## Contributing

Design before code, in `docs/design.md`, with claims measured; a gate is fixed before the code it judges and must be able to fail; a claim that turns out false is corrected in place.

## Licence

[EUPL-1.2](LICENSE).
