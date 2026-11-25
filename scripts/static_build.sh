#!/bin/sh
# Build oci-build as a static executable: build/oci-build-static. Needs a static libc (libc.a).
# The source list is read from cancho.toml (the [[bin]] named oci-build), not repeated here, so the two cannot drift.
set -eu
cd "$(dirname "$0")/.."
mkdir -p build
FILES=$(python3 - <<'PY'
import sys
sys.path.insert(0, "scripts")
import authority_ceiling as a
b = next(b for b in a.bins() if b["name"] == "oci-build")
print(" ".join(a.sources(b)))
PY
)
# shellcheck disable=SC2086
# cancho 0.1.1 does not read $CC; the linker is chosen with --clang (the wrapper adds -static)
rm -f build/oci-build-static
cancho build $FILES --std -o build/oci-build-static --clang "$PWD/scripts/static-cc"
file build/oci-build-static 2>/dev/null || true
# fail loudly if the result is not static: a dynamic executable has a PT_INTERP program header
python3 - <<'PY'
import struct, sys
d = open("build/oci-build-static", "rb").read()
if d[:4] != b"\x7fELF" or d[4] != 2:
    sys.exit("static_build.sh: build/oci-build-static is not a 64-bit ELF executable")
phoff = struct.unpack_from("<Q", d, 32)[0]
phentsize, phnum = struct.unpack_from("<HH", d, 54)
for i in range(phnum):
    if struct.unpack_from("<I", d, phoff + i * phentsize)[0] == 3:
        sys.exit("static_build.sh: build/oci-build-static is dynamically linked (it has an interpreter). "
                 "Check that scripts/static-cc was used (cancho 0.1.1 needs --clang, not $CC) and that libc.a is installed (libc6-dev).")
print("static_build.sh: build/oci-build-static is static")
PY
