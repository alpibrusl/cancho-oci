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
CC="$PWD/scripts/static-cc" cancho build $FILES --std -o build/oci-build-static
file build/oci-build-static 2>/dev/null || true
