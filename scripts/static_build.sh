#!/bin/sh
# Build oci-build as a static executable: build/oci-build-static. Needs a static libc (libc.a).
set -eu
cd "$(dirname "$0")/.."
mkdir -p build
CC="$PWD/scripts/static-cc" cancho build \
  src/digest/digest.cho src/tar/tar.cho src/elf/elf.cho src/place/place.cho src/store/store.cho \
  src/image/image.cho src/layer/layer.cho src/build/main.cho --std -o build/oci-build-static
file build/oci-build-static 2>/dev/null || true
