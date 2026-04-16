#!/usr/bin/env bash
#
# Build and run the native MWEB unit tests inside the official Jade
# builder Docker image. Every test here is a standalone C binary that
# links against libwally-core (via its combined.c amalgamation) and a
# portable-only BLAKE3. The SIMD-specialised BLAKE3 dispatch units are
# replaced by a local portable dispatcher so the link step does not
# pull in the SSE/AVX object files.
#
# Usage:
#   ./main/mweb/tests/run_native_tests.sh
#     — builds and runs from inside Docker. Repeats any test flagged
#       by JADE_MWEB_TEST_FILTER if set (otherwise runs all).
#
# Exits non-zero on any test failure so the script is usable as a
# plain CI step.

set -euo pipefail

# Resolve Jade repo root (…/main/mweb/tests/.. /../.. = repo root).
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
JADE_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"

DOCKER_IMAGE="${JADE_BUILDER_IMAGE:-blockstream/jade_builder}"

# If the image is not available locally under that tag, fall back to any
# locally-tagged jade_builder image (supports the <none>-tagged copy in
# dev setups).
if ! docker image inspect "${DOCKER_IMAGE}" > /dev/null 2>&1; then
    fallback_id="$(docker images --format '{{.ID}}' "blockstream/jade_builder" | head -1)"
    if [ -n "${fallback_id}" ]; then
        DOCKER_IMAGE="${fallback_id}"
    fi
fi

docker run --rm -i \
    -v "${JADE_ROOT}":/Jade \
    "${DOCKER_IMAGE}" \
    /bin/bash -s <<'INNER'
set -euo pipefail

apt-get update -qq > /dev/null 2>&1
apt-get install -y -qq libmbedtls-dev > /dev/null 2>&1 || true

INCS="
  -I/Jade/main
  -I/Jade/main/mweb
  -I/Jade/main/mweb/tests
  -I/Jade/components/blake3
  -I/Jade/components/libwally-core
  -I/Jade/components/libwally-core/upstream
  -I/Jade/components/libwally-core/upstream/include
  -I/Jade/components/libwally-core/upstream/src
  -I/Jade/components/libwally-core/upstream/src/ccan
  -I/Jade/components/libwally-core/upstream/src/secp256k1
  -I/Jade/components/libwally-core/upstream/src/secp256k1/include
  -I/Jade/components/libwally-core/upstream/src/secp256k1/src
  -I/Jade/components/libwally-core/upstream/src/amalgamation
  -I/Jade/components/libwally-core/upstream/tools/build_helpers/inc
"

DEFS="
  -DHAVE_CONFIG_H=1
  -DBLAKE3_NO_SSE2 -DBLAKE3_NO_SSE41 -DBLAKE3_NO_AVX2 -DBLAKE3_NO_AVX512
  -DBUILD_MWEB=1
  -DMWEB_TEST_STANDALONE=1
"

mkdir -p /tmp/jade_native_tests
cd /tmp/jade_native_tests

gcc $INCS $DEFS -c /Jade/components/blake3/blake3.c          -o blake3.o
gcc $INCS $DEFS -c /Jade/components/blake3/blake3_portable.c -o blake3_portable.o

# Portable-only dispatcher: replaces the SIMD-specialised one so we do
# not need to link the SSE/AVX object files.
cat > /tmp/jade_native_tests/blake3_dispatch_portable.c <<'CDISP'
#include "blake3_impl.h"
#include <string.h>
void blake3_compress_in_place(uint32_t cv[8], const uint8_t block[BLAKE3_BLOCK_LEN],
                              uint8_t block_len, uint64_t counter, uint8_t flags) {
    blake3_compress_in_place_portable(cv, block, block_len, counter, flags);
}
void blake3_compress_xof(const uint32_t cv[8], const uint8_t block[BLAKE3_BLOCK_LEN],
                         uint8_t block_len, uint64_t counter, uint8_t flags,
                         uint8_t out[64]) {
    blake3_compress_xof_portable(cv, block, block_len, counter, flags, out);
}
void blake3_hash_many(const uint8_t *const *inputs, size_t num_inputs, size_t blocks,
                      const uint32_t key[8], uint64_t counter, bool increment_counter,
                      uint8_t flags, uint8_t flags_start, uint8_t flags_end, uint8_t *out) {
    blake3_hash_many_portable(inputs, num_inputs, blocks, key, counter, increment_counter,
                              flags, flags_start, flags_end, out);
}
void blake3_xof_many(const uint32_t cv[8], const uint8_t block[BLAKE3_BLOCK_LEN],
                     uint8_t block_len, uint64_t counter, uint8_t flags, uint8_t out[64],
                     size_t outblocks) {
    for (size_t i = 0; i < outblocks; ++i) {
        blake3_compress_xof_portable(cv, block, block_len, counter + i, flags, out + i * 64);
    }
}
size_t blake3_simd_degree(void) { return 1; }
CDISP
gcc $INCS $DEFS -c /tmp/jade_native_tests/blake3_dispatch_portable.c -o blake3_dispatch.o

gcc $INCS $DEFS -w -O0 \
  -c /Jade/components/libwally-core/upstream/src/amalgamation/combined.c \
  -o wally_combined.o

cat > /tmp/jade_native_tests/stubs.c <<'CSTUB'
#include <stdint.h>
#include <stddef.h>
#include <string.h>
__attribute__((weak)) void get_random(void* out, size_t n) { memset(out, 0, n); }
CSTUB

LINKLIBS="blake3.o blake3_portable.o blake3_dispatch.o wally_combined.o"

run_one() {
    local tgt="$1"
    shift
    local srcs="$*"

    echo ""
    echo "==== ${tgt} ===="
    gcc $INCS $DEFS -w ${srcs} /tmp/jade_native_tests/stubs.c ${LINKLIBS} \
        -o "/tmp/jade_native_tests/${tgt}" -lm -lmbedcrypto 2>&1 | \
        grep -vE "deprecated-declarations|declared here|note:|pragma" || true
    if [ ! -x "/tmp/jade_native_tests/${tgt}" ]; then
        echo "BUILD FAILED: ${tgt}"
        exit 1
    fi
    "/tmp/jade_native_tests/${tgt}"
}

run_one test_mweb_sign \
    /Jade/main/mweb/tests/test_mweb_sign.c \
    /Jade/main/mweb/mweb_sign.c /Jade/main/mweb/mweb_blind.c \
    /Jade/main/mweb/mweb_hash.c /Jade/main/mweb/mweb_schnorr.c \
    /Jade/main/mweb/mweb_scalar.c /Jade/main/mweb/mweb_kernel.c

run_one test_mweb_kernel \
    /Jade/main/mweb/tests/test_mweb_kernel.c \
    /Jade/main/mweb/mweb_kernel.c /Jade/main/mweb/mweb_scalar.c \
    /Jade/main/mweb/mweb_blind.c /Jade/main/mweb/mweb_hash.c \
    /Jade/main/mweb/mweb_schnorr.c

run_one test_mweb_output \
    /Jade/main/mweb/tests/test_mweb_output.c \
    /Jade/main/mweb/mweb_output.c /Jade/main/mweb/mweb_kernel.c \
    /Jade/main/mweb/mweb_scalar.c /Jade/main/mweb/mweb_blind.c \
    /Jade/main/mweb/mweb_hash.c /Jade/main/mweb/mweb_schnorr.c

run_one test_mweb_atomic_sign \
    /Jade/main/mweb/tests/test_mweb_atomic_sign.c \
    /Jade/main/mweb/mweb_atomic_sign.c /Jade/main/mweb/mweb_sign.c \
    /Jade/main/mweb/mweb_kernel.c /Jade/main/mweb/mweb_scalar.c \
    /Jade/main/mweb/mweb_output.c /Jade/main/mweb/mweb_blind.c \
    /Jade/main/mweb/mweb_hash.c /Jade/main/mweb/mweb_schnorr.c
INNER
