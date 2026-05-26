#ifndef MWEB_RANGEPROOF_H_
#define MWEB_RANGEPROOF_H_

#include <stddef.h>
#include <stdint.h>

#include "mweb_kernel.h"  /* mweb_err_t */

/* Serialized length of an MWEB bulletproof: single 64-bit committed
 * value, no aggregation. The prover always writes exactly this many
 * bytes when the call returns MWEB_OK. */
#define MWEB_RANGEPROOF_LEN 675

/*
 * Idempotent first-call initializer for the bulletproof generators
 * table (256 NUMS generators, ~16 KB). The table is deterministic and
 * holds no secrets, so a single process-lifetime copy is safe.
 *
 * The prove call's scratch arena (~64 KB) is allocated per call and
 * destroyed on return: secp copies the caller's blind into scratch and
 * the upstream checkpoint rewind does not zero memory, so persisting
 * scratch would persist the last blind.
 *
 * Aborts on allocation failure: MWEB signing is non-functional without
 * the generators table, so fail-closed at the first attempt rather
 * than at each prove call.
 */
void mweb_bulletproof_generators_init(void);

/*
 * Build a 675-byte MWEB bulletproof range proof for a single 64-bit
 * value committed via Pedersen(blind, value) against the secp256k1
 * value generator H.
 *
 * Draws two independent 32-byte TRNG nonces internally, each validated
 * as non-zero and below the curve order with an 8-retry budget.
 *
 * extra_commit (the serialized MwebOutputMessage in production) binds
 * the proof to the output's public fields. May be NULL iff
 * extra_commit_len == 0. The 20-byte recoverable-message slot is the
 * MWEB-canonical all-zeros.
 *
 * Caller owns blind and is responsible for wiping it after the call.
 */
mweb_err_t mweb_build_rangeproof(
    uint64_t value,
    const uint8_t blind[32],
    const uint8_t* extra_commit, size_t extra_commit_len,
    uint8_t proof_out[MWEB_RANGEPROOF_LEN]);

/*
 * Test seam: same as mweb_build_rangeproof but with caller-supplied
 * bulletproof nonces. Both nonces must be non-zero and below the curve
 * order; otherwise returns MWEB_ERR_INTERNAL.
 */
mweb_err_t mweb_build_rangeproof_with_nonces(
    uint64_t value,
    const uint8_t blind[32],
    const uint8_t nonce[32],
    const uint8_t private_nonce[32],
    const uint8_t* extra_commit, size_t extra_commit_len,
    uint8_t proof_out[MWEB_RANGEPROOF_LEN]);

#endif /* MWEB_RANGEPROOF_H_ */
