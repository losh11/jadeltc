#include "mweb_rangeproof.h"
#include "mweb_kernel.h"

#include <stdlib.h>
#include <string.h>

#include <secp256k1.h>
#include <secp256k1_bulletproofs.h>
#include <secp256k1_generator.h>
#include <wally_core.h>

#ifndef MWEB_RANGEPROOF_NO_TRNG
#include "../random.h"
#endif

/* Scratch budget for a single 64-bit single-commit Bulletproof prove.
 * Sized generously; actual usage is in the low tens of KB. */
#define MWEB_BP_SCRATCH_BYTES (64u * 1024u)

/* 256 NUMS generators ≈ 16 KB. A 64-bit single-commit proof uses
 * 2*64 = 128 of these; matches the upstream default. */
#define MWEB_BP_NUMS_GENS 256

/* The generators table is deterministic and contains no secrets, so a
 * single process-lifetime copy is safe. Scratch, in contrast, holds the
 * caller's blind scalar across the prove call — secp's checkpoint rewind
 * only moves the alloc cursor, leaving the bytes readable — so scratch
 * is allocated per prove and destroyed on return. */
static secp256k1_bulletproof_generators *g_bp_gens = NULL;

void mweb_bulletproof_generators_init(void)
{
    if (g_bp_gens) {
        return;
    }
    const secp256k1_context *ctx = wally_get_secp_context();
    if (!ctx) {
        abort();
    }
    /* secp256k1_generator_g is the Pedersen blinding base (G);
     * commit = r*G + v*H. Generators are deterministic (RFC6979 of G),
     * so a verifier built with the same blinding_gen sees the same
     * NUMS table. */
    g_bp_gens = secp256k1_bulletproof_generators_create(
        ctx, secp256k1_generator_g, MWEB_BP_NUMS_GENS);
    if (!g_bp_gens) {
        abort();
    }
}

mweb_err_t mweb_build_rangeproof_with_nonces(
    uint64_t value,
    const uint8_t blind[32],
    const uint8_t nonce[32],
    const uint8_t private_nonce[32],
    const uint8_t* extra_commit, size_t extra_commit_len,
    uint8_t proof_out[MWEB_RANGEPROOF_LEN])
{
    /* Reject (NULL, non-zero) before secp's illegal-arg abort; normalize
     * (non-NULL, 0) to (NULL, 0) so the Fiat-Shamir transcript matches
     * the canonical no-extra-commit form regardless of caller convention
     * — rangeproof_impl.h gates the SHA round on `extra_commit != NULL`,
     * not on extra_commit_len. */
    if (extra_commit_len == 0) {
        extra_commit = NULL;
    } else if (extra_commit == NULL) {
        return MWEB_ERR_INTERNAL;
    }

    if (!mweb_validate_scalar(nonce) || !mweb_validate_scalar(private_nonce)) {
        return MWEB_ERR_INTERNAL;
    }

    mweb_bulletproof_generators_init();

    const secp256k1_context *ctx = wally_get_secp_context();
    if (!ctx) {
        return MWEB_ERR_INTERNAL;
    }

    /* Per-prove scratch caps the lifetime of the in-scratch copy of `blind`
     * to a single prove call. secp's destroy frees the buffer without
     * zeroing it (scratch_impl.h's secp256k1_scratch_destroy only clears
     * the 8-byte magic before free), so residue persists in the freed
     * heap block until the allocator reuses that region — typically the
     * next prove call in a multi-output session. A future fix is an
     * upstream `secp256k1_scratch_wipe()` API; until then this is the
     * tightest bound public-API consumers can achieve. */
    secp256k1_scratch_space *scratch = secp256k1_scratch_space_create(
        ctx, MWEB_BP_SCRATCH_BYTES);
    if (!scratch) {
        return MWEB_ERR_INTERNAL;
    }

    static const uint8_t recoverable_message[20] = {0};
    size_t proof_len = MWEB_RANGEPROOF_LEN;
    const uint8_t *blinds[1] = { blind };
    const uint64_t value_arr[1] = { value };

    int rc = secp256k1_bulletproof_rangeproof_prove(
        ctx, scratch, g_bp_gens,
        proof_out, &proof_len,
        NULL, NULL, NULL,                  /* tau_x, t_one, t_two: multi-party slots */
        value_arr, NULL,                   /* min_value = 0 */
        blinds, NULL, 1,                   /* commits derived from blinds; n_commits = 1 */
        secp256k1_generator_h, 64,         /* value generator H; full 64-bit range */
        nonce, private_nonce,
        extra_commit, extra_commit_len,
        recoverable_message);

    secp256k1_scratch_space_destroy(ctx, scratch);

    if (rc != 1 || proof_len != MWEB_RANGEPROOF_LEN) {
        return MWEB_ERR_INTERNAL;
    }
    return MWEB_OK;
}

#ifndef MWEB_RANGEPROOF_NO_TRNG
mweb_err_t mweb_build_rangeproof(
    uint64_t value,
    const uint8_t blind[32],
    const uint8_t* extra_commit, size_t extra_commit_len,
    uint8_t proof_out[MWEB_RANGEPROOF_LEN])
{
    uint8_t nonce[32];
    uint8_t private_nonce[32];
    mweb_err_t err = MWEB_ERR_INTERNAL;

    for (int tries = 0; tries < 8; ++tries) {
        get_random(nonce, 32);
        if (mweb_validate_scalar(nonce)) {
            break;
        }
        if (tries == 7) {
            goto cleanup;
        }
    }
    for (int tries = 0; tries < 8; ++tries) {
        get_random(private_nonce, 32);
        if (mweb_validate_scalar(private_nonce)) {
            break;
        }
        if (tries == 7) {
            goto cleanup;
        }
    }

    err = mweb_build_rangeproof_with_nonces(
        value, blind, nonce, private_nonce,
        extra_commit, extra_commit_len, proof_out);

cleanup:
    wally_bzero(nonce, sizeof(nonce));
    wally_bzero(private_nonce, sizeof(private_nonce));
    return err;
}
#endif /* MWEB_RANGEPROOF_NO_TRNG */
