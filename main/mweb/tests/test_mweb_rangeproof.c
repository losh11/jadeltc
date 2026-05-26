/*
 * Tests for mweb_build_rangeproof_with_nonces (MWEB bulletproof range proof).
 *
 * The prover is exercised end-to-end by feeding its output into
 * secp256k1_bulletproof_rangeproof_verify and asserting acceptance,
 * plus negative checks that tampering or altering the bound data
 * makes verify reject.
 *
 * Coverage:
 *   - prove-then-verify across the value range (0, 1, typical, max)
 *   - determinism: same inputs -> same proof bytes
 *   - tampered proof byte is rejected by verify
 *   - extra_commit binding: altering it after prove makes verify fail
 *   - prove with no extra_commit (NULL, len=0) round-trips
 *   - invalid bulletproof nonce is rejected up-front
 */
#include "mweb_rangeproof.h"
#include "mweb_kernel.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <secp256k1.h>
#include <secp256k1_bulletproofs.h>
#include <secp256k1_generator.h>
#include <wally_core.h>

static int failures = 0;
static int test_count = 0;

#define PASS(name) do { test_count++; printf("PASS: %s\n", name); } while (0)
#define FAIL(name, ...) do { test_count++; failures++; printf("FAIL: %s — ", name); printf(__VA_ARGS__); printf("\n"); } while (0)

/* --- Fixtures (deterministic) --- */

static const uint8_t BLIND[32] = {
    0xb1,0x1d,0xb1,0x1d,0xb1,0x1d,0xb1,0x1d,
    0xb1,0x1d,0xb1,0x1d,0xb1,0x1d,0xb1,0x1d,
    0xb1,0x1d,0xb1,0x1d,0xb1,0x1d,0xb1,0x1d,
    0xb1,0x1d,0xb1,0x1d,0xb1,0x1d,0xb1,0x1d,
};

static const uint8_t NONCE[32] = {
    0xc0,0xff,0xee,0xc0,0xff,0xee,0xc0,0xff,
    0xee,0xc0,0xff,0xee,0xc0,0xff,0xee,0xc0,
    0xff,0xee,0xc0,0xff,0xee,0xc0,0xff,0xee,
    0xc0,0xff,0xee,0xc0,0xff,0xee,0xc0,0xff,
};

static const uint8_t PRIVATE_NONCE[32] = {
    0xde,0xad,0xbe,0xef,0xde,0xad,0xbe,0xef,
    0xde,0xad,0xbe,0xef,0xde,0xad,0xbe,0xef,
    0xde,0xad,0xbe,0xef,0xde,0xad,0xbe,0xef,
    0xde,0xad,0xbe,0xef,0xde,0xad,0xbe,0xef,
};

/* MwebOutputMessage-shaped extra_commit: features(1) || K_e(33) ||
 * view_tag(1) || masked_value(8) || masked_nonce(16). The prover hashes
 * this opaquely, so byte content matters but structure doesn't. */
static const uint8_t EXTRA_COMMIT[] = {
    0x01,
    0x02,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff,
    0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff,
    0x7a,
    0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,
    0xaa,0xbb,0xcc,0xdd,0xee,0xff,0x00,0x11,
    0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,
};

/* --- Verify-side resources (deterministic NUMS table matches prover) --- */

static secp256k1_bulletproof_generators *t_gens = NULL;
static secp256k1_scratch_space          *t_scratch = NULL;

static int setup_verify_resources(void)
{
    const secp256k1_context *ctx = wally_get_secp_context();
    if (!ctx) return 0;
    t_gens = secp256k1_bulletproof_generators_create(
        ctx, secp256k1_generator_g, 256);
    if (!t_gens) return 0;
    t_scratch = secp256k1_scratch_space_create(ctx, 64u * 1024u);
    if (!t_scratch) return 0;
    return 1;
}

static int pedersen_commit(uint64_t value, const uint8_t blind[32],
                            secp256k1_pedersen_commitment *commit_out)
{
    const secp256k1_context *ctx = wally_get_secp_context();
    return secp256k1_pedersen_commit(
        ctx, commit_out, blind, value, secp256k1_generator_h);
}

static int verify(const uint8_t *proof, size_t plen,
                   uint64_t value, const uint8_t blind[32],
                   const uint8_t *extra_commit, size_t extra_commit_len)
{
    const secp256k1_context *ctx = wally_get_secp_context();
    secp256k1_pedersen_commitment commit;
    if (!pedersen_commit(value, blind, &commit)) return 0;
    return secp256k1_bulletproof_rangeproof_verify(
        ctx, t_scratch, t_gens,
        proof, plen,
        NULL, &commit, 1, 64,
        secp256k1_generator_h,
        extra_commit, extra_commit_len);
}

/* --- Tests --- */

static void test_prove_then_verify(const char *name, uint64_t value)
{
    uint8_t proof[MWEB_RANGEPROOF_LEN];
    mweb_err_t err = mweb_build_rangeproof_with_nonces(
        value, BLIND, NONCE, PRIVATE_NONCE,
        EXTRA_COMMIT, sizeof(EXTRA_COMMIT),
        proof);
    if (err != MWEB_OK) {
        FAIL(name, "prove failed: err=%d", (int)err);
        return;
    }
    if (!verify(proof, MWEB_RANGEPROOF_LEN, value, BLIND,
                EXTRA_COMMIT, sizeof(EXTRA_COMMIT))) {
        FAIL(name, "verify rejected a valid proof");
        return;
    }
    PASS(name);
}

static void test_determinism(void)
{
    uint8_t proof1[MWEB_RANGEPROOF_LEN];
    uint8_t proof2[MWEB_RANGEPROOF_LEN];

    if (mweb_build_rangeproof_with_nonces(
            100000000ULL, BLIND, NONCE, PRIVATE_NONCE,
            EXTRA_COMMIT, sizeof(EXTRA_COMMIT), proof1) != MWEB_OK) {
        FAIL("determinism", "first prove failed");
        return;
    }
    if (mweb_build_rangeproof_with_nonces(
            100000000ULL, BLIND, NONCE, PRIVATE_NONCE,
            EXTRA_COMMIT, sizeof(EXTRA_COMMIT), proof2) != MWEB_OK) {
        FAIL("determinism", "second prove failed");
        return;
    }
    if (memcmp(proof1, proof2, MWEB_RANGEPROOF_LEN) != 0) {
        FAIL("determinism", "proofs differ for identical inputs");
        return;
    }
    PASS("determinism");
}

static void test_tampered_proof_rejected(void)
{
    uint8_t proof[MWEB_RANGEPROOF_LEN];
    if (mweb_build_rangeproof_with_nonces(
            100000000ULL, BLIND, NONCE, PRIVATE_NONCE,
            EXTRA_COMMIT, sizeof(EXTRA_COMMIT), proof) != MWEB_OK) {
        FAIL("tamper_rejected", "prove failed");
        return;
    }
    proof[100] ^= 0xff;
    if (verify(proof, MWEB_RANGEPROOF_LEN, 100000000ULL, BLIND,
               EXTRA_COMMIT, sizeof(EXTRA_COMMIT))) {
        FAIL("tamper_rejected", "verify accepted a tampered proof");
        return;
    }
    PASS("tamper_rejected");
}

static void test_extra_commit_binding(void)
{
    uint8_t proof[MWEB_RANGEPROOF_LEN];
    if (mweb_build_rangeproof_with_nonces(
            42, BLIND, NONCE, PRIVATE_NONCE,
            EXTRA_COMMIT, sizeof(EXTRA_COMMIT), proof) != MWEB_OK) {
        FAIL("extra_commit_binding", "prove failed");
        return;
    }
    uint8_t alt[sizeof(EXTRA_COMMIT)];
    memcpy(alt, EXTRA_COMMIT, sizeof(EXTRA_COMMIT));
    alt[0] ^= 0xff;
    if (verify(proof, MWEB_RANGEPROOF_LEN, 42, BLIND,
               alt, sizeof(alt))) {
        FAIL("extra_commit_binding", "verify accepted proof under altered extra_commit");
        return;
    }
    PASS("extra_commit_binding");
}

static void test_no_extra_commit(void)
{
    uint8_t proof[MWEB_RANGEPROOF_LEN];
    mweb_err_t err = mweb_build_rangeproof_with_nonces(
        12345, BLIND, NONCE, PRIVATE_NONCE,
        NULL, 0, proof);
    if (err != MWEB_OK) {
        FAIL("no_extra_commit", "prove failed: err=%d", (int)err);
        return;
    }
    if (!verify(proof, MWEB_RANGEPROOF_LEN, 12345, BLIND, NULL, 0)) {
        FAIL("no_extra_commit", "verify rejected a valid proof");
        return;
    }
    PASS("no_extra_commit");
}

static void test_zero_nonce_rejected(void)
{
    static const uint8_t ZERO[32] = {0};
    uint8_t proof[MWEB_RANGEPROOF_LEN];
    if (mweb_build_rangeproof_with_nonces(
            1, BLIND, ZERO, PRIVATE_NONCE,
            EXTRA_COMMIT, sizeof(EXTRA_COMMIT), proof) == MWEB_OK) {
        FAIL("zero_nonce_rejected", "accepted zero primary nonce");
        return;
    }
    if (mweb_build_rangeproof_with_nonces(
            1, BLIND, NONCE, ZERO,
            EXTRA_COMMIT, sizeof(EXTRA_COMMIT), proof) == MWEB_OK) {
        FAIL("zero_nonce_rejected", "accepted zero private nonce");
        return;
    }
    PASS("zero_nonce_rejected");
}

static void test_null_extra_commit_with_nonzero_len_rejected(void)
{
    uint8_t proof[MWEB_RANGEPROOF_LEN];
    mweb_err_t err = mweb_build_rangeproof_with_nonces(
        1, BLIND, NONCE, PRIVATE_NONCE,
        NULL, 5, proof);
    if (err == MWEB_OK) {
        FAIL("null_extra_commit_with_nonzero_len_rejected",
             "accepted NULL extra_commit with non-zero length");
        return;
    }
    PASS("null_extra_commit_with_nonzero_len_rejected");
}

static void test_zero_len_extra_commit_canonicalized(void)
{
    /* (non-NULL, 0) must produce the same proof as (NULL, 0): the wrapper
     * normalizes the non-NULL pointer to NULL so secp's Fiat-Shamir gate
     * (`if (extra_commit != NULL) ...`) reaches the same transcript. */
    uint8_t proof_null[MWEB_RANGEPROOF_LEN];
    uint8_t proof_nonnull_zerolen[MWEB_RANGEPROOF_LEN];
    if (mweb_build_rangeproof_with_nonces(
            7, BLIND, NONCE, PRIVATE_NONCE,
            NULL, 0, proof_null) != MWEB_OK) {
        FAIL("zero_len_extra_commit_canonicalized", "NULL/0 prove failed");
        return;
    }
    if (mweb_build_rangeproof_with_nonces(
            7, BLIND, NONCE, PRIVATE_NONCE,
            EXTRA_COMMIT, 0, proof_nonnull_zerolen) != MWEB_OK) {
        FAIL("zero_len_extra_commit_canonicalized", "non-NULL/0 prove failed");
        return;
    }
    if (memcmp(proof_null, proof_nonnull_zerolen, MWEB_RANGEPROOF_LEN) != 0) {
        FAIL("zero_len_extra_commit_canonicalized",
             "proofs differ — (non-NULL,0) was not normalized to (NULL,0)");
        return;
    }
    PASS("zero_len_extra_commit_canonicalized");
}

static void test_overflow_nonce_rejected(void)
{
    /* n exactly — should be rejected (mweb_validate_scalar treats s == n as overflow). */
    static const uint8_t ORDER[32] = {
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,
        0xBA,0xAE,0xDC,0xE6,0xAF,0x48,0xA0,0x3B,
        0xBF,0xD2,0x5E,0x8C,0xD0,0x36,0x41,0x41,
    };
    uint8_t proof[MWEB_RANGEPROOF_LEN];
    if (mweb_build_rangeproof_with_nonces(
            1, BLIND, ORDER, PRIVATE_NONCE,
            EXTRA_COMMIT, sizeof(EXTRA_COMMIT), proof) == MWEB_OK) {
        FAIL("overflow_nonce_rejected", "accepted n-as-nonce");
        return;
    }
    PASS("overflow_nonce_rejected");
}

int main(void)
{
    if (!setup_verify_resources()) {
        printf("FATAL: could not allocate test verify resources\n");
        return 1;
    }

    test_prove_then_verify("value_zero",    0);
    test_prove_then_verify("value_one",     1);
    test_prove_then_verify("value_typical", 100000000ULL);   /* 1 LTC */
    test_prove_then_verify("value_max",     UINT64_MAX);

    test_determinism();
    test_tampered_proof_rejected();
    test_extra_commit_binding();
    test_no_extra_commit();
    test_zero_nonce_rejected();
    test_overflow_nonce_rejected();
    test_null_extra_commit_with_nonzero_len_rejected();
    test_zero_len_extra_commit_canonicalized();

    printf("\n%d/%d tests passed (%d failures)\n",
           test_count - failures, test_count, failures);
    return failures == 0 ? 0 : 1;
}
