/*
 * Tests for mweb_derive_output and mweb_build_output[_with_nonces].
 *
 * derive_output coverage uses pinned fixtures (output_vectors.h).
 * build_output coverage verifies its output against the upstream
 * bulletproof verifier and an independently-computed Schnorr signature;
 * the test never trusts the wrapper's own primitives by themselves.
 */
#include "mweb_kernel.h"     /* mweb_err_t */
#include "mweb_output.h"
#include "mweb_rangeproof.h" /* MWEB_RANGEPROOF_LEN */
#include "mweb_schnorr.h"    /* mweb_schnorr_sign */
#include "fixtures/output_vectors.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <blake3.h>
#include <secp256k1.h>
#include <secp256k1_bulletproofs.h>
#include <secp256k1_generator.h>
#include <wally_core.h>

static int failures = 0;
static int test_count = 0;

#define PASS(name) do { test_count++; printf("PASS: %s\n", name); } while (0)
#define FAIL(name, ...) do { \
        test_count++; failures++; \
        printf("FAIL: %s — ", name); printf(__VA_ARGS__); printf("\n"); \
    } while (0)

static void hexprint(const char *label, const uint8_t *b, size_t n)
{
    printf("  %s ", label);
    for (size_t i = 0; i < n; i++) printf("%02x", b[i]);
    printf("\n");
}

/* Byte-for-byte equality on the full derived struct vs. pinned fixture. */
static bool check_all_fields(const char *name,
                             const struct mweb_derived_output *got,
                             const uint8_t blind[32],
                             const uint8_t Ko[33],
                             const uint8_t Ks[33],
                             const uint8_t Ke[33],
                             const uint8_t commit[33],
                             uint8_t view_tag,
                             uint64_t masked_value,
                             const uint8_t masked_nonce[16])
{
    bool ok = true;
    if (memcmp(got->blind, blind, 32) != 0) {
        FAIL(name, "blind mismatch");
        hexprint("got: ", got->blind, 32);
        hexprint("exp: ", blind, 32);
        ok = false;
    }
    if (memcmp(got->output_pubkey, Ko, 33) != 0) {
        FAIL(name, "K_o mismatch");
        hexprint("got: ", got->output_pubkey, 33);
        hexprint("exp: ", Ko, 33);
        ok = false;
    }
    if (memcmp(got->sender_pubkey, Ks, 33) != 0) {
        FAIL(name, "K_s mismatch");
        hexprint("got: ", got->sender_pubkey, 33);
        hexprint("exp: ", Ks, 33);
        ok = false;
    }
    if (memcmp(got->key_exchange_pubkey, Ke, 33) != 0) {
        FAIL(name, "K_e mismatch");
        hexprint("got: ", got->key_exchange_pubkey, 33);
        hexprint("exp: ", Ke, 33);
        ok = false;
    }
    if (memcmp(got->commit, commit, 33) != 0) {
        FAIL(name, "C_out mismatch");
        hexprint("got: ", got->commit, 33);
        hexprint("exp: ", commit, 33);
        ok = false;
    }
    if (got->view_tag != view_tag) {
        FAIL(name, "view_tag mismatch: got 0x%02x, want 0x%02x",
             got->view_tag, view_tag);
        ok = false;
    }
    if (got->masked_value != masked_value) {
        FAIL(name, "masked_value mismatch: got 0x%016llx, want 0x%016llx",
             (unsigned long long)got->masked_value,
             (unsigned long long)masked_value);
        ok = false;
    }
    if (memcmp(got->masked_nonce, masked_nonce, 16) != 0) {
        FAIL(name, "masked_nonce mismatch");
        hexprint("got: ", got->masked_nonce, 16);
        hexprint("exp: ", masked_nonce, 16);
        ok = false;
    }
    return ok;
}

/* ── 1. HAPPY — all eight fields match the fixture ──────────────────── */

static void test_happy(void)
{
    struct mweb_derived_output got;
    mweb_err_t err = mweb_derive_output(OUT_HAPPY_SENDER_KEY,
                                        OUT_HAPPY_SCAN_A,
                                        OUT_HAPPY_SPEND_B,
                                        OUT_HAPPY_VALUE,
                                        &got);
    if (err != MWEB_OK) {
        FAIL("happy", "returned err %d", err);
        return;
    }
    if (check_all_fields("happy", &got,
                         OUT_HAPPY_BLIND, OUT_HAPPY_KO, OUT_HAPPY_KS,
                         OUT_HAPPY_KE, OUT_HAPPY_COMMIT,
                         OUT_HAPPY_VIEW_TAG, OUT_HAPPY_MASKED_VALUE,
                         OUT_HAPPY_MASKED_NONCE)) {
        PASS("happy");
    }
}

/* ── 2. INVALID_SCALAR — reject zero and >= n ───────────────────────── */

static void test_invalid_scalar(void)
{
    struct mweb_derived_output got;

    static const uint8_t ZERO[32] = {0};
    mweb_err_t err = mweb_derive_output(ZERO,
                                        OUT_HAPPY_SCAN_A,
                                        OUT_HAPPY_SPEND_B,
                                        OUT_HAPPY_VALUE,
                                        &got);
    if (err != MWEB_ERR_INVALID_SCALAR) {
        FAIL("invalid_scalar/zero", "expected INVALID_SCALAR, got %d", err);
        return;
    }

    /* Exactly the curve order n (big-endian) — rejected as >= n. */
    static const uint8_t N[32] = {
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,
        0xBA,0xAE,0xDC,0xE6,0xAF,0x48,0xA0,0x3B,
        0xBF,0xD2,0x5E,0x8C,0xD0,0x36,0x41,0x41,
    };
    err = mweb_derive_output(N,
                             OUT_HAPPY_SCAN_A,
                             OUT_HAPPY_SPEND_B,
                             OUT_HAPPY_VALUE,
                             &got);
    if (err != MWEB_ERR_INVALID_SCALAR) {
        FAIL("invalid_scalar/n", "expected INVALID_SCALAR, got %d", err);
        return;
    }

    /* n + 1 — still rejected as >= n. */
    static const uint8_t N_PLUS_1[32] = {
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,
        0xBA,0xAE,0xDC,0xE6,0xAF,0x48,0xA0,0x3B,
        0xBF,0xD2,0x5E,0x8C,0xD0,0x36,0x41,0x42,
    };
    err = mweb_derive_output(N_PLUS_1,
                             OUT_HAPPY_SCAN_A,
                             OUT_HAPPY_SPEND_B,
                             OUT_HAPPY_VALUE,
                             &got);
    if (err != MWEB_ERR_INVALID_SCALAR) {
        FAIL("invalid_scalar/n+1", "expected INVALID_SCALAR, got %d", err);
        return;
    }

    PASS("invalid_scalar");
}

/* ── 3. ENDIAN — fixture chosen so LE/BE confusion of value-mask and
 *    reversal of nonce-mask both yield different results ──────────── */

static void test_endian(void)
{
    struct mweb_derived_output got;
    mweb_err_t err = mweb_derive_output(OUT_ENDIAN_SENDER_KEY,
                                        OUT_ENDIAN_SCAN_A,
                                        OUT_ENDIAN_SPEND_B,
                                        OUT_ENDIAN_VALUE,
                                        &got);
    if (err != MWEB_OK) {
        FAIL("endian", "returned err %d", err);
        return;
    }

    /* Byte-for-byte against the fixture (LE u64 + BE 128-bit XOR). */
    if (got.masked_value != OUT_ENDIAN_MASKED_VALUE) {
        FAIL("endian", "masked_value mismatch 0x%016llx vs 0x%016llx",
             (unsigned long long)got.masked_value,
             (unsigned long long)OUT_ENDIAN_MASKED_VALUE);
        return;
    }
    if (memcmp(got.masked_nonce, OUT_ENDIAN_MASKED_NONCE, 16) != 0) {
        FAIL("endian", "masked_nonce mismatch");
        hexprint("got: ", got.masked_nonce, 16);
        hexprint("exp: ", OUT_ENDIAN_MASKED_NONCE, 16);
        return;
    }

    /* Construct the BE-decoded alternative: a buggy helper that read
     * Hashed('Y', t)[0..8] as BE instead of LE would yield v XOR
     * reverse_bytes(value_mask). Verify our correct output differs from
     * that alternative — guarding the LE invariant. */
    uint64_t value_mask_le = OUT_ENDIAN_VALUE ^ OUT_ENDIAN_MASKED_VALUE;
    uint64_t value_mask_be = 0;
    for (int i = 0; i < 8; i++) {
        value_mask_be |= ((value_mask_le >> (i * 8)) & 0xffULL)
                         << ((7 - i) * 8);
    }
    if (value_mask_le == value_mask_be) {
        FAIL("endian", "value_mask is byte-palindrome — fixture degenerate");
        return;
    }
    uint64_t masked_value_be = OUT_ENDIAN_VALUE ^ value_mask_be;
    if (got.masked_value == masked_value_be) {
        FAIL("endian", "helper matched BE-u64 alternative");
        return;
    }

    /* Sanity guard for the 16-byte XOR: masked_nonce itself must not be
     * a byte-palindrome, else a reverse-XOR impl coincides for any n_16
     * that is a palindrome. (The stronger "nonce_mask is not palindromic"
     * check lives in the fixture generator.) */
    bool palindrome = true;
    for (int i = 0; i < 8; i++) {
        if (OUT_ENDIAN_MASKED_NONCE[i] != OUT_ENDIAN_MASKED_NONCE[15 - i]) {
            palindrome = false;
            break;
        }
    }
    if (palindrome) {
        FAIL("endian", "masked_nonce is byte-palindrome — fixture degenerate");
        return;
    }

    PASS("endian");
}

/* ── 4. TAG_BYTES — wrong tags 'V'/'R' yield different mask outputs ── */

static void test_tag_bytes(void)
{
    struct mweb_derived_output got;
    mweb_err_t err = mweb_derive_output(OUT_TAG_BYTES_SENDER_KEY,
                                        OUT_TAG_BYTES_SCAN_A,
                                        OUT_TAG_BYTES_SPEND_B,
                                        OUT_TAG_BYTES_VALUE,
                                        &got);
    if (err != MWEB_OK) {
        FAIL("tag_bytes", "returned err %d", err);
        return;
    }

    /* Helper uses the correct Y/X tags — matches fixture. */
    if (got.masked_value != OUT_TAG_BYTES_MASKED_VALUE) {
        FAIL("tag_bytes", "masked_value mismatch (right-tag)");
        return;
    }
    if (memcmp(got.masked_nonce, OUT_TAG_BYTES_MASKED_NONCE, 16) != 0) {
        FAIL("tag_bytes", "masked_nonce mismatch (right-tag)");
        return;
    }

    /* A helper that silently drifted to the wrong tags 'V' (0x56) / 'R'
     * (0x52) would produce these alternative values. Assert both:
     *   (a) our helper output differs from the wrong-tag variant, and
     *   (b) the wrong-tag variant genuinely differs from the right one
     *       (guards against a degenerate fixture). */
    if (got.masked_value == OUT_TAG_BYTES_MASKED_VALUE_WRONG_V) {
        FAIL("tag_bytes", "helper matched WRONG-tag V value-mask");
        return;
    }
    if (memcmp(got.masked_nonce,
               OUT_TAG_BYTES_MASKED_NONCE_WRONG_R, 16) == 0) {
        FAIL("tag_bytes", "helper matched WRONG-tag R nonce-mask");
        return;
    }
    if (OUT_TAG_BYTES_MASKED_VALUE == OUT_TAG_BYTES_MASKED_VALUE_WRONG_V) {
        FAIL("tag_bytes", "fixture: right-tag and wrong-tag value-mask equal");
        return;
    }
    if (memcmp(OUT_TAG_BYTES_MASKED_NONCE,
               OUT_TAG_BYTES_MASKED_NONCE_WRONG_R, 16) == 0) {
        FAIL("tag_bytes", "fixture: right-tag and wrong-tag nonce-mask equal");
        return;
    }

    PASS("tag_bytes");
}

/* ── 5. VIEW_TAG_SOURCE — helper takes Hashed('T', sA), not ('T', t) ─ */

static void test_view_tag_source(void)
{
    struct mweb_derived_output got;
    mweb_err_t err = mweb_derive_output(OUT_VIEW_TAG_SOURCE_SENDER_KEY,
                                        OUT_VIEW_TAG_SOURCE_SCAN_A,
                                        OUT_VIEW_TAG_SOURCE_SPEND_B,
                                        OUT_VIEW_TAG_SOURCE_VALUE,
                                        &got);
    if (err != MWEB_OK) {
        FAIL("view_tag_source", "returned err %d", err);
        return;
    }

    if (got.view_tag != OUT_VIEW_TAG_SOURCE_VIEW_TAG) {
        FAIL("view_tag_source", "view_tag mismatch: got 0x%02x, want 0x%02x",
             got.view_tag, OUT_VIEW_TAG_SOURCE_VIEW_TAG);
        return;
    }

    /* A helper that used Hashed('T', t) instead would produce this byte. */
    if (got.view_tag == OUT_VIEW_TAG_SOURCE_VIEW_TAG_FROM_T) {
        FAIL("view_tag_source", "helper matched the WRONG 'T, t' source");
        return;
    }
    /* Guard against a fixture where H('T', sA)[0] == H('T', t)[0] by chance. */
    if (OUT_VIEW_TAG_SOURCE_VIEW_TAG == OUT_VIEW_TAG_SOURCE_VIEW_TAG_FROM_T) {
        FAIL("view_tag_source",
             "fixture: Hashed('T', sA)[0] == Hashed('T', t)[0] — regenerate");
        return;
    }

    PASS("view_tag_source");
}

/* ── 6. KE_SOURCE — K_e = s*B, not sender_key*A ─────────────────────── */

static void test_ke_source(void)
{
    struct mweb_derived_output got;
    mweb_err_t err = mweb_derive_output(OUT_KE_SOURCE_SENDER_KEY,
                                        OUT_KE_SOURCE_SCAN_A,
                                        OUT_KE_SOURCE_SPEND_B,
                                        OUT_KE_SOURCE_VALUE,
                                        &got);
    if (err != MWEB_OK) {
        FAIL("ke_source", "returned err %d", err);
        return;
    }

    if (memcmp(got.key_exchange_pubkey, OUT_KE_SOURCE_KE, 33) != 0) {
        FAIL("ke_source", "K_e mismatch (s*B)");
        hexprint("got: ", got.key_exchange_pubkey, 33);
        hexprint("exp: ", OUT_KE_SOURCE_KE, 33);
        return;
    }

    /* A helper that computed sender_key*A instead would produce this value. */
    if (memcmp(got.key_exchange_pubkey, OUT_KE_SOURCE_KE_WRONG_SKA, 33) == 0) {
        FAIL("ke_source", "helper matched WRONG sender_key*A");
        return;
    }
    /* Guard against a degenerate fixture. */
    if (memcmp(OUT_KE_SOURCE_KE, OUT_KE_SOURCE_KE_WRONG_SKA, 33) == 0) {
        FAIL("ke_source", "fixture: s*B == sender_key*A — regenerate");
        return;
    }

    PASS("ke_source");
}

/* ── 7. ZERO_VALUE — derivation still works for v = 0 ──────────────── */

static void test_zero_value(void)
{
    struct mweb_derived_output got;
    mweb_err_t err = mweb_derive_output(OUT_ZERO_VALUE_SENDER_KEY,
                                        OUT_ZERO_VALUE_SCAN_A,
                                        OUT_ZERO_VALUE_SPEND_B,
                                        OUT_ZERO_VALUE_VALUE,
                                        &got);
    if (err != MWEB_OK) {
        FAIL("zero_value", "returned err %d", err);
        return;
    }
    if (check_all_fields("zero_value", &got,
                         OUT_ZERO_VALUE_BLIND, OUT_ZERO_VALUE_KO,
                         OUT_ZERO_VALUE_KS, OUT_ZERO_VALUE_KE,
                         OUT_ZERO_VALUE_COMMIT,
                         OUT_ZERO_VALUE_VIEW_TAG,
                         OUT_ZERO_VALUE_MASKED_VALUE,
                         OUT_ZERO_VALUE_MASKED_NONCE)) {
        PASS("zero_value");
    }
}

/* ────────────────────────────────────────────────────────────────────
 *  mweb_build_output[_with_nonces] tests
 * ────────────────────────────────────────────────────────────────────
 *
 * Build-path coverage:
 *   - factored helper produces the SAME 8 binding fields as the verify
 *     path (cross-check against the HAPPY fixture)
 *   - the resulting range_proof verifies via secp256k1_bulletproof_*_verify
 *     against the built commit and the serialized output message
 *   - the resulting signature equals mweb_schnorr_sign(sender_key,
 *     BLAKE3(commit || K_s || K_o || BLAKE3(msg) || BLAKE3(rp))) — anchors
 *     the wrapper's transcript order
 *   - determinism: identical (sk, A, B, v, features, extra_data, nonces)
 *     → byte-identical mweb_built_output
 *   - varying inputs propagate (different nonces -> different proof;
 *     different features -> different proof and signature)
 *   - extra_data shape rules and size cap are enforced
 */

static const uint8_t BP_NONCE[32] = {
    0xc0,0xff,0xee,0xc0,0xff,0xee,0xc0,0xff,
    0xee,0xc0,0xff,0xee,0xc0,0xff,0xee,0xc0,
    0xff,0xee,0xc0,0xff,0xee,0xc0,0xff,0xee,
    0xc0,0xff,0xee,0xc0,0xff,0xee,0xc0,0xff,
};

static const uint8_t BP_PRIVATE_NONCE[32] = {
    0xde,0xad,0xbe,0xef,0xde,0xad,0xbe,0xef,
    0xde,0xad,0xbe,0xef,0xde,0xad,0xbe,0xef,
    0xde,0xad,0xbe,0xef,0xde,0xad,0xbe,0xef,
    0xde,0xad,0xbe,0xef,0xde,0xad,0xbe,0xef,
};

static const uint8_t EXTRA_DATA[] = {
    0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80,
};

/* Independent verifier resources (NUMS table is RFC6979-deterministic
 * of G + index, so the prover and verifier match without sharing
 * state). */
static secp256k1_bulletproof_generators *t_gens = NULL;
static secp256k1_scratch_space          *t_scratch = NULL;

static bool setup_verify_resources(void)
{
    const secp256k1_context *ctx = wally_get_secp_context();
    if (!ctx) return false;
    if (!t_gens) {
        t_gens = secp256k1_bulletproof_generators_create(
            ctx, secp256k1_generator_g, 256);
        if (!t_gens) return false;
    }
    if (!t_scratch) {
        t_scratch = secp256k1_scratch_space_create(ctx, 64u * 1024u);
        if (!t_scratch) return false;
    }
    return true;
}

/* Re-serialize the MwebOutputMessage exactly as mweb_build_output would,
 * but in test code, so the verify side is independent of the production
 * serializer (a bug in the production serializer would surface as a
 * verify failure). */
static size_t build_expected_msg_buf(
    uint8_t features,
    const struct mweb_built_output *built,
    const uint8_t *extra_data, size_t extra_data_len,
    uint8_t *out_buf)
{
    size_t off = 0;
    out_buf[off++] = features;
    if (features & MWEB_OUTPUT_STANDARD_FIELDS_BIT) {
        memcpy(out_buf + off, built->key_exchange_pubkey, 33); off += 33;
        out_buf[off++] = built->view_tag;
        for (int i = 0; i < 8; i++) {
            out_buf[off++] = (uint8_t)(built->masked_value >> (i * 8));
        }
        memcpy(out_buf + off, built->masked_nonce, 16); off += 16;
    }
    if (features & MWEB_OUTPUT_EXTRA_DATA_BIT) {
        uint64_t len = (uint64_t)extra_data_len;
        if (len < 0xfd) {
            out_buf[off++] = (uint8_t)len;
        } else if (len <= 0xffff) {
            out_buf[off++] = 0xfd;
            out_buf[off++] = (uint8_t)(len);
            out_buf[off++] = (uint8_t)(len >> 8);
        } else if (len <= 0xffffffffULL) {
            out_buf[off++] = 0xfe;
            for (int i = 0; i < 4; i++) out_buf[off++] = (uint8_t)(len >> (i * 8));
        } else {
            out_buf[off++] = 0xff;
            for (int i = 0; i < 8; i++) out_buf[off++] = (uint8_t)(len >> (i * 8));
        }
        if (extra_data_len > 0) {
            memcpy(out_buf + off, extra_data, extra_data_len);
            off += extra_data_len;
        }
    }
    return off;
}

static bool verify_built_proof(
    const struct mweb_built_output *built,
    const uint8_t *extra_commit, size_t extra_commit_len)
{
    const secp256k1_context *ctx = wally_get_secp_context();
    secp256k1_pedersen_commitment commit;
    if (!secp256k1_pedersen_commitment_parse(ctx, &commit, built->commit)) {
        return false;
    }
    return secp256k1_bulletproof_rangeproof_verify(
        ctx, t_scratch, t_gens,
        built->range_proof, MWEB_RANGEPROOF_LEN,
        NULL, &commit, 1, 64,
        secp256k1_generator_h,
        extra_commit, extra_commit_len) == 1;
}

/* Independently recompute expected signature from public output fields:
 *   sigHash = BLAKE3(commit || K_s || K_o || BLAKE3(msg) || BLAKE3(rp))
 *   expected = mweb_schnorr_sign(sender_key, sigHash, 32)
 * Both BLAKE3 (linked, content-addressed) and mweb_schnorr_sign
 * (byte-pinned tests) are independently anchored to ltcsuite. */
static bool verify_built_signature(
    const uint8_t sender_key[32],
    const struct mweb_built_output *built,
    const uint8_t *msg_buf, size_t msg_len,
    uint8_t expected_sig_out[64])
{
    uint8_t msg_hash[32], rp_hash[32], sig_hash[32];
    blake3_hasher h;

    blake3_hasher_init(&h);
    blake3_hasher_update(&h, msg_buf, msg_len);
    blake3_hasher_finalize(&h, msg_hash, 32);

    blake3_hasher_init(&h);
    blake3_hasher_update(&h, built->range_proof, MWEB_RANGEPROOF_LEN);
    blake3_hasher_finalize(&h, rp_hash, 32);

    blake3_hasher_init(&h);
    blake3_hasher_update(&h, built->commit,        33);
    blake3_hasher_update(&h, built->sender_pubkey, 33);
    blake3_hasher_update(&h, built->output_pubkey, 33);
    blake3_hasher_update(&h, msg_hash, 32);
    blake3_hasher_update(&h, rp_hash,  32);
    blake3_hasher_finalize(&h, sig_hash, 32);

    return mweb_schnorr_sign(sender_key, sig_hash, 32, expected_sig_out);
}

/* Test 1: factored helper consistency.
 *
 * mweb_derive_output and mweb_build_output_with_nonces share a static
 * helper; both MUST produce identical 8 binding fields for the same
 * (sender_key, A, B, value) inputs. We anchor against the pinned
 * derive_output fixture (HAPPY): if the factored helper diverges, the
 * cross-check fails AND the existing test_happy fails. */
static void test_build_factor_consistency(void)
{
    struct mweb_built_output built;
    mweb_err_t err = mweb_build_output_with_nonces(
        OUT_HAPPY_SENDER_KEY, OUT_HAPPY_SCAN_A, OUT_HAPPY_SPEND_B,
        OUT_HAPPY_VALUE,
        MWEB_OUTPUT_STANDARD_FIELDS_BIT,
        NULL, 0,
        BP_NONCE, BP_PRIVATE_NONCE,
        &built);
    if (err != MWEB_OK) {
        FAIL("build_factor_consistency", "build err=%d", (int)err);
        return;
    }

    bool ok = true;
    if (memcmp(built.blind, OUT_HAPPY_BLIND, 32) != 0) {
        FAIL("build_factor_consistency", "blind diverged from derive fixture");
        hexprint("got: ", built.blind, 32); hexprint("exp: ", OUT_HAPPY_BLIND, 32);
        ok = false;
    }
    if (memcmp(built.output_pubkey, OUT_HAPPY_KO, 33) != 0) {
        FAIL("build_factor_consistency", "K_o diverged"); ok = false;
    }
    if (memcmp(built.sender_pubkey, OUT_HAPPY_KS, 33) != 0) {
        FAIL("build_factor_consistency", "K_s diverged"); ok = false;
    }
    if (memcmp(built.key_exchange_pubkey, OUT_HAPPY_KE, 33) != 0) {
        FAIL("build_factor_consistency", "K_e diverged"); ok = false;
    }
    if (memcmp(built.commit, OUT_HAPPY_COMMIT, 33) != 0) {
        FAIL("build_factor_consistency", "commit diverged"); ok = false;
    }
    if (built.view_tag != OUT_HAPPY_VIEW_TAG) {
        FAIL("build_factor_consistency", "view_tag diverged"); ok = false;
    }
    if (built.masked_value != OUT_HAPPY_MASKED_VALUE) {
        FAIL("build_factor_consistency", "masked_value diverged"); ok = false;
    }
    if (memcmp(built.masked_nonce, OUT_HAPPY_MASKED_NONCE, 16) != 0) {
        FAIL("build_factor_consistency", "masked_nonce diverged"); ok = false;
    }
    if (ok) PASS("build_factor_consistency");
}

/* Test 2: range proof verifies for the built output. */
static void test_build_proof_verifies(void)
{
    struct mweb_built_output built;
    uint8_t expected_msg[MWEB_OUTPUT_MAX_EXTRA_DATA_LEN + 128];

    mweb_err_t err = mweb_build_output_with_nonces(
        OUT_HAPPY_SENDER_KEY, OUT_HAPPY_SCAN_A, OUT_HAPPY_SPEND_B,
        OUT_HAPPY_VALUE,
        MWEB_OUTPUT_STANDARD_FIELDS_BIT,
        NULL, 0,
        BP_NONCE, BP_PRIVATE_NONCE,
        &built);
    if (err != MWEB_OK) {
        FAIL("build_proof_verifies", "build err=%d", (int)err);
        return;
    }
    size_t msg_len = build_expected_msg_buf(
        MWEB_OUTPUT_STANDARD_FIELDS_BIT, &built, NULL, 0, expected_msg);
    if (!verify_built_proof(&built, expected_msg, msg_len)) {
        FAIL("build_proof_verifies", "verify rejected built proof");
        return;
    }
    PASS("build_proof_verifies");
}

/* Test 3: signature equals the independently-computed expected. */
static void test_build_signature_equals_independent(void)
{
    struct mweb_built_output built;
    uint8_t expected_msg[MWEB_OUTPUT_MAX_EXTRA_DATA_LEN + 128];
    uint8_t expected_sig[64];

    mweb_err_t err = mweb_build_output_with_nonces(
        OUT_HAPPY_SENDER_KEY, OUT_HAPPY_SCAN_A, OUT_HAPPY_SPEND_B,
        OUT_HAPPY_VALUE,
        MWEB_OUTPUT_STANDARD_FIELDS_BIT,
        NULL, 0,
        BP_NONCE, BP_PRIVATE_NONCE,
        &built);
    if (err != MWEB_OK) {
        FAIL("build_signature_equals_independent", "build err=%d", (int)err);
        return;
    }
    size_t msg_len = build_expected_msg_buf(
        MWEB_OUTPUT_STANDARD_FIELDS_BIT, &built, NULL, 0, expected_msg);
    if (!verify_built_signature(OUT_HAPPY_SENDER_KEY, &built,
                                 expected_msg, msg_len, expected_sig)) {
        FAIL("build_signature_equals_independent", "schnorr_sign helper failed");
        return;
    }
    if (memcmp(built.signature, expected_sig, 64) != 0) {
        FAIL("build_signature_equals_independent", "signature mismatch");
        return;
    }
    PASS("build_signature_equals_independent");
}

/* Test 4: determinism — identical inputs produce identical built. */
static void test_build_determinism(void)
{
    struct mweb_built_output b1, b2;
    mweb_err_t e1 = mweb_build_output_with_nonces(
        OUT_HAPPY_SENDER_KEY, OUT_HAPPY_SCAN_A, OUT_HAPPY_SPEND_B,
        OUT_HAPPY_VALUE, MWEB_OUTPUT_STANDARD_FIELDS_BIT,
        NULL, 0, BP_NONCE, BP_PRIVATE_NONCE, &b1);
    mweb_err_t e2 = mweb_build_output_with_nonces(
        OUT_HAPPY_SENDER_KEY, OUT_HAPPY_SCAN_A, OUT_HAPPY_SPEND_B,
        OUT_HAPPY_VALUE, MWEB_OUTPUT_STANDARD_FIELDS_BIT,
        NULL, 0, BP_NONCE, BP_PRIVATE_NONCE, &b2);
    if (e1 != MWEB_OK || e2 != MWEB_OK) {
        FAIL("build_determinism", "build failed e1=%d e2=%d", (int)e1, (int)e2);
        return;
    }
    if (memcmp(&b1, &b2, sizeof(b1)) != 0) {
        FAIL("build_determinism", "built structs differ");
        return;
    }
    PASS("build_determinism");
}

/* Test 5: a different bp_nonce changes the proof AND the signature
 * (because the signature transcript includes BLAKE3(range_proof)). */
static void test_build_nonce_propagates(void)
{
    struct mweb_built_output b_canon, b_alt;
    uint8_t alt_nonce[32];
    memcpy(alt_nonce, BP_NONCE, 32);
    alt_nonce[0] ^= 0xff;

    if (mweb_build_output_with_nonces(
            OUT_HAPPY_SENDER_KEY, OUT_HAPPY_SCAN_A, OUT_HAPPY_SPEND_B,
            OUT_HAPPY_VALUE, MWEB_OUTPUT_STANDARD_FIELDS_BIT,
            NULL, 0, BP_NONCE, BP_PRIVATE_NONCE, &b_canon) != MWEB_OK ||
        mweb_build_output_with_nonces(
            OUT_HAPPY_SENDER_KEY, OUT_HAPPY_SCAN_A, OUT_HAPPY_SPEND_B,
            OUT_HAPPY_VALUE, MWEB_OUTPUT_STANDARD_FIELDS_BIT,
            NULL, 0, alt_nonce, BP_PRIVATE_NONCE, &b_alt) != MWEB_OK) {
        FAIL("build_nonce_propagates", "build failed");
        return;
    }
    if (memcmp(b_canon.range_proof, b_alt.range_proof, MWEB_RANGEPROOF_LEN) == 0) {
        FAIL("build_nonce_propagates", "same proof bytes despite different nonce");
        return;
    }
    if (memcmp(b_canon.signature, b_alt.signature, 64) == 0) {
        FAIL("build_nonce_propagates", "same signature despite different proof");
        return;
    }
    /* Binding fields must NOT change — nonces affect only the proof. */
    if (memcmp(b_canon.blind,         b_alt.blind, 32) != 0 ||
        memcmp(b_canon.output_pubkey, b_alt.output_pubkey, 33) != 0 ||
        memcmp(b_canon.sender_pubkey, b_alt.sender_pubkey, 33) != 0 ||
        memcmp(b_canon.commit,        b_alt.commit, 33) != 0) {
        FAIL("build_nonce_propagates", "binding fields changed");
        return;
    }
    PASS("build_nonce_propagates");
}

/* Test 6: features=0x03 (StandardFields | ExtraData) — proof binds to
 * the extra_data section via WriteVarBytes-style compact_size prefix. */
static void test_build_with_extra_data(void)
{
    struct mweb_built_output built;
    uint8_t expected_msg[MWEB_OUTPUT_MAX_EXTRA_DATA_LEN + 128];
    uint8_t expected_sig[64];

    const uint8_t features = MWEB_OUTPUT_STANDARD_FIELDS_BIT
                           | MWEB_OUTPUT_EXTRA_DATA_BIT;

    mweb_err_t err = mweb_build_output_with_nonces(
        OUT_HAPPY_SENDER_KEY, OUT_HAPPY_SCAN_A, OUT_HAPPY_SPEND_B,
        OUT_HAPPY_VALUE,
        features,
        EXTRA_DATA, sizeof(EXTRA_DATA),
        BP_NONCE, BP_PRIVATE_NONCE,
        &built);
    if (err != MWEB_OK) {
        FAIL("build_with_extra_data", "build err=%d", (int)err);
        return;
    }
    /* Binding fields are unchanged from features=0x01 (only the message
     * buffer and downstream proof/sig change). Cross-check against the
     * derive-output fixture to confirm. */
    if (memcmp(built.blind, OUT_HAPPY_BLIND, 32) != 0 ||
        memcmp(built.commit, OUT_HAPPY_COMMIT, 33) != 0) {
        FAIL("build_with_extra_data", "binding diverged with extra_data");
        return;
    }
    size_t msg_len = build_expected_msg_buf(
        features, &built, EXTRA_DATA, sizeof(EXTRA_DATA), expected_msg);
    /* Sanity: message buffer length = 1 + 58 + 1 (compact_size) + 8 = 68. */
    if (msg_len != 1 + 33 + 1 + 8 + 16 + 1 + sizeof(EXTRA_DATA)) {
        FAIL("build_with_extra_data", "expected msg_len wrong: %zu", msg_len);
        return;
    }
    if (!verify_built_proof(&built, expected_msg, msg_len)) {
        FAIL("build_with_extra_data", "proof verify failed");
        return;
    }
    if (!verify_built_signature(OUT_HAPPY_SENDER_KEY, &built,
                                 expected_msg, msg_len, expected_sig)) {
        FAIL("build_with_extra_data", "schnorr_sign helper failed");
        return;
    }
    if (memcmp(built.signature, expected_sig, 64) != 0) {
        FAIL("build_with_extra_data", "signature mismatch");
        return;
    }
    PASS("build_with_extra_data");
}

/* Test 7: features=0x00 (no StandardFields, no ExtraData) — message is
 * just the features byte. The range proof still verifies. */
static void test_build_features_minimal(void)
{
    struct mweb_built_output built;
    uint8_t expected_msg[MWEB_OUTPUT_MAX_EXTRA_DATA_LEN + 128];

    mweb_err_t err = mweb_build_output_with_nonces(
        OUT_HAPPY_SENDER_KEY, OUT_HAPPY_SCAN_A, OUT_HAPPY_SPEND_B,
        OUT_HAPPY_VALUE,
        0x00,
        NULL, 0,
        BP_NONCE, BP_PRIVATE_NONCE,
        &built);
    if (err != MWEB_OK) {
        FAIL("build_features_minimal", "build err=%d", (int)err);
        return;
    }
    size_t msg_len = build_expected_msg_buf(0x00, &built, NULL, 0, expected_msg);
    if (msg_len != 1) {
        FAIL("build_features_minimal", "expected 1-byte msg, got %zu", msg_len);
        return;
    }
    if (!verify_built_proof(&built, expected_msg, msg_len)) {
        FAIL("build_features_minimal", "proof verify failed");
        return;
    }
    PASS("build_features_minimal");
}

/* Test 8: features changes propagate into the proof — features=0x01 and
 * features=0x03 produce different range proofs because the extra_commit
 * (serialized message) differs. */
static void test_build_features_change_proof(void)
{
    struct mweb_built_output b1, b3;
    if (mweb_build_output_with_nonces(
            OUT_HAPPY_SENDER_KEY, OUT_HAPPY_SCAN_A, OUT_HAPPY_SPEND_B,
            OUT_HAPPY_VALUE, MWEB_OUTPUT_STANDARD_FIELDS_BIT,
            NULL, 0, BP_NONCE, BP_PRIVATE_NONCE, &b1) != MWEB_OK ||
        mweb_build_output_with_nonces(
            OUT_HAPPY_SENDER_KEY, OUT_HAPPY_SCAN_A, OUT_HAPPY_SPEND_B,
            OUT_HAPPY_VALUE,
            MWEB_OUTPUT_STANDARD_FIELDS_BIT | MWEB_OUTPUT_EXTRA_DATA_BIT,
            EXTRA_DATA, sizeof(EXTRA_DATA),
            BP_NONCE, BP_PRIVATE_NONCE, &b3) != MWEB_OK) {
        FAIL("build_features_change_proof", "build failed");
        return;
    }
    if (memcmp(b1.range_proof, b3.range_proof, MWEB_RANGEPROOF_LEN) == 0) {
        FAIL("build_features_change_proof", "same proof for different features");
        return;
    }
    PASS("build_features_change_proof");
}

/* Test 9: invalid sender_key → MWEB_ERR_INVALID_SCALAR. */
static void test_build_invalid_sender_key(void)
{
    static const uint8_t ZERO[32] = {0};
    struct mweb_built_output built;
    mweb_err_t err = mweb_build_output_with_nonces(
        ZERO, OUT_HAPPY_SCAN_A, OUT_HAPPY_SPEND_B,
        OUT_HAPPY_VALUE, MWEB_OUTPUT_STANDARD_FIELDS_BIT,
        NULL, 0, BP_NONCE, BP_PRIVATE_NONCE, &built);
    if (err != MWEB_ERR_INVALID_SCALAR) {
        FAIL("build_invalid_sender_key", "expected INVALID_SCALAR, got %d", (int)err);
        return;
    }
    PASS("build_invalid_sender_key");
}

/* Test 10: invalid bp_nonce (zero) → MWEB_ERR_INTERNAL from the
 * rangeproof primitive (mweb_build_rangeproof_with_nonces rejects up-front
 * via mweb_validate_scalar). */
static void test_build_invalid_bp_nonce(void)
{
    static const uint8_t ZERO[32] = {0};
    struct mweb_built_output built;
    mweb_err_t err = mweb_build_output_with_nonces(
        OUT_HAPPY_SENDER_KEY, OUT_HAPPY_SCAN_A, OUT_HAPPY_SPEND_B,
        OUT_HAPPY_VALUE, MWEB_OUTPUT_STANDARD_FIELDS_BIT,
        NULL, 0, ZERO, BP_PRIVATE_NONCE, &built);
    if (err != MWEB_ERR_INTERNAL) {
        FAIL("build_invalid_bp_nonce", "expected MWEB_ERR_INTERNAL, got %d", (int)err);
        return;
    }
    PASS("build_invalid_bp_nonce");
}

/* Test 11: extra_data_len > MAX → MWEB_ERR_INTERNAL. */
static void test_build_extra_data_too_large(void)
{
    uint8_t big[MWEB_OUTPUT_MAX_EXTRA_DATA_LEN + 1];
    memset(big, 0x5a, sizeof(big));
    struct mweb_built_output built;
    mweb_err_t err = mweb_build_output_with_nonces(
        OUT_HAPPY_SENDER_KEY, OUT_HAPPY_SCAN_A, OUT_HAPPY_SPEND_B,
        OUT_HAPPY_VALUE,
        MWEB_OUTPUT_STANDARD_FIELDS_BIT | MWEB_OUTPUT_EXTRA_DATA_BIT,
        big, sizeof(big),
        BP_NONCE, BP_PRIVATE_NONCE, &built);
    if (err != MWEB_ERR_INTERNAL) {
        FAIL("build_extra_data_too_large",
             "expected MWEB_ERR_INTERNAL, got %d", (int)err);
        return;
    }
    PASS("build_extra_data_too_large");
}

/* Test 12: extra_data present but bit not set → MWEB_ERR_INTERNAL. */
static void test_build_extra_data_without_bit(void)
{
    struct mweb_built_output built;
    mweb_err_t err = mweb_build_output_with_nonces(
        OUT_HAPPY_SENDER_KEY, OUT_HAPPY_SCAN_A, OUT_HAPPY_SPEND_B,
        OUT_HAPPY_VALUE,
        MWEB_OUTPUT_STANDARD_FIELDS_BIT, /* no EXTRA_DATA_BIT */
        EXTRA_DATA, sizeof(EXTRA_DATA),
        BP_NONCE, BP_PRIVATE_NONCE, &built);
    if (err != MWEB_ERR_INTERNAL) {
        FAIL("build_extra_data_without_bit",
             "expected MWEB_ERR_INTERNAL, got %d", (int)err);
        return;
    }
    PASS("build_extra_data_without_bit");
}

/* Test 13: NULL bp_nonce / bp_private_nonce in _with_nonces → reject. */
static void test_build_null_nonce_with_nonces(void)
{
    struct mweb_built_output built;
    mweb_err_t err1 = mweb_build_output_with_nonces(
        OUT_HAPPY_SENDER_KEY, OUT_HAPPY_SCAN_A, OUT_HAPPY_SPEND_B,
        OUT_HAPPY_VALUE, MWEB_OUTPUT_STANDARD_FIELDS_BIT,
        NULL, 0, NULL, BP_PRIVATE_NONCE, &built);
    if (err1 != MWEB_ERR_INTERNAL) {
        FAIL("build_null_nonce_with_nonces",
             "NULL bp_nonce: expected MWEB_ERR_INTERNAL, got %d", (int)err1);
        return;
    }
    mweb_err_t err2 = mweb_build_output_with_nonces(
        OUT_HAPPY_SENDER_KEY, OUT_HAPPY_SCAN_A, OUT_HAPPY_SPEND_B,
        OUT_HAPPY_VALUE, MWEB_OUTPUT_STANDARD_FIELDS_BIT,
        NULL, 0, BP_NONCE, NULL, &built);
    if (err2 != MWEB_ERR_INTERNAL) {
        FAIL("build_null_nonce_with_nonces",
             "NULL bp_private_nonce: expected MWEB_ERR_INTERNAL, got %d", (int)err2);
        return;
    }
    PASS("build_null_nonce_with_nonces");
}

/* Test 14: features=0x02 (ExtraDataBit only) with extra_data_len==0 →
 * message = [features byte | compact_size(0)] = exactly 2 bytes.
 * Locks the contract that an EXTRA_DATA_BIT flagged output with no
 * payload still emits the WriteVarBytes length prefix, and that the
 * Standard-fields section is properly omitted when its bit is clear. */
static void test_build_extra_data_bit_with_zero_len(void)
{
    struct mweb_built_output built;
    uint8_t expected_msg[MWEB_OUTPUT_MAX_EXTRA_DATA_LEN + 128];

    const uint8_t features = MWEB_OUTPUT_EXTRA_DATA_BIT;

    mweb_err_t err = mweb_build_output_with_nonces(
        OUT_HAPPY_SENDER_KEY, OUT_HAPPY_SCAN_A, OUT_HAPPY_SPEND_B,
        OUT_HAPPY_VALUE,
        features,
        NULL, 0,
        BP_NONCE, BP_PRIVATE_NONCE,
        &built);
    if (err != MWEB_OK) {
        FAIL("build_extra_data_bit_with_zero_len", "build err=%d", (int)err);
        return;
    }
    size_t msg_len = build_expected_msg_buf(features, &built, NULL, 0, expected_msg);
    /* 1 features + 1 compact_size(0) = 2; no standard-fields block. */
    if (msg_len != 2) {
        FAIL("build_extra_data_bit_with_zero_len", "expected msg_len=2, got %zu", msg_len);
        return;
    }
    if (expected_msg[0] != 0x02 || expected_msg[1] != 0x00) {
        FAIL("build_extra_data_bit_with_zero_len",
             "expected [0x02, 0x00], got [0x%02x, 0x%02x]",
             expected_msg[0], expected_msg[1]);
        return;
    }
    if (!verify_built_proof(&built, expected_msg, msg_len)) {
        FAIL("build_extra_data_bit_with_zero_len", "proof verify failed");
        return;
    }
    PASS("build_extra_data_bit_with_zero_len");
}

/* Test 15: NULL extra_data with positive extra_data_len → MWEB_ERR_INTERNAL
 * (caller bug; the bit-set + zero-len case is covered by Test 14). */
static void test_build_null_extra_data_positive_len(void)
{
    struct mweb_built_output built;
    mweb_err_t err = mweb_build_output_with_nonces(
        OUT_HAPPY_SENDER_KEY, OUT_HAPPY_SCAN_A, OUT_HAPPY_SPEND_B,
        OUT_HAPPY_VALUE,
        MWEB_OUTPUT_STANDARD_FIELDS_BIT | MWEB_OUTPUT_EXTRA_DATA_BIT,
        NULL, 5,
        BP_NONCE, BP_PRIVATE_NONCE,
        &built);
    if (err != MWEB_ERR_INTERNAL) {
        FAIL("build_null_extra_data_positive_len",
             "expected MWEB_ERR_INTERNAL, got %d", (int)err);
        return;
    }
    PASS("build_null_extra_data_positive_len");
}

/* Test 16: production path with broken TRNG (stub returns all-zero) →
 * 8 retries exhausted → MWEB_ERR_INTERNAL. Exercises mweb_build_output
 * which forwards to mweb_build_rangeproof's internal TRNG draws. */
static void test_build_production_path_trng_failure(void)
{
    struct mweb_built_output built;
    mweb_err_t err = mweb_build_output(
        OUT_HAPPY_SENDER_KEY, OUT_HAPPY_SCAN_A, OUT_HAPPY_SPEND_B,
        OUT_HAPPY_VALUE, MWEB_OUTPUT_STANDARD_FIELDS_BIT,
        NULL, 0, &built);
    if (err != MWEB_ERR_INTERNAL) {
        FAIL("build_production_path_trng_failure",
             "expected MWEB_ERR_INTERNAL, got %d (stub TRNG returns 0)", (int)err);
        return;
    }
    PASS("build_production_path_trng_failure");
}

/* Test 17: every failure path must leave `built` zeroed (the header
 * contract). Pre-fill with a 0xa5 marker, call with bad inputs, and
 * confirm the wrapper zeroed the buffer instead of leaking caller
 * residue. Covers each path the wrapper can take to a non-OK return:
 *   - invalid sender_key
 *   - extra_data bytes without the bit
 *   - extra_data_len above MWEB_OUTPUT_MAX_EXTRA_DATA_LEN
 *   - NULL extra_data with positive len
 *   - NULL bp_nonce (wrapper-level, before build_output_impl)
 *   - NULL bp_private_nonce (wrapper-level)
 * The marker byte 0xa5 = 0b10100101 is chosen so any single surviving
 * byte fails the all-zero check. */
static bool buffer_is_all_zero(const struct mweb_built_output *b)
{
    const uint8_t *p = (const uint8_t *)b;
    for (size_t i = 0; i < sizeof(*b); i++) {
        if (p[i] != 0) return false;
    }
    return true;
}

static void test_build_failure_zeroes_built(void)
{
    static const uint8_t ZERO[32] = {0};
    struct mweb_built_output built;
    uint8_t marker[sizeof(built)];
    memset(marker, 0xa5, sizeof(marker));

    /* (a) Invalid sender_key. */
    memcpy(&built, marker, sizeof(built));
    if (mweb_build_output_with_nonces(
            ZERO, OUT_HAPPY_SCAN_A, OUT_HAPPY_SPEND_B,
            OUT_HAPPY_VALUE, MWEB_OUTPUT_STANDARD_FIELDS_BIT,
            NULL, 0, BP_NONCE, BP_PRIVATE_NONCE, &built)
        != MWEB_ERR_INVALID_SCALAR) {
        FAIL("build_failure_zeroes_built", "(a) wrong error");
        return;
    }
    if (!buffer_is_all_zero(&built)) {
        FAIL("build_failure_zeroes_built", "(a) buffer not zeroed");
        return;
    }

    /* (b) Bytes without bit. */
    memcpy(&built, marker, sizeof(built));
    if (mweb_build_output_with_nonces(
            OUT_HAPPY_SENDER_KEY, OUT_HAPPY_SCAN_A, OUT_HAPPY_SPEND_B,
            OUT_HAPPY_VALUE, MWEB_OUTPUT_STANDARD_FIELDS_BIT,
            EXTRA_DATA, sizeof(EXTRA_DATA), BP_NONCE, BP_PRIVATE_NONCE, &built)
        != MWEB_ERR_INTERNAL) {
        FAIL("build_failure_zeroes_built", "(b) wrong error");
        return;
    }
    if (!buffer_is_all_zero(&built)) {
        FAIL("build_failure_zeroes_built", "(b) buffer not zeroed");
        return;
    }

    /* (c) Oversize extra_data. */
    uint8_t big[MWEB_OUTPUT_MAX_EXTRA_DATA_LEN + 1];
    memset(big, 0x5a, sizeof(big));
    memcpy(&built, marker, sizeof(built));
    if (mweb_build_output_with_nonces(
            OUT_HAPPY_SENDER_KEY, OUT_HAPPY_SCAN_A, OUT_HAPPY_SPEND_B,
            OUT_HAPPY_VALUE,
            MWEB_OUTPUT_STANDARD_FIELDS_BIT | MWEB_OUTPUT_EXTRA_DATA_BIT,
            big, sizeof(big), BP_NONCE, BP_PRIVATE_NONCE, &built)
        != MWEB_ERR_INTERNAL) {
        FAIL("build_failure_zeroes_built", "(c) wrong error");
        return;
    }
    if (!buffer_is_all_zero(&built)) {
        FAIL("build_failure_zeroes_built", "(c) buffer not zeroed");
        return;
    }

    /* (d) NULL extra_data with positive len. */
    memcpy(&built, marker, sizeof(built));
    if (mweb_build_output_with_nonces(
            OUT_HAPPY_SENDER_KEY, OUT_HAPPY_SCAN_A, OUT_HAPPY_SPEND_B,
            OUT_HAPPY_VALUE,
            MWEB_OUTPUT_STANDARD_FIELDS_BIT | MWEB_OUTPUT_EXTRA_DATA_BIT,
            NULL, 5, BP_NONCE, BP_PRIVATE_NONCE, &built)
        != MWEB_ERR_INTERNAL) {
        FAIL("build_failure_zeroes_built", "(d) wrong error");
        return;
    }
    if (!buffer_is_all_zero(&built)) {
        FAIL("build_failure_zeroes_built", "(d) buffer not zeroed");
        return;
    }

    /* (e) NULL bp_nonce — rejected at the wrapper level, BEFORE
     * build_output_impl runs. Confirms the wrapper-level memset works. */
    memcpy(&built, marker, sizeof(built));
    if (mweb_build_output_with_nonces(
            OUT_HAPPY_SENDER_KEY, OUT_HAPPY_SCAN_A, OUT_HAPPY_SPEND_B,
            OUT_HAPPY_VALUE, MWEB_OUTPUT_STANDARD_FIELDS_BIT,
            NULL, 0, NULL, BP_PRIVATE_NONCE, &built)
        != MWEB_ERR_INTERNAL) {
        FAIL("build_failure_zeroes_built", "(e) wrong error");
        return;
    }
    if (!buffer_is_all_zero(&built)) {
        FAIL("build_failure_zeroes_built", "(e) buffer not zeroed");
        return;
    }

    /* (f) NULL bp_private_nonce. */
    memcpy(&built, marker, sizeof(built));
    if (mweb_build_output_with_nonces(
            OUT_HAPPY_SENDER_KEY, OUT_HAPPY_SCAN_A, OUT_HAPPY_SPEND_B,
            OUT_HAPPY_VALUE, MWEB_OUTPUT_STANDARD_FIELDS_BIT,
            NULL, 0, BP_NONCE, NULL, &built)
        != MWEB_ERR_INTERNAL) {
        FAIL("build_failure_zeroes_built", "(f) wrong error");
        return;
    }
    if (!buffer_is_all_zero(&built)) {
        FAIL("build_failure_zeroes_built", "(f) buffer not zeroed");
        return;
    }

    PASS("build_failure_zeroes_built");
}

int main(void)
{
    test_happy();
    test_invalid_scalar();
    test_endian();
    test_tag_bytes();
    test_view_tag_source();
    test_ke_source();
    test_zero_value();

    if (!setup_verify_resources()) {
        printf("FATAL: could not allocate test verify resources\n");
        return 1;
    }
    test_build_factor_consistency();
    test_build_proof_verifies();
    test_build_signature_equals_independent();
    test_build_determinism();
    test_build_nonce_propagates();
    test_build_with_extra_data();
    test_build_features_minimal();
    test_build_features_change_proof();
    test_build_invalid_sender_key();
    test_build_invalid_bp_nonce();
    test_build_extra_data_too_large();
    test_build_extra_data_without_bit();
    test_build_null_nonce_with_nonces();
    test_build_extra_data_bit_with_zero_len();
    test_build_null_extra_data_positive_len();
    test_build_production_path_trng_failure();
    test_build_failure_zeroes_built();

    printf("\n%d/%d tests passed (%d failures)\n",
           test_count - failures, test_count, failures);
    return failures == 0 ? 0 : 1;
}
