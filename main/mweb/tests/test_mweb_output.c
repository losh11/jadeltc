/*
 * Tests for mweb_derive_output.
 *
 * Fixtures generated with pinned inputs.
 */
#include "mweb_kernel.h"   /* mweb_err_t */
#include "mweb_output.h"
#include "fixtures/output_vectors.h"

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

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
    if (err != MWEB_ERR_INVALID_PRESIGN_SCALAR) {
        FAIL("invalid_scalar/zero", "expected INVALID_PRESIGN_SCALAR, got %d", err);
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
    if (err != MWEB_ERR_INVALID_PRESIGN_SCALAR) {
        FAIL("invalid_scalar/n", "expected INVALID_PRESIGN_SCALAR, got %d", err);
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
    if (err != MWEB_ERR_INVALID_PRESIGN_SCALAR) {
        FAIL("invalid_scalar/n+1", "expected INVALID_PRESIGN_SCALAR, got %d", err);
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

int main(void)
{
    test_happy();
    test_invalid_scalar();
    test_endian();
    test_tag_bytes();
    test_view_tag_source();
    test_ke_source();
    test_zero_value();

    printf("\n%d/%d tests passed (%d failures)\n",
           test_count - failures, test_count, failures);
    return failures == 0 ? 0 : 1;
}
