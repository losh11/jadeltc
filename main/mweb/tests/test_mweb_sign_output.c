/*
 * Tests for mweb_sign_output (per-output MWEB Schnorr signature wrapper).
 *
 * mweb_sign_output is sigHash = BLAKE3(commit || K_s || K_o || msg_hash
 * || rp_hash) followed by mweb_schnorr_sign(sender_key, sigHash, 32).
 * Both primitives have their own byte-pinned vectors anchored against
 * ltcsuite, so the wrapper is exercised here by computing the same
 * composition independently in the test and asserting equality, plus a
 * battery of order-sensitivity / NULL / invalid-scalar checks that
 * would catch any wrapper-only bug (reordered concat, wrong hash
 * function, dropped input, missing scalar validation).
 */
#include "mweb_schnorr.h"
#include "mweb_kernel.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <blake3.h>
#include <wally_core.h>

static int failures = 0;
static int test_count = 0;

#define PASS(name) do { test_count++; printf("PASS: %s\n", name); } while (0)
#define FAIL(name, ...) do { test_count++; failures++; printf("FAIL: %s — ", name); printf(__VA_ARGS__); printf("\n"); } while (0)

/* --- Test keys (m/0'/100' from common test seed; same as test_mweb_schnorr) --- */

static const uint8_t SCAN_KEY[32] = {
    0xb3,0xc9,0x1b,0x72,0x91,0xc2,0xe1,0xe0,
    0x6d,0x4a,0x93,0xf3,0xdc,0x32,0x40,0x4a,
    0xef,0x99,0x27,0xdb,0x8e,0x79,0x4c,0x01,
    0xa7,0xb4,0xde,0x18,0xa3,0x97,0xc3,0x38,
};

static const uint8_t SPEND_KEY[32] = {
    0x2f,0xe1,0x98,0x2b,0x98,0xc0,0xb6,0x8c,
    0x08,0x39,0x42,0x1c,0x8a,0x0a,0x0a,0x67,
    0xef,0x31,0x98,0xc7,0x46,0xab,0x8e,0x6d,
    0x09,0x10,0x1e,0xb7,0x39,0x6a,0x44,0xd8,
};

/* --- Pseudo output fields (distinct first bytes so reorder bugs are caught) --- */

static const uint8_t COMMIT[33] = {
    0x08,
    0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,
    0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,
    0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,
    0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,
};

static const uint8_t Ks[33] = {
    0x02,
    0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22,
    0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22,
    0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22,
    0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22,
};

static const uint8_t Ko[33] = {
    0x03,
    0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,
    0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,
    0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,
    0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,
};

static const uint8_t MSG_HASH[32] = {
    0x44,0x44,0x44,0x44,0x44,0x44,0x44,0x44,
    0x44,0x44,0x44,0x44,0x44,0x44,0x44,0x44,
    0x44,0x44,0x44,0x44,0x44,0x44,0x44,0x44,
    0x44,0x44,0x44,0x44,0x44,0x44,0x44,0x44,
};

static const uint8_t RP_HASH[32] = {
    0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,
    0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,
    0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,
    0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,
};

/* --- Helpers --- */

/* Compute sigHash = BLAKE3(commit || K_s || K_o || msg_hash || rp_hash)
 * via an independent blake3_hasher call. Mirrors what mweb_sign_output
 * must compute; a divergence in the wrapper's internal hash (reorder,
 * substitute, drop, or extra input) makes the round-trip assertion fail. */
static void compose_sig_hash(
    const uint8_t commit[33], const uint8_t Ks_[33], const uint8_t Ko_[33],
    const uint8_t msg_hash[32], const uint8_t rp_hash[32],
    uint8_t out[32])
{
    blake3_hasher h;
    blake3_hasher_init(&h);
    blake3_hasher_update(&h, commit,   33);
    blake3_hasher_update(&h, Ks_,      33);
    blake3_hasher_update(&h, Ko_,      33);
    blake3_hasher_update(&h, msg_hash, 32);
    blake3_hasher_update(&h, rp_hash,  32);
    blake3_hasher_finalize(&h, out, 32);
}

/* --- Tests --- */

/*
 * Round-trip: compute the expected signature using the same primitives
 * the wrapper uses (BLAKE3 of canonical concat, mweb_schnorr_sign of
 * the resulting hash) and assert byte-equality with mweb_sign_output.
 * Both primitives are byte-anchored against ltcsuite via their own
 * tests; this test pins the wrapper's composition.
 */
static void test_round_trip(const char *name, const uint8_t sender_key[32])
{
    uint8_t expected_sig_hash[32];
    uint8_t expected_sig[64];
    uint8_t actual_sig[64];

    compose_sig_hash(COMMIT, Ks, Ko, MSG_HASH, RP_HASH, expected_sig_hash);
    if (!mweb_schnorr_sign(sender_key, expected_sig_hash, 32, expected_sig)) {
        FAIL(name, "expected_sig schnorr_sign failed");
        return;
    }

    mweb_err_t err = mweb_sign_output(
        sender_key, COMMIT, Ks, Ko, MSG_HASH, RP_HASH, actual_sig);
    if (err != MWEB_OK) {
        FAIL(name, "mweb_sign_output err=%d", (int)err);
        return;
    }

    if (memcmp(actual_sig, expected_sig, 64) != 0) {
        FAIL(name, "signature mismatch");
        printf("  got : ");
        for (int i = 0; i < 64; i++) printf("%02x", actual_sig[i]);
        printf("\n  want: ");
        for (int i = 0; i < 64; i++) printf("%02x", expected_sig[i]);
        printf("\n");
        return;
    }
    PASS(name);
}

/*
 * Determinism: identical inputs must produce identical signatures
 * (mweb_schnorr_sign uses a deterministic nonce derived from sk + msg).
 */
static void test_determinism(void)
{
    uint8_t s1[64], s2[64];
    if (mweb_sign_output(SCAN_KEY, COMMIT, Ks, Ko, MSG_HASH, RP_HASH, s1) != MWEB_OK ||
        mweb_sign_output(SCAN_KEY, COMMIT, Ks, Ko, MSG_HASH, RP_HASH, s2) != MWEB_OK) {
        FAIL("determinism", "sign failed");
        return;
    }
    if (memcmp(s1, s2, 64) != 0) {
        FAIL("determinism", "signatures differ");
        return;
    }
    PASS("determinism");
}

/*
 * Order-sensitivity: swapping any two of (commit, K_s, K_o) must change
 * the signature. Catches reorder bugs in the wrapper's BLAKE3 calls.
 */
static void test_order_sensitive_commit_Ks(void)
{
    uint8_t s_canon[64], s_swapped[64];

    if (mweb_sign_output(SCAN_KEY, COMMIT, Ks, Ko, MSG_HASH, RP_HASH, s_canon) != MWEB_OK) {
        FAIL("order_commit_Ks", "canon sign failed");
        return;
    }
    /* Pass Ks where commit goes and commit where Ks goes — must yield a
     * different signature, otherwise the wrapper isn't honoring the
     * canonical order. */
    if (mweb_sign_output(SCAN_KEY, Ks, COMMIT, Ko, MSG_HASH, RP_HASH, s_swapped) != MWEB_OK) {
        FAIL("order_commit_Ks", "swapped sign failed");
        return;
    }
    if (memcmp(s_canon, s_swapped, 64) == 0) {
        FAIL("order_commit_Ks", "swap produced same signature — wrapper ignores order");
        return;
    }
    PASS("order_commit_Ks");
}

static void test_order_sensitive_msg_rp(void)
{
    uint8_t s_canon[64], s_swapped[64];

    if (mweb_sign_output(SCAN_KEY, COMMIT, Ks, Ko, MSG_HASH, RP_HASH, s_canon) != MWEB_OK) {
        FAIL("order_msg_rp", "canon sign failed");
        return;
    }
    if (mweb_sign_output(SCAN_KEY, COMMIT, Ks, Ko, RP_HASH, MSG_HASH, s_swapped) != MWEB_OK) {
        FAIL("order_msg_rp", "swapped sign failed");
        return;
    }
    if (memcmp(s_canon, s_swapped, 64) == 0) {
        FAIL("order_msg_rp", "swap produced same signature");
        return;
    }
    PASS("order_msg_rp");
}

/*
 * Differing sender_key must change the signature: confirms the wrapper
 * actually passes sender_key into mweb_schnorr_sign rather than hashing
 * it (or ignoring it).
 */
static void test_sender_key_changes_sig(void)
{
    uint8_t s_scan[64], s_spend[64];
    if (mweb_sign_output(SCAN_KEY,  COMMIT, Ks, Ko, MSG_HASH, RP_HASH, s_scan)  != MWEB_OK ||
        mweb_sign_output(SPEND_KEY, COMMIT, Ks, Ko, MSG_HASH, RP_HASH, s_spend) != MWEB_OK) {
        FAIL("sender_key_changes_sig", "sign failed");
        return;
    }
    if (memcmp(s_scan, s_spend, 64) == 0) {
        FAIL("sender_key_changes_sig", "different keys produced same signature");
        return;
    }
    PASS("sender_key_changes_sig");
}

/*
 * Each input must change the signature: flip one byte of each of
 * commit, K_s, K_o, msg_hash, rp_hash in turn and confirm divergence.
 * Catches the case where the wrapper hashes the right number of bytes
 * total but reads from the wrong source.
 */
static void test_each_input_in_sig_hash(void)
{
    uint8_t s_canon[64];
    if (mweb_sign_output(SCAN_KEY, COMMIT, Ks, Ko, MSG_HASH, RP_HASH, s_canon) != MWEB_OK) {
        FAIL("each_input_in_hash", "canon sign failed");
        return;
    }

    struct { const char *label; size_t which; } variants[] = {
        {"commit",   0},
        {"Ks",       1},
        {"Ko",       2},
        {"msg_hash", 3},
        {"rp_hash",  4},
    };
    for (size_t i = 0; i < sizeof(variants)/sizeof(variants[0]); i++) {
        uint8_t c[33], ks[33], ko[33], mh[32], rh[32];
        memcpy(c,  COMMIT, 33);
        memcpy(ks, Ks,     33);
        memcpy(ko, Ko,     33);
        memcpy(mh, MSG_HASH, 32);
        memcpy(rh, RP_HASH,  32);
        switch (variants[i].which) {
            case 0: c[10]  ^= 0xff; break;
            case 1: ks[10] ^= 0xff; break;
            case 2: ko[10] ^= 0xff; break;
            case 3: mh[10] ^= 0xff; break;
            case 4: rh[10] ^= 0xff; break;
        }
        uint8_t s_perturbed[64];
        if (mweb_sign_output(SCAN_KEY, c, ks, ko, mh, rh, s_perturbed) != MWEB_OK) {
            FAIL("each_input_in_hash", "perturbed sign failed (%s)", variants[i].label);
            return;
        }
        if (memcmp(s_canon, s_perturbed, 64) == 0) {
            FAIL("each_input_in_hash", "%s perturbation did not change sig", variants[i].label);
            return;
        }
    }
    PASS("each_input_in_hash");
}

/*
 * Invalid sender_key → MWEB_ERR_INVALID_SCALAR.
 */
static void test_zero_sender_key_rejected(void)
{
    static const uint8_t ZERO[32] = {0};
    uint8_t sig[64] = {0};
    mweb_err_t err = mweb_sign_output(ZERO, COMMIT, Ks, Ko, MSG_HASH, RP_HASH, sig);
    if (err == MWEB_OK) {
        FAIL("zero_sender_key_rejected", "accepted zero sender_key");
        return;
    }
    if (err != MWEB_ERR_INVALID_SCALAR) {
        FAIL("zero_sender_key_rejected", "wrong err code: %d", (int)err);
        return;
    }
    PASS("zero_sender_key_rejected");
}

static void test_overflow_sender_key_rejected(void)
{
    static const uint8_t ORDER[32] = {
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,
        0xBA,0xAE,0xDC,0xE6,0xAF,0x48,0xA0,0x3B,
        0xBF,0xD2,0x5E,0x8C,0xD0,0x36,0x41,0x41,
    };
    uint8_t sig[64] = {0};
    mweb_err_t err = mweb_sign_output(ORDER, COMMIT, Ks, Ko, MSG_HASH, RP_HASH, sig);
    if (err == MWEB_OK) {
        FAIL("overflow_sender_key_rejected", "accepted n-as-sender_key");
        return;
    }
    if (err != MWEB_ERR_INVALID_SCALAR) {
        FAIL("overflow_sender_key_rejected", "wrong err code: %d", (int)err);
        return;
    }
    PASS("overflow_sender_key_rejected");
}

/*
 * NULL pointer arguments → MWEB_ERR_INTERNAL.
 */
static void test_null_args_rejected(void)
{
    uint8_t sig[64] = {0};
    if (mweb_sign_output(NULL, COMMIT, Ks, Ko, MSG_HASH, RP_HASH, sig) != MWEB_ERR_INTERNAL) {
        FAIL("null_args_rejected", "NULL sender_key accepted");
        return;
    }
    if (mweb_sign_output(SCAN_KEY, NULL, Ks, Ko, MSG_HASH, RP_HASH, sig) != MWEB_ERR_INTERNAL) {
        FAIL("null_args_rejected", "NULL commit accepted");
        return;
    }
    if (mweb_sign_output(SCAN_KEY, COMMIT, NULL, Ko, MSG_HASH, RP_HASH, sig) != MWEB_ERR_INTERNAL) {
        FAIL("null_args_rejected", "NULL Ks accepted");
        return;
    }
    if (mweb_sign_output(SCAN_KEY, COMMIT, Ks, NULL, MSG_HASH, RP_HASH, sig) != MWEB_ERR_INTERNAL) {
        FAIL("null_args_rejected", "NULL Ko accepted");
        return;
    }
    if (mweb_sign_output(SCAN_KEY, COMMIT, Ks, Ko, NULL, RP_HASH, sig) != MWEB_ERR_INTERNAL) {
        FAIL("null_args_rejected", "NULL msg_hash accepted");
        return;
    }
    if (mweb_sign_output(SCAN_KEY, COMMIT, Ks, Ko, MSG_HASH, NULL, sig) != MWEB_ERR_INTERNAL) {
        FAIL("null_args_rejected", "NULL rp_hash accepted");
        return;
    }
    if (mweb_sign_output(SCAN_KEY, COMMIT, Ks, Ko, MSG_HASH, RP_HASH, NULL) != MWEB_ERR_INTERNAL) {
        FAIL("null_args_rejected", "NULL sig_out accepted");
        return;
    }
    PASS("null_args_rejected");
}

int main(void)
{
    test_round_trip("round_trip_scan",  SCAN_KEY);
    test_round_trip("round_trip_spend", SPEND_KEY);
    test_determinism();
    test_order_sensitive_commit_Ks();
    test_order_sensitive_msg_rp();
    test_sender_key_changes_sig();
    test_each_input_in_sig_hash();
    test_zero_sender_key_rejected();
    test_overflow_sender_key_rejected();
    test_null_args_rejected();

    printf("\n%d/%d tests passed (%d failures)\n",
           test_count - failures, test_count, failures);
    return failures == 0 ? 0 : 1;
}
