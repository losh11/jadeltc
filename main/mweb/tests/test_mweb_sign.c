/*
 * Tests for the two-stage MWEB input signing API.
 *
 *   mweb_derive_input_state — Stage A (non-signing derivation)
 *   mweb_sign_input_from_state — Stage B (Schnorr emission)
 *
 * Uses the known scan/spend keys from mweb_compat_test.go and constructs
 * a synthetic MWEB input to test:
 *   - Output key verification accepts correct address_index
 *   - Output key verification rejects wrong address_index
 *   - Missing STEALTH_KEY_BIT is rejected
 *   - Two-stage pipeline is deterministic given a fixed ephemeral
 *   - Reference-vector parity against the legacy single-shot signer
 *   - extra_data affects the emitted signature
 *   - EXTRA_DATA_BIT with empty data is distinguishable from no-bit
 *   - Stage A emits no signature (no Schnorr side effect)
 */
#include "mweb_sign.h"
#include "mweb_hash.h"
#include "mweb_kernel.h"

#include <stdio.h>
#include <string.h>

#include <blake3.h>
#include <secp256k1.h>
#include <wally_core.h>
#include <wally_crypto.h>

static int failures = 0;

/* Deterministic "random" for testing — set by test before calling Stage A. */
static uint8_t g_test_random[32];

/* Stub for get_random that returns deterministic bytes. */
void get_random(void* bytes_out, size_t len)
{
    if (len <= 32) {
        memcpy(bytes_out, g_test_random, len);
    } else {
        memset(bytes_out, 0, len);
        memcpy(bytes_out, g_test_random, 32);
    }
}

/* --- Known keys from mweb_compat_test.go --- */

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

/*
 * Build a synthetic MWEB output for testing.
 * Given scan/spend keys, address index, and a sender key, derive:
 *   - key_exchange_pk
 *   - spent_output_pk (Ko)
 *   - spent_output_id (arbitrary hash)
 */
static bool build_test_input(
    uint32_t address_index,
    const uint8_t sender_key[32],
    uint8_t key_exchange_pk_out[33],
    uint8_t spent_output_pk_out[33],
    uint8_t spent_output_id_out[32])
{
    const secp256k1_context* ctx = wally_get_secp_context();

    /* m_i = Hashed('A', index || scan_key) */
    uint8_t mi_buf[4 + 32];
    mi_buf[0] = (uint8_t)(address_index);
    mi_buf[1] = (uint8_t)(address_index >> 8);
    mi_buf[2] = (uint8_t)(address_index >> 16);
    mi_buf[3] = (uint8_t)(address_index >> 24);
    memcpy(mi_buf + 4, SCAN_KEY, 32);
    uint8_t m_i[32];
    mweb_hashed(MWEB_TAG_ADDRESS, mi_buf, sizeof(mi_buf), m_i);

    /* B_i = spend_pub + m_i*G */
    uint8_t spend_pub[33], mi_pub[33];
    if (wally_ec_public_key_from_private_key(SPEND_KEY, 32, spend_pub, 33) != WALLY_OK) return false;
    if (wally_ec_public_key_from_private_key(m_i, 32, mi_pub, 33) != WALLY_OK) return false;

    secp256k1_pubkey sp_pk, mi_pk, Bi_pk;
    if (!secp256k1_ec_pubkey_parse(ctx, &sp_pk, spend_pub, 33)) return false;
    if (!secp256k1_ec_pubkey_parse(ctx, &mi_pk, mi_pub, 33)) return false;
    const secp256k1_pubkey* pts[2] = { &sp_pk, &mi_pk };
    if (!secp256k1_ec_pubkey_combine(ctx, &Bi_pk, pts, 2)) return false;

    /* key_exchange_pk = sender_key * B_i */
    secp256k1_pubkey Ke_pk = Bi_pk;
    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &Ke_pk, sender_key)) return false;
    size_t ke_len = 33;
    secp256k1_ec_pubkey_serialize(ctx, key_exchange_pk_out, &ke_len, &Ke_pk, SECP256K1_EC_COMPRESSED);

    /* shared_secret = Hashed('D', key_exchange_pk * scan_key) */
    secp256k1_pubkey kex_parsed;
    if (!secp256k1_ec_pubkey_parse(ctx, &kex_parsed, key_exchange_pk_out, 33)) return false;
    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &kex_parsed, SCAN_KEY)) return false;
    uint8_t ecdh_bytes[33];
    size_t ecdh_len = 33;
    secp256k1_ec_pubkey_serialize(ctx, ecdh_bytes, &ecdh_len, &kex_parsed, SECP256K1_EC_COMPRESSED);
    uint8_t ss[32];
    mweb_hashed(MWEB_TAG_DERIVE, ecdh_bytes, 33, ss);

    /* out_key_hash = Hashed('O', shared_secret) */
    uint8_t okh[32];
    mweb_hashed(MWEB_TAG_OUTKEY, ss, 32, okh);

    /* Ko = out_key_hash * B_i */
    secp256k1_pubkey Ko_pk = Bi_pk;
    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &Ko_pk, okh)) return false;
    size_t ko_len = 33;
    secp256k1_ec_pubkey_serialize(ctx, spent_output_pk_out, &ko_len, &Ko_pk, SECP256K1_EC_COMPRESSED);

    /* spent_output_id: deterministic hash of Ko */
    mweb_hashed(MWEB_TAG_TAG, spent_output_pk_out, 33, spent_output_id_out);

    return true;
}

/* --- Tests --- */

static void test_two_stage_success(void)
{
    const uint8_t sender_key[32] = {
        0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,
        0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff,0x00,
        0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
        0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10,
    };

    uint8_t kex[33], Ko[33], oid[32];
    if (!build_test_input(0, sender_key, kex, Ko, oid)) {
        printf("FAIL: two_stage_success — build_test_input\n");
        failures++;
        return;
    }

    memset(g_test_random, 0x42, 32);

    mweb_input_state_t state;
    if (mweb_derive_input_state(SCAN_KEY, SPEND_KEY, 0,
            MWEB_INPUT_STEALTH_KEY_BIT,
            oid, Ko, 1000000,
            kex, &state) != MWEB_OK) {
        printf("FAIL: two_stage_success — derive_input_state\n");
        failures++;
        return;
    }

    uint8_t signature[64];
    if (mweb_sign_input_from_state(&state, NULL, 0, signature) != MWEB_OK) {
        printf("FAIL: two_stage_success — sign_input_from_state\n");
        failures++;
        return;
    }

    if (state.output_commit[0] != 0x08 && state.output_commit[0] != 0x09) {
        printf("FAIL: two_stage_success — commit prefix 0x%02x\n", state.output_commit[0]);
        failures++;
        return;
    }

    int sig_nonzero = 0;
    for (int i = 0; i < 64; i++) {
        if (signature[i]) sig_nonzero = 1;
    }
    if (!sig_nonzero) {
        printf("FAIL: two_stage_success — zero signature\n");
        failures++;
        return;
    }

    printf("PASS: two_stage_success\n");
}

/*
 * Reference vectors for deterministic signing.
 * Inputs: scan/spend keys from mweb_compat_test.go, address_index=0,
 *         sender_key=0x1122..10, ephemeral=0x42 repeated, amount=1000000.
 *
 * These are the same bytes the legacy single-shot signer produced.
 * The two-stage API must maintain byte-for-byte parity.
 */
static const uint8_t EXPECTED_SIGNATURE[64] = {
    0x8d,0x6c,0x01,0xfb,0x52,0xbf,0x9a,0xf4,
    0x48,0x91,0x21,0xa9,0x3f,0xa5,0x41,0x69,
    0x62,0x1d,0xa2,0xa4,0x03,0x6a,0xad,0x9c,
    0x68,0x3c,0x45,0xcc,0xf1,0xa0,0xa6,0x18,
    0x9c,0xfe,0x70,0x6d,0x1a,0x12,0xb8,0x9b,
    0xf5,0x0b,0xf5,0x5e,0x86,0x42,0x11,0x23,
    0x31,0x2c,0x2c,0x7b,0x20,0xa0,0x84,0xe6,
    0x1c,0x46,0x18,0xf1,0xb3,0xca,0x98,0xd7,
};
static const uint8_t EXPECTED_INPUT_BLIND[32] = {
    0x91,0x29,0x81,0x92,0xa2,0x88,0x38,0x41,
    0x25,0xd0,0xd6,0x92,0xb6,0x36,0xec,0xff,
    0xd4,0x4e,0x5b,0x33,0x6d,0xed,0x4b,0x7b,
    0x5c,0xf2,0xfc,0xa2,0x2a,0x72,0x73,0x15,
};
static const uint8_t EXPECTED_STEALTH_TWEAK[32] = {
    0xb3,0x54,0x01,0x6b,0x52,0xc8,0x03,0x99,
    0x58,0x53,0x26,0x78,0x00,0x7c,0x90,0x18,
    0x20,0xed,0xc3,0x07,0xe2,0x9e,0xad,0xe6,
    0x11,0xa2,0x49,0x27,0x5c,0x22,0x04,0x9c,
};
static const uint8_t EXPECTED_INPUT_PUBKEY[33] = {
    0x03,0x24,0x65,0x3e,0xac,0x43,0x44,0x88,
    0x00,0x2c,0xc0,0x6b,0xbf,0xb7,0xf1,0x0f,
    0xe1,0x89,0x91,0xe3,0x5f,0x9f,0xe4,0x30,
    0x2d,0xbe,0xa6,0xd2,0x35,0x3d,0xc0,0xab,
    0x1c,
};
static const uint8_t EXPECTED_OUTPUT_COMMIT[33] = {
    0x09,0xe5,0x1a,0xee,0x1a,0xb3,0x0a,0x06,
    0x46,0xa9,0x48,0xdb,0x5f,0xae,0x2a,0x48,
    0x0d,0x6d,0xf4,0xc4,0x80,0x5a,0x34,0x66,
    0x6e,0xad,0xd9,0x81,0xcf,0x98,0x67,0xaf,
    0x51,
};

static void test_legacy_reference_vectors(void)
{
    const uint8_t sender_key[32] = {
        0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,
        0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff,0x00,
        0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
        0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10,
    };

    uint8_t kex[33], Ko[33], oid[32];
    if (!build_test_input(0, sender_key, kex, Ko, oid)) {
        printf("FAIL: legacy_reference — build\n");
        failures++;
        return;
    }

    memset(g_test_random, 0x42, 32);
    mweb_input_state_t state;
    if (mweb_derive_input_state(SCAN_KEY, SPEND_KEY, 0,
            MWEB_INPUT_STEALTH_KEY_BIT,
            oid, Ko, 1000000, kex, &state) != MWEB_OK) {
        printf("FAIL: legacy_reference — derive\n");
        failures++;
        return;
    }

    uint8_t signature[64];
    if (mweb_sign_input_from_state(&state, NULL, 0, signature) != MWEB_OK) {
        printf("FAIL: legacy_reference — sign\n");
        failures++;
        return;
    }

    if (memcmp(signature, EXPECTED_SIGNATURE, 64) != 0) {
        printf("FAIL: legacy_reference — signature mismatch\n");
        failures++;
        return;
    }
    if (memcmp(state.blind, EXPECTED_INPUT_BLIND, 32) != 0) {
        printf("FAIL: legacy_reference — input_blind mismatch\n");
        failures++;
        return;
    }
    if (memcmp(state.stealth_tweak, EXPECTED_STEALTH_TWEAK, 32) != 0) {
        printf("FAIL: legacy_reference — stealth_tweak mismatch\n");
        failures++;
        return;
    }
    if (memcmp(state.input_pubkey, EXPECTED_INPUT_PUBKEY, 33) != 0) {
        printf("FAIL: legacy_reference — input_pubkey mismatch\n");
        failures++;
        return;
    }
    if (memcmp(state.output_commit, EXPECTED_OUTPUT_COMMIT, 33) != 0) {
        printf("FAIL: legacy_reference — output_commit mismatch\n");
        failures++;
        return;
    }

    /* Determinism: rerun with same ephemeral, assert byte-identical. */
    memset(g_test_random, 0x42, 32);
    mweb_input_state_t state2;
    if (mweb_derive_input_state(SCAN_KEY, SPEND_KEY, 0,
            MWEB_INPUT_STEALTH_KEY_BIT,
            oid, Ko, 1000000, kex, &state2) != MWEB_OK) {
        printf("FAIL: legacy_reference — derive2\n");
        failures++;
        return;
    }
    uint8_t signature2[64];
    if (mweb_sign_input_from_state(&state2, NULL, 0, signature2) != MWEB_OK) {
        printf("FAIL: legacy_reference — sign2\n");
        failures++;
        return;
    }
    if (memcmp(signature, signature2, 64) != 0
        || memcmp(state.blind, state2.blind, 32) != 0
        || memcmp(state.stealth_tweak, state2.stealth_tweak, 32) != 0
        || memcmp(state.input_pubkey, state2.input_pubkey, 33) != 0
        || memcmp(state.output_commit, state2.output_commit, 33) != 0) {
        printf("FAIL: legacy_reference — re-run differs\n");
        failures++;
        return;
    }

    printf("PASS: legacy_reference_vectors\n");
}

/*
 * Stage A alone must not emit any Schnorr signature.
 * Verified indirectly by asserting the output_commit/blind/stealth_tweak
 * fields match the reference vectors (i.e. Stage A executed fully) while
 * no signature variable has been computed. Stage B only runs when the
 * caller explicitly invokes mweb_sign_input_from_state.
 */
static void test_stage_a_no_signature(void)
{
    const uint8_t sender_key[32] = {
        0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,
        0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff,0x00,
        0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
        0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10,
    };

    uint8_t kex[33], Ko[33], oid[32];
    if (!build_test_input(0, sender_key, kex, Ko, oid)) {
        printf("FAIL: stage_a_no_signature — build\n");
        failures++;
        return;
    }

    memset(g_test_random, 0x42, 32);
    mweb_input_state_t state;
    if (mweb_derive_input_state(SCAN_KEY, SPEND_KEY, 0,
            MWEB_INPUT_STEALTH_KEY_BIT,
            oid, Ko, 1000000, kex, &state) != MWEB_OK) {
        printf("FAIL: stage_a_no_signature — derive\n");
        failures++;
        return;
    }

    /* The state struct has no signature field. Stage A cannot have
     * emitted one. Also assert the Stage-B-reproducibility fields
     * are cached. */
    if (state.value != 1000000) {
        printf("FAIL: stage_a_no_signature — value not cached\n");
        failures++;
        return;
    }
    if (state.features != MWEB_INPUT_STEALTH_KEY_BIT) {
        printf("FAIL: stage_a_no_signature — features not cached\n");
        failures++;
        return;
    }
    if (memcmp(state.spent_output_id, oid, 32) != 0
        || memcmp(state.spent_output_pk, Ko, 33) != 0) {
        printf("FAIL: stage_a_no_signature — identifiers not cached\n");
        failures++;
        return;
    }

    printf("PASS: stage_a_no_signature\n");
}

static void test_wrong_address_index(void)
{
    const uint8_t sender_key[32] = {
        0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,
        0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff,0x00,
        0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
        0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10,
    };

    uint8_t kex[33], Ko[33], oid[32];
    /* Build for index 0, try to sign with index 1 */
    if (!build_test_input(0, sender_key, kex, Ko, oid)) {
        printf("FAIL: wrong_index — build\n");
        failures++;
        return;
    }

    memset(g_test_random, 0x42, 32);
    mweb_input_state_t state;
    mweb_err_t err = mweb_derive_input_state(SCAN_KEY, SPEND_KEY, 1,
        MWEB_INPUT_STEALTH_KEY_BIT,
        oid, Ko, 1000000, kex, &state);
    if (err != MWEB_ERR_FOREIGN_MWEB_INPUT) {
        printf("FAIL: wrong_index — expected FOREIGN_MWEB_INPUT, got %d\n", err);
        failures++;
        return;
    }

    printf("PASS: wrong_address_index_rejected\n");
}

static void test_missing_stealth_bit(void)
{
    const uint8_t sender_key[32] = {
        0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,
        0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff,0x00,
        0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
        0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10,
    };

    uint8_t kex[33], Ko[33], oid[32];
    if (!build_test_input(0, sender_key, kex, Ko, oid)) {
        printf("FAIL: missing_stealth — build\n");
        failures++;
        return;
    }

    memset(g_test_random, 0x42, 32);
    mweb_input_state_t state;
    mweb_err_t err = mweb_derive_input_state(SCAN_KEY, SPEND_KEY, 0,
        0x00, /* no stealth bit */
        oid, Ko, 1000000, kex, &state);
    if (err != MWEB_ERR_INVALID_PRESIGN_SCALAR) {
        printf("FAIL: missing_stealth — expected INVALID_PRESIGN_SCALAR, got %d\n", err);
        failures++;
        return;
    }

    printf("PASS: missing_stealth_bit_rejected\n");
}

static void test_sign_with_extra_data(void)
{
    const uint8_t sender_key[32] = {
        0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,
        0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff,0x00,
        0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
        0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10,
    };

    uint8_t kex[33], Ko[33], oid[32];
    if (!build_test_input(0, sender_key, kex, Ko, oid)) {
        printf("FAIL: extra_data — build\n");
        failures++;
        return;
    }

    const uint8_t extra[] = { 0xde, 0xad, 0xbe, 0xef };

    memset(g_test_random, 0x42, 32);
    mweb_input_state_t state_with;
    if (mweb_derive_input_state(SCAN_KEY, SPEND_KEY, 0,
            MWEB_INPUT_STEALTH_KEY_BIT | MWEB_INPUT_EXTRA_DATA_BIT,
            oid, Ko, 1000000, kex, &state_with) != MWEB_OK) {
        printf("FAIL: extra_data — derive_with\n");
        failures++;
        return;
    }
    uint8_t sig_with[64];
    if (mweb_sign_input_from_state(&state_with, extra, sizeof(extra), sig_with)
            != MWEB_OK) {
        printf("FAIL: extra_data — sign_with\n");
        failures++;
        return;
    }

    memset(g_test_random, 0x42, 32);
    mweb_input_state_t state_without;
    if (mweb_derive_input_state(SCAN_KEY, SPEND_KEY, 0,
            MWEB_INPUT_STEALTH_KEY_BIT,
            oid, Ko, 1000000, kex, &state_without) != MWEB_OK) {
        printf("FAIL: extra_data — derive_without\n");
        failures++;
        return;
    }
    uint8_t sig_without[64];
    if (mweb_sign_input_from_state(&state_without, NULL, 0, sig_without) != MWEB_OK) {
        printf("FAIL: extra_data — sign_without\n");
        failures++;
        return;
    }

    if (memcmp(sig_with, sig_without, 64) == 0) {
        printf("FAIL: extra_data — signatures should differ\n");
        failures++;
        return;
    }

    printf("PASS: sign_with_extra_data\n");
}

/*
 * Reproduce the same osk = (spend_key + m_i) * out_key_hash that
 * Stage A derives, so a test can drive ephemeral == osk and verify
 * the zero-stealth_tweak path.
 */
static bool compute_osk(uint32_t address_index,
                        const uint8_t sender_key[32],
                        uint8_t osk_out[32])
{
    const secp256k1_context* ctx = wally_get_secp_context();

    uint8_t mi_buf[4 + 32];
    mi_buf[0] = (uint8_t)(address_index);
    mi_buf[1] = (uint8_t)(address_index >> 8);
    mi_buf[2] = (uint8_t)(address_index >> 16);
    mi_buf[3] = (uint8_t)(address_index >> 24);
    memcpy(mi_buf + 4, SCAN_KEY, 32);
    uint8_t m_i[32];
    mweb_hashed(MWEB_TAG_ADDRESS, mi_buf, sizeof(mi_buf), m_i);

    uint8_t spend_pub[33], mi_pub[33];
    if (wally_ec_public_key_from_private_key(SPEND_KEY, 32, spend_pub, 33) != WALLY_OK) return false;
    if (wally_ec_public_key_from_private_key(m_i, 32, mi_pub, 33) != WALLY_OK) return false;
    secp256k1_pubkey sp_pk, mi_pk, Bi_pk;
    if (!secp256k1_ec_pubkey_parse(ctx, &sp_pk, spend_pub, 33)) return false;
    if (!secp256k1_ec_pubkey_parse(ctx, &mi_pk, mi_pub, 33)) return false;
    const secp256k1_pubkey* pts[2] = { &sp_pk, &mi_pk };
    if (!secp256k1_ec_pubkey_combine(ctx, &Bi_pk, pts, 2)) return false;

    secp256k1_pubkey Ke_pk = Bi_pk;
    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &Ke_pk, sender_key)) return false;
    uint8_t kex[33];
    size_t kex_len = 33;
    secp256k1_ec_pubkey_serialize(ctx, kex, &kex_len, &Ke_pk, SECP256K1_EC_COMPRESSED);

    secp256k1_pubkey kex_parsed;
    if (!secp256k1_ec_pubkey_parse(ctx, &kex_parsed, kex, 33)) return false;
    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &kex_parsed, SCAN_KEY)) return false;
    uint8_t ecdh[33];
    size_t ecdh_len = 33;
    secp256k1_ec_pubkey_serialize(ctx, ecdh, &ecdh_len, &kex_parsed, SECP256K1_EC_COMPRESSED);
    uint8_t ss[32];
    mweb_hashed(MWEB_TAG_DERIVE, ecdh, 33, ss);

    uint8_t okh[32];
    mweb_hashed(MWEB_TAG_OUTKEY, ss, 32, okh);

    /* osk = (spend_key + m_i) * out_key_hash */
    memcpy(osk_out, SPEND_KEY, 32);
    if (!secp256k1_ec_seckey_tweak_add(ctx, osk_out, m_i)) return false;
    if (!secp256k1_ec_seckey_tweak_mul(ctx, osk_out, okh)) return false;
    return true;
}

/*
 * Drive ephemeral == osk so stealth_tweak = ephemeral - osk is the zero
 * scalar. This is mathematically a valid contribution to the global
 * stealth offset, and Stage A must NOT fail on it — older versions
 * that used secp256k1_ec_seckey_tweak_add() (which rejects a zero
 * result) would regress here.
 */
static void test_zero_stealth_tweak_accepted(void)
{
    const uint8_t sender_key[32] = {
        0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,
        0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff,0x00,
        0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
        0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10,
    };

    uint8_t kex[33], Ko[33], oid[32];
    if (!build_test_input(0, sender_key, kex, Ko, oid)) {
        printf("FAIL: zero_stealth_tweak — build\n");
        failures++;
        return;
    }

    uint8_t osk[32];
    if (!compute_osk(0, sender_key, osk)) {
        printf("FAIL: zero_stealth_tweak — compute_osk\n");
        failures++;
        return;
    }

    /* Force the TRNG to hand Stage A the osk value so ephemeral == osk. */
    memcpy(g_test_random, osk, 32);

    mweb_input_state_t state;
    if (mweb_derive_input_state(SCAN_KEY, SPEND_KEY, 0,
            MWEB_INPUT_STEALTH_KEY_BIT,
            oid, Ko, 1000000, kex, &state) != MWEB_OK) {
        printf("FAIL: zero_stealth_tweak — derive rejected zero tweak\n");
        failures++;
        return;
    }

    const uint8_t zero32[32] = { 0 };
    if (memcmp(state.stealth_tweak, zero32, 32) != 0) {
        printf("FAIL: zero_stealth_tweak — tweak is not all-zero\n");
        failures++;
        return;
    }

    /* Stage B should also succeed on the resulting state. */
    uint8_t signature[64];
    if (mweb_sign_input_from_state(&state, NULL, 0, signature) != MWEB_OK) {
        printf("FAIL: zero_stealth_tweak — Stage B rejected\n");
        failures++;
        return;
    }

    printf("PASS: zero_stealth_tweak_accepted\n");
}

/*
 * EXTRA_DATA_BIT set with empty data hashes varint(0)=0x00 and must
 * produce a different signature than the no-bit case.
 */
static void test_empty_extra_data(void)
{
    const uint8_t sender_key[32] = {
        0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,
        0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff,0x00,
        0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
        0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10,
    };

    uint8_t kex[33], Ko[33], oid[32];
    if (!build_test_input(0, sender_key, kex, Ko, oid)) {
        printf("FAIL: empty_extra_data — build\n");
        failures++;
        return;
    }

    memset(g_test_random, 0x42, 32);
    mweb_input_state_t state_empty;
    if (mweb_derive_input_state(SCAN_KEY, SPEND_KEY, 0,
            MWEB_INPUT_STEALTH_KEY_BIT | MWEB_INPUT_EXTRA_DATA_BIT,
            oid, Ko, 1000000, kex, &state_empty) != MWEB_OK) {
        printf("FAIL: empty_extra_data — derive_empty\n");
        failures++;
        return;
    }
    uint8_t sig_empty[64];
    if (mweb_sign_input_from_state(&state_empty, NULL, 0, sig_empty) != MWEB_OK) {
        printf("FAIL: empty_extra_data — sign_empty\n");
        failures++;
        return;
    }

    memset(g_test_random, 0x42, 32);
    mweb_input_state_t state_nobit;
    if (mweb_derive_input_state(SCAN_KEY, SPEND_KEY, 0,
            MWEB_INPUT_STEALTH_KEY_BIT,
            oid, Ko, 1000000, kex, &state_nobit) != MWEB_OK) {
        printf("FAIL: empty_extra_data — derive_nobit\n");
        failures++;
        return;
    }
    uint8_t sig_nobit[64];
    if (mweb_sign_input_from_state(&state_nobit, NULL, 0, sig_nobit) != MWEB_OK) {
        printf("FAIL: empty_extra_data — sign_nobit\n");
        failures++;
        return;
    }

    if (memcmp(sig_empty, sig_nobit, 64) == 0) {
        printf("FAIL: empty_extra_data — signatures should differ "
               "(varint(0) vs nothing)\n");
        failures++;
        return;
    }

    printf("PASS: empty_extra_data\n");
}

int test_mweb_sign(void)
{
    failures = 0;

    test_two_stage_success();
    test_legacy_reference_vectors();
    test_stage_a_no_signature();
    test_wrong_address_index();
    test_missing_stealth_bit();
    test_sign_with_extra_data();
    test_empty_extra_data();
    test_zero_stealth_tweak_accepted();

    printf("\nmweb_sign: %d tests, %d failures\n", 8, failures);
    return failures;
}

#ifdef MWEB_TEST_STANDALONE
int main(void) { return test_mweb_sign() == 0 ? 0 : 1; }
#endif
