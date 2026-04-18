/*
 * MWEB on-device self-check tests.
 *
 * Called from selfcheck.c as part of debug_selfcheck().
 * Uses the selfcheck FAIL() convention: returns false on first failure.
 *
 * Tests pure crypto primitives with fixed vectors plus property-based
 * signing tests (the hardware TRNG can't be mocked on device, so
 * byte-exact signature vectors are only checked in native tests).
 */
#ifndef AMALGAMATED_BUILD

#include "mweb_hash.h"
#include "mweb_schnorr.h"
#include "mweb_blind.h"
#include "mweb_sign.h"
#include "mweb_keychain.h"
#include "mweb_kernel.h"
#include "mweb_output.h"
#include "mweb_scalar.h"
#include "mweb_atomic_sign.h"
#include "mweb_selfcheck.h"

#include "../jade_assert.h"
#include "../utils/network.h"

#include <stdint.h>
#include <string.h>
#include <secp256k1.h>
#include <wally_core.h>
#include <wally_crypto.h>
#include <wally_map.h>
#include <wally_psbt.h>

#include <freertos/FreeRTOS.h>
#include <freertos/task.h>

/* Use the FAIL() macro from selfcheck.c (included via amalgamated build
 * or defined in the including file). */
#ifndef FAIL
#define FAIL()                                                                 \
    do {                                                                       \
        return false;                                                          \
    } while (false)
#endif

/* ── Test scan / spend keys ──────────────────────────────────────────── */

static const uint8_t MWEB_TEST_SCAN_KEY[32] = {
    0xb3,0xc9,0x1b,0x72,0x91,0xc2,0xe1,0xe0,
    0x6d,0x4a,0x93,0xf3,0xdc,0x32,0x40,0x4a,
    0xef,0x99,0x27,0xdb,0x8e,0x79,0x4c,0x01,
    0xa7,0xb4,0xde,0x18,0xa3,0x97,0xc3,0x38,
};

static const uint8_t MWEB_TEST_SPEND_KEY[32] = {
    0x2f,0xe1,0x98,0x2b,0x98,0xc0,0xb6,0x8c,
    0x08,0x39,0x42,0x1c,0x8a,0x0a,0x0a,0x67,
    0xef,0x31,0x98,0xc7,0x46,0xab,0x8e,0x6d,
    0x09,0x10,0x1e,0xb7,0x39,0x6a,0x44,0xd8,
};

/* ── BLAKE3 tagged hash vectors ──────────────────────────────────────── */

static bool test_mweb_hashes(void)
{
    uint8_t out[32];

    /* BLAKE3('A') = hashed('A', empty) */
    static const uint8_t HASH_A_EMPTY[32] = {
        0x32,0x68,0x4b,0xfa,0x28,0xc0,0xc8,0x4d,
        0x6f,0x21,0x05,0x11,0xaa,0xce,0x0e,0xfc,
        0x51,0x71,0xc7,0x88,0x91,0x48,0xba,0x89,
        0x20,0x8d,0x5a,0xa2,0x97,0x05,0xfa,0x98,
    };
    mweb_hashed(MWEB_TAG_ADDRESS, NULL, 0, out);
    if (memcmp(out, HASH_A_EMPTY, 32) != 0) { FAIL(); }

    /* BLAKE3('B') */
    static const uint8_t HASH_B_EMPTY[32] = {
        0x9f,0x95,0x24,0xca,0x18,0xc0,0xcc,0x03,
        0xae,0xf1,0xa0,0xb8,0x4f,0xae,0xd9,0x37,
        0x5e,0x5d,0x19,0x57,0x5e,0x93,0x28,0xe6,
        0x5f,0xea,0x72,0x99,0x1f,0x0f,0x58,0xcf,
    };
    mweb_hashed(MWEB_TAG_BLIND, NULL, 0, out);
    if (memcmp(out, HASH_B_EMPTY, 32) != 0) { FAIL(); }

    /* m_0 = BLAKE3('A' || 0x00000000 || scan_key) */
    static const uint8_t HASH_A_IDX0[32] = {
        0x10,0x94,0xe7,0xf0,0xc0,0x5a,0x46,0x7a,
        0xca,0x48,0xfa,0x5c,0xfb,0x84,0x42,0x2b,
        0xb7,0x75,0x02,0x0b,0xd7,0x31,0x18,0x06,
        0xdb,0x47,0x24,0xba,0xf0,0x5d,0x06,0x40,
    };
    uint8_t mi_buf[36] = {0};
    memcpy(mi_buf + 4, MWEB_TEST_SCAN_KEY, 32);
    mweb_hashed(MWEB_TAG_ADDRESS, mi_buf, 36, out);
    if (memcmp(out, HASH_A_IDX0, 32) != 0) { FAIL(); }

    return true;
}

/* ── Schnorr signature vectors ───────────────────────────────────────── */

static bool test_mweb_schnorr_vectors(void)
{
    uint8_t sig[64];
    static const uint8_t MSG_ZERO[32] = {0};
    static const uint8_t MSG_NONZERO[32] = {
        0x24,0x3f,0x6a,0x88,0x85,0xa3,0x08,0xd3,
        0x13,0x19,0x8a,0x2e,0x03,0x70,0x73,0x44,
        0xa4,0x09,0x38,0x22,0x29,0x9f,0x31,0xd0,
        0x08,0x2e,0xfa,0x98,0xec,0x4e,0x6c,0x89,
    };

    /* scan_key + zero_msg */
    static const uint8_t SIG_SCAN_ZERO[64] = {
        0x3b,0x7c,0x8c,0xfe,0x4a,0x8e,0xb4,0x26,
        0x2a,0x20,0xfe,0x7b,0x3b,0xe2,0x5a,0x2a,
        0x66,0x2e,0xd5,0xed,0x3e,0x6f,0xe7,0x96,
        0xee,0x4c,0x72,0x46,0xff,0x77,0x65,0xf4,
        0x46,0xcd,0xae,0x64,0x07,0xbd,0x9f,0x17,
        0x7a,0xc5,0xcb,0x8d,0xb5,0x3e,0x88,0x02,
        0x09,0x96,0x46,0x0b,0xd3,0x8e,0x1b,0x71,
        0x60,0x33,0xfe,0x52,0x03,0x65,0x57,0xb9,
    };
    if (!mweb_schnorr_sign(MWEB_TEST_SCAN_KEY, MSG_ZERO, 32, sig)) { FAIL(); }
    if (memcmp(sig, SIG_SCAN_ZERO, 64) != 0) { FAIL(); }

    /* scan_key + nonzero_msg */
    static const uint8_t SIG_SCAN_NONZERO[64] = {
        0xde,0xca,0x7d,0x93,0xdc,0x3c,0x52,0x31,
        0x79,0xef,0xc0,0xa0,0xda,0x96,0x4b,0xf7,
        0x4d,0x73,0x59,0xc2,0x1d,0x5e,0x40,0xb8,
        0x62,0x63,0x0b,0x8b,0xc3,0xa0,0xda,0x05,
        0x76,0xf5,0xa4,0x26,0xe4,0xf0,0xb3,0xc8,
        0xe9,0xbf,0x84,0xf9,0x4c,0xa4,0xa9,0x2c,
        0xfb,0xd6,0x6a,0x69,0x14,0x77,0x36,0x7c,
        0xa4,0x78,0xf4,0x59,0x1b,0x01,0x73,0xf8,
    };
    if (!mweb_schnorr_sign(MWEB_TEST_SCAN_KEY, MSG_NONZERO, 32, sig)) { FAIL(); }
    if (memcmp(sig, SIG_SCAN_NONZERO, 64) != 0) { FAIL(); }

    /* spend_key + zero_msg */
    static const uint8_t SIG_SPEND_ZERO[64] = {
        0xbc,0xd3,0x3a,0x38,0xb6,0x76,0x5a,0xa9,
        0x88,0xc4,0x12,0x21,0xdc,0xe0,0x19,0x51,
        0xf8,0xdf,0xc4,0x13,0x91,0x4f,0x03,0xfa,
        0x18,0x12,0xaf,0x1b,0xa2,0x44,0x1f,0xe9,
        0x5a,0x04,0xdb,0x6e,0x61,0x8c,0x0b,0x03,
        0x8b,0xcb,0xa1,0xea,0x72,0x58,0x96,0x82,
        0x24,0xd5,0x35,0xfd,0x10,0x27,0x80,0x8a,
        0x05,0xf9,0x82,0x11,0x9c,0x6d,0x29,0xc9,
    };
    if (!mweb_schnorr_sign(MWEB_TEST_SPEND_KEY, MSG_ZERO, 32, sig)) { FAIL(); }
    if (memcmp(sig, SIG_SPEND_ZERO, 64) != 0) { FAIL(); }

    /* spend_key + nonzero_msg */
    static const uint8_t SIG_SPEND_NONZERO[64] = {
        0x2f,0x19,0x09,0xa4,0xb1,0x26,0xfb,0xae,
        0x04,0x3f,0x74,0x03,0x77,0x95,0xc4,0xe1,
        0x00,0xd8,0x95,0x3c,0x47,0xb6,0x8b,0xdf,
        0xe9,0x84,0x56,0xed,0x64,0x3d,0x19,0x83,
        0x86,0xcd,0x32,0xae,0x52,0x04,0xc7,0x89,
        0xa2,0x70,0xb9,0x74,0x64,0xc3,0xb3,0x6c,
        0x95,0x6e,0xd8,0x86,0x7c,0xd1,0xa9,0xe0,
        0xe2,0x99,0x34,0x0c,0x2d,0x3f,0xb3,0x57,
    };
    if (!mweb_schnorr_sign(MWEB_TEST_SPEND_KEY, MSG_NONZERO, 32, sig)) { FAIL(); }
    if (memcmp(sig, SIG_SPEND_NONZERO, 64) != 0) { FAIL(); }

    /* Determinism: same inputs → same output */
    uint8_t sig2[64];
    if (!mweb_schnorr_sign(MWEB_TEST_SCAN_KEY, MSG_ZERO, 32, sig2)) { FAIL(); }
    if (!mweb_schnorr_sign(MWEB_TEST_SCAN_KEY, MSG_ZERO, 32, sig)) { FAIL(); }
    if (memcmp(sig, sig2, 64) != 0) { FAIL(); }

    return true;
}

/* ── Pedersen commitment + BlindSwitch vectors ───────────────────────── */

static bool test_mweb_blind_vectors(void)
{
    uint8_t commit[33], blind_out[32];

    /* Pedersen(scan_key, 0) */
    static const uint8_t COMMIT_V0[33] = {
        0x08,0xcd,0x7e,0x29,0xe3,0x1b,0xf0,0xc0,
        0x72,0x81,0xd3,0xc5,0x91,0xfe,0x3d,0xbe,
        0x43,0x75,0xb9,0x11,0xcc,0x60,0x38,0xec,
        0x5d,0x1b,0xe8,0x20,0x99,0xd6,0xc4,0x82,
        0xf5,
    };
    if (!mweb_pedersen_commit(MWEB_TEST_SCAN_KEY, 0, commit)) { FAIL(); }
    if (memcmp(commit, COMMIT_V0, 33) != 0) { FAIL(); }

    /* Pedersen(scan_key, 1000000) */
    static const uint8_t COMMIT_V1M[33] = {
        0x08,0x9c,0x29,0x7c,0x8a,0x89,0xcf,0x4b,
        0xa8,0xd9,0x1f,0xb5,0x7d,0xb5,0xea,0x70,
        0xa5,0x25,0xd7,0x9f,0x87,0x37,0x70,0xa3,
        0xae,0x63,0x6b,0x39,0xa7,0x8f,0x99,0x6d,
        0x58,
    };
    if (!mweb_pedersen_commit(MWEB_TEST_SCAN_KEY, 1000000, commit)) { FAIL(); }
    if (memcmp(commit, COMMIT_V1M, 33) != 0) { FAIL(); }

    /* Pedersen(0x01..01, 42) — verifies 0x09 prefix path */
    static const uint8_t BLIND_ONES[32] = {
        0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
        0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
        0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
        0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
    };
    if (!mweb_pedersen_commit(BLIND_ONES, 42, commit)) { FAIL(); }
    if (commit[0] != 0x09) { FAIL(); } /* prefix diversity check */

    /* BlindSwitch(scan_key, 1000000) */
    static const uint8_t BSWITCH_V1M[32] = {
        0x82,0xd1,0x97,0xc3,0x6a,0xcd,0x61,0x14,
        0xbc,0x9f,0x93,0x27,0x43,0x54,0x14,0x55,
        0xb2,0xb8,0xce,0xda,0xad,0xc3,0xcd,0x5b,
        0x0c,0x15,0xf0,0xf6,0x30,0xdd,0x04,0xbf,
    };
    if (!mweb_blind_switch(MWEB_TEST_SCAN_KEY, 1000000, blind_out)) { FAIL(); }
    if (memcmp(blind_out, BSWITCH_V1M, 32) != 0) { FAIL(); }

    /* SwitchCommit = Pedersen(BlindSwitch(blind, value), value) */
    static const uint8_t SWITCH_COMMIT_V1M[33] = {
        0x08,0x12,0xcc,0x19,0x43,0xb5,0xb7,0x4a,
        0x15,0x6a,0x5c,0x29,0x67,0x28,0x6f,0x3c,
        0x4f,0x46,0xa4,0x84,0x9e,0x8d,0x61,0x5a,
        0xe3,0xb1,0xe9,0xd0,0x42,0xfb,0xc2,0xc8,
        0xb4,
    };
    if (!mweb_pedersen_commit(BSWITCH_V1M, 1000000, commit)) { FAIL(); }
    if (memcmp(commit, SWITCH_COMMIT_V1M, 33) != 0) { FAIL(); }

    /* Zero blind must be rejected */
    static const uint8_t ZERO[32] = {0};
    uint8_t dummy[32];
    if (mweb_blind_switch(ZERO, 1, dummy)) { FAIL(); } /* should return false */

    return true;
}

/* ── Spend pubkey derivation ────────────────────────────────────────── */

static bool test_mweb_spend_pubkey(void)
{
    /* Expected spend pubkey from mweb_import_test.go */
    static const uint8_t EXPECTED_SPEND_PUBKEY[33] = {
        0x03,0xe3,0x90,0x8a,0xf7,0x00,0x85,0xb4,
        0x58,0x02,0x0e,0x64,0xaa,0xa5,0xc9,0xa4,
        0xb8,0xff,0x38,0x2d,0x42,0xaf,0x08,0x75,
        0xc8,0x14,0x5d,0xb6,0xa3,0x0d,0xb9,0xca,
        0xd2,
    };

    uint8_t pubkey[33];
    if (!mweb_derive_spend_pubkey(MWEB_TEST_SPEND_KEY, pubkey)) { FAIL(); }
    if (memcmp(pubkey, EXPECTED_SPEND_PUBKEY, 33) != 0) { FAIL(); }

    /* Zero key must be rejected */
    static const uint8_t ZERO[32] = {0};
    if (mweb_derive_spend_pubkey(ZERO, pubkey)) { FAIL(); }

    return true;
}

/* ── Stealth address derivation ──────────────────────────────────────── */

static bool test_mweb_addresses(void)
{
    char* addr = NULL;

    /* index=0 expected address */
    if (!mweb_derive_address(MWEB_TEST_SCAN_KEY, MWEB_TEST_SPEND_KEY,
                             0, NETWORK_LITECOIN, &addr)) { FAIL(); }
    if (!addr) { FAIL(); }
    if (strcmp(addr, "ltcmweb1qqwkdldufg0enxpphwc8rwucc9ru6h43x5uklzm78ektgmufmw3j6k"
                     "qu76qqw66w204vn7zddfgmnyq9ujugjvx4t2mhuqkuj5h4tgd8cvs6gg076") != 0) {
        wally_free_string(addr);
        FAIL();
    }
    wally_free_string(addr);

    /* index=1 */
    if (!mweb_derive_address(MWEB_TEST_SCAN_KEY, MWEB_TEST_SPEND_KEY,
                             1, NETWORK_LITECOIN, &addr)) { FAIL(); }
    if (!addr) { FAIL(); }
    if (strcmp(addr, "ltcmweb1qqfgk4yhnh3szt08zjy0xw9qdmmf54s0e8r0szjxfk3uw2aa4q48yy"
                     "q6a44z9re8jhl2khvpxdgfdj2h5wjw58fzjgu099fphh8tmhv2hcygfr2nl") != 0) {
        wally_free_string(addr);
        FAIL();
    }
    wally_free_string(addr);

    /* HRP mapping */
    if (strcmp(mweb_network_hrp(NETWORK_LITECOIN), "ltcmweb") != 0) { FAIL(); }
    if (strcmp(mweb_network_hrp(NETWORK_LITECOIN_TESTNET), "tmweb") != 0) { FAIL(); }
    if (mweb_network_hrp(NETWORK_BITCOIN) != NULL) { FAIL(); }

    return true;
}

/* ── Sign property tests (uses real TRNG — no byte-for-byte vectors) ─ */

static bool test_mweb_sign_properties(void)
{
    const secp256k1_context* ctx = wally_get_secp_context();
    if (!ctx) { FAIL(); }

    /* Build a synthetic MWEB output for address_index=0 */
    /* m_i = Hashed('A', index || scan_key) */
    uint8_t mi_buf[36] = {0};
    memcpy(mi_buf + 4, MWEB_TEST_SCAN_KEY, 32);
    uint8_t m_i[32];
    mweb_hashed(MWEB_TAG_ADDRESS, mi_buf, 36, m_i);

    /* B_i = spend_pub + m_i*G */
    uint8_t spend_pub[EC_PUBLIC_KEY_LEN], mi_pub[EC_PUBLIC_KEY_LEN];
    if (wally_ec_public_key_from_private_key(MWEB_TEST_SPEND_KEY, 32,
            spend_pub, sizeof(spend_pub)) != WALLY_OK) { FAIL(); }
    if (wally_ec_public_key_from_private_key(m_i, 32,
            mi_pub, sizeof(mi_pub)) != WALLY_OK) { FAIL(); }

    secp256k1_pubkey sp_pk, mi_pk, Bi_pk;
    if (!secp256k1_ec_pubkey_parse(ctx, &sp_pk, spend_pub, 33)) { FAIL(); }
    if (!secp256k1_ec_pubkey_parse(ctx, &mi_pk, mi_pub, 33)) { FAIL(); }
    const secp256k1_pubkey* pts[2] = { &sp_pk, &mi_pk };
    if (!secp256k1_ec_pubkey_combine(ctx, &Bi_pk, pts, 2)) { FAIL(); }

    /* Use a fixed sender key to derive key_exchange_pk and shared_secret */
    static const uint8_t SENDER_KEY[32] = {
        0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,
        0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff,0x00,
        0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
        0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10,
    };

    /* key_exchange_pk = sender_key * B_i */
    secp256k1_pubkey Ke_pk = Bi_pk;
    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &Ke_pk, SENDER_KEY)) { FAIL(); }
    uint8_t kex[33];
    size_t ke_len = 33;
    secp256k1_ec_pubkey_serialize(ctx, kex, &ke_len, &Ke_pk, SECP256K1_EC_COMPRESSED);

    /* shared_secret = Hashed('D', kex * scan_key) */
    secp256k1_pubkey kex_parsed;
    if (!secp256k1_ec_pubkey_parse(ctx, &kex_parsed, kex, 33)) { FAIL(); }
    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &kex_parsed, MWEB_TEST_SCAN_KEY)) { FAIL(); }
    uint8_t ecdh_bytes[33];
    size_t ecdh_len = 33;
    secp256k1_ec_pubkey_serialize(ctx, ecdh_bytes, &ecdh_len, &kex_parsed, SECP256K1_EC_COMPRESSED);
    uint8_t ss[32];
    mweb_hashed(MWEB_TAG_DERIVE, ecdh_bytes, 33, ss);

    /* Ko = out_key_hash * B_i */
    uint8_t okh[32];
    mweb_hashed(MWEB_TAG_OUTKEY, ss, 32, okh);
    secp256k1_pubkey Ko_pk = Bi_pk;
    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &Ko_pk, okh)) { FAIL(); }
    uint8_t Ko[33];
    size_t ko_len = 33;
    secp256k1_ec_pubkey_serialize(ctx, Ko, &ko_len, &Ko_pk, SECP256K1_EC_COMPRESSED);

    /* spent_output_id = Hashed('T', Ko) */
    uint8_t oid[32];
    mweb_hashed(MWEB_TAG_TAG, Ko, 33, oid);

    /* Test 1: Stage A + Stage B with correct params succeed */
    mweb_input_state_t state;
    if (mweb_derive_input_state(MWEB_TEST_SCAN_KEY, MWEB_TEST_SPEND_KEY, 0,
            MWEB_INPUT_STEALTH_KEY_BIT,
            oid, Ko, 1000000, kex, &state) != MWEB_OK) { FAIL(); }

    uint8_t signature[64];
    if (mweb_sign_input_from_state(&state, NULL, 0, signature) != MWEB_OK) { FAIL(); }

    /* Commitment must have 0x08 or 0x09 prefix */
    if (state.output_commit[0] != 0x08 && state.output_commit[0] != 0x09) { FAIL(); }

    /* Signature must be non-zero */
    uint8_t zero_sig[64] = {0};
    if (memcmp(signature, zero_sig, 64) == 0) { FAIL(); }

    /* input_pubkey must be a valid 33-byte compressed pubkey */
    if (state.input_pubkey[0] != 0x02 && state.input_pubkey[0] != 0x03) { FAIL(); }

    /* Test 2: Wrong address_index must be rejected at Stage A */
    mweb_input_state_t state_wrong;
    if (mweb_derive_input_state(MWEB_TEST_SCAN_KEY, MWEB_TEST_SPEND_KEY, 1,
            MWEB_INPUT_STEALTH_KEY_BIT,
            oid, Ko, 1000000, kex, &state_wrong) != MWEB_ERR_FOREIGN_MWEB_INPUT) {
        FAIL();
    }

    /* Test 3: Missing STEALTH_KEY_BIT must be rejected at Stage A */
    mweb_input_state_t state_nobit;
    if (mweb_derive_input_state(MWEB_TEST_SCAN_KEY, MWEB_TEST_SPEND_KEY, 0,
            0x00, /* no stealth bit */
            oid, Ko, 1000000, kex, &state_nobit) != MWEB_ERR_INVALID_PRESIGN_SCALAR) {
        FAIL();
    }

    (void)ss; /* retained for local scoping symmetry; bypass path is gone */

    return true;
}

/* ── Watch-only address consistency ──────────────────────────────────── */
/*
 * Proves that a watch-only wallet with (scan_secret, spend_pubkey) generates
 * the same stealth addresses as full-access derivation with (scan_secret,
 * spend_secret).  This is the core invariant behind get_mweb_watch_keys.
 */
static bool test_mweb_watch_only_consistency(void)
{
    const secp256k1_context* ctx = wally_get_secp_context();
    if (!ctx) { FAIL(); }

    /* Get spend pubkey via the helper (no spend secret after this) */
    uint8_t spend_pubkey[EC_PUBLIC_KEY_LEN];
    if (!mweb_derive_spend_pubkey(MWEB_TEST_SPEND_KEY, spend_pubkey)) { FAIL(); }

    /* Full-access address at index 0 */
    char* addr_full = NULL;
    if (!mweb_derive_address(MWEB_TEST_SCAN_KEY, MWEB_TEST_SPEND_KEY,
                             0, NETWORK_LITECOIN, &addr_full)) { FAIL(); }

    /* Watch-only derivation using spend_pubkey only (no spend_secret) */
    /* m_i = BLAKE3('A', index_le32 || scan_key) */
    uint8_t mi_buf[36] = {0}; /* index=0 little-endian */
    memcpy(mi_buf + 4, MWEB_TEST_SCAN_KEY, 32);
    uint8_t m_i[32];
    mweb_hashed(MWEB_TAG_ADDRESS, mi_buf, sizeof(mi_buf), m_i);

    /* m_i_pub = m_i * G */
    uint8_t mi_pub[EC_PUBLIC_KEY_LEN];
    if (wally_ec_public_key_from_private_key(m_i, 32,
            mi_pub, sizeof(mi_pub)) != WALLY_OK) {
        wally_free_string(addr_full);
        FAIL();
    }

    /* B_i = spend_pubkey + m_i*G */
    secp256k1_pubkey sp_pk, mi_pk, Bi_pk;
    if (!secp256k1_ec_pubkey_parse(ctx, &sp_pk, spend_pubkey, 33)
        || !secp256k1_ec_pubkey_parse(ctx, &mi_pk, mi_pub, 33)) {
        wally_free_string(addr_full);
        FAIL();
    }
    const secp256k1_pubkey* pts[2] = { &sp_pk, &mi_pk };
    if (!secp256k1_ec_pubkey_combine(ctx, &Bi_pk, pts, 2)) {
        wally_free_string(addr_full);
        FAIL();
    }

    uint8_t Bi[EC_PUBLIC_KEY_LEN];
    size_t bi_len = sizeof(Bi);
    secp256k1_ec_pubkey_serialize(ctx, Bi, &bi_len, &Bi_pk, SECP256K1_EC_COMPRESSED);

    /* A_i = scan_key * B_i */
    secp256k1_pubkey Ai_pk = Bi_pk;
    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &Ai_pk, MWEB_TEST_SCAN_KEY)) {
        wally_free_string(addr_full);
        FAIL();
    }

    uint8_t Ai[EC_PUBLIC_KEY_LEN];
    size_t ai_len = sizeof(Ai);
    secp256k1_ec_pubkey_serialize(ctx, Ai, &ai_len, &Ai_pk, SECP256K1_EC_COMPRESSED);

    /* Encode as bech32 and compare */
    uint8_t payload[66];
    memcpy(payload, Ai, 33);
    memcpy(payload + 33, Bi, 33);

    char watch_addr[128];
    if (!mweb_bech32_encode_payload(payload, 66, "ltcmweb", watch_addr, sizeof(watch_addr))) {
        wally_free_string(addr_full);
        FAIL();
    }

    if (strcmp(addr_full, watch_addr) != 0) {
        wally_free_string(addr_full);
        FAIL();
    }

    wally_free_string(addr_full);
    return true;
}

/* ── Kernel signing — SIMPLE, full ──────────────────────────────────── */

/*
 * Non-stealth-excess kernel, one input and one output, balanced with
 * fee=10000. `mweb_sign_kernel_with_ek` must emit the expected
 * (E_k, signature, O_k_final, O_s_final) tuple — exercises every
 * scalar operation and the BLAKE3 kernel hash end-to-end on device.
 */
static bool test_mweb_kernel_sign_simple(void)
{
    static const uint8_t EK[32] = {
        0x0a,0x0a,0x0a,0x0a,0x0a,0x0a,0x0a,0x0a,
        0x0a,0x0a,0x0a,0x0a,0x0a,0x0a,0x0a,0x0a,
        0x0a,0x0a,0x0a,0x0a,0x0a,0x0a,0x0a,0x0a,
        0x0a,0x0a,0x0a,0x0a,0x0a,0x0a,0x0a,0x0a,
    };
    static const uint8_t IN_BLIND[32] = {
        0x05,0x05,0x05,0x05,0x05,0x05,0x05,0x05,
        0x05,0x05,0x05,0x05,0x05,0x05,0x05,0x05,
        0x05,0x05,0x05,0x05,0x05,0x05,0x05,0x05,
        0x05,0x05,0x05,0x05,0x05,0x05,0x05,0x05,
    };
    static const uint8_t IN_TWEAK[32] = {
        0x06,0x06,0x06,0x06,0x06,0x06,0x06,0x06,
        0x06,0x06,0x06,0x06,0x06,0x06,0x06,0x06,
        0x06,0x06,0x06,0x06,0x06,0x06,0x06,0x06,
        0x06,0x06,0x06,0x06,0x06,0x06,0x06,0x06,
    };
    static const uint8_t OUT_BLIND[32] = {
        0x07,0x07,0x07,0x07,0x07,0x07,0x07,0x07,
        0x07,0x07,0x07,0x07,0x07,0x07,0x07,0x07,
        0x07,0x07,0x07,0x07,0x07,0x07,0x07,0x07,
        0x07,0x07,0x07,0x07,0x07,0x07,0x07,0x07,
    };
    static const uint8_t RECV_TX_OFF[32] = {
        0x03,0x03,0x03,0x03,0x03,0x03,0x03,0x03,
        0x03,0x03,0x03,0x03,0x03,0x03,0x03,0x03,
        0x03,0x03,0x03,0x03,0x03,0x03,0x03,0x03,
        0x03,0x03,0x03,0x03,0x03,0x03,0x03,0x03,
    };
    static const uint8_t RECV_ST_OFF[32] = {
        0x04,0x04,0x04,0x04,0x04,0x04,0x04,0x04,
        0x04,0x04,0x04,0x04,0x04,0x04,0x04,0x04,
        0x04,0x04,0x04,0x04,0x04,0x04,0x04,0x04,
        0x04,0x04,0x04,0x04,0x04,0x04,0x04,0x04,
    };

    /* Pinned expected outputs for the EK above. */
    static const uint8_t EXPECTED_EXCESS[33] = {
        0x08,0xf7,0x6a,0x39,0xd0,0x56,0x86,0xe3,
        0x4a,0x44,0x20,0x89,0x7e,0x35,0x93,0x71,
        0x83,0x61,0x45,0xdd,0x39,0x73,0xe3,0x98,
        0x25,0x68,0xb6,0x0f,0x84,0x33,0xad,0xde,
        0x6e,
    };
    static const uint8_t EXPECTED_SIG[64] = {
        0xb7,0x7a,0x61,0x0d,0xa8,0xc1,0x36,0x8c,
        0x7d,0x7d,0x0f,0x50,0xee,0x95,0xb5,0xb7,
        0xe8,0x65,0x9a,0x0d,0x71,0x73,0x98,0xbd,
        0xe4,0x87,0xb7,0xdd,0x55,0x6a,0x06,0x7c,
        0x5c,0x21,0xc9,0xed,0x85,0xbb,0x57,0xee,
        0x36,0x3e,0x7a,0x2b,0x31,0x97,0x54,0x01,
        0xf5,0x47,0xd9,0x2e,0xcf,0x6f,0xaf,0xc5,
        0x3a,0x3f,0xfc,0x69,0xc3,0x53,0x81,0x6d,
    };
    static const uint8_t EXPECTED_TX_OFF[32] = {
        0xf3,0xf3,0xf3,0xf3,0xf3,0xf3,0xf3,0xf3,
        0xf3,0xf3,0xf3,0xf3,0xf3,0xf3,0xf3,0xf2,
        0xae,0xa2,0xd0,0xda,0xa3,0x3c,0x94,0x2f,
        0xb3,0xc6,0x52,0x80,0xc4,0x2a,0x35,0x35,
    };
    static const uint8_t EXPECTED_ST_OFF[32] = {
        0x0a,0x0a,0x0a,0x0a,0x0a,0x0a,0x0a,0x0a,
        0x0a,0x0a,0x0a,0x0a,0x0a,0x0a,0x0a,0x0a,
        0x0a,0x0a,0x0a,0x0a,0x0a,0x0a,0x0a,0x0a,
        0x0a,0x0a,0x0a,0x0a,0x0a,0x0a,0x0a,0x0a,
    };

    mweb_input_ctx_t inp;
    inp.value = 100010000;
    memcpy(inp.blind, IN_BLIND, 32);
    memcpy(inp.stealth_tweak, IN_TWEAK, 32);

    mweb_output_ctx_t outp;
    outp.value = 100000000;
    memcpy(outp.blind, OUT_BLIND, 32);

    struct mweb_kernel_sign_params params;
    memset(&params, 0, sizeof(params));
    params.inputs = &inp; params.n_inputs = 1;
    params.outputs = &outp; params.n_outputs = 1;
    params.features = MWEB_KERNEL_FEE_BIT;
    params.fee = 10000; params.has_fee = true;
    params.received_tx_offset = RECV_TX_OFF;
    params.received_stealth_offset = RECV_ST_OFF;

    struct mweb_kernel_sign_outputs result;
    if (mweb_sign_kernel_with_ek(EK, &params, &result) != MWEB_OK) { FAIL(); }
    if (memcmp(result.excess_kG, EXPECTED_EXCESS, 33) != 0) { FAIL(); }
    if (memcmp(result.signature, EXPECTED_SIG, 64) != 0) { FAIL(); }
    if (memcmp(result.tx_offset_final, EXPECTED_TX_OFF, 32) != 0) { FAIL(); }
    if (memcmp(result.stealth_offset_final, EXPECTED_ST_OFF, 32) != 0) { FAIL(); }

    return true;
}

/* ── Kernel signing — STEALTH excess, full ──────────────────────────── */

/*
 * Stealth-excess kernel with the sigKey tweak active. Covers the
 * O_s_final = received + Sum(tweak) - stealthKey path.
 */
static bool test_mweb_kernel_sign_stealth(void)
{
    static const uint8_t EK[32] = {
        0x1b,0x1b,0x1b,0x1b,0x1b,0x1b,0x1b,0x1b,
        0x1b,0x1b,0x1b,0x1b,0x1b,0x1b,0x1b,0x1b,
        0x1b,0x1b,0x1b,0x1b,0x1b,0x1b,0x1b,0x1b,
        0x1b,0x1b,0x1b,0x1b,0x1b,0x1b,0x1b,0x1b,
    };
    static const uint8_t STEALTH_KEY[32] = {
        0x2c,0x2c,0x2c,0x2c,0x2c,0x2c,0x2c,0x2c,
        0x2c,0x2c,0x2c,0x2c,0x2c,0x2c,0x2c,0x2c,
        0x2c,0x2c,0x2c,0x2c,0x2c,0x2c,0x2c,0x2c,
        0x2c,0x2c,0x2c,0x2c,0x2c,0x2c,0x2c,0x2c,
    };
    static const uint8_t IN_BLIND[32] = {
        0x05,0x05,0x05,0x05,0x05,0x05,0x05,0x05,
        0x05,0x05,0x05,0x05,0x05,0x05,0x05,0x05,
        0x05,0x05,0x05,0x05,0x05,0x05,0x05,0x05,
        0x05,0x05,0x05,0x05,0x05,0x05,0x05,0x05,
    };
    static const uint8_t IN_TWEAK[32] = {
        0x06,0x06,0x06,0x06,0x06,0x06,0x06,0x06,
        0x06,0x06,0x06,0x06,0x06,0x06,0x06,0x06,
        0x06,0x06,0x06,0x06,0x06,0x06,0x06,0x06,
        0x06,0x06,0x06,0x06,0x06,0x06,0x06,0x06,
    };
    static const uint8_t OUT_BLIND[32] = {
        0x07,0x07,0x07,0x07,0x07,0x07,0x07,0x07,
        0x07,0x07,0x07,0x07,0x07,0x07,0x07,0x07,
        0x07,0x07,0x07,0x07,0x07,0x07,0x07,0x07,
        0x07,0x07,0x07,0x07,0x07,0x07,0x07,0x07,
    };
    static const uint8_t RECV_TX_OFF[32] = {
        0x03,0x03,0x03,0x03,0x03,0x03,0x03,0x03,
        0x03,0x03,0x03,0x03,0x03,0x03,0x03,0x03,
        0x03,0x03,0x03,0x03,0x03,0x03,0x03,0x03,
        0x03,0x03,0x03,0x03,0x03,0x03,0x03,0x03,
    };
    static const uint8_t RECV_ST_OFF[32] = {
        0x04,0x04,0x04,0x04,0x04,0x04,0x04,0x04,
        0x04,0x04,0x04,0x04,0x04,0x04,0x04,0x04,
        0x04,0x04,0x04,0x04,0x04,0x04,0x04,0x04,
        0x04,0x04,0x04,0x04,0x04,0x04,0x04,0x04,
    };

    static const uint8_t EXPECTED_EXCESS[33] = {
        0x09,0x74,0x30,0x6d,0xa5,0x30,0xaf,0x51,
        0x65,0x69,0xcc,0xc4,0x86,0x26,0x1d,0xb3,
        0xdd,0x67,0xa4,0xee,0x87,0xf1,0x1c,0x96,
        0xc8,0xac,0x14,0x72,0x5d,0xc0,0x7f,0x29,
        0x3e,
    };
    static const uint8_t EXPECTED_STEALTH_EXCESS[33] = {
        0x02,0x8f,0x53,0x04,0xe2,0x37,0x3e,0x56,
        0xee,0x7d,0x77,0x4c,0xb8,0x9e,0x9f,0x1a,
        0xfe,0xcf,0x0e,0xe7,0xe3,0xe3,0x75,0x7f,
        0x18,0x99,0x08,0xf0,0x69,0xda,0xa3,0x6c,
        0x60,
    };
    static const uint8_t EXPECTED_SIG[64] = {
        0x9a,0xf2,0xb5,0x0d,0x96,0xce,0x63,0x19,
        0x61,0xd2,0xa6,0x0b,0x69,0xf9,0x8b,0x50,
        0x7b,0x88,0xde,0xca,0x0f,0x49,0x0d,0xd5,
        0xfe,0xc4,0x1e,0xcc,0x96,0xa8,0x02,0x80,
        0xea,0x3e,0x25,0x47,0xdc,0x68,0x59,0x01,
        0x3e,0x66,0x06,0xc1,0x05,0x4b,0x4f,0x57,
        0x35,0xa0,0x94,0xe8,0xd5,0xfc,0x49,0x14,
        0x0a,0xb1,0xdb,0xc8,0x25,0x13,0x00,0x88,
    };
    static const uint8_t EXPECTED_TX_OFF[32] = {
        0xe2,0xe2,0xe2,0xe2,0xe2,0xe2,0xe2,0xe2,
        0xe2,0xe2,0xe2,0xe2,0xe2,0xe2,0xe2,0xe1,
        0x9d,0x91,0xbf,0xc9,0x92,0x2b,0x83,0x1e,
        0xa2,0xb5,0x41,0x6f,0xb3,0x19,0x24,0x24,
    };
    static const uint8_t EXPECTED_ST_OFF[32] = {
        0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,
        0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdc,
        0x98,0x8c,0xba,0xc4,0x8d,0x26,0x7e,0x19,
        0x9d,0xb0,0x3c,0x6a,0xae,0x14,0x1f,0x1f,
    };

    mweb_input_ctx_t inp;
    inp.value = 100005000;
    memcpy(inp.blind, IN_BLIND, 32);
    memcpy(inp.stealth_tweak, IN_TWEAK, 32);

    mweb_output_ctx_t outp;
    outp.value = 100000000;
    memcpy(outp.blind, OUT_BLIND, 32);

    struct mweb_kernel_sign_params params;
    memset(&params, 0, sizeof(params));
    params.inputs = &inp; params.n_inputs = 1;
    params.outputs = &outp; params.n_outputs = 1;
    params.features = MWEB_KERNEL_FEE_BIT | MWEB_KERNEL_STEALTH_EXCESS_BIT;
    params.fee = 5000; params.has_fee = true;
    params.stealth_key_or_null = STEALTH_KEY;
    params.received_tx_offset = RECV_TX_OFF;
    params.received_stealth_offset = RECV_ST_OFF;

    struct mweb_kernel_sign_outputs result;
    if (mweb_sign_kernel_with_ek(EK, &params, &result) != MWEB_OK) { FAIL(); }
    if (memcmp(result.excess_kG,         EXPECTED_EXCESS,         33) != 0) { FAIL(); }
    if (memcmp(result.stealth_excess_G,  EXPECTED_STEALTH_EXCESS, 33) != 0) { FAIL(); }
    if (memcmp(result.signature,         EXPECTED_SIG,            64) != 0) { FAIL(); }
    if (memcmp(result.tx_offset_final,   EXPECTED_TX_OFF,         32) != 0) { FAIL(); }
    if (memcmp(result.stealth_offset_final, EXPECTED_ST_OFF,      32) != 0) { FAIL(); }

    return true;
}

/* ── Kernel signing — error taxonomy ────────────────────────────────── */

/*
 * Exercises every policy-level failure code `mweb_sign_kernel_with_ek`
 * can return: zero/overflow scalars, feature-bit ↔ field presence
 * mismatches in both directions, the stealth-excess split between
 * MISSING_STEALTH_KEY and KERNEL_FEATURE_MISMATCH, and u64 balance
 * failures (including overflow).
 *
 * A regression that silently collapses two codes would only surface
 * at boot through this test.
 */
static bool test_mweb_kernel_sign_errors(void)
{
    static const uint8_t ZERO[32] = {0};
    static const uint8_t ONE[32] = {
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,
    };
    /* n (secp256k1 group order) */
    static const uint8_t ORDER[32] = {
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,
        0xBA,0xAE,0xDC,0xE6,0xAF,0x48,0xA0,0x3B,
        0xBF,0xD2,0x5E,0x8C,0xD0,0x36,0x41,0x41,
    };

    mweb_input_ctx_t inp; memset(&inp, 0, sizeof(inp));
    mweb_output_ctx_t outp; memset(&outp, 0, sizeof(outp));

    struct mweb_kernel_sign_params params;
    struct mweb_kernel_sign_outputs result;

    /* Baseline: balanced fee-only kernel. Each sub-test perturbs one
     * field and asserts the specific policy code. */
    #define BASE_PARAMS()                                                 \
        do {                                                              \
            inp.value = 1000;                                             \
            outp.value = 500;                                             \
            memset(&params, 0, sizeof(params));                           \
            params.inputs = &inp; params.n_inputs = 1;                    \
            params.outputs = &outp; params.n_outputs = 1;                 \
            params.features = MWEB_KERNEL_FEE_BIT;                        \
            params.fee = 500; params.has_fee = true;                      \
            params.received_tx_offset = ZERO;                             \
            params.received_stealth_offset = ZERO;                        \
        } while (0)

    /* 1. Zero e_k → INVALID_PRESIGN_SCALAR */
    BASE_PARAMS();
    if (mweb_sign_kernel_with_ek(ZERO, &params, &result)
        != MWEB_ERR_INVALID_PRESIGN_SCALAR) { FAIL(); }

    /* 2. e_k == n → INVALID_PRESIGN_SCALAR */
    BASE_PARAMS();
    if (mweb_sign_kernel_with_ek(ORDER, &params, &result)
        != MWEB_ERR_INVALID_PRESIGN_SCALAR) { FAIL(); }

    /* 3. Unbalanced (output > input+fee): BALANCE_FAIL */
    BASE_PARAMS();
    outp.value = 10000;  /* 10000 != 1000 - 500 */
    if (mweb_sign_kernel_with_ek(ONE, &params, &result)
        != MWEB_ERR_BALANCE_FAIL) { FAIL(); }

    /* 4. u64 overflow on input side: BALANCE_FAIL */
    BASE_PARAMS();
    inp.value = UINT64_MAX;
    outp.value = UINT64_MAX - 1;
    params.pegin_amount = UINT64_MAX;
    params.has_pegin_amount = true;
    params.features = MWEB_KERNEL_FEE_BIT | MWEB_KERNEL_PEGIN_BIT;
    params.fee = 1;
    if (mweb_sign_kernel_with_ek(ONE, &params, &result)
        != MWEB_ERR_BALANCE_FAIL) { FAIL(); }

    /* 5. FeeBit set but has_fee=false: FEATURE_MISMATCH */
    BASE_PARAMS();
    params.has_fee = false;
    if (mweb_sign_kernel_with_ek(ONE, &params, &result)
        != MWEB_ERR_KERNEL_FEATURE_MISMATCH) { FAIL(); }

    /* 6. has_fee=true but FeeBit clear: FEATURE_MISMATCH */
    BASE_PARAMS();
    params.features = 0;
    if (mweb_sign_kernel_with_ek(ONE, &params, &result)
        != MWEB_ERR_KERNEL_FEATURE_MISMATCH) { FAIL(); }

    /* 7. PeginBit set but has_pegin=false: FEATURE_MISMATCH */
    BASE_PARAMS();
    params.features |= MWEB_KERNEL_PEGIN_BIT;
    params.has_pegin_amount = false;
    if (mweb_sign_kernel_with_ek(ONE, &params, &result)
        != MWEB_ERR_KERNEL_FEATURE_MISMATCH) { FAIL(); }

    /* 8. PegoutBit set but pegouts NULL: FEATURE_MISMATCH */
    BASE_PARAMS();
    params.features |= MWEB_KERNEL_PEGOUT_BIT;
    params.pegouts = NULL;
    if (mweb_sign_kernel_with_ek(ONE, &params, &result)
        != MWEB_ERR_KERNEL_FEATURE_MISMATCH) { FAIL(); }

    /* 9. LockHeightBit set but has_lock_height=false: FEATURE_MISMATCH */
    BASE_PARAMS();
    params.features |= MWEB_KERNEL_HEIGHT_LOCK_BIT;
    params.has_lock_height = false;
    if (mweb_sign_kernel_with_ek(ONE, &params, &result)
        != MWEB_ERR_KERNEL_FEATURE_MISMATCH) { FAIL(); }

    /* 10. ExtraDataBit set but extra_data NULL / len=0: FEATURE_MISMATCH */
    BASE_PARAMS();
    params.features |= MWEB_KERNEL_EXTRA_DATA_BIT;
    params.extra_data = NULL;
    params.extra_data_len = 0;
    if (mweb_sign_kernel_with_ek(ONE, &params, &result)
        != MWEB_ERR_KERNEL_FEATURE_MISMATCH) { FAIL(); }

    /* 11. StealthExcessBit set but stealth_key NULL: MISSING_STEALTH_KEY
     *     (distinct from FEATURE_MISMATCH so the user-visible error
     *     points at missing presign data, not a structural mismatch). */
    BASE_PARAMS();
    params.features |= MWEB_KERNEL_STEALTH_EXCESS_BIT;
    params.stealth_key_or_null = NULL;
    if (mweb_sign_kernel_with_ek(ONE, &params, &result)
        != MWEB_ERR_MISSING_STEALTH_KEY) { FAIL(); }

    /* 12. !StealthExcessBit but stealth_key present: FEATURE_MISMATCH
     *     (inverse direction — structural inconsistency, not a
     *     data-gathering problem.) */
    BASE_PARAMS();
    params.stealth_key_or_null = ONE;
    if (mweb_sign_kernel_with_ek(ONE, &params, &result)
        != MWEB_ERR_KERNEL_FEATURE_MISMATCH) { FAIL(); }

    /* 13. Zero stealth_key: INVALID_PRESIGN_SCALAR */
    BASE_PARAMS();
    params.features |= MWEB_KERNEL_STEALTH_EXCESS_BIT;
    params.stealth_key_or_null = ZERO;
    if (mweb_sign_kernel_with_ek(ONE, &params, &result)
        != MWEB_ERR_INVALID_PRESIGN_SCALAR) { FAIL(); }

    #undef BASE_PARAMS
    return true;
}

/* ── Kernel signing — fee=0 with FeeBit set is accepted ──────────────── */

/*
 * Regression guard for the presence-not-nonzero rule.
 * `has_fee=true, fee=0, FeeBit=1` is a valid kernel: the zero u64 is
 * hashed, the signature verifies, and the helper returns MWEB_OK.
 */
static bool test_mweb_kernel_fee_zero_ok(void)
{
    static const uint8_t ONE[32] = {
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,
    };
    static const uint8_t ZERO[32] = {0};

    struct mweb_kernel_sign_params params;
    memset(&params, 0, sizeof(params));
    params.features = MWEB_KERNEL_FEE_BIT;
    params.fee = 0;
    params.has_fee = true;
    params.received_tx_offset = ZERO;
    params.received_stealth_offset = ZERO;

    struct mweb_kernel_sign_outputs result;
    if (mweb_sign_kernel_with_ek(ONE, &params, &result) != MWEB_OK) { FAIL(); }

    /* Signature must be non-zero: a zero signature would indicate a
     * code-path short-circuit bypassing the Schnorr primitive. */
    uint8_t zero_sig[64] = {0};
    if (memcmp(result.signature, zero_sig, 64) == 0) { FAIL(); }

    /* E_k must be a valid Pedersen commitment (0x08/0x09 prefix). */
    if (result.excess_kG[0] != 0x08 && result.excess_kG[0] != 0x09) { FAIL(); }

    return true;
}

/* ── Zero offsets are accepted ──────────────────────────────────────── */

/*
 * Construct an honest PSBT whose scalar arithmetic produces a zero
 * O_k_final and a zero O_s_final. `mweb_scalar_*_mod_n` accepts zero
 * operands and zero results, so a legitimately-zero offset must not
 * short-circuit the sign path.
 *
 *   O_k_final = received_tx_offset - Sum(blind) - e_k  (mod n)
 *             = (0x00..02) - (0x00..01) - (0x00..01) = 0
 *
 *   O_s_final = received_stealth + Sum(stealth_tweak)  (non-stealth)
 *             = 0 + 0 = 0
 *
 * Balance: v_in(1000) = v_out(500) + fee(500).
 */
static bool test_mweb_zero_offsets_accepted(void)
{
    static const uint8_t ONE_BE[32] = {
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,
    };
    static const uint8_t TWO_BE[32] = {
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,2,
    };
    static const uint8_t ZERO[32] = {0};

    mweb_input_ctx_t inp;
    memset(&inp, 0, sizeof(inp));
    inp.value = 1000;
    memcpy(inp.blind, ONE_BE, 32);
    /* stealth_tweak is zero — sum is zero. */

    mweb_output_ctx_t outp;
    memset(&outp, 0, sizeof(outp));
    outp.value = 500;

    struct mweb_kernel_sign_params params;
    memset(&params, 0, sizeof(params));
    params.inputs = &inp; params.n_inputs = 1;
    params.outputs = &outp; params.n_outputs = 1;
    params.features = MWEB_KERNEL_FEE_BIT;
    params.fee = 500; params.has_fee = true;
    params.received_tx_offset = TWO_BE;        /* 2 - 1 - 1 = 0 */
    params.received_stealth_offset = ZERO;     /* 0 + 0 = 0    */

    struct mweb_kernel_sign_outputs result;
    if (mweb_sign_kernel_with_ek(ONE_BE, &params, &result) != MWEB_OK) { FAIL(); }

    /* Both offsets must be exactly 32 zero bytes — not the "silent
     * reset to zero" of the deleted accumulator, but the arithmetic
     * result accepted verbatim. */
    if (memcmp(result.tx_offset_final,      ZERO, 32) != 0) { FAIL(); }
    if (memcmp(result.stealth_offset_final, ZERO, 32) != 0) { FAIL(); }

    /* Signature itself must still be emitted (non-zero). */
    uint8_t zero_sig[64] = {0};
    if (memcmp(result.signature, zero_sig, 64) == 0) { FAIL(); }

    return true;
}

/* ── Kernel message hash vectors ────────────────────────────────────── */

/*
 * Pinned kernel-hash vectors over the shared EXCESS / STEALTH_EXCESS
 * pubkeys. Cover the feature combinations in the broader fixture file
 * at main/mweb/tests/fixtures/kernel_hash_vectors.h.
 */
static const uint8_t KH_EXCESS[33] = {
    0x08,
    0xa1,0xa1,0xa1,0xa1,0xa1,0xa1,0xa1,0xa1,
    0xa1,0xa1,0xa1,0xa1,0xa1,0xa1,0xa1,0xa1,
    0xa1,0xa1,0xa1,0xa1,0xa1,0xa1,0xa1,0xa1,
    0xa1,0xa1,0xa1,0xa1,0xa1,0xa1,0xa1,0xa1,
};
static const uint8_t KH_STEALTH[33] = {
    0x02,
    0xb2,0xb2,0xb2,0xb2,0xb2,0xb2,0xb2,0xb2,
    0xb2,0xb2,0xb2,0xb2,0xb2,0xb2,0xb2,0xb2,
    0xb2,0xb2,0xb2,0xb2,0xb2,0xb2,0xb2,0xb2,
    0xb2,0xb2,0xb2,0xb2,0xb2,0xb2,0xb2,0xb2,
};

static bool test_mweb_kernel_hash(void)
{
    uint8_t hash[32];

    /* FEE_ONLY — features=0x01, fee=50000 */
    static const uint8_t H_FEE_ONLY[32] = {
        0x1b,0x0e,0xe8,0xf6,0x39,0x43,0x41,0x3d,
        0x8e,0x6d,0x0b,0xe3,0x68,0x40,0xe2,0x25,
        0xf8,0xca,0xa4,0x0d,0x19,0xec,0xd1,0x05,
        0xfb,0x13,0x54,0x26,0x69,0x96,0xb6,0x3c,
    };
    if (!mweb_kernel_sig_hash(MWEB_KERNEL_FEE_BIT, KH_EXCESS,
                              50000, true,
                              0, false,
                              NULL,
                              0, false,
                              NULL, NULL, 0,
                              hash)) { FAIL(); }
    if (memcmp(hash, H_FEE_ONLY, 32) != 0) { FAIL(); }

    /* FEE_AND_STEALTH — features=0x11, fee=25000, stealth_excess present. */
    static const uint8_t H_FEE_AND_STEALTH[32] = {
        0xe1,0x6e,0xff,0xb5,0x1a,0x2d,0x8f,0xad,
        0x9e,0x35,0x70,0xfc,0xaf,0x14,0x2b,0x92,
        0x6d,0x7a,0xb8,0x46,0x48,0xe2,0x8f,0xb9,
        0x46,0xd5,0x5c,0x30,0x7d,0x56,0xaa,0xb7,
    };
    if (!mweb_kernel_sig_hash(MWEB_KERNEL_FEE_BIT | MWEB_KERNEL_STEALTH_EXCESS_BIT,
                              KH_EXCESS,
                              25000, true,
                              0, false,
                              NULL,
                              0, false,
                              KH_STEALTH, NULL, 0,
                              hash)) { FAIL(); }
    if (memcmp(hash, H_FEE_AND_STEALTH, 32) != 0) { FAIL(); }

    /* FEE_ZERO — presence-not-nonzero (fee=0, has_fee=true, FeeBit set). */
    static const uint8_t H_FEE_ZERO[32] = {
        0xa7,0x72,0x89,0x94,0x59,0x94,0xa2,0xd2,
        0xb0,0xd8,0xa0,0x9b,0xbc,0xcd,0x58,0xb9,
        0x0e,0x60,0x77,0x0d,0xf1,0xdb,0x02,0x5a,
        0x91,0x66,0x67,0x99,0x5d,0x4f,0x2b,0x93,
    };
    if (!mweb_kernel_sig_hash(MWEB_KERNEL_FEE_BIT, KH_EXCESS,
                              0, true,
                              0, false,
                              NULL,
                              0, false,
                              NULL, NULL, 0,
                              hash)) { FAIL(); }
    if (memcmp(hash, H_FEE_ZERO, 32) != 0) { FAIL(); }

    /* PLAIN_NO_FEATURES — features=0x00, only excess in the hash. */
    static const uint8_t H_PLAIN[32] = {
        0x6c,0xe0,0xcc,0xe6,0x69,0x97,0x20,0xad,
        0xe3,0x3e,0x25,0x01,0xeb,0x58,0x94,0xe0,
        0x9f,0x15,0xd2,0xfa,0x4b,0x9d,0xad,0x49,
        0xf5,0x9d,0x40,0xc5,0x9a,0x5d,0xef,0xc3,
    };
    if (!mweb_kernel_sig_hash(0, KH_EXCESS,
                              0, false,
                              0, false,
                              NULL,
                              0, false,
                              NULL, NULL, 0,
                              hash)) { FAIL(); }
    if (memcmp(hash, H_PLAIN, 32) != 0) { FAIL(); }

    /* NULL excess_commitment rejected. */
    if (mweb_kernel_sig_hash(MWEB_KERNEL_FEE_BIT, NULL,
                             1, true,
                             0, false,
                             NULL,
                             0, false,
                             NULL, NULL, 0,
                             hash)) { FAIL(); }

    return true;
}

/* ── Output recipient-binding vectors ───────────────────────────────── */

/*
 * Pinned HAPPY vector: sender_key=0x11..11, (A, B) derived from
 * scan_sk=0x01..01 / spend_sk=0x02..02, value=100000000. Every
 * rederived field must match the host-supplied PSBT field — that's
 * the recipient-binding guarantee.
 *
 * Fixture shared with main/mweb/tests/fixtures/output_vectors.h.
 */
static const uint8_t OUT_SENDER_KEY[32] = {
    0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,
    0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,
    0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,
    0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,
};
static const uint8_t OUT_SCAN_A[33] = {
    0x03,0x1b,0x84,0xc5,0x56,0x7b,0x12,0x64,
    0x40,0x99,0x5d,0x3e,0xd5,0xaa,0xba,0x05,
    0x65,0xd7,0x1e,0x18,0x34,0x60,0x48,0x19,
    0xff,0x9c,0x17,0xf5,0xe9,0xd5,0xdd,0x07,
    0x8f,
};
static const uint8_t OUT_SPEND_B[33] = {
    0x02,0x4d,0x4b,0x6c,0xd1,0x36,0x10,0x32,
    0xca,0x9b,0xd2,0xae,0xb9,0xd9,0x00,0xaa,
    0x4d,0x45,0xd9,0xea,0xd8,0x0a,0xc9,0x42,
    0x33,0x74,0xc4,0x51,0xa7,0x25,0x4d,0x07,
    0x66,
};
static const uint64_t OUT_VALUE = 100000000ULL;

static const uint8_t OUT_EXP_BLIND[32] = {
    0x5c,0x1b,0x0e,0x92,0xaf,0xe3,0xe7,0x03,
    0xf4,0xc5,0xf2,0xf6,0x79,0xaa,0x28,0x5e,
    0x00,0x62,0xe7,0x27,0x5b,0xa1,0xcc,0x27,
    0x22,0x42,0xfd,0x6b,0xfd,0xef,0xc8,0x81,
};
static const uint8_t OUT_EXP_KO[33] = {
    0x02,0x05,0x3b,0x89,0xb9,0x14,0x4c,0xe2,
    0xd7,0x20,0x1c,0x9e,0x93,0x21,0xd8,0x8d,
    0x68,0x74,0x94,0xfb,0xfe,0x7d,0xbd,0x70,
    0xf5,0x28,0x11,0x04,0x2b,0xd0,0x62,0xdc,
    0x64,
};
static const uint8_t OUT_EXP_KS[33] = {
    0x03,0x4f,0x35,0x5b,0xdc,0xb7,0xcc,0x0a,
    0xf7,0x28,0xef,0x3c,0xce,0xb9,0x61,0x5d,
    0x90,0x68,0x4b,0xb5,0xb2,0xca,0x5f,0x85,
    0x9a,0xb0,0xf0,0xb7,0x04,0x07,0x58,0x71,
    0xaa,
};
static const uint8_t OUT_EXP_KE[33] = {
    0x02,0x15,0x17,0x36,0xfd,0xc3,0xc2,0x61,
    0x38,0x47,0xf6,0x05,0x91,0xff,0xc2,0xa0,
    0xec,0x2b,0x20,0x55,0x01,0x07,0x46,0xd1,
    0x37,0xb7,0xa3,0x6f,0x14,0xad,0xfe,0x9b,
    0xe7,
};
static const uint8_t OUT_EXP_COMMIT[33] = {
    0x08,0x65,0xc1,0x7a,0x39,0x27,0xc5,0xd3,
    0xc3,0x64,0xee,0x6c,0x04,0xb8,0x85,0xb5,
    0x2a,0x85,0x11,0x3c,0xdf,0x7f,0xd0,0x1d,
    0x71,0xee,0x55,0x8e,0x64,0x34,0xc4,0xc9,
    0x1d,
};
#define OUT_EXP_VIEW_TAG       ((uint8_t)0x1f)
#define OUT_EXP_MASKED_VALUE   ((uint64_t)0x990f3e2289a63b46ULL)
static const uint8_t OUT_EXP_MASKED_NONCE[16] = {
    0x75,0x0d,0x01,0xb1,0x7b,0x1c,0x7b,0x61,
    0x74,0x78,0x60,0xf4,0x30,0x0f,0x0b,0xf7,
};

static bool test_mweb_derive_output_happy(void)
{
    /* Happy path — every rederived field must match byte-for-byte. */
    struct mweb_derived_output got;
    if (mweb_derive_output(OUT_SENDER_KEY, OUT_SCAN_A, OUT_SPEND_B,
                           OUT_VALUE, &got) != MWEB_OK) { FAIL(); }
    if (memcmp(got.blind,               OUT_EXP_BLIND,        32) != 0) { FAIL(); }
    if (memcmp(got.output_pubkey,       OUT_EXP_KO,           33) != 0) { FAIL(); }
    if (memcmp(got.sender_pubkey,       OUT_EXP_KS,           33) != 0) { FAIL(); }
    if (memcmp(got.key_exchange_pubkey, OUT_EXP_KE,           33) != 0) { FAIL(); }
    if (memcmp(got.commit,              OUT_EXP_COMMIT,       33) != 0) { FAIL(); }
    if (got.view_tag                 != OUT_EXP_VIEW_TAG)             { FAIL(); }
    if (got.masked_value             != OUT_EXP_MASKED_VALUE)         { FAIL(); }
    if (memcmp(got.masked_nonce,        OUT_EXP_MASKED_NONCE, 16) != 0) { FAIL(); }

    /* Invalid-scalar rejection — sender_key == 0 rejected before any EC op. */
    static const uint8_t ZERO[32] = {0};
    if (mweb_derive_output(ZERO, OUT_SCAN_A, OUT_SPEND_B, OUT_VALUE, &got)
        != MWEB_ERR_INVALID_PRESIGN_SCALAR) { FAIL(); }

    return true;
}

/*
 * Tamper-detection: the derivation must be sensitive to each of its
 * inputs. For the atomic-pass side to reject adversarial output
 * bodies, the device-side derivation has to diverge when ANY input
 * differs.
 *
 * Drives three single-bit perturbations (sender_key, value,
 * stealth_address B) and asserts that at least one of the rederived
 * fields differs from the HAPPY vector. A naive implementation that
 * silently ignored an input would fail one of these.
 */
static bool test_mweb_derive_output_mismatch(void)
{
    struct mweb_derived_output got;

    /* 1. Tampered sender_key (flip lowest bit). Every field should change. */
    uint8_t tampered_sk[32];
    memcpy(tampered_sk, OUT_SENDER_KEY, 32);
    tampered_sk[31] ^= 0x01;
    if (mweb_derive_output(tampered_sk, OUT_SCAN_A, OUT_SPEND_B,
                           OUT_VALUE, &got) != MWEB_OK) { FAIL(); }
    if (memcmp(got.sender_pubkey, OUT_EXP_KS, 33) == 0) { FAIL(); }
    if (memcmp(got.output_pubkey, OUT_EXP_KO, 33) == 0) { FAIL(); }
    if (memcmp(got.commit,        OUT_EXP_COMMIT, 33) == 0) { FAIL(); }

    /* 2. Tampered value. commit / masked_value must differ; K_s
     *    unchanged (K_s = sender_key * G is value-independent). */
    if (mweb_derive_output(OUT_SENDER_KEY, OUT_SCAN_A, OUT_SPEND_B,
                           OUT_VALUE + 1, &got) != MWEB_OK) { FAIL(); }
    if (memcmp(got.sender_pubkey, OUT_EXP_KS,     33) != 0) { FAIL(); }
    if (memcmp(got.commit,        OUT_EXP_COMMIT, 33) == 0) { FAIL(); }
    if (got.masked_value == OUT_EXP_MASKED_VALUE)           { FAIL(); }

    /* 3. Tampered stealth address B (spend pubkey). K_o and K_e both
     *    depend on B; at least one of them must differ. */
    uint8_t tampered_B[33];
    memcpy(tampered_B, OUT_SPEND_B, 33);
    tampered_B[32] ^= 0x01;
    if (mweb_derive_output(OUT_SENDER_KEY, OUT_SCAN_A, tampered_B,
                           OUT_VALUE, &got) != MWEB_OK) { FAIL(); }
    if (memcmp(got.output_pubkey,       OUT_EXP_KO, 33) == 0
        && memcmp(got.key_exchange_pubkey, OUT_EXP_KE, 33) == 0) {
        FAIL();
    }

    return true;
}

/* ── Scalar validation ──────────────────────────────────────────────── */

/*
 * Every host-supplied scalar that enters an EC operation must pass
 * `mweb_validate_scalar`: zero and overflow (>= curve order) are both
 * rejected before the scalar can reach secp256k1.
 */
static bool test_mweb_scalar_validate(void)
{
    static const uint8_t ZERO[32] = {0};
    static const uint8_t ONE[32] = {
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,
    };
    /* n — curve order, not a valid scalar (must be strictly less). */
    static const uint8_t ORDER[32] = {
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,
        0xBA,0xAE,0xDC,0xE6,0xAF,0x48,0xA0,0x3B,
        0xBF,0xD2,0x5E,0x8C,0xD0,0x36,0x41,0x41,
    };
    /* n-1 — largest valid scalar. */
    static const uint8_t N_MINUS_1[32] = {
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,
        0xBA,0xAE,0xDC,0xE6,0xAF,0x48,0xA0,0x3B,
        0xBF,0xD2,0x5E,0x8C,0xD0,0x36,0x41,0x40,
    };
    /* n+1 — overflows to 1 mod n, still rejected (absolute comparison). */
    static const uint8_t N_PLUS_1[32] = {
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,
        0xBA,0xAE,0xDC,0xE6,0xAF,0x48,0xA0,0x3B,
        0xBF,0xD2,0x5E,0x8C,0xD0,0x36,0x41,0x42,
    };
    /* All-ones — larger than n, rejected. */
    static const uint8_t ALL_ONES[32] = {
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    };

    if ( mweb_validate_scalar(ZERO))       { FAIL(); }  /* zero rejected */
    if ( mweb_validate_scalar(ORDER))      { FAIL(); }  /* n rejected    */
    if ( mweb_validate_scalar(N_PLUS_1))   { FAIL(); }  /* >n rejected   */
    if ( mweb_validate_scalar(ALL_ONES))   { FAIL(); }  /* >n rejected   */
    if (!mweb_validate_scalar(ONE))        { FAIL(); }  /* 1 accepted    */
    if (!mweb_validate_scalar(N_MINUS_1))  { FAIL(); }  /* n-1 accepted  */

    return true;
}

/* ── Scalar arithmetic mod n ────────────────────────────────────────── */

/*
 * `mweb_scalar_*_mod_n` must accept zero operands AND zero results —
 * this is the discriminator against `secp256k1_ec_seckey_tweak_*`
 * which rejects zero results as invalid seckeys. A zero offset is
 * the unique scalar where Sum(blind) + e_k exactly cancels
 * received_tx_offset, and the plan deliberately allows it.
 */
static bool test_mweb_scalar_arithmetic(void)
{
    static const uint8_t ZERO[32] = {0};
    static const uint8_t ONE[32] = {
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,
    };
    /* n-1 */
    static const uint8_t N_MINUS_1[32] = {
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,
        0xBA,0xAE,0xDC,0xE6,0xAF,0x48,0xA0,0x3B,
        0xBF,0xD2,0x5E,0x8C,0xD0,0x36,0x41,0x40,
    };

    uint8_t out[32];

    /* add(a, 0) = a */
    if (!mweb_scalar_add_mod_n(N_MINUS_1, ZERO, out)) { FAIL(); }
    if (memcmp(out, N_MINUS_1, 32) != 0) { FAIL(); }

    /* add(n-1, 1) = 0  (the load-bearing zero-result case) */
    if (!mweb_scalar_add_mod_n(N_MINUS_1, ONE, out)) { FAIL(); }
    if (memcmp(out, ZERO, 32) != 0) { FAIL(); }

    /* sub(a, a) = 0 */
    if (!mweb_scalar_sub_mod_n(N_MINUS_1, N_MINUS_1, out)) { FAIL(); }
    if (memcmp(out, ZERO, 32) != 0) { FAIL(); }

    /* sub(0, 1) = n-1 */
    if (!mweb_scalar_sub_mod_n(ZERO, ONE, out)) { FAIL(); }
    if (memcmp(out, N_MINUS_1, 32) != 0) { FAIL(); }

    /* neg(0) = 0 */
    if (!mweb_scalar_neg_mod_n(ZERO, out)) { FAIL(); }
    if (memcmp(out, ZERO, 32) != 0) { FAIL(); }

    /* neg(1) = n-1 */
    if (!mweb_scalar_neg_mod_n(ONE, out)) { FAIL(); }
    if (memcmp(out, N_MINUS_1, 32) != 0) { FAIL(); }

    /* neg(n-1) = 1 */
    if (!mweb_scalar_neg_mod_n(N_MINUS_1, out)) { FAIL(); }
    if (memcmp(out, ONE, 32) != 0) { FAIL(); }

    return true;
}

/* ── Two-stage input signing invariants ─────────────────────────────── */

/*
 * After Stage A (`mweb_derive_input_state`) the cached state MUST
 * satisfy `stealth_tweak + osk ≡ ephemeral (mod n)`. The kernel signer
 * relies on this equation when folding `stealth_tweak` into
 * `O_s_final` before Stage B emits the signature that reveals
 * `sig_key = osk*key_hash + ephemeral`.
 *
 * Also verifies Stage B determinism: running `sign_input_from_state`
 * twice against the same cached state produces the same 64-byte
 * signature — proves Stage B reuses the cached `ephemeral` and does
 * not draw fresh entropy at emission time.
 */
static bool test_mweb_two_stage_invariant(void)
{
    const secp256k1_context* ctx = wally_get_secp_context();
    if (!ctx) { FAIL(); }

    /* Build a synthetic MWEB output for address_index=0. Shared setup
     * lives in test_mweb_sign_properties; we inline a trimmed copy
     * here to keep this test standalone. */
    uint8_t mi_buf[36] = {0};
    memcpy(mi_buf + 4, MWEB_TEST_SCAN_KEY, 32);
    uint8_t m_i[32];
    mweb_hashed(MWEB_TAG_ADDRESS, mi_buf, 36, m_i);

    uint8_t spend_pub[EC_PUBLIC_KEY_LEN], mi_pub[EC_PUBLIC_KEY_LEN];
    if (wally_ec_public_key_from_private_key(MWEB_TEST_SPEND_KEY, 32,
            spend_pub, sizeof(spend_pub)) != WALLY_OK) { FAIL(); }
    if (wally_ec_public_key_from_private_key(m_i, 32,
            mi_pub, sizeof(mi_pub)) != WALLY_OK) { FAIL(); }

    secp256k1_pubkey sp_pk, mi_pk, Bi_pk;
    if (!secp256k1_ec_pubkey_parse(ctx, &sp_pk, spend_pub, 33)) { FAIL(); }
    if (!secp256k1_ec_pubkey_parse(ctx, &mi_pk, mi_pub, 33)) { FAIL(); }
    const secp256k1_pubkey* pts[2] = { &sp_pk, &mi_pk };
    if (!secp256k1_ec_pubkey_combine(ctx, &Bi_pk, pts, 2)) { FAIL(); }

    static const uint8_t SENDER_KEY[32] = {
        0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,
        0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff,0x00,
        0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
        0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10,
    };

    secp256k1_pubkey Ke_pk = Bi_pk;
    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &Ke_pk, SENDER_KEY)) { FAIL(); }
    uint8_t kex[33];
    size_t ke_len = 33;
    secp256k1_ec_pubkey_serialize(ctx, kex, &ke_len, &Ke_pk, SECP256K1_EC_COMPRESSED);

    secp256k1_pubkey kex_parsed;
    if (!secp256k1_ec_pubkey_parse(ctx, &kex_parsed, kex, 33)) { FAIL(); }
    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &kex_parsed, MWEB_TEST_SCAN_KEY)) { FAIL(); }
    uint8_t ecdh_bytes[33];
    size_t ecdh_len = 33;
    secp256k1_ec_pubkey_serialize(ctx, ecdh_bytes, &ecdh_len, &kex_parsed, SECP256K1_EC_COMPRESSED);
    uint8_t ss[32];
    mweb_hashed(MWEB_TAG_DERIVE, ecdh_bytes, 33, ss);

    uint8_t okh[32];
    mweb_hashed(MWEB_TAG_OUTKEY, ss, 32, okh);
    secp256k1_pubkey Ko_pk = Bi_pk;
    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &Ko_pk, okh)) { FAIL(); }
    uint8_t Ko[33];
    size_t ko_len = 33;
    secp256k1_ec_pubkey_serialize(ctx, Ko, &ko_len, &Ko_pk, SECP256K1_EC_COMPRESSED);

    uint8_t oid[32];
    mweb_hashed(MWEB_TAG_TAG, Ko, 33, oid);

    /* Stage A → state with live TRNG ephemeral. */
    mweb_input_state_t state;
    if (mweb_derive_input_state(MWEB_TEST_SCAN_KEY, MWEB_TEST_SPEND_KEY, 0,
            MWEB_INPUT_STEALTH_KEY_BIT,
            oid, Ko, 2500000, kex, &state) != MWEB_OK) { FAIL(); }

    /* Invariant: stealth_tweak + osk ≡ ephemeral (mod n).
     *
     * Keeps O_s_final (computed from Sum(stealth_tweak) before any
     * signature is emitted) consistent with the randomizer the
     * later signature reveals. Reimplemented via `mweb_scalar_add_mod_n`
     * rather than `secp256k1_ec_seckey_tweak_add` because the latter
     * rejects zero operands / zero results. */
    uint8_t reconstructed_ephemeral[32];
    if (!mweb_scalar_add_mod_n(state.stealth_tweak, state.osk,
                               reconstructed_ephemeral)) { FAIL(); }
    if (memcmp(reconstructed_ephemeral, state.ephemeral, 32) != 0) { FAIL(); }

    /* Stage B determinism: two invocations against the same state must
     * produce byte-identical signatures. A fresh get_random() call
     * inside Stage B would break this, and would also desynchronise
     * the S4c-committed tweak from the S6-emitted randomizer. */
    uint8_t sig1[64], sig2[64];
    if (mweb_sign_input_from_state(&state, NULL, 0, sig1) != MWEB_OK) { FAIL(); }
    if (mweb_sign_input_from_state(&state, NULL, 0, sig2) != MWEB_OK) { FAIL(); }
    if (memcmp(sig1, sig2, 64) != 0) { FAIL(); }

    /* Sanity: signature is non-zero (the Schnorr primitive actually ran). */
    uint8_t zero_sig[64] = {0};
    if (memcmp(sig1, zero_sig, 64) == 0) { FAIL(); }

    /* Sanity: state.input_pubkey is a valid compressed pubkey. */
    if (state.input_pubkey[0] != 0x02 && state.input_pubkey[0] != 0x03) { FAIL(); }

    /* Extra_data path: Stage B with non-empty extra_data produces a
     * different signature than the NULL case, exercising the
     * MWEB_INPUT_EXTRA_DATA_BIT branch inside msg_hash. */
    const uint8_t extra[] = { 0xde, 0xad, 0xbe, 0xef };
    mweb_input_state_t state_ed = state;
    state_ed.features |= MWEB_INPUT_EXTRA_DATA_BIT;
    uint8_t sig_ed[64];
    if (mweb_sign_input_from_state(&state_ed, extra, sizeof(extra), sig_ed)
        != MWEB_OK) { FAIL(); }
    if (memcmp(sig_ed, sig1, 64) == 0) { FAIL(); }

    return true;
}

/* ── Session-level boot-time tests ───────────────────────────────────── */

/*
 * These exercise mweb_session_begin / commit / abort against kernel-
 * only PSBTs (no MWEB inputs, no MWEB outputs). They don't depend on
 * wallet state — the fingerprint check in session_begin is skipped when
 * there are no MWEB inputs — so they safely run at boot or from
 * debug_selfcheck_mweb even on a fresh, uninitialised device.
 *
 * Full coverage of owned-input signing and output recipient-binding
 * requires mocked wallet keys and a full producer-side fixture; those
 * paths live in the native test suite (test_mweb_atomic_sign.c) and in
 * the host-driven Python end-to-end flow.
 */

#define MWEB_TEST_FEE_BIT_LOCAL     0x01
#define MWEB_TEST_PEGIN_BIT_LOCAL   0x02
#define MWEB_TEST_PEGOUT_BIT_LOCAL  0x04

static bool test_mweb_session_null_guards(void)
{
    /* Query helpers on NULL sessions must not crash and must return
     * neutral values — mirrors the native coverage but runs against
     * the actual firmware objects. */
    if (mweb_session_pegout_count(NULL)     != 0)                 { FAIL(); }
    if (mweb_session_has_pegin(NULL))                             { FAIL(); }
    if (mweb_session_pegin_amount(NULL)     != 0)                 { FAIL(); }
    if (mweb_session_total_fee(NULL)        != 0)                 { FAIL(); }
    if (mweb_session_num_mweb_outputs(NULL) != 0)                 { FAIL(); }
    if (mweb_session_num_mweb_inputs(NULL)  != 0)                 { FAIL(); }

    uint64_t v = 0;
    if (mweb_session_get_output_value(NULL, 0, &v) != MWEB_ERR_INTERNAL) { FAIL(); }

    uint64_t amt = 0;
    const uint8_t *scr = NULL;
    size_t slen = 0, kidx = 0;
    if (mweb_session_get_pegout(NULL, 0, &amt, &scr, &slen, &kidx)
            != MWEB_ERR_INTERNAL) { FAIL(); }

    /* Abort / mark on NULL sessions are no-ops. */
    mweb_session_abort(NULL, NULL);
    mweb_session_mark_pegout_confirmed(NULL, 0);

    /* begin with NULL psbt surfaces INTERNAL and must clear *out_session. */
    mweb_session_t *s = (void *)0xdeadbeef;
    if (mweb_session_begin(NULL, (uint8_t)NETWORK_LITECOIN, &s)
            != MWEB_ERR_INTERNAL) { FAIL(); }
    if (s != NULL) { FAIL(); }

    return true;
}

/* Build a PSBT with a stack-owned kernel populated by `prepare`, run
 * `fn(psbt, kernel)` against it, then tear down. Handles the kernel-
 * borrow bookkeeping so libwally doesn't try to free stack memory. */
static bool with_kernel_psbt(
    void (*prepare)(struct wally_psbt_kernel *k),
    bool (*fn)(struct wally_psbt *psbt, struct wally_psbt_kernel *k))
{
    struct wally_psbt *psbt = NULL;
    if (wally_psbt_init_alloc(2, 0, 0, 0, 0, &psbt) != WALLY_OK || !psbt) {
        return false;
    }
    struct wally_psbt_kernel kernel;
    memset(&kernel, 0, sizeof(kernel));
    prepare(&kernel);
    psbt->mweb_kernels = &kernel;
    psbt->num_mweb_kernels = 1;
    psbt->mweb_kernels_allocation_len = 0;

    bool ok = fn(psbt, &kernel);

    psbt->mweb_kernels = NULL;
    psbt->num_mweb_kernels = 0;
    wally_map_clear(&kernel.pegouts);
    wally_map_clear(&kernel.unknowns);
    wally_psbt_free(psbt);
    return ok;
}

/* Standard→MWEB kernel-only shape: 0 inputs + 0 outputs + fee-only
 * kernel with balanced u64 (fee = 0). session_begin accepts;
 * session_commit writes excess + signature + offsets. */
static void prep_feezero_only(struct wally_psbt_kernel *k)
{
    k->has_fee = 1;      k->fee = 0;
    k->has_features = 1; k->features = MWEB_TEST_FEE_BIT_LOCAL;
}

static bool run_standard_to_mweb_ok(struct wally_psbt *psbt, struct wally_psbt_kernel *k)
{
    mweb_session_t *s = NULL;
    if (mweb_session_begin(psbt, (uint8_t)NETWORK_LITECOIN, &s) != MWEB_OK
        || !s) { return false; }
    if (mweb_session_commit(s, psbt) != MWEB_OK) { return false; }
    if (!k->has_excess_commitment || !k->has_signature) { return false; }
    if (!psbt->has_mweb_tx_offset || !psbt->has_mweb_stealth_offset) { return false; }
    if (k->excess_commitment[0] != 0x08 && k->excess_commitment[0] != 0x09) {
        return false;
    }
    uint8_t zero_sig[64] = {0};
    if (memcmp(k->signature, zero_sig, 64) == 0) { return false; }
    return true;
}

static bool test_mweb_session_standard_to_mweb_ok(void)
{
    if (!with_kernel_psbt(prep_feezero_only, run_standard_to_mweb_ok)) { FAIL(); }
    return true;
}

/* Rollback: seed every PSBT mutable field with non-zero bytes, force
 * BALANCE_FAIL via fee out-of-range, confirm post-abort snapshot is
 * byte-identical to pre-begin. */
static void prep_fee_out_of_range_local(struct wally_psbt_kernel *k)
{
    /* LTC supply cap + 1 litoshi → MoneyRange reject. */
    k->has_fee = 1;
    k->fee = (uint64_t)84000000 * (uint64_t)100000000 + 1;
    k->has_features = 1;
    k->features = MWEB_TEST_FEE_BIT_LOCAL;
}

typedef struct {
    uint32_t has_tx_offset;          uint8_t tx_offset[32];
    uint32_t has_stealth_offset;     uint8_t stealth_offset[32];
    uint32_t kernel_has_excess;      uint8_t kernel_excess[33];
    uint32_t kernel_has_stealth_ex;  uint8_t kernel_stealth_ex[33];
    uint32_t kernel_has_signature;   uint8_t kernel_signature[64];
} session_snapshot_t;

static void snapshot_session_state(const struct wally_psbt *psbt,
                                    const struct wally_psbt_kernel *k,
                                    session_snapshot_t *s)
{
    s->has_tx_offset = psbt->has_mweb_tx_offset;
    memcpy(s->tx_offset, psbt->mweb_tx_offset, 32);
    s->has_stealth_offset = psbt->has_mweb_stealth_offset;
    memcpy(s->stealth_offset, psbt->mweb_stealth_offset, 32);
    s->kernel_has_excess = k->has_excess_commitment;
    memcpy(s->kernel_excess, k->excess_commitment, 33);
    s->kernel_has_stealth_ex = k->has_stealth_excess;
    memcpy(s->kernel_stealth_ex, k->stealth_excess, 33);
    s->kernel_has_signature = k->has_signature;
    memcpy(s->kernel_signature, k->signature, 64);
}

static bool session_snapshots_equal(const session_snapshot_t *a,
                                     const session_snapshot_t *b)
{
    return a->has_tx_offset == b->has_tx_offset
        && memcmp(a->tx_offset, b->tx_offset, 32) == 0
        && a->has_stealth_offset == b->has_stealth_offset
        && memcmp(a->stealth_offset, b->stealth_offset, 32) == 0
        && a->kernel_has_excess == b->kernel_has_excess
        && memcmp(a->kernel_excess, b->kernel_excess, 33) == 0
        && a->kernel_has_stealth_ex == b->kernel_has_stealth_ex
        && memcmp(a->kernel_stealth_ex, b->kernel_stealth_ex, 33) == 0
        && a->kernel_has_signature == b->kernel_has_signature
        && memcmp(a->kernel_signature, b->kernel_signature, 64) == 0;
}

static bool run_rollback_on_reject(struct wally_psbt *psbt, struct wally_psbt_kernel *k)
{
    /* Seed with non-zero so "still zero" can't be a vacuous pass. */
    psbt->has_mweb_tx_offset = 1;
    memset(psbt->mweb_tx_offset, 0xA5, 32);
    psbt->has_mweb_stealth_offset = 1;
    memset(psbt->mweb_stealth_offset, 0x5A, 32);
    k->has_excess_commitment = 1;
    memset(k->excess_commitment, 0x11, 33);
    k->has_signature = 1;
    memset(k->signature, 0x22, 64);

    session_snapshot_t pre, post;
    snapshot_session_state(psbt, k, &pre);

    mweb_session_t *s = NULL;
    const mweb_err_t err = mweb_session_begin(psbt, (uint8_t)NETWORK_LITECOIN, &s);

    snapshot_session_state(psbt, k, &post);

    if (err != MWEB_ERR_BALANCE_FAIL) { return false; }
    if (s != NULL) { return false; }
    return session_snapshots_equal(&pre, &post);
}

static bool test_mweb_session_rollback_on_reject(void)
{
    if (!with_kernel_psbt(prep_fee_out_of_range_local, run_rollback_on_reject)) {
        FAIL();
    }
    return true;
}

/* Pegout confirmation flow. pegouts[0] = {P2WPKH, 500_000}, pegin
 * covers fee + pegout. Commit without marking rejects with
 * PEGOUTS_NOT_DISPLAYED; marking then committing succeeds. */
static uint8_t g_pegout_val[32];
static const uint8_t P2WPKH_SCRIPT[22] = {
    0x00, 0x14,
    0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11,
    0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
    0xaa, 0xbb, 0xcc, 0xdd,
};

static void prep_pegout_balanced(struct wally_psbt_kernel *k)
{
    const uint64_t fee = 1000, pegout = 500000;
    /* 8B LE amount || varint(script_len) || script */
    for (int i = 0; i < 8; i++) g_pegout_val[i] = (uint8_t)(pegout >> (i * 8));
    g_pegout_val[8] = (uint8_t)sizeof(P2WPKH_SCRIPT);
    memcpy(g_pegout_val + 9, P2WPKH_SCRIPT, sizeof(P2WPKH_SCRIPT));
    const size_t val_len = 8 + 1 + sizeof(P2WPKH_SCRIPT);
    wally_map_init(1, NULL, &k->pegouts);
    wally_map_add_integer(&k->pegouts, 0, g_pegout_val, val_len);
    k->has_fee = 1;           k->fee = fee;
    k->has_pegin_amount = 1;  k->pegin_amount = fee + pegout;
    k->has_features = 1;
    k->features = MWEB_TEST_FEE_BIT_LOCAL | MWEB_TEST_PEGIN_BIT_LOCAL
                | MWEB_TEST_PEGOUT_BIT_LOCAL;
}

static bool run_pegout_skipped(struct wally_psbt *psbt, struct wally_psbt_kernel *k)
{
    (void)k;
    session_snapshot_t pre, post;
    snapshot_session_state(psbt, k, &pre);

    mweb_session_t *s = NULL;
    if (mweb_session_begin(psbt, (uint8_t)NETWORK_LITECOIN, &s) != MWEB_OK
        || !s) { return false; }
    if (mweb_session_pegout_count(s) != 1) { return false; }
    /* Commit without mark → reject + rollback. */
    if (mweb_session_commit(s, psbt) != MWEB_ERR_PEGOUTS_NOT_DISPLAYED) { return false; }

    snapshot_session_state(psbt, k, &post);
    return session_snapshots_equal(&pre, &post);
}

static bool test_mweb_session_pegout_skipped_rejects(void)
{
    if (!with_kernel_psbt(prep_pegout_balanced, run_pegout_skipped)) { FAIL(); }
    return true;
}

static bool run_pegout_marked_ok(struct wally_psbt *psbt, struct wally_psbt_kernel *k)
{
    mweb_session_t *s = NULL;
    if (mweb_session_begin(psbt, (uint8_t)NETWORK_LITECOIN, &s) != MWEB_OK
        || !s) { return false; }
    mweb_session_mark_pegout_confirmed(s, 0);
    if (mweb_session_commit(s, psbt) != MWEB_OK) { return false; }
    if (!k->has_excess_commitment || !k->has_signature) { return false; }
    if (!psbt->has_mweb_tx_offset || !psbt->has_mweb_stealth_offset) { return false; }
    return true;
}

static bool test_mweb_session_pegout_marked_ok(void)
{
    if (!with_kernel_psbt(prep_pegout_balanced, run_pegout_marked_ok)) { FAIL(); }
    return true;
}

#undef MWEB_TEST_FEE_BIT_LOCAL
#undef MWEB_TEST_PEGIN_BIT_LOCAL
#undef MWEB_TEST_PEGOUT_BIT_LOCAL

/* ── Top-level entry points ──────────────────────────────────────────── */

/* mweb_test_result_t, MWEB_SELFCHECK_MAX_TESTS, and the prototypes live
 * in mweb_selfcheck.h. */

size_t test_mweb_crypto_run_all(mweb_test_result_t *out, size_t max)
{
    size_t n = 0;

    #define RUN(label, fn)                                                \
        do {                                                              \
            if (n < max) {                                                \
                const TickType_t _start = xTaskGetTickCount();            \
                const bool _ok = fn();                                    \
                const TickType_t _end = xTaskGetTickCount();              \
                out[n].name = label;                                      \
                out[n].passed = _ok;                                      \
                out[n].elapsed_ms                                         \
                    = (uint32_t)((_end - _start) * portTICK_PERIOD_MS);   \
                n++;                                                      \
            }                                                             \
        } while (0)

    RUN("hashes",                    test_mweb_hashes);
    RUN("schnorr_vectors",           test_mweb_schnorr_vectors);
    RUN("blind_vectors",             test_mweb_blind_vectors);
    RUN("spend_pubkey",              test_mweb_spend_pubkey);
    RUN("addresses",                 test_mweb_addresses);
    RUN("watch_only_consistency",    test_mweb_watch_only_consistency);
    RUN("sign_properties",           test_mweb_sign_properties);
    RUN("two_stage_invariant",       test_mweb_two_stage_invariant);
    RUN("kernel_hash",               test_mweb_kernel_hash);
    RUN("kernel_sign_simple",        test_mweb_kernel_sign_simple);
    RUN("kernel_sign_stealth",       test_mweb_kernel_sign_stealth);
    RUN("kernel_sign_errors",        test_mweb_kernel_sign_errors);
    RUN("kernel_fee_zero_ok",        test_mweb_kernel_fee_zero_ok);
    RUN("zero_offsets_accepted",     test_mweb_zero_offsets_accepted);
    RUN("scalar_validate",           test_mweb_scalar_validate);
    RUN("scalar_arithmetic",         test_mweb_scalar_arithmetic);
    RUN("derive_output_happy",       test_mweb_derive_output_happy);
    RUN("derive_output_mismatch",    test_mweb_derive_output_mismatch);
    RUN("session_null_guards",       test_mweb_session_null_guards);
    RUN("session_standard_to_mweb",  test_mweb_session_standard_to_mweb_ok);
    RUN("session_rollback_reject",   test_mweb_session_rollback_on_reject);
    RUN("session_pegout_skipped",    test_mweb_session_pegout_skipped_rejects);
    RUN("session_pegout_marked",     test_mweb_session_pegout_marked_ok);

    #undef RUN
    return n;
}

/*
 * Boot-time wrapper for debug_selfcheck(). Preserves the historical
 * "return false on first failure" contract so the main selfcheck path
 * aborts early on any regression. debug_selfcheck_mweb uses
 * test_mweb_crypto_run_all() directly for per-test visibility.
 */
bool test_mweb_crypto(void)
{
    static mweb_test_result_t scratch[MWEB_SELFCHECK_MAX_TESTS];
    const size_t n = test_mweb_crypto_run_all(scratch, MWEB_SELFCHECK_MAX_TESTS);
    for (size_t i = 0; i < n; i++) {
        if (!scratch[i].passed) {
            return false;
        }
    }
    return true;
}

/*
 * RPC callback used by debug_selfcheck_mweb in dashboard.c.
 * Serialises the results array as a CBOR map so Python callers can
 * iterate per-test. The reply-context struct lives in the shared
 * header so dashboard.c and this TU agree on layout.
 */
void mweb_selfcheck_reply_cb(const void *ctx, CborEncoder *container)
{
    const struct mweb_selfcheck_reply_ctx *r = ctx;
    CborError e;

    CborEncoder root;
    e = cbor_encoder_create_map(container, &root, 2);
    JADE_ASSERT(e == CborNoError);

    /* "elapsed_ms": wall-clock for the full sweep. */
    e = cbor_encode_text_stringz(&root, "elapsed_ms");
    JADE_ASSERT(e == CborNoError);
    e = cbor_encode_uint(&root, r->elapsed_time_ms);
    JADE_ASSERT(e == CborNoError);

    /* "results": array of {"name", "passed", "elapsed_ms"} maps. */
    e = cbor_encode_text_stringz(&root, "results");
    JADE_ASSERT(e == CborNoError);

    CborEncoder arr;
    e = cbor_encoder_create_array(&root, &arr, r->n_results);
    JADE_ASSERT(e == CborNoError);

    for (size_t i = 0; i < r->n_results; i++) {
        CborEncoder entry;
        e = cbor_encoder_create_map(&arr, &entry, 3);
        JADE_ASSERT(e == CborNoError);

        e = cbor_encode_text_stringz(&entry, "name");
        JADE_ASSERT(e == CborNoError);
        e = cbor_encode_text_stringz(&entry,
            r->results[i].name ? r->results[i].name : "(null)");
        JADE_ASSERT(e == CborNoError);

        e = cbor_encode_text_stringz(&entry, "passed");
        JADE_ASSERT(e == CborNoError);
        e = cbor_encode_boolean(&entry, r->results[i].passed);
        JADE_ASSERT(e == CborNoError);

        e = cbor_encode_text_stringz(&entry, "elapsed_ms");
        JADE_ASSERT(e == CborNoError);
        e = cbor_encode_uint(&entry, r->results[i].elapsed_ms);
        JADE_ASSERT(e == CborNoError);

        e = cbor_encoder_close_container(&arr, &entry);
        JADE_ASSERT(e == CborNoError);
    }

    e = cbor_encoder_close_container(&root, &arr);
    JADE_ASSERT(e == CborNoError);
    e = cbor_encoder_close_container(container, &root);
    JADE_ASSERT(e == CborNoError);
}

#undef FAIL

#endif /* AMALGAMATED_BUILD */
