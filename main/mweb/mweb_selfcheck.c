/*
 * MWEB on-device self-check tests.
 *
 * Called from selfcheck.c as part of debug_selfcheck().
 * Uses the selfcheck FAIL() convention: returns false on first failure.
 *
 * Tests pure crypto primitives with fixed vectors from ltcsuite, plus
 * property-based signing tests (can't mock the hardware TRNG on device,
 * so byte-for-byte signature vectors are only checked in native tests).
 */
#include "mweb_hash.h"
#include "mweb_schnorr.h"
#include "mweb_blind.h"
#include "mweb_sign.h"
#include "mweb_keychain.h"
#include "mweb_kernel.h"

#include <string.h>
#include <secp256k1.h>
#include <wally_core.h>
#include <wally_crypto.h>

/* Use the FAIL() macro from selfcheck.c (included via amalgamated build
 * or defined in the including file). */
#ifndef FAIL
#define FAIL()                                                                 \
    do {                                                                       \
        return false;                                                          \
    } while (false)
#endif

/* ── Keys from ltcsuite waddrmgr/mweb_compat_test.go ────────────────── */

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

    /* Test 1: Signing with correct params succeeds */
    mweb_sign_result_t result;
    if (!mweb_sign_input(MWEB_TEST_SCAN_KEY, MWEB_TEST_SPEND_KEY, 0,
                         MWEB_INPUT_STEALTH_KEY_BIT,
                         oid, Ko, 1000000,
                         NULL, 0, kex, NULL, &result)) { FAIL(); }

    /* Commitment must have 0x08 or 0x09 prefix */
    if (result.output_commit[0] != 0x08 && result.output_commit[0] != 0x09) { FAIL(); }

    /* Signature must be non-zero */
    uint8_t zero_sig[64] = {0};
    if (memcmp(result.signature, zero_sig, 64) == 0) { FAIL(); }

    /* input_pubkey must be a valid 33-byte compressed pubkey */
    if (result.input_pubkey[0] != 0x02 && result.input_pubkey[0] != 0x03) { FAIL(); }

    /* Test 2: Wrong address_index must be rejected */
    if (mweb_sign_input(MWEB_TEST_SCAN_KEY, MWEB_TEST_SPEND_KEY, 1, /* wrong index */
                        MWEB_INPUT_STEALTH_KEY_BIT,
                        oid, Ko, 1000000,
                        NULL, 0, kex, NULL, &result)) {
        FAIL(); /* should have been rejected */
    }

    /* Test 3: Missing STEALTH_KEY_BIT must be rejected */
    if (mweb_sign_input(MWEB_TEST_SCAN_KEY, MWEB_TEST_SPEND_KEY, 0,
                        0x00, /* no stealth bit */
                        oid, Ko, 1000000,
                        NULL, 0, kex, NULL, &result)) {
        FAIL(); /* should have been rejected */
    }

    /* Test 4: Shared secret path must produce same commitment as kex path */
    mweb_sign_result_t result_ss;
    if (!mweb_sign_input(MWEB_TEST_SCAN_KEY, MWEB_TEST_SPEND_KEY, 0,
                         MWEB_INPUT_STEALTH_KEY_BIT,
                         oid, Ko, 1000000,
                         NULL, 0, NULL, ss, &result_ss)) { FAIL(); }

    /* Both paths derive the same blind → same commitment */
    if (memcmp(result.output_commit, result_ss.output_commit, 33) != 0) { FAIL(); }

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

/* ── Kernel message hash vector ──────────────────────────────────────── */

static bool test_mweb_kernel_hash(void)
{
    static const uint8_t EXCESS[33] = {
        0x08,
        0xa1,0xa1,0xa1,0xa1,0xa1,0xa1,0xa1,0xa1,
        0xa1,0xa1,0xa1,0xa1,0xa1,0xa1,0xa1,0xa1,
        0xa1,0xa1,0xa1,0xa1,0xa1,0xa1,0xa1,0xa1,
        0xa1,0xa1,0xa1,0xa1,0xa1,0xa1,0xa1,0xa1,
    };
    static const uint8_t EXPECTED[32] = {
        0x1b,0x0e,0xe8,0xf6,0x39,0x43,0x41,0x3d,
        0x8e,0x6d,0x0b,0xe3,0x68,0x40,0xe2,0x25,
        0xf8,0xca,0xa4,0x0d,0x19,0xec,0xd1,0x05,
        0xfb,0x13,0x54,0x26,0x69,0x96,0xb6,0x3c,
    };

    uint8_t hash[32];
    if (!mweb_kernel_sig_hash(MWEB_KERNEL_FEE_BIT, EXCESS,
                              50000, true,
                              0, false,
                              NULL,
                              0, false,
                              NULL, NULL, 0,
                              hash)) {
        FAIL();
    }
    if (memcmp(hash, EXPECTED, 32) != 0) { FAIL(); }

    return true;
}

/* ── Top-level entry point for selfcheck.c ───────────────────────────── */

bool test_mweb_crypto(void)
{
    if (!test_mweb_hashes()) { return false; }
    if (!test_mweb_schnorr_vectors()) { return false; }
    if (!test_mweb_blind_vectors()) { return false; }
    if (!test_mweb_spend_pubkey()) { return false; }
    if (!test_mweb_addresses()) { return false; }
    if (!test_mweb_watch_only_consistency()) { return false; }
    if (!test_mweb_sign_properties()) { return false; }
    if (!test_mweb_kernel_hash()) { return false; }
    return true;
}

#undef FAIL
