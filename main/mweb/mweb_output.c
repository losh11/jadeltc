#include "mweb_output.h"
#include "mweb_blind.h"
#include "mweb_hash.h"
#include "mweb_kernel.h"  /* mweb_validate_scalar */

#include <string.h>

#include <secp256k1.h>
#include <wally_core.h>

/*
 * Per-output recipient-binding derivation.
 *
 * Tag bytes are the ASCII constants from mweb_hash.h; the BLAKE3 primitive
 * prepends exactly one untagged byte before the data.
 */
mweb_err_t mweb_derive_output(
    const uint8_t sender_key[32],
    const uint8_t scan_pub_A[33],
    const uint8_t spend_pub_B[33],
    uint64_t value,
    struct mweb_derived_output *out)
{
    if (!sender_key || !scan_pub_A || !spend_pub_B || !out) {
        return MWEB_ERR_INTERNAL;
    }

    /* Reject zero / >= n before any EC op consumes the scalar. */
    if (!mweb_validate_scalar(sender_key)) {
        return MWEB_ERR_INVALID_PRESIGN_SCALAR;
    }

    const secp256k1_context* ctx = wally_get_secp_context();
    if (!ctx) {
        return MWEB_ERR_INTERNAL;
    }

    memset(out, 0, sizeof(*out));

    mweb_err_t err = MWEB_ERR_INTERNAL;

    /* Intermediate scalars / buffers — all wiped in cleanup. */
    uint8_t n_hash[32];        /* Hashed('N', sender_key) */
    uint8_t n_16[16];          /* 128-bit secret nonce, BE-interpreted */
    uint8_t s_input[33 + 33 + 8 + 16]; /* A || B || LE64(v) || n_16 */
    uint8_t s[32];             /* unique sending scalar */
    uint8_t sA[33];            /* s * A (compressed) */
    uint8_t t[32];             /* shared secret Hashed('D', sA) */
    uint8_t o_scalar[32];      /* Hashed('O', t) */
    uint8_t y_hash[32];        /* Hashed('Y', t) */
    uint8_t x_hash[32];        /* Hashed('X', t) */
    uint8_t nonce_mask_16[16]; /* x_hash[0..16], BE-interpreted */
    uint8_t mask_blind[32];    /* Hashed('B', t) — the r_pre blind */
    uint8_t tag_hash[32];      /* Hashed('T', sA) */

    /* Step 2: n_16 = Hashed('N', sender_key)[0..16] */
    mweb_hashed(MWEB_TAG_NONCE, sender_key, 32, n_hash);
    memcpy(n_16, n_hash, 16);

    /* Step 3: s = Hashed('S', A_33 || B_33 || LE64(v) || n_16) */
    memcpy(s_input, scan_pub_A, 33);
    memcpy(s_input + 33, spend_pub_B, 33);
    for (int i = 0; i < 8; i++) {
        s_input[66 + i] = (uint8_t)(value >> (i * 8));
    }
    memcpy(s_input + 74, n_16, 16);
    mweb_hashed(MWEB_TAG_SENDKEY, s_input, sizeof(s_input), s);

    /* Step 4: sA = s * A (33B compressed).
     * secp256k1_ec_pubkey_tweak_mul rejects s == 0 and s >= n; for a
     * well-formed sender_key this only hits with negligible probability. */
    {
        secp256k1_pubkey A_pk;
        if (!secp256k1_ec_pubkey_parse(ctx, &A_pk, scan_pub_A, 33)) {
            goto cleanup;
        }
        if (!secp256k1_ec_pubkey_tweak_mul(ctx, &A_pk, s)) {
            goto cleanup;
        }
        size_t len = 33;
        secp256k1_ec_pubkey_serialize(ctx, sA, &len, &A_pk,
                                      SECP256K1_EC_COMPRESSED);
    }

    /* Step 5: t = Hashed('D', sA). */
    mweb_hashed(MWEB_TAG_DERIVE, sA, 33, t);

    /* Step 6: K_o = Hashed('O', t) * B. */
    mweb_hashed(MWEB_TAG_OUTKEY, t, 32, o_scalar);
    {
        secp256k1_pubkey B_pk;
        if (!secp256k1_ec_pubkey_parse(ctx, &B_pk, spend_pub_B, 33)) {
            goto cleanup;
        }
        if (!secp256k1_ec_pubkey_tweak_mul(ctx, &B_pk, o_scalar)) {
            goto cleanup;
        }
        size_t len = 33;
        secp256k1_ec_pubkey_serialize(ctx, out->output_pubkey, &len, &B_pk,
                                      SECP256K1_EC_COMPRESSED);
    }

    /* Step 7: K_e = s * B (NOT sender_key * A). */
    {
        secp256k1_pubkey B_pk;
        if (!secp256k1_ec_pubkey_parse(ctx, &B_pk, spend_pub_B, 33)) {
            goto cleanup;
        }
        if (!secp256k1_ec_pubkey_tweak_mul(ctx, &B_pk, s)) {
            goto cleanup;
        }
        size_t len = 33;
        secp256k1_ec_pubkey_serialize(ctx, out->key_exchange_pubkey, &len,
                                      &B_pk, SECP256K1_EC_COMPRESSED);
    }

    /* Step 8: derive the OutputMask tuple. All three hashes consume
     * the same shared secret t. */
    mweb_hashed(MWEB_TAG_BLIND,     t, 32, mask_blind);
    mweb_hashed(MWEB_TAG_VALUEMASK, t, 32, y_hash);
    mweb_hashed(MWEB_TAG_NONCEMASK, t, 32, x_hash);
    memcpy(nonce_mask_16, x_hash, 16);

    /* Step 9: r_out = BlindSwitch(mask_blind, v). */
    if (!mweb_blind_switch(mask_blind, value, out->blind)) {
        goto cleanup;
    }

    /* Step 10: masked_value = v XOR LE64(Hashed('Y', t)[0..8]). */
    {
        uint64_t value_mask = 0;
        for (int i = 0; i < 8; i++) {
            value_mask |= ((uint64_t)y_hash[i]) << (i * 8);
        }
        out->masked_value = value ^ value_mask;
    }

    /* Step 11: masked_nonce[16] = n_16 XOR nonce_mask_16.
     * Both operands are 16-byte big-endian buffers, so byte-wise XOR
     * produces the BE representation of the numeric XOR. */
    for (int i = 0; i < 16; i++) {
        out->masked_nonce[i] = n_16[i] ^ nonce_mask_16[i];
    }

    /* Step 12: C_out = Pedersen(blind, v) — 0x08/0x09 prefix. */
    if (!mweb_pedersen_commit(out->blind, value, out->commit)) {
        goto cleanup;
    }

    /* Step 13: K_s = sender_key * G. */
    {
        secp256k1_pubkey Ks_pk;
        if (!secp256k1_ec_pubkey_create(ctx, &Ks_pk, sender_key)) {
            goto cleanup;
        }
        size_t len = 33;
        secp256k1_ec_pubkey_serialize(ctx, out->sender_pubkey, &len, &Ks_pk,
                                      SECP256K1_EC_COMPRESSED);
    }

    /* Step 14: view_tag = Hashed('T', sA)[0]  (NOT Hashed('T', t)[0]). */
    mweb_hashed(MWEB_TAG_TAG, sA, 33, tag_hash);
    out->view_tag = tag_hash[0];

    err = MWEB_OK;

cleanup:
    wally_bzero(n_hash,        sizeof(n_hash));
    wally_bzero(n_16,          sizeof(n_16));
    wally_bzero(s_input,       sizeof(s_input));
    wally_bzero(s,             sizeof(s));
    wally_bzero(sA,            sizeof(sA));
    wally_bzero(t,             sizeof(t));
    wally_bzero(o_scalar,      sizeof(o_scalar));
    wally_bzero(y_hash,        sizeof(y_hash));
    wally_bzero(x_hash,        sizeof(x_hash));
    wally_bzero(nonce_mask_16, sizeof(nonce_mask_16));
    wally_bzero(mask_blind,    sizeof(mask_blind));
    wally_bzero(tag_hash,      sizeof(tag_hash));
    if (err != MWEB_OK) {
        wally_bzero(out, sizeof(*out));
    }
    return err;
}
