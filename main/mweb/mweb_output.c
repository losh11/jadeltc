#include "mweb_output.h"
#include "mweb_blind.h"
#include "mweb_hash.h"
#include "mweb_kernel.h"     /* mweb_validate_scalar, mweb_write_compact_size */
#include "mweb_rangeproof.h" /* mweb_build_rangeproof[_with_nonces] */
#include "mweb_schnorr.h"    /* mweb_sign_output */

#include <stddef.h>
#include <string.h>

#include <blake3.h>
#include <secp256k1.h>
#include <wally_core.h>

/* mweb_built_output's first 8 fields are byte-identical in layout to
 * mweb_derived_output. The build path relies on this to copy the
 * binding section in one shot — per-field offset checks lock the
 * contract so a future same-size reorder still fails to compile. */
_Static_assert(offsetof(struct mweb_built_output, blind)
                   == offsetof(struct mweb_derived_output, blind),
               "mweb_built_output.blind offset must match mweb_derived_output");
_Static_assert(offsetof(struct mweb_built_output, output_pubkey)
                   == offsetof(struct mweb_derived_output, output_pubkey),
               "mweb_built_output.output_pubkey offset mismatch");
_Static_assert(offsetof(struct mweb_built_output, sender_pubkey)
                   == offsetof(struct mweb_derived_output, sender_pubkey),
               "mweb_built_output.sender_pubkey offset mismatch");
_Static_assert(offsetof(struct mweb_built_output, key_exchange_pubkey)
                   == offsetof(struct mweb_derived_output, key_exchange_pubkey),
               "mweb_built_output.key_exchange_pubkey offset mismatch");
_Static_assert(offsetof(struct mweb_built_output, commit)
                   == offsetof(struct mweb_derived_output, commit),
               "mweb_built_output.commit offset mismatch");
_Static_assert(offsetof(struct mweb_built_output, view_tag)
                   == offsetof(struct mweb_derived_output, view_tag),
               "mweb_built_output.view_tag offset mismatch");
_Static_assert(offsetof(struct mweb_built_output, masked_value)
                   == offsetof(struct mweb_derived_output, masked_value),
               "mweb_built_output.masked_value offset mismatch");
_Static_assert(offsetof(struct mweb_built_output, masked_nonce)
                   == offsetof(struct mweb_derived_output, masked_nonce),
               "mweb_built_output.masked_nonce offset mismatch");
_Static_assert(offsetof(struct mweb_built_output, range_proof)
                   == sizeof(struct mweb_derived_output),
               "mweb_built_output prefix size must equal mweb_derived_output");

/* Worst-case serialized MwebOutputMessage:
 *   features(1) + StandardFields(33+1+8+16=58) + ExtraData(9 cs + max bytes)
 * with extra_data capped at MWEB_OUTPUT_MAX_EXTRA_DATA_LEN. */
#define MWEB_OUTPUT_MESSAGE_MAX_LEN \
    (1 + 33 + 1 + 8 + 16 + 9 + MWEB_OUTPUT_MAX_EXTRA_DATA_LEN)

/*
 * 14-step per-output recipient binding derivation shared by the verify
 * path (mweb_derive_output) and the build path
 * (mweb_build_output[_with_nonces]). Caller is responsible for
 * validating sender_key and resolving ctx; this helper assumes both
 * are non-NULL and does not zero `out` itself on failure (callers do).
 *
 * Tag bytes are the ASCII constants from mweb_hash.h; the BLAKE3 primitive
 * prepends exactly one untagged byte before the data.
 */
static mweb_err_t derive_output_binding(
    const secp256k1_context *ctx,
    const uint8_t sender_key[32],
    const uint8_t scan_pub_A[33],
    const uint8_t spend_pub_B[33],
    uint64_t value,
    struct mweb_derived_output *out)
{
    mweb_err_t err = MWEB_ERR_INTERNAL;

    uint8_t n_hash[32];
    uint8_t n_16[16];
    uint8_t s_input[33 + 33 + 8 + 16]; /* A || B || LE64(v) || n_16 */
    uint8_t s[32];
    uint8_t sA[33];
    uint8_t t[32];
    uint8_t o_scalar[32];
    uint8_t y_hash[32];
    uint8_t x_hash[32];
    uint8_t nonce_mask_16[16];
    uint8_t mask_blind[32];
    uint8_t tag_hash[32];

    /* Hoisted out of inner blocks so cleanup can wipe them — secp256k1_pubkey
     * holds the parsed point internally, including A_pk's sA shared-secret
     * and the intermediate B_pk values multiplied by secret scalars. */
    secp256k1_pubkey A_pk;
    secp256k1_pubkey B_pk_Ko;
    secp256k1_pubkey B_pk_Ke;
    secp256k1_pubkey Ks_pk;
    memset(&A_pk,    0, sizeof(A_pk));
    memset(&B_pk_Ko, 0, sizeof(B_pk_Ko));
    memset(&B_pk_Ke, 0, sizeof(B_pk_Ke));
    memset(&Ks_pk,   0, sizeof(Ks_pk));

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

    /* Step 4: sA = s * A. Negligible-probability failure on s==0 or s>=n. */
    if (!secp256k1_ec_pubkey_parse(ctx, &A_pk, scan_pub_A, 33)) {
        goto cleanup;
    }
    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &A_pk, s)) {
        goto cleanup;
    }
    {
        size_t len = 33;
        secp256k1_ec_pubkey_serialize(ctx, sA, &len, &A_pk,
                                      SECP256K1_EC_COMPRESSED);
    }

    /* Step 5: t = Hashed('D', sA). */
    mweb_hashed(MWEB_TAG_DERIVE, sA, 33, t);

    /* Step 6: K_o = Hashed('O', t) * B. */
    mweb_hashed(MWEB_TAG_OUTKEY, t, 32, o_scalar);
    if (!secp256k1_ec_pubkey_parse(ctx, &B_pk_Ko, spend_pub_B, 33)) {
        goto cleanup;
    }
    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &B_pk_Ko, o_scalar)) {
        goto cleanup;
    }
    {
        size_t len = 33;
        secp256k1_ec_pubkey_serialize(ctx, out->output_pubkey, &len, &B_pk_Ko,
                                      SECP256K1_EC_COMPRESSED);
    }

    /* Step 7: K_e = s * B (NOT sender_key * A). */
    if (!secp256k1_ec_pubkey_parse(ctx, &B_pk_Ke, spend_pub_B, 33)) {
        goto cleanup;
    }
    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &B_pk_Ke, s)) {
        goto cleanup;
    }
    {
        size_t len = 33;
        secp256k1_ec_pubkey_serialize(ctx, out->key_exchange_pubkey, &len,
                                      &B_pk_Ke, SECP256K1_EC_COMPRESSED);
    }

    /* Step 8: derive the OutputMask tuple from the shared secret t. */
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

    /* Step 11: masked_nonce = n_16 XOR nonce_mask_16 (16-byte BE XOR). */
    for (int i = 0; i < 16; i++) {
        out->masked_nonce[i] = n_16[i] ^ nonce_mask_16[i];
    }

    /* Step 12: C_out = Pedersen(blind, v) — 0x08/0x09 prefix. */
    if (!mweb_pedersen_commit(out->blind, value, out->commit)) {
        goto cleanup;
    }

    /* Step 13: K_s = sender_key * G. */
    if (!secp256k1_ec_pubkey_create(ctx, &Ks_pk, sender_key)) {
        goto cleanup;
    }
    {
        size_t len = 33;
        secp256k1_ec_pubkey_serialize(ctx, out->sender_pubkey, &len, &Ks_pk,
                                      SECP256K1_EC_COMPRESSED);
    }

    /* Step 14: view_tag = Hashed('T', sA)[0] (NOT Hashed('T', t)[0]). */
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
    wally_bzero(&A_pk,    sizeof(A_pk));     /* held sA shared-secret point */
    wally_bzero(&B_pk_Ko, sizeof(B_pk_Ko));  /* derived via secret o_scalar */
    wally_bzero(&B_pk_Ke, sizeof(B_pk_Ke));  /* derived via secret s */
    wally_bzero(&Ks_pk,   sizeof(Ks_pk));    /* derived via secret sender_key */
    return err;
}

mweb_err_t mweb_derive_output(
    const uint8_t sender_key[32],
    const uint8_t scan_pub_A[33],
    const uint8_t spend_pub_B[33],
    uint64_t value,
    struct mweb_derived_output *out)
{
    if (!out) {
        return MWEB_ERR_INTERNAL;
    }
    /* Zero up front so every failure path leaves `out` cleared, not
     * carrying caller residue. */
    memset(out, 0, sizeof(*out));
    if (!sender_key || !scan_pub_A || !spend_pub_B) {
        return MWEB_ERR_INTERNAL;
    }
    if (!mweb_validate_scalar(sender_key)) {
        return MWEB_ERR_INVALID_SCALAR;
    }
    const secp256k1_context *ctx = wally_get_secp_context();
    if (!ctx) {
        return MWEB_ERR_INTERNAL;
    }

    mweb_err_t err = derive_output_binding(
        ctx, sender_key, scan_pub_A, spend_pub_B, value, out);
    if (err != MWEB_OK) {
        wally_bzero(out, sizeof(*out));
    }
    return err;
}

/*
 * Serialize a MwebOutputMessage per ltcsuite wire/mweboutput.go:write.
 * StandardFields and ExtraData are independently gated on their feature
 * bits; extra_data uses a compact-size length prefix (WriteVarBytes).
 *
 * Caller must size out_buf for the worst case; this function does not
 * range-check (its only caller validates bounds upstream).
 */
static size_t serialize_output_message(
    uint8_t features,
    const uint8_t key_exchange_pubkey[33],
    uint8_t view_tag,
    uint64_t masked_value,
    const uint8_t masked_nonce[16],
    const uint8_t *extra_data, size_t extra_data_len,
    uint8_t *out_buf)
{
    size_t off = 0;
    out_buf[off++] = features;

    if (features & MWEB_OUTPUT_STANDARD_FIELDS_BIT) {
        memcpy(out_buf + off, key_exchange_pubkey, 33);
        off += 33;
        out_buf[off++] = view_tag;
        for (int i = 0; i < 8; i++) {
            out_buf[off++] = (uint8_t)(masked_value >> (i * 8));
        }
        memcpy(out_buf + off, masked_nonce, 16);
        off += 16;
    }

    if (features & MWEB_OUTPUT_EXTRA_DATA_BIT) {
        off += mweb_write_compact_size(out_buf + off, (uint64_t)extra_data_len);
        if (extra_data_len > 0) {
            memcpy(out_buf + off, extra_data, extra_data_len);
            off += extra_data_len;
        }
    }
    return off;
}

/*
 * Shared implementation behind mweb_build_output and
 * mweb_build_output_with_nonces. If bp_nonce / bp_private_nonce are NULL
 * the underlying mweb_build_rangeproof draws TRNG; otherwise the test
 * seam mweb_build_rangeproof_with_nonces consumes the caller's bytes.
 *
 * NOTE: both nonce pointers must have the same NULL-ness. The two
 * callers ensure that contract.
 */
static mweb_err_t build_output_impl(
    const uint8_t sender_key[32],
    const uint8_t scan_pub_A[33],
    const uint8_t spend_pub_B[33],
    uint64_t value,
    uint8_t features,
    const uint8_t *extra_data, size_t extra_data_len,
    const uint8_t *bp_nonce,
    const uint8_t *bp_private_nonce,
    struct mweb_built_output *built)
{
    if (!built) {
        return MWEB_ERR_INTERNAL;
    }
    /* Zero the output buffer up front so EVERY subsequent failure path
     * leaves it cleared — caller-visible bytes never carry stale values
     * from a prior call's residue. */
    memset(built, 0, sizeof(*built));

    if (!sender_key || !scan_pub_A || !spend_pub_B) {
        return MWEB_ERR_INTERNAL;
    }
    if (!mweb_validate_scalar(sender_key)) {
        return MWEB_ERR_INVALID_SCALAR;
    }
    /* extra_data shape contract: bit set ↔ caller intends to emit bytes
     * (zero bytes are legal — yields compact_size(0)); bit clear means
     * no extra_data section, so no bytes may be supplied. */
    if (!(features & MWEB_OUTPUT_EXTRA_DATA_BIT) && extra_data_len > 0) {
        return MWEB_ERR_INTERNAL;
    }
    if (extra_data_len > 0 && extra_data == NULL) {
        return MWEB_ERR_INTERNAL;
    }
    if (extra_data_len > MWEB_OUTPUT_MAX_EXTRA_DATA_LEN) {
        return MWEB_ERR_INTERNAL;
    }

    const secp256k1_context *ctx = wally_get_secp_context();
    if (!ctx) {
        return MWEB_ERR_INTERNAL;
    }

    mweb_err_t err = MWEB_ERR_INTERNAL;
    uint8_t msg_buf[MWEB_OUTPUT_MESSAGE_MAX_LEN];
    size_t msg_len = 0;
    uint8_t msg_hash[32];
    uint8_t rp_hash[32];
    struct mweb_derived_output binding;
    memset(&binding, 0, sizeof(binding));

    err = derive_output_binding(
        ctx, sender_key, scan_pub_A, spend_pub_B, value, &binding);
    if (err != MWEB_OK) {
        goto cleanup;
    }

    /* Copy the binding prefix in one shot — the static_assert at the
     * top of this file pins this struct layout match. */
    memcpy(built, &binding, sizeof(binding));

    msg_len = serialize_output_message(
        features,
        built->key_exchange_pubkey,
        built->view_tag,
        built->masked_value,
        built->masked_nonce,
        extra_data, extra_data_len,
        msg_buf);

    if (bp_nonce) {
        err = mweb_build_rangeproof_with_nonces(
            value, built->blind, bp_nonce, bp_private_nonce,
            msg_buf, msg_len, built->range_proof);
    } else {
        err = mweb_build_rangeproof(
            value, built->blind, msg_buf, msg_len, built->range_proof);
    }
    if (err != MWEB_OK) {
        goto cleanup;
    }

    /* msg_hash = BLAKE3(serialized message), rp_hash = BLAKE3(rangeproof). */
    {
        blake3_hasher h;
        blake3_hasher_init(&h);
        blake3_hasher_update(&h, msg_buf, msg_len);
        blake3_hasher_finalize(&h, msg_hash, 32);
    }
    {
        blake3_hasher h;
        blake3_hasher_init(&h);
        blake3_hasher_update(&h, built->range_proof, MWEB_RANGEPROOF_LEN);
        blake3_hasher_finalize(&h, rp_hash, 32);
    }

    err = mweb_sign_output(
        sender_key,
        built->commit,
        built->sender_pubkey,
        built->output_pubkey,
        msg_hash, rp_hash,
        built->signature);

cleanup:
    wally_bzero(&binding, sizeof(binding));
    wally_bzero(msg_buf,  sizeof(msg_buf));
    wally_bzero(msg_hash, sizeof(msg_hash));
    wally_bzero(rp_hash,  sizeof(rp_hash));
    if (err != MWEB_OK) {
        wally_bzero(built, sizeof(*built));
    }
    return err;
}

mweb_err_t mweb_build_output(
    const uint8_t sender_key[32],
    const uint8_t scan_pub_A[33],
    const uint8_t spend_pub_B[33],
    uint64_t value,
    uint8_t features,
    const uint8_t *extra_data, size_t extra_data_len,
    struct mweb_built_output *built)
{
    return build_output_impl(
        sender_key, scan_pub_A, spend_pub_B, value, features,
        extra_data, extra_data_len,
        NULL, NULL,
        built);
}

mweb_err_t mweb_build_output_with_nonces(
    const uint8_t sender_key[32],
    const uint8_t scan_pub_A[33],
    const uint8_t spend_pub_B[33],
    uint64_t value,
    uint8_t features,
    const uint8_t *extra_data, size_t extra_data_len,
    const uint8_t bp_nonce[32],
    const uint8_t bp_private_nonce[32],
    struct mweb_built_output *built)
{
    /* Zero built before any other check so the failure-zero contract
     * holds regardless of which arg was bad. build_output_impl repeats
     * the up-front zero — harmless and keeps it self-contained. */
    if (!built) {
        return MWEB_ERR_INTERNAL;
    }
    memset(built, 0, sizeof(*built));
    if (!bp_nonce || !bp_private_nonce) {
        return MWEB_ERR_INTERNAL;
    }
    return build_output_impl(
        sender_key, scan_pub_A, spend_pub_B, value, features,
        extra_data, extra_data_len,
        bp_nonce, bp_private_nonce,
        built);
}
