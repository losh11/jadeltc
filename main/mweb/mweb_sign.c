#include "mweb_sign.h"
#include "mweb_blind.h"
#include "mweb_hash.h"
#include "mweb_scalar.h"
#include "mweb_schnorr.h"

#include <string.h>

#include <blake3.h>
#include <secp256k1.h>
#include <wally_core.h>
#include <wally_crypto.h>

#include "../random.h"

/*
 * Write a Bitcoin-style compact varint to buf.
 * Returns the number of bytes written (1, 3, 5, or 9).
 */
static size_t write_varint(uint8_t* buf, uint64_t val)
{
    if (val < 0xfd) {
        buf[0] = (uint8_t)val;
        return 1;
    } else if (val <= 0xffff) {
        buf[0] = 0xfd;
        buf[1] = (uint8_t)(val);
        buf[2] = (uint8_t)(val >> 8);
        return 3;
    } else if (val <= 0xffffffff) {
        buf[0] = 0xfe;
        buf[1] = (uint8_t)(val);
        buf[2] = (uint8_t)(val >> 8);
        buf[3] = (uint8_t)(val >> 16);
        buf[4] = (uint8_t)(val >> 24);
        return 5;
    } else {
        buf[0] = 0xff;
        for (int i = 0; i < 8; i++) {
            buf[1 + i] = (uint8_t)(val >> (i * 8));
        }
        return 9;
    }
}

mweb_err_t mweb_derive_input_state(
    const uint8_t scan_key[32],
    const uint8_t spend_key[32],
    uint32_t address_index,
    uint8_t features,
    const uint8_t spent_output_id[32],
    const uint8_t spent_output_pk[33],
    uint64_t amount,
    const uint8_t key_exchange_pubkey[33],
    mweb_input_state_t* out_state)
{
    if (!scan_key || !spend_key || !spent_output_id || !spent_output_pk
        || !key_exchange_pubkey || !out_state) {
        return MWEB_ERR_INTERNAL;
    }

    const secp256k1_context* ctx = wally_get_secp_context();
    if (!ctx) {
        return MWEB_ERR_INTERNAL;
    }

    /* STEALTH_KEY_BIT is required for any MWEB input Jade signs. */
    if (!(features & MWEB_INPUT_STEALTH_KEY_BIT)) {
        return MWEB_ERR_INVALID_PRESIGN_SCALAR;
    }

    memset(out_state, 0, sizeof(*out_state));

    mweb_err_t err = MWEB_ERR_INTERNAL;

    /* Intermediate scalars — all wiped in cleanup. */
    uint8_t ss[32];         /* shared secret */
    uint8_t pre_blind[32];
    uint8_t out_key_hash[32];
    uint8_t m_i[32];

    /* ECDH: key_exchange_pubkey * scan_key → compressed → Hashed('D', ...) */
    {
        secp256k1_pubkey kex;
        if (!secp256k1_ec_pubkey_parse(ctx, &kex, key_exchange_pubkey, 33)) {
            goto cleanup;
        }
        if (!secp256k1_ec_pubkey_tweak_mul(ctx, &kex, scan_key)) {
            goto cleanup;
        }
        uint8_t ecdh_result[EC_PUBLIC_KEY_LEN];
        size_t ecdh_len = sizeof(ecdh_result);
        secp256k1_ec_pubkey_serialize(ctx, ecdh_result, &ecdh_len,
                                      &kex, SECP256K1_EC_COMPRESSED);
        mweb_hashed(MWEB_TAG_DERIVE, ecdh_result, 33, ss);
    }

    /* pre_blind = Hashed('B', ss) */
    mweb_hashed(MWEB_TAG_BLIND, ss, 32, pre_blind);

    /* out_key_hash = Hashed('O', ss) */
    mweb_hashed(MWEB_TAG_OUTKEY, ss, 32, out_key_hash);

    /* m_i = Hashed('A', index_le32 || scan_key) */
    {
        uint8_t mi_buf[4 + 32];
        mi_buf[0] = (uint8_t)(address_index);
        mi_buf[1] = (uint8_t)(address_index >> 8);
        mi_buf[2] = (uint8_t)(address_index >> 16);
        mi_buf[3] = (uint8_t)(address_index >> 24);
        memcpy(mi_buf + 4, scan_key, 32);
        mweb_hashed(MWEB_TAG_ADDRESS, mi_buf, sizeof(mi_buf), m_i);
        wally_bzero(mi_buf, sizeof(mi_buf));
    }

    /* osk = (spend_key + m_i) * out_key_hash */
    memcpy(out_state->osk, spend_key, 32);
    if (!secp256k1_ec_seckey_tweak_add(ctx, out_state->osk, m_i)) {
        goto cleanup;
    }
    if (!secp256k1_ec_seckey_tweak_mul(ctx, out_state->osk, out_key_hash)) {
        goto cleanup;
    }

    /* Mandatory output-key verification:
     *   B_i = spend_pub + m_i*G
     *   expected_Ko = out_key_hash * B_i
     * A mismatch means this address_index did not produce the on-chain
     * K_o, i.e. the input is foreign to this wallet. */
    {
        uint8_t spend_pub[EC_PUBLIC_KEY_LEN];
        if (wally_ec_public_key_from_private_key(spend_key, 32,
                spend_pub, sizeof(spend_pub)) != WALLY_OK) {
            goto cleanup;
        }

        uint8_t mi_pub[EC_PUBLIC_KEY_LEN];
        if (wally_ec_public_key_from_private_key(m_i, 32,
                mi_pub, sizeof(mi_pub)) != WALLY_OK) {
            goto cleanup;
        }

        secp256k1_pubkey sp_pk, mi_pk, Bi_pk;
        if (!secp256k1_ec_pubkey_parse(ctx, &sp_pk, spend_pub, 33)) {
            goto cleanup;
        }
        if (!secp256k1_ec_pubkey_parse(ctx, &mi_pk, mi_pub, 33)) {
            goto cleanup;
        }
        const secp256k1_pubkey* pts[2] = { &sp_pk, &mi_pk };
        if (!secp256k1_ec_pubkey_combine(ctx, &Bi_pk, pts, 2)) {
            goto cleanup;
        }
        if (!secp256k1_ec_pubkey_tweak_mul(ctx, &Bi_pk, out_key_hash)) {
            goto cleanup;
        }

        uint8_t expected_Ko[EC_PUBLIC_KEY_LEN];
        size_t ko_len = sizeof(expected_Ko);
        secp256k1_ec_pubkey_serialize(ctx, expected_Ko, &ko_len,
                                      &Bi_pk, SECP256K1_EC_COMPRESSED);

        if (memcmp(expected_Ko, spent_output_pk, EC_PUBLIC_KEY_LEN) != 0) {
            err = MWEB_ERR_FOREIGN_MWEB_INPUT;
            goto cleanup;
        }
    }

    /* blind = BlindSwitch(pre_blind, amount) */
    if (!mweb_blind_switch(pre_blind, amount, out_state->blind)) {
        goto cleanup;
    }

    /* ephemeral = get_random(32), validated canonical (non-zero, < n).
     * TRNG failure here is astronomically rare; we retry a few times
     * before surfacing MWEB_ERR_INVALID_PRESIGN_SCALAR to the caller. */
    {
        bool got_scalar = false;
        for (int tries = 0; tries < 8; ++tries) {
            get_random(out_state->ephemeral, 32);
            if (mweb_validate_scalar(out_state->ephemeral)) {
                got_scalar = true;
                break;
            }
        }
        if (!got_scalar) {
            err = MWEB_ERR_INVALID_PRESIGN_SCALAR;
            goto cleanup;
        }
    }

    /* input_pubkey = ephemeral * G (compressed) */
    if (wally_ec_public_key_from_private_key(out_state->ephemeral, 32,
            out_state->input_pubkey, EC_PUBLIC_KEY_LEN) != WALLY_OK) {
        goto cleanup;
    }

    /* key_hash = BLAKE3(input_pubkey || spent_output_pk) — raw, NO tag */
    {
        blake3_hasher hasher;
        blake3_hasher_init(&hasher);
        blake3_hasher_update(&hasher, out_state->input_pubkey, 33);
        blake3_hasher_update(&hasher, spent_output_pk, 33);
        blake3_hasher_finalize(&hasher, out_state->key_hash, 32);
    }

    /* output_commit = Pedersen(blind, amount) — compared later against
     * the host-supplied spent_output_commit. */
    if (!mweb_pedersen_commit(out_state->blind, amount, out_state->output_commit)) {
        goto cleanup;
    }

    /* stealth_tweak = ephemeral - osk (mod n) — summed into the global
     * stealth offset by the kernel signer. Use the zero-result-accepting
     * helper: the pathological ephemeral == osk case is a mathematically
     * valid tweak contribution (a zero scalar) and must not be treated
     * as a signing failure. */
    if (!mweb_scalar_sub_mod_n(out_state->ephemeral, out_state->osk,
            out_state->stealth_tweak)) {
        goto cleanup;
    }

    /* Cache the fields Stage B needs to reproduce the signature. */
    out_state->value = amount;
    out_state->features = features;
    memcpy(out_state->spent_output_id, spent_output_id, 32);
    memcpy(out_state->spent_output_pk, spent_output_pk, 33);

    err = MWEB_OK;

cleanup:
    wally_bzero(ss, sizeof(ss));
    wally_bzero(pre_blind, sizeof(pre_blind));
    wally_bzero(out_key_hash, sizeof(out_key_hash));
    wally_bzero(m_i, sizeof(m_i));
    if (err != MWEB_OK) {
        wally_bzero(out_state, sizeof(*out_state));
    }
    return err;
}

mweb_err_t mweb_sign_input_from_state(
    const mweb_input_state_t* state,
    const uint8_t* extra_data, size_t extra_data_len,
    uint8_t out_signature[64])
{
    if (!state || !out_signature) {
        return MWEB_ERR_INTERNAL;
    }

    const secp256k1_context* ctx = wally_get_secp_context();
    if (!ctx) {
        return MWEB_ERR_INTERNAL;
    }

    mweb_err_t err = MWEB_ERR_INTERNAL;

    uint8_t sig_key[32];
    uint8_t msg_hash[32];

    /* sig_key = osk * key_hash + ephemeral */
    memcpy(sig_key, state->osk, 32);
    if (!secp256k1_ec_seckey_tweak_mul(ctx, sig_key, state->key_hash)) {
        goto cleanup;
    }
    if (!secp256k1_ec_seckey_tweak_add(ctx, sig_key, state->ephemeral)) {
        goto cleanup;
    }

    /* msg_hash = BLAKE3(features || spent_output_id || [varint || extra_data]) */
    {
        blake3_hasher hasher;
        blake3_hasher_init(&hasher);
        blake3_hasher_update(&hasher, &state->features, 1);
        blake3_hasher_update(&hasher, state->spent_output_id, 32);

        if (state->features & MWEB_INPUT_EXTRA_DATA_BIT) {
            uint8_t vi_buf[9];
            size_t vi_len = write_varint(vi_buf, (uint64_t)extra_data_len);
            blake3_hasher_update(&hasher, vi_buf, vi_len);
            if (extra_data && extra_data_len > 0) {
                blake3_hasher_update(&hasher, extra_data, extra_data_len);
            }
        }

        blake3_hasher_finalize(&hasher, msg_hash, 32);
    }

    if (!mweb_schnorr_sign(sig_key, msg_hash, 32, out_signature)) {
        goto cleanup;
    }

    err = MWEB_OK;

cleanup:
    wally_bzero(sig_key, sizeof(sig_key));
    wally_bzero(msg_hash, sizeof(msg_hash));
    return err;
}
