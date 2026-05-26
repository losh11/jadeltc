#include "mweb_kernel.h"
#include "mweb_blind.h"
#include "mweb_schnorr.h"
#include "mweb_scalar.h"

#include <blake3.h>
#include <string.h>

#include <secp256k1.h>
#include <wally_core.h>
#include <wally_crypto.h>

#ifndef MWEB_KERNEL_NO_TRNG
#include "../random.h"
#endif

/* ── Scalar validation ───────────────────────────────────────────────── */

bool mweb_validate_scalar(const uint8_t s[32])
{
    /* Reject zero */
    bool all_zero = true;
    for (int i = 0; i < 32; i++) {
        if (s[i] != 0) { all_zero = false; break; }
    }
    if (all_zero) {
        return false;
    }

    /* Reject s >= n (big-endian comparison) */
    for (int i = 0; i < 32; i++) {
        if (s[i] < SECP256K1_ORDER[i]) { return true;  }
        if (s[i] > SECP256K1_ORDER[i]) { return false; }
    }
    /* s == n exactly → overflow */
    return false;
}

/* Bitcoin compact-size varint */
size_t mweb_write_compact_size(uint8_t *buf, uint64_t val)
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

/* Litecoin-internal varint (7-bit encoding with continuation bit).
 *
 * Algorithm: build bytes from LSB to MSB into buf[0..i], then write
 * them in reverse (MSB first). The first byte written (highest index)
 * has its high bit clear; all preceding bytes have 0x80 set. */
static size_t write_mweb_varint(uint8_t *buf, uint64_t n)
{
    uint8_t tmp[10];
    int i = 0;
    for (;; i++) {
        tmp[i] = (uint8_t)(n & 0x7f);
        if (i > 0) {
            tmp[i] |= 0x80;
        }
        if (n < 0x80) {
            break;
        }
        n = (n >> 7) - 1;
    }
    size_t len = (size_t)(i + 1);
    for (int j = 0; j <= i; j++) {
        buf[j] = tmp[i - j];
    }
    return len;
}

/* Parse a pegout map value: le64(amount) || compact_size(script_len) || script.
 * Returns false if the value is too short to contain amount + at least 1 byte. */
static bool parse_pegout_value(const uint8_t *val, size_t val_len,
                               uint64_t *amount_out,
                               const uint8_t **script_out, size_t *script_len_out)
{
    if (val_len < 9) {
        return false;
    }
    *amount_out = 0;
    for (int i = 0; i < 8; i++) {
        *amount_out |= ((uint64_t)val[i]) << (i * 8);
    }

    const uint8_t *p = val + 8;
    size_t remaining = val_len - 8;

    uint64_t slen;
    size_t hdr;
    if (p[0] < 0xfd) {
        slen = p[0];
        hdr = 1;
    } else if (p[0] == 0xfd && remaining >= 3) {
        slen = (uint64_t)p[1] | ((uint64_t)p[2] << 8);
        hdr = 3;
    } else if (p[0] == 0xfe && remaining >= 5) {
        slen = (uint64_t)p[1] | ((uint64_t)p[2] << 8)
             | ((uint64_t)p[3] << 16) | ((uint64_t)p[4] << 24);
        hdr = 5;
    } else if (p[0] == 0xff && remaining >= 9) {
        slen = 0;
        for (int i = 0; i < 8; i++) {
            slen |= ((uint64_t)p[1 + i]) << (i * 8);
        }
        hdr = 9;
    } else {
        return false;
    }

    if (hdr + slen > remaining) {
        return false;
    }
    *script_out = p + hdr;
    *script_len_out = (size_t)slen;
    return true;
}

bool mweb_kernel_sig_hash(
    uint8_t features,
    const uint8_t excess_commitment[33],
    uint64_t fee,           bool has_fee,
    uint64_t pegin_amount,  bool has_pegin_amount,
    const struct wally_map *pegouts,
    uint32_t lock_height,   bool has_lock_height,
    const uint8_t *stealth_excess,
    const uint8_t *extra_data, size_t extra_data_len,
    uint8_t out_hash[32])
{
    if (!excess_commitment || !out_hash) {
        return false;
    }

    blake3_hasher hasher;
    blake3_hasher_init(&hasher);

    /* 1. features (1 byte) */
    blake3_hasher_update(&hasher, &features, 1);

    /* 2. excess_commitment (33 bytes, always in message mode) */
    blake3_hasher_update(&hasher, excess_commitment, 33);

    uint8_t vi[10];
    size_t vi_len;

    /* 3. fee — Litecoin internal varint */
    if (has_fee) {
        vi_len = write_mweb_varint(vi, fee);
        blake3_hasher_update(&hasher, vi, vi_len);
    }

    /* 4. pegin — Litecoin internal varint */
    if (has_pegin_amount) {
        vi_len = write_mweb_varint(vi, pegin_amount);
        blake3_hasher_update(&hasher, vi, vi_len);
    }

    /* 5. pegouts */
    if (features & MWEB_KERNEL_PEGOUT_BIT) {
        size_t count = pegouts ? pegouts->num_items : 0;

        /* pegout count — Bitcoin compact-size varint */
        vi_len = mweb_write_compact_size(vi, (uint64_t)count);
        blake3_hasher_update(&hasher, vi, vi_len);

        for (size_t i = 0; i < count; i++) {
            const struct wally_map_item *item = &pegouts->items[i];
            uint64_t pegout_amount;
            const uint8_t *script;
            size_t script_len;

            if (!parse_pegout_value(item->value, item->value_len,
                                    &pegout_amount, &script, &script_len)) {
                return false;
            }

            /* pegout amount — Litecoin internal varint */
            vi_len = write_mweb_varint(vi, pegout_amount);
            blake3_hasher_update(&hasher, vi, vi_len);

            /* pkScript — Bitcoin compact-size length + bytes */
            vi_len = mweb_write_compact_size(vi, (uint64_t)script_len);
            blake3_hasher_update(&hasher, vi, vi_len);
            if (script_len > 0) {
                blake3_hasher_update(&hasher, script, script_len);
            }
        }
    }

    /* 6. lock_height — Litecoin internal varint */
    if (has_lock_height) {
        vi_len = write_mweb_varint(vi, (uint64_t)lock_height);
        blake3_hasher_update(&hasher, vi, vi_len);
    }

    /* 7. stealth_excess — 33 raw bytes */
    if (stealth_excess) {
        blake3_hasher_update(&hasher, stealth_excess, 33);
    }

    /* 8. extra_data — Bitcoin compact-size length + bytes.
     * ltcsuite always calls WriteVarBytes when the feature bit is set,
     * which emits a compact-size 0x00 even for nil/empty extra data. */
    if (features & MWEB_KERNEL_EXTRA_DATA_BIT) {
        size_t elen = extra_data ? extra_data_len : 0;
        vi_len = mweb_write_compact_size(vi, (uint64_t)elen);
        blake3_hasher_update(&hasher, vi, vi_len);
        if (extra_data && extra_data_len > 0) {
            blake3_hasher_update(&hasher, extra_data, extra_data_len);
        }
    }

    blake3_hasher_finalize(&hasher, out_hash, 32);
    return true;
}

/* ── Kernel signing ──────────────────────────────────────────────────── */

/*
 * Checked u64 addition: *out = a + b. Returns false on overflow.
 */
static bool u64_add_checked(uint64_t a, uint64_t b, uint64_t *out)
{
    *out = a + b;
    return *out >= a;  /* overflow iff result < either operand */
}

/*
 * Derive the total pegout amount by summing pegouts[*].amount.
 * Returns false on parse error or u64 overflow.
 */
static bool derive_pegout_total(const struct wally_map *pegouts,
                                uint64_t *total_out)
{
    *total_out = 0;
    if (!pegouts) {
        return true;
    }
    for (size_t i = 0; i < pegouts->num_items; i++) {
        const struct wally_map_item *item = &pegouts->items[i];
        uint64_t amount;
        const uint8_t *script;
        size_t script_len;
        if (!parse_pegout_value(item->value, item->value_len,
                                &amount, &script, &script_len)) {
            return false;
        }
        if (!u64_add_checked(*total_out, amount, total_out)) {
            return false;
        }
    }
    return true;
}

mweb_err_t mweb_sign_kernel_with_ek(
    const uint8_t e_k[32],
    const struct mweb_kernel_sign_params *in,
    struct mweb_kernel_sign_outputs *out)
{
    if (!e_k || !in || !out) {
        return MWEB_ERR_INTERNAL;
    }

    /* Required pointers that are always dereferenced */
    if (!in->received_tx_offset || !in->received_stealth_offset) {
        return MWEB_ERR_INTERNAL;
    }
    if (in->n_inputs > 0 && !in->inputs) {
        return MWEB_ERR_INTERNAL;
    }
    if (in->n_outputs > 0 && !in->outputs) {
        return MWEB_ERR_INTERNAL;
    }

    const secp256k1_context *ctx = wally_get_secp_context();
    if (!ctx) {
        return MWEB_ERR_INTERNAL;
    }

    mweb_err_t err = MWEB_ERR_INTERNAL;
    uint8_t sig_key[32];
    uint8_t kernel_hash[32];
    uint8_t ek_pubkey[33];  /* e_k * G as 0x02/0x03 pubkey (for stealth tweak) */

    memset(out, 0, sizeof(*out));
    memset(sig_key, 0, sizeof(sig_key));

    /* ── 1. Input validation ─────────────────────────────────────────── */

    /* 1a. Validate e_k */
    if (!mweb_validate_scalar(e_k)) {
        err = MWEB_ERR_INVALID_SCALAR;
        goto cleanup;
    }

    /* 1b. Feature-bit ↔ field presence consistency */
    if (in->has_fee != ((in->features & MWEB_KERNEL_FEE_BIT) != 0)) {
        err = MWEB_ERR_KERNEL_FEATURE_MISMATCH;
        goto cleanup;
    }
    if (in->has_pegin_amount != ((in->features & MWEB_KERNEL_PEGIN_BIT) != 0)) {
        err = MWEB_ERR_KERNEL_FEATURE_MISMATCH;
        goto cleanup;
    }
    {
        bool has_pegouts = in->pegouts && in->pegouts->num_items > 0;
        if (has_pegouts != ((in->features & MWEB_KERNEL_PEGOUT_BIT) != 0)) {
            err = MWEB_ERR_KERNEL_FEATURE_MISMATCH;
            goto cleanup;
        }
    }
    if (in->has_lock_height != ((in->features & MWEB_KERNEL_HEIGHT_LOCK_BIT) != 0)) {
        err = MWEB_ERR_KERNEL_FEATURE_MISMATCH;
        goto cleanup;
    }
    {
        bool has_extra = in->extra_data && in->extra_data_len > 0;
        if (has_extra != ((in->features & MWEB_KERNEL_EXTRA_DATA_BIT) != 0)) {
            err = MWEB_ERR_KERNEL_FEATURE_MISMATCH;
            goto cleanup;
        }
    }

    /* 1c. Stealth-excess binding */
    if ((in->features & MWEB_KERNEL_STEALTH_EXCESS_BIT) && !in->stealth_key_or_null) {
        err = MWEB_ERR_MISSING_STEALTH_SCALAR;
        goto cleanup;
    }
    if (!(in->features & MWEB_KERNEL_STEALTH_EXCESS_BIT) && in->stealth_key_or_null) {
        err = MWEB_ERR_KERNEL_FEATURE_MISMATCH;
        goto cleanup;
    }

    /* 1d. Validate stealth_key if present */
    if (in->stealth_key_or_null) {
        if (!mweb_validate_scalar(in->stealth_key_or_null)) {
            err = MWEB_ERR_INVALID_SCALAR;
            goto cleanup;
        }
    }

    /* ── 2. Derive pegout_total ──────────────────────────────────────── */
    uint64_t pegout_total = 0;
    if (in->features & MWEB_KERNEL_PEGOUT_BIT) {
        if (!derive_pegout_total(in->pegouts, &pegout_total)) {
            err = MWEB_ERR_BALANCE_FAIL;
            goto cleanup;
        }
    }

    /* ── 3. u64 balance check ────────────────────────────────────────── */
    {
        /* input side: Sum(v_in) + pegin_amount */
        uint64_t input_sum = 0;
        for (size_t i = 0; i < in->n_inputs; i++) {
            if (!u64_add_checked(input_sum, in->inputs[i].value, &input_sum)) {
                err = MWEB_ERR_BALANCE_FAIL;
                goto cleanup;
            }
        }
        if (in->has_pegin_amount) {
            if (!u64_add_checked(input_sum, in->pegin_amount, &input_sum)) {
                err = MWEB_ERR_BALANCE_FAIL;
                goto cleanup;
            }
        }

        /* output side: Sum(v_out) + fee + pegout_total */
        uint64_t output_sum = 0;
        for (size_t i = 0; i < in->n_outputs; i++) {
            if (!u64_add_checked(output_sum, in->outputs[i].value, &output_sum)) {
                err = MWEB_ERR_BALANCE_FAIL;
                goto cleanup;
            }
        }
        if (in->has_fee) {
            if (!u64_add_checked(output_sum, in->fee, &output_sum)) {
                err = MWEB_ERR_BALANCE_FAIL;
                goto cleanup;
            }
        }
        if (!u64_add_checked(output_sum, pegout_total, &output_sum)) {
            err = MWEB_ERR_BALANCE_FAIL;
            goto cleanup;
        }

        if (input_sum != output_sum) {
            err = MWEB_ERR_BALANCE_FAIL;
            goto cleanup;
        }
    }

    /* ── 4. Derive E_k = Pedersen(e_k, 0) ───────────────────────────── */
    /* Pedersen commitment format: 0x08/0x09 prefix */
    if (!mweb_pedersen_commit(e_k, 0, out->excess_kG)) {
        err = MWEB_ERR_INTERNAL;
        goto cleanup;
    }

    /* Also compute e_k*G as a standard pubkey (0x02/0x03) for the stealth tweak */
    {
        secp256k1_pubkey pk;
        if (!secp256k1_ec_pubkey_create(ctx, &pk, e_k)) {
            err = MWEB_ERR_INTERNAL;
            goto cleanup;
        }
        size_t pk_len = 33;
        secp256k1_ec_pubkey_serialize(ctx, ek_pubkey, &pk_len,
                                      &pk, SECP256K1_EC_COMPRESSED);
    }

    /* ── 5. Stealth excess ───────────────────────────────────────────── */
    if (in->features & MWEB_KERNEL_STEALTH_EXCESS_BIT) {
        /* E_stealth = stealthKey * G (standard compressed pubkey) */
        secp256k1_pubkey spk;
        if (!secp256k1_ec_pubkey_create(ctx, &spk, in->stealth_key_or_null)) {
            err = MWEB_ERR_INTERNAL;
            goto cleanup;
        }
        size_t spk_len = 33;
        secp256k1_ec_pubkey_serialize(ctx, out->stealth_excess_G, &spk_len,
                                      &spk, SECP256K1_EC_COMPRESSED);
    }

    /* ── 6. Build kernel_hash ────────────────────────────────────────── */
    {
        /* stealth_excess in the hash uses the 0x02/0x03 pubkey form */
        const uint8_t *stealth_for_hash =
            (in->features & MWEB_KERNEL_STEALTH_EXCESS_BIT)
                ? out->stealth_excess_G : NULL;

        if (!mweb_kernel_sig_hash(in->features, out->excess_kG,
                                  in->fee, in->has_fee,
                                  in->pegin_amount, in->has_pegin_amount,
                                  in->pegouts,
                                  in->lock_height, in->has_lock_height,
                                  stealth_for_hash,
                                  in->extra_data, in->extra_data_len,
                                  kernel_hash)) {
            err = MWEB_ERR_INTERNAL;
            goto cleanup;
        }
    }

    /* ── 7. Derive sig_key ───────────────────────────────────────────── */
    if (in->features & MWEB_KERNEL_STEALTH_EXCESS_BIT) {
        /*
         * tweak = BLAKE3(kernelExcess.PubKey() || stealthExcess)
         * sigKey = e_k * tweak + stealthKey
         *
         * kernelExcess.PubKey() is the commitment converted to 0x02/0x03
         * form. We use ek_pubkey (e_k*G as standard pubkey) which gives
         * the same point.
         */
        uint8_t tweak[32];
        blake3_hasher h;
        blake3_hasher_init(&h);
        blake3_hasher_update(&h, ek_pubkey, 33);
        blake3_hasher_update(&h, out->stealth_excess_G, 33);
        blake3_hasher_finalize(&h, tweak, 32);

        /* sig_key = e_k * tweak */
        memcpy(sig_key, e_k, 32);
        if (!secp256k1_ec_seckey_tweak_mul(ctx, sig_key, tweak)) {
            wally_bzero(tweak, sizeof(tweak));
            err = MWEB_ERR_INTERNAL;
            goto cleanup;
        }
        /* sig_key += stealthKey */
        if (!secp256k1_ec_seckey_tweak_add(ctx, sig_key, in->stealth_key_or_null)) {
            wally_bzero(tweak, sizeof(tweak));
            err = MWEB_ERR_INTERNAL;
            goto cleanup;
        }
        wally_bzero(tweak, sizeof(tweak));
    } else {
        memcpy(sig_key, e_k, 32);
    }

    /* ── 8. Sign ─────────────────────────────────────────────────────── */
    if (!mweb_schnorr_sign(sig_key, kernel_hash, 32, out->signature)) {
        err = MWEB_ERR_INTERNAL;
        goto cleanup;
    }

    /* ── 9. Compute O_k_final ────────────────────────────────────────── */
    /*
     * O_k_final = received_tx_offset - Sum(r_in_i) - e_k  (mod n)
     *
     * All arithmetic via mweb_scalar_*_mod_n which accept zero results.
     */
    {
        /* Accumulate Sum(r_in_i) */
        uint8_t sum_blind[32] = {0};
        for (size_t i = 0; i < in->n_inputs; i++) {
            if (!mweb_scalar_add_mod_n(sum_blind, in->inputs[i].blind, sum_blind)) {
                err = MWEB_ERR_INTERNAL;
                goto cleanup;
            }
        }

        /* O_k = received - Sum(blind) */
        uint8_t tmp[32];
        if (!mweb_scalar_sub_mod_n(in->received_tx_offset, sum_blind, tmp)) {
            err = MWEB_ERR_INTERNAL;
            goto cleanup;
        }
        /* O_k = O_k - e_k */
        if (!mweb_scalar_sub_mod_n(tmp, e_k, out->tx_offset_final)) {
            err = MWEB_ERR_INTERNAL;
            goto cleanup;
        }

        wally_bzero(sum_blind, sizeof(sum_blind));
        wally_bzero(tmp, sizeof(tmp));
    }

    /* ── 10. Compute O_s_final ───────────────────────────────────────── */
    /*
     * O_s_final = received_stealth_offset
     *             + Sum(stealth_tweak_i)
     *             - stealthKey  (if stealth-excess feature)
     */
    {
        uint8_t sum_tweak[32] = {0};
        for (size_t i = 0; i < in->n_inputs; i++) {
            if (!mweb_scalar_add_mod_n(sum_tweak, in->inputs[i].stealth_tweak,
                                       sum_tweak)) {
                err = MWEB_ERR_INTERNAL;
                goto cleanup;
            }
        }

        uint8_t tmp[32];
        if (!mweb_scalar_add_mod_n(in->received_stealth_offset, sum_tweak, tmp)) {
            err = MWEB_ERR_INTERNAL;
            goto cleanup;
        }

        if (in->features & MWEB_KERNEL_STEALTH_EXCESS_BIT) {
            if (!mweb_scalar_sub_mod_n(tmp, in->stealth_key_or_null,
                                       out->stealth_offset_final)) {
                err = MWEB_ERR_INTERNAL;
                goto cleanup;
            }
        } else {
            memcpy(out->stealth_offset_final, tmp, 32);
        }

        wally_bzero(sum_tweak, sizeof(sum_tweak));
        wally_bzero(tmp, sizeof(tmp));
    }

    err = MWEB_OK;

cleanup:
    wally_bzero(sig_key, sizeof(sig_key));
    wally_bzero(kernel_hash, sizeof(kernel_hash));
    wally_bzero(ek_pubkey, sizeof(ek_pubkey));
    if (err != MWEB_OK) {
        wally_bzero(out, sizeof(*out));
    }
    return err;
}

#ifndef MWEB_KERNEL_NO_TRNG
mweb_err_t mweb_sign_kernel(
    const struct mweb_kernel_sign_params *in,
    struct mweb_kernel_sign_outputs *out)
{
    uint8_t e_k[32];

    for (int tries = 0; tries < 8; ++tries) {
        get_random(e_k, 32);
        if (mweb_validate_scalar(e_k)) {
            break;
        }
        if (tries == 7) {
            wally_bzero(e_k, sizeof(e_k));
            return MWEB_ERR_INTERNAL;
        }
    }

    mweb_err_t err = mweb_sign_kernel_with_ek(e_k, in, out);
    wally_bzero(e_k, sizeof(e_k));
    return err;
}
#endif /* MWEB_KERNEL_NO_TRNG */
