#include "mweb_kernel.h"

#include <blake3.h>
#include <string.h>

#include <wally_core.h>

/* Bitcoin compact-size varint */
static size_t write_compact_size(uint8_t *buf, uint64_t val)
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
        vi_len = write_compact_size(vi, (uint64_t)count);
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
            vi_len = write_compact_size(vi, (uint64_t)script_len);
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
        vi_len = write_compact_size(vi, (uint64_t)elen);
        blake3_hasher_update(&hasher, vi, vi_len);
        if (extra_data && extra_data_len > 0) {
            blake3_hasher_update(&hasher, extra_data, extra_data_len);
        }
    }

    blake3_hasher_finalize(&hasher, out_hash, 32);
    return true;
}
