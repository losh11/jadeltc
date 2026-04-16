#ifndef MWEB_KERNEL_H
#define MWEB_KERNEL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <wally_core.h>
#include <wally_map.h>

/* Kernel feature bits */
#define MWEB_KERNEL_FEE_BIT              0x01
#define MWEB_KERNEL_PEGIN_BIT            0x02
#define MWEB_KERNEL_PEGOUT_BIT           0x04
#define MWEB_KERNEL_HEIGHT_LOCK_BIT      0x08
#define MWEB_KERNEL_STEALTH_EXCESS_BIT   0x10
#define MWEB_KERNEL_EXTRA_DATA_BIT       0x20

#define MWEB_KERNEL_ALL_BITS \
    (MWEB_KERNEL_FEE_BIT | MWEB_KERNEL_PEGIN_BIT | MWEB_KERNEL_PEGOUT_BIT | \
     MWEB_KERNEL_HEIGHT_LOCK_BIT | MWEB_KERNEL_STEALTH_EXCESS_BIT |          \
     MWEB_KERNEL_EXTRA_DATA_BIT)

/*
 * Compute the MWEB kernel signature message hash.
 *
 * Byte layout:
 *
 *   features (1 byte)
 *   excess_commitment (33 bytes, ALWAYS present)
 *   [fee              — Litecoin internal varint, iff MWEB_KERNEL_FEE_BIT]
 *   [pegin_amount     — Litecoin internal varint, iff MWEB_KERNEL_PEGIN_BIT]
 *   [pegout_count     — Bitcoin compact-size varint
 *     for each pegout:
 *       amount         — Litecoin internal varint
 *       pkscript_len   — Bitcoin compact-size varint
 *       pkscript bytes
 *     iff MWEB_KERNEL_PEGOUT_BIT]
 *   [lock_height      — Litecoin internal varint, iff MWEB_KERNEL_HEIGHT_LOCK_BIT]
 *   [stealth_excess   — 33 raw bytes, iff MWEB_KERNEL_STEALTH_EXCESS_BIT]
 *   [extra_data_len   — Bitcoin compact-size varint
 *    extra_data bytes  — iff MWEB_KERNEL_EXTRA_DATA_BIT]
 *
 * Pegouts map: each entry has an integer key (pegout index, used only
 * for ordering) and value = le64(amount) || compact_size(script_len) ||
 * script_bytes. The caller passes the libwally struct wally_map whose entries
 * were parsed from PSBT MWEB_KRN_PEGOUT fields. The helper unpacks each entry.
 *
 * Returns false if excess_commitment is NULL.
 */
bool mweb_kernel_sig_hash(
    uint8_t features,
    const uint8_t excess_commitment[33],
    uint64_t fee,           bool has_fee,
    uint64_t pegin_amount,  bool has_pegin_amount,
    const struct wally_map *pegouts,
    uint32_t lock_height,   bool has_lock_height,
    const uint8_t *stealth_excess,
    const uint8_t *extra_data, size_t extra_data_len,
    uint8_t out_hash[32]);

#endif /* MWEB_KERNEL_H */
