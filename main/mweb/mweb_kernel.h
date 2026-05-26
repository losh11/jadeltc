#ifndef MWEB_KERNEL_H
#define MWEB_KERNEL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <wally_core.h>
#include <wally_map.h>

/* ── Error codes ─────────────────────────────────────────────────────── */

typedef enum {
    MWEB_OK = 0,
    MWEB_ERR_MISSING_SENDER_KEY,
    MWEB_ERR_MISSING_STEALTH_KEY,
    MWEB_ERR_INVALID_PRESIGN_SCALAR,
    MWEB_ERR_OUTPUT_FIELD_MISMATCH,
    MWEB_ERR_INPUT_COMMIT_MISMATCH,
    MWEB_ERR_BALANCE_FAIL,
    MWEB_ERR_KERNEL_FEATURE_MISMATCH,
    MWEB_ERR_FOREIGN_MWEB_INPUT,
    MWEB_ERR_MULTI_KERNEL_UNSUPPORTED,
    MWEB_ERR_MISSING_KERNEL,
    MWEB_ERR_PEGOUTS_NOT_DISPLAYED,
    MWEB_ERR_OFFSET_ACCUMULATE_FAIL,
    MWEB_ERR_UNSUPPORTED_NETWORK,
    MWEB_ERR_USER_CANCEL,
    MWEB_ERR_INTERNAL,
} mweb_err_t;

/* ── Scalar validation ───────────────────────────────────────────────── */

/*
 * Validate a 32-byte big-endian scalar: reject zero and >= curve order n.
 * Every host-supplied scalar that enters an EC operation on Jade must
 * pass this check first.
 */
bool mweb_validate_scalar(const uint8_t s[32]);

/* ── Wire serialization ──────────────────────────────────────────────── */

/* Write a Bitcoin compact-size varint to buf, returning bytes written
 * (1, 3, 5, or 9). buf must have room for up to 9 bytes. Shared between
 * the kernel hash and the MWEB output message serializer. */
size_t mweb_write_compact_size(uint8_t *buf, uint64_t val);

/* ── Kernel feature bits ─────────────────────────────────────────────── */

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

/* ── Kernel message hash ─────────────────────────────────────────────── */

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

/* ── Kernel signing ──────────────────────────────────────────────────── */

/* Per-input context for the kernel balance/offset computation. */
typedef struct {
    uint64_t value;            /* v_in_i */
    uint8_t  blind[32];        /* r_in_i (session-arena only) */
    uint8_t  stealth_tweak[32]; /* ephemeral - osk (mod n);
                                   produced by mweb_derive_input_state
                                   at S1 without emitting a signature */
} mweb_input_ctx_t;

/* Per-output context for the kernel balance/offset computation. */
typedef struct {
    uint64_t value;            /* v_out_j */
    uint8_t  blind[32];        /* r_out_j (session-arena only) */
} mweb_output_ctx_t;

struct mweb_kernel_sign_params {
    const mweb_input_ctx_t  *inputs;   size_t n_inputs;
    const mweb_output_ctx_t *outputs;  size_t n_outputs;

    uint8_t  features;

    /* Presence flags mirror libwally struct wally_psbt_kernel has_* fields
     * being *uint64 pointers: false means absent from the kernel and from the hash.
     * Presence MUST match the feature bits. */
    uint64_t fee;              bool has_fee;
    uint64_t pegin_amount;     bool has_pegin_amount;
    uint32_t lock_height;      bool has_lock_height;

    const struct wally_map *pegouts;   /* NULL or num_items==0
                                          iff !MWEB_KERNEL_PEGOUT_BIT;
                                          pegout_total is derived inside
                                          the helper by summing entries. */

    const uint8_t *extra_data;
    size_t         extra_data_len;

    const uint8_t *stealth_key_or_null; /* 32B iff StealthExcessBit, else NULL */

    const uint8_t *received_tx_offset;      /* 32B */
    const uint8_t *received_stealth_offset; /* 32B */
};

struct mweb_kernel_sign_outputs {
    uint8_t excess_kG[33];             /* E_k = Pedersen(e_k, 0), 0x08/0x09 */
    uint8_t stealth_excess_G[33];      /* stealthKey*G (0x02/0x03), or zeros */
    uint8_t tx_offset_final[32];       /* O_k_final */
    uint8_t stealth_offset_final[32];  /* O_s_final */
    uint8_t signature[64];
};

/*
 * Pure kernel signing function with caller-supplied e_k (test seam).
 *
 * NOT exposed outside main/mweb/ except to tests. Validates all inputs,
 * checks the u64 balance, derives E_k, the kernel hash, the (possibly
 * stealth-tweaked) signing key, signs, and computes final offsets.
 *
 * Returns the specific mweb_err_t for each failure mode.
 */
mweb_err_t mweb_sign_kernel_with_ek(
    const uint8_t e_k[32],
    const struct mweb_kernel_sign_params *in,
    struct mweb_kernel_sign_outputs *out);

/*
 * Production kernel signing entry point.
 * Pulls e_k from TRNG, validates, and delegates to mweb_sign_kernel_with_ek.
 */
mweb_err_t mweb_sign_kernel(
    const struct mweb_kernel_sign_params *in,
    struct mweb_kernel_sign_outputs *out);

#endif /* MWEB_KERNEL_H */
