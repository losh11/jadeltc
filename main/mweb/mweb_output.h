#ifndef MWEB_OUTPUT_H
#define MWEB_OUTPUT_H

#include <stdint.h>

#include "mweb_kernel.h"  /* for mweb_err_t */

/*
 * Per-output MWEB recipient-binding derivation.
 *
 * Given a per-output 32-byte senderKey and the stealth address (A, B),
 * rederives every output field the host supplies in the PSBT so the
 * caller can compare byte-for-byte.
 *
 * The `blind` field (r_out = BlindSwitch(r_pre, v)) is retained by the
 * caller for kernel-offset math and must live in the same session arena
 * as the kernel signer's state. Every other intermediate scalar is
 * wiped inside the helper before return.
 */

struct mweb_derived_output {
    uint8_t  blind[32];               /* r_out_j — device only; feeds kernel
                                         balance/offset math */
    uint8_t  output_pubkey[33];       /* K_o = Hashed('O', t) * B
                                         — compare with PSBT 0x94 */
    uint8_t  sender_pubkey[33];       /* K_s = senderKey * G
                                         — compare with PSBT 0x93 */
    uint8_t  key_exchange_pubkey[33]; /* K_e = s * B (NOT senderKey * A)
                                         — compare with 0x95.key_exchange_pubkey */
    uint8_t  commit[33];              /* C_out = Pedersen(blind, v), 0x08/0x09
                                         prefix — compare with PSBT 0x91 */
    uint8_t  view_tag;                /* Hashed('T', sA)[0]
                                         — compare with 0x95.view_tag */
    uint64_t masked_value;            /* v XOR LE64(Hashed('Y', t)[0..8])
                                         — compare with 0x95.masked_value */
    uint8_t  masked_nonce[16];        /* n_16 XOR Hashed('X', t)[0..16]
                                         (big-endian 128-bit XOR)
                                         — compare with 0x95.masked_nonce */
};

/*
 * Derive the recipient-binding fields for one MWEB output.
 *
 * Inputs:
 *   sender_key   — 32-byte scalar; (reject zero / >= n)
 *   scan_pub_A   — 33-byte compressed scan pubkey  (stealth address A)
 *   spend_pub_B  — 33-byte compressed spend pubkey (stealth address B)
 *   value        — u64 MWEB output amount
 *
 * Output:
 *   out          — populated on MWEB_OK; zeroed on failure
 *
 * Failure modes:
 *   MWEB_ERR_INVALID_PRESIGN_SCALAR — sender_key fails validation
 *   MWEB_ERR_INTERNAL                — null argument, secp256k1 operation
 *                                      failed (unreachable for well-formed
 *                                      inputs), or BLAKE3/Pedersen primitive
 *                                      returned false
 */
mweb_err_t mweb_derive_output(
    const uint8_t sender_key[32],
    const uint8_t scan_pub_A[33],
    const uint8_t spend_pub_B[33],
    uint64_t value,
    struct mweb_derived_output *out);

#endif /* MWEB_OUTPUT_H */
