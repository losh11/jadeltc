#ifndef MWEB_SCHNORR_H_
#define MWEB_SCHNORR_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "mweb_kernel.h"  /* mweb_err_t */

/*
 * MWEB Schnorr signature
 *
 * Differences from BIP340:
 *   - SHA256 for nonce derivation and challenge (not tagged SHA256)
 *   - 33-byte compressed pubkey in challenge hash (not x-only 32-byte)
 *   - Quadratic residue convention for R.y (not even/odd parity)
 *   - s = e * secret_key + k (same math, different normalization)
 *
 * Algorithm:
 *   k = SHA256(secret_key || message)
 *   R = k * G
 *   if R.y is NOT a quadratic residue mod p: negate k
 *   e = SHA256(R.x || compress(secret_key*G) || message)
 *   s = e * secret_key + k
 *   signature = (R.x[32] || s[32])
 */
bool mweb_schnorr_sign(const uint8_t secret_key[32],
                       const uint8_t* msg, size_t msg_len,
                       uint8_t signature[64]);

/*
 * Sign one MWEB output.
 *
 * sigHash = BLAKE3(commit ‖ K_s ‖ K_o ‖ msg_hash ‖ rp_hash)
 * signature = mweb_schnorr_sign(sender_key, sigHash, 32)
 *
 * Inputs are concatenation-order-sensitive: commit, K_s, K_o are the
 * 33-byte compressed bytes of the corresponding output fields; msg_hash
 * is BLAKE3(MwebOutputMessage); rp_hash is BLAKE3(rangeproof). The
 * order matches MwebOutput.sig_hash() in ltcsuite.
 *
 * Returns MWEB_ERR_INVALID_PRESIGN_SCALAR if sender_key fails scalar
 * validation; MWEB_ERR_INTERNAL on signing failure or NULL inputs.
 */
mweb_err_t mweb_sign_output(
    const uint8_t sender_key[32],
    const uint8_t commit[33],
    const uint8_t K_s[33],
    const uint8_t K_o[33],
    const uint8_t msg_hash[32],
    const uint8_t rp_hash[32],
    uint8_t sig_out[64]);

#endif /* MWEB_SCHNORR_H_ */
