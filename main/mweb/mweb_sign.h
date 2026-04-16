#ifndef MWEB_SIGN_H_
#define MWEB_SIGN_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "mweb_kernel.h"  /* mweb_err_t */

#define MWEB_INPUT_STEALTH_KEY_BIT 0x01
#define MWEB_INPUT_EXTRA_DATA_BIT  0x02

/*
 * Two-stage MWEB input signing.
 *
 * Stage A — mweb_derive_input_state — runs at begin of the atomic
 * pass. Performs every input-side derivation EXCEPT the Schnorr
 * emission:
 *   - ECDH shared secret from key_exchange_pubkey
 *   - pre_blind, out_key_hash, address tweak m_i, output spend key
 *   - mandatory output-key verification against spent_output_pk
 *   - r_in = BlindSwitch(pre_blind, amount)
 *   - ephemeral nonce (TRNG, validated <n and non-zero)
 *   - input_pubkey = ephemeral*G
 *   - key_hash = BLAKE3(input_pubkey || spent_output_pk)
 *   - output_commit = Pedersen(r_in, amount), compared later against
 *     the host-supplied spent_output_commit
 *   - stealth_tweak = (ephemeral - osk) mod n, summed into the
 *     global stealth offset by the kernel signer
 *
 * No signature is emitted. Every scalar is cached into
 * `mweb_input_state_t` so Stage B can reproduce the signature
 * deterministically without re-reading host PSBT bytes.
 *
 * Stage B — mweb_sign_input_from_state — runs after user
 * confirmation. Derives the sig_key from the cached state, builds
 * msg_hash over features || spent_output_id || [varint || extra_data],
 * and emits a Schnorr signature. Reuses the cached ephemeral so the
 * signature's randomizer equals the `stealth_tweak` that was already
 * committed to when the kernel was signed.
 *
 * `mweb_input_state_t` is a device-only secret carrier. Callers MUST
 * wally_bzero the struct after Stage B or on rollback.
 */
typedef struct {
    uint64_t value;              /* v_in */
    uint8_t  blind[32];          /* r_in = BlindSwitch(pre_blind, v) */
    uint8_t  ephemeral[32];      /* TRNG at Stage A; reused at Stage B */
    uint8_t  osk[32];            /* output spend key scalar */
    uint8_t  input_pubkey[33];   /* ephemeral*G, compressed */
    uint8_t  stealth_tweak[32];  /* (ephemeral - osk) mod n */
    uint8_t  output_commit[33];  /* Pedersen(blind, value), 0x08/0x09 prefix */

    /* Stage-B-reproducibility fields. Cached so Stage B never re-reads
     * host memory. */
    uint8_t  features;
    uint8_t  spent_output_id[32];
    uint8_t  spent_output_pk[33];
    uint8_t  key_hash[32];       /* BLAKE3(input_pubkey || spent_output_pk) */
} mweb_input_state_t;

/*
 * Stage A: derive every input-side quantity except the Schnorr emission.
 *
 * ECDH only — no shared-secret bypass. Callers must provide the 33-byte
 * compressed `key_exchange_pubkey` from the PSBT input's 0x99 field.
 *
 * Failure modes:
 *   MWEB_ERR_INVALID_PRESIGN_SCALAR  — features lacks STEALTH_KEY_BIT, or
 *                                      the ephemeral TRNG draw produced a
 *                                      non-canonical scalar after 8 retries.
 *   MWEB_ERR_FOREIGN_MWEB_INPUT      — output-key verification fails.
 *   MWEB_ERR_INTERNAL                — null argument or secp256k1/BLAKE3
 *                                      primitive returned false.
 */
mweb_err_t mweb_derive_input_state(
    const uint8_t scan_key[32],
    const uint8_t spend_key[32],
    uint32_t address_index,
    uint8_t features,
    const uint8_t spent_output_id[32],
    const uint8_t spent_output_pk[33],
    uint64_t amount,
    const uint8_t key_exchange_pubkey[33],
    mweb_input_state_t* out_state);

/*
 * Stage B: emit the Schnorr signature using the cached state.
 *
 * Does NOT draw fresh entropy — the ephemeral from Stage A is reused
 * so the emitted signature's randomizer equals the stealth_tweak that
 * was already folded into the kernel's global stealth offset.
 *
 * Failure modes:
 *   MWEB_ERR_INTERNAL — null argument or secp256k1 primitive returned false.
 */
mweb_err_t mweb_sign_input_from_state(
    const mweb_input_state_t* state,
    const uint8_t* extra_data, size_t extra_data_len,
    uint8_t out_signature[64]);

#endif /* MWEB_SIGN_H_ */
