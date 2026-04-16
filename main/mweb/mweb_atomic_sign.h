#ifndef MWEB_ATOMIC_SIGN_H
#define MWEB_ATOMIC_SIGN_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <wally_psbt.h>

#include "mweb_kernel.h"  /* mweb_err_t */

/*
 * Atomic MWEB PSBT signing session (bind-then-sign).
 *
 * A session owns everything the UI needs to render and everything
 * commit needs to write to the PSBT. It is heap-allocated on entry
 * and either:
 *   - consumed by mweb_session_commit() on successful signing, or
 *   - torn down by mweb_session_abort() on any error or user cancel.
 *
 * Canonical flow inside sign_psbt_process():
 *
 *   mweb_session_t *s = NULL;
 *   if (has_mweb) {
 *       mweb_err_t err = mweb_session_begin(psbt, network_id, &s);
 *       if (err != MWEB_OK) { handle; goto cleanup; }
 *       // Outputs verified, balance + kernel sig produced into s,
 *       // PSBT still unmodified.
 *   }
 *
 *   // UI confirmation (standard outputs, MWEB outputs, pegouts, fee).
 *   // Every confirmed pegout MUST call mweb_session_mark_pegout_confirmed();
 *   // the post-assertion inside mweb_session_commit() rejects
 *   // MWEB_ERR_PEGOUTS_NOT_DISPLAYED if any entry was skipped.
 *
 *   // Standard input signing (existing loop).
 *
 *   if (has_mweb) {
 *       mweb_err_t err = mweb_session_commit(s, psbt);
 *       if (err != MWEB_OK) { handle; goto cleanup; }
 *       // MWEB input sigs + kernel fields + offsets written to PSBT
 *       // atomically. Session consumed.
 *       s = NULL;
 *   }
 *
 * cleanup:
 *   if (s) mweb_session_abort(s, psbt);
 *
 * Every host-supplied scalar that enters an EC operation inside the
 * session is validated (non-zero, < curve order). Every PSBT byte Jade
 * writes is covered by the rollback snapshot. Secrets are wiped on
 * destroy.
 */

typedef struct mweb_session mweb_session_t;

/*
 * Derive input states, verify every MWEB output's recipient binding,
 * check input commits, validate the u64 balance, and sign the kernel
 * into session memory. PSBT is NOT mutated by this call.
 *
 * On success *out_session receives a heap allocation. On failure
 * *out_session is NULL.
 */
mweb_err_t mweb_session_begin(
    struct wally_psbt *psbt,
    uint8_t network_id,
    mweb_session_t **out_session);

/*
 * Queries for the UI layer.
 */
size_t   mweb_session_pegout_count(const mweb_session_t *s);

/*
 * Fetch the k-th pegout entry across all kernels (flat index).
 * On success:
 *   *amount_out       — satoshi value
 *   *script_out       — borrowed pointer into the PSBT kernel map entry
 *                       (do NOT free; valid until the PSBT is freed)
 *   *script_len_out   — script byte length
 *   *kernel_index_out — which kernel this pegout belongs to
 */
mweb_err_t mweb_session_get_pegout(
    const mweb_session_t *s, size_t idx,
    uint64_t *amount_out,
    const uint8_t **script_out, size_t *script_len_out,
    size_t *kernel_index_out);

/*
 * Mark pegout at flat index `idx` as displayed+confirmed by the user.
 * mweb_session_commit() returns MWEB_ERR_PEGOUTS_NOT_DISPLAYED if any
 * entry was left unconfirmed.
 */
void mweb_session_mark_pegout_confirmed(mweb_session_t *s, size_t idx);

bool     mweb_session_has_pegin(const mweb_session_t *s);
uint64_t mweb_session_pegin_amount(const mweb_session_t *s);
uint64_t mweb_session_total_fee(const mweb_session_t *s);
size_t   mweb_session_num_mweb_outputs(const mweb_session_t *s);
size_t   mweb_session_num_mweb_inputs(const mweb_session_t *s);

/*
 * Return the verified v_out for the MWEB output at PSBT index
 * `psbt_index`.
 *
 * The value is the one that passed the recipient-binding derivation
 * chain inside mweb_session_begin(); UI code MUST source MWEB output
 * amounts from here rather than from tx->outputs[i].satoshi or
 * psbt->outputs[i].amount directly, so every amount shown on a
 * confirmation screen is one that has been cryptographically bound to
 * the commitment.
 *
 * Returns MWEB_OK on match; MWEB_ERR_INTERNAL if `psbt_index` does not
 * correspond to a verified MWEB output in this session.
 */
mweb_err_t mweb_session_get_output_value(
    const mweb_session_t *s, size_t psbt_index, uint64_t *value_out);

/*
 * Emit MWEB input sigs and write kernel excess / stealth_excess /
 * signature and the global tx_offset / stealth_offset to the PSBT.
 *
 * On success: the session is freed and PSBT carries the signatures.
 * On failure: PSBT is rolled back to its begin-entry state and the
 * session is freed. Either way, caller's pointer is now dangling —
 * set to NULL.
 */
mweb_err_t mweb_session_commit(mweb_session_t *s, struct wally_psbt *psbt);

/*
 * Rollback + destroy. Safe to call with a session that was never
 * committed (e.g. user cancelled). Restores the PSBT byte-for-byte to
 * its begin-entry state and wipes session secrets.
 */
void mweb_session_abort(mweb_session_t *s, struct wally_psbt *psbt);

/*
 * Map mweb_err_t to a short user-facing string.
 */
const char *mweb_err_to_string(mweb_err_t err);

#endif /* MWEB_ATOMIC_SIGN_H */
