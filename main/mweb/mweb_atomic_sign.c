/*
 * This translation unit dereferences MWEB-only fields on struct
 * wally_psbt / wally_psbt_kernel and must therefore only compile when
 * BUILD_MWEB is in effect.
 *
 * Two build flavours reach this file:
 *   - The IDF per-component build: `-DAMALGAMATED_BUILD=1` is added to
 *     main/ and each .c file is also compiled standalone. In that mode
 *     BUILD_MWEB is NOT set for main/, so the body below is wrapped in
 *     `#ifndef AMALGAMATED_BUILD` and compiles to an empty TU — the
 *     real code path is the amalgamation.
 *   - The amalgamated build (libjade / IDF amalgamation): amalgamated.c
 *     defines BUILD_MWEB and #undef's AMALGAMATED_BUILD before
 *     #include-ing this file, so the body below is processed with the
 *     MWEB struct fields visible on wally_psbt.
 *
 * Native unit tests build this file directly with `-DBUILD_MWEB=1` and
 * no AMALGAMATED_BUILD, so the body is processed there too.
 */
#ifndef AMALGAMATED_BUILD

#include "mweb_atomic_sign.h"

#include "mweb_kernel.h"
#include "mweb_output.h"
#include "mweb_scalar.h"
#include "mweb_sign.h"
#include "mweb_keychain.h"

#include "../utils/network.h"
#include "../sensitive.h"
#include "../wallet.h"

#include <stdlib.h>
#include <string.h>

#include <wally_core.h>
#include <wally_crypto.h>
#include <wally_map.h>
#include <wally_psbt.h>

/*
 * Max BIP32 path depth for key-origin derivation. The core value is
 * `MAX_PATH_LEN = 16` in utils/cbor_rpc.h. We define a local synonym so
 * this TU compiles under AMALGAMATED_BUILD where cbor_rpc.h may appear
 * elsewhere in the TU with unrelated macros.
 */
#define MWEB_ATOMIC_MAX_PATH_LEN 16

/*
 * MWEB proprietary-key discriminators. These mirror the libwally
 * definitions in psbt_io.h (which is a private header). We duplicate
 * the constants locally so this TU compiles under the per-component
 * IDF build where psbt_io.h is not on the include path.
 */
#define MWEB_OUT_STEALTH_ADDRESS_KEY  0x90
#define MWEB_OUT_COMMIT_KEY           0x91
#define MWEB_OUT_SENDER_PUBKEY_KEY    0x93
#define MWEB_OUT_OUTPUT_PUBKEY_KEY    0x94
#define MWEB_OUT_STANDARD_FIELDS_KEY  0x95

#define MWEB_IN_SPENT_OUTPUT_ID_KEY      0x90
#define MWEB_IN_SPENT_OUTPUT_COMMIT_KEY  0x91
#define MWEB_IN_INPUT_PUBKEY_KEY         0x93
#define MWEB_IN_INPUT_SIGNATURE_KEY      0x95
#define MWEB_IN_SHARED_SECRET_KEY        0x98
#define MWEB_IN_KEY_EXCHANGE_PUBKEY_KEY  0x99
#define MWEB_IN_MIN_KEY                  0x90
#define MWEB_OUT_MIN_KEY                 0x90

#define MWEB_IN_BIT(k)  (1u << ((k) - MWEB_IN_MIN_KEY))
#define MWEB_OUT_BIT(k) (1u << ((k) - MWEB_OUT_MIN_KEY))

/*
 * Keyset-bit predicates. Matches the public-header macros we would
 * otherwise inherit from psbt_io.h; kept in sync with libwally.
 * Defined unconditionally so this TU is self-contained regardless of
 * whether the amalgamated build happens to pre-include psbt_io.h.
 */
#undef MWEB_IN_HAS_OUTPUT_ID
#define MWEB_IN_HAS_OUTPUT_ID(keyset) \
    (((keyset) & MWEB_IN_BIT(MWEB_IN_SPENT_OUTPUT_ID_KEY)) != 0)

#undef MWEB_OUT_IS_MWEB
#define MWEB_OUT_IS_MWEB(keyset) \
    (((keyset) & (MWEB_OUT_BIT(MWEB_OUT_STEALTH_ADDRESS_KEY) |   \
                  MWEB_OUT_BIT(MWEB_OUT_COMMIT_KEY))) != 0)

/* ── Session structs ──────────────────────────────────────────────────── */

typedef struct {
    size_t              psbt_index;
    mweb_input_state_t  state;

    uint16_t prev_keyset;
    uint8_t  prev_input_signature[64];
    uint8_t  prev_input_pubkey[33];
} session_input_t;

typedef struct {
    size_t   psbt_index;
    uint64_t value;
    uint8_t  blind[32];
} session_output_t;

typedef struct {
    /* Pre-computed by begin, written to the PSBT by commit. */
    uint8_t excess_commitment[33];
    uint8_t stealth_excess[33];
    uint8_t signature[64];
    uint8_t tx_offset_final[32];
    uint8_t stealth_offset_final[32];
    bool    has_stealth_excess;

    /* Per-kernel rollback snapshot of fields commit mutates. */
    uint8_t  prev_excess_commitment[33];
    uint32_t prev_has_excess_commitment;
    uint8_t  prev_stealth_excess[33];
    uint32_t prev_has_stealth_excess;
    uint8_t  prev_signature[64];
    uint32_t prev_has_signature;
} session_kernel_t;

typedef struct {
    size_t          kernel_index;
    uint64_t        amount;
    const uint8_t  *script;
    size_t          script_len;
    bool            confirmed;
} session_pegout_t;

/*
 * Per-wally_map snapshot for the rollback arena.
 *
 * Each standard PSBT input has three wally_map fields that standard
 * signing may mutate:
 *   - `signatures`              — ECDSA partial sigs
 *   - `psbt_fields`             — holds the taproot key-path signature
 *                                  among other keyed fields
 *   - `taproot_leaf_signatures` — taproot script-path sigs per leaf
 *
 * Abort must restore each of these maps to its begin-entry state
 * byte-identical, and that restore MUST NOT depend on allocation
 * succeeding — an OOM during rollback would leave a live map truncated
 * while the caller thinks rollback succeeded.
 *
 * Design (zero-allocation restore):
 *   - At begin we pre-allocate a deep clone of the live map via
 *     wally_map_init + wally_map_combine. Any allocation failure here
 *     surfaces up from mweb_session_begin() BEFORE any mutation is
 *     committed, so it never leaves the tree in a half-restored state.
 *   - At abort we SWAP the clone's wally_map struct with the live
 *     map's struct: a pure pointer exchange that cannot fail. The
 *     verify_fn is preserved, items and their key/value buffers move
 *     wholesale. We then wally_map_clear the slot holding what was
 *     previously on the live map (the standard loop's new sigs/fields),
 *     which frees those bytes through wally's own allocator.
 *   - `valid == false` means the clone was never populated (OOM at
 *     begin, or the input had no live map): restore leaves the live
 *     map alone.
 */
typedef struct {
    struct wally_map      original;   /* Deep clone of live at begin. Owned. */
    bool                  valid;      /* True iff `original` holds a valid clone. */
} wally_map_snapshot_t;

/*
 * Composite snapshot of every wally_map on a PSBT input that the
 * standard signing loop may write to. All three clones succeed or all
 * three fail atomically (`snapshot_std_input`).
 */
typedef struct {
    wally_map_snapshot_t signatures;
    wally_map_snapshot_t psbt_fields;
    wally_map_snapshot_t taproot_leaf_signatures;
} std_input_snapshot_t;

struct mweb_session {
    session_input_t  *inputs;
    size_t            n_inputs;
    session_output_t *outputs;
    size_t            n_outputs;

    session_kernel_t  kernel;
    size_t            kernel_index;

    session_pegout_t *pegouts;
    size_t            n_pegouts;

    uint64_t total_fee;
    uint64_t total_pegin;
    uint64_t total_pegout;
    uint64_t total_input_value;
    uint64_t total_output_value;
    bool     has_pegin;

    /* Global rollback snapshot. */
    uint8_t  prev_tx_offset[32];
    uint32_t prev_has_tx_offset;
    uint8_t  prev_stealth_offset[32];
    uint32_t prev_has_stealth_offset;

    /*
     * Per-PSBT-input composite snapshot (signatures + psbt_fields +
     * taproot_leaf_signatures). One entry per psbt->inputs[]. NULL on
     * the (rare) path where mweb_session_begin() failed before the
     * snapshot was taken.
     */
    std_input_snapshot_t *std_input_snapshots;
    size_t                n_std_input_snapshots;
};

/* ── Helpers ──────────────────────────────────────────────────────────── */

static bool atomic_u64_add(uint64_t a, uint64_t b, uint64_t *out)
{
    if (a > UINT64_MAX - b) {
        return false;
    }
    *out = a + b;
    return true;
}

static bool atomic_parse_pegout(const uint8_t *val, size_t val_len,
                               uint64_t *amount_out,
                               const uint8_t **script_out, size_t *script_len_out)
{
    if (val_len < 9) {
        return false;
    }
    uint64_t amount = 0;
    for (int i = 0; i < 8; i++) {
        amount |= ((uint64_t)val[i]) << (i * 8);
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
    *amount_out = amount;
    *script_out = p + hdr;
    *script_len_out = (size_t)slen;
    return true;
}

static const struct wally_map_item *find_unknown(const struct wally_map *m, uint8_t key)
{
    size_t found = 0;
    if (wally_map_find(m, &key, 1, &found) != WALLY_OK || found == 0) {
        return NULL;
    }
    return &m->items[found - 1];
}

/* ── Snapshot / rollback ──────────────────────────────────────────────── */

static void snapshot_globals(struct mweb_session *s, const struct wally_psbt *psbt)
{
    s->prev_has_tx_offset = psbt->has_mweb_tx_offset;
    memcpy(s->prev_tx_offset, psbt->mweb_tx_offset, 32);
    s->prev_has_stealth_offset = psbt->has_mweb_stealth_offset;
    memcpy(s->prev_stealth_offset, psbt->mweb_stealth_offset, 32);
}

static void snapshot_kernel(session_kernel_t *sk, const struct wally_psbt_kernel *k)
{
    sk->prev_has_excess_commitment = k->has_excess_commitment;
    memcpy(sk->prev_excess_commitment, k->excess_commitment, 33);
    sk->prev_has_stealth_excess = k->has_stealth_excess;
    memcpy(sk->prev_stealth_excess, k->stealth_excess, 33);
    sk->prev_has_signature = k->has_signature;
    memcpy(sk->prev_signature, k->signature, 64);
}

static void snapshot_input(session_input_t *si, const struct wally_psbt_input *in)
{
    si->prev_keyset = in->mweb_keyset;
    memcpy(si->prev_input_signature, in->mweb_input_signature, 64);
    memcpy(si->prev_input_pubkey, in->mweb_input_pubkey, 33);
}

static void restore_globals(const struct mweb_session *s, struct wally_psbt *psbt)
{
    psbt->has_mweb_tx_offset = s->prev_has_tx_offset;
    memcpy(psbt->mweb_tx_offset, s->prev_tx_offset, 32);
    psbt->has_mweb_stealth_offset = s->prev_has_stealth_offset;
    memcpy(psbt->mweb_stealth_offset, s->prev_stealth_offset, 32);
}

static void restore_kernel(const session_kernel_t *sk, struct wally_psbt_kernel *k)
{
    k->has_excess_commitment = sk->prev_has_excess_commitment;
    memcpy(k->excess_commitment, sk->prev_excess_commitment, 33);
    k->has_stealth_excess = sk->prev_has_stealth_excess;
    memcpy(k->stealth_excess, sk->prev_stealth_excess, 33);
    k->has_signature = sk->prev_has_signature;
    memcpy(k->signature, sk->prev_signature, 64);
}

static void restore_input(const session_input_t *si, struct wally_psbt_input *in)
{
    in->mweb_keyset = si->prev_keyset;
    memcpy(in->mweb_input_signature, si->prev_input_signature, 64);
    memcpy(in->mweb_input_pubkey, si->prev_input_pubkey, 33);
}

/* ── Partial_sigs snapshot / restore / free ──────────────────────────── */

/*
 * Release the clone held by this snapshot, if any. Safe on zeroed or
 * already-freed snapshots.
 */
static void free_wally_map_snapshot(wally_map_snapshot_t *snap)
{
    if (!snap) return;
    if (snap->valid) {
        wally_map_clear(&snap->original);
    }
    memset(snap, 0, sizeof(*snap));
}

/*
 * Pre-populate a deep clone of `src` into `snap->original`. Any
 * allocation failure here is surfaced to the caller before any state
 * mutation begins, so the caller can propagate it as a begin-time
 * error and the abort path sees `valid == false` and leaves the live
 * map alone.
 *
 * Returns true on success (including the "no live map" case, which is
 * marked valid with an empty clone) or false on OOM.
 */
static bool snapshot_wally_map(wally_map_snapshot_t *snap,
                                const struct wally_map *src)
{
    memset(snap, 0, sizeof(*snap));
    if (!src) {
        /* Not a failure — an absent live map is a legitimate empty
         * state that restore will preserve (valid clone is empty). */
        if (wally_map_init(0, NULL, &snap->original) != WALLY_OK) {
            return false;
        }
        snap->valid = true;
        return true;
    }

    /* Initialise the clone with the live map's verify_fn so a later
     * wally_map_add against the cloned state (after the abort swap)
     * preserves the same validation. Reserving at least as much
     * capacity as the live map avoids reallocation during combine. */
    const size_t reserve = src->items_allocation_len;
    if (wally_map_init(reserve, src->verify_fn, &snap->original) != WALLY_OK) {
        return false;
    }

    /* Deep-copy src's items into the clone via libwally's own allocator.
     * On OOM, clear and signal failure without having touched `src`. */
    if (wally_map_combine(&snap->original, src) != WALLY_OK) {
        wally_map_clear(&snap->original);
        return false;
    }

    snap->valid = true;
    return true;
}

/*
 * Swap the clone into the live map slot and move whatever was on live
 * into the clone slot (which we then free). Pure pointer exchange:
 * cannot fail at rollback time.
 *
 * After this returns:
 *   - `live` holds the begin-entry state (including verify_fn).
 *   - `snap->original` is cleared and `snap->valid` is false.
 */
static void restore_wally_map(wally_map_snapshot_t *snap,
                               struct wally_map *live)
{
    if (!live || !snap || !snap->valid) {
        /* Snapshot was never captured (or already consumed) — do NOT
         * touch the live map. Clobbering an already-valid live map
         * here would erase pre-existing signatures. */
        return;
    }

    /* Swap the two wally_map structs. wally_map is a plain POD struct
     * (items ptr + sizes + verify_fn), so memcpy-based swap is
     * well-defined and transfers full ownership atomically. */
    struct wally_map tmp;
    memcpy(&tmp,             live,             sizeof(tmp));
    memcpy(live,             &snap->original,  sizeof(*live));
    memcpy(&snap->original,  &tmp,             sizeof(snap->original));

    /* Free the bytes that were on the live map just before the swap
     * (i.e. whatever the standard loop may have added). This is a
     * libwally-managed deallocation — no rollback-path allocation,
     * no partial state. */
    wally_map_clear(&snap->original);
    snap->valid = false;
}

/* ── Composite per-input snapshot ──────────────────────────────────── */

static void free_std_input_snapshot(std_input_snapshot_t *snap)
{
    if (!snap) return;
    free_wally_map_snapshot(&snap->signatures);
    free_wally_map_snapshot(&snap->psbt_fields);
    free_wally_map_snapshot(&snap->taproot_leaf_signatures);
}

/*
 * Clone every standard-signing-mutable wally_map on this input. All
 * three clones succeed or all three fail — on partial failure we free
 * any earlier clones so the composite snapshot has all three
 * `valid == false` and restore leaves the input entirely alone.
 */
static bool snapshot_std_input(std_input_snapshot_t *snap,
                                const struct wally_psbt_input *in)
{
    memset(snap, 0, sizeof(*snap));
    if (!in) return true; /* no input; no-op snapshot, all valid==false */

    if (!snapshot_wally_map(&snap->signatures, &in->signatures)) {
        return false;
    }
    if (!snapshot_wally_map(&snap->psbt_fields, &in->psbt_fields)) {
        free_wally_map_snapshot(&snap->signatures);
        return false;
    }
    if (!snapshot_wally_map(&snap->taproot_leaf_signatures,
            &in->taproot_leaf_signatures)) {
        free_wally_map_snapshot(&snap->signatures);
        free_wally_map_snapshot(&snap->psbt_fields);
        return false;
    }
    return true;
}

/*
 * Swap every captured map back into place on this input. Each inner
 * call is a no-op if that map was never snapshotted; otherwise it is
 * a pure pointer-exchange that cannot fail.
 */
static void restore_std_input(std_input_snapshot_t *snap,
                               struct wally_psbt_input *in)
{
    if (!snap || !in) return;
    restore_wally_map(&snap->signatures,              &in->signatures);
    restore_wally_map(&snap->psbt_fields,             &in->psbt_fields);
    restore_wally_map(&snap->taproot_leaf_signatures, &in->taproot_leaf_signatures);
}

/* ── Destroy ──────────────────────────────────────────────────────────── */

static void session_free(struct mweb_session *s)
{
    if (!s) return;
    if (s->inputs) {
        for (size_t i = 0; i < s->n_inputs; i++) {
            wally_bzero(&s->inputs[i].state, sizeof(s->inputs[i].state));
        }
        wally_bzero(s->inputs, sizeof(s->inputs[0]) * s->n_inputs);
        free(s->inputs);
    }
    if (s->outputs) {
        wally_bzero(s->outputs, sizeof(s->outputs[0]) * s->n_outputs);
        free(s->outputs);
    }
    if (s->pegouts) {
        free(s->pegouts);
    }
    if (s->std_input_snapshots) {
        for (size_t i = 0; i < s->n_std_input_snapshots; i++) {
            free_std_input_snapshot(&s->std_input_snapshots[i]);
        }
        free(s->std_input_snapshots);
    }
    wally_bzero(&s->kernel, sizeof(s->kernel));
    wally_bzero(s, sizeof(*s));
    free(s);
}

void mweb_session_abort(mweb_session_t *s, struct wally_psbt *psbt)
{
    if (!s) return;
    if (psbt) {
        restore_globals(s, psbt);
        if (s->kernel_index < psbt->num_mweb_kernels) {
            restore_kernel(&s->kernel, &psbt->mweb_kernels[s->kernel_index]);
        }
        for (size_t i = 0; i < s->n_inputs; i++) {
            if (s->inputs[i].psbt_index < psbt->num_inputs) {
                restore_input(&s->inputs[i], &psbt->inputs[s->inputs[i].psbt_index]);
            }
        }
        /* Restore every input's three standard-signing wally_map slots
         * (signatures, psbt_fields, taproot_leaf_signatures) to their
         * begin-entry state so any standard-loop writes between begin
         * and abort are unwound. Each inner restore is a pure pointer
         * swap that cannot fail at rollback time — any allocation
         * failure already surfaced as an early-return from
         * mweb_session_begin(). Snapshots flagged !valid (never
         * captured or already consumed) are no-ops, so a half-populated
         * snapshot array cannot clobber live maps. */
        for (size_t i = 0; i < s->n_std_input_snapshots && i < psbt->num_inputs; i++) {
            restore_std_input(&s->std_input_snapshots[i], &psbt->inputs[i]);
        }
    }
    session_free(s);
}

/* ── Per-input derivation ─────────────────────────────────────────────── */

static mweb_err_t derive_owned_input(const struct wally_psbt *psbt,
                                      size_t i,
                                      const uint8_t wallet_fp_le[4],
                                      session_input_t *out,
                                      bool *is_owned)
{
    *is_owned = false;
    const struct wally_psbt_input *in = &psbt->inputs[i];

    /* Legacy shared-secret bypass is a hard reject. */
    if (in->mweb_keyset & MWEB_IN_BIT(MWEB_IN_SHARED_SECRET_KEY)) {
        return MWEB_ERR_FOREIGN_MWEB_INPUT;
    }
    if (!(in->mweb_keyset & MWEB_IN_BIT(MWEB_IN_KEY_EXCHANGE_PUBKEY_KEY))) {
        return MWEB_ERR_FOREIGN_MWEB_INPUT;
    }

    uint8_t scan_fp[4];
    if (wally_map_keypath_get_item_fingerprint(&in->mweb_scan_key_origin, 0,
            scan_fp, sizeof(scan_fp)) != WALLY_OK) {
        return MWEB_ERR_FOREIGN_MWEB_INPUT;
    }
    uint8_t spend_fp[4];
    if (wally_map_keypath_get_item_fingerprint(&in->mweb_spend_key_origin, 0,
            spend_fp, sizeof(spend_fp)) != WALLY_OK) {
        return MWEB_ERR_FOREIGN_MWEB_INPUT;
    }
    if (memcmp(scan_fp, wallet_fp_le, 4) != 0
        || memcmp(spend_fp, wallet_fp_le, 4) != 0) {
        return MWEB_ERR_FOREIGN_MWEB_INPUT;
    }

    *is_owned = true;

    uint32_t scan_path[MWEB_ATOMIC_MAX_PATH_LEN];
    size_t   scan_path_len = 0;
    if (wally_map_keypath_get_item_path(&in->mweb_scan_key_origin, 0,
            scan_path, MWEB_ATOMIC_MAX_PATH_LEN, &scan_path_len) != WALLY_OK
        || scan_path_len == 0) {
        return MWEB_ERR_INTERNAL;
    }

    uint8_t scan_key[32];
#ifndef AMALGAMATED_BUILD
    SENSITIVE_PUSH(scan_key, sizeof(scan_key));
#endif
    if (!mweb_derive_key_from_path(scan_path, scan_path_len, scan_key)) {
#ifndef AMALGAMATED_BUILD
        SENSITIVE_POP(scan_key);
#endif
        return MWEB_ERR_INTERNAL;
    }

    uint32_t spend_path[MWEB_ATOMIC_MAX_PATH_LEN];
    size_t   spend_path_len = 0;
    if (wally_map_keypath_get_item_path(&in->mweb_spend_key_origin, 0,
            spend_path, MWEB_ATOMIC_MAX_PATH_LEN, &spend_path_len) != WALLY_OK
        || spend_path_len == 0) {
        wally_bzero(scan_key, 32);
#ifndef AMALGAMATED_BUILD
        SENSITIVE_POP(scan_key);
#endif
        return MWEB_ERR_INTERNAL;
    }

    uint8_t spend_key[32];
#ifndef AMALGAMATED_BUILD
    SENSITIVE_PUSH(spend_key, sizeof(spend_key));
#endif
    if (!mweb_derive_key_from_path(spend_path, spend_path_len, spend_key)) {
        wally_bzero(scan_key, 32);
#ifndef AMALGAMATED_BUILD
        SENSITIVE_POP(spend_key);
        SENSITIVE_POP(scan_key);
#endif
        return MWEB_ERR_INTERNAL;
    }

    mweb_err_t err = mweb_derive_input_state(scan_key, spend_key,
        in->mweb_address_index,
        in->mweb_input_features,
        in->mweb_spent_output_id,
        in->mweb_spent_output_pubkey,
        in->mweb_input_amount,
        in->mweb_key_exchange_pubkey,
        &out->state);

    wally_bzero(scan_key, 32);
    wally_bzero(spend_key, 32);
#ifndef AMALGAMATED_BUILD
    SENSITIVE_POP(spend_key);
    SENSITIVE_POP(scan_key);
#endif

    if (err != MWEB_OK) {
        return err;
    }

    /* Host-supplied spent_output_commit must equal Pedersen(r_in, v_in). */
    if (!(in->mweb_keyset & MWEB_IN_BIT(MWEB_IN_SPENT_OUTPUT_COMMIT_KEY))) {
        wally_bzero(&out->state, sizeof(out->state));
        return MWEB_ERR_INPUT_COMMIT_MISMATCH;
    }
    if (memcmp(in->mweb_spent_output_commit, out->state.output_commit, 33) != 0) {
        wally_bzero(&out->state, sizeof(out->state));
        return MWEB_ERR_INPUT_COMMIT_MISMATCH;
    }

    out->psbt_index = i;
    snapshot_input(out, in);
    return MWEB_OK;
}

/* ── Per-output recipient binding ──────────────────────────────────── */

static mweb_err_t verify_mweb_output(const struct wally_psbt_output *po,
                                      size_t i, session_output_t *out)
{
    if (!po->has_amount) {
        return MWEB_ERR_OUTPUT_FIELD_MISMATCH;
    }
    uint64_t value = (uint64_t)po->amount;

    uint8_t sender_key[32];
    size_t  written = 0;
    if (wally_psbt_output_get_mweb_presign_sender_key(po,
            sender_key, sizeof(sender_key), &written) != WALLY_OK
        || written != 32) {
        return MWEB_ERR_MISSING_SENDER_KEY;
    }
    if (!mweb_validate_scalar(sender_key)) {
        wally_bzero(sender_key, 32);
        return MWEB_ERR_INVALID_PRESIGN_SCALAR;
    }

    const struct wally_map_item *sa = find_unknown(&po->unknowns,
        MWEB_OUT_STEALTH_ADDRESS_KEY);
    if (!sa || sa->value_len != 66) {
        wally_bzero(sender_key, 32);
        return MWEB_ERR_OUTPUT_FIELD_MISMATCH;
    }
    const uint8_t *A = sa->value;
    const uint8_t *B = sa->value + 33;

    const struct wally_map_item *cm = find_unknown(&po->unknowns,
        MWEB_OUT_COMMIT_KEY);
    const struct wally_map_item *sp = find_unknown(&po->unknowns,
        MWEB_OUT_SENDER_PUBKEY_KEY);
    const struct wally_map_item *op = find_unknown(&po->unknowns,
        MWEB_OUT_OUTPUT_PUBKEY_KEY);
    const struct wally_map_item *sf = find_unknown(&po->unknowns,
        MWEB_OUT_STANDARD_FIELDS_KEY);
    if (!cm || cm->value_len != 33
        || !sp || sp->value_len != 33
        || !op || op->value_len != 33
        || !sf || sf->value_len != 58) {
        wally_bzero(sender_key, 32);
        return MWEB_ERR_OUTPUT_FIELD_MISMATCH;
    }

    /* 0x95: Ke[33] || viewTag[1] || maskedValue[8 LE] || maskedNonce[16 BE] */
    const uint8_t *sf_ke = sf->value;
    uint8_t  sf_view_tag = sf->value[33];
    uint64_t sf_masked_value = 0;
    for (int k = 0; k < 8; k++) {
        sf_masked_value |= ((uint64_t)sf->value[34 + k]) << (k * 8);
    }
    const uint8_t *sf_masked_nonce = sf->value + 42;

    struct mweb_derived_output derived;
    mweb_err_t err = mweb_derive_output(sender_key, A, B, value, &derived);
    wally_bzero(sender_key, 32);
    if (err != MWEB_OK) {
        wally_bzero(&derived, sizeof(derived));
        return err;
    }

    if (memcmp(cm->value, derived.commit,              33) != 0
        || memcmp(sp->value, derived.sender_pubkey,       33) != 0
        || memcmp(op->value, derived.output_pubkey,       33) != 0
        || memcmp(sf_ke,     derived.key_exchange_pubkey, 33) != 0
        || sf_view_tag       != derived.view_tag
        || sf_masked_value   != derived.masked_value
        || memcmp(sf_masked_nonce, derived.masked_nonce, 16) != 0) {
        wally_bzero(&derived, sizeof(derived));
        return MWEB_ERR_OUTPUT_FIELD_MISMATCH;
    }

    out->psbt_index = i;
    out->value      = value;
    memcpy(out->blind, derived.blind, 32);
    wally_bzero(&derived, sizeof(derived));
    return MWEB_OK;
}

/* ── mweb_session_begin ────────────────────────────────────────────── */

mweb_err_t mweb_session_begin(
    struct wally_psbt *psbt,
    uint8_t network_id,
    mweb_session_t **out_session)
{
    if (out_session) {
        *out_session = NULL;
    }
    if (!psbt || !out_session) {
        return MWEB_ERR_INTERNAL;
    }

    /* MWEB is Litecoin-only; reject any other network up-front so the
     * session cannot verify + commit an MWEB kernel while the caller's
     * UI block (gated on network_is_litecoin) is silently skipped. */
    if (!network_is_litecoin((network_t)network_id)) {
        return MWEB_ERR_UNSUPPORTED_NETWORK;
    }

    if (psbt->num_mweb_kernels == 0) {
        return MWEB_ERR_MISSING_KERNEL;
    }
    if (psbt->num_mweb_kernels != 1) {
        return MWEB_ERR_MULTI_KERNEL_UNSUPPORTED;
    }

    struct mweb_session *s = calloc(1, sizeof(*s));
    if (!s) {
        return MWEB_ERR_INTERNAL;
    }
    s->kernel_index = 0;

    /* Snapshot mutable global + kernel state before any mutation path. */
    struct wally_psbt_kernel *kernel = &psbt->mweb_kernels[0];
    snapshot_kernel(&s->kernel, kernel);
    snapshot_globals(s, psbt);

    /* Shared rollback arena: snapshot every input's three
     * standard-signing wally_map slots at begin (signatures,
     * psbt_fields, taproot_leaf_signatures) so mweb_session_abort()
     * can restore byte-identical state if the standard signing loop
     * (which runs between begin and commit) or commit itself fails.
     * psbt_fields is where the taproot key-path signature lands. */
    if (psbt->num_inputs > 0) {
        s->std_input_snapshots = calloc(psbt->num_inputs,
                                        sizeof(s->std_input_snapshots[0]));
        if (!s->std_input_snapshots) {
            mweb_session_abort(s, psbt);
            return MWEB_ERR_INTERNAL;
        }
        s->n_std_input_snapshots = psbt->num_inputs;
        for (size_t i = 0; i < psbt->num_inputs; i++) {
            if (!snapshot_std_input(&s->std_input_snapshots[i],
                    &psbt->inputs[i])) {
                mweb_session_abort(s, psbt);
                return MWEB_ERR_INTERNAL;
            }
        }
    }

    mweb_err_t err = MWEB_ERR_INTERNAL;

    /*
     * Reject kernels that omit the features byte. The wire encoding
     * writes `features` unconditionally, so a PSBT with !has_features
     * is malformed: signing would hash `features=0x00` into the
     * message, but the kernel serialisation — and the hash the
     * consensus verifier reproduces — would omit the byte, and the
     * signature would fail on broadcast.
     */
    if (!kernel->has_features) {
        err = MWEB_ERR_KERNEL_FEATURE_MISMATCH;
        goto fail;
    }

    uint8_t  features      = kernel->features;
    uint8_t  stealth_key[32] = {0};
    bool     has_stealth_key = false;

    /* Feature bit ↔ field presence (libwally `has_*` flags). */
    const bool fee_bit    = (features & MWEB_KERNEL_FEE_BIT) != 0;
    const bool pegin_bit  = (features & MWEB_KERNEL_PEGIN_BIT) != 0;
    const bool pegout_bit = (features & MWEB_KERNEL_PEGOUT_BIT) != 0;
    const bool lh_bit     = (features & MWEB_KERNEL_HEIGHT_LOCK_BIT) != 0;
    const bool se_bit     = (features & MWEB_KERNEL_STEALTH_EXCESS_BIT) != 0;
    const bool ed_bit     = (features & MWEB_KERNEL_EXTRA_DATA_BIT) != 0;

    const bool has_pegouts    = kernel->pegouts.num_items > 0;
    const bool has_extra_data = kernel->extra_data && kernel->extra_data_len > 0;

    if (fee_bit    != (kernel->has_fee          != 0)
        || pegin_bit  != (kernel->has_pegin_amount != 0)
        || pegout_bit != has_pegouts
        || lh_bit     != (kernel->has_lock_height  != 0)
        || ed_bit     != has_extra_data) {
        err = MWEB_ERR_KERNEL_FEATURE_MISMATCH;
        goto fail;
    }

    {
        size_t written = 0;
        if (wally_psbt_kernel_get_mweb_presign_stealth_key(kernel,
                stealth_key, sizeof(stealth_key), &written) == WALLY_OK
            && written == 32) {
            has_stealth_key = true;
        }
    }
    if (se_bit && !has_stealth_key) {
        err = MWEB_ERR_MISSING_STEALTH_KEY;
        goto fail;
    }
    if (!se_bit && has_stealth_key) {
        err = MWEB_ERR_KERNEL_FEATURE_MISMATCH;
        goto fail;
    }
    if (has_stealth_key && !mweb_validate_scalar(stealth_key)) {
        err = MWEB_ERR_INVALID_PRESIGN_SCALAR;
        goto fail;
    }
    s->kernel.has_stealth_excess = se_bit;

    /* Allocate per-input/output arrays. */
    size_t n_mweb_inputs_seen = 0;
    for (size_t i = 0; i < psbt->num_inputs; i++) {
        if (MWEB_IN_HAS_OUTPUT_ID(psbt->inputs[i].mweb_keyset)) {
            n_mweb_inputs_seen++;
        }
    }
    size_t n_mweb_outputs = 0;
    for (size_t i = 0; i < psbt->num_outputs; i++) {
        if (MWEB_OUT_IS_MWEB(psbt->outputs[i].mweb_output_keyset)) {
            n_mweb_outputs++;
        }
    }

    if (n_mweb_inputs_seen > 0) {
        s->inputs = calloc(n_mweb_inputs_seen, sizeof(s->inputs[0]));
        if (!s->inputs) { err = MWEB_ERR_INTERNAL; goto fail; }
    }
    if (n_mweb_outputs > 0) {
        s->outputs = calloc(n_mweb_outputs, sizeof(s->outputs[0]));
        if (!s->outputs) { err = MWEB_ERR_INTERNAL; goto fail; }
    }

    uint8_t wallet_fp_be[4];
    wallet_get_fingerprint(wallet_fp_be, sizeof(wallet_fp_be));
    uint8_t wallet_fp_le[4] = {
        wallet_fp_be[3], wallet_fp_be[2], wallet_fp_be[1], wallet_fp_be[0]
    };

    /* Per-owned-input state + input-commit check. */
    for (size_t i = 0; i < psbt->num_inputs; i++) {
        const struct wally_psbt_input *in = &psbt->inputs[i];
        if (!MWEB_IN_HAS_OUTPUT_ID(in->mweb_keyset)) {
            continue;
        }

        session_input_t si;
        memset(&si, 0, sizeof(si));
        bool is_owned = false;
        mweb_err_t ie = derive_owned_input(psbt, i, wallet_fp_le, &si, &is_owned);
        if (ie != MWEB_OK) {
            wally_bzero(&si, sizeof(si));
            err = ie;
            goto fail;
        }
        if (!is_owned) {
            /* Foreign MWEB inputs are rejected in v1. */
            err = MWEB_ERR_FOREIGN_MWEB_INPUT;
            goto fail;
        }

        /* Record total before the struct moves so we trap overflow early. */
        if (!atomic_u64_add(s->total_input_value,
                in->mweb_input_amount, &s->total_input_value)) {
            wally_bzero(&si, sizeof(si));
            err = MWEB_ERR_BALANCE_FAIL;
            goto fail;
        }

        s->inputs[s->n_inputs++] = si;
        wally_bzero(&si, sizeof(si));
    }

    /* Recipient-binding verification for every MWEB output. */
    for (size_t i = 0; i < psbt->num_outputs; i++) {
        const struct wally_psbt_output *po = &psbt->outputs[i];
        if (!MWEB_OUT_IS_MWEB(po->mweb_output_keyset)) {
            continue;
        }

        session_output_t so;
        memset(&so, 0, sizeof(so));
        mweb_err_t oe = verify_mweb_output(po, i, &so);
        if (oe != MWEB_OK) {
            wally_bzero(&so, sizeof(so));
            err = oe;
            goto fail;
        }
        if (!atomic_u64_add(s->total_output_value, so.value,
                &s->total_output_value)) {
            wally_bzero(&so, sizeof(so));
            err = MWEB_ERR_BALANCE_FAIL;
            goto fail;
        }

        s->outputs[s->n_outputs++] = so;
        wally_bzero(&so, sizeof(so));
    }

    /* Kernel totals + pegout table. */
    s->total_fee   = kernel->has_fee          ? kernel->fee          : 0;
    s->total_pegin = kernel->has_pegin_amount ? kernel->pegin_amount : 0;
    s->has_pegin   = kernel->has_pegin_amount != 0;

    if (kernel->pegouts.num_items > 0) {
        s->pegouts = calloc(kernel->pegouts.num_items, sizeof(s->pegouts[0]));
        if (!s->pegouts) { err = MWEB_ERR_INTERNAL; goto fail; }

        for (size_t p = 0; p < kernel->pegouts.num_items; p++) {
            const struct wally_map_item *item = &kernel->pegouts.items[p];
            uint64_t amount = 0;
            const uint8_t *script = NULL;
            size_t script_len = 0;
            if (!atomic_parse_pegout(item->value, item->value_len,
                    &amount, &script, &script_len)) {
                err = MWEB_ERR_KERNEL_FEATURE_MISMATCH;
                goto fail;
            }
            s->pegouts[s->n_pegouts].kernel_index = 0;
            s->pegouts[s->n_pegouts].amount       = amount;
            s->pegouts[s->n_pegouts].script       = script;
            s->pegouts[s->n_pegouts].script_len   = script_len;
            s->pegouts[s->n_pegouts].confirmed    = false;
            s->n_pegouts++;

            if (!atomic_u64_add(s->total_pegout, amount, &s->total_pegout)) {
                err = MWEB_ERR_BALANCE_FAIL;
                goto fail;
            }
        }
    }

    /* u64 balance:
     *   Sum(v_in) + pegin == Sum(v_out) + fee + pegout */
    {
        uint64_t input_side = 0, output_side = 0;
        if (!atomic_u64_add(s->total_input_value, s->total_pegin, &input_side)) {
            err = MWEB_ERR_BALANCE_FAIL;
            goto fail;
        }
        if (!atomic_u64_add(s->total_output_value, s->total_fee, &output_side)
            || !atomic_u64_add(output_side, s->total_pegout, &output_side)) {
            err = MWEB_ERR_BALANCE_FAIL;
            goto fail;
        }
        if (input_side != output_side) {
            err = MWEB_ERR_BALANCE_FAIL;
            goto fail;
        }
    }

    /* Kernel signing using the session arena. */
    {
        struct mweb_kernel_sign_params kp;
        memset(&kp, 0, sizeof(kp));

        mweb_input_ctx_t  *in_ctx  = NULL;
        mweb_output_ctx_t *out_ctx = NULL;
        if (s->n_inputs > 0) {
            in_ctx = calloc(s->n_inputs, sizeof(*in_ctx));
            if (!in_ctx) { err = MWEB_ERR_INTERNAL; goto fail; }
            for (size_t i = 0; i < s->n_inputs; i++) {
                in_ctx[i].value = s->inputs[i].state.value;
                memcpy(in_ctx[i].blind,         s->inputs[i].state.blind,         32);
                memcpy(in_ctx[i].stealth_tweak, s->inputs[i].state.stealth_tweak, 32);
            }
        }
        if (s->n_outputs > 0) {
            out_ctx = calloc(s->n_outputs, sizeof(*out_ctx));
            if (!out_ctx) {
                if (in_ctx) { wally_bzero(in_ctx, sizeof(*in_ctx) * s->n_inputs); free(in_ctx); }
                err = MWEB_ERR_INTERNAL;
                goto fail;
            }
            for (size_t i = 0; i < s->n_outputs; i++) {
                out_ctx[i].value = s->outputs[i].value;
                memcpy(out_ctx[i].blind, s->outputs[i].blind, 32);
            }
        }

        uint8_t received_tx_offset[32]      = {0};
        uint8_t received_stealth_offset[32] = {0};
        if (psbt->has_mweb_tx_offset) {
            memcpy(received_tx_offset, psbt->mweb_tx_offset, 32);
        }
        if (psbt->has_mweb_stealth_offset) {
            memcpy(received_stealth_offset, psbt->mweb_stealth_offset, 32);
        }

        kp.inputs                  = in_ctx;
        kp.n_inputs                = s->n_inputs;
        kp.outputs                 = out_ctx;
        kp.n_outputs               = s->n_outputs;
        kp.features                = features;
        kp.fee                     = s->total_fee;
        kp.has_fee                 = kernel->has_fee != 0;
        kp.pegin_amount            = s->total_pegin;
        kp.has_pegin_amount        = kernel->has_pegin_amount != 0;
        kp.lock_height             = kernel->has_lock_height ? kernel->lock_height : 0;
        kp.has_lock_height         = kernel->has_lock_height != 0;
        kp.pegouts                 = (kernel->pegouts.num_items > 0)
                                        ? &kernel->pegouts : NULL;
        kp.extra_data              = kernel->extra_data;
        kp.extra_data_len          = kernel->extra_data_len;
        kp.stealth_key_or_null     = has_stealth_key ? stealth_key : NULL;
        kp.received_tx_offset      = received_tx_offset;
        kp.received_stealth_offset = received_stealth_offset;

        struct mweb_kernel_sign_outputs ko;
        memset(&ko, 0, sizeof(ko));
        mweb_err_t ke = mweb_sign_kernel(&kp, &ko);

        if (in_ctx)  { wally_bzero(in_ctx, sizeof(*in_ctx) * s->n_inputs); free(in_ctx); }
        if (out_ctx) { wally_bzero(out_ctx, sizeof(*out_ctx) * s->n_outputs); free(out_ctx); }
        wally_bzero(received_tx_offset, 32);
        wally_bzero(received_stealth_offset, 32);

        if (ke != MWEB_OK) {
            wally_bzero(&ko, sizeof(ko));
            err = ke;
            goto fail;
        }

        memcpy(s->kernel.excess_commitment,    ko.excess_kG,            33);
        memcpy(s->kernel.stealth_excess,       ko.stealth_excess_G,     33);
        memcpy(s->kernel.signature,            ko.signature,            64);
        memcpy(s->kernel.tx_offset_final,      ko.tx_offset_final,      32);
        memcpy(s->kernel.stealth_offset_final, ko.stealth_offset_final, 32);
        wally_bzero(&ko, sizeof(ko));
    }

    wally_bzero(stealth_key, 32);
    *out_session = s;
    return MWEB_OK;

fail:
    wally_bzero(stealth_key, 32);
    mweb_session_abort(s, psbt);
    return err;
}

/* ── Queries ──────────────────────────────────────────────────────────── */

size_t mweb_session_pegout_count(const mweb_session_t *s)
{
    return s ? s->n_pegouts : 0;
}

mweb_err_t mweb_session_get_pegout(
    const mweb_session_t *s, size_t idx,
    uint64_t *amount_out,
    const uint8_t **script_out, size_t *script_len_out,
    size_t *kernel_index_out)
{
    if (!s || idx >= s->n_pegouts) {
        return MWEB_ERR_INTERNAL;
    }
    if (amount_out)       *amount_out       = s->pegouts[idx].amount;
    if (script_out)       *script_out       = s->pegouts[idx].script;
    if (script_len_out)   *script_len_out   = s->pegouts[idx].script_len;
    if (kernel_index_out) *kernel_index_out = s->pegouts[idx].kernel_index;
    return MWEB_OK;
}

void mweb_session_mark_pegout_confirmed(mweb_session_t *s, size_t idx)
{
    if (!s || idx >= s->n_pegouts) return;
    s->pegouts[idx].confirmed = true;
}

bool     mweb_session_has_pegin(const mweb_session_t *s)        { return s && s->has_pegin; }
uint64_t mweb_session_pegin_amount(const mweb_session_t *s)     { return s ? s->total_pegin : 0; }
uint64_t mweb_session_total_fee(const mweb_session_t *s)        { return s ? s->total_fee   : 0; }
size_t   mweb_session_num_mweb_outputs(const mweb_session_t *s) { return s ? s->n_outputs   : 0; }
size_t   mweb_session_num_mweb_inputs(const mweb_session_t *s)  { return s ? s->n_inputs    : 0; }

mweb_err_t mweb_session_get_output_value(
    const mweb_session_t *s, size_t psbt_index, uint64_t *value_out)
{
    if (!s || !value_out) {
        return MWEB_ERR_INTERNAL;
    }
    for (size_t j = 0; j < s->n_outputs; j++) {
        if (s->outputs[j].psbt_index == psbt_index) {
            *value_out = s->outputs[j].value;
            return MWEB_OK;
        }
    }
    return MWEB_ERR_INTERNAL;
}

/* ── Commit ───────────────────────────────────────────────────────── */

mweb_err_t mweb_session_commit(mweb_session_t *s, struct wally_psbt *psbt)
{
    if (!s || !psbt) {
        if (s) mweb_session_abort(s, psbt);
        return MWEB_ERR_INTERNAL;
    }

    /* Every pegout must have been displayed to the user. */
    for (size_t p = 0; p < s->n_pegouts; p++) {
        if (!s->pegouts[p].confirmed) {
            mweb_session_abort(s, psbt);
            return MWEB_ERR_PEGOUTS_NOT_DISPLAYED;
        }
    }

    /* Emit MWEB input signatures via Stage B. */
    for (size_t i = 0; i < s->n_inputs; i++) {
        session_input_t *si = &s->inputs[i];
        if (si->psbt_index >= psbt->num_inputs) {
            mweb_session_abort(s, psbt);
            return MWEB_ERR_INTERNAL;
        }
        struct wally_psbt_input *in = &psbt->inputs[si->psbt_index];

        uint8_t signature[64];
        mweb_err_t err = mweb_sign_input_from_state(&si->state,
            in->mweb_extra_data, in->mweb_extra_data_len, signature);
        if (err != MWEB_OK) {
            wally_bzero(signature, 64);
            mweb_session_abort(s, psbt);
            return err;
        }

        memcpy(in->mweb_input_signature, signature, 64);
        memcpy(in->mweb_input_pubkey,    si->state.input_pubkey, 33);
        in->mweb_keyset |= MWEB_IN_BIT(MWEB_IN_INPUT_SIGNATURE_KEY);
        in->mweb_keyset |= MWEB_IN_BIT(MWEB_IN_INPUT_PUBKEY_KEY);
        wally_bzero(signature, 64);
    }

    /* Write kernel fields + offsets. */
    if (s->kernel_index >= psbt->num_mweb_kernels) {
        mweb_session_abort(s, psbt);
        return MWEB_ERR_INTERNAL;
    }
    struct wally_psbt_kernel *k = &psbt->mweb_kernels[s->kernel_index];

    memcpy(k->excess_commitment, s->kernel.excess_commitment, 33);
    k->has_excess_commitment = 1;
    memcpy(k->signature, s->kernel.signature, 64);
    k->has_signature = 1;
    if (s->kernel.has_stealth_excess) {
        memcpy(k->stealth_excess, s->kernel.stealth_excess, 33);
        k->has_stealth_excess = 1;
    } else {
        /* Fully restore absence so the field is not orphaned after commit. */
        memset(k->stealth_excess, 0, 33);
        k->has_stealth_excess = 0;
    }

    memcpy(psbt->mweb_tx_offset,      s->kernel.tx_offset_final,      32);
    psbt->has_mweb_tx_offset      = 1;
    memcpy(psbt->mweb_stealth_offset, s->kernel.stealth_offset_final, 32);
    psbt->has_mweb_stealth_offset = 1;

    session_free(s);
    return MWEB_OK;
}

/* ── Error string map ─────────────────────────────────────────────────── */

const char *mweb_err_to_string(mweb_err_t err)
{
    switch (err) {
    case MWEB_OK:                           return "OK";
    case MWEB_ERR_MISSING_SENDER_KEY:       return "PSBT is missing MWEB presign data";
    case MWEB_ERR_MISSING_STEALTH_KEY:      return "PSBT is missing MWEB stealth presign data";
    case MWEB_ERR_INVALID_PRESIGN_SCALAR:   return "Companion wallet sent invalid MWEB data (scalar out of range)";
    case MWEB_ERR_OUTPUT_FIELD_MISMATCH:    return "MWEB output verification failed";
    case MWEB_ERR_INPUT_COMMIT_MISMATCH:    return "MWEB input amount does not match on-chain commitment";
    case MWEB_ERR_BALANCE_FAIL:             return "MWEB transaction value balance is invalid";
    case MWEB_ERR_KERNEL_FEATURE_MISMATCH:  return "Invalid MWEB kernel: feature flags do not match kernel fields";
    case MWEB_ERR_FOREIGN_MWEB_INPUT:       return "Foreign or unsupported MWEB input format";
    case MWEB_ERR_MULTI_KERNEL_UNSUPPORTED: return "Multi-kernel MWEB transactions are not yet supported";
    case MWEB_ERR_MISSING_KERNEL:           return "MWEB transaction is missing a kernel";
    case MWEB_ERR_PEGOUTS_NOT_DISPLAYED:    return "MWEB pegout was not displayed for confirmation";
    case MWEB_ERR_OFFSET_ACCUMULATE_FAIL:   return "MWEB offset accumulation failed";
    case MWEB_ERR_UNSUPPORTED_NETWORK:      return "MWEB is only supported on Litecoin";
    case MWEB_ERR_USER_CANCEL:              return "User declined";
    case MWEB_ERR_INTERNAL:
    default:                                return "MWEB signing internal error";
    }
}

#endif /* AMALGAMATED_BUILD */
