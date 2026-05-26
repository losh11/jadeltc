/*
 * Unit tests for mweb_atomic_sign.
 *
 * Covers the pure helpers and session-lifecycle guards:
 *   - mweb_err_to_string  — every mweb_err_t enum value maps to a
 *                           distinct non-empty string
 *   - Null-guard behaviour of the query helpers
 *   - mweb_session_begin invalid-input rejection
 *   - mweb_session_begin on an empty PSBT rejects MWEB_ERR_MISSING_KERNEL
 *     and leaves *out_session NULL
 *   - Multi-kernel PSBTs rejected
 *
 * Full end-to-end coverage (happy-path MWEB→MWEB, standard→MWEB
 * gating, pegout UI skipped, rollback byte-identity) requires a
 * fixture generator that produces a signed-input-less MWEB PSBT,
 * which sits in a separate tool and is not reproducible in this TU
 * without porting the full PSBT producer — the on-device selfcheck
 * vectors and the external Python suite carry that coverage instead.
 */
#include "mweb_atomic_sign.h"
#include "mweb_kernel.h"
#include "mweb_hash.h"
#include "mweb_blind.h"
#include "mweb_gate.h"
#include "mweb_output.h"

#include "../../utils/network.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <secp256k1.h>
#include <wally_bip32.h>
#include <wally_core.h>
#include <wally_crypto.h>
#include <wally_map.h>
#include <wally_psbt.h>

static int failures = 0;

/* Deterministic TRNG stub shared with other native tests. */
static uint8_t g_test_random[32];
void get_random(void* bytes_out, size_t len)
{
    if (len <= 32) {
        memcpy(bytes_out, g_test_random, len);
    } else {
        memset(bytes_out, 0, len);
        memcpy(bytes_out, g_test_random, 32);
    }
}

/*
 * Canonical test scan/spend keys shared with mweb_selfcheck.c fixtures.
 * Non-zero so the owned-input path in mweb_derive_input_state can run
 * wally_ec_public_key_from_private_key without rejection.
 */
static const uint8_t OWNED_TEST_SCAN_KEY[32] = {
    0xb3,0xc9,0x1b,0x72,0x91,0xc2,0xe1,0xe0,
    0x6d,0x4a,0x93,0xf3,0xdc,0x32,0x40,0x4a,
    0xef,0x99,0x27,0xdb,0x8e,0x79,0x4c,0x01,
    0xa7,0xb4,0xde,0x18,0xa3,0x97,0xc3,0x38,
};
static const uint8_t OWNED_TEST_SPEND_KEY[32] = {
    0x2f,0xe1,0x98,0x2b,0x98,0xc0,0xb6,0x8c,
    0x08,0x39,0x42,0x1c,0x8a,0x0a,0x0a,0x67,
    0xef,0x31,0x98,0xc7,0x46,0xab,0x8e,0x6d,
    0x09,0x10,0x1e,0xb7,0x39,0x6a,0x44,0xd8,
};
/* Arbitrary non-zero fingerprint so a broken comparison (reversed
 * endianness, wrong length) surfaces as a test failure rather than a
 * silent zero-vs-zero pass. */
static const uint8_t OWNED_TEST_WALLET_FP_BE[4] = { 0xde, 0xad, 0xbe, 0xef };

/*
 * Stubs for firmware symbols the atomic signer references. Strong
 * definitions — the owned-input path now routes through them with real
 * test keys. Existing kernel-only / shared-secret-bypass tests either
 * skip the fingerprint check entirely or reject on an earlier branch,
 * so switching from "returns zeros" to "returns a stable test
 * fingerprint" does not break them.
 */
__attribute__((weak)) void wallet_get_fingerprint(uint8_t* out, size_t len)
{
    if (len >= 4) { memcpy(out, OWNED_TEST_WALLET_FP_BE, 4); }
    if (len  > 4) { memset(out + 4, 0, len - 4); }
}

__attribute__((weak)) bool mweb_derive_key_from_path(
    const uint32_t* path, size_t path_len, uint8_t key_out[32])
{
    /* m/0'/100'/{0|1}' dispatches to scan vs spend. Anything else
     * fails — mirrors the real firmware path rejecting non-MWEB keys. */
    if (path_len != 3
        || path[0] != BIP32_INITIAL_HARDENED_CHILD
        || path[1] != BIP32_INITIAL_HARDENED_CHILD + 100) {
        memset(key_out, 0, 32);
        return false;
    }
    if (path[2] == BIP32_INITIAL_HARDENED_CHILD + 0) {
        memcpy(key_out, OWNED_TEST_SCAN_KEY, 32);
        return true;
    }
    if (path[2] == BIP32_INITIAL_HARDENED_CHILD + 1) {
        memcpy(key_out, OWNED_TEST_SPEND_KEY, 32);
        return true;
    }
    memset(key_out, 0, 32);
    return false;
}

/* sensitive_push/pop are Jade firmware helpers that track secret buffers.
 * Native tests don't need them; provide weak stubs for link-only coverage. */
__attribute__((weak)) void sensitive_push(const void* ptr, size_t len)
{
    (void)ptr; (void)len;
}
__attribute__((weak)) void sensitive_pop(const void* ptr)
{
    (void)ptr;
}

/* network_is_litecoin mirrors the real implementation shape (Litecoin
 * mainnet / testnet / regtest all count) so the network-rejection test
 * can cover both accept and reject paths without pulling in the full
 * firmware network.c / jade_assert.h dependency chain. */
__attribute__((weak)) bool network_is_litecoin(network_t n)
{
    return n == NETWORK_LITECOIN
        || n == NETWORK_LITECOIN_TESTNET
        || n == NETWORK_LITECOIN_REGTEST;
}

static void test_err_to_string_covers_all_codes(void)
{
    const mweb_err_t codes[] = {
        MWEB_OK,
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
    };
    const size_t n = sizeof(codes) / sizeof(codes[0]);

    for (size_t i = 0; i < n; ++i) {
        const char* s = mweb_err_to_string(codes[i]);
        if (!s || !*s) {
            printf("FAIL: err_to_string — code %d returned empty\n", codes[i]);
            failures++;
            return;
        }
    }

    /* Distinct strings for distinct codes (except the fallthrough default). */
    for (size_t i = 0; i < n; ++i) {
        for (size_t j = i + 1; j < n; ++j) {
            if (strcmp(mweb_err_to_string(codes[i]),
                       mweb_err_to_string(codes[j])) == 0) {
                printf("FAIL: err_to_string — codes %d and %d share message\n",
                    codes[i], codes[j]);
                failures++;
                return;
            }
        }
    }

    printf("PASS: err_to_string_covers_all_codes\n");
}

static void test_null_guards(void)
{
    /* Every query helper tolerates a NULL session. */
    if (mweb_session_pegout_count(NULL) != 0) {
        printf("FAIL: null_guards — pegout_count\n");
        failures++;
        return;
    }
    if (mweb_session_has_pegin(NULL)) {
        printf("FAIL: null_guards — has_pegin\n");
        failures++;
        return;
    }
    if (mweb_session_pegin_amount(NULL) != 0) {
        printf("FAIL: null_guards — pegin_amount\n");
        failures++;
        return;
    }
    if (mweb_session_total_fee(NULL) != 0) {
        printf("FAIL: null_guards — total_fee\n");
        failures++;
        return;
    }
    if (mweb_session_num_mweb_outputs(NULL) != 0
        || mweb_session_num_mweb_inputs(NULL) != 0) {
        printf("FAIL: null_guards — num_inputs/outputs\n");
        failures++;
        return;
    }

    uint64_t v = 0;
    if (mweb_session_get_output_value(NULL, 0, &v) != MWEB_ERR_INTERNAL) {
        printf("FAIL: null_guards — get_output_value NULL session\n");
        failures++;
        return;
    }

    uint64_t amt = 0;
    const uint8_t *scr = NULL;
    size_t slen = 0;
    size_t kidx = 0;
    if (mweb_session_get_pegout(NULL, 0, &amt, &scr, &slen, &kidx)
            != MWEB_ERR_INTERNAL) {
        printf("FAIL: null_guards — get_pegout NULL session\n");
        failures++;
        return;
    }

    /* Abort on NULL session is a no-op (no crash). */
    mweb_session_abort(NULL, NULL);

    /* mark_pegout_confirmed on NULL session is a no-op. */
    mweb_session_mark_pegout_confirmed(NULL, 0);

    printf("PASS: null_guards\n");
}

static void test_begin_rejects_bad_inputs(void)
{
    mweb_session_t* s = (void*)0xdeadbeef;

    /* NULL psbt → MWEB_ERR_INTERNAL, out_session must be cleared. */
    if (mweb_session_begin(NULL, 0, &s) != MWEB_ERR_INTERNAL) {
        printf("FAIL: begin_bad_inputs — NULL psbt\n");
        failures++;
        return;
    }
    if (s != NULL) {
        printf("FAIL: begin_bad_inputs — NULL psbt did not clear out_session\n");
        failures++;
        return;
    }

    /* NULL out_session → MWEB_ERR_INTERNAL. */
    struct wally_psbt dummy;
    memset(&dummy, 0, sizeof(dummy));
    if (mweb_session_begin(&dummy, 0, NULL) != MWEB_ERR_INTERNAL) {
        printf("FAIL: begin_bad_inputs — NULL out_session\n");
        failures++;
        return;
    }

    printf("PASS: begin_bad_inputs\n");
}

static void test_begin_rejects_missing_kernel(void)
{
    /* Allocate a PSBTv2 with zero MWEB kernels. */
    struct wally_psbt* psbt = NULL;
    if (wally_psbt_init_alloc(2, 0, 0, 0, 0, &psbt) != WALLY_OK || !psbt) {
        printf("FAIL: missing_kernel — wally_psbt_init_alloc\n");
        failures++;
        return;
    }

    mweb_session_t* s = NULL;
    mweb_err_t err = mweb_session_begin(psbt, (uint8_t)NETWORK_LITECOIN, &s);
    if (err != MWEB_ERR_MISSING_KERNEL) {
        printf("FAIL: missing_kernel — expected %d got %d\n",
            MWEB_ERR_MISSING_KERNEL, err);
        failures++;
        wally_psbt_free(psbt);
        return;
    }
    if (s != NULL) {
        printf("FAIL: missing_kernel — session not cleared on error\n");
        failures++;
        wally_psbt_free(psbt);
        return;
    }

    wally_psbt_free(psbt);
    printf("PASS: missing_kernel\n");
}

/*
 * Multi-kernel PSBTs are rejected in v1. psbt_kernels_free() guards on
 * `kernels != NULL`, so we can safely assert num_mweb_kernels>1 with a
 * NULL mweb_kernels pointer for this count-only test — the begin path
 * returns the error before it dereferences mweb_kernels[0], and free
 * is a no-op under the NULL guard.
 */
static void test_begin_rejects_multi_kernel(void)
{
    struct wally_psbt* psbt = NULL;
    if (wally_psbt_init_alloc(2, 0, 0, 0, 0, &psbt) != WALLY_OK || !psbt) {
        printf("FAIL: multi_kernel — wally_psbt_init_alloc\n");
        failures++;
        return;
    }

    psbt->num_mweb_kernels = 2;
    /* mweb_kernels stays NULL; psbt_kernels_free's if-guard handles it. */

    mweb_session_t* s = NULL;
    mweb_err_t err = mweb_session_begin(psbt, (uint8_t)NETWORK_LITECOIN, &s);
    if (err != MWEB_ERR_MULTI_KERNEL_UNSUPPORTED) {
        printf("FAIL: multi_kernel — expected %d got %d\n",
            MWEB_ERR_MULTI_KERNEL_UNSUPPORTED, err);
        failures++;
        wally_psbt_free(psbt);
        return;
    }
    if (s != NULL) {
        printf("FAIL: multi_kernel — session not cleared on error\n");
        failures++;
        wally_psbt_free(psbt);
        return;
    }

    wally_psbt_free(psbt);
    printf("PASS: multi_kernel_rejected\n");
}

/*
 * MWEB is Litecoin-only. A non-Litecoin network id MUST be rejected
 * at begin-time so the caller cannot build and commit an MWEB kernel
 * while the UI path (which is gated on the same network check) is
 * silently skipped.
 */
static void test_begin_rejects_non_litecoin(void)
{
    struct wally_psbt* psbt = NULL;
    if (wally_psbt_init_alloc(2, 0, 0, 0, 0, &psbt) != WALLY_OK || !psbt) {
        printf("FAIL: non_litecoin — wally_psbt_init_alloc\n");
        failures++;
        return;
    }
    /* A single MWEB kernel so the reject can't trip on kernel count. */
    psbt->num_mweb_kernels = 1;

    const network_t foreign[] = {
        NETWORK_BITCOIN, NETWORK_BITCOIN_TESTNET, NETWORK_BITCOIN_REGTEST,
        NETWORK_LIQUID,  NETWORK_LIQUID_TESTNET,  NETWORK_LIQUID_REGTEST,
    };
    for (size_t i = 0; i < sizeof(foreign) / sizeof(foreign[0]); ++i) {
        mweb_session_t* s = NULL;
        mweb_err_t err = mweb_session_begin(psbt, (uint8_t)foreign[i], &s);
        if (err != MWEB_ERR_UNSUPPORTED_NETWORK) {
            printf("FAIL: non_litecoin — network %u got %d\n",
                (unsigned)foreign[i], err);
            failures++;
            psbt->num_mweb_kernels = 0;
            wally_psbt_free(psbt);
            return;
        }
        if (s != NULL) {
            printf("FAIL: non_litecoin — session not cleared for network %u\n",
                (unsigned)foreign[i]);
            failures++;
            psbt->num_mweb_kernels = 0;
            wally_psbt_free(psbt);
            return;
        }
    }

    /* NETWORK_LITECOIN itself gets past the network check and lands on
     * a later error (here: multi-kernel not wired), proving the gate is
     * network-specific rather than a blanket reject. */
    psbt->num_mweb_kernels = 2;
    mweb_session_t* s = NULL;
    mweb_err_t err = mweb_session_begin(psbt, (uint8_t)NETWORK_LITECOIN, &s);
    if (err != MWEB_ERR_MULTI_KERNEL_UNSUPPORTED) {
        printf("FAIL: non_litecoin — litecoin should proceed past net check, got %d\n", err);
        failures++;
        psbt->num_mweb_kernels = 0;
        wally_psbt_free(psbt);
        return;
    }

    psbt->num_mweb_kernels = 0;
    wally_psbt_free(psbt);
    printf("PASS: non_litecoin_rejected\n");
}

/*
 * ── Helpers for kernel-field rejection tests ──────────────────────────
 *
 * These tests exercise the kernel validation path (MoneyRange on fee /
 * pegin / pegouts, pegout script type classifier). They construct a
 * PSBTv2 with zero inputs + zero outputs and one in-tree wally_psbt_kernel
 * populated directly — the input/output loops are no-ops so the session
 * reaches the kernel block under test.
 */
#define MWEB_TEST_LTC_MAX_LITOSHI ((uint64_t)84000000 * (uint64_t)100000000)

static void u64_to_le(uint64_t v, uint8_t out[8])
{
    for (int i = 0; i < 8; ++i) {
        out[i] = (uint8_t)(v >> (i * 8));
    }
}

/*
 * Build a pegout map entry payload: 8-byte LE amount || varint script_len
 * || script. `script_len` fits in a single-byte varint for test data we
 * use (< 0xfd bytes), keeping the writer trivial.
 */
static size_t build_pegout_value(uint64_t amount,
                                 const uint8_t *script, size_t script_len,
                                 uint8_t *buf, size_t buf_cap)
{
    if (script_len >= 0xfd || buf_cap < 8 + 1 + script_len) {
        return 0;
    }
    u64_to_le(amount, buf);
    buf[8] = (uint8_t)script_len;
    memcpy(buf + 9, script, script_len);
    return 8 + 1 + script_len;
}

/*
 * Run session_begin against an empty PSBT holding a single, stack-owned
 * kernel populated by `prepare`. Asserts the returned mweb_err_t matches
 * `expected_err`. Handles the kernel-pointer bookkeeping so psbt_free
 * never touches the stack buffer.
 */
static void run_kernel_reject_case(const char *tag,
                                    void (*prepare)(struct wally_psbt_kernel *),
                                    mweb_err_t expected_err)
{
    struct wally_psbt *psbt = NULL;
    if (wally_psbt_init_alloc(2, 0, 0, 0, 0, &psbt) != WALLY_OK || !psbt) {
        printf("FAIL: %s — wally_psbt_init_alloc\n", tag);
        failures++;
        return;
    }

    struct wally_psbt_kernel kernel;
    memset(&kernel, 0, sizeof(kernel));
    prepare(&kernel);

    psbt->mweb_kernels = &kernel;
    psbt->num_mweb_kernels = 1;
    psbt->mweb_kernels_allocation_len = 0; /* We own the buffer, libwally must not free it. */

    mweb_session_t *s = NULL;
    mweb_err_t err = mweb_session_begin(psbt, (uint8_t)NETWORK_LITECOIN, &s);

    /* Tear the borrowed kernel out of the PSBT before libwally frees it. */
    psbt->mweb_kernels = NULL;
    psbt->num_mweb_kernels = 0;
    wally_map_clear(&kernel.pegouts);
    wally_map_clear(&kernel.unknowns);

    wally_psbt_free(psbt);

    if (err != expected_err) {
        printf("FAIL: %s — expected %d got %d\n", tag, expected_err, err);
        failures++;
        return;
    }
    if (s != NULL) {
        printf("FAIL: %s — session not cleared\n", tag);
        failures++;
        return;
    }
    printf("PASS: %s\n", tag);
}

/* Feature bits mirror main/mweb/mweb_kernel.h. Copied locally so the test
 * is independent of that header's include chain. */
#define MWEB_TEST_FEE_BIT             0x01
#define MWEB_TEST_PEGIN_BIT           0x02
#define MWEB_TEST_PEGOUT_BIT          0x04
#define MWEB_TEST_STEALTH_EXCESS_BIT  0x10

static void prep_fee_out_of_range(struct wally_psbt_kernel *k)
{
    k->has_fee = 1;
    k->fee = MWEB_TEST_LTC_MAX_LITOSHI + 1;
    k->has_features = 1;
    k->features = MWEB_TEST_FEE_BIT;
}

static void prep_pegin_out_of_range(struct wally_psbt_kernel *k)
{
    k->has_pegin_amount = 1;
    k->pegin_amount = MWEB_TEST_LTC_MAX_LITOSHI + 1;
    k->has_features = 1;
    k->features = MWEB_TEST_PEGIN_BIT;
}

static void prep_pegout_amount_out_of_range(struct wally_psbt_kernel *k)
{
    /* P2WPKH-shaped script so the pegout-script classifier accepts it;
     * the rejection must come from the amount MoneyRange check. */
    static const uint8_t p2wpkh[22] = {
        0x00, 0x14,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
        0x11, 0x22, 0x33, 0x44,
    };
    static uint8_t pegout_buf[32];
    const size_t n = build_pegout_value(
        MWEB_TEST_LTC_MAX_LITOSHI + 1, p2wpkh, sizeof(p2wpkh),
        pegout_buf, sizeof(pegout_buf));
    if (n == 0) { return; }

    wally_map_init(1, NULL, &k->pegouts);
    wally_map_add_integer(&k->pegouts, 0, pegout_buf, n);
    k->has_features = 1;
    k->features = MWEB_TEST_PEGOUT_BIT;
}

static void prep_pegout_unknown_script(struct wally_psbt_kernel *k)
{
    /* A single OP_0 byte is not a P2PKH / P2SH / P2WPKH / P2WSH / P2TR
     * script, so wally_scriptpubkey_get_type classifies it as UNKNOWN
     * and the pegout classifier MUST reject. */
    static const uint8_t unknown_script[1] = { 0x00 };
    static uint8_t pegout_buf[32];
    const size_t n = build_pegout_value(
        1000, unknown_script, sizeof(unknown_script),
        pegout_buf, sizeof(pegout_buf));
    if (n == 0) { return; }

    wally_map_init(1, NULL, &k->pegouts);
    wally_map_add_integer(&k->pegouts, 0, pegout_buf, n);
    k->has_features = 1;
    k->features = MWEB_TEST_PEGOUT_BIT;
}

static void test_money_range_fee_rejected(void)
{
    run_kernel_reject_case("money_range_fee_rejected",
        prep_fee_out_of_range, MWEB_ERR_BALANCE_FAIL);
}

static void test_money_range_pegin_rejected(void)
{
    run_kernel_reject_case("money_range_pegin_rejected",
        prep_pegin_out_of_range, MWEB_ERR_BALANCE_FAIL);
}

static void test_money_range_pegout_amount_rejected(void)
{
    run_kernel_reject_case("money_range_pegout_amount_rejected",
        prep_pegout_amount_out_of_range, MWEB_ERR_BALANCE_FAIL);
}

static void test_pegout_unknown_script_rejected(void)
{
    run_kernel_reject_case("pegout_unknown_script_rejected",
        prep_pegout_unknown_script, MWEB_ERR_KERNEL_FEATURE_MISMATCH);
}

/*
 * Abort on a never-begun session is a no-op; callers use this idiom in
 * the cleanup path after a `goto cleanup` that occurred before any
 * mweb_session_begin() call completed.
 */
static void test_abort_null_session_no_crash(void)
{
    mweb_session_abort(NULL, NULL);

    /* Also safe with a non-NULL psbt but NULL session. */
    struct wally_psbt* psbt = NULL;
    if (wally_psbt_init_alloc(2, 0, 0, 0, 0, &psbt) != WALLY_OK || !psbt) {
        printf("FAIL: abort_null — wally_psbt_init_alloc\n");
        failures++;
        return;
    }
    mweb_session_abort(NULL, psbt);
    wally_psbt_free(psbt);
    printf("PASS: abort_null_session_no_crash\n");
}

/*
 * ── Session-lifecycle regression tests ─────────────────────────────────
 *
 * Drive mweb_session_begin/commit/abort against stack-owned kernels and
 * (optionally) stack-owned inputs without needing a UI mock, PSBT
 * serialiser, or end-to-end host-driven fixture. Cover the session-
 * level invariants that hold the bind-then-sign boundary together:
 * standard→MWEB gating, rollback byte-equality, the pegout
 * confirmation loop, shared-secret bypass rejection.
 */

/* Snapshot of every PSBT byte Jade may mutate inside a session. A passing
 * rollback test asserts these are byte-identical pre-begin and post-abort
 * (or post-commit-failure). */
typedef struct {
    uint32_t has_tx_offset;
    uint8_t  tx_offset[32];
    uint32_t has_stealth_offset;
    uint8_t  stealth_offset[32];
    uint32_t kernel_has_excess;
    uint8_t  kernel_excess[33];
    uint32_t kernel_has_stealth_excess;
    uint8_t  kernel_stealth_excess[33];
    uint32_t kernel_has_signature;
    uint8_t  kernel_signature[64];
} psbt_mweb_snapshot_t;

static void snapshot_psbt_mweb(const struct wally_psbt *psbt,
                                const struct wally_psbt_kernel *k,
                                psbt_mweb_snapshot_t *snap)
{
    snap->has_tx_offset      = psbt->has_mweb_tx_offset;
    memcpy(snap->tx_offset,      psbt->mweb_tx_offset,      32);
    snap->has_stealth_offset = psbt->has_mweb_stealth_offset;
    memcpy(snap->stealth_offset, psbt->mweb_stealth_offset, 32);
    snap->kernel_has_excess          = k->has_excess_commitment;
    memcpy(snap->kernel_excess,          k->excess_commitment, 33);
    snap->kernel_has_stealth_excess  = k->has_stealth_excess;
    memcpy(snap->kernel_stealth_excess,  k->stealth_excess,    33);
    snap->kernel_has_signature       = k->has_signature;
    memcpy(snap->kernel_signature,       k->signature,         64);
}

static bool snapshots_equal(const psbt_mweb_snapshot_t *a,
                             const psbt_mweb_snapshot_t *b)
{
    /* Compare field-by-field: memcmp over the whole struct would
     * include padding bytes between the uint32_t flags and the
     * trailing arrays, which the compiler is free to leave
     * uninitialised. */
    return a->has_tx_offset           == b->has_tx_offset
        && memcmp(a->tx_offset,          b->tx_offset,          32) == 0
        && a->has_stealth_offset      == b->has_stealth_offset
        && memcmp(a->stealth_offset,     b->stealth_offset,     32) == 0
        && a->kernel_has_excess       == b->kernel_has_excess
        && memcmp(a->kernel_excess,      b->kernel_excess,      33) == 0
        && a->kernel_has_stealth_excess == b->kernel_has_stealth_excess
        && memcmp(a->kernel_stealth_excess, b->kernel_stealth_excess, 33) == 0
        && a->kernel_has_signature    == b->kernel_has_signature
        && memcmp(a->kernel_signature,   b->kernel_signature,   64) == 0;
}

/*
 * Seed g_test_random with a non-zero canonical scalar so
 * mweb_sign_kernel's TRNG retry loop picks up a valid e_k on the
 * first try. Zero-seeded TRNG fails mweb_validate_scalar and surfaces
 * as MWEB_ERR_INTERNAL.
 */
static void seed_trng_nonzero(uint8_t byte)
{
    memset(g_test_random, byte ? byte : 0x01, sizeof(g_test_random));
}

/* Balanced fee-only kernel (0 pegin, 0 pegout, 0 fee). Exercises the
 * happy path for a PSBT whose `has_mweb` gate fires solely on the
 * presence of a kernel — standard→MWEB sends shaped this way must
 * reach the kernel-sign step. */
static void prep_valid_fee_only(struct wally_psbt_kernel *k)
{
    k->has_fee = 1;
    k->fee = 0;
    k->has_features = 1;
    k->features = MWEB_TEST_FEE_BIT;
}

/*
 * Balanced single-pegout kernel: pegin covers fee + pegout. No MWEB
 * inputs or outputs, so the balance equation is:
 *   0 + pegin_amount == 0 + fee + pegout_total
 */
static const uint8_t P2WPKH_PEGOUT_SCRIPT[22] = {
    0x00, 0x14,
    0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11,
    0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
    0xaa, 0xbb, 0xcc, 0xdd,
};
#define PEGOUT_AMOUNT   ((uint64_t)500000)
#define PEGOUT_FEE      ((uint64_t)1000)
#define PEGOUT_PEGIN    (PEGOUT_AMOUNT + PEGOUT_FEE)

/* Pegout map entry buffer lives at file scope so it outlives the
 * borrowed-kernel teardown. wally_map_add copies the bytes internally, but
 * we reuse the buffer across tests so using file scope is cleanest. */
static uint8_t g_pegout_value_buf[32];

static void prep_valid_pegout(struct wally_psbt_kernel *k)
{
    const size_t n = build_pegout_value(
        PEGOUT_AMOUNT,
        P2WPKH_PEGOUT_SCRIPT, sizeof(P2WPKH_PEGOUT_SCRIPT),
        g_pegout_value_buf, sizeof(g_pegout_value_buf));
    if (n == 0) {
        return;  /* build_pegout_value failed; the session will reject */
    }
    wally_map_init(1, NULL, &k->pegouts);
    wally_map_add_integer(&k->pegouts, 0, g_pegout_value_buf, n);
    k->has_fee = 1;
    k->fee = PEGOUT_FEE;
    k->has_pegin_amount = 1;
    k->pegin_amount = PEGOUT_PEGIN;
    k->has_features = 1;
    k->features = MWEB_TEST_FEE_BIT | MWEB_TEST_PEGIN_BIT | MWEB_TEST_PEGOUT_BIT;
}

/*
 * Standard→MWEB gate. A PSBT with zero MWEB inputs, zero MWEB outputs,
 * and a single valid kernel must be accepted by session_begin and
 * committed successfully — this is the shape a pure standard-to-MWEB
 * send takes once the has_mweb widening fires.
 */
static void test_standard_to_mweb_session_commit_ok(void)
{
    struct wally_psbt *psbt = NULL;
    if (wally_psbt_init_alloc(2, 0, 0, 0, 0, &psbt) != WALLY_OK || !psbt) {
        printf("FAIL: std_to_mweb — wally_psbt_init_alloc\n");
        failures++;
        return;
    }

    struct wally_psbt_kernel kernel;
    memset(&kernel, 0, sizeof(kernel));
    prep_valid_fee_only(&kernel);

    psbt->mweb_kernels = &kernel;
    psbt->num_mweb_kernels = 1;
    psbt->mweb_kernels_allocation_len = 0;

    psbt_mweb_snapshot_t pre;
    snapshot_psbt_mweb(psbt, &kernel, &pre);

    seed_trng_nonzero(0x42);
    mweb_session_t *s = NULL;
    mweb_err_t err = mweb_session_begin(psbt, (uint8_t)NETWORK_LITECOIN, &s);

    bool ok = true;
    if (err != MWEB_OK) {
        printf("FAIL: std_to_mweb — begin returned %d\n", err);
        ok = false;
    } else if (!s) {
        printf("FAIL: std_to_mweb — session was NULL on success\n");
        ok = false;
    }

    /* Nothing to confirm (no pegouts). Commit should succeed and write
     * kernel signature + offsets into the PSBT. */
    if (ok) {
        err = mweb_session_commit(s, psbt);
        if (err != MWEB_OK) {
            printf("FAIL: std_to_mweb — commit returned %d\n", err);
            ok = false;
        }
    }

    /* Post-commit: kernel has excess + signature + offsets populated. */
    if (ok) {
        if (!kernel.has_excess_commitment
            || !kernel.has_signature
            || !psbt->has_mweb_tx_offset
            || !psbt->has_mweb_stealth_offset) {
            printf("FAIL: std_to_mweb — expected fields not written post-commit\n");
            ok = false;
        }
        /* Excess must be a valid Pedersen commitment (0x08/0x09 prefix). */
        if (ok && kernel.excess_commitment[0] != 0x08
               && kernel.excess_commitment[0] != 0x09) {
            printf("FAIL: std_to_mweb — excess prefix 0x%02x\n",
                   kernel.excess_commitment[0]);
            ok = false;
        }
        /* Signature must be non-zero. */
        uint8_t zero_sig[64] = {0};
        if (ok && memcmp(kernel.signature, zero_sig, 64) == 0) {
            printf("FAIL: std_to_mweb — signature is all-zero\n");
            ok = false;
        }
        /* Fields must differ from pre-begin snapshot (we actually wrote). */
        psbt_mweb_snapshot_t post;
        snapshot_psbt_mweb(psbt, &kernel, &post);
        if (ok && snapshots_equal(&pre, &post)) {
            printf("FAIL: std_to_mweb — commit left PSBT byte-identical\n");
            ok = false;
        }
    }

    psbt->mweb_kernels = NULL;
    psbt->num_mweb_kernels = 0;
    wally_map_clear(&kernel.pegouts);
    wally_map_clear(&kernel.unknowns);
    wally_psbt_free(psbt);

    if (ok) {
        printf("PASS: standard_to_mweb_session_commit_ok\n");
    } else {
        failures++;
    }
}

/*
 * Rollback byte-equality on a pre-kernel-sign reject. Forces the
 * session to reject on kernel MoneyRange (fee out of range), then
 * asserts every PSBT byte Jade could have touched is unchanged.
 */
static void test_rollback_byte_equal_on_reject(void)
{
    struct wally_psbt *psbt = NULL;
    if (wally_psbt_init_alloc(2, 0, 0, 0, 0, &psbt) != WALLY_OK || !psbt) {
        printf("FAIL: rollback_reject — wally_psbt_init_alloc\n");
        failures++;
        return;
    }

    struct wally_psbt_kernel kernel;
    memset(&kernel, 0, sizeof(kernel));
    prep_fee_out_of_range(&kernel);

    psbt->mweb_kernels = &kernel;
    psbt->num_mweb_kernels = 1;
    psbt->mweb_kernels_allocation_len = 0;

    /* Seed one byte on every mutable field so "still zero" isn't a
     * tautological pass — a rollback bug that silently zeros fields
     * would now show up as a diff. */
    psbt->has_mweb_tx_offset = 1;
    memset(psbt->mweb_tx_offset, 0xA5, 32);
    psbt->has_mweb_stealth_offset = 1;
    memset(psbt->mweb_stealth_offset, 0x5A, 32);
    kernel.has_excess_commitment = 1;
    memset(kernel.excess_commitment, 0x11, 33);
    kernel.has_signature = 1;
    memset(kernel.signature, 0x22, 64);
    kernel.has_stealth_excess = 0;
    memset(kernel.stealth_excess, 0x33, 33);

    psbt_mweb_snapshot_t pre;
    snapshot_psbt_mweb(psbt, &kernel, &pre);

    mweb_session_t *s = NULL;
    mweb_err_t err = mweb_session_begin(psbt, (uint8_t)NETWORK_LITECOIN, &s);

    psbt_mweb_snapshot_t post;
    snapshot_psbt_mweb(psbt, &kernel, &post);

    psbt->mweb_kernels = NULL;
    psbt->num_mweb_kernels = 0;
    wally_map_clear(&kernel.pegouts);
    wally_map_clear(&kernel.unknowns);
    wally_psbt_free(psbt);

    if (err != MWEB_ERR_BALANCE_FAIL) {
        printf("FAIL: rollback_reject — expected BALANCE_FAIL got %d\n", err);
        failures++;
        return;
    }
    if (s != NULL) {
        printf("FAIL: rollback_reject — session leaked on reject\n");
        failures++;
        return;
    }
    if (!snapshots_equal(&pre, &post)) {
        printf("FAIL: rollback_reject — PSBT mutated during rejected begin\n");
        failures++;
        return;
    }
    printf("PASS: rollback_byte_equal_on_reject\n");
}

/*
 * A session with an unconfirmed pegout MUST return
 * PEGOUTS_NOT_DISPLAYED from commit, and rollback leaves the PSBT
 * byte-identical to its pre-begin state. Defence-in-depth against a
 * UI regression that silently skips the pegout loop and still calls
 * commit.
 */
static void test_pegout_flow_skipped_rejects_and_rolls_back(void)
{
    struct wally_psbt *psbt = NULL;
    if (wally_psbt_init_alloc(2, 0, 0, 0, 0, &psbt) != WALLY_OK || !psbt) {
        printf("FAIL: pegout_skipped — wally_psbt_init_alloc\n");
        failures++;
        return;
    }

    struct wally_psbt_kernel kernel;
    memset(&kernel, 0, sizeof(kernel));
    prep_valid_pegout(&kernel);

    psbt->mweb_kernels = &kernel;
    psbt->num_mweb_kernels = 1;
    psbt->mweb_kernels_allocation_len = 0;

    psbt_mweb_snapshot_t pre;
    snapshot_psbt_mweb(psbt, &kernel, &pre);

    seed_trng_nonzero(0x42);
    mweb_session_t *s = NULL;
    mweb_err_t err = mweb_session_begin(psbt, (uint8_t)NETWORK_LITECOIN, &s);

    bool ok = true;
    if (err != MWEB_OK || !s) {
        printf("FAIL: pegout_skipped — begin returned %d\n", err);
        ok = false;
    }

    if (ok && mweb_session_pegout_count(s) != 1) {
        printf("FAIL: pegout_skipped — pegout_count != 1\n");
        ok = false;
    }

    /* Query the pegout entry back — mirrors what the UI layer does. */
    if (ok) {
        uint64_t amount = 0;
        const uint8_t *script = NULL;
        size_t script_len = 0;
        size_t kernel_idx = SIZE_MAX;
        mweb_err_t qerr = mweb_session_get_pegout(s, 0, &amount, &script,
                                                   &script_len, &kernel_idx);
        if (qerr != MWEB_OK
            || amount != PEGOUT_AMOUNT
            || script_len != sizeof(P2WPKH_PEGOUT_SCRIPT)
            || memcmp(script, P2WPKH_PEGOUT_SCRIPT, script_len) != 0
            || kernel_idx != 0) {
            printf("FAIL: pegout_skipped — get_pegout mismatch\n");
            ok = false;
        }
    }

    /* Commit WITHOUT marking the pegout confirmed. Must reject and
     * roll back to pre-begin state. */
    if (ok) {
        err = mweb_session_commit(s, psbt);
        if (err != MWEB_ERR_PEGOUTS_NOT_DISPLAYED) {
            printf("FAIL: pegout_skipped — commit returned %d, expected PEGOUTS_NOT_DISPLAYED\n", err);
            ok = false;
        }
    }

    if (ok) {
        psbt_mweb_snapshot_t post;
        snapshot_psbt_mweb(psbt, &kernel, &post);
        if (!snapshots_equal(&pre, &post)) {
            printf("FAIL: pegout_skipped — rollback did not restore PSBT\n");
            ok = false;
        }
    }

    psbt->mweb_kernels = NULL;
    psbt->num_mweb_kernels = 0;
    wally_map_clear(&kernel.pegouts);
    wally_map_clear(&kernel.unknowns);
    wally_psbt_free(psbt);

    if (ok) {
        printf("PASS: pegout_flow_skipped_rejects_and_rolls_back\n");
    } else {
        failures++;
    }
}

/*
 * Pegout happy path: after the UI marks the pegout confirmed, commit
 * succeeds and the PSBT carries the final kernel signature + offsets.
 */
static void test_pegout_flow_marked_commits_ok(void)
{
    struct wally_psbt *psbt = NULL;
    if (wally_psbt_init_alloc(2, 0, 0, 0, 0, &psbt) != WALLY_OK || !psbt) {
        printf("FAIL: pegout_ok — wally_psbt_init_alloc\n");
        failures++;
        return;
    }

    struct wally_psbt_kernel kernel;
    memset(&kernel, 0, sizeof(kernel));
    prep_valid_pegout(&kernel);

    psbt->mweb_kernels = &kernel;
    psbt->num_mweb_kernels = 1;
    psbt->mweb_kernels_allocation_len = 0;

    seed_trng_nonzero(0x42);
    mweb_session_t *s = NULL;
    mweb_err_t err = mweb_session_begin(psbt, (uint8_t)NETWORK_LITECOIN, &s);

    bool ok = true;
    if (err != MWEB_OK || !s) {
        printf("FAIL: pegout_ok — begin returned %d\n", err);
        ok = false;
    }

    if (ok) {
        mweb_session_mark_pegout_confirmed(s, 0);
        err = mweb_session_commit(s, psbt);
        if (err != MWEB_OK) {
            printf("FAIL: pegout_ok — commit returned %d\n", err);
            ok = false;
        }
    }

    if (ok) {
        if (!kernel.has_excess_commitment
            || !kernel.has_signature
            || !psbt->has_mweb_tx_offset
            || !psbt->has_mweb_stealth_offset) {
            printf("FAIL: pegout_ok — expected fields not written\n");
            ok = false;
        }
    }

    psbt->mweb_kernels = NULL;
    psbt->num_mweb_kernels = 0;
    wally_map_clear(&kernel.pegouts);
    wally_map_clear(&kernel.unknowns);
    wally_psbt_free(psbt);

    if (ok) {
        printf("PASS: pegout_flow_marked_commits_ok\n");
    } else {
        failures++;
    }
}

/*
 * A PSBT whose MWEB input exposes MWEB_IN_SHARED_SECRET (0x98) must
 * be rejected with MWEB_ERR_FOREIGN_MWEB_INPUT. The 0x98 bypass is
 * treated as an unsupported legacy shape; no further host-supplied
 * data is processed.
 *
 * Only the 0x98 + 0x90 (OUTPUT_ID) keyset bits are needed — the
 * keyset check is the first thing derive_owned_input looks at, and
 * the 0x90 bit is what makes session_begin's input loop route through
 * derive_owned_input at all. No keypath origins or fingerprint data
 * required.
 */
static void test_shared_secret_bypass_rejected(void)
{
    const uint32_t MWEB_IN_MIN_KEY_LOCAL = 0x90;
    #define MWEB_IN_BIT_LOCAL(k) (1u << ((k) - MWEB_IN_MIN_KEY_LOCAL))

    struct wally_psbt *psbt = NULL;
    if (wally_psbt_init_alloc(2, 1, 0, 0, 0, &psbt) != WALLY_OK || !psbt) {
        printf("FAIL: ss_bypass — wally_psbt_init_alloc\n");
        failures++;
        return;
    }
    /* init_alloc sets capacity but leaves num_inputs at 0. Bump it so
     * mweb_session_begin iterates the zeroed input slot we're about to
     * stamp the bypass bits onto. */
    psbt->num_inputs = 1;

    /* OUTPUT_ID bit routes the input into derive_owned_input; the
     * SHARED_SECRET bit trips the bypass reject on the first check. */
    psbt->inputs[0].mweb_keyset
        = MWEB_IN_BIT_LOCAL(0x90)   /* OUTPUT_ID */
        | MWEB_IN_BIT_LOCAL(0x98);  /* SHARED_SECRET */

    struct wally_psbt_kernel kernel;
    memset(&kernel, 0, sizeof(kernel));
    prep_valid_fee_only(&kernel);
    psbt->mweb_kernels = &kernel;
    psbt->num_mweb_kernels = 1;
    psbt->mweb_kernels_allocation_len = 0;

    mweb_session_t *s = NULL;
    mweb_err_t err = mweb_session_begin(psbt, (uint8_t)NETWORK_LITECOIN, &s);

    bool ok = (err == MWEB_ERR_FOREIGN_MWEB_INPUT) && (s == NULL);
    if (!ok) {
        printf("FAIL: ss_bypass — got err=%d session=%p, expected FOREIGN_MWEB_INPUT + NULL\n",
               err, (void*)s);
    }

    /* Clear keyset so psbt_free doesn't try to free non-owned fields. */
    psbt->inputs[0].mweb_keyset = 0;
    psbt->mweb_kernels = NULL;
    psbt->num_mweb_kernels = 0;
    wally_map_clear(&kernel.pegouts);
    wally_map_clear(&kernel.unknowns);
    wally_psbt_free(psbt);

    if (ok) {
        printf("PASS: shared_secret_bypass_rejected\n");
    } else {
        failures++;
    }

    #undef MWEB_IN_BIT_LOCAL
}

/*
 * ── Owned MWEB input + real MWEB output fixtures ───────────────────────
 *
 * build_owned_mweb_input() populates a PSBT input whose fingerprint /
 * path origins match the stubs' wallet identity and whose
 * spent_output_pubkey / spent_output_commit / key_exchange_pubkey
 * values are derived from the same test scan/spend keys the stub
 * returns. The input therefore round-trips through derive_owned_input
 * → mweb_derive_input_state → (at commit) mweb_sign_input_from_state.
 *
 * build_mweb_output() populates a PSBT output with every field the
 * recipient-binding derivation reproduces (stealth address, commit,
 * sender+output+key-exchange pubkeys, standard-fields tuple), all
 * derived from a host-chosen senderKey via mweb_derive_output. The
 * session's verification phase then either accepts (fields match) or
 * returns MWEB_ERR_OUTPUT_FIELD_MISMATCH (any tamper).
 *
 * We cannot unit-test sign_psbt.c's has_mweb gate itself without
 * rewriting a ~2000-line process function; the host-driven
 * test_ltc_psbt.py covers the gate end-to-end. The session-level path
 * exercised here is the only thing that gate routes into, so a
 * regression that stops routing to mweb_session_begin is still caught
 * upstream the moment any MWEB PSBT reaches the device.
 */

#define OWNED_INPUT_AMOUNT ((uint64_t)100000000)

/*
 * Build a single owned MWEB input (no standard input, one kernel) and
 * stamp every required MWEB field into psbt->inputs[0]. Fixtures are
 * generated using the firmware's own primitives, so any drift in the
 * BLAKE3 / Pedersen / BlindSwitch math also shows up as a fixture
 * mismatch (catch drift at source).
 *
 * kex_secret_in: a non-zero 32-byte scalar acting as the "sender's"
 * ephemeral used to construct K_e = kex_secret * G. For the happy path
 * it can be anything; for the mismatch test we pass it to force a
 * non-zero key_exchange_pubkey that Jade will ECDH against.
 *
 * On success:
 *   - psbt->inputs[0] is populated with every MWEB_IN_* field Jade reads
 *   - psbt->num_inputs is bumped to 1
 *   - `out_commit` receives the derived spent_output_commit (33B) for
 *     the caller to optionally tamper before calling session_begin.
 */
static bool build_owned_mweb_input(
    struct wally_psbt *psbt,
    const uint8_t kex_secret_in[32],
    uint8_t out_commit[33])
{
    const secp256k1_context *ctx = wally_get_secp_context();
    if (!ctx) return false;

    struct wally_psbt_input *pi = &psbt->inputs[0];

    /* wally_psbt_init_alloc only allocates the inputs array; it does
     * NOT call psbt_input_init. That means the embedded MWEB origin maps
     * have verify_fn == NULL, and wally_map_keypath_add rejects them
     * with WALLY_EINVAL. Initialise the two origin maps explicitly so
     * they accept compressed pubkey keys. */
    if (wally_map_init(0, wally_keypath_public_key_verify,
            &pi->mweb_scan_key_origin) != WALLY_OK) return false;
    if (wally_map_init(0, wally_keypath_public_key_verify,
            &pi->mweb_spend_key_origin) != WALLY_OK) return false;

    /* B_i = spend_pub + m_i * G, where m_i = Hashed('A', idx_le || scan). */
    uint8_t mi_buf[4 + 32] = {0};
    memcpy(mi_buf + 4, OWNED_TEST_SCAN_KEY, 32);  /* index = 0 */
    uint8_t m_i[32];
    mweb_hashed(MWEB_TAG_ADDRESS, mi_buf, sizeof(mi_buf), m_i);

    uint8_t spend_pub[33], mi_pub[33];
    if (wally_ec_public_key_from_private_key(OWNED_TEST_SPEND_KEY, 32,
            spend_pub, sizeof(spend_pub)) != WALLY_OK) return false;
    if (wally_ec_public_key_from_private_key(m_i, 32,
            mi_pub, sizeof(mi_pub)) != WALLY_OK) return false;

    secp256k1_pubkey sp_pk, mi_pk, Bi_pk;
    if (!secp256k1_ec_pubkey_parse(ctx, &sp_pk, spend_pub, 33)) return false;
    if (!secp256k1_ec_pubkey_parse(ctx, &mi_pk, mi_pub, 33)) return false;
    const secp256k1_pubkey *pts[2] = { &sp_pk, &mi_pk };
    if (!secp256k1_ec_pubkey_combine(ctx, &Bi_pk, pts, 2)) return false;

    /* K_e = kex_secret * G. */
    uint8_t Ke[33];
    if (wally_ec_public_key_from_private_key(kex_secret_in, 32,
            Ke, sizeof(Ke)) != WALLY_OK) return false;

    /* ss = Hashed('D', compressed(scan_key * K_e)). Receiver-side ECDH. */
    secp256k1_pubkey Ke_pk;
    if (!secp256k1_ec_pubkey_parse(ctx, &Ke_pk, Ke, 33)) return false;
    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &Ke_pk, OWNED_TEST_SCAN_KEY)) return false;
    uint8_t ecdh_bytes[33];
    size_t ecdh_len = 33;
    secp256k1_ec_pubkey_serialize(ctx, ecdh_bytes, &ecdh_len, &Ke_pk,
        SECP256K1_EC_COMPRESSED);
    uint8_t ss[32];
    mweb_hashed(MWEB_TAG_DERIVE, ecdh_bytes, 33, ss);

    /* K_o = Hashed('O', ss) * B_i. */
    uint8_t okh[32];
    mweb_hashed(MWEB_TAG_OUTKEY, ss, 32, okh);
    secp256k1_pubkey Ko_pk = Bi_pk;
    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &Ko_pk, okh)) return false;
    uint8_t Ko[33];
    size_t ko_len = 33;
    secp256k1_ec_pubkey_serialize(ctx, Ko, &ko_len, &Ko_pk,
        SECP256K1_EC_COMPRESSED);

    /* pre_blind = Hashed('B', ss); r_in = BlindSwitch(pre_blind, v);
     * commit = Pedersen(r_in, v) with 0x08/0x09 prefix. */
    uint8_t pre_blind[32];
    mweb_hashed(MWEB_TAG_BLIND, ss, 32, pre_blind);
    uint8_t r_in[32];
    if (!mweb_blind_switch(pre_blind, OWNED_INPUT_AMOUNT, r_in)) return false;
    uint8_t commit[33];
    if (!mweb_pedersen_commit(r_in, OWNED_INPUT_AMOUNT, commit)) return false;

    /* Any 32-byte value works for spent_output_id — mweb_derive_input_state
     * caches it into the state and only hashes it into msg_hash at S6.
     * Use a stable pattern so test output is reproducible. */
    uint8_t spent_output_id[32];
    memset(spent_output_id, 0x5A, 32);

    /* Populate the input struct. */
    memcpy(pi->mweb_spent_output_id,     spent_output_id, 32);
    memcpy(pi->mweb_spent_output_commit, commit,           33);
    memcpy(pi->mweb_spent_output_pubkey, Ko,               33);
    memcpy(pi->mweb_key_exchange_pubkey, Ke,               33);
    pi->mweb_address_index  = 0;
    /* MWEB_INPUT_STEALTH_KEY_BIT (0x01) must be set — mweb_derive_input_state
     * rejects inputs without it as INVALID_PRESIGN_SCALAR (mweb_sign.c:68).
     * The bit says "I hold a stealth key derived from scan+spend", which
     * is the only mode Jade supports in v1. */
    pi->mweb_input_features = 0x01;  /* MWEB_INPUT_STEALTH_KEY_BIT */
    pi->mweb_input_amount   = OWNED_INPUT_AMOUNT;

    /* mweb_keyset — every required on-wire field bit. MWEB_IN_MIN_KEY is
     * 0x90; MWEB_IN_BIT(k) = 1 << (k - 0x90). */
    pi->mweb_keyset
        = (1u << (0x90 - 0x90))   /* SPENT_OUTPUT_ID */
        | (1u << (0x91 - 0x90))   /* SPENT_OUTPUT_COMMIT */
        | (1u << (0x92 - 0x90))   /* SPENT_OUTPUT_PUBKEY */
        | (1u << (0x94 - 0x90))   /* FEATURES */
        | (1u << (0x96 - 0x90))   /* ADDRESS_INDEX */
        | (1u << (0x97 - 0x90))   /* INPUT_AMOUNT */
        | (1u << (0x99 - 0x90));  /* KEY_EXCHANGE_PUBKEY */

    /* Scan / spend keypath origins — match the stub's wallet fingerprint
     * so derive_owned_input's fingerprint check passes. Origin pubkey
     * is arbitrary; the session only reads fingerprint + path.
     *
     * MWEB 0x9A/0x9B origins store the fingerprint in LITTLE-ENDIAN byte
     * order (opposite to the standard BIP32 0x06 keypath convention);
     * mweb_atomic_sign.c reverses wallet_get_fingerprint's BE result to
     * LE before comparing with map bytes. Match that: feed the reversed
     * fingerprint to wally_map_keypath_add so the map entry ends up in
     * LE, matching what session_begin actually compares against. */
    const uint8_t wallet_fp_le[4] = {
        OWNED_TEST_WALLET_FP_BE[3], OWNED_TEST_WALLET_FP_BE[2],
        OWNED_TEST_WALLET_FP_BE[1], OWNED_TEST_WALLET_FP_BE[0],
    };
    const uint32_t scan_path[3]  = {
        BIP32_INITIAL_HARDENED_CHILD,
        BIP32_INITIAL_HARDENED_CHILD + 100,
        BIP32_INITIAL_HARDENED_CHILD + 0,
    };
    const uint32_t spend_path[3] = {
        BIP32_INITIAL_HARDENED_CHILD,
        BIP32_INITIAL_HARDENED_CHILD + 100,
        BIP32_INITIAL_HARDENED_CHILD + 1,
    };
    if (wally_map_keypath_add(&pi->mweb_scan_key_origin,
            spend_pub, 33,
            wallet_fp_le, 4,
            scan_path, 3) != WALLY_OK) return false;
    if (wally_map_keypath_add(&pi->mweb_spend_key_origin,
            spend_pub, 33,
            wallet_fp_le, 4,
            spend_path, 3) != WALLY_OK) return false;

    psbt->num_inputs = 1;

    if (out_commit) memcpy(out_commit, commit, 33);
    return true;
}

/*
 * Build a PSBT output at psbt->outputs[0] that satisfies the
 * recipient-binding rederivation. `sender_key` is the per-output
 * random scalar Jade accepts as the 0xFC"JADE"0x01 proprietary
 * presign field; every other field is derived from it using
 * mweb_derive_output.
 */
static bool build_mweb_output(
    struct wally_psbt *psbt,
    const uint8_t sender_key[32],
    uint64_t value)
{
    const secp256k1_context *ctx = wally_get_secp_context();
    if (!ctx) return false;

    struct wally_psbt_output *po = &psbt->outputs[0];

    /* init_alloc zeroes outputs[0] but does NOT call psbt_output_init.
     * The `unknowns` and `psbt_fields` maps both need initialization
     * before wally_map_add / wally_psbt_output_set_mweb_presign_sender_key
     * can touch them. */
    if (wally_map_init(0, NULL, &po->unknowns) != WALLY_OK) return false;

    /* A_i = scan * B_i, B_i = spend_pub + m_i*G with index = 0. */
    uint8_t mi_buf[4 + 32] = {0};
    memcpy(mi_buf + 4, OWNED_TEST_SCAN_KEY, 32);
    uint8_t m_i[32];
    mweb_hashed(MWEB_TAG_ADDRESS, mi_buf, sizeof(mi_buf), m_i);

    uint8_t spend_pub[33], mi_pub[33];
    if (wally_ec_public_key_from_private_key(OWNED_TEST_SPEND_KEY, 32,
            spend_pub, 33) != WALLY_OK) return false;
    if (wally_ec_public_key_from_private_key(m_i, 32, mi_pub, 33) != WALLY_OK)
        return false;

    secp256k1_pubkey sp_pk, mi_pk, Bi_pk;
    if (!secp256k1_ec_pubkey_parse(ctx, &sp_pk, spend_pub, 33)) return false;
    if (!secp256k1_ec_pubkey_parse(ctx, &mi_pk, mi_pub, 33)) return false;
    const secp256k1_pubkey *pts[2] = { &sp_pk, &mi_pk };
    if (!secp256k1_ec_pubkey_combine(ctx, &Bi_pk, pts, 2)) return false;

    uint8_t B_i[33]; size_t bl = 33;
    secp256k1_ec_pubkey_serialize(ctx, B_i, &bl, &Bi_pk, SECP256K1_EC_COMPRESSED);

    secp256k1_pubkey Ai_pk = Bi_pk;
    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &Ai_pk, OWNED_TEST_SCAN_KEY)) return false;
    uint8_t A_i[33]; size_t al = 33;
    secp256k1_ec_pubkey_serialize(ctx, A_i, &al, &Ai_pk, SECP256K1_EC_COMPRESSED);

    /* Derive the recipient-binding fields. */
    struct mweb_derived_output d;
    if (mweb_derive_output(sender_key, A_i, B_i, value, &d) != MWEB_OK) {
        return false;
    }

    po->has_amount = 1;
    po->amount = value;

    /* 0x90 stealth address: A || B, 66 bytes. */
    uint8_t sa[66];
    memcpy(sa,      A_i, 33);
    memcpy(sa + 33, B_i, 33);
    uint8_t k;

    k = 0x90;
    if (wally_map_add(&po->unknowns, &k, 1, sa, 66) != WALLY_OK) return false;
    k = 0x91;
    if (wally_map_add(&po->unknowns, &k, 1, d.commit,         33) != WALLY_OK) return false;
    k = 0x93;
    if (wally_map_add(&po->unknowns, &k, 1, d.sender_pubkey,  33) != WALLY_OK) return false;
    k = 0x94;
    if (wally_map_add(&po->unknowns, &k, 1, d.output_pubkey,  33) != WALLY_OK) return false;

    /* 0x95 standard fields: Ke(33) || viewTag(1) || maskedValue(8 LE) || maskedNonce(16 BE). */
    uint8_t sf[58];
    memcpy(sf, d.key_exchange_pubkey, 33);
    sf[33] = d.view_tag;
    for (int i = 0; i < 8; i++) sf[34 + i] = (uint8_t)(d.masked_value >> (i * 8));
    memcpy(sf + 42, d.masked_nonce, 16);
    k = 0x95;
    if (wally_map_add(&po->unknowns, &k, 1, sf, 58) != WALLY_OK) return false;

    /* Proprietary presign 0xFC "JADE" 0x01 — sender_key. */
    if (wally_psbt_output_set_mweb_presign_sender_key(po, sender_key, 32)
        != WALLY_OK) return false;

    /* MWEB_OUT_IS_MWEB gates session_begin's output loop on the presence
     * of 0x90 (stealth addr) or 0x91 (commit) in mweb_output_keyset.
     * Without this the output is skipped, Sum(v_out)=0, and balance
     * fails with BALANCE_FAIL. */
    po->mweb_output_keyset
        = (1u << (0x90 - 0x90))   /* STEALTH_ADDRESS */
        | (1u << (0x91 - 0x90))   /* COMMIT */
        | (1u << (0x93 - 0x90))   /* SENDER_PUBKEY */
        | (1u << (0x94 - 0x90))   /* OUTPUT_PUBKEY */
        | (1u << (0x95 - 0x90));  /* STANDARD_FIELDS */

    psbt->num_outputs = 1;
    return true;
}

/*
 * Happy path: an owned MWEB input signs end-to-end through
 * session_begin + session_commit. Verifies:
 *   - begin + commit return MWEB_OK
 *   - Jade writes INPUT_SIGNATURE and INPUT_PUBKEY bits into mweb_keyset
 *   - Jade does NOT write SPENT_OUTPUT_COMMIT — the host-provided 0x91
 *     is the source of truth and Jade only verifies against it
 *   - the 0x91 commit bytes are byte-identical pre vs post commit
 *   - kernel excess + signature + offsets are populated
 */
static void test_owned_input_sign_ok(void)
{
    struct wally_psbt *psbt = NULL;
    if (wally_psbt_init_alloc(2, 1, 0, 0, 0, &psbt) != WALLY_OK || !psbt) {
        printf("FAIL: owned_input_ok — wally_psbt_init_alloc\n");
        failures++;
        return;
    }

    /* kex_secret arbitrary non-zero scalar for the test UTXO's K_e. */
    const uint8_t kex_secret[32] = {
        0xa5,0xa5,0xa5,0xa5,0xa5,0xa5,0xa5,0xa5,
        0xa5,0xa5,0xa5,0xa5,0xa5,0xa5,0xa5,0xa5,
        0xa5,0xa5,0xa5,0xa5,0xa5,0xa5,0xa5,0xa5,
        0xa5,0xa5,0xa5,0xa5,0xa5,0xa5,0xa5,0xa5,
    };
    uint8_t host_commit[33];
    if (!build_owned_mweb_input(psbt, kex_secret, host_commit)) {
        printf("FAIL: owned_input_ok — build_owned_mweb_input\n");
        failures++;
        wally_psbt_free(psbt);
        return;
    }

    /* Balanced fee-only kernel: Sum(v_in) = fee → v_in covers fee only.
     * For this test we burn the full input as fee to avoid needing a
     * matching pegout/output. */
    struct wally_psbt_kernel kernel;
    memset(&kernel, 0, sizeof(kernel));
    kernel.has_fee = 1;
    kernel.fee = OWNED_INPUT_AMOUNT;
    kernel.has_features = 1;
    kernel.features = MWEB_TEST_FEE_BIT;
    psbt->mweb_kernels = &kernel;
    psbt->num_mweb_kernels = 1;
    psbt->mweb_kernels_allocation_len = 0;

    const uint16_t keyset_before = psbt->inputs[0].mweb_keyset;
    uint8_t commit_before[33];
    memcpy(commit_before, psbt->inputs[0].mweb_spent_output_commit, 33);

    seed_trng_nonzero(0x42);
    mweb_session_t *s = NULL;
    mweb_err_t err = mweb_session_begin(psbt, (uint8_t)NETWORK_LITECOIN, &s);

    bool ok = true;
    if (err != MWEB_OK || !s) {
        printf("FAIL: owned_input_ok — begin returned %d\n", err);
        ok = false;
    }

    if (ok) {
        err = mweb_session_commit(s, psbt);
        if (err != MWEB_OK) {
            printf("FAIL: owned_input_ok — commit returned %d\n", err);
            ok = false;
        }
    }

    if (ok) {
        /* Device must not overwrite the host-supplied 0x91 commit. */
        if (memcmp(psbt->inputs[0].mweb_spent_output_commit,
                   commit_before, 33) != 0) {
            printf("FAIL: owned_input_ok — Jade overwrote mweb_spent_output_commit\n");
            ok = false;
        }

        /* Jade wrote INPUT_SIGNATURE (0x95) + INPUT_PUBKEY (0x93). */
        const uint16_t expected_new_bits
            = (1u << (0x93 - 0x90))   /* INPUT_PUBKEY */
            | (1u << (0x95 - 0x90));  /* INPUT_SIGNATURE */
        if ((psbt->inputs[0].mweb_keyset & expected_new_bits) != expected_new_bits) {
            printf("FAIL: owned_input_ok — signature/pubkey bits not set (keyset %04x → %04x)\n",
                keyset_before, psbt->inputs[0].mweb_keyset);
            ok = false;
        }

        /* Signature buffer non-zero (Schnorr primitive actually ran). */
        uint8_t zero_sig[64] = {0};
        if (memcmp(psbt->inputs[0].mweb_input_signature, zero_sig, 64) == 0) {
            printf("FAIL: owned_input_ok — input_signature all-zero\n");
            ok = false;
        }

        /* Input pubkey compressed prefix. */
        if (psbt->inputs[0].mweb_input_pubkey[0] != 0x02
            && psbt->inputs[0].mweb_input_pubkey[0] != 0x03) {
            printf("FAIL: owned_input_ok — input_pubkey prefix 0x%02x\n",
                psbt->inputs[0].mweb_input_pubkey[0]);
            ok = false;
        }

        /* Kernel + globals populated. */
        if (!kernel.has_excess_commitment
            || !kernel.has_signature
            || !psbt->has_mweb_tx_offset
            || !psbt->has_mweb_stealth_offset) {
            printf("FAIL: owned_input_ok — kernel/global fields missing\n");
            ok = false;
        }
    }

    /* Teardown. */
    psbt->inputs[0].mweb_keyset = 0;
    psbt->mweb_kernels = NULL;
    psbt->num_mweb_kernels = 0;
    wally_map_clear(&kernel.pegouts);
    wally_map_clear(&kernel.unknowns);
    wally_psbt_free(psbt);

    if (ok) printf("PASS: owned_input_sign_ok\n");
    else failures++;
}

/*
 * PSBT lies about spent_output_commit. Jade MUST reject with
 * MWEB_ERR_INPUT_COMMIT_MISMATCH before any kernel / input signing.
 */
static void test_input_commit_mismatch_rejects(void)
{
    struct wally_psbt *psbt = NULL;
    if (wally_psbt_init_alloc(2, 1, 0, 0, 0, &psbt) != WALLY_OK || !psbt) {
        printf("FAIL: input_commit_mismatch — wally_psbt_init_alloc\n");
        failures++;
        return;
    }

    const uint8_t kex_secret[32] = { [0 ... 31] = 0xa5 };
    if (!build_owned_mweb_input(psbt, kex_secret, NULL)) {
        printf("FAIL: input_commit_mismatch — build_owned_mweb_input\n");
        failures++;
        wally_psbt_free(psbt);
        return;
    }

    /* Tamper: flip one bit of the advertised commit. Keeps the 0x08/0x09
     * prefix valid so it's a structural look-alike; only the Pedersen
     * compare catches it. */
    psbt->inputs[0].mweb_spent_output_commit[16] ^= 0x01;

    struct wally_psbt_kernel kernel;
    memset(&kernel, 0, sizeof(kernel));
    kernel.has_fee = 1; kernel.fee = OWNED_INPUT_AMOUNT;
    kernel.has_features = 1; kernel.features = MWEB_TEST_FEE_BIT;
    psbt->mweb_kernels = &kernel;
    psbt->num_mweb_kernels = 1;
    psbt->mweb_kernels_allocation_len = 0;

    seed_trng_nonzero(0x42);
    mweb_session_t *s = NULL;
    mweb_err_t err = mweb_session_begin(psbt, (uint8_t)NETWORK_LITECOIN, &s);

    bool ok = (err == MWEB_ERR_INPUT_COMMIT_MISMATCH) && (s == NULL);
    if (!ok) {
        printf("FAIL: input_commit_mismatch — expected INPUT_COMMIT_MISMATCH got %d\n", err);
    }

    psbt->inputs[0].mweb_keyset = 0;
    psbt->mweb_kernels = NULL;
    psbt->num_mweb_kernels = 0;
    wally_map_clear(&kernel.pegouts);
    wally_map_clear(&kernel.unknowns);
    wally_psbt_free(psbt);

    if (ok) printf("PASS: input_commit_mismatch_rejects\n");
    else failures++;
}

/*
 * PSBT omits spent_output_commit entirely. Absent 0x91 bit must map
 * to INPUT_COMMIT_MISMATCH — Jade must treat the field as
 * host-provides / device-verifies, never silently computing and
 * writing it itself.
 */
static void test_input_commit_missing_rejects(void)
{
    struct wally_psbt *psbt = NULL;
    if (wally_psbt_init_alloc(2, 1, 0, 0, 0, &psbt) != WALLY_OK || !psbt) {
        printf("FAIL: input_commit_missing — wally_psbt_init_alloc\n");
        failures++;
        return;
    }

    const uint8_t kex_secret[32] = { [0 ... 31] = 0xa5 };
    if (!build_owned_mweb_input(psbt, kex_secret, NULL)) {
        printf("FAIL: input_commit_missing — build_owned_mweb_input\n");
        failures++;
        wally_psbt_free(psbt);
        return;
    }

    /* Clear the OUTPUT_COMMIT bit; leave the buffer bytes alone. */
    psbt->inputs[0].mweb_keyset &= ~(1u << (0x91 - 0x90));

    struct wally_psbt_kernel kernel;
    memset(&kernel, 0, sizeof(kernel));
    kernel.has_fee = 1; kernel.fee = OWNED_INPUT_AMOUNT;
    kernel.has_features = 1; kernel.features = MWEB_TEST_FEE_BIT;
    psbt->mweb_kernels = &kernel;
    psbt->num_mweb_kernels = 1;
    psbt->mweb_kernels_allocation_len = 0;

    seed_trng_nonzero(0x42);
    mweb_session_t *s = NULL;
    mweb_err_t err = mweb_session_begin(psbt, (uint8_t)NETWORK_LITECOIN, &s);

    bool ok = (err == MWEB_ERR_INPUT_COMMIT_MISMATCH) && (s == NULL);
    if (!ok) {
        printf("FAIL: input_commit_missing — expected INPUT_COMMIT_MISMATCH got %d\n", err);
    }

    psbt->inputs[0].mweb_keyset = 0;
    psbt->mweb_kernels = NULL;
    psbt->num_mweb_kernels = 0;
    wally_map_clear(&kernel.pegouts);
    wally_map_clear(&kernel.unknowns);
    wally_psbt_free(psbt);

    if (ok) printf("PASS: input_commit_missing_rejects\n");
    else failures++;
}

/*
 * After a successful session_commit the 33 bytes of
 * mweb_spent_output_commit on every MWEB input must be byte-identical to
 * what the host placed there before session_begin. Jade reads the field
 * to verify it matches the on-device derivation, but must never write it
 * back. A re-introduction of any unconditional memcpy into that field
 * during signing would be caught here even when the host commit is honest,
 * because the write would occur regardless of whether the bytes changed.
 */
static void test_input_commit_not_rewritten(void)
{
    struct wally_psbt *psbt = NULL;
    if (wally_psbt_init_alloc(2, 1, 0, 0, 0, &psbt) != WALLY_OK || !psbt) {
        printf("FAIL: commit_not_rewritten — wally_psbt_init_alloc\n");
        failures++;
        return;
    }

    const uint8_t kex_secret[32] = { [0 ... 31] = 0xa5 };
    if (!build_owned_mweb_input(psbt, kex_secret, NULL)) {
        printf("FAIL: commit_not_rewritten — build_owned_mweb_input\n");
        failures++;
        wally_psbt_free(psbt);
        return;
    }

    /* Snapshot the 33 bytes as the host supplied them.  Any mutation
     * by Jade during the session will be detected by the memcmp below,
     * even if the mutated value happens to equal the original (because
     * an unconditional write is itself the bug, not merely a wrong value). */
    uint8_t commit_s0[33];
    memcpy(commit_s0, psbt->inputs[0].mweb_spent_output_commit, 33);

    struct wally_psbt_kernel kernel;
    memset(&kernel, 0, sizeof(kernel));
    kernel.has_fee      = 1;
    kernel.fee          = OWNED_INPUT_AMOUNT;
    kernel.has_features = 1;
    kernel.features     = MWEB_TEST_FEE_BIT;
    psbt->mweb_kernels                = &kernel;
    psbt->num_mweb_kernels            = 1;
    psbt->mweb_kernels_allocation_len = 0;

    seed_trng_nonzero(0x42);
    mweb_session_t *s = NULL;
    mweb_err_t err = mweb_session_begin(psbt, (uint8_t)NETWORK_LITECOIN, &s);

    bool ok = true;
    if (err != MWEB_OK || !s) {
        printf("FAIL: commit_not_rewritten — begin returned %d\n", err);
        ok = false;
    }

    if (ok) {
        err = mweb_session_commit(s, psbt);
        if (err != MWEB_OK) {
            printf("FAIL: commit_not_rewritten — commit returned %d\n", err);
            ok = false;
        }
    }

    /* Core assertion: 33 bytes must be exactly what the host placed there. */
    if (ok && memcmp(psbt->inputs[0].mweb_spent_output_commit,
                     commit_s0, 33) != 0) {
        printf("FAIL: commit_not_rewritten — mweb_spent_output_commit was modified\n");
        ok = false;
    }

    /* Secondary: the SPENT_OUTPUT_COMMIT keyset bit must still be set (Jade
     * must not have cleared it) and no unexpected bits must have appeared
     * beyond the two Jade legitimately writes: INPUT_PUBKEY and
     * INPUT_SIGNATURE. */
    if (ok) {
        const uint16_t commit_bit    = (uint16_t)(1u << (0x91 - 0x90));
        const uint16_t pubkey_bit    = (uint16_t)(1u << (0x93 - 0x90));
        const uint16_t sig_bit       = (uint16_t)(1u << (0x95 - 0x90));
        const uint16_t allowed_new   = pubkey_bit | sig_bit;
        const uint16_t ks            = psbt->inputs[0].mweb_keyset;

        if (!(ks & commit_bit)) {
            printf("FAIL: commit_not_rewritten — SPENT_OUTPUT_COMMIT bit cleared\n");
            ok = false;
        }
        /* Any bit set that is neither pre-existing nor one of the two Jade
         * is allowed to write indicates an unexpected field write-back. */
        const uint16_t pre_existing = (uint16_t)(
              (1u << (0x90 - 0x90))   /* SPENT_OUTPUT_ID */
            | (1u << (0x91 - 0x90))   /* SPENT_OUTPUT_COMMIT */
            | (1u << (0x92 - 0x90))   /* SPENT_OUTPUT_PUBKEY */
            | (1u << (0x94 - 0x90))   /* FEATURES */
            | (1u << (0x96 - 0x90))   /* ADDRESS_INDEX */
            | (1u << (0x97 - 0x90))   /* INPUT_AMOUNT */
            | (1u << (0x99 - 0x90))   /* KEY_EXCHANGE_PUBKEY */
        );
        const uint16_t unexpected = ks & ~(pre_existing | allowed_new);
        if (unexpected) {
            printf("FAIL: commit_not_rewritten — unexpected keyset bits 0x%04x\n",
                   unexpected);
            ok = false;
        }
    }

    psbt->inputs[0].mweb_keyset       = 0;
    psbt->mweb_kernels                = NULL;
    psbt->num_mweb_kernels            = 0;
    wally_map_clear(&kernel.pegouts);
    wally_map_clear(&kernel.unknowns);
    wally_psbt_free(psbt);

    if (ok) printf("PASS: input_commit_not_rewritten\n");
    else    failures++;
}

/*
 * Full session-level standard→MWEB shape: zero MWEB inputs, one real
 * MWEB output (host-derived via mweb_derive_output), one balanced
 * kernel. Forces the session to run recipient-binding verification.
 * A regression that short-circuits the output verification chain
 * (e.g. failing to rederive K_o / K_e / masked_* / commit) fails here.
 */
static void test_mweb_output_s2_binding_ok(void)
{
    struct wally_psbt *psbt = NULL;
    if (wally_psbt_init_alloc(2, 0, 1, 0, 0, &psbt) != WALLY_OK || !psbt) {
        printf("FAIL: output_s2_ok — wally_psbt_init_alloc\n");
        failures++;
        return;
    }

    static const uint8_t sender_key[32] = { [0 ... 31] = 0x11 };
    const uint64_t value = 42000000ULL;
    if (!build_mweb_output(psbt, sender_key, value)) {
        printf("FAIL: output_s2_ok — build_mweb_output\n");
        failures++;
        wally_psbt_free(psbt);
        return;
    }

    /* Balanced kernel: pegin covers MWEB output + fee. */
    struct wally_psbt_kernel kernel;
    memset(&kernel, 0, sizeof(kernel));
    kernel.has_fee = 1; kernel.fee = 1000;
    kernel.has_pegin_amount = 1; kernel.pegin_amount = value + 1000;
    kernel.has_features = 1;
    kernel.features = MWEB_TEST_FEE_BIT | MWEB_TEST_PEGIN_BIT;
    psbt->mweb_kernels = &kernel;
    psbt->num_mweb_kernels = 1;
    psbt->mweb_kernels_allocation_len = 0;

    seed_trng_nonzero(0x42);
    mweb_session_t *s = NULL;
    mweb_err_t err = mweb_session_begin(psbt, (uint8_t)NETWORK_LITECOIN, &s);

    bool ok = true;
    if (err != MWEB_OK || !s) {
        printf("FAIL: output_s2_ok — begin returned %d\n", err);
        ok = false;
    }

    /* The session should have recorded the MWEB output and we can query
     * its verified value. */
    if (ok) {
        uint64_t v_out = 0;
        if (mweb_session_get_output_value(s, 0, &v_out) != MWEB_OK
            || v_out != value) {
            printf("FAIL: output_s2_ok — get_output_value got %llu want %llu\n",
                (unsigned long long)v_out, (unsigned long long)value);
            ok = false;
        }
        if (mweb_session_num_mweb_outputs(s) != 1) {
            printf("FAIL: output_s2_ok — num_mweb_outputs != 1\n");
            ok = false;
        }
    }

    if (ok) {
        err = mweb_session_commit(s, psbt);
        if (err != MWEB_OK) {
            printf("FAIL: output_s2_ok — commit returned %d\n", err);
            ok = false;
        }
    }

    psbt->mweb_kernels = NULL;
    psbt->num_mweb_kernels = 0;
    wally_map_clear(&kernel.pegouts);
    wally_map_clear(&kernel.unknowns);
    wally_psbt_free(psbt);

    if (ok) printf("PASS: mweb_output_s2_binding_ok\n");
    else failures++;
}

/*
 * Tamper check: flip one byte of the host-supplied MWEB output
 * commit. Jade's rederivation must diverge from the tampered PSBT
 * field and return MWEB_ERR_OUTPUT_FIELD_MISMATCH. This is the
 * primary theft-prevention assertion — without it a compromised
 * companion could substitute an attacker-owned output body while
 * the displayed stealth address still reads the honest recipient.
 */
static void test_mweb_output_s2_tampered_commit_rejects(void)
{
    struct wally_psbt *psbt = NULL;
    if (wally_psbt_init_alloc(2, 0, 1, 0, 0, &psbt) != WALLY_OK || !psbt) {
        printf("FAIL: output_s2_tampered — wally_psbt_init_alloc\n");
        failures++;
        return;
    }

    static const uint8_t sender_key[32] = { [0 ... 31] = 0x22 };
    const uint64_t value = 7000000ULL;
    if (!build_mweb_output(psbt, sender_key, value)) {
        printf("FAIL: output_s2_tampered — build_mweb_output\n");
        failures++;
        wally_psbt_free(psbt);
        return;
    }

    /* Tamper the 0x91 commit by one bit. */
    uint8_t commit_key = 0x91;
    size_t found = 0;
    if (wally_map_find(&psbt->outputs[0].unknowns, &commit_key, 1, &found)
            != WALLY_OK || found == 0) {
        printf("FAIL: output_s2_tampered — commit not in unknowns\n");
        failures++;
        wally_psbt_free(psbt);
        return;
    }
    struct wally_map_item *item = &psbt->outputs[0].unknowns.items[found - 1];
    item->value[16] ^= 0x01;

    struct wally_psbt_kernel kernel;
    memset(&kernel, 0, sizeof(kernel));
    kernel.has_fee = 1; kernel.fee = 1000;
    kernel.has_pegin_amount = 1; kernel.pegin_amount = value + 1000;
    kernel.has_features = 1;
    kernel.features = MWEB_TEST_FEE_BIT | MWEB_TEST_PEGIN_BIT;
    psbt->mweb_kernels = &kernel;
    psbt->num_mweb_kernels = 1;
    psbt->mweb_kernels_allocation_len = 0;

    seed_trng_nonzero(0x42);
    mweb_session_t *s = NULL;
    mweb_err_t err = mweb_session_begin(psbt, (uint8_t)NETWORK_LITECOIN, &s);

    bool ok = (err == MWEB_ERR_OUTPUT_FIELD_MISMATCH) && (s == NULL);
    if (!ok) {
        printf("FAIL: output_s2_tampered — expected OUTPUT_FIELD_MISMATCH got %d\n", err);
    }

    psbt->mweb_kernels = NULL;
    psbt->num_mweb_kernels = 0;
    wally_map_clear(&kernel.pegouts);
    wally_map_clear(&kernel.unknowns);
    wally_psbt_free(psbt);

    if (ok) printf("PASS: mweb_output_s2_tampered_commit_rejects\n");
    else failures++;
}

/*
 * ── sign_psbt_has_mweb_component gate coverage ─────────────────────────────
 *
 * Links against the production helper in main/mweb/mweb_gate.c and
 * drives it with concrete PSBT shapes. A regression in the helper
 * that narrows the gate (e.g. back to a single input-count check, or
 * drops one of the OR branches) now fails loudly here. A regression
 * that stops *calling* the helper from sign_psbt.c is still a gap,
 * but it's a grep-catchable refactor rather than a silent logic
 * change inside the gate.
 */
#define GATE_IN_OUTPUT_ID_BIT   (1u << 0)   /* input 0x90 */
#define GATE_OUT_STEALTH_BIT    (1u << 0)   /* output 0x90 */
#define GATE_OUT_COMMIT_BIT     (1u << 1)   /* output 0x91 */

static void test_has_mweb_gate_shapes(void)
{
    struct wally_psbt *psbt = NULL;

    /* 1. Pure standard PSBT: 1 standard input, 0 outputs, 0 kernels. */
    wally_psbt_init_alloc(2, 1, 0, 0, 0, &psbt);
    psbt->num_inputs = 1;
    if (sign_psbt_has_mweb_component(psbt)) {
        printf("FAIL: gate_shapes — pure-standard fires\n"); failures++;
        wally_psbt_free(psbt); return;
    }
    wally_psbt_free(psbt);

    /* 2. MWEB kernel only: 0 inputs, 0 outputs, 1 kernel. */
    wally_psbt_init_alloc(2, 0, 0, 0, 0, &psbt);
    struct wally_psbt_kernel k_only;
    memset(&k_only, 0, sizeof(k_only));
    psbt->mweb_kernels = &k_only;
    psbt->num_mweb_kernels = 1;
    psbt->mweb_kernels_allocation_len = 0;
    if (!sign_psbt_has_mweb_component(psbt)) {
        printf("FAIL: gate_shapes — kernel-only does not fire\n"); failures++;
        psbt->mweb_kernels = NULL; psbt->num_mweb_kernels = 0;
        wally_psbt_free(psbt); return;
    }
    psbt->mweb_kernels = NULL;
    psbt->num_mweb_kernels = 0;
    wally_psbt_free(psbt);

    /* 3. MWEB input only. */
    wally_psbt_init_alloc(2, 1, 0, 0, 0, &psbt);
    psbt->num_inputs = 1;
    psbt->inputs[0].mweb_keyset = GATE_IN_OUTPUT_ID_BIT;
    if (!sign_psbt_has_mweb_component(psbt)) {
        printf("FAIL: gate_shapes — mweb-input-only does not fire\n"); failures++;
        psbt->inputs[0].mweb_keyset = 0;
        wally_psbt_free(psbt); return;
    }
    psbt->inputs[0].mweb_keyset = 0;
    wally_psbt_free(psbt);

    /* 4. MWEB output only. */
    wally_psbt_init_alloc(2, 0, 1, 0, 0, &psbt);
    psbt->num_outputs = 1;
    psbt->outputs[0].mweb_output_keyset = GATE_OUT_STEALTH_BIT;
    if (!sign_psbt_has_mweb_component(psbt)) {
        printf("FAIL: gate_shapes — mweb-output-only does not fire\n"); failures++;
        psbt->outputs[0].mweb_output_keyset = 0;
        wally_psbt_free(psbt); return;
    }
    psbt->outputs[0].mweb_output_keyset = 0;
    wally_psbt_free(psbt);

    /* 5. Standard input + MWEB output + kernel — the exact shape a
     *    standard→MWEB send takes, and the one a regression to the
     *    old `mweb_input_count > 0` gate would silently miss. */
    wally_psbt_init_alloc(2, 1, 1, 0, 0, &psbt);
    psbt->num_inputs = 1;
    psbt->num_outputs = 1;
    psbt->inputs[0].mweb_keyset = 0;                          /* standard */
    psbt->outputs[0].mweb_output_keyset = GATE_OUT_COMMIT_BIT; /* mweb out */
    struct wally_psbt_kernel k_sm;
    memset(&k_sm, 0, sizeof(k_sm));
    psbt->mweb_kernels = &k_sm;
    psbt->num_mweb_kernels = 1;
    psbt->mweb_kernels_allocation_len = 0;
    if (!sign_psbt_has_mweb_component(psbt)) {
        printf("FAIL: gate_shapes — standard+mweb_output+kernel does not fire\n");
        failures++;
        psbt->outputs[0].mweb_output_keyset = 0;
        psbt->mweb_kernels = NULL; psbt->num_mweb_kernels = 0;
        wally_psbt_free(psbt); return;
    }
    psbt->outputs[0].mweb_output_keyset = 0;
    psbt->mweb_kernels = NULL;
    psbt->num_mweb_kernels = 0;
    wally_psbt_free(psbt);

    /* 6. NULL psbt — gate must be false, not crash. */
    if (sign_psbt_has_mweb_component(NULL)) {
        printf("FAIL: gate_shapes — NULL fires\n"); failures++; return;
    }

    printf("PASS: has_mweb_gate_shapes\n");
}

#undef GATE_IN_OUTPUT_ID_BIT
#undef GATE_OUT_STEALTH_BIT
#undef GATE_OUT_COMMIT_BIT

/*
 * ── Per-output unknowns + mweb_output_keyset rollback ──────────────────
 *
 * mweb_session_begin clones every output's `unknowns` map and stashes
 * `mweb_output_keyset` into the session arena; mweb_session_abort swaps
 * them back via a pointer exchange. No production code path writes to
 * either field today, so the tests mutate the live state directly
 * between begin and abort to exercise the snapshot/restore path, then
 * assert byte-identical restoration. A non-MWEB output keyset (no
 * STEALTH_ADDRESS / COMMIT bits) is used so the verify_mweb_output
 * loop skips the output — begin reaches the snapshot phase, completes
 * kernel signing, and hands back a valid session that abort can tear
 * down.
 */

/* Mirrors production MWEB_OUT_BIT (the .c-local macro). Re-declared
 * test-side because the production header doesn't export it. */
#define TEST_MWEB_OUT_BIT(k) ((uint16_t)(1u << ((k) - 0x90)))

static bool wally_maps_byte_equal(const struct wally_map *a,
                                   const struct wally_map *b)
{
    if (!a || !b) return false;
    if (a->num_items != b->num_items) return false;
    for (size_t i = 0; i < a->num_items; i++) {
        const struct wally_map_item *ai = &a->items[i];
        const struct wally_map_item *bi = &b->items[i];
        /* libwally encodes integer keys as `key == NULL` with the key
         * value stored in `key_len`, and byte keys as `key != NULL`
         * with the byte length in `key_len`. The two forms are not
         * interchangeable, so a difference in key shape is itself an
         * inequality. */
        if ((ai->key == NULL) != (bi->key == NULL)) return false;
        if (ai->key_len   != bi->key_len)   return false;
        if (ai->value_len != bi->value_len) return false;
        /* For integer keys both `ai->key` and `bi->key` are NULL;
         * the `key_len` equality above already proved the integer
         * keys match, so no key-byte compare is needed. */
        if (ai->key != NULL && memcmp(ai->key, bi->key, ai->key_len) != 0) return false;
        if (ai->value_len && memcmp(ai->value, bi->value, ai->value_len) != 0) return false;
    }
    return true;
}

static void test_output_unknowns_restored_after_abort(void)
{
    struct wally_psbt *psbt = NULL;
    if (wally_psbt_init_alloc(2, 0, 1, 0, 0, &psbt) != WALLY_OK || !psbt) {
        printf("FAIL: out_unknowns_restored — wally_psbt_init_alloc\n");
        failures++;
        return;
    }
    psbt->num_outputs = 1;

    /* Pre-populate output[0].unknowns with two arbitrary entries. The
     * key choices (0x92, 0x98) are deliberately outside the
     * STEALTH_ADDRESS / COMMIT pair that MWEB_OUT_IS_MWEB looks at, so
     * the begin-time output loop skips verify_mweb_output and the
     * session reaches the snapshot phase + kernel sign on a fee-only
     * kernel. */
    if (wally_map_init(2, NULL, &psbt->outputs[0].unknowns) != WALLY_OK) {
        printf("FAIL: out_unknowns_restored — wally_map_init\n");
        failures++;
        wally_psbt_free(psbt);
        return;
    }
    const uint8_t k_a = 0x92;
    const uint8_t k_b = 0x98;
    const uint8_t v_a[5] = { 'a','l','p','h','a' };
    const uint8_t v_b[4] = { 'b','e','t','a' };
    if (wally_map_add(&psbt->outputs[0].unknowns, &k_a, 1, v_a, sizeof(v_a)) != WALLY_OK
        || wally_map_add(&psbt->outputs[0].unknowns, &k_b, 1, v_b, sizeof(v_b)) != WALLY_OK) {
        printf("FAIL: out_unknowns_restored — wally_map_add\n");
        failures++;
        wally_psbt_free(psbt);
        return;
    }
    /* FEATURES bit (0x92) — non-MWEB-trigger so verify_mweb_output is skipped. */
    const uint16_t expected_keyset = TEST_MWEB_OUT_BIT(0x92);
    psbt->outputs[0].mweb_output_keyset = expected_keyset;
    psbt->outputs[0].has_amount = 1;
    psbt->outputs[0].amount = 0;

    /* Independent deep clone of the live map for post-abort comparison. */
    struct wally_map expected;
    memset(&expected, 0, sizeof(expected));
    if (wally_map_init(2, NULL, &expected) != WALLY_OK
        || wally_map_combine(&expected, &psbt->outputs[0].unknowns) != WALLY_OK) {
        printf("FAIL: out_unknowns_restored — clone expected\n");
        failures++;
        wally_map_clear(&expected);
        wally_psbt_free(psbt);
        return;
    }

    struct wally_psbt_kernel kernel;
    memset(&kernel, 0, sizeof(kernel));
    prep_valid_fee_only(&kernel);
    psbt->mweb_kernels = &kernel;
    psbt->num_mweb_kernels = 1;
    psbt->mweb_kernels_allocation_len = 0;

    seed_trng_nonzero(0x42);
    mweb_session_t *s = NULL;
    mweb_err_t err = mweb_session_begin(psbt, (uint8_t)NETWORK_LITECOIN, &s);

    bool ok = true;
    if (err != MWEB_OK || !s) {
        printf("FAIL: out_unknowns_restored — begin returned %d\n", err);
        ok = false;
    }

    /* Append a new entry to the live map and flip an unrelated bit
     * in the keyset; abort must undo both. */
    if (ok) {
        const uint8_t k_new = 0x96;
        const uint8_t v_new[3] = { 'n','e','w' };
        if (wally_map_add(&psbt->outputs[0].unknowns, &k_new, 1, v_new, sizeof(v_new))
                != WALLY_OK) {
            printf("FAIL: out_unknowns_restored — wally_map_add on live\n");
            ok = false;
        }
        psbt->outputs[0].mweb_output_keyset |= TEST_MWEB_OUT_BIT(0x96);
    }

    /* Sanity: the mutation IS observable pre-abort. If this assertion
     * fires, the test itself is broken (e.g. the live map and the
     * expected clone are aliased somehow). */
    if (ok && wally_maps_byte_equal(&psbt->outputs[0].unknowns, &expected)) {
        printf("FAIL: out_unknowns_restored — live mutation invisible (test bug)\n");
        ok = false;
    }
    if (ok && psbt->outputs[0].mweb_output_keyset == expected_keyset) {
        printf("FAIL: out_unknowns_restored — keyset mutation invisible (test bug)\n");
        ok = false;
    }

    mweb_session_abort(s, psbt);
    s = NULL;

    if (ok && !wally_maps_byte_equal(&psbt->outputs[0].unknowns, &expected)) {
        printf("FAIL: out_unknowns_restored — abort did not restore unknowns\n");
        ok = false;
    }
    if (ok && psbt->outputs[0].mweb_output_keyset != expected_keyset) {
        printf("FAIL: out_unknowns_restored — abort did not restore keyset (got %04x expected %04x)\n",
               psbt->outputs[0].mweb_output_keyset, expected_keyset);
        ok = false;
    }

    wally_map_clear(&expected);
    psbt->mweb_kernels = NULL;
    psbt->num_mweb_kernels = 0;
    wally_map_clear(&kernel.pegouts);
    wally_map_clear(&kernel.unknowns);
    wally_psbt_free(psbt);

    if (ok) printf("PASS: output_unknowns_restored_after_abort\n");
    else failures++;
}

static void test_output_unknowns_snapshot_empty_map(void)
{
    struct wally_psbt *psbt = NULL;
    if (wally_psbt_init_alloc(2, 0, 1, 0, 0, &psbt) != WALLY_OK || !psbt) {
        printf("FAIL: empty_map — wally_psbt_init_alloc\n");
        failures++;
        return;
    }
    psbt->num_outputs = 1;

    /* output[0].unknowns is zero-initialised; mweb_output_keyset stays 0
     * so verify_mweb_output is skipped. */
    psbt->outputs[0].has_amount = 1;
    psbt->outputs[0].amount = 0;

    struct wally_psbt_kernel kernel;
    memset(&kernel, 0, sizeof(kernel));
    prep_valid_fee_only(&kernel);
    psbt->mweb_kernels = &kernel;
    psbt->num_mweb_kernels = 1;
    psbt->mweb_kernels_allocation_len = 0;

    seed_trng_nonzero(0x42);
    mweb_session_t *s = NULL;
    mweb_err_t err = mweb_session_begin(psbt, (uint8_t)NETWORK_LITECOIN, &s);

    bool ok = true;
    if (err != MWEB_OK || !s) {
        printf("FAIL: empty_map — begin returned %d\n", err);
        ok = false;
    }

    /* Mutate the previously-empty live map. */
    if (ok) {
        const uint8_t k = 0x96;
        const uint8_t v[3] = { 'n','e','w' };
        if (wally_map_add(&psbt->outputs[0].unknowns, &k, 1, v, sizeof(v)) != WALLY_OK) {
            printf("FAIL: empty_map — wally_map_add\n");
            ok = false;
        }
        psbt->outputs[0].mweb_output_keyset |= TEST_MWEB_OUT_BIT(0x96);
    }

    mweb_session_abort(s, psbt);
    s = NULL;

    if (ok && psbt->outputs[0].unknowns.num_items != 0) {
        printf("FAIL: empty_map — abort did not empty unknowns (num_items=%zu)\n",
               psbt->outputs[0].unknowns.num_items);
        ok = false;
    }
    if (ok && psbt->outputs[0].mweb_output_keyset != 0) {
        printf("FAIL: empty_map — abort did not zero keyset (got %04x)\n",
               psbt->outputs[0].mweb_output_keyset);
        ok = false;
    }

    psbt->mweb_kernels = NULL;
    psbt->num_mweb_kernels = 0;
    wally_map_clear(&kernel.pegouts);
    wally_map_clear(&kernel.unknowns);
    wally_psbt_free(psbt);

    if (ok) printf("PASS: output_unknowns_snapshot_empty_map\n");
    else failures++;
}

/*
 * Multi-output independence: two outputs each carry distinct unknowns
 * + keysets at begin; abort must restore each slot to its own
 * begin-entry state without crosstalk.
 */
static void test_output_unknowns_multi_output_independence(void)
{
    struct wally_psbt *psbt = NULL;
    if (wally_psbt_init_alloc(2, 0, 2, 0, 0, &psbt) != WALLY_OK || !psbt) {
        printf("FAIL: multi_out — wally_psbt_init_alloc\n");
        failures++;
        return;
    }
    psbt->num_outputs = 2;

    /* Output 0: one entry at 0x92, FEATURES keyset bit. */
    if (wally_map_init(1, NULL, &psbt->outputs[0].unknowns) != WALLY_OK) {
        printf("FAIL: multi_out — wally_map_init[0]\n");
        failures++;
        wally_psbt_free(psbt);
        return;
    }
    const uint8_t k0 = 0x92;
    const uint8_t v0[4] = { 'z','e','r','o' };
    if (wally_map_add(&psbt->outputs[0].unknowns, &k0, 1, v0, sizeof(v0)) != WALLY_OK) {
        printf("FAIL: multi_out — wally_map_add[0]\n");
        failures++;
        wally_psbt_free(psbt);
        return;
    }
    const uint16_t ks0 = TEST_MWEB_OUT_BIT(0x92);
    psbt->outputs[0].mweb_output_keyset = ks0;
    psbt->outputs[0].has_amount = 1;

    /* Output 1: two entries at 0x98 and 0x9A, EXTRA_DATA keyset bit. */
    if (wally_map_init(2, NULL, &psbt->outputs[1].unknowns) != WALLY_OK) {
        printf("FAIL: multi_out — wally_map_init[1]\n");
        failures++;
        wally_psbt_free(psbt);
        return;
    }
    const uint8_t k1a = 0x98, k1b = 0x9A;
    const uint8_t v1a[3] = { 'o','n','e' };
    const uint8_t v1b[5] = { 't','h','r','e','e' };
    if (wally_map_add(&psbt->outputs[1].unknowns, &k1a, 1, v1a, sizeof(v1a)) != WALLY_OK
        || wally_map_add(&psbt->outputs[1].unknowns, &k1b, 1, v1b, sizeof(v1b)) != WALLY_OK) {
        printf("FAIL: multi_out — wally_map_add[1]\n");
        failures++;
        wally_psbt_free(psbt);
        return;
    }
    const uint16_t ks1 = TEST_MWEB_OUT_BIT(0x98);
    psbt->outputs[1].mweb_output_keyset = ks1;
    psbt->outputs[1].has_amount = 1;

    /* Clone each begin-entry state. */
    struct wally_map exp0, exp1;
    memset(&exp0, 0, sizeof(exp0));
    memset(&exp1, 0, sizeof(exp1));
    if (wally_map_init(1, NULL, &exp0) != WALLY_OK
        || wally_map_combine(&exp0, &psbt->outputs[0].unknowns) != WALLY_OK
        || wally_map_init(2, NULL, &exp1) != WALLY_OK
        || wally_map_combine(&exp1, &psbt->outputs[1].unknowns) != WALLY_OK) {
        printf("FAIL: multi_out — clone expected\n");
        failures++;
        wally_map_clear(&exp0);
        wally_map_clear(&exp1);
        wally_psbt_free(psbt);
        return;
    }

    struct wally_psbt_kernel kernel;
    memset(&kernel, 0, sizeof(kernel));
    prep_valid_fee_only(&kernel);
    psbt->mweb_kernels = &kernel;
    psbt->num_mweb_kernels = 1;
    psbt->mweb_kernels_allocation_len = 0;

    seed_trng_nonzero(0x42);
    mweb_session_t *s = NULL;
    mweb_err_t err = mweb_session_begin(psbt, (uint8_t)NETWORK_LITECOIN, &s);

    bool ok = true;
    if (err != MWEB_OK || !s) {
        printf("FAIL: multi_out — begin returned %d\n", err);
        ok = false;
    }

    /* Mutate both slots distinctly between begin and abort. */
    if (ok) {
        const uint8_t k_new0 = 0x96;
        const uint8_t v_new0[3] = { 'A','A','A' };
        if (wally_map_add(&psbt->outputs[0].unknowns, &k_new0, 1, v_new0, sizeof(v_new0))
                != WALLY_OK) { ok = false; }
        psbt->outputs[0].mweb_output_keyset |= TEST_MWEB_OUT_BIT(0x96);

        const uint8_t k_new1 = 0x97;
        const uint8_t v_new1[2] = { 'B','B' };
        if (ok && wally_map_add(&psbt->outputs[1].unknowns, &k_new1, 1, v_new1, sizeof(v_new1))
                != WALLY_OK) { ok = false; }
        psbt->outputs[1].mweb_output_keyset |= TEST_MWEB_OUT_BIT(0x97);

        if (!ok) printf("FAIL: multi_out — wally_map_add on live\n");
    }

    mweb_session_abort(s, psbt);
    s = NULL;

    if (ok && (!wally_maps_byte_equal(&psbt->outputs[0].unknowns, &exp0)
               || psbt->outputs[0].mweb_output_keyset != ks0)) {
        printf("FAIL: multi_out — output[0] not restored\n");
        ok = false;
    }
    if (ok && (!wally_maps_byte_equal(&psbt->outputs[1].unknowns, &exp1)
               || psbt->outputs[1].mweb_output_keyset != ks1)) {
        printf("FAIL: multi_out — output[1] not restored\n");
        ok = false;
    }

    wally_map_clear(&exp0);
    wally_map_clear(&exp1);
    psbt->mweb_kernels = NULL;
    psbt->num_mweb_kernels = 0;
    wally_map_clear(&kernel.pegouts);
    wally_map_clear(&kernel.unknowns);
    wally_psbt_free(psbt);

    if (ok) printf("PASS: output_unknowns_multi_output_independence\n");
    else failures++;
}

/*
 * Integer-key round-trip via `wally_map_replace_integer`. Integer-keyed
 * items have a structurally different on-disk shape from byte-keyed
 * items (`item.key == NULL`, `item.key_len` holds the integer value),
 * so this test exercises the clone+swap path against that shape — the
 * byte-key shape `wally_map_add` produces is covered separately above.
 */
static void test_output_unknowns_integer_keys_restored_after_abort(void)
{
    struct wally_psbt *psbt = NULL;
    if (wally_psbt_init_alloc(2, 0, 1, 0, 0, &psbt) != WALLY_OK || !psbt) {
        printf("FAIL: int_keys_restored — wally_psbt_init_alloc\n");
        failures++;
        return;
    }
    psbt->num_outputs = 1;

    if (wally_map_init(2, NULL, &psbt->outputs[0].unknowns) != WALLY_OK) {
        printf("FAIL: int_keys_restored — wally_map_init\n");
        failures++;
        wally_psbt_free(psbt);
        return;
    }
    /* Seed with two integer-keyed entries that the host might leave on
     * an unsigned PSBT (0x92 features, 0x98 extra_data). Keys outside
     * the STEALTH_ADDRESS / COMMIT pair so verify_mweb_output is
     * skipped. */
    const uint8_t v_features[1] = { 0x01 };
    const uint8_t v_extra[6]    = { 'm','e','m','o','=','1' };
    if (wally_map_replace_integer(&psbt->outputs[0].unknowns, 0x92,
                                   v_features, sizeof(v_features)) != WALLY_OK
        || wally_map_replace_integer(&psbt->outputs[0].unknowns, 0x98,
                                      v_extra, sizeof(v_extra)) != WALLY_OK) {
        printf("FAIL: int_keys_restored — wally_map_replace_integer (seed)\n");
        failures++;
        wally_psbt_free(psbt);
        return;
    }
    const uint16_t expected_keyset = TEST_MWEB_OUT_BIT(0x92) | TEST_MWEB_OUT_BIT(0x98);
    psbt->outputs[0].mweb_output_keyset = expected_keyset;
    psbt->outputs[0].has_amount = 1;
    psbt->outputs[0].amount = 0;

    struct wally_map expected;
    memset(&expected, 0, sizeof(expected));
    if (wally_map_init(2, NULL, &expected) != WALLY_OK
        || wally_map_combine(&expected, &psbt->outputs[0].unknowns) != WALLY_OK) {
        printf("FAIL: int_keys_restored — clone expected\n");
        failures++;
        wally_map_clear(&expected);
        wally_psbt_free(psbt);
        return;
    }

    struct wally_psbt_kernel kernel;
    memset(&kernel, 0, sizeof(kernel));
    prep_valid_fee_only(&kernel);
    psbt->mweb_kernels = &kernel;
    psbt->num_mweb_kernels = 1;
    psbt->mweb_kernels_allocation_len = 0;

    seed_trng_nonzero(0x42);
    mweb_session_t *s = NULL;
    mweb_err_t err = mweb_session_begin(psbt, (uint8_t)NETWORK_LITECOIN, &s);

    bool ok = true;
    if (err != MWEB_OK || !s) {
        printf("FAIL: int_keys_restored — begin returned %d\n", err);
        ok = false;
    }

    /* Replace three integer-keyed entries and OR new bits into the
     * keyset. */
    if (ok) {
        const uint8_t v_commit[33]    = { 0x08, 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,
                                           17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32 };
        const uint8_t v_pubkey[33]    = { 0x02, 32,31,30,29,28,27,26,25,24,23,22,21,20,19,18,17,
                                           16,15,14,13,12,11,10,9,8,7,6,5,4,3,2,1 };
        const uint8_t v_signature[64] = { [0 ... 63] = 0xCC };
        if (wally_map_replace_integer(&psbt->outputs[0].unknowns, 0x91,
                                       v_commit, sizeof(v_commit)) != WALLY_OK
            || wally_map_replace_integer(&psbt->outputs[0].unknowns, 0x94,
                                          v_pubkey, sizeof(v_pubkey)) != WALLY_OK
            || wally_map_replace_integer(&psbt->outputs[0].unknowns, 0x97,
                                          v_signature, sizeof(v_signature)) != WALLY_OK) {
            printf("FAIL: int_keys_restored — wally_map_replace_integer (mutate)\n");
            ok = false;
        }
        psbt->outputs[0].mweb_output_keyset
            |= TEST_MWEB_OUT_BIT(0x91)
             | TEST_MWEB_OUT_BIT(0x94)
             | TEST_MWEB_OUT_BIT(0x97);
    }

    /* Sanity: pre-abort mutation is observable. */
    if (ok && wally_maps_byte_equal(&psbt->outputs[0].unknowns, &expected)) {
        printf("FAIL: int_keys_restored — mutation invisible (test bug)\n");
        ok = false;
    }

    mweb_session_abort(s, psbt);
    s = NULL;

    if (ok && !wally_maps_byte_equal(&psbt->outputs[0].unknowns, &expected)) {
        printf("FAIL: int_keys_restored — abort did not restore integer-keyed unknowns\n");
        ok = false;
    }
    if (ok && psbt->outputs[0].mweb_output_keyset != expected_keyset) {
        printf("FAIL: int_keys_restored — abort did not restore keyset (got %04x expected %04x)\n",
               psbt->outputs[0].mweb_output_keyset, expected_keyset);
        ok = false;
    }
    /* Cross-check the post-abort items are integer-keyed (key == NULL)
     * to prove the clone preserved the libwally integer-key encoding,
     * not just byte-converted them. */
    if (ok) {
        for (size_t i = 0; i < psbt->outputs[0].unknowns.num_items; i++) {
            if (psbt->outputs[0].unknowns.items[i].key != NULL) {
                printf("FAIL: int_keys_restored — item %zu key not NULL (clone lost integer-key shape)\n", i);
                ok = false;
                break;
            }
        }
    }

    wally_map_clear(&expected);
    psbt->mweb_kernels = NULL;
    psbt->num_mweb_kernels = 0;
    wally_map_clear(&kernel.pegouts);
    wally_map_clear(&kernel.unknowns);
    wally_psbt_free(psbt);

    if (ok) printf("PASS: output_unknowns_integer_keys_restored_after_abort\n");
    else failures++;
}

/* ── Stealth-excess kernel TRNG path ────────────────────────────────── */

/*
 * Happy path: a stealth-excess kernel signs end-to-end. With the TRNG
 * stub seeded non-zero, the on-device stealth-key draw passes
 * mweb_validate_scalar on the first try and the kernel signer produces
 * a populated stealth_excess pubkey, a non-zero signature, and a
 * stealth_offset_final the commit pass writes into the PSBT.
 *
 * Note this asserts only invariants (pubkey prefix, signature non-zero,
 * field presence); byte-equal pinning lives in the kernel-level
 * selfcheck (mweb_selfcheck.c), which calls mweb_sign_kernel_with_ek
 * directly with a fixed stealth_key.
 */
static void test_kernel_stealth_excess_session_commit_ok(void)
{
    struct wally_psbt *psbt = NULL;
    if (wally_psbt_init_alloc(2, 0, 0, 0, 0, &psbt) != WALLY_OK || !psbt) {
        printf("FAIL: stealth_excess_ok — wally_psbt_init_alloc\n");
        failures++;
        return;
    }

    struct wally_psbt_kernel kernel;
    memset(&kernel, 0, sizeof(kernel));
    prep_valid_fee_only(&kernel);
    kernel.features |= MWEB_TEST_STEALTH_EXCESS_BIT;

    psbt->mweb_kernels = &kernel;
    psbt->num_mweb_kernels = 1;
    psbt->mweb_kernels_allocation_len = 0;

    seed_trng_nonzero(0x42);
    mweb_session_t *s = NULL;
    mweb_err_t err = mweb_session_begin(psbt, (uint8_t)NETWORK_LITECOIN, &s);

    bool ok = true;
    if (err != MWEB_OK) {
        printf("FAIL: stealth_excess_ok — begin returned %d\n", err);
        ok = false;
    } else if (!s) {
        printf("FAIL: stealth_excess_ok — session was NULL on success\n");
        ok = false;
    }

    if (ok) {
        err = mweb_session_commit(s, psbt);
        if (err != MWEB_OK) {
            printf("FAIL: stealth_excess_ok — commit returned %d\n", err);
            ok = false;
        }
    }

    if (ok) {
        if (!kernel.has_stealth_excess) {
            printf("FAIL: stealth_excess_ok — has_stealth_excess not set\n");
            ok = false;
        }
        if (ok && kernel.stealth_excess[0] != 0x02
               && kernel.stealth_excess[0] != 0x03) {
            printf("FAIL: stealth_excess_ok — stealth_excess prefix 0x%02x\n",
                   kernel.stealth_excess[0]);
            ok = false;
        }
        if (ok && !kernel.has_signature) {
            printf("FAIL: stealth_excess_ok — has_signature not set\n");
            ok = false;
        }
        uint8_t zero_sig[64] = {0};
        if (ok && memcmp(kernel.signature, zero_sig, 64) == 0) {
            printf("FAIL: stealth_excess_ok — signature is all-zero\n");
            ok = false;
        }
        if (ok && !psbt->has_mweb_stealth_offset) {
            printf("FAIL: stealth_excess_ok — has_mweb_stealth_offset not set\n");
            ok = false;
        }
        uint8_t zero_off[32] = {0};
        if (ok && memcmp(psbt->mweb_stealth_offset, zero_off, 32) == 0) {
            printf("FAIL: stealth_excess_ok — stealth_offset is all-zero\n");
            ok = false;
        }
    }

    psbt->mweb_kernels = NULL;
    psbt->num_mweb_kernels = 0;
    wally_map_clear(&kernel.pegouts);
    wally_map_clear(&kernel.unknowns);
    wally_psbt_free(psbt);

    if (ok) {
        printf("PASS: kernel_stealth_excess_session_commit_ok\n");
    } else {
        failures++;
    }
}

/*
 * TRNG exhaustion. With the stub returning all-zero bytes for every
 * get_random() call, mweb_validate_scalar rejects the draw (zero scalar
 * is out of [1, n-1]) on every retry. After eight failed attempts the
 * stealth-key path returns MWEB_ERR_INTERNAL — never reaching the
 * kernel-signer's own e_k draw — and out_session stays NULL so the
 * caller is not handed a partial session.
 */
static void test_kernel_stealth_excess_trng_exhausts_to_internal(void)
{
    struct wally_psbt *psbt = NULL;
    if (wally_psbt_init_alloc(2, 0, 0, 0, 0, &psbt) != WALLY_OK || !psbt) {
        printf("FAIL: stealth_excess_trng_exhaust — wally_psbt_init_alloc\n");
        failures++;
        return;
    }

    struct wally_psbt_kernel kernel;
    memset(&kernel, 0, sizeof(kernel));
    prep_valid_fee_only(&kernel);
    kernel.features |= MWEB_TEST_STEALTH_EXCESS_BIT;

    psbt->mweb_kernels = &kernel;
    psbt->num_mweb_kernels = 1;
    psbt->mweb_kernels_allocation_len = 0;

    psbt_mweb_snapshot_t pre;
    snapshot_psbt_mweb(psbt, &kernel, &pre);

    /* All-zero TRNG: every mweb_validate_scalar call returns false. */
    memset(g_test_random, 0, sizeof(g_test_random));

    mweb_session_t *s = NULL;
    mweb_err_t err = mweb_session_begin(psbt, (uint8_t)NETWORK_LITECOIN, &s);

    bool ok = true;
    if (err != MWEB_ERR_INTERNAL) {
        printf("FAIL: stealth_excess_trng_exhaust — expected INTERNAL got %d\n", err);
        ok = false;
    }
    if (s != NULL) {
        printf("FAIL: stealth_excess_trng_exhaust — out_session not NULL on reject\n");
        ok = false;
    }

    /* Reject must not leave any PSBT field touched. */
    psbt_mweb_snapshot_t post;
    snapshot_psbt_mweb(psbt, &kernel, &post);
    if (ok && !snapshots_equal(&pre, &post)) {
        printf("FAIL: stealth_excess_trng_exhaust — reject mutated PSBT\n");
        ok = false;
    }

    psbt->mweb_kernels = NULL;
    psbt->num_mweb_kernels = 0;
    wally_map_clear(&kernel.pegouts);
    wally_map_clear(&kernel.unknowns);
    wally_psbt_free(psbt);

    if (ok) {
        printf("PASS: kernel_stealth_excess_trng_exhausts_to_internal\n");
    } else {
        failures++;
    }
}

int test_mweb_atomic_sign(void)
{
    failures = 0;
    memset(g_test_random, 0, sizeof(g_test_random));

    test_err_to_string_covers_all_codes();
    test_null_guards();
    test_begin_rejects_bad_inputs();
    test_begin_rejects_missing_kernel();
    test_begin_rejects_multi_kernel();
    test_begin_rejects_non_litecoin();
    test_money_range_fee_rejected();
    test_money_range_pegin_rejected();
    test_money_range_pegout_amount_rejected();
    test_pegout_unknown_script_rejected();
    test_abort_null_session_no_crash();
    test_standard_to_mweb_session_commit_ok();
    test_rollback_byte_equal_on_reject();
    test_pegout_flow_skipped_rejects_and_rolls_back();
    test_pegout_flow_marked_commits_ok();
    test_shared_secret_bypass_rejected();
    test_owned_input_sign_ok();
    test_input_commit_mismatch_rejects();
    test_input_commit_missing_rejects();
    test_input_commit_not_rewritten();
    test_mweb_output_s2_binding_ok();
    test_mweb_output_s2_tampered_commit_rejects();
    test_has_mweb_gate_shapes();
    test_output_unknowns_restored_after_abort();
    test_output_unknowns_snapshot_empty_map();
    test_output_unknowns_multi_output_independence();
    test_output_unknowns_integer_keys_restored_after_abort();
    test_kernel_stealth_excess_session_commit_ok();
    test_kernel_stealth_excess_trng_exhausts_to_internal();

    printf("\nmweb_atomic_sign: 29 tests, %d failures\n", failures);
    return failures;
}

#ifdef MWEB_TEST_STANDALONE
int main(void) { return test_mweb_atomic_sign() == 0 ? 0 : 1; }
#endif
