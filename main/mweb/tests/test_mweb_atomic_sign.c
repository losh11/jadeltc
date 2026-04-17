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

#include "../../utils/network.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <wally_core.h>
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

/* Weak stubs for firmware symbols the atomic signer references on
 * codepaths this test does not exercise (no owned MWEB input path). If
 * the test is ever extended to exercise the full flow, it must link the
 * real firmware objects and these stubs will be overridden. */
__attribute__((weak)) void wallet_get_fingerprint(uint8_t* out, size_t len)
{
    memset(out, 0, len);
}

__attribute__((weak)) bool mweb_derive_key_from_path(
    const uint32_t* path, size_t path_len, uint8_t key_out[32])
{
    (void)path; (void)path_len;
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
#define MWEB_TEST_FEE_BIT    0x01
#define MWEB_TEST_PEGIN_BIT  0x02
#define MWEB_TEST_PEGOUT_BIT 0x04

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

    printf("\nmweb_atomic_sign: 11 tests, %d failures\n", failures);
    return failures;
}

#ifdef MWEB_TEST_STANDALONE
int main(void) { return test_mweb_atomic_sign() == 0 ? 0 : 1; }
#endif
