#ifndef MWEB_SELFCHECK_H
#define MWEB_SELFCHECK_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <cbor.h>

/*
 * Per-test result recorded by test_mweb_crypto_run_all().
 *
 * `name` points at a static string literal owned by the firmware image;
 * the RPC handler encodes it by reference without copying. Do NOT free
 * or take ownership from outside mweb_selfcheck.c.
 */
typedef struct {
    const char *name;
    bool        passed;
    uint32_t    elapsed_ms;
} mweb_test_result_t;

/* Bumped whenever a new test is added. Callers size their scratch
 * buffer from this so growing the suite doesn't silently truncate
 * results. */
#define MWEB_SELFCHECK_MAX_TESTS 32

/*
 * CBOR reply-buffer upper bound. Each result-array entry encodes as:
 *   map(3) header                            1 B
 *   "name" + varlen label (≤32 B payload)   ≤40 B
 *   "passed" + bool                          9 B
 *   "elapsed_ms" + u32                      17 B
 * plus fixed overhead for the outer map + "elapsed_ms"/"results" keys
 * + array header + the elapsed_ms u64 value. 80 B/entry is a generous
 * upper bound (actual is ~67 B). Tie the buffer size to
 * MWEB_SELFCHECK_MAX_TESTS so bumping the max also bumps the buffer.
 */
#define MWEB_SELFCHECK_REPLY_BUF_BYTES \
    ((MWEB_SELFCHECK_MAX_TESTS * 80) + 128)

/*
 * Run every MWEB crypto test, writing up to `max` entries into `out[]`.
 * Does NOT short-circuit on a failing test — the caller sees every
 * regression in a single run. Returns the number of results filled.
 */
size_t test_mweb_crypto_run_all(mweb_test_result_t *out, size_t max);

/*
 * Historical boot-time wrapper: true iff every sub-test passed.
 * Preserves debug_selfcheck()'s "stop on first failure" contract.
 */
bool test_mweb_crypto(void);

/*
 * RPC reply context + serializer for debug_selfcheck_mweb. The
 * callback emits { "elapsed_ms": u64,
 *                  "results": [ { "name": str,
 *                                 "passed": bool,
 *                                 "elapsed_ms": u32 }, ... ] }.
 */
struct mweb_selfcheck_reply_ctx {
    const mweb_test_result_t *results;
    size_t                    n_results;
    uint64_t                  elapsed_time_ms;
};

void mweb_selfcheck_reply_cb(const void *ctx, CborEncoder *container);

#endif /* MWEB_SELFCHECK_H */
