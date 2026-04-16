#include "mweb_scalar.h"

#include <string.h>

#include <mbedtls/bignum.h>
#include <wally_core.h>

/* secp256k1 group order n (big-endian). Declared in mweb_scalar.h;
 * mweb_blind and mweb_kernel reference this single definition. */
const uint8_t SECP256K1_ORDER[32] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
    0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
    0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
};

bool mweb_scalar_add_mod_n(const uint8_t a[32], const uint8_t b[32],
                           uint8_t out[32])
{
    bool ok = false;
    mbedtls_mpi a_mpi, b_mpi, n_mpi, r_mpi;
    mbedtls_mpi_init(&a_mpi);
    mbedtls_mpi_init(&b_mpi);
    mbedtls_mpi_init(&n_mpi);
    mbedtls_mpi_init(&r_mpi);

    if (mbedtls_mpi_read_binary(&a_mpi, a, 32) != 0
        || mbedtls_mpi_read_binary(&b_mpi, b, 32) != 0
        || mbedtls_mpi_read_binary(&n_mpi, SECP256K1_ORDER, 32) != 0) {
        goto cleanup;
    }

    /* r = (a + b) mod n */
    if (mbedtls_mpi_add_mpi(&r_mpi, &a_mpi, &b_mpi) != 0
        || mbedtls_mpi_mod_mpi(&r_mpi, &r_mpi, &n_mpi) != 0
        || mbedtls_mpi_write_binary(&r_mpi, out, 32) != 0) {
        goto cleanup;
    }
    ok = true;

cleanup:
    mbedtls_mpi_free(&a_mpi);
    mbedtls_mpi_free(&b_mpi);
    mbedtls_mpi_free(&n_mpi);
    mbedtls_mpi_free(&r_mpi);
    return ok;
}

bool mweb_scalar_neg_mod_n(const uint8_t a[32], uint8_t out[32])
{
    /* -a mod n = n - (a mod n).
     * Reduces a mod n first so non-canonical operands (a >= n) are handled. */

    /* Reduce a mod n via the add helper: (a + 0) mod n = a mod n */
    static const uint8_t ZERO32[32] = {0};
    uint8_t reduced[32];
    if (!mweb_scalar_add_mod_n(a, ZERO32, reduced)) {
        return false;
    }

    /* Check if reduced is zero */
    bool all_zero = true;
    for (int i = 0; i < 32; i++) {
        if (reduced[i] != 0) { all_zero = false; break; }
    }
    if (all_zero) {
        memset(out, 0, 32);
        return true;
    }

    /* Unsigned big-endian subtraction: out = n - reduced.
     * Since reduced is in [1, n-1], the result is in [1, n-1]. */
    int borrow = 0;
    for (int i = 31; i >= 0; i--) {
        int diff = (int)SECP256K1_ORDER[i] - (int)reduced[i] - borrow;
        if (diff < 0) {
            diff += 256;
            borrow = 1;
        } else {
            borrow = 0;
        }
        out[i] = (uint8_t)diff;
    }

    wally_bzero(reduced, sizeof(reduced));
    return true;
}

bool mweb_scalar_sub_mod_n(const uint8_t a[32], const uint8_t b[32],
                           uint8_t out[32])
{
    /* (a - b) mod n = a + (-b mod n) mod n.
     * Avoids negative intermediate values. */
    uint8_t neg_b[32];
    if (!mweb_scalar_neg_mod_n(b, neg_b)) {
        return false;
    }
    bool ok = mweb_scalar_add_mod_n(a, neg_b, out);
    wally_bzero(neg_b, sizeof(neg_b));
    return ok;
}
