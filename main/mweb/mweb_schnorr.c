#include "mweb_schnorr.h"

#include <string.h>

#include <blake3.h>
#include <mbedtls/bignum.h>
#include <mbedtls/sha256.h>

#include <secp256k1.h>
#include <wally_core.h>
#include <wally_crypto.h>

/*
 * secp256k1 field prime:
 *   p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
 */
static const uint8_t SECP256K1_FIELD_PRIME[32] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFC, 0x2F,
};

/*
 * (p - 1) / 2 for Euler's criterion (Legendre symbol).
 *   0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7FFFFE17
 */
static const uint8_t SECP256K1_HALF_P_MINUS_1[32] = {
    0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0x7F, 0xFF, 0xFE, 0x17,
};

/*
 * Check if a 256-bit field element y is a quadratic residue mod p.
 *
 * Uses Euler's criterion: y is QR iff y^((p-1)/2) = 1 mod p.
 * This is the MWEB/Grin convention — NOT the BIP340 even/odd check.
 *
 * Returns true on success, writing the QR result to *is_quad_out.
 * Returns false on internal MPI error (caller must abort signing).
 */
static bool fe_is_quad(const uint8_t y[32], bool* is_quad_out)
{
    bool ok = false;
    mbedtls_mpi y_mpi, p_mpi, exp_mpi, res_mpi;

    mbedtls_mpi_init(&y_mpi);
    mbedtls_mpi_init(&p_mpi);
    mbedtls_mpi_init(&exp_mpi);
    mbedtls_mpi_init(&res_mpi);

    if (mbedtls_mpi_read_binary(&y_mpi, y, 32) != 0) {
        goto cleanup;
    }
    if (mbedtls_mpi_read_binary(&p_mpi, SECP256K1_FIELD_PRIME, 32) != 0) {
        goto cleanup;
    }
    if (mbedtls_mpi_read_binary(&exp_mpi, SECP256K1_HALF_P_MINUS_1, 32) != 0) {
        goto cleanup;
    }

    /* y^((p-1)/2) mod p */
    if (mbedtls_mpi_exp_mod(&res_mpi, &y_mpi, &exp_mpi, &p_mpi, NULL) != 0) {
        goto cleanup;
    }

    /* QR iff result == 1 */
    *is_quad_out = (mbedtls_mpi_cmp_int(&res_mpi, 1) == 0);
    ok = true;

cleanup:
    mbedtls_mpi_free(&y_mpi);
    mbedtls_mpi_free(&p_mpi);
    mbedtls_mpi_free(&exp_mpi);
    mbedtls_mpi_free(&res_mpi);
    return ok;
}

/*
 * Incremental SHA-256 helper: SHA256(a || b)
 */
static void sha256_two(const uint8_t* a, size_t a_len,
                       const uint8_t* b, size_t b_len,
                       uint8_t output[32])
{
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts(&ctx, 0);
    mbedtls_sha256_update(&ctx, a, a_len);
    mbedtls_sha256_update(&ctx, b, b_len);
    mbedtls_sha256_finish(&ctx, output);
    mbedtls_sha256_free(&ctx);
}

/*
 * Incremental SHA-256 helper: SHA256(a || b || c)
 */
static void sha256_three(const uint8_t* a, size_t a_len,
                         const uint8_t* b, size_t b_len,
                         const uint8_t* c, size_t c_len,
                         uint8_t output[32])
{
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts(&ctx, 0);
    mbedtls_sha256_update(&ctx, a, a_len);
    mbedtls_sha256_update(&ctx, b, b_len);
    mbedtls_sha256_update(&ctx, c, c_len);
    mbedtls_sha256_finish(&ctx, output);
    mbedtls_sha256_free(&ctx);
}

bool mweb_schnorr_sign(const uint8_t secret_key[32],
                       const uint8_t* msg, size_t msg_len,
                       uint8_t signature[64])
{
    const secp256k1_context* ctx = wally_get_secp_context();
    if (!ctx) {
        return false;
    }

    bool ok = false;
    uint8_t k[32];
    uint8_t e[32];
    uint8_t s[32];
    uint8_t pubkey_compressed[EC_PUBLIC_KEY_LEN]; /* 33 bytes */
    uint8_t R_uncompressed[EC_PUBLIC_KEY_UNCOMPRESSED_LEN]; /* 65 bytes */
    secp256k1_pubkey R_pk;
    secp256k1_pubkey sk_pk;

    /* 1. k = SHA256(secret_key || message)
     *
     * Deviation from ltcsuite: the Go code turns this hash into a scalar via
     * SecretKey.scalar() which allows zero but panics on overflow (>= n).
     * Here we pass k through secp256k1_ec_pubkey_create and the seckey tweak
     * helpers, which reject both zero and overflow. This means we return false
     * where Go would panic or produce a degenerate signature. The probability
     * of SHA256 yielding zero is ~2^-256, overflow ~2^-128 — neither is
     * reachable in practice. Graceful failure is preferable on a HW wallet. */
    sha256_two(secret_key, 32, msg, msg_len, k);

    /* 2. R = k * G */
    if (!secp256k1_ec_pubkey_create(ctx, &R_pk, k)) {
        goto cleanup;
    }

    /* 3. Serialize R as uncompressed to get R.x and R.y */
    size_t R_len = sizeof(R_uncompressed);
    secp256k1_ec_pubkey_serialize(ctx, R_uncompressed, &R_len,
                                 &R_pk, SECP256K1_EC_UNCOMPRESSED);
    /* R_uncompressed: [0x04][R.x: 32 bytes][R.y: 32 bytes] */

    /* Store R.x in signature[0..32] */
    memcpy(signature, R_uncompressed + 1, 32);

    /* 4. If R.y is NOT a quadratic residue, negate k.
     *    This is the MWEB/Grin convention (QR check), NOT BIP340 (even/odd). */
    bool r_y_is_quad;
    if (!fe_is_quad(R_uncompressed + 33, &r_y_is_quad)) {
        goto cleanup; /* MPI error — abort rather than sign with wrong nonce */
    }
    if (!r_y_is_quad) {
        if (!secp256k1_ec_seckey_negate(ctx, k)) {
            goto cleanup;
        }
    }

    /* 5. Compute compressed public key from secret_key (33 bytes) */
    if (!secp256k1_ec_pubkey_create(ctx, &sk_pk, secret_key)) {
        goto cleanup;
    }
    size_t pk_len = sizeof(pubkey_compressed);
    secp256k1_ec_pubkey_serialize(ctx, pubkey_compressed, &pk_len,
                                 &sk_pk, SECP256K1_EC_COMPRESSED);

    /* 6. e = SHA256(R.x || compressed_pubkey || message) */
    sha256_three(signature, 32,           /* R.x */
                 pubkey_compressed, 33,   /* compressed pubkey */
                 msg, msg_len,            /* message */
                 e);

    /* 7. s = e * secret_key + k
     *    Using secp256k1 scalar operations via public API:
     *      s = e
     *      s *= secret_key   (s = e * sk)
     *      s += k            (s = e * sk + k)
     */
    memcpy(s, e, 32);
    if (!secp256k1_ec_seckey_tweak_mul(ctx, s, secret_key)) {
        goto cleanup;
    }
    if (!secp256k1_ec_seckey_tweak_add(ctx, s, k)) {
        goto cleanup;
    }

    /* 8. signature = (R.x || s) — R.x already written in step 3 */
    memcpy(signature + 32, s, 32);
    ok = true;

cleanup:
    /* If the call failed after R.x was written at line ~155 but before s
     * was written, signature[0..32] would otherwise hold R.x while
     * signature[32..64] is uninitialized stomp. Wipe so callers that
     * misuse the buffer despite ok=false see all-zero. */
    if (!ok) {
        wally_bzero(signature, 64);
    }
    wally_bzero(k, sizeof(k));
    wally_bzero(e, sizeof(e));
    wally_bzero(s, sizeof(s));
    wally_bzero(pubkey_compressed, sizeof(pubkey_compressed));
    wally_bzero(R_uncompressed, sizeof(R_uncompressed));
    wally_bzero(&R_pk, sizeof(R_pk));
    wally_bzero(&sk_pk, sizeof(sk_pk));
    return ok;
}

mweb_err_t mweb_sign_output(
    const uint8_t sender_key[32],
    const uint8_t commit[33],
    const uint8_t K_s[33],
    const uint8_t K_o[33],
    const uint8_t msg_hash[32],
    const uint8_t rp_hash[32],
    uint8_t sig_out[64])
{
    if (!sender_key || !commit || !K_s || !K_o
        || !msg_hash || !rp_hash || !sig_out) {
        return MWEB_ERR_INTERNAL;
    }
    if (!mweb_validate_scalar(sender_key)) {
        return MWEB_ERR_INVALID_PRESIGN_SCALAR;
    }

    uint8_t sig_hash[32];
    blake3_hasher hasher;
    blake3_hasher_init(&hasher);
    blake3_hasher_update(&hasher, commit,   33);
    blake3_hasher_update(&hasher, K_s,      33);
    blake3_hasher_update(&hasher, K_o,      33);
    blake3_hasher_update(&hasher, msg_hash, 32);
    blake3_hasher_update(&hasher, rp_hash,  32);
    blake3_hasher_finalize(&hasher, sig_hash, 32);

    mweb_err_t err = MWEB_OK;
    if (!mweb_schnorr_sign(sender_key, sig_hash, 32, sig_out)) {
        err = MWEB_ERR_INTERNAL;
    }
    wally_bzero(sig_hash, sizeof(sig_hash));
    return err;
}
