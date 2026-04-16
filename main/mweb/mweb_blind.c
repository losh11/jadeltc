#include "mweb_blind.h"
#include "mweb_scalar.h"

#include <string.h>

#include <mbedtls/bignum.h>
#include <secp256k1.h>
#include <secp256k1_generator.h>
#include <wally_core.h>
#include <wally_crypto.h>

/* Generator J for BlindSwitch (compressed pubkey, 33 bytes). */
static const uint8_t GENERATOR_J[33] = {
    0x02,
    0xb8, 0x60, 0xf5, 0x67, 0x95, 0xfc, 0x03, 0xf3,
    0xc2, 0x16, 0x85, 0x38, 0x3d, 0x1b, 0x5a, 0x2f,
    0x29, 0x54, 0xf4, 0x9b, 0x7e, 0x39, 0x8b, 0x8d,
    0x2a, 0x01, 0x93, 0x93, 0x36, 0x21, 0x15, 0x5f,
};

bool mweb_pedersen_commit(const uint8_t blind[32], uint64_t value,
                          uint8_t commitment[33])
{
    const secp256k1_context* ctx = wally_get_secp_context();
    if (!ctx) {
        return false;
    }

    secp256k1_pedersen_commitment c;
    if (!secp256k1_pedersen_commit(ctx, &c, blind, value,
                                   secp256k1_generator_h)) {
        return false;
    }
    secp256k1_pedersen_commitment_serialize(ctx, commitment, &c);
    /* commitment is 33 bytes with 0x08/0x09 prefix */
    return true;
}

bool mweb_blind_switch(const uint8_t blind[32], uint64_t value,
                       uint8_t output_blind[32])
{
    const secp256k1_context* ctx = wally_get_secp_context();
    if (!ctx) {
        return false;
    }

    /* 1. C = Pedersen(blind, value) → 33 bytes with 0x08/0x09 prefix */
    uint8_t commit_bytes[33];
    if (!mweb_pedersen_commit(blind, value, commit_bytes)) {
        return false;
    }

    /* 2. J_point = blind * generator_J → 33 bytes with 0x02/0x03 prefix
     *    Parse generator_J, then multiply by blind scalar. */
    secp256k1_pubkey J;
    if (!secp256k1_ec_pubkey_parse(ctx, &J, GENERATOR_J, 33)) {
        return false;
    }
    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &J, blind)) {
        return false;
    }
    uint8_t j_bytes[33];
    size_t j_len = sizeof(j_bytes);
    secp256k1_ec_pubkey_serialize(ctx, j_bytes, &j_len,
                                  &J, SECP256K1_EC_COMPRESSED);

    /* 3. tweak = SHA256(C_33bytes || J_point_33bytes)
     *    Note: C uses 0x08/0x09 prefix, J uses 0x02/0x03 prefix. */
    uint8_t sha_input[66];
    memcpy(sha_input, commit_bytes, 33);
    memcpy(sha_input + 33, j_bytes, 33);

    uint8_t tweak[32];
    if (wally_sha256(sha_input, sizeof(sha_input), tweak, sizeof(tweak))
        != WALLY_OK) {
        return false;
    }

    /* 4. output = blind + tweak (mod n)
     *
     * Matches Core's secp256k1_blind_switch (commitment/main_impl.h:339-351):
     *   - Reject tweak (hash) if >= n  (line 339-343)
     *   - Reject blind if >= n         (line 344-348)
     *   - Raw scalar add, zero result allowed (line 350) */
    {
        bool add_ok = false;
        mbedtls_mpi b_mpi, t_mpi, n_mpi, r_mpi;
        mbedtls_mpi_init(&b_mpi);
        mbedtls_mpi_init(&t_mpi);
        mbedtls_mpi_init(&n_mpi);
        mbedtls_mpi_init(&r_mpi);

        if (mbedtls_mpi_read_binary(&b_mpi, blind, 32) != 0
            || mbedtls_mpi_read_binary(&t_mpi, tweak, 32) != 0
            || mbedtls_mpi_read_binary(&n_mpi, SECP256K1_ORDER, 32) != 0) {
            goto add_cleanup;
        }

        /* Reject tweak >= n (Core line 339-343: scalar_set_b32 overflow check) */
        if (mbedtls_mpi_cmp_mpi(&t_mpi, &n_mpi) >= 0) {
            goto add_cleanup;
        }

        /* Reject blind >= n (Core line 344-348: scalar_set_b32 overflow check) */
        if (mbedtls_mpi_cmp_mpi(&b_mpi, &n_mpi) >= 0) {
            goto add_cleanup;
        }

        /* Raw add + reduce mod n. Allows zero result (Core line 350). */
        if (mbedtls_mpi_add_mpi(&r_mpi, &b_mpi, &t_mpi) == 0
            && mbedtls_mpi_mod_mpi(&r_mpi, &r_mpi, &n_mpi) == 0
            && mbedtls_mpi_write_binary(&r_mpi, output_blind, 32) == 0) {
            add_ok = true;
        }

    add_cleanup:

        mbedtls_mpi_free(&b_mpi);
        mbedtls_mpi_free(&t_mpi);
        mbedtls_mpi_free(&n_mpi);
        mbedtls_mpi_free(&r_mpi);

        if (!add_ok) {
            return false;
        }
    }

    wally_bzero(tweak, sizeof(tweak));
    wally_bzero(sha_input, sizeof(sha_input));
    return true;
}
