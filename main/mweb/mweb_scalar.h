#ifndef MWEB_SCALAR_H
#define MWEB_SCALAR_H

#include <stdbool.h>
#include <stdint.h>

/*
 * 32-byte big-endian scalar arithmetic mod secp256k1 order n.
 *
 * Unlike secp256k1_ec_seckey_tweak_add/negate, these helpers accept
 * zero operands AND zero results. They reject only on internal MPI
 * error (callers treat false as MWEB_ERR_INTERNAL).
 *
 * Used by mweb_sign_kernel to compute O_k_final and O_s_final, which
 * are ordinary scalars mod n where zero is a mathematically valid
 * final offset.
 */

/* secp256k1 group order n (big-endian). Single definition lives in
 * mweb_scalar.c; mweb_blind and mweb_kernel consume it via this decl. */
extern const uint8_t SECP256K1_ORDER[32];

/* out = (a + b) mod n */
bool mweb_scalar_add_mod_n(const uint8_t a[32], const uint8_t b[32],
                           uint8_t out[32]);

/* out = (a - b) mod n */
bool mweb_scalar_sub_mod_n(const uint8_t a[32], const uint8_t b[32],
                           uint8_t out[32]);

/* out = (-a) mod n */
bool mweb_scalar_neg_mod_n(const uint8_t a[32], uint8_t out[32]);

#endif /* MWEB_SCALAR_H */
