#ifndef AMALGAMATED_BUILD

#include "mweb_gate.h"

#include <stddef.h>
#include <wally_psbt.h>

/* MWEB keyset bits (encoded as 1 << (type_byte - base)). Kept inline
 * rather than pulled from sign_psbt.c's macros so this TU has no
 * dependencies outside wally_psbt.h. */
#define MWEB_GATE_IN_SPENT_OUTPUT_ID_BIT  (1u << 0)  /* input 0x90 */
#define MWEB_GATE_OUT_STEALTH_ADDR_BIT    (1u << 0)  /* output 0x90 */
#define MWEB_GATE_OUT_COMMIT_BIT          (1u << 1)  /* output 0x91 */

bool sign_psbt_has_mweb_component(const struct wally_psbt *psbt)
{
    if (!psbt) {
        return false;
    }
    if (psbt->num_mweb_kernels > 0) {
        return true;
    }
    for (size_t i = 0; i < psbt->num_inputs; ++i) {
        if (psbt->inputs[i].mweb_keyset & MWEB_GATE_IN_SPENT_OUTPUT_ID_BIT) {
            return true;
        }
    }
    for (size_t i = 0; i < psbt->num_outputs; ++i) {
        if (psbt->outputs[i].mweb_output_keyset
                & (MWEB_GATE_OUT_STEALTH_ADDR_BIT | MWEB_GATE_OUT_COMMIT_BIT)) {
            return true;
        }
    }
    return false;
}

#endif /* AMALGAMATED_BUILD */
