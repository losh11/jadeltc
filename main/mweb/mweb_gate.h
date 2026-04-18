#ifndef MWEB_GATE_H_
#define MWEB_GATE_H_

#include <stdbool.h>
#include <wally_psbt.h>

/*
 * Returns true iff the PSBT has any MWEB component that must route
 * through the atomic signing session:
 *
 *   - any input with SPENT_OUTPUT_ID (0x90) set in mweb_keyset, or
 *   - any MWEB output (STEALTH_ADDRESS 0x90 or COMMIT 0x91 in
 *     mweb_output_keyset), or
 *   - any MWEB kernel.
 *
 * This is the sign_psbt has_mweb gate. Lives in its own translation
 * unit (separate from sign_psbt.c's keychain / UI / task dependencies)
 * so the native test harness can link and call it directly.
 *
 * NULL-safe: returns false on NULL psbt.
 */
bool sign_psbt_has_mweb_component(const struct wally_psbt *psbt);

#endif /* MWEB_GATE_H_ */
