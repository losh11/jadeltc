#ifndef UI_SIGN_TX_H_
#define UI_SIGN_TX_H_

#include "../ui.h"
#include "../utils/network.h"

typedef struct _asset_info asset_info_t;
typedef struct _asset_summary asset_summary_t;
typedef struct _output_info output_info_t;
struct wally_tx;

bool show_btc_transaction_outputs_activity(
    network_t network_id, const struct wally_tx* tx, const output_info_t* output_info);

bool show_btc_final_confirmation_activity(const network_t network_id, uint64_t fee, const char* warning_msg);

bool show_elements_transaction_outputs_activity(network_t network_id, const struct wally_tx* tx,
    const output_info_t* output_info, const asset_info_t* assets, size_t num_assets);

bool show_elements_final_confirmation_activity(
    network_t network_id, const char* title, uint64_t fee, const char* warning_msg);

bool show_elements_swap_activity(network_t network_id, bool initial_proposal, const asset_summary_t* in_sums,
    size_t num_in_sums, const asset_summary_t* out_sums, size_t num_out_sums, const asset_info_t* assets,
    size_t num_assets);

// MWEB UI screens
bool show_mweb_scan_key_export_activity(network_t network);
bool show_mweb_watch_keys_export_activity(network_t network);
bool show_mweb_address_activity(const char* address, network_t network);
bool show_mweb_output_activity(const char* title, const char* address, const char* amount, network_t network);
bool show_mweb_pegin_activity(uint64_t amount, network_t network);

// Progress state for the MWEB output-build screen. The text node is
// NULL on initial declaration; the first call to
// mweb_session_progress_cb() lazily creates and shows the activity,
// then stashes the text node here so subsequent calls update the
// existing screen instead of re-creating it.
typedef struct {
    gui_view_node_t* text_node;
} mweb_build_progress_state_t;

// Progress callback compatible with mweb_build_progress_cb (declared
// in mweb_atomic_sign.h). Renders "Building MWEB output i/n" and
// updates the screen so the device does not appear frozen during the
// ~5s/output bulletproof generation. `ctx` MUST point to a
// mweb_build_progress_state_t.
void mweb_session_progress_cb(size_t current, size_t total, void* ctx);

#endif /* UI_SIGN_TX_H_ */
