#ifndef AMALGAMATED_BUILD
#include "../jade_assert.h"
#include "../keychain.h"
#include "../process.h"
#include "../sensitive.h"
#include "../ui.h"
#include "../ui/sign_tx.h"
#include "../utils/cbor_rpc.h"
#include "../utils/malloc_ext.h"

#include "../mweb/mweb_keychain.h"
#include "../mweb/mweb_sign.h"
#include "../wallet.h"

#include "process_utils.h"

#include <wally_core.h>
#include <wally_crypto.h>

/*
 * get_mweb_scan_key — Export the 32-byte MWEB scan secret key.
 *
 * Params: { "network": "litecoin" }
 * Returns: 32 bytes (scan secret from m/0'/100'/0')
 */
void get_mweb_scan_key_process(void* process_ptr)
{
    JADE_LOGI("Starting: %d", xPortGetFreeHeapSize());
    jade_process_t* process = process_ptr;

    ASSERT_CURRENT_MESSAGE(process, "get_mweb_scan_key");
    ASSERT_KEYCHAIN_UNLOCKED_BY_MESSAGE_SOURCE(process);
    GET_MSG_PARAMS(process);
    CHECK_NETWORK_CONSISTENT(process);

    if (!network_is_litecoin(network_id)) {
        jade_process_reject_message(
            process, CBOR_RPC_BAD_PARAMETERS, "MWEB is only supported on Litecoin networks");
        goto cleanup;
    }

    /* User confirmation */
    if (!show_mweb_scan_key_export_activity(network_id)) {
        JADE_LOGW("User declined to export MWEB scan key");
        jade_process_reject_message(
            process, CBOR_RPC_USER_CANCELLED, "User declined to export MWEB scan key");
        goto cleanup;
    }

    /* Derive scan key */
    uint8_t scan_key[32];
    SENSITIVE_PUSH(scan_key, sizeof(scan_key));

    uint8_t spend_key[32];
    SENSITIVE_PUSH(spend_key, sizeof(spend_key));

    if (!mweb_derive_standard_keys(scan_key, spend_key)) {
        SENSITIVE_POP(spend_key);
        SENSITIVE_POP(scan_key);
        jade_process_reject_message(process, CBOR_RPC_INTERNAL_ERROR, "Failed to derive MWEB keys");
        goto cleanup;
    }

    jade_process_reply_to_message_bytes(process->ctx, scan_key, 32);
    JADE_LOGI("Success");

    SENSITIVE_POP(spend_key);
    SENSITIVE_POP(scan_key);

cleanup:
    return;
}

/*
 * get_mweb_address — Derive and display an MWEB stealth address.
 *
 * Params: { "network": "litecoin", "index": 0 }
 * Returns: bech32 stealth address string (e.g. "ltcmweb1qq...")
 */
void get_mweb_address_process(void* process_ptr)
{
    JADE_LOGI("Starting: %d", xPortGetFreeHeapSize());
    jade_process_t* process = process_ptr;

    ASSERT_CURRENT_MESSAGE(process, "get_mweb_address");
    ASSERT_KEYCHAIN_UNLOCKED_BY_MESSAGE_SOURCE(process);
    GET_MSG_PARAMS(process);
    CHECK_NETWORK_CONSISTENT(process);

    if (!network_is_litecoin(network_id)) {
        jade_process_reject_message(
            process, CBOR_RPC_BAD_PARAMETERS, "MWEB is only supported on Litecoin networks");
        goto cleanup;
    }

    size_t index = 0;
    if (!rpc_get_sizet("index", &params, &index) || index > UINT32_MAX) {
        jade_process_reject_message(
            process, CBOR_RPC_BAD_PARAMETERS, "Failed to extract index from parameters");
        goto cleanup;
    }

    /* Derive scan + spend keys */
    uint8_t scan_key[32], spend_key[32];
    SENSITIVE_PUSH(scan_key, sizeof(scan_key));
    SENSITIVE_PUSH(spend_key, sizeof(spend_key));

    if (!mweb_derive_standard_keys(scan_key, spend_key)) {
        SENSITIVE_POP(spend_key);
        SENSITIVE_POP(scan_key);
        jade_process_reject_message(process, CBOR_RPC_INTERNAL_ERROR, "Failed to derive MWEB keys");
        goto cleanup;
    }

    /* Derive stealth address */
    char* address = NULL;
    if (!mweb_derive_address(scan_key, spend_key, (uint32_t)index, network_id, &address)) {
        SENSITIVE_POP(spend_key);
        SENSITIVE_POP(scan_key);
        jade_process_reject_message(process, CBOR_RPC_INTERNAL_ERROR, "Failed to derive MWEB address");
        goto cleanup;
    }

    SENSITIVE_POP(spend_key);
    SENSITIVE_POP(scan_key);

    /* Display address on screen */
    if (!show_mweb_address_activity(address, network_id)) {
        JADE_LOGW("User declined MWEB address");
        jade_process_reject_message(
            process, CBOR_RPC_USER_CANCELLED, "User declined to confirm MWEB address");
        wally_free_string(address);
        goto cleanup;
    }

    /* Return address string */
    uint8_t buf[256];
    jade_process_reply_to_message_result(process->ctx, buf, sizeof(buf), address, cbor_result_string_cb);
    JADE_LOGI("Success");

    wally_free_string(address);

cleanup:
    return;
}

/*
 * sign_mweb_input — Sign an MWEB input (standalone RPC).
 *
 * Wrapper over the two-stage API so the dispatch table keeps linking.
 *
 * Params: {
 *   "network": "litecoin",
 *   "features": 1,
 *   "spent_output_id": <32 bytes>,
 *   "spent_output_pk": <33 bytes>,
 *   "amount": 100000,
 *   "key_exchange_pk": <33 bytes>,
 *   "address_index": 0,
 *   "extra_data": <bytes>   (optional, if EXTRA_DATA_BIT)
 * }
 *
 * Returns: {
 *   "signature": <64 bytes>,
 *   "input_blind": <32 bytes>,
 *   "stealth_tweak": <32 bytes>,
 *   "input_pubkey": <33 bytes>,
 *   "output_commit": <33 bytes>
 * }
 */

typedef struct {
    uint8_t signature[64];
    uint8_t input_blind[32];
    uint8_t stealth_tweak[32];
    uint8_t input_pubkey[33];
    uint8_t output_commit[33];
} mweb_sign_cbor_result_t;

static void sign_mweb_result_cb(const void* ctx, CborEncoder* container)
{
    JADE_ASSERT(ctx);
    const mweb_sign_cbor_result_t* result = (const mweb_sign_cbor_result_t*)ctx;

    CborEncoder map_encoder;
    CborError cberr = cbor_encoder_create_map(container, &map_encoder, 5);
    JADE_ASSERT(cberr == CborNoError);

    add_bytes_to_map(&map_encoder, "signature", result->signature, sizeof(result->signature));
    add_bytes_to_map(&map_encoder, "input_blind", result->input_blind, sizeof(result->input_blind));
    add_bytes_to_map(&map_encoder, "stealth_tweak", result->stealth_tweak, sizeof(result->stealth_tweak));
    add_bytes_to_map(&map_encoder, "input_pubkey", result->input_pubkey, sizeof(result->input_pubkey));
    add_bytes_to_map(&map_encoder, "output_commit", result->output_commit, sizeof(result->output_commit));

    cberr = cbor_encoder_close_container(container, &map_encoder);
    JADE_ASSERT(cberr == CborNoError);
}

void sign_mweb_input_process(void* process_ptr)
{
    JADE_LOGI("Starting: %d", xPortGetFreeHeapSize());
    jade_process_t* process = process_ptr;

    ASSERT_CURRENT_MESSAGE(process, "sign_mweb_input");
    ASSERT_KEYCHAIN_UNLOCKED_BY_MESSAGE_SOURCE(process);
    GET_MSG_PARAMS(process);
    CHECK_NETWORK_CONSISTENT(process);

    if (!network_is_litecoin(network_id)) {
        jade_process_reject_message(
            process, CBOR_RPC_BAD_PARAMETERS, "MWEB is only supported on Litecoin networks");
        goto cleanup;
    }

    /* Extract parameters */
    uint64_t features_u64 = 0;
    if (!rpc_get_uint64_t("features", &params, &features_u64) || features_u64 > 0xFF) {
        jade_process_reject_message(
            process, CBOR_RPC_BAD_PARAMETERS, "Failed to extract features from parameters");
        goto cleanup;
    }
    const uint8_t features = (uint8_t)features_u64;

    uint8_t spent_output_id[32];
    if (!rpc_get_n_bytes("spent_output_id", &params, sizeof(spent_output_id), spent_output_id)) {
        jade_process_reject_message(
            process, CBOR_RPC_BAD_PARAMETERS, "Failed to extract spent_output_id from parameters");
        goto cleanup;
    }

    uint8_t spent_output_pk[EC_PUBLIC_KEY_LEN];
    if (!rpc_get_n_bytes("spent_output_pk", &params, sizeof(spent_output_pk), spent_output_pk)) {
        jade_process_reject_message(
            process, CBOR_RPC_BAD_PARAMETERS, "Failed to extract spent_output_pk from parameters");
        goto cleanup;
    }

    uint64_t amount = 0;
    if (!rpc_get_uint64_t("amount", &params, &amount)) {
        jade_process_reject_message(
            process, CBOR_RPC_BAD_PARAMETERS, "Failed to extract amount from parameters");
        goto cleanup;
    }

    uint8_t key_exchange_pk[EC_PUBLIC_KEY_LEN];
    if (!rpc_get_n_bytes("key_exchange_pk", &params, sizeof(key_exchange_pk), key_exchange_pk)) {
        jade_process_reject_message(
            process, CBOR_RPC_BAD_PARAMETERS, "Failed to extract key_exchange_pk from parameters");
        goto cleanup;
    }

    size_t address_index = 0;
    if (!rpc_get_sizet("address_index", &params, &address_index) || address_index > UINT32_MAX) {
        jade_process_reject_message(
            process, CBOR_RPC_BAD_PARAMETERS, "Failed to extract address_index from parameters");
        goto cleanup;
    }

    /* Optional extra_data */
    const uint8_t* extra_data = NULL;
    size_t extra_data_len = 0;
    rpc_get_bytes_ptr("extra_data", &params, &extra_data, &extra_data_len);

    /* Derive scan + spend keys from standard paths */
    uint8_t scan_key[32], spend_key[32];
    SENSITIVE_PUSH(scan_key, sizeof(scan_key));
    SENSITIVE_PUSH(spend_key, sizeof(spend_key));

    if (!mweb_derive_standard_keys(scan_key, spend_key)) {
        SENSITIVE_POP(spend_key);
        SENSITIVE_POP(scan_key);
        jade_process_reject_message(process, CBOR_RPC_INTERNAL_ERROR, "Failed to derive MWEB keys");
        goto cleanup;
    }

    /* Two-stage signing: Stage A derivation then Stage B Schnorr emission. */
    mweb_input_state_t state;
    if (mweb_derive_input_state(scan_key, spend_key, (uint32_t)address_index,
            features, spent_output_id, spent_output_pk, amount,
            key_exchange_pk, &state) != MWEB_OK) {
        SENSITIVE_POP(spend_key);
        SENSITIVE_POP(scan_key);
        jade_process_reject_message(process, CBOR_RPC_INTERNAL_ERROR, "MWEB input signing failed");
        goto cleanup;
    }

    SENSITIVE_POP(spend_key);
    SENSITIVE_POP(scan_key);

    mweb_sign_cbor_result_t result;
    if (mweb_sign_input_from_state(&state, extra_data, extra_data_len,
            result.signature) != MWEB_OK) {
        wally_bzero(&state, sizeof(state));
        jade_process_reject_message(process, CBOR_RPC_INTERNAL_ERROR, "MWEB input signing failed");
        goto cleanup;
    }

    memcpy(result.input_blind, state.blind, 32);
    memcpy(result.stealth_tweak, state.stealth_tweak, 32);
    memcpy(result.input_pubkey, state.input_pubkey, 33);
    memcpy(result.output_commit, state.output_commit, 33);
    wally_bzero(&state, sizeof(state));

    /* Return result map */
    uint8_t buf[512];
    jade_process_reply_to_message_result(process->ctx, buf, sizeof(buf), &result, sign_mweb_result_cb);
    wally_bzero(&result, sizeof(result));
    JADE_LOGI("Success");

cleanup:
    return;
}

/*
 * get_mweb_watch_keys — Export the data needed to import an MWEB watch-only wallet.
 *
 * Params: { "network": "litecoin" }
 * Returns: {
 *   "scan_secret":  <32 bytes>,   (MWEB scan secret from m/0'/100'/0')
 *   "spend_pubkey": <33 bytes>,   (compressed pubkey of m/0'/100'/1')
 *   "fingerprint":  <4 bytes>     (master key fingerprint)
 * }
 */

typedef struct {
    const uint8_t* scan_secret;
    const uint8_t* spend_pubkey;
    const uint8_t* fingerprint;
} watch_keys_ctx_t;

static void watch_keys_result_cb(const void* ctx, CborEncoder* container)
{
    JADE_ASSERT(ctx);
    const watch_keys_ctx_t* wk = (const watch_keys_ctx_t*)ctx;

    CborEncoder map_encoder;
    CborError cberr = cbor_encoder_create_map(container, &map_encoder, 3);
    JADE_ASSERT(cberr == CborNoError);

    add_bytes_to_map(&map_encoder, "scan_secret", wk->scan_secret, 32);
    add_bytes_to_map(&map_encoder, "spend_pubkey", wk->spend_pubkey, EC_PUBLIC_KEY_LEN);
    add_bytes_to_map(&map_encoder, "fingerprint", wk->fingerprint, 4);

    cberr = cbor_encoder_close_container(container, &map_encoder);
    JADE_ASSERT(cberr == CborNoError);
}

void get_mweb_watch_keys_process(void* process_ptr)
{
    JADE_LOGI("Starting: %d", xPortGetFreeHeapSize());
    jade_process_t* process = process_ptr;

    ASSERT_CURRENT_MESSAGE(process, "get_mweb_watch_keys");
    ASSERT_KEYCHAIN_UNLOCKED_BY_MESSAGE_SOURCE(process);
    GET_MSG_PARAMS(process);
    CHECK_NETWORK_CONSISTENT(process);

    if (!network_is_litecoin(network_id)) {
        jade_process_reject_message(
            process, CBOR_RPC_BAD_PARAMETERS, "MWEB is only supported on Litecoin networks");
        goto cleanup;
    }

    /* User confirmation */
    if (!show_mweb_watch_keys_export_activity(network_id)) {
        JADE_LOGW("User declined to export MWEB watch keys");
        jade_process_reject_message(
            process, CBOR_RPC_USER_CANCELLED, "User declined to export MWEB watch keys");
        goto cleanup;
    }

    /* Derive scan + spend keys */
    uint8_t scan_key[32];
    SENSITIVE_PUSH(scan_key, sizeof(scan_key));

    uint8_t spend_key[32];
    SENSITIVE_PUSH(spend_key, sizeof(spend_key));

    if (!mweb_derive_standard_keys(scan_key, spend_key)) {
        SENSITIVE_POP(spend_key);
        SENSITIVE_POP(scan_key);
        jade_process_reject_message(process, CBOR_RPC_INTERNAL_ERROR, "Failed to derive MWEB keys");
        goto cleanup;
    }

    /* Compute spend pubkey, then clear spend secret immediately */
    uint8_t spend_pubkey[EC_PUBLIC_KEY_LEN];
    if (!mweb_derive_spend_pubkey(spend_key, spend_pubkey)) {
        SENSITIVE_POP(spend_key);
        SENSITIVE_POP(scan_key);
        jade_process_reject_message(process, CBOR_RPC_INTERNAL_ERROR, "Failed to derive spend pubkey");
        goto cleanup;
    }
    SENSITIVE_POP(spend_key);

    /* Get master fingerprint */
    uint8_t fingerprint[4];
    wallet_get_fingerprint(fingerprint, sizeof(fingerprint));

    /* Reply with CBOR map */
    const watch_keys_ctx_t wk = {
        .scan_secret = scan_key,
        .spend_pubkey = spend_pubkey,
        .fingerprint = fingerprint,
    };

    uint8_t buf[256];
    jade_process_reply_to_message_result(process->ctx, buf, sizeof(buf), &wk, watch_keys_result_cb);
    JADE_LOGI("Success");

    SENSITIVE_POP(scan_key);

cleanup:
    return;
}
#endif /* AMALGAMATED_BUILD */
