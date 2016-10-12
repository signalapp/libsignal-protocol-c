#include "session_builder.h"
#include "session_builder_internal.h"

#include <assert.h>
#include <string.h>
#include "session_pre_key.h"
#include "session_record.h"
#include "session_state.h"
#include "ratchet.h"
#include "protocol.h"
#include "key_helper.h"
#include "signal_protocol_internal.h"

struct session_builder
{
    signal_protocol_store_context *store;
    const signal_protocol_address *remote_address;
    signal_context *global_context;
};

static int session_builder_process_pre_key_signal_message_v3(session_builder *builder,
        session_record *record, pre_key_signal_message *message, uint32_t *unsigned_pre_key_id);
static int session_builder_process_initiate(session_builder *builder,
        key_exchange_message *message, key_exchange_message **response_message);
static int session_builder_process_response(session_builder *builder,
        key_exchange_message *message);

int session_builder_create(session_builder **builder,
        signal_protocol_store_context *store, const signal_protocol_address *remote_address,
        signal_context *global_context)
{
    session_builder *result = 0;

    assert(store);
    assert(global_context);

    result = malloc(sizeof(session_builder));
    if(!result) {
        return SG_ERR_NOMEM;
    }
    memset(result, 0, sizeof(session_builder));

    result->store = store;
    result->remote_address = remote_address;
    result->global_context = global_context;

    *builder = result;
    return 0;
}

int session_builder_process_pre_key_signal_message(session_builder *builder,
        session_record *record, pre_key_signal_message *message, uint32_t *unsigned_pre_key_id)
{
    int result = 0;
    int has_unsigned_pre_key_id_result = 0;
    uint32_t unsigned_pre_key_id_result = 0;
    ec_public_key *their_identity_key = pre_key_signal_message_get_identity_key(message);

    result = signal_protocol_identity_is_trusted_identity(builder->store,
            builder->remote_address,
            their_identity_key);
    if(result < 0) {
        goto complete;
    }
    if(result == 0) {
        result = SG_ERR_UNTRUSTED_IDENTITY;
        goto complete;
    }

    result = session_builder_process_pre_key_signal_message_v3(builder, record, message, &unsigned_pre_key_id_result);
    if(result < 0) {
        goto complete;
    }
    has_unsigned_pre_key_id_result = result;

    result = signal_protocol_identity_save_identity(builder->store,
            builder->remote_address,
            their_identity_key);
    if(result < 0) {
        goto complete;
    }

    result = has_unsigned_pre_key_id_result;

complete:
    if(result >= 0) {
        *unsigned_pre_key_id = unsigned_pre_key_id_result;
    }
    return result;
}

static int session_builder_process_pre_key_signal_message_v3(session_builder *builder,
        session_record *record, pre_key_signal_message *message, uint32_t *unsigned_pre_key_id)
{
    int result = 0;
    uint32_t unsigned_pre_key_id_result = 0;
    session_signed_pre_key *our_signed_pre_key = 0;
    ratchet_identity_key_pair *our_identity_key = 0;
    bob_signal_protocol_parameters *parameters = 0;
    session_pre_key *session_our_one_time_pre_key = 0;
    ec_key_pair *our_one_time_pre_key = 0;
    session_state *state = 0;
    uint32_t local_registration_id = 0;

    int has_session_state = session_record_has_session_state(record,
            pre_key_signal_message_get_message_version(message),
            pre_key_signal_message_get_base_key(message));
    if(has_session_state) {
        signal_log(builder->global_context, SG_LOG_INFO, "We've already setup a session for this V3 message, letting bundled message fall through...");
        result = 0;
        goto complete;
    }

    result = signal_protocol_signed_pre_key_load_key(builder->store,
            &our_signed_pre_key,
            pre_key_signal_message_get_signed_pre_key_id(message));
    if(result < 0) {
        goto complete;
    }

    result = signal_protocol_identity_get_key_pair(builder->store, &our_identity_key);
    if(result < 0) {
        goto complete;
    }

    if(pre_key_signal_message_has_pre_key_id(message)) {
        result = signal_protocol_pre_key_load_key(builder->store,
                &session_our_one_time_pre_key,
                pre_key_signal_message_get_pre_key_id(message));
        if(result < 0) {
            goto complete;
        }
        our_one_time_pre_key = session_pre_key_get_key_pair(session_our_one_time_pre_key);
    }

    result = bob_signal_protocol_parameters_create(
            &parameters,
            our_identity_key,
            session_signed_pre_key_get_key_pair(our_signed_pre_key),
            our_one_time_pre_key,
            session_signed_pre_key_get_key_pair(our_signed_pre_key),
            pre_key_signal_message_get_identity_key(message),
            pre_key_signal_message_get_base_key(message));
    if(result < 0) {
        goto complete;
    }

    if(!session_record_is_fresh(record)) {
        result = session_record_archive_current_state(record);
        if(result < 0) {
            goto complete;
        }
    }

    state = session_record_get_state(record);

    result = ratcheting_session_bob_initialize(
            state, parameters,
            builder->global_context);
    if(result < 0) {
        goto complete;
    }

    result = signal_protocol_identity_get_local_registration_id(builder->store, &local_registration_id);
    if(result < 0) {
        goto complete;
    }

    session_state_set_local_registration_id(state, local_registration_id);
    session_state_set_remote_registration_id(state,
            pre_key_signal_message_get_registration_id(message));
    session_state_set_alice_base_key(state,
            pre_key_signal_message_get_base_key(message));;

    if(pre_key_signal_message_has_pre_key_id(message) &&
            pre_key_signal_message_get_pre_key_id(message) != PRE_KEY_MEDIUM_MAX_VALUE) {
        unsigned_pre_key_id_result = pre_key_signal_message_get_pre_key_id(message);
        result = 1;
    }
    else {
        result = 0;
    }

complete:
    SIGNAL_UNREF(parameters);
    SIGNAL_UNREF(our_identity_key);
    SIGNAL_UNREF(our_signed_pre_key);
    SIGNAL_UNREF(session_our_one_time_pre_key);
    if(result >= 0) {
        *unsigned_pre_key_id = unsigned_pre_key_id_result;
    }
    return result;
}

int session_builder_process_pre_key_bundle(session_builder *builder, session_pre_key_bundle *bundle)
{
    int result = 0;
    session_record *record = 0;
    ec_key_pair *our_base_key = 0;
    ratchet_identity_key_pair *our_identity_key = 0;
    alice_signal_protocol_parameters *parameters = 0;
    ec_public_key *signed_pre_key = 0;
    ec_public_key *pre_key = 0;
    ec_public_key *their_identity_key = 0;
    ec_public_key *their_signed_pre_key = 0;
    ec_public_key *their_one_time_pre_key = 0;
    int has_their_one_time_pre_key_id = 0;
    uint32_t their_one_time_pre_key_id = 0;
    session_state *state = 0;
    uint32_t local_registration_id = 0;

    assert(builder);
    assert(builder->store);
    assert(bundle);
    signal_lock(builder->global_context);

    result = signal_protocol_identity_is_trusted_identity(builder->store,
            builder->remote_address,
            session_pre_key_bundle_get_identity_key(bundle));
    if(result < 0) {
        goto complete;
    }
    if(result == 0) {
        result = SG_ERR_UNTRUSTED_IDENTITY;
        goto complete;
    }

    signed_pre_key = session_pre_key_bundle_get_signed_pre_key(bundle);
    pre_key = session_pre_key_bundle_get_pre_key(bundle);

    if(signed_pre_key) {
        ec_public_key *identity_key = session_pre_key_bundle_get_identity_key(bundle);
        signal_buffer *signature = session_pre_key_bundle_get_signed_pre_key_signature(bundle);

        signal_buffer *serialized_signed_pre_key = 0;
        result = ec_public_key_serialize(&serialized_signed_pre_key, signed_pre_key);
        if(result < 0) {
            goto complete;
        }

        result = curve_verify_signature(identity_key,
                signal_buffer_data(serialized_signed_pre_key),
                signal_buffer_len(serialized_signed_pre_key),
                signal_buffer_data(signature),
                signal_buffer_len(signature));

        signal_buffer_free(serialized_signed_pre_key);

        if(result == 0) {
            signal_log(builder->global_context, SG_LOG_WARNING, "invalid signature on device key!");
            result = SG_ERR_INVALID_KEY;
        }
        if(result < 0) {
            goto complete;
        }
    }

    if(!signed_pre_key) {
        result = SG_ERR_INVALID_KEY;
        signal_log(builder->global_context, SG_LOG_WARNING, "no signed pre key!");
        goto complete;
    }

    result = signal_protocol_session_load_session(builder->store, &record, builder->remote_address);
    if(result < 0) {
        goto complete;
    }

    result = curve_generate_key_pair(builder->global_context, &our_base_key);
    if(result < 0) {
        goto complete;
    }

    their_identity_key = session_pre_key_bundle_get_identity_key(bundle);
    their_signed_pre_key = signed_pre_key;
    their_one_time_pre_key = pre_key;

    if(their_one_time_pre_key) {
        has_their_one_time_pre_key_id = 1;
        their_one_time_pre_key_id = session_pre_key_bundle_get_pre_key_id(bundle);
    }

    result = signal_protocol_identity_get_key_pair(builder->store, &our_identity_key);
    if(result < 0) {
        goto complete;
    }

    result = alice_signal_protocol_parameters_create(&parameters,
            our_identity_key,
            our_base_key,
            their_identity_key,
            their_signed_pre_key,
            their_one_time_pre_key,
            their_signed_pre_key);
    if(result < 0) {
        goto complete;
    }

    if(!session_record_is_fresh(record)) {
        result = session_record_archive_current_state(record);
        if(result < 0) {
            goto complete;
        }
    }

    state = session_record_get_state(record);

    result = ratcheting_session_alice_initialize(
            state, parameters,
            builder->global_context);
    if(result < 0) {
        goto complete;
    }

    session_state_set_unacknowledged_pre_key_message(state,
            has_their_one_time_pre_key_id ? &their_one_time_pre_key_id : 0,
            session_pre_key_bundle_get_signed_pre_key_id(bundle),
            ec_key_pair_get_public(our_base_key));

    result = signal_protocol_identity_get_local_registration_id(builder->store, &local_registration_id);
    if(result < 0) {
        goto complete;
    }

    session_state_set_local_registration_id(state, local_registration_id);
    session_state_set_remote_registration_id(state,
            session_pre_key_bundle_get_registration_id(bundle));
    session_state_set_alice_base_key(state, ec_key_pair_get_public(our_base_key));

    result = signal_protocol_session_store_session(builder->store, builder->remote_address, record);
    if(result < 0) {
        goto complete;
    }

    result = signal_protocol_identity_save_identity(builder->store,
            builder->remote_address,
            their_identity_key);
    if(result < 0) {
        goto complete;
    }

complete:
    SIGNAL_UNREF(record);
    SIGNAL_UNREF(our_base_key);
    SIGNAL_UNREF(our_identity_key);
    SIGNAL_UNREF(parameters);
    signal_unlock(builder->global_context);
    return result;
}

int session_builder_process_key_exchange_message(session_builder *builder, key_exchange_message *message, key_exchange_message **response_message)
{
    int result = 0;
    key_exchange_message *result_response_message = 0;

    assert(builder);
    assert(builder->store);
    signal_lock(builder->global_context);

    result = signal_protocol_identity_is_trusted_identity(builder->store,
            builder->remote_address,
            key_exchange_message_get_identity_key(message));
    if(result < 0) {
        goto complete;
    }
    if(result == 0) {
        result = SG_ERR_UNTRUSTED_IDENTITY;
        goto complete;
    }
    result = 0;

    if(key_exchange_message_is_initiate(message)) {
        result = session_builder_process_initiate(builder, message, &result_response_message);
    }
    else {
        result = session_builder_process_response(builder, message);
    }

complete:
    if(result >= 0) {
        *response_message = result_response_message;
    }
    else {
        SIGNAL_UNREF(result_response_message);
    }
    signal_unlock(builder->global_context);
    return result;
}

static int session_builder_process_initiate(session_builder *builder, key_exchange_message *message, key_exchange_message **response_message)
{
    int result = 0;
    key_exchange_message *result_response_message = 0;

    uint32_t flags = KEY_EXCHANGE_RESPONSE_FLAG;
    session_record *record = 0;
    session_state *state = 0;
    ratchet_identity_key_pair *identity_key_pair = 0;
    ec_key_pair *our_base_key = 0;
    ec_key_pair *our_ratchet_key = 0;
    symmetric_signal_protocol_parameters *parameters = 0;
    ratchet_identity_key_pair *parameters_identity_key = 0;
    ec_key_pair *parameters_base_key = 0;
    signal_buffer *parameters_public_base_key_serialized = 0;
    ec_key_pair *parameters_ratchet_key = 0;
    signal_buffer *base_key_signature = 0;
    ec_public_key *message_identity_key = 0;
    ec_public_key *message_base_key = 0;
    signal_buffer *message_base_key_serialized = 0;
    uint8_t *message_base_key_signature = 0;

    result = signal_protocol_session_load_session(builder->store, &record, builder->remote_address);
    if(result < 0) {
        goto complete;
    }

    message_identity_key = key_exchange_message_get_identity_key(message);
    message_base_key = key_exchange_message_get_base_key(message);

    result = ec_public_key_serialize(&message_base_key_serialized, message_base_key);
    if(result < 0) {
        goto complete;
    }

    message_base_key_signature = key_exchange_message_get_base_key_signature(message);

    result = curve_verify_signature(message_identity_key,
            signal_buffer_data(message_base_key_serialized),
            signal_buffer_len(message_base_key_serialized),
            message_base_key_signature, CURVE_SIGNATURE_LEN);
    signal_buffer_free(message_base_key_serialized);
    if(result < 0) {
        goto complete;
    }
    if(result != 1) {
        signal_log(builder->global_context, SG_LOG_WARNING, "Bad signature!");
        result = SG_ERR_INVALID_KEY;
        goto complete;
    }

    state = session_record_get_state(record);
    if(!session_state_has_pending_key_exchange(state)) {
        result = signal_protocol_identity_get_key_pair(builder->store, &identity_key_pair);
        if(result < 0) {
            goto complete;
        }

        result = curve_generate_key_pair(builder->global_context, &our_base_key);
        if(result < 0) {
            goto complete;
        }

        result = curve_generate_key_pair(builder->global_context, &our_ratchet_key);
        if(result < 0) {
            goto complete;
        }

        result = symmetric_signal_protocol_parameters_create(
                &parameters,
                identity_key_pair,
                our_base_key,
                our_ratchet_key,
                key_exchange_message_get_base_key(message),
                key_exchange_message_get_ratchet_key(message),
                key_exchange_message_get_identity_key(message));
        if(result < 0) {
            goto complete;
        }
    }
    else {
        result = symmetric_signal_protocol_parameters_create(
                &parameters,
                session_state_get_pending_key_exchange_identity_key(state),
                session_state_get_pending_key_exchange_base_key(state),
                session_state_get_pending_key_exchange_ratchet_key(state),
                key_exchange_message_get_base_key(message),
                key_exchange_message_get_ratchet_key(message),
                key_exchange_message_get_identity_key(message));
        if(result < 0) {
            goto complete;
        }

        flags |= KEY_EXCHANGE_SIMULTAENOUS_INITIATE_FLAG;
    }

    if(!session_record_is_fresh(record)) {
        result = session_record_archive_current_state(record);
        if(result < 0) {
            goto complete;
        }
    }

    state = session_record_get_state(record);
    result = ratcheting_session_symmetric_initialize(
            state, parameters,
            builder->global_context);
    if(result < 0) {
        goto complete;
    }

    result = signal_protocol_session_store_session(builder->store, builder->remote_address, record);
    if(result < 0) {
        goto complete;
    }

    result = signal_protocol_identity_save_identity(builder->store,
            builder->remote_address,
            key_exchange_message_get_identity_key(message));
    if(result < 0) {
        goto complete;
    }

    parameters_identity_key = symmetric_signal_protocol_parameters_get_our_identity_key(parameters);
    parameters_base_key = symmetric_signal_protocol_parameters_get_our_base_key(parameters);
    parameters_ratchet_key = symmetric_signal_protocol_parameters_get_our_ratchet_key(parameters);

    result = ec_public_key_serialize(&parameters_public_base_key_serialized,
            ec_key_pair_get_public(parameters_base_key));
    if(result < 0) {
        goto complete;
    }

    result = curve_calculate_signature(builder->global_context,
            &base_key_signature,
            ratchet_identity_key_pair_get_private(parameters_identity_key),
            signal_buffer_data(parameters_public_base_key_serialized),
            signal_buffer_len(parameters_public_base_key_serialized));
    if(result < 0) {
        goto complete;
    }

    result = key_exchange_message_create(&result_response_message,
            session_state_get_session_version(state),
            key_exchange_message_get_sequence(message),
            flags,
            ec_key_pair_get_public(parameters_base_key),
            signal_buffer_data(base_key_signature),
            ec_key_pair_get_public(parameters_ratchet_key),
            ratchet_identity_key_pair_get_public(parameters_identity_key));

complete:
    signal_buffer_free(parameters_public_base_key_serialized);
    signal_buffer_free(base_key_signature);
    SIGNAL_UNREF(our_base_key);
    SIGNAL_UNREF(our_ratchet_key);
    SIGNAL_UNREF(identity_key_pair);
    SIGNAL_UNREF(parameters);
    SIGNAL_UNREF(record);
    if(result >= 0) {
        *response_message = result_response_message;
    }
    else {
        SIGNAL_UNREF(result_response_message);
    }
    return result;
}

static int session_builder_process_response(session_builder *builder, key_exchange_message *message)
{
    int result = 0;
    session_record *record = 0;
    session_state *state = 0;
    int has_pending_key_exchange = 0;
    int is_simultaneous_initiate_response = 0;
    symmetric_signal_protocol_parameters *parameters = 0;

    result = signal_protocol_session_load_session(builder->store, &record, builder->remote_address);
    if(result < 0) {
        goto complete;
    }

    state = session_record_get_state(record);
    has_pending_key_exchange = session_state_has_pending_key_exchange(state);
    is_simultaneous_initiate_response = key_exchange_message_is_response_for_simultaneous_initiate(message);

    if(!has_pending_key_exchange ||
            session_state_get_pending_key_exchange_sequence(state) != key_exchange_message_get_sequence(message)) {
        signal_log(builder->global_context, SG_LOG_INFO, "No matching sequence for response. Is simultaneous initiate response: %d", is_simultaneous_initiate_response);
        if(!is_simultaneous_initiate_response) {
            result = SG_ERR_STALE_KEY_EXCHANGE;
            goto complete;
        }
        else  {
            result = SG_SUCCESS;
            goto complete;
        }
    }

    result = symmetric_signal_protocol_parameters_create(
            &parameters,
            session_state_get_pending_key_exchange_identity_key(state),
            session_state_get_pending_key_exchange_base_key(state),
            session_state_get_pending_key_exchange_ratchet_key(state),
            key_exchange_message_get_base_key(message),
            key_exchange_message_get_ratchet_key(message),
            key_exchange_message_get_identity_key(message));
    if(result < 0) {
        goto complete;
    }

    if(!session_record_is_fresh(record)) {
        result = session_record_archive_current_state(record);
        if(result < 0) {
            goto complete;
        }
    }

    state = session_record_get_state(record);
    result = ratcheting_session_symmetric_initialize(
            state, parameters,
            builder->global_context);
    if(result < 0) {
        goto complete;
    }

    result = signal_protocol_session_store_session(builder->store, builder->remote_address, record);
    if(result < 0) {
        goto complete;
    }

    if(session_state_get_session_version(state) >= 3) {
        ec_public_key *message_identity_key = key_exchange_message_get_identity_key(message);
        ec_public_key *message_base_key = key_exchange_message_get_base_key(message);
        signal_buffer *message_base_key_serialized = 0;
        uint8_t *message_base_key_signature = 0;

        result = ec_public_key_serialize(&message_base_key_serialized, message_base_key);
        if(result < 0) {
            goto complete;
        }

        message_base_key_signature = key_exchange_message_get_base_key_signature(message);

        result = curve_verify_signature(message_identity_key,
                signal_buffer_data(message_base_key_serialized),
                signal_buffer_len(message_base_key_serialized),
                message_base_key_signature, CURVE_SIGNATURE_LEN);
        signal_buffer_free(message_base_key_serialized);
        if(result < 0) {
            goto complete;
        }
        if(result != 1) {
            signal_log(builder->global_context, SG_LOG_WARNING, "Base key signature doesn't match!");
            result = SG_ERR_INVALID_KEY;
            goto complete;
        }
    }

    result = signal_protocol_session_store_session(builder->store, builder->remote_address, record);
    if(result < 0) {
        goto complete;
    }

    result = signal_protocol_identity_save_identity(builder->store,
            builder->remote_address,
            key_exchange_message_get_identity_key(message));
    if(result < 0) {
        goto complete;
    }

complete:
    SIGNAL_UNREF(parameters);
    SIGNAL_UNREF(record);
    return result;
}

int session_builder_process(session_builder *builder, key_exchange_message **message)
{
    int result = 0;
    key_exchange_message *result_message = 0;
    int random_value = 0;
    uint32_t sequence = 0;
    uint32_t flags = KEY_EXCHANGE_INITIATE_FLAG;
    ec_key_pair *base_key = 0;
    ec_key_pair *ratchet_key = 0;
    ratchet_identity_key_pair *identity_key = 0;
    signal_buffer *base_key_public_serialized = 0;
    signal_buffer *base_key_signature = 0;
    session_record *record = 0;
    session_state *state = 0;

    assert(builder);
    assert(builder->store);
    signal_lock(builder->global_context);

    result = signal_protocol_key_helper_get_random_sequence(&random_value, 65534, builder->global_context);
    if(result < 0) {
        goto complete;
    }
    sequence = ((uint32_t)random_value) + 1;

    result = curve_generate_key_pair(builder->global_context, &base_key);
    if(result < 0) {
        goto complete;
    }

    result = curve_generate_key_pair(builder->global_context, &ratchet_key);
    if(result < 0) {
        goto complete;
    }

    result = signal_protocol_identity_get_key_pair(builder->store, &identity_key);
    if(result < 0) {
        goto complete;
    }

    result = ec_public_key_serialize(&base_key_public_serialized, ec_key_pair_get_public(base_key));
    if(result < 0) {
        goto complete;
    }

    result = curve_calculate_signature(builder->global_context, &base_key_signature,
            ratchet_identity_key_pair_get_private(identity_key),
            signal_buffer_data(base_key_public_serialized),
            signal_buffer_len(base_key_public_serialized));
    if(result < 0) {
        goto complete;
    }

    if(signal_buffer_len(base_key_signature) != CURVE_SIGNATURE_LEN) {
        result = SG_ERR_UNKNOWN;
        goto complete;
    }

    result = signal_protocol_session_load_session(builder->store, &record, builder->remote_address);
    if(result < 0) {
        goto complete;
    }

    state = session_record_get_state(record);
    session_state_set_pending_key_exchange(state, sequence, base_key, ratchet_key, identity_key);

    result = signal_protocol_session_store_session(builder->store, builder->remote_address, record);
    if(result < 0) {
        goto complete;
    }

    result = key_exchange_message_create(&result_message,
            CIPHERTEXT_CURRENT_VERSION, sequence, flags,
            ec_key_pair_get_public(base_key),
            signal_buffer_data(base_key_signature),
            ec_key_pair_get_public(ratchet_key),
            ratchet_identity_key_pair_get_public(identity_key));

complete:
    SIGNAL_UNREF(record);
    signal_buffer_free(base_key_signature);
    signal_buffer_free(base_key_public_serialized);
    SIGNAL_UNREF(identity_key);
    SIGNAL_UNREF(ratchet_key);
    SIGNAL_UNREF(base_key);
    if(result >= 0) {
        *message = result_message;
    }
    else {
        result = SG_ERR_INVALID_KEY;
        SIGNAL_UNREF(result_message);
    }
    signal_unlock(builder->global_context);
    return result;
}

void session_builder_free(session_builder *builder)
{
    if(builder) {
        free(builder);
    }
}
