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
#include "signal_protocol_types.h"
#include "sc.h"
#include "ge.h"
#include "generalized/gen_crypto_additions.h"
#include "crypto_additions.h"
#include "../tests/test_common.h"

#define DJB_KEY_LEN 32

struct session_builder
{
    signal_protocol_store_context *store;
    const signal_protocol_address *remote_address;
    signal_context *global_context;
};

signal_protocol_store_context *session_builder_get_store(session_builder *session_builder)
{
    return session_builder->store;
};

const signal_protocol_address *session_builder_get_remote_address(session_builder *session_builder)
{
    return session_builder->remote_address;
};

static int session_builder_process_pre_key_signal_message_v3(session_builder *builder,
        session_record *record, pre_key_signal_message *message, uint32_t *unsigned_pre_key_id);

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

// originally fixed incompatible limb definitions b/n curve25519donna and ed25519,
// but ultimately unnecessary
void contract(uint8_t* out, const fe in) {
	//int64_t limbs[10]={0};
	//for(int i=0;i<10;i++)
	//	limbs[i]=in[i];  //write 32B value to 64B spot
	//fcontract(out,limbs);//condense
	fe_tobytes(out,in);
}

/* compacts full general representation of a curve point to just the
 * 32Byte reduced x-value: X/Z. NOTE in edwards coordinates!! */
void justx3(uint8_t* out, const ge_p3* in) {
	fe z_inv={0};
	fe ret={0};
	fe_invert(z_inv,in->Z);
	fe_mul(ret,z_inv,in->X); //prepare short x
	contract(out,ret);
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
    signal_buffer *r_buf = 0;
    signal_buffer *c_buf = 0;
    r_buf = signal_buffer_alloc(DJB_KEY_LEN);
    c_buf = signal_buffer_alloc(DJB_KEY_LEN);
    signal_buffer *s_buf = 0;
    s_buf = signal_buffer_alloc(DJB_KEY_LEN);
    ge_p3 Xfull;
    signal_buffer *Xfull_buf = 0;
    ge_p3 Rfull;
    signal_buffer *Rfull_buf = 0;
    Xfull_buf = signal_buffer_alloc(128);
    Rfull_buf = signal_buffer_alloc(128);
    ge_p3 alice_lhs_pre;
    ge_p3 alice_rhs_pre;
    uint8_t *alice_lhs = malloc(DJB_KEY_LEN);
    uint8_t *alice_rhs = malloc(DJB_KEY_LEN);

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

        uint8_t *Rhatfull_buf = session_pre_key_bundle_get_Rhatfull(bundle);
        ge_p3 Rhatfull;
        ge_frombytes_128(&Rhatfull, Rhatfull_buf);

        uint8_t *Yfull_buf = session_pre_key_bundle_get_Yfull(bundle);
        ge_p3 Yfull;
        ge_frombytes_128(&Yfull, Yfull_buf);

        uint8_t *shat = session_pre_key_bundle_get_shat(bundle);

        uint8_t *chat = session_pre_key_bundle_get_chat(bundle);

        ge_scalarmult_base(&alice_lhs_pre,shat);
        ge_scalarmult(&alice_rhs_pre,chat,&Yfull);
         
        ge_p3_add(&alice_rhs_pre,&alice_rhs_pre,&Rhatfull);
         
        justx3(alice_lhs,&alice_lhs_pre);
        justx3(alice_rhs,&alice_rhs_pre);
         
        result = memcmp(alice_lhs,alice_rhs,DJB_KEY_LEN);
         
        if (result!=0) {
        printf("test failed!\n");
        printf("quiting\n");
        goto complete;
        } else printf("\tpassed.\n");
    
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

    // Generate random value for r
    ec_private_key *r = 0;
    result = curve_generate_private_key(builder->global_context, &r);
    if (result < 0) {
        goto complete;
    }
    r_buf = signal_buffer_create(get_private_data(r), DJB_KEY_LEN); 

    // generate hash value for c
    void *hmac_context = 0;
    uint8_t csalt[DJB_KEY_LEN];
    memset(csalt, 0, sizeof(csalt));

    // initialize HMAC_CTX
    result = signal_hmac_sha256_init(builder->global_context, &hmac_context, csalt, DJB_KEY_LEN);
    if (result < 0) {
        goto complete;
    }

    // digest input message stream A
    result = signal_hmac_sha256_update(builder->global_context, hmac_context, get_public_data(ratchet_identity_key_pair_get_public(our_identity_key)), DJB_KEY_LEN);
    if (result < 0) {
        goto complete;
    }

    // digest input message stream X 
    result = signal_hmac_sha256_update(builder->global_context, hmac_context, get_public_data(ec_key_pair_get_public(our_base_key)), DJB_KEY_LEN);
    if (result < 0) {
        goto complete;
    }

    // digest input message stream B
    result = signal_hmac_sha256_update(builder->global_context, hmac_context, get_public_data(their_identity_key), DJB_KEY_LEN);
    if (result < 0) {
        goto complete;
    }

    // place authentication code in c_buf
    result = signal_hmac_sha256_final(builder->global_context, hmac_context, &c_buf);
    if (result < 0) {
        goto complete;
    }
    
    signal_hmac_sha256_cleanup(builder->global_context, hmac_context);

// "clamping" suggested in Alex's code ---added
    c_buf->data[31] &= 127; 
    c_buf->data[31] |= 64;

    // generate value for s
    // s = r+cxmodq
    sc_muladd(signal_buffer_data(s_buf), get_private_data(ec_key_pair_get_private(our_base_key)), signal_buffer_data(c_buf), signal_buffer_data(r_buf));

    // generate Xfull
    ge_scalarmult_base(&Xfull, get_private_data(ec_key_pair_get_private(our_base_key)));
    ge_p3_tobytes_128(signal_buffer_data(Xfull_buf), &Xfull);

    // generate Rfull
    ge_scalarmult_base(&Rfull, r_buf->data);
    ge_p3_tobytes_128(signal_buffer_data(Rfull_buf), &Rfull);

    ge_scalarmult_base(&alice_lhs_pre, session_pre_key_bundle_get_shat(bundle));

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
    session_state_set_alice_s(state, s_buf);
    session_state_set_alice_c(state, c_buf);
    session_state_set_alice_Xfull(state, Xfull_buf);
    session_state_set_alice_Rfull(state, Rfull_buf);

    printf("stored s_buf.....\n");
    print(session_state_get_alice_s(state), session_state_get_alice_s(state)->len);
    printf("stored c_buf.....\n");
    print(session_state_get_alice_c(state), session_state_get_alice_c(state)->len);
    printf("stored Xfull_buf.....\n");
    print(session_state_get_alice_Xfull(state), session_state_get_alice_Xfull(state)->len);
    printf("stored Rfull_buf.....\n");
    print(session_state_get_alice_Rfull(state), session_state_get_alice_Rfull(state)->len);

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

void build_bob_lhs(uint8_t* bob_lhs, signal_buffer** s_buf) {
    uint8_t *s = signal_buffer_data(*s_buf);
    ge_p3 bob_lhs_pre;
    ge_scalarmult_base(&bob_lhs_pre,s);
    justx3(bob_lhs,&bob_lhs_pre);
}

void build_bob_rhs(uint8_t* bob_rhs, signal_buffer** c_buf, signal_buffer** Xfull_buf, signal_buffer** Rfull_buf){
    uint8_t *c = signal_buffer_data(*c_buf);
    uint8_t *Xfull_data = signal_buffer_data(*Xfull_buf);
    uint8_t *Rfull_data = signal_buffer_data(*Rfull_buf);

    ge_p3 Xfull;
    ge_p3 Rfull;
    ge_p3 bob_rhs_pre;   
    ge_frombytes_128(&Xfull, Xfull_data);
    ge_frombytes_128(&Rfull, Rfull_data);
    
    ge_scalarmult(&bob_rhs_pre, c, &Xfull); 
    ge_p3_add(&bob_rhs_pre,&bob_rhs_pre,&Rfull);
    justx3(bob_rhs, &bob_rhs_pre);
}

void session_builder_free(session_builder *builder)
{
    if(builder) {
        free(builder);
    }
}
