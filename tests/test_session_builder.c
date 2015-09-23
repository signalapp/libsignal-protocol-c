#include <stdio.h>
#include <stdlib.h>
#include <check.h>
#include <pthread.h>

#include "axolotl.h"
#include "session_record.h"
#include "session_state.h"
#include "session_cipher.h"
#include "session_builder.h"
#include "session_pre_key.h"
#include "curve.h"
#include "ratchet.h"
#include "protocol.h"
#include "test_common.h"

static axolotl_address alice_address = {
        "+14151111111", 12, 1
};

static axolotl_address bob_address = {
        "+14152222222", 12, 1
};

axolotl_context *global_context;
pthread_mutex_t global_mutex;
pthread_mutexattr_t global_mutex_attr;

void run_interaction(axolotl_store_context *alice_store, axolotl_store_context *bob_store);
int test_basic_pre_key_v3_decrypt_callback(session_cipher *cipher, axolotl_buffer *plaintext, void *decrypt_context);

void test_lock(void *user_data)
{
    pthread_mutex_lock(&global_mutex);
}

void test_unlock(void *user_data)
{
    pthread_mutex_unlock(&global_mutex);
}

void test_setup()
{
    int result;

    pthread_mutexattr_init(&global_mutex_attr);
    pthread_mutexattr_settype(&global_mutex_attr, PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(&global_mutex, &global_mutex_attr);

    result = axolotl_context_create(&global_context, 0);
    ck_assert_int_eq(result, 0);
    axolotl_context_set_log_function(global_context, test_log);

    setup_test_crypto_provider(global_context);

    result = axolotl_context_set_locking_functions(global_context, test_lock, test_unlock);
    ck_assert_int_eq(result, 0);
}

void test_teardown()
{
    axolotl_context_destroy(global_context);

    pthread_mutex_destroy(&global_mutex);
    pthread_mutexattr_destroy(&global_mutex_attr);
}

START_TEST(test_basic_pre_key_v2)
{
    int result = 0;

    /* Create Alice's data store and session builder */
    axolotl_store_context *alice_store = 0;
    setup_test_store_context(&alice_store, global_context);
    session_builder *alice_session_builder = 0;
    result = session_builder_create(&alice_session_builder, alice_store, &bob_address, global_context);
    ck_assert_int_eq(result, 0);

    /* Create Bob's data store and pre key bundle */
    axolotl_store_context *bob_store = 0;
    setup_test_store_context(&bob_store, global_context);

    uint32_t bob_local_registration_id = 0;
    result = axolotl_identity_get_local_registration_id(bob_store, &bob_local_registration_id);
    ck_assert_int_eq(result, 0);

    ec_key_pair *bob_pre_key_pair = 0;
    result = curve_generate_key_pair(global_context, &bob_pre_key_pair);
    ck_assert_int_eq(result, 0);

    ratchet_identity_key_pair *bob_identity_key_pair = 0;
    result = axolotl_identity_get_key_pair(bob_store, &bob_identity_key_pair);
    ck_assert_int_eq(result, 0);

    session_pre_key_bundle *bob_pre_key = 0;
    result = session_pre_key_bundle_create(&bob_pre_key,
            bob_local_registration_id,
            1, /* device ID */
            31337, /* pre key ID */
            ec_key_pair_get_public(bob_pre_key_pair),
            0, 0, 0, 0, /* no signed pre key or signature */
            ratchet_identity_key_pair_get_public(bob_identity_key_pair));
    ck_assert_int_eq(result, 0);

    /* Have Alice process Bob's pre key bundle */
    result = session_builder_process_pre_key_bundle(alice_session_builder, bob_pre_key);
    ck_assert_int_eq(result, 0);

    /* Check that we can load the session state and verify its version */
    result = axolotl_session_contains_session(alice_store, &bob_address);
    ck_assert_int_eq(result, 1);

    session_record *loaded_record = 0;
    session_state *loaded_record_state = 0;
    result = axolotl_session_load_session(alice_store, &loaded_record, &bob_address);
    ck_assert_int_eq(result, 0);

    loaded_record_state = session_record_get_state(loaded_record);
    ck_assert_ptr_ne(loaded_record_state, 0);

    ck_assert_int_eq(session_state_get_session_version(loaded_record_state), 2);

    AXOLOTL_UNREF(loaded_record);
    loaded_record = 0;
    loaded_record_state = 0;

    static const char original_message[] = "L'homme est condamné à être libre";
    size_t original_message_len = sizeof(original_message) - 1;
    session_cipher *alice_session_cipher = 0;
    result = session_cipher_create(&alice_session_cipher, alice_store, &bob_address, global_context);
    ck_assert_int_eq(result, 0);

    ciphertext_message *outgoing_message = 0;
    result = session_cipher_encrypt(alice_session_cipher, (uint8_t *)original_message, original_message_len, &outgoing_message);
    ck_assert_int_eq(result, 0);

    ck_assert_int_eq(ciphertext_message_get_type(outgoing_message), CIPHERTEXT_PREKEY_TYPE);

    axolotl_buffer *outgoing_serialized = ciphertext_message_get_serialized(outgoing_message);

    pre_key_whisper_message *incoming_message = 0;
    result = pre_key_whisper_message_deserialize(&incoming_message,
            axolotl_buffer_data(outgoing_serialized),
            axolotl_buffer_len(outgoing_serialized), global_context);
    ck_assert_int_eq(result, 0);

    session_pre_key *bob_pre_key_record = 0;
    result = session_pre_key_create(&bob_pre_key_record,
            session_pre_key_bundle_get_pre_key_id(bob_pre_key),
            bob_pre_key_pair);
    ck_assert_int_eq(result, 0);

    result = axolotl_pre_key_store_key(bob_store, bob_pre_key_record);
    ck_assert_int_eq(result, 0);

    session_cipher *bob_session_cipher = 0;
    result = session_cipher_create(&bob_session_cipher, bob_store, &alice_address, global_context);
    ck_assert_int_eq(result, 0);

    axolotl_buffer *plaintext = 0;
    result = session_cipher_decrypt_pre_key_whisper_message(bob_session_cipher, incoming_message, 0, &plaintext);
    ck_assert_int_eq(result, 0);

    ck_assert_int_eq(axolotl_session_contains_session(bob_store, &alice_address), 1);

    session_record *alice_recipient_session_record = 0;
    axolotl_session_load_session(bob_store, &alice_recipient_session_record, &alice_address);

    session_state *alice_recipient_session_state = session_record_get_state(alice_recipient_session_record);
    ck_assert_int_eq(session_state_get_session_version(alice_recipient_session_state), 2);

    uint8_t *plaintext_data = axolotl_buffer_data(plaintext);
    size_t plaintext_len = axolotl_buffer_len(plaintext);

    ck_assert_int_eq(original_message_len, plaintext_len);
    ck_assert_int_eq(memcmp(original_message, plaintext_data, plaintext_len), 0);

    ciphertext_message *bob_outgoing_message = 0;
    result = session_cipher_encrypt(bob_session_cipher, (uint8_t *)original_message, original_message_len, &bob_outgoing_message);
    ck_assert_int_eq(result, 0);

    ck_assert_int_eq(ciphertext_message_get_type(bob_outgoing_message), CIPHERTEXT_WHISPER_TYPE);

    axolotl_buffer *alice_plaintext = 0;
    result = session_cipher_decrypt_whisper_message(alice_session_cipher, (whisper_message *)bob_outgoing_message, 0, &alice_plaintext);
    ck_assert_int_eq(result, 0);

    uint8_t *alice_plaintext_data = axolotl_buffer_data(alice_plaintext);
    size_t alice_plaintext_len = axolotl_buffer_len(alice_plaintext);

    ck_assert_int_eq(original_message_len, alice_plaintext_len);
    ck_assert_int_eq(memcmp(original_message, alice_plaintext_data, alice_plaintext_len), 0);

    /* Cleanup */
    axolotl_buffer_free(alice_plaintext); alice_plaintext = 0;
    AXOLOTL_UNREF(bob_outgoing_message); bob_outgoing_message = 0;
    AXOLOTL_UNREF(alice_recipient_session_record); alice_recipient_session_record = 0;
    axolotl_buffer_free(plaintext); plaintext = 0;
    AXOLOTL_UNREF(incoming_message); incoming_message = 0;
    AXOLOTL_UNREF(outgoing_message); outgoing_message = 0;
    AXOLOTL_UNREF(bob_pre_key); bob_pre_key = 0;
    session_builder_free(alice_session_builder); alice_session_builder = 0;
    session_cipher_free(alice_session_cipher); alice_session_cipher = 0;

    fprintf(stderr, "Pre-interaction tests complete\n");

    /* Interaction tests */
    run_interaction(alice_store, bob_store);

    /* Cleanup state from previous tests that we need to replace */
    axolotl_store_context_destroy(alice_store); alice_store = 0;
    AXOLOTL_UNREF(bob_pre_key_pair); bob_pre_key_pair = 0;
    AXOLOTL_UNREF(bob_identity_key_pair); bob_identity_key_pair = 0;
    AXOLOTL_UNREF(bob_pre_key_record); bob_pre_key_record = 0;

    /* Create Alice's new session data */
    setup_test_store_context(&alice_store, global_context);
    result = session_builder_create(&alice_session_builder, alice_store, &bob_address, global_context);
    ck_assert_int_eq(result, 0);
    result = session_cipher_create(&alice_session_cipher, alice_store, &bob_address, global_context);
    ck_assert_int_eq(result, 0);

    /* Create Bob's new pre key bundle */
    result = curve_generate_key_pair(global_context, &bob_pre_key_pair);
    ck_assert_int_eq(result, 0);

    result = axolotl_identity_get_key_pair(bob_store, &bob_identity_key_pair);
    ck_assert_int_eq(result, 0);

    result = session_pre_key_bundle_create(&bob_pre_key,
            bob_local_registration_id,
            1, /* device ID */
            31338, /* pre key ID */
            ec_key_pair_get_public(bob_pre_key_pair),
            0, 0, 0, 0,
            ratchet_identity_key_pair_get_public(bob_identity_key_pair));
    ck_assert_int_eq(result, 0);

    /* Save the new pre key and signed pre key in Bob's data store */
    result = session_pre_key_create(&bob_pre_key_record,
            session_pre_key_bundle_get_pre_key_id(bob_pre_key),
            bob_pre_key_pair);
    ck_assert_int_eq(result, 0);

    result = axolotl_pre_key_store_key(bob_store, bob_pre_key_record);
    ck_assert_int_eq(result, 0);

    /* Have Alice process Bob's pre key bundle */
    result = session_builder_process_pre_key_bundle(alice_session_builder, bob_pre_key);
    ck_assert_int_eq(result, 0);

    /* Have Alice encrypt a message for Bob */
    result = session_cipher_encrypt(alice_session_cipher, (uint8_t *)original_message, original_message_len, &outgoing_message);
    ck_assert_int_eq(result, 0);

    ck_assert_int_eq(ciphertext_message_get_type(outgoing_message), CIPHERTEXT_PREKEY_TYPE);

    /* Have Bob try to decrypt the message */
    pre_key_whisper_message *outgoing_message_copy = 0;
    result = pre_key_whisper_message_copy(&outgoing_message_copy, (pre_key_whisper_message *)outgoing_message, global_context);
    ck_assert_int_eq(result, 0);

    /* The decrypt should fail with a specific error */
    result = session_cipher_decrypt_pre_key_whisper_message(bob_session_cipher, outgoing_message_copy, 0, &plaintext);
    ck_assert_int_eq(result, AX_ERR_UNTRUSTED_IDENTITY);
    AXOLOTL_UNREF(outgoing_message_copy); outgoing_message_copy = 0;
    axolotl_buffer_free(plaintext); plaintext = 0;

    result = pre_key_whisper_message_copy(&outgoing_message_copy, (pre_key_whisper_message *)outgoing_message, global_context);
    ck_assert_int_eq(result, 0);

    /* Save the identity key to Bob's store */
    result = axolotl_identity_save_identity(bob_store,
            alice_address.name, alice_address.name_len,
            pre_key_whisper_message_get_identity_key(outgoing_message_copy));
    ck_assert_int_eq(result, 0);
    AXOLOTL_UNREF(outgoing_message_copy); outgoing_message_copy = 0;

    /* Try the decrypt again, this time it should succeed */
    result = pre_key_whisper_message_copy(&outgoing_message_copy, (pre_key_whisper_message *)outgoing_message, global_context);
    ck_assert_int_eq(result, 0);

    result = session_cipher_decrypt_pre_key_whisper_message(bob_session_cipher, outgoing_message_copy, 0, &plaintext);
    ck_assert_int_eq(result, AX_SUCCESS);
    AXOLOTL_UNREF(outgoing_message_copy); outgoing_message_copy = 0;

    plaintext_data = axolotl_buffer_data(plaintext);
    plaintext_len = axolotl_buffer_len(plaintext);

    ck_assert_int_eq(original_message_len, plaintext_len);
    ck_assert_int_eq(memcmp(original_message, plaintext_data, plaintext_len), 0);

    AXOLOTL_UNREF(bob_pre_key); bob_pre_key = 0;

    /* Create a new pre key for Bob */
    ec_public_key *test_public_key = create_test_ec_public_key(global_context);

    ratchet_identity_key_pair *alice_identity_key_pair = 0;
    result = axolotl_identity_get_key_pair(alice_store, &alice_identity_key_pair);
    ck_assert_int_eq(result, 0);

    result = session_pre_key_bundle_create(&bob_pre_key,
            bob_local_registration_id,
            1, /* device ID */
            31337, /* pre key ID */
            test_public_key,
            0, 0, 0, 0,
            ratchet_identity_key_pair_get_public(alice_identity_key_pair));
    ck_assert_int_eq(result, 0);

    /* Have Alice process Bob's new pre key bundle, which should fail */
    result = session_builder_process_pre_key_bundle(alice_session_builder, bob_pre_key);
    ck_assert_int_eq(result, AX_ERR_UNTRUSTED_IDENTITY);

    fprintf(stderr, "Post-interaction tests complete\n");

    /* Final cleanup */
    AXOLOTL_UNREF(alice_identity_key_pair);
    AXOLOTL_UNREF(test_public_key);
    AXOLOTL_UNREF(bob_pre_key);
    axolotl_buffer_free(plaintext);
    AXOLOTL_UNREF(outgoing_message);
    AXOLOTL_UNREF(outgoing_message_copy);
    AXOLOTL_UNREF(bob_pre_key_record);
    AXOLOTL_UNREF(bob_pre_key_pair);
    AXOLOTL_UNREF(bob_identity_key_pair);
    session_cipher_free(bob_session_cipher);
    axolotl_store_context_destroy(bob_store);
    session_builder_free(alice_session_builder);
    session_cipher_free(alice_session_cipher);
    axolotl_store_context_destroy(alice_store);
}
END_TEST

typedef struct {
    const char *original_message;
    size_t original_message_len;
    axolotl_store_context *bob_store;
} test_basic_pre_key_v3_callback_data;

START_TEST(test_basic_pre_key_v3)
{
    int result = 0;

    /* Create Alice's data store and session builder */
    axolotl_store_context *alice_store = 0;
    setup_test_store_context(&alice_store, global_context);
    session_builder *alice_session_builder = 0;
    result = session_builder_create(&alice_session_builder, alice_store, &bob_address, global_context);
    ck_assert_int_eq(result, 0);

    /* Create Bob's data store and pre key bundle */
    axolotl_store_context *bob_store = 0;
    setup_test_store_context(&bob_store, global_context);

    uint32_t bob_local_registration_id = 0;
    result = axolotl_identity_get_local_registration_id(bob_store, &bob_local_registration_id);
    ck_assert_int_eq(result, 0);

    ec_key_pair *bob_pre_key_pair = 0;
    result = curve_generate_key_pair(global_context, &bob_pre_key_pair);
    ck_assert_int_eq(result, 0);

    ec_key_pair *bob_signed_pre_key_pair = 0;
    result = curve_generate_key_pair(global_context, &bob_signed_pre_key_pair);
    ck_assert_int_eq(result, 0);

    ratchet_identity_key_pair *bob_identity_key_pair = 0;
    result = axolotl_identity_get_key_pair(bob_store, &bob_identity_key_pair);
    ck_assert_int_eq(result, 0);

    axolotl_buffer *bob_signed_pre_key_public_serialized = 0;
    result = ec_public_key_serialize(&bob_signed_pre_key_public_serialized,
            ec_key_pair_get_public(bob_signed_pre_key_pair));
    ck_assert_int_eq(result, 0);

    axolotl_buffer *bob_signed_pre_key_signature = 0;
    result = curve_calculate_signature(global_context,
            &bob_signed_pre_key_signature,
            ratchet_identity_key_pair_get_private(bob_identity_key_pair),
            axolotl_buffer_data(bob_signed_pre_key_public_serialized),
            axolotl_buffer_len(bob_signed_pre_key_public_serialized));
    ck_assert_int_eq(result, 0);

    session_pre_key_bundle *bob_pre_key = 0;
    result = session_pre_key_bundle_create(&bob_pre_key,
            bob_local_registration_id,
            1, /* device ID */
            31337, /* pre key ID */
            ec_key_pair_get_public(bob_pre_key_pair),
            22, /* signed pre key ID */
            ec_key_pair_get_public(bob_signed_pre_key_pair),
            axolotl_buffer_data(bob_signed_pre_key_signature),
            axolotl_buffer_len(bob_signed_pre_key_signature),
            ratchet_identity_key_pair_get_public(bob_identity_key_pair));
    ck_assert_int_eq(result, 0);

    axolotl_buffer_free(bob_signed_pre_key_public_serialized);

    /* Have Alice process Bob's pre key bundle */
    result = session_builder_process_pre_key_bundle(alice_session_builder, bob_pre_key);
    ck_assert_int_eq(result, 0);

    /* Check that we can load the session state and verify its version */
    result = axolotl_session_contains_session(alice_store, &bob_address);
    ck_assert_int_eq(result, 1);

    session_record *loaded_record = 0;
    session_state *loaded_record_state = 0;
    result = axolotl_session_load_session(alice_store, &loaded_record, &bob_address);
    ck_assert_int_eq(result, 0);

    loaded_record_state = session_record_get_state(loaded_record);
    ck_assert_ptr_ne(loaded_record_state, 0);

    ck_assert_int_eq(session_state_get_session_version(loaded_record_state), 3);

    AXOLOTL_UNREF(loaded_record);
    loaded_record = 0;
    loaded_record_state = 0;

    /* Encrypt an outgoing message to send to Bob */
    static const char original_message[] = "L'homme est condamné à être libre";
    size_t original_message_len = sizeof(original_message) - 1;
    session_cipher *alice_session_cipher = 0;
    result = session_cipher_create(&alice_session_cipher, alice_store, &bob_address, global_context);
    ck_assert_int_eq(result, 0);

    ciphertext_message *outgoing_message = 0;
    result = session_cipher_encrypt(alice_session_cipher, (uint8_t *)original_message, original_message_len, &outgoing_message);
    ck_assert_int_eq(result, 0);

    ck_assert_int_eq(ciphertext_message_get_type(outgoing_message), CIPHERTEXT_PREKEY_TYPE);

    /* Convert to an incoming message for Bob */
    axolotl_buffer *outgoing_serialized = ciphertext_message_get_serialized(outgoing_message);
    pre_key_whisper_message *incoming_message = 0;
    result = pre_key_whisper_message_deserialize(&incoming_message,
            axolotl_buffer_data(outgoing_serialized),
            axolotl_buffer_len(outgoing_serialized), global_context);
    ck_assert_int_eq(result, 0);

    /* Save the pre key and signed pre key in Bob's data store */
    session_pre_key *bob_pre_key_record = 0;
    result = session_pre_key_create(&bob_pre_key_record,
            session_pre_key_bundle_get_pre_key_id(bob_pre_key),
            bob_pre_key_pair);
    ck_assert_int_eq(result, 0);

    result = axolotl_pre_key_store_key(bob_store, bob_pre_key_record);
    ck_assert_int_eq(result, 0);

    session_signed_pre_key *bob_signed_pre_key_record = 0;
    result = session_signed_pre_key_create(&bob_signed_pre_key_record,
            22, time(0),
            bob_signed_pre_key_pair,
            axolotl_buffer_data(bob_signed_pre_key_signature),
            axolotl_buffer_len(bob_signed_pre_key_signature));
    ck_assert_int_eq(result, 0);

    result = axolotl_signed_pre_key_store_key(bob_store, bob_signed_pre_key_record);
    ck_assert_int_eq(result, 0);

    /* Create Bob's session cipher and decrypt the message from Alice */
    session_cipher *bob_session_cipher = 0;
    result = session_cipher_create(&bob_session_cipher, bob_store, &alice_address, global_context);
    ck_assert_int_eq(result, 0);

    /* Prepare the data for the callback test */
    int callback_context = 1234;
    test_basic_pre_key_v3_callback_data callback_data = {
            .original_message = original_message,
            .original_message_len = original_message_len,
            .bob_store = bob_store
    };
    session_cipher_set_user_data(bob_session_cipher, &callback_data);
    session_cipher_set_decryption_callback(bob_session_cipher, test_basic_pre_key_v3_decrypt_callback);

    axolotl_buffer *plaintext = 0;
    result = session_cipher_decrypt_pre_key_whisper_message(bob_session_cipher, incoming_message, &callback_context, &plaintext);
    ck_assert_int_eq(result, 0);

    /* Clean up callback data */
    session_cipher_set_user_data(bob_session_cipher, 0);
    session_cipher_set_decryption_callback(bob_session_cipher, 0);

    /* Verify Bob's session state and the decrypted message */
    ck_assert_int_eq(axolotl_session_contains_session(bob_store, &alice_address), 1);

    session_record *alice_recipient_session_record = 0;
    axolotl_session_load_session(bob_store, &alice_recipient_session_record, &alice_address);

    session_state *alice_recipient_session_state = session_record_get_state(alice_recipient_session_record);
    ck_assert_int_eq(session_state_get_session_version(alice_recipient_session_state), 3);
    ck_assert_ptr_ne(session_state_get_alice_base_key(alice_recipient_session_state), 0);

    uint8_t *plaintext_data = axolotl_buffer_data(plaintext);
    size_t plaintext_len = axolotl_buffer_len(plaintext);

    ck_assert_int_eq(original_message_len, plaintext_len);
    ck_assert_int_eq(memcmp(original_message, plaintext_data, plaintext_len), 0);

    /* Have Bob send a reply to Alice */
    ciphertext_message *bob_outgoing_message = 0;
    result = session_cipher_encrypt(bob_session_cipher, (uint8_t *)original_message, original_message_len, &bob_outgoing_message);
    ck_assert_int_eq(result, 0);

    ck_assert_int_eq(ciphertext_message_get_type(bob_outgoing_message), CIPHERTEXT_WHISPER_TYPE);

    /* Verify that Alice can decrypt it */
    whisper_message *bob_outgoing_message_copy = 0;
    result = whisper_message_copy(&bob_outgoing_message_copy, (whisper_message *)bob_outgoing_message, global_context);
    ck_assert_int_eq(result, 0);

    axolotl_buffer *alice_plaintext = 0;
    result = session_cipher_decrypt_whisper_message(alice_session_cipher, bob_outgoing_message_copy, 0, &alice_plaintext);
    ck_assert_int_eq(result, 0);

    uint8_t *alice_plaintext_data = axolotl_buffer_data(alice_plaintext);
    size_t alice_plaintext_len = axolotl_buffer_len(alice_plaintext);

    ck_assert_int_eq(original_message_len, alice_plaintext_len);
    ck_assert_int_eq(memcmp(original_message, alice_plaintext_data, alice_plaintext_len), 0);

    axolotl_buffer_free(alice_plaintext); alice_plaintext = 0;
    AXOLOTL_UNREF(bob_outgoing_message); bob_outgoing_message = 0;
    AXOLOTL_UNREF(bob_outgoing_message_copy); bob_outgoing_message_copy = 0;
    AXOLOTL_UNREF(alice_recipient_session_record); alice_recipient_session_record = 0;
    axolotl_buffer_free(plaintext); plaintext = 0;
    AXOLOTL_UNREF(incoming_message); incoming_message = 0;
    AXOLOTL_UNREF(outgoing_message); outgoing_message = 0;
    AXOLOTL_UNREF(bob_pre_key); bob_pre_key = 0;
    session_cipher_free(alice_session_cipher); alice_session_cipher = 0;
    session_builder_free(alice_session_builder); alice_session_builder = 0;

    fprintf(stderr, "Pre-interaction tests complete\n");

    /* Interaction tests */
    run_interaction(alice_store, bob_store);

    /* Cleanup state from previous tests that we need to replace */
    axolotl_store_context_destroy(alice_store); alice_store = 0;
    AXOLOTL_UNREF(bob_pre_key_pair); bob_pre_key_pair = 0;
    AXOLOTL_UNREF(bob_signed_pre_key_pair); bob_signed_pre_key_pair = 0;
    AXOLOTL_UNREF(bob_identity_key_pair); bob_identity_key_pair = 0;
    axolotl_buffer_free(bob_signed_pre_key_signature); bob_signed_pre_key_signature = 0;
    AXOLOTL_UNREF(bob_pre_key_record); bob_pre_key_record = 0;
    AXOLOTL_UNREF(bob_signed_pre_key_record); bob_signed_pre_key_record = 0;

    /* Create Alice's new session data */
    setup_test_store_context(&alice_store, global_context);
    result = session_builder_create(&alice_session_builder, alice_store, &bob_address, global_context);
    ck_assert_int_eq(result, 0);
    result = session_cipher_create(&alice_session_cipher, alice_store, &bob_address, global_context);
    ck_assert_int_eq(result, 0);

    /* Create Bob's new pre key bundle */
    result = curve_generate_key_pair(global_context, &bob_pre_key_pair);
    ck_assert_int_eq(result, 0);

    result = curve_generate_key_pair(global_context, &bob_signed_pre_key_pair);
    ck_assert_int_eq(result, 0);

    result = axolotl_identity_get_key_pair(bob_store, &bob_identity_key_pair);
    ck_assert_int_eq(result, 0);

    result = ec_public_key_serialize(&bob_signed_pre_key_public_serialized,
            ec_key_pair_get_public(bob_signed_pre_key_pair));
    ck_assert_int_eq(result, 0);

    result = curve_calculate_signature(global_context,
            &bob_signed_pre_key_signature,
            ratchet_identity_key_pair_get_private(bob_identity_key_pair),
            axolotl_buffer_data(bob_signed_pre_key_public_serialized),
            axolotl_buffer_len(bob_signed_pre_key_public_serialized));
    ck_assert_int_eq(result, 0);

    result = session_pre_key_bundle_create(&bob_pre_key,
            bob_local_registration_id,
            1, /* device ID */
            31338, /* pre key ID */
            ec_key_pair_get_public(bob_pre_key_pair),
            23, /* signed pre key ID */
            ec_key_pair_get_public(bob_signed_pre_key_pair),
            axolotl_buffer_data(bob_signed_pre_key_signature),
            axolotl_buffer_len(bob_signed_pre_key_signature),
            ratchet_identity_key_pair_get_public(bob_identity_key_pair));
    ck_assert_int_eq(result, 0);

    axolotl_buffer_free(bob_signed_pre_key_public_serialized);

    /* Save the new pre key and signed pre key in Bob's data store */
    result = session_pre_key_create(&bob_pre_key_record,
            session_pre_key_bundle_get_pre_key_id(bob_pre_key),
            bob_pre_key_pair);
    ck_assert_int_eq(result, 0);

    result = axolotl_pre_key_store_key(bob_store, bob_pre_key_record);
    ck_assert_int_eq(result, 0);

    result = session_signed_pre_key_create(&bob_signed_pre_key_record,
            23, time(0),
            bob_signed_pre_key_pair,
            axolotl_buffer_data(bob_signed_pre_key_signature),
            axolotl_buffer_len(bob_signed_pre_key_signature));
    ck_assert_int_eq(result, 0);

    result = axolotl_signed_pre_key_store_key(bob_store, bob_signed_pre_key_record);
    ck_assert_int_eq(result, 0);

    /* Have Alice process Bob's pre key bundle */
    result = session_builder_process_pre_key_bundle(alice_session_builder, bob_pre_key);
    ck_assert_int_eq(result, 0);

    /* Have Alice encrypt a message for Bob */
    result = session_cipher_encrypt(alice_session_cipher, (uint8_t *)original_message, original_message_len, &outgoing_message);
    ck_assert_int_eq(result, 0);

    ck_assert_int_eq(ciphertext_message_get_type(outgoing_message), CIPHERTEXT_PREKEY_TYPE);

    /* Have Bob try to decrypt the message */
    pre_key_whisper_message *outgoing_message_copy = 0;
    result = pre_key_whisper_message_copy(&outgoing_message_copy, (pre_key_whisper_message *)outgoing_message, global_context);
    ck_assert_int_eq(result, 0);

    /* The decrypt should fail with a specific error */
    result = session_cipher_decrypt_pre_key_whisper_message(bob_session_cipher, outgoing_message_copy, 0, &plaintext);
    ck_assert_int_eq(result, AX_ERR_UNTRUSTED_IDENTITY);
    AXOLOTL_UNREF(outgoing_message_copy); outgoing_message_copy = 0;
    axolotl_buffer_free(plaintext); plaintext = 0;

    result = pre_key_whisper_message_copy(&outgoing_message_copy, (pre_key_whisper_message *)outgoing_message, global_context);
    ck_assert_int_eq(result, 0);

    /* Save the identity key to Bob's store */
    result = axolotl_identity_save_identity(bob_store,
            alice_address.name, alice_address.name_len,
            pre_key_whisper_message_get_identity_key(outgoing_message_copy));
    ck_assert_int_eq(result, 0);
    AXOLOTL_UNREF(outgoing_message_copy); outgoing_message_copy = 0;

    /* Try the decrypt again, this time it should succeed */
    result = pre_key_whisper_message_copy(&outgoing_message_copy, (pre_key_whisper_message *)outgoing_message, global_context);
    ck_assert_int_eq(result, 0);

    result = session_cipher_decrypt_pre_key_whisper_message(bob_session_cipher, outgoing_message_copy, 0, &plaintext);
    ck_assert_int_eq(result, AX_SUCCESS);
    AXOLOTL_UNREF(outgoing_message_copy); outgoing_message_copy = 0;

    plaintext_data = axolotl_buffer_data(plaintext);
    plaintext_len = axolotl_buffer_len(plaintext);

    ck_assert_int_eq(original_message_len, plaintext_len);
    ck_assert_int_eq(memcmp(original_message, plaintext_data, plaintext_len), 0);

    AXOLOTL_UNREF(bob_pre_key); bob_pre_key = 0;

    /* Create a new pre key for Bob */
    ec_public_key *test_public_key = create_test_ec_public_key(global_context);

    ratchet_identity_key_pair *alice_identity_key_pair = 0;
    result = axolotl_identity_get_key_pair(alice_store, &alice_identity_key_pair);
    ck_assert_int_eq(result, 0);

    result = session_pre_key_bundle_create(&bob_pre_key,
            bob_local_registration_id,
            1, /* device ID */
            31337, /* pre key ID */
            test_public_key,
            23, /* signed pre key ID */
            ec_key_pair_get_public(bob_signed_pre_key_pair),
            axolotl_buffer_data(bob_signed_pre_key_signature),
            axolotl_buffer_len(bob_signed_pre_key_signature),
            ratchet_identity_key_pair_get_public(alice_identity_key_pair));
    ck_assert_int_eq(result, 0);

    /* Have Alice process Bob's new pre key bundle, which should fail */
    result = session_builder_process_pre_key_bundle(alice_session_builder, bob_pre_key);
    ck_assert_int_eq(result, AX_ERR_UNTRUSTED_IDENTITY);

    fprintf(stderr, "Post-interaction tests complete\n");

    /* Cleanup */
    AXOLOTL_UNREF(alice_identity_key_pair);
    AXOLOTL_UNREF(test_public_key);
    AXOLOTL_UNREF(bob_pre_key);
    axolotl_buffer_free(plaintext);
    AXOLOTL_UNREF(outgoing_message);
    AXOLOTL_UNREF(outgoing_message_copy);
    AXOLOTL_UNREF(bob_signed_pre_key_record);
    AXOLOTL_UNREF(bob_pre_key_record);
    axolotl_buffer_free(bob_signed_pre_key_signature);
    AXOLOTL_UNREF(bob_pre_key_pair);
    AXOLOTL_UNREF(bob_signed_pre_key_pair);
    AXOLOTL_UNREF(bob_identity_key_pair);
    session_cipher_free(bob_session_cipher);
    axolotl_store_context_destroy(bob_store);
    session_builder_free(alice_session_builder);
    session_cipher_free(alice_session_cipher);
    axolotl_store_context_destroy(alice_store);
}
END_TEST

int test_basic_pre_key_v3_decrypt_callback(session_cipher *cipher, axolotl_buffer *plaintext, void *decrypt_context)
{
    test_basic_pre_key_v3_callback_data *callback_data = session_cipher_get_user_data(cipher);
    int callback_context = *(int*)decrypt_context;

    /* Make sure we got the same decrypt context value we passed in */
    ck_assert_int_eq(callback_context, 1234);

    /* Verify that the plaintext matches what we expected */
    uint8_t *plaintext_data = axolotl_buffer_data(plaintext);
    size_t plaintext_len = axolotl_buffer_len(plaintext);

    ck_assert_int_eq(callback_data->original_message_len, plaintext_len);
    ck_assert_int_eq(memcmp(callback_data->original_message, plaintext_data, plaintext_len), 0);

    /* Verify that Bob's session state has not yet been updated */
    ck_assert_int_eq(axolotl_session_contains_session(callback_data->bob_store, &alice_address), 0);

    return 0;
}

START_TEST(test_bad_signed_pre_key_signature)
{
    int result = 0;

    /* Create Alice's data store and session builder */
    axolotl_store_context *alice_store = 0;
    setup_test_store_context(&alice_store, global_context);
    session_builder *alice_session_builder = 0;
    result = session_builder_create(&alice_session_builder, alice_store, &bob_address, global_context);
    ck_assert_int_eq(result, 0);

    /* Create Bob's data store */
    axolotl_store_context *bob_store = 0;
    setup_test_store_context(&bob_store, global_context);

    uint32_t bob_local_registration_id = 0;
    result = axolotl_identity_get_local_registration_id(bob_store, &bob_local_registration_id);
    ck_assert_int_eq(result, 0);

    /* Create Bob's regular and signed pre key pairs */
    ec_key_pair *bob_pre_key_pair = 0;
    result = curve_generate_key_pair(global_context, &bob_pre_key_pair);
    ck_assert_int_eq(result, 0);

    ec_key_pair *bob_signed_pre_key_pair = 0;
    result = curve_generate_key_pair(global_context, &bob_signed_pre_key_pair);
    ck_assert_int_eq(result, 0);

    /* Create Bob's signed pre key signature */
    ratchet_identity_key_pair *bob_identity_key_pair = 0;
    result = axolotl_identity_get_key_pair(bob_store, &bob_identity_key_pair);
    ck_assert_int_eq(result, 0);

    axolotl_buffer *bob_signed_pre_key_public_serialized = 0;
    result = ec_public_key_serialize(&bob_signed_pre_key_public_serialized,
            ec_key_pair_get_public(bob_signed_pre_key_pair));
    ck_assert_int_eq(result, 0);

    axolotl_buffer *bob_signed_pre_key_signature = 0;
    result = curve_calculate_signature(global_context,
            &bob_signed_pre_key_signature,
            ratchet_identity_key_pair_get_private(bob_identity_key_pair),
            axolotl_buffer_data(bob_signed_pre_key_public_serialized),
            axolotl_buffer_len(bob_signed_pre_key_public_serialized));
    ck_assert_int_eq(result, 0);

    size_t signature_len = axolotl_buffer_len(bob_signed_pre_key_signature);

    int i;
    for(i = 0; i < signature_len * 8; i++) {
        axolotl_buffer *modified_signature = axolotl_buffer_copy(bob_signed_pre_key_signature);
        uint8_t *modified_signature_data = axolotl_buffer_data(modified_signature);

        /* Intentionally corrupt the signature data */
        modified_signature_data[i / 8] ^= (0x01 << ((uint8_t)i % 8));

        /* Create a pre key bundle */
        session_pre_key_bundle *bob_pre_key = 0;
        result = session_pre_key_bundle_create(&bob_pre_key,
                bob_local_registration_id,
                1, /* device ID */
                31337, /* pre key ID */
                ec_key_pair_get_public(bob_pre_key_pair),
                22, /* signed pre key ID */
                ec_key_pair_get_public(bob_signed_pre_key_pair),
                modified_signature_data,
                signature_len,
                ratchet_identity_key_pair_get_public(bob_identity_key_pair));
        ck_assert_int_eq(result, 0);

        /* Process the bundle and make sure we fail with an invalid key error */
        result = session_builder_process_pre_key_bundle(alice_session_builder, bob_pre_key);
        ck_assert_int_eq(result, AX_ERR_INVALID_KEY);

        axolotl_buffer_free(modified_signature);
        AXOLOTL_UNREF(bob_pre_key);
    }

    /* Create a correct pre key bundle */
    session_pre_key_bundle *bob_pre_key = 0;
    result = session_pre_key_bundle_create(&bob_pre_key,
            bob_local_registration_id,
            1, /* device ID */
            31337, /* pre key ID */
            ec_key_pair_get_public(bob_pre_key_pair),
            22, /* signed pre key ID */
            ec_key_pair_get_public(bob_signed_pre_key_pair),
            axolotl_buffer_data(bob_signed_pre_key_signature),
            signature_len,
            ratchet_identity_key_pair_get_public(bob_identity_key_pair));
    ck_assert_int_eq(result, 0);

    /* Process the bundle and make sure we do not fail */
    result = session_builder_process_pre_key_bundle(alice_session_builder, bob_pre_key);
    ck_assert_int_eq(result, AX_SUCCESS);

    /* Cleanup */
    AXOLOTL_UNREF(bob_pre_key);
    AXOLOTL_UNREF(bob_pre_key_pair);
    AXOLOTL_UNREF(bob_signed_pre_key_pair);
    AXOLOTL_UNREF(bob_identity_key_pair);
    axolotl_buffer_free(bob_signed_pre_key_signature);
    axolotl_buffer_free(bob_signed_pre_key_public_serialized);
    session_builder_free(alice_session_builder);
    axolotl_store_context_destroy(alice_store);
    axolotl_store_context_destroy(bob_store);
}
END_TEST

START_TEST(test_repeat_bundle_message_v2)
{
    int result = 0;

    /* Create Alice's data store and session builder */
    axolotl_store_context *alice_store = 0;
    setup_test_store_context(&alice_store, global_context);
    session_builder *alice_session_builder = 0;
    result = session_builder_create(&alice_session_builder, alice_store, &bob_address, global_context);
    ck_assert_int_eq(result, 0);

    /* Create Bob's data store and pre key bundle */
    axolotl_store_context *bob_store = 0;
    setup_test_store_context(&bob_store, global_context);

    uint32_t bob_local_registration_id = 0;
    result = axolotl_identity_get_local_registration_id(bob_store, &bob_local_registration_id);
    ck_assert_int_eq(result, 0);

    ec_key_pair *bob_pre_key_pair = 0;
    result = curve_generate_key_pair(global_context, &bob_pre_key_pair);
    ck_assert_int_eq(result, 0);

    ec_key_pair *bob_signed_pre_key_pair = 0;
    result = curve_generate_key_pair(global_context, &bob_signed_pre_key_pair);
    ck_assert_int_eq(result, 0);

    ratchet_identity_key_pair *bob_identity_key_pair = 0;
    result = axolotl_identity_get_key_pair(bob_store, &bob_identity_key_pair);
    ck_assert_int_eq(result, 0);

    axolotl_buffer *bob_signed_pre_key_public_serialized = 0;
    result = ec_public_key_serialize(&bob_signed_pre_key_public_serialized,
            ec_key_pair_get_public(bob_signed_pre_key_pair));
    ck_assert_int_eq(result, 0);

    axolotl_buffer *bob_signed_pre_key_signature = 0;
    result = curve_calculate_signature(global_context,
            &bob_signed_pre_key_signature,
            ratchet_identity_key_pair_get_private(bob_identity_key_pair),
            axolotl_buffer_data(bob_signed_pre_key_public_serialized),
            axolotl_buffer_len(bob_signed_pre_key_public_serialized));
    ck_assert_int_eq(result, 0);

    session_pre_key_bundle *bob_pre_key = 0;
    result = session_pre_key_bundle_create(&bob_pre_key,
            bob_local_registration_id,
            1, /* device ID */
            31337, /* pre key ID */
            ec_key_pair_get_public(bob_pre_key_pair),
            0, 0, 0, 0,
            ratchet_identity_key_pair_get_public(bob_identity_key_pair));
    ck_assert_int_eq(result, 0);

    /* Add Bob's pre keys to Bob's data store */
    session_pre_key *bob_pre_key_record = 0;
    result = session_pre_key_create(&bob_pre_key_record,
            session_pre_key_bundle_get_pre_key_id(bob_pre_key),
            bob_pre_key_pair);
    ck_assert_int_eq(result, 0);

    result = axolotl_pre_key_store_key(bob_store, bob_pre_key_record);
    ck_assert_int_eq(result, 0);

    session_signed_pre_key *bob_signed_pre_key_record = 0;
    result = session_signed_pre_key_create(&bob_signed_pre_key_record,
            22, time(0),
            bob_signed_pre_key_pair,
            axolotl_buffer_data(bob_signed_pre_key_signature),
            axolotl_buffer_len(bob_signed_pre_key_signature));
    ck_assert_int_eq(result, 0);

    result = axolotl_signed_pre_key_store_key(bob_store, bob_signed_pre_key_record);
    ck_assert_int_eq(result, 0);

    /* Have Alice process Bob's pre key bundle */
    result = session_builder_process_pre_key_bundle(alice_session_builder, bob_pre_key);
    ck_assert_int_eq(result, 0);

    /* Initialize Alice's session cipher */
    static const char original_message[] = "L'homme est condamné à être libre";
    size_t original_message_len = sizeof(original_message) - 1;
    session_cipher *alice_session_cipher = 0;
    result = session_cipher_create(&alice_session_cipher, alice_store, &bob_address, global_context);
    ck_assert_int_eq(result, 0);

    /* Create two outgoing messages */
    ciphertext_message *outgoing_message_one = 0;
    result = session_cipher_encrypt(alice_session_cipher, (uint8_t *)original_message, original_message_len, &outgoing_message_one);
    ck_assert_int_eq(result, 0);

    ciphertext_message *outgoing_message_two = 0;
    result = session_cipher_encrypt(alice_session_cipher, (uint8_t *)original_message, original_message_len, &outgoing_message_two);
    ck_assert_int_eq(result, 0);

    ck_assert_int_eq(ciphertext_message_get_type(outgoing_message_one), CIPHERTEXT_PREKEY_TYPE);
    ck_assert_int_eq(ciphertext_message_get_type(outgoing_message_two), CIPHERTEXT_PREKEY_TYPE);

    /* Copy to an incoming message */
    pre_key_whisper_message *incoming_message = 0;
    result = pre_key_whisper_message_copy(&incoming_message, (pre_key_whisper_message *)outgoing_message_one, global_context);
    ck_assert_int_eq(result, 0);

    /* Create Bob's session cipher */
    session_cipher *bob_session_cipher = 0;
    result = session_cipher_create(&bob_session_cipher, bob_store, &alice_address, global_context);
    ck_assert_int_eq(result, 0);

    /* Have Bob decrypt the message, and verify that it matches */
    axolotl_buffer *plaintext = 0;
    result = session_cipher_decrypt_pre_key_whisper_message(bob_session_cipher, incoming_message, 0, &plaintext);
    ck_assert_int_eq(result, 0);

    uint8_t *plaintext_data = axolotl_buffer_data(plaintext);
    size_t plaintext_len = axolotl_buffer_len(plaintext);

    ck_assert_int_eq(original_message_len, plaintext_len);
    ck_assert_int_eq(memcmp(original_message, plaintext_data, plaintext_len), 0);
    axolotl_buffer_free(plaintext); plaintext = 0;

    /* Construct an outgoing message from Bob back to Alice */
    ciphertext_message *bob_outgoing_message = 0;
    result = session_cipher_encrypt(bob_session_cipher, (uint8_t *)original_message, original_message_len, &bob_outgoing_message);
    ck_assert_int_eq(result, 0);

    /* Have Alice decrypt the message, and verify that it matches */
    whisper_message *bob_outgoing_message_copy = 0;
    result = whisper_message_copy(&bob_outgoing_message_copy, (whisper_message *)bob_outgoing_message, global_context);
    ck_assert_int_eq(result, 0);

    result = session_cipher_decrypt_whisper_message(alice_session_cipher, bob_outgoing_message_copy, 0, &plaintext);
    ck_assert_int_eq(result, 0);

    plaintext_data = axolotl_buffer_data(plaintext);
    plaintext_len = axolotl_buffer_len(plaintext);

    ck_assert_int_eq(original_message_len, plaintext_len);
    ck_assert_int_eq(memcmp(original_message, plaintext_data, plaintext_len), 0);
    axolotl_buffer_free(plaintext); plaintext = 0;

    fprintf(stderr, "Test setup complete\n");

    /* The Test */

    pre_key_whisper_message *incoming_message_two = 0;
    result = pre_key_whisper_message_copy(&incoming_message_two, (pre_key_whisper_message *)outgoing_message_two, global_context);

    result = session_cipher_decrypt_pre_key_whisper_message(bob_session_cipher, incoming_message_two, 0, &plaintext);
    ck_assert_int_eq(result, 0);

    plaintext_data = axolotl_buffer_data(plaintext);
    plaintext_len = axolotl_buffer_len(plaintext);

    ck_assert_int_eq(original_message_len, plaintext_len);
    ck_assert_int_eq(memcmp(original_message, plaintext_data, plaintext_len), 0);
    axolotl_buffer_free(plaintext); plaintext = 0;

    ciphertext_message *bob_outgoing_message_two = 0;
    result = session_cipher_encrypt(bob_session_cipher, (uint8_t *)original_message, original_message_len, &bob_outgoing_message_two);
    ck_assert_int_eq(result, 0);

    whisper_message *bob_outgoing_message_two_copy = 0;
    result = whisper_message_copy(&bob_outgoing_message_two_copy, (whisper_message *)bob_outgoing_message_two, global_context);
    ck_assert_int_eq(result, 0);

    result = session_cipher_decrypt_whisper_message(alice_session_cipher, bob_outgoing_message_two_copy, 0, &plaintext);
    ck_assert_int_eq(result, 0);

    plaintext_data = axolotl_buffer_data(plaintext);
    plaintext_len = axolotl_buffer_len(plaintext);

    ck_assert_int_eq(original_message_len, plaintext_len);
    ck_assert_int_eq(memcmp(original_message, plaintext_data, plaintext_len), 0);
    axolotl_buffer_free(plaintext); plaintext = 0;

    fprintf(stderr, "Test process complete\n");

    /* Cleanup */
    AXOLOTL_UNREF(bob_outgoing_message_two_copy);
    AXOLOTL_UNREF(bob_outgoing_message_two);
    AXOLOTL_UNREF(incoming_message_two);
    AXOLOTL_UNREF(bob_outgoing_message_copy);
    AXOLOTL_UNREF(bob_outgoing_message);
    AXOLOTL_UNREF(incoming_message);
    AXOLOTL_UNREF(outgoing_message_one);
    AXOLOTL_UNREF(outgoing_message_two);
    session_cipher_free(alice_session_cipher);
    session_cipher_free(bob_session_cipher);
    axolotl_buffer_free(bob_signed_pre_key_public_serialized);
    axolotl_buffer_free(bob_signed_pre_key_signature);
    AXOLOTL_UNREF(bob_pre_key);
    AXOLOTL_UNREF(bob_signed_pre_key_record);
    AXOLOTL_UNREF(bob_pre_key_record);
    AXOLOTL_UNREF(bob_pre_key_pair);
    AXOLOTL_UNREF(bob_signed_pre_key_pair);
    AXOLOTL_UNREF(bob_identity_key_pair);
    session_builder_free(alice_session_builder);
    axolotl_store_context_destroy(alice_store);
    axolotl_store_context_destroy(bob_store);
}
END_TEST

START_TEST(test_repeat_bundle_message_v3)
{
    int result = 0;

    /* Create Alice's data store and session builder */
    axolotl_store_context *alice_store = 0;
    setup_test_store_context(&alice_store, global_context);
    session_builder *alice_session_builder = 0;
    result = session_builder_create(&alice_session_builder, alice_store, &bob_address, global_context);
    ck_assert_int_eq(result, 0);

    /* Create Bob's data store and pre key bundle */
    axolotl_store_context *bob_store = 0;
    setup_test_store_context(&bob_store, global_context);

    uint32_t bob_local_registration_id = 0;
    result = axolotl_identity_get_local_registration_id(bob_store, &bob_local_registration_id);
    ck_assert_int_eq(result, 0);

    ec_key_pair *bob_pre_key_pair = 0;
    result = curve_generate_key_pair(global_context, &bob_pre_key_pair);
    ck_assert_int_eq(result, 0);

    ec_key_pair *bob_signed_pre_key_pair = 0;
    result = curve_generate_key_pair(global_context, &bob_signed_pre_key_pair);
    ck_assert_int_eq(result, 0);

    ratchet_identity_key_pair *bob_identity_key_pair = 0;
    result = axolotl_identity_get_key_pair(bob_store, &bob_identity_key_pair);
    ck_assert_int_eq(result, 0);

    axolotl_buffer *bob_signed_pre_key_public_serialized = 0;
    result = ec_public_key_serialize(&bob_signed_pre_key_public_serialized,
            ec_key_pair_get_public(bob_signed_pre_key_pair));
    ck_assert_int_eq(result, 0);

    axolotl_buffer *bob_signed_pre_key_signature = 0;
    result = curve_calculate_signature(global_context,
            &bob_signed_pre_key_signature,
            ratchet_identity_key_pair_get_private(bob_identity_key_pair),
            axolotl_buffer_data(bob_signed_pre_key_public_serialized),
            axolotl_buffer_len(bob_signed_pre_key_public_serialized));
    ck_assert_int_eq(result, 0);

    session_pre_key_bundle *bob_pre_key = 0;
    result = session_pre_key_bundle_create(&bob_pre_key,
            bob_local_registration_id,
            1, /* device ID */
            31337, /* pre key ID */
            ec_key_pair_get_public(bob_pre_key_pair),
            22, /* signed pre key ID */
            ec_key_pair_get_public(bob_signed_pre_key_pair),
            axolotl_buffer_data(bob_signed_pre_key_signature),
            axolotl_buffer_len(bob_signed_pre_key_signature),
            ratchet_identity_key_pair_get_public(bob_identity_key_pair));
    ck_assert_int_eq(result, 0);

    /* Add Bob's pre keys to Bob's data store */
    session_pre_key *bob_pre_key_record = 0;
    result = session_pre_key_create(&bob_pre_key_record,
            session_pre_key_bundle_get_pre_key_id(bob_pre_key),
            bob_pre_key_pair);
    ck_assert_int_eq(result, 0);

    result = axolotl_pre_key_store_key(bob_store, bob_pre_key_record);
    ck_assert_int_eq(result, 0);

    session_signed_pre_key *bob_signed_pre_key_record = 0;
    result = session_signed_pre_key_create(&bob_signed_pre_key_record,
            22, time(0),
            bob_signed_pre_key_pair,
            axolotl_buffer_data(bob_signed_pre_key_signature),
            axolotl_buffer_len(bob_signed_pre_key_signature));
    ck_assert_int_eq(result, 0);

    result = axolotl_signed_pre_key_store_key(bob_store, bob_signed_pre_key_record);
    ck_assert_int_eq(result, 0);

    /* Have Alice process Bob's pre key bundle */
    result = session_builder_process_pre_key_bundle(alice_session_builder, bob_pre_key);
    ck_assert_int_eq(result, 0);

    /* Initialize Alice's session cipher */
    static const char original_message[] = "L'homme est condamné à être libre";
    size_t original_message_len = sizeof(original_message) - 1;
    session_cipher *alice_session_cipher = 0;
    result = session_cipher_create(&alice_session_cipher, alice_store, &bob_address, global_context);
    ck_assert_int_eq(result, 0);

    /* Create two outgoing messages */
    ciphertext_message *outgoing_message_one = 0;
    result = session_cipher_encrypt(alice_session_cipher, (uint8_t *)original_message, original_message_len, &outgoing_message_one);
    ck_assert_int_eq(result, 0);

    ciphertext_message *outgoing_message_two = 0;
    result = session_cipher_encrypt(alice_session_cipher, (uint8_t *)original_message, original_message_len, &outgoing_message_two);
    ck_assert_int_eq(result, 0);

    ck_assert_int_eq(ciphertext_message_get_type(outgoing_message_one), CIPHERTEXT_PREKEY_TYPE);
    ck_assert_int_eq(ciphertext_message_get_type(outgoing_message_two), CIPHERTEXT_PREKEY_TYPE);

    /* Copy to an incoming message */
    pre_key_whisper_message *incoming_message = 0;
    result = pre_key_whisper_message_copy(&incoming_message, (pre_key_whisper_message *)outgoing_message_one, global_context);
    ck_assert_int_eq(result, 0);

    /* Create Bob's session cipher */
    session_cipher *bob_session_cipher = 0;
    result = session_cipher_create(&bob_session_cipher, bob_store, &alice_address, global_context);
    ck_assert_int_eq(result, 0);

    /* Have Bob decrypt the message, and verify that it matches */
    axolotl_buffer *plaintext = 0;
    result = session_cipher_decrypt_pre_key_whisper_message(bob_session_cipher, incoming_message, 0, &plaintext);
    ck_assert_int_eq(result, 0);

    uint8_t *plaintext_data = axolotl_buffer_data(plaintext);
    size_t plaintext_len = axolotl_buffer_len(plaintext);

    ck_assert_int_eq(original_message_len, plaintext_len);
    ck_assert_int_eq(memcmp(original_message, plaintext_data, plaintext_len), 0);
    axolotl_buffer_free(plaintext); plaintext = 0;

    /* Construct an outgoing message from Bob back to Alice */
    ciphertext_message *bob_outgoing_message = 0;
    result = session_cipher_encrypt(bob_session_cipher, (uint8_t *)original_message, original_message_len, &bob_outgoing_message);
    ck_assert_int_eq(result, 0);

    /* Have Alice decrypt the message, and verify that it matches */
    whisper_message *bob_outgoing_message_copy = 0;
    result = whisper_message_copy(&bob_outgoing_message_copy, (whisper_message *)bob_outgoing_message, global_context);
    ck_assert_int_eq(result, 0);

    result = session_cipher_decrypt_whisper_message(alice_session_cipher, bob_outgoing_message_copy, 0, &plaintext);
    ck_assert_int_eq(result, 0);

    plaintext_data = axolotl_buffer_data(plaintext);
    plaintext_len = axolotl_buffer_len(plaintext);

    ck_assert_int_eq(original_message_len, plaintext_len);
    ck_assert_int_eq(memcmp(original_message, plaintext_data, plaintext_len), 0);
    axolotl_buffer_free(plaintext); plaintext = 0;

    fprintf(stderr, "Test setup complete\n");

    /* The Test */

    pre_key_whisper_message *incoming_message_two = 0;
    result = pre_key_whisper_message_copy(&incoming_message_two, (pre_key_whisper_message *)outgoing_message_two, global_context);

    result = session_cipher_decrypt_pre_key_whisper_message(bob_session_cipher, incoming_message_two, 0, &plaintext);
    ck_assert_int_eq(result, 0);

    plaintext_data = axolotl_buffer_data(plaintext);
    plaintext_len = axolotl_buffer_len(plaintext);

    ck_assert_int_eq(original_message_len, plaintext_len);
    ck_assert_int_eq(memcmp(original_message, plaintext_data, plaintext_len), 0);
    axolotl_buffer_free(plaintext); plaintext = 0;

    ciphertext_message *bob_outgoing_message_two = 0;
    result = session_cipher_encrypt(bob_session_cipher, (uint8_t *)original_message, original_message_len, &bob_outgoing_message_two);
    ck_assert_int_eq(result, 0);

    whisper_message *bob_outgoing_message_two_copy = 0;
    result = whisper_message_copy(&bob_outgoing_message_two_copy, (whisper_message *)bob_outgoing_message_two, global_context);
    ck_assert_int_eq(result, 0);

    result = session_cipher_decrypt_whisper_message(alice_session_cipher, bob_outgoing_message_two_copy, 0, &plaintext);
    ck_assert_int_eq(result, 0);

    plaintext_data = axolotl_buffer_data(plaintext);
    plaintext_len = axolotl_buffer_len(plaintext);

    ck_assert_int_eq(original_message_len, plaintext_len);
    ck_assert_int_eq(memcmp(original_message, plaintext_data, plaintext_len), 0);
    axolotl_buffer_free(plaintext); plaintext = 0;

    fprintf(stderr, "Test process complete\n");

    /* Cleanup */
    AXOLOTL_UNREF(bob_outgoing_message_two_copy);
    AXOLOTL_UNREF(bob_outgoing_message_two);
    AXOLOTL_UNREF(incoming_message_two);
    AXOLOTL_UNREF(bob_outgoing_message_copy);
    AXOLOTL_UNREF(bob_outgoing_message);
    AXOLOTL_UNREF(incoming_message);
    AXOLOTL_UNREF(outgoing_message_one);
    AXOLOTL_UNREF(outgoing_message_two);
    session_cipher_free(alice_session_cipher);
    session_cipher_free(bob_session_cipher);
    axolotl_buffer_free(bob_signed_pre_key_public_serialized);
    axolotl_buffer_free(bob_signed_pre_key_signature);
    AXOLOTL_UNREF(bob_pre_key);
    AXOLOTL_UNREF(bob_signed_pre_key_record);
    AXOLOTL_UNREF(bob_pre_key_record);
    AXOLOTL_UNREF(bob_pre_key_pair);
    AXOLOTL_UNREF(bob_signed_pre_key_pair);
    AXOLOTL_UNREF(bob_identity_key_pair);
    session_builder_free(alice_session_builder);
    axolotl_store_context_destroy(alice_store);
    axolotl_store_context_destroy(bob_store);
}
END_TEST

START_TEST(test_bad_message_bundle)
{
    int result = 0;

    /* Create Alice's data store and session builder */
    axolotl_store_context *alice_store = 0;
    setup_test_store_context(&alice_store, global_context);
    session_builder *alice_session_builder = 0;
    result = session_builder_create(&alice_session_builder, alice_store, &bob_address, global_context);
    ck_assert_int_eq(result, 0);

    /* Create Bob's data store and pre key bundle */
    axolotl_store_context *bob_store = 0;
    setup_test_store_context(&bob_store, global_context);

    uint32_t bob_local_registration_id = 0;
    result = axolotl_identity_get_local_registration_id(bob_store, &bob_local_registration_id);
    ck_assert_int_eq(result, 0);

    ec_key_pair *bob_pre_key_pair = 0;
    result = curve_generate_key_pair(global_context, &bob_pre_key_pair);
    ck_assert_int_eq(result, 0);

    ec_key_pair *bob_signed_pre_key_pair = 0;
    result = curve_generate_key_pair(global_context, &bob_signed_pre_key_pair);
    ck_assert_int_eq(result, 0);

    ratchet_identity_key_pair *bob_identity_key_pair = 0;
    result = axolotl_identity_get_key_pair(bob_store, &bob_identity_key_pair);
    ck_assert_int_eq(result, 0);

    axolotl_buffer *bob_signed_pre_key_public_serialized = 0;
    result = ec_public_key_serialize(&bob_signed_pre_key_public_serialized,
            ec_key_pair_get_public(bob_signed_pre_key_pair));
    ck_assert_int_eq(result, 0);

    axolotl_buffer *bob_signed_pre_key_signature = 0;
    result = curve_calculate_signature(global_context,
            &bob_signed_pre_key_signature,
            ratchet_identity_key_pair_get_private(bob_identity_key_pair),
            axolotl_buffer_data(bob_signed_pre_key_public_serialized),
            axolotl_buffer_len(bob_signed_pre_key_public_serialized));
    ck_assert_int_eq(result, 0);

    session_pre_key_bundle *bob_pre_key = 0;
    result = session_pre_key_bundle_create(&bob_pre_key,
            bob_local_registration_id,
            1, /* device ID */
            31337, /* pre key ID */
            ec_key_pair_get_public(bob_pre_key_pair),
            22, /* signed pre key ID */
            ec_key_pair_get_public(bob_signed_pre_key_pair),
            axolotl_buffer_data(bob_signed_pre_key_signature),
            axolotl_buffer_len(bob_signed_pre_key_signature),
            ratchet_identity_key_pair_get_public(bob_identity_key_pair));
    ck_assert_int_eq(result, 0);

    /* Add Bob's pre keys to Bob's data store */
    session_pre_key *bob_pre_key_record = 0;
    result = session_pre_key_create(&bob_pre_key_record,
            session_pre_key_bundle_get_pre_key_id(bob_pre_key),
            bob_pre_key_pair);
    ck_assert_int_eq(result, 0);

    result = axolotl_pre_key_store_key(bob_store, bob_pre_key_record);
    ck_assert_int_eq(result, 0);

    session_signed_pre_key *bob_signed_pre_key_record = 0;
    result = session_signed_pre_key_create(&bob_signed_pre_key_record,
            22, time(0),
            bob_signed_pre_key_pair,
            axolotl_buffer_data(bob_signed_pre_key_signature),
            axolotl_buffer_len(bob_signed_pre_key_signature));
    ck_assert_int_eq(result, 0);

    result = axolotl_signed_pre_key_store_key(bob_store, bob_signed_pre_key_record);
    ck_assert_int_eq(result, 0);

    /* Have Alice process Bob's pre key bundle */
    result = session_builder_process_pre_key_bundle(alice_session_builder, bob_pre_key);
    ck_assert_int_eq(result, 0);

    /* Encrypt an outgoing message to send to Bob */
    static const char original_message[] = "L'homme est condamné à être libre";
    size_t original_message_len = sizeof(original_message) - 1;
    session_cipher *alice_session_cipher = 0;
    result = session_cipher_create(&alice_session_cipher, alice_store, &bob_address, global_context);
    ck_assert_int_eq(result, 0);

    ciphertext_message *outgoing_message_one = 0;
    result = session_cipher_encrypt(alice_session_cipher, (uint8_t *)original_message, original_message_len, &outgoing_message_one);
    ck_assert_int_eq(result, 0);

    ck_assert_int_eq(ciphertext_message_get_type(outgoing_message_one), CIPHERTEXT_PREKEY_TYPE);

    axolotl_buffer *good_message = ciphertext_message_get_serialized(outgoing_message_one);
    uint8_t *good_message_data = axolotl_buffer_data(good_message);
    size_t good_message_len = axolotl_buffer_len(good_message);

    axolotl_buffer *bad_message = axolotl_buffer_copy(good_message);
    uint8_t *bad_message_data = axolotl_buffer_data(bad_message);
    size_t bad_message_len = axolotl_buffer_len(bad_message);

    bad_message_data[bad_message_len - 10] ^= 0x01;

    pre_key_whisper_message *incoming_message_bad = 0;
    result = pre_key_whisper_message_deserialize(&incoming_message_bad, bad_message_data, bad_message_len, global_context);
    ck_assert_int_eq(result, 0);

    session_cipher *bob_session_cipher = 0;
    result = session_cipher_create(&bob_session_cipher, bob_store, &alice_address, global_context);
    ck_assert_int_eq(result, 0);

    /* Check that the decrypt fails with an invalid message error */
    axolotl_buffer *plaintext = 0;
    result = session_cipher_decrypt_pre_key_whisper_message(bob_session_cipher, incoming_message_bad, 0, &plaintext);
    ck_assert_int_eq(result, AX_ERR_INVALID_MESSAGE);
    axolotl_buffer_free(plaintext); plaintext = 0;

    /* Make sure the pre key is there */
    result = axolotl_pre_key_contains_key(bob_store, 31337);
    ck_assert_int_eq(result, 1);

    /* Check that the decrypt succeeds with the good message */
    pre_key_whisper_message *incoming_message_good = 0;
    result = pre_key_whisper_message_deserialize(&incoming_message_good, good_message_data, good_message_len, global_context);
    ck_assert_int_eq(result, 0);

    result = session_cipher_decrypt_pre_key_whisper_message(bob_session_cipher, incoming_message_good, 0, &plaintext);
    ck_assert_int_eq(result, AX_SUCCESS);

    uint8_t *plaintext_data = axolotl_buffer_data(plaintext);
    size_t plaintext_len = axolotl_buffer_len(plaintext);

    ck_assert_int_eq(original_message_len, plaintext_len);
    ck_assert_int_eq(memcmp(original_message, plaintext_data, plaintext_len), 0);
    axolotl_buffer_free(plaintext); plaintext = 0;

    /* Make sure the pre key is no longer there */
    result = axolotl_pre_key_contains_key(bob_store, 31337);
    ck_assert_int_eq(result, 0);

    /* Cleanup */
    AXOLOTL_UNREF(incoming_message_good);
    session_cipher_free(bob_session_cipher);
    AXOLOTL_UNREF(incoming_message_bad);
    axolotl_buffer_free(bad_message);
    AXOLOTL_UNREF(outgoing_message_one);
    session_cipher_free(alice_session_cipher);
    AXOLOTL_UNREF(bob_pre_key);
    AXOLOTL_UNREF(bob_pre_key_pair);
    AXOLOTL_UNREF(bob_signed_pre_key_pair);
    AXOLOTL_UNREF(bob_identity_key_pair);
    AXOLOTL_UNREF(bob_signed_pre_key_record);
    AXOLOTL_UNREF(bob_pre_key_record);
    axolotl_buffer_free(bob_signed_pre_key_public_serialized);
    axolotl_buffer_free(bob_signed_pre_key_signature);
    session_builder_free(alice_session_builder);
    axolotl_store_context_destroy(alice_store);
    axolotl_store_context_destroy(bob_store);
}
END_TEST

START_TEST(test_basic_key_exchange)
{
    int result = 0;

    /* Create Alice's data store and session builder */
    axolotl_store_context *alice_store = 0;
    setup_test_store_context(&alice_store, global_context);
    session_builder *alice_session_builder = 0;
    result = session_builder_create(&alice_session_builder, alice_store, &bob_address, global_context);
    ck_assert_int_eq(result, 0);

    /* Create Bob's data store and session builder */
    axolotl_store_context *bob_store = 0;
    setup_test_store_context(&bob_store, global_context);
    session_builder *bob_session_builder = 0;
    result = session_builder_create(&bob_session_builder, bob_store, &alice_address, global_context);
    ck_assert_int_eq(result, 0);

    /* Create Alice's key exchange message */
    key_exchange_message *alice_key_exchange_message = 0;
    result = session_builder_process(alice_session_builder, &alice_key_exchange_message);
    ck_assert_int_eq(result, 0);
    ck_assert_ptr_ne(alice_key_exchange_message, 0);

    axolotl_buffer *alice_key_exchange_message_serialized =
            key_exchange_message_get_serialized(alice_key_exchange_message);

    /* Have Bob process the key exchange message */
    key_exchange_message *alice_key_exchange_message_deserialized = 0;
    result = key_exchange_message_deserialize(&alice_key_exchange_message_deserialized,
            axolotl_buffer_data(alice_key_exchange_message_serialized),
            axolotl_buffer_len(alice_key_exchange_message_serialized), global_context);
    ck_assert_int_eq(result, 0);

    key_exchange_message *bob_key_exchange_message = 0;
    result = session_builder_process_key_exchange_message(bob_session_builder,
            alice_key_exchange_message_deserialized,
            &bob_key_exchange_message);
    ck_assert_int_eq(result, 0);
    ck_assert_ptr_ne(bob_key_exchange_message, 0);

    axolotl_buffer *bob_key_exchange_message_serialized =
            key_exchange_message_get_serialized(bob_key_exchange_message);

    /* Have Alice process Bob's response */
    key_exchange_message *bob_key_exchange_message_deserialized = 0;
    result = key_exchange_message_deserialize(&bob_key_exchange_message_deserialized,
            axolotl_buffer_data(bob_key_exchange_message_serialized),
            axolotl_buffer_len(bob_key_exchange_message_serialized), global_context);
    ck_assert_int_eq(result, 0);

    key_exchange_message *response = 0;
    result = session_builder_process_key_exchange_message(alice_session_builder,
            bob_key_exchange_message_deserialized,
            &response);
    ck_assert_int_eq(result, 0);
    ck_assert_ptr_eq(response, 0);

    /* Check that Alice and Bob have sessions stored for each other */
    ck_assert_int_eq(axolotl_session_contains_session(alice_store, &bob_address), 1);
    ck_assert_int_eq(axolotl_session_contains_session(bob_store, &alice_address), 1);

    run_interaction(alice_store, bob_store);

    /* Clean up Alice's data store and session builder */
    session_builder_free(alice_session_builder);
    axolotl_store_context_destroy(alice_store);
    alice_session_builder = 0;
    alice_store = 0;
    AXOLOTL_UNREF(alice_key_exchange_message);
    AXOLOTL_UNREF(bob_key_exchange_message);

    /* Create a fresh data store and session builder for Alice */
    setup_test_store_context(&alice_store, global_context);
    result = session_builder_create(&alice_session_builder, alice_store, &bob_address, global_context);
    ck_assert_int_eq(result, 0);

    /* Have Alice generate a fresh key exchange message */
    result = session_builder_process(alice_session_builder, &alice_key_exchange_message);
    ck_assert_int_eq(result, 0);

    /* Have Bob process Alice's fresh key exchange message, which should fail */
    result = session_builder_process_key_exchange_message(bob_session_builder,
            alice_key_exchange_message,
            &bob_key_exchange_message);
    ck_assert_int_eq(result, AX_ERR_UNTRUSTED_IDENTITY);
    AXOLOTL_UNREF(bob_key_exchange_message);

    /* Save Alice's new identity key in Bob's store */
    result = axolotl_identity_save_identity(bob_store,
            alice_address.name, alice_address.name_len,
            key_exchange_message_get_identity_key(alice_key_exchange_message));
    ck_assert_int_eq(result, 0);

    /* Have Bob process Alice's key exchange message again */
    result = session_builder_process_key_exchange_message(bob_session_builder,
            alice_key_exchange_message,
            &bob_key_exchange_message);
    ck_assert_int_eq(result, 0);

    /* Have Alice process Bob's key exchange message */
    key_exchange_message *temp_key_exchange_message = 0;
    result = session_builder_process_key_exchange_message(alice_session_builder,
            bob_key_exchange_message,
            &temp_key_exchange_message);
    ck_assert_int_eq(result, 0);
    ck_assert_ptr_eq(temp_key_exchange_message, 0);
    AXOLOTL_UNREF(temp_key_exchange_message);

    run_interaction(alice_store, bob_store);

    /* Cleanup */
    AXOLOTL_UNREF(response);
    AXOLOTL_UNREF(bob_key_exchange_message_deserialized);
    AXOLOTL_UNREF(bob_key_exchange_message);
    AXOLOTL_UNREF(alice_key_exchange_message_deserialized);
    AXOLOTL_UNREF(alice_key_exchange_message);
    session_builder_free(alice_session_builder);
    session_builder_free(bob_session_builder);
    axolotl_store_context_destroy(alice_store);
    axolotl_store_context_destroy(bob_store);
}
END_TEST

START_TEST(test_simultaneous_key_exchange)
{
    int result = 0;

    /* Create Alice's data store and session builder */
    axolotl_store_context *alice_store = 0;
    setup_test_store_context(&alice_store, global_context);
    session_builder *alice_session_builder = 0;
    result = session_builder_create(&alice_session_builder, alice_store, &bob_address, global_context);
    ck_assert_int_eq(result, 0);

    /* Create Bob's data store and session builder */
    axolotl_store_context *bob_store = 0;
    setup_test_store_context(&bob_store, global_context);
    session_builder *bob_session_builder = 0;
    result = session_builder_create(&bob_session_builder, bob_store, &alice_address, global_context);
    ck_assert_int_eq(result, 0);

    /* Create Alice's key exchange message */
    key_exchange_message *alice_key_exchange = 0;
    result = session_builder_process(alice_session_builder, &alice_key_exchange);
    ck_assert_int_eq(result, 0);

    /* Create Bob's key exchange message */
    key_exchange_message *bob_key_exchange = 0;
    result = session_builder_process(bob_session_builder, &bob_key_exchange);
    ck_assert_int_eq(result, 0);

    /* Check that we have key exchange messages for Bob and Alice */
    ck_assert_ptr_ne(alice_key_exchange, 0);
    ck_assert_ptr_ne(bob_key_exchange, 0);

    /* Generate Alice's key exchange response */
    key_exchange_message *alice_response = 0;
    result = session_builder_process_key_exchange_message(alice_session_builder,
            bob_key_exchange, &alice_response);
    ck_assert_int_eq(result, 0);

    /* Generate Bob's key exchange response */
    key_exchange_message *bob_response = 0;
    result = session_builder_process_key_exchange_message(bob_session_builder,
            alice_key_exchange, &bob_response);
    ck_assert_int_eq(result, 0);

    /* Check that we have key exchange responses for Bob and Alice */
    ck_assert_ptr_ne(alice_response, 0);
    ck_assert_ptr_ne(bob_response, 0);

    /* Generate Alice's key exchange ack */
    key_exchange_message *alice_ack = 0;
    result = session_builder_process_key_exchange_message(alice_session_builder,
            bob_response, &alice_ack);
    ck_assert_int_eq(result, 0);

    /* Generate Bob's key exchange ack */
    key_exchange_message *bob_ack = 0;
    result = session_builder_process_key_exchange_message(bob_session_builder,
            alice_response, &bob_ack);
    ck_assert_int_eq(result, 0);

    /* Check that we have null key exchange acks for Bob and Alice */
    ck_assert_ptr_eq(alice_ack, 0);
    ck_assert_ptr_eq(bob_ack, 0);

    run_interaction(alice_store, bob_store);

    /* Cleanup */
    AXOLOTL_UNREF(alice_ack);
    AXOLOTL_UNREF(bob_ack);
    AXOLOTL_UNREF(alice_response);
    AXOLOTL_UNREF(bob_response);
    AXOLOTL_UNREF(alice_key_exchange);
    AXOLOTL_UNREF(bob_key_exchange);
    session_builder_free(alice_session_builder);
    session_builder_free(bob_session_builder);
    axolotl_store_context_destroy(alice_store);
    axolotl_store_context_destroy(bob_store);
}
END_TEST

START_TEST(test_optional_one_time_pre_key)
{
    int result = 0;

    /* Create Alice's data store and session builder */
    axolotl_store_context *alice_store = 0;
    setup_test_store_context(&alice_store, global_context);
    session_builder *alice_session_builder = 0;
    result = session_builder_create(&alice_session_builder, alice_store, &bob_address, global_context);
    ck_assert_int_eq(result, 0);

    /* Create Bob's data store and pre key bundle */
    axolotl_store_context *bob_store = 0;
    setup_test_store_context(&bob_store, global_context);

    uint32_t bob_local_registration_id = 0;
    result = axolotl_identity_get_local_registration_id(bob_store, &bob_local_registration_id);
    ck_assert_int_eq(result, 0);

    ec_key_pair *bob_pre_key_pair = 0;
    result = curve_generate_key_pair(global_context, &bob_pre_key_pair);
    ck_assert_int_eq(result, 0);

    ec_key_pair *bob_signed_pre_key_pair = 0;
    result = curve_generate_key_pair(global_context, &bob_signed_pre_key_pair);
    ck_assert_int_eq(result, 0);

    ratchet_identity_key_pair *bob_identity_key_pair = 0;
    result = axolotl_identity_get_key_pair(bob_store, &bob_identity_key_pair);
    ck_assert_int_eq(result, 0);

    axolotl_buffer *bob_signed_pre_key_public_serialized = 0;
    result = ec_public_key_serialize(&bob_signed_pre_key_public_serialized,
            ec_key_pair_get_public(bob_signed_pre_key_pair));
    ck_assert_int_eq(result, 0);

    axolotl_buffer *bob_signed_pre_key_signature = 0;
    result = curve_calculate_signature(global_context,
            &bob_signed_pre_key_signature,
            ratchet_identity_key_pair_get_private(bob_identity_key_pair),
            axolotl_buffer_data(bob_signed_pre_key_public_serialized),
            axolotl_buffer_len(bob_signed_pre_key_public_serialized));
    ck_assert_int_eq(result, 0);

    session_pre_key_bundle *bob_pre_key = 0;
    result = session_pre_key_bundle_create(&bob_pre_key,
            bob_local_registration_id,
            1, /* device ID */
            0, 0,
            22, /* signed pre key ID */
            ec_key_pair_get_public(bob_signed_pre_key_pair),
            axolotl_buffer_data(bob_signed_pre_key_signature),
            axolotl_buffer_len(bob_signed_pre_key_signature),
            ratchet_identity_key_pair_get_public(bob_identity_key_pair));
    ck_assert_int_eq(result, 0);

    /* Have Alice process Bob's pre key bundle */
    result = session_builder_process_pre_key_bundle(alice_session_builder, bob_pre_key);
    ck_assert_int_eq(result, 0);

    /* Find and verify the session version in Alice's store */
    result = axolotl_session_contains_session(alice_store, &bob_address);
    ck_assert_int_eq(result, 1);

    session_record *record = 0;
    result = axolotl_session_load_session(alice_store, &record, &bob_address);
    ck_assert_int_eq(result, 0);

    session_state *state = 0;
    state = session_record_get_state(record);

    ck_assert_int_eq(session_state_get_session_version(state), 3);
    AXOLOTL_UNREF(record);

    static const char original_message[] = "L'homme est condamné à être libre";
    size_t original_message_len = sizeof(original_message) - 1;

    /* Create Alice's session cipher */
    session_cipher *alice_session_cipher = 0;
    result = session_cipher_create(&alice_session_cipher, alice_store, &bob_address, global_context);
    ck_assert_int_eq(result, 0);

    /* Create an outgoing message */
    ciphertext_message *outgoing_message = 0;
    result = session_cipher_encrypt(alice_session_cipher, (uint8_t *)original_message, original_message_len, &outgoing_message);
    ck_assert_int_eq(result, 0);

    ck_assert_int_eq(ciphertext_message_get_type(outgoing_message), CIPHERTEXT_PREKEY_TYPE);

    /* Convert to an incoming message */
    pre_key_whisper_message *incoming_message = 0;
    result = pre_key_whisper_message_copy(&incoming_message, (pre_key_whisper_message *)outgoing_message, global_context);
    ck_assert_int_eq(result, 0);

    /* Make sure the pre key ID is not present */
    ck_assert_int_eq(pre_key_whisper_message_has_pre_key_id(incoming_message), 0);

    /* Add Bob's pre keys to Bob's data store */
    session_pre_key *bob_pre_key_record = 0;
    result = session_pre_key_create(&bob_pre_key_record,
            session_pre_key_bundle_get_pre_key_id(bob_pre_key),
            bob_pre_key_pair);
    ck_assert_int_eq(result, 0);

    result = axolotl_pre_key_store_key(bob_store, bob_pre_key_record);
    ck_assert_int_eq(result, 0);

    session_signed_pre_key *bob_signed_pre_key_record = 0;
    result = session_signed_pre_key_create(&bob_signed_pre_key_record,
            22, time(0),
            bob_signed_pre_key_pair,
            axolotl_buffer_data(bob_signed_pre_key_signature),
            axolotl_buffer_len(bob_signed_pre_key_signature));
    ck_assert_int_eq(result, 0);

    result = axolotl_signed_pre_key_store_key(bob_store, bob_signed_pre_key_record);
    ck_assert_int_eq(result, 0);

    /* Create Bob's session cipher */
    session_cipher *bob_session_cipher = 0;
    result = session_cipher_create(&bob_session_cipher, bob_store, &alice_address, global_context);
    ck_assert_int_eq(result, 0);

    axolotl_buffer *plaintext = 0;
    result = session_cipher_decrypt_pre_key_whisper_message(bob_session_cipher, incoming_message, 0, &plaintext);
    ck_assert_int_eq(result, 0);

    ck_assert_int_eq(axolotl_session_contains_session(bob_store, &alice_address), 1);

    result = axolotl_session_load_session(bob_store, &record, &alice_address);
    ck_assert_int_eq(result, 0);

    state = session_record_get_state(record);

    ck_assert_int_eq(session_state_get_session_version(state), 3);
    ck_assert_ptr_ne(session_state_get_alice_base_key(state), 0);

    uint8_t *plaintext_data = axolotl_buffer_data(plaintext);
    size_t plaintext_len = axolotl_buffer_len(plaintext);

    ck_assert_int_eq(original_message_len, plaintext_len);
    ck_assert_int_eq(memcmp(original_message, plaintext_data, plaintext_len), 0);
    axolotl_buffer_free(plaintext);
    plaintext = 0;
    AXOLOTL_UNREF(record);

    /* Cleanup */
    axolotl_buffer_free(plaintext);
    session_cipher_free(bob_session_cipher);
    AXOLOTL_UNREF(bob_signed_pre_key_record);
    AXOLOTL_UNREF(bob_pre_key_record);
    AXOLOTL_UNREF(incoming_message);
    AXOLOTL_UNREF(outgoing_message);
    session_cipher_free(alice_session_cipher);
    AXOLOTL_UNREF(bob_pre_key);
    AXOLOTL_UNREF(bob_pre_key_pair);
    AXOLOTL_UNREF(bob_signed_pre_key_pair);
    AXOLOTL_UNREF(bob_identity_key_pair);
    axolotl_buffer_free(bob_signed_pre_key_public_serialized);
    axolotl_buffer_free(bob_signed_pre_key_signature);
    session_builder_free(alice_session_builder);
    axolotl_store_context_destroy(alice_store);
    axolotl_store_context_destroy(bob_store);
}
END_TEST

axolotl_buffer *create_looping_message(int index)
{
    static const char looping_message[] = "You can only desire based on what you know:  ";

    axolotl_buffer *buffer = axolotl_buffer_create((uint8_t *)looping_message, sizeof(looping_message) - 1);
    uint8_t *data = axolotl_buffer_data(buffer);
    size_t len = axolotl_buffer_len(buffer);

    data[len - 1] = (uint8_t)index;
    return buffer;
}

axolotl_buffer *create_looping_message_short(int index)
{
    static const char looping_message[] =
            "What do we mean by saying that existence precedes essence? "
            "We mean that man first of all exists, encounters himself, "
            "surges up in the world--and defines himself aftward.  ";

    axolotl_buffer *buffer = axolotl_buffer_create((uint8_t *)looping_message, sizeof(looping_message) - 1);
    uint8_t *data = axolotl_buffer_data(buffer);
    size_t len = axolotl_buffer_len(buffer);

    data[len - 1] = (uint8_t)index;
    return buffer;
}

void run_interaction(axolotl_store_context *alice_store, axolotl_store_context *bob_store)
{
    int result = 0;

    /* Create the session ciphers */
    session_cipher *alice_session_cipher = 0;
    result = session_cipher_create(&alice_session_cipher, alice_store, &bob_address, global_context);
    ck_assert_int_eq(result, 0);

    session_cipher *bob_session_cipher = 0;
    result = session_cipher_create(&bob_session_cipher, bob_store, &alice_address, global_context);
    ck_assert_int_eq(result, 0);

    /* Create a test message */
    static const char original_message[] = "smert ze smert";
    size_t original_message_len = sizeof(original_message) - 1;

    /* Simulate Alice sending a message to Bob */
    ciphertext_message *alice_message = 0;
    result = session_cipher_encrypt(alice_session_cipher, (uint8_t *)original_message, original_message_len, &alice_message);
    ck_assert_int_eq(result, 0);

    ck_assert_int_eq(ciphertext_message_get_type(alice_message), CIPHERTEXT_WHISPER_TYPE);

    whisper_message *alice_message_copy = 0;
    result = whisper_message_copy(&alice_message_copy, (whisper_message *)alice_message, global_context);
    ck_assert_int_eq(result, 0);

    axolotl_buffer *plaintext = 0;
    result = session_cipher_decrypt_whisper_message(bob_session_cipher, alice_message_copy, 0, &plaintext);
    ck_assert_int_eq(result, 0);

    uint8_t *plaintext_data = axolotl_buffer_data(plaintext);
    size_t plaintext_len = axolotl_buffer_len(plaintext);

    ck_assert_int_eq(original_message_len, plaintext_len);
    ck_assert_int_eq(memcmp(original_message, plaintext_data, plaintext_len), 0);
    axolotl_buffer_free(plaintext);
    plaintext = 0;

    fprintf(stderr, "Interaction complete: Alice -> Bob\n");

    /* Simulate Bob sending a message to Alice */
    ciphertext_message *bob_message = 0;
    result = session_cipher_encrypt(bob_session_cipher, (uint8_t *)original_message, original_message_len, &bob_message);
    ck_assert_int_eq(result, 0);

    ck_assert_int_eq(ciphertext_message_get_type(bob_message), CIPHERTEXT_WHISPER_TYPE);

    whisper_message *bob_message_copy = 0;
    result = whisper_message_copy(&bob_message_copy, (whisper_message *)bob_message, global_context);
    ck_assert_int_eq(result, 0);

    result = session_cipher_decrypt_whisper_message(alice_session_cipher, bob_message_copy, 0, &plaintext);
    ck_assert_int_eq(result, 0);

    plaintext_data = axolotl_buffer_data(plaintext);
    plaintext_len = axolotl_buffer_len(plaintext);

    ck_assert_int_eq(original_message_len, plaintext_len);
    ck_assert_int_eq(memcmp(original_message, plaintext_data, plaintext_len), 0);
    axolotl_buffer_free(plaintext);
    plaintext = 0;

    fprintf(stderr, "Interaction complete: Bob -> Alice\n");

    /* Cleanup */
    AXOLOTL_UNREF(bob_message_copy);
    AXOLOTL_UNREF(bob_message);
    AXOLOTL_UNREF(alice_message_copy);
    AXOLOTL_UNREF(alice_message);

    int i;
    /* Looping Alice -> Bob */
    for(i = 0; i < 10; i++) {
        axolotl_buffer *looping_message = create_looping_message(i);

        ciphertext_message *alice_looping_message = 0;
        result = session_cipher_encrypt(alice_session_cipher,
                axolotl_buffer_data(looping_message),
                axolotl_buffer_len(looping_message),
                &alice_looping_message);
        ck_assert_int_eq(result, 0);

        whisper_message *alice_looping_message_message_copy = 0;
        result = whisper_message_copy(&alice_looping_message_message_copy, (whisper_message *)alice_looping_message, global_context);
        ck_assert_int_eq(result, 0);

        axolotl_buffer *looping_plaintext = 0;
        result = session_cipher_decrypt_whisper_message(bob_session_cipher, alice_looping_message_message_copy, 0, &looping_plaintext);
        ck_assert_int_eq(result, 0);

        ck_assert_int_eq(axolotl_buffer_compare(looping_message, looping_plaintext), 0);

        axolotl_buffer_free(looping_plaintext);
        axolotl_buffer_free(looping_message);
        AXOLOTL_UNREF(alice_looping_message);
        AXOLOTL_UNREF(alice_looping_message_message_copy);
    }
    fprintf(stderr, "Interaction complete: Alice -> Bob (looping)\n");

    /* Looping Bob -> Alice */
    for(i = 0; i < 10; i++) {
        axolotl_buffer *looping_message = create_looping_message(i);

        ciphertext_message *bob_looping_message = 0;
        result = session_cipher_encrypt(bob_session_cipher,
                axolotl_buffer_data(looping_message),
                axolotl_buffer_len(looping_message),
                &bob_looping_message);
        ck_assert_int_eq(result, 0);

        whisper_message *bob_looping_message_message_copy = 0;
        result = whisper_message_copy(&bob_looping_message_message_copy, (whisper_message *)bob_looping_message, global_context);
        ck_assert_int_eq(result, 0);

        axolotl_buffer *looping_plaintext = 0;
        result = session_cipher_decrypt_whisper_message(alice_session_cipher, bob_looping_message_message_copy, 0, &looping_plaintext);
        ck_assert_int_eq(result, 0);

        ck_assert_int_eq(axolotl_buffer_compare(looping_message, looping_plaintext), 0);

        axolotl_buffer_free(looping_plaintext);
        axolotl_buffer_free(looping_message);
        AXOLOTL_UNREF(bob_looping_message);
        AXOLOTL_UNREF(bob_looping_message_message_copy);
    }
    fprintf(stderr, "Interaction complete: Bob -> Alice (looping)\n");

    /* Generate a shuffled list of encrypted messages for later use */
    axolotl_buffer *alice_ooo_plaintext[10];
    axolotl_buffer *alice_ooo_ciphertext[10];
    for(i = 0; i < 10; i++) {
        axolotl_buffer *looping_message = create_looping_message(i);

        ciphertext_message *alice_looping_message = 0;
        result = session_cipher_encrypt(alice_session_cipher,
                axolotl_buffer_data(looping_message),
                axolotl_buffer_len(looping_message),
                &alice_looping_message);
        ck_assert_int_eq(result, 0);

        axolotl_buffer *alice_looping_message_serialized = ciphertext_message_get_serialized(alice_looping_message);

        alice_ooo_plaintext[i] = looping_message;
        alice_ooo_ciphertext[i] = axolotl_buffer_copy(alice_looping_message_serialized);
        AXOLOTL_UNREF(alice_looping_message);
    }

    time_t seed = time(0);
    srand(seed);
    shuffle_buffers(alice_ooo_plaintext, 10);
    srand(seed);
    shuffle_buffers(alice_ooo_ciphertext, 10);
    fprintf(stderr, "Shuffled Alice->Bob messages created\n");

    /* Looping Alice -> Bob (repeated) */
    for(i = 0; i < 10; i++) {
        axolotl_buffer *looping_message = create_looping_message(i);

        ciphertext_message *alice_looping_message = 0;
        result = session_cipher_encrypt(alice_session_cipher,
                axolotl_buffer_data(looping_message),
                axolotl_buffer_len(looping_message),
                &alice_looping_message);
        ck_assert_int_eq(result, 0);

        whisper_message *alice_looping_message_message_copy = 0;
        result = whisper_message_copy(&alice_looping_message_message_copy, (whisper_message *)alice_looping_message, global_context);
        ck_assert_int_eq(result, 0);

        axolotl_buffer *looping_plaintext = 0;
        result = session_cipher_decrypt_whisper_message(bob_session_cipher, alice_looping_message_message_copy, 0, &looping_plaintext);
        ck_assert_int_eq(result, 0);

        ck_assert_int_eq(axolotl_buffer_compare(looping_message, looping_plaintext), 0);

        axolotl_buffer_free(looping_plaintext);
        axolotl_buffer_free(looping_message);
        AXOLOTL_UNREF(alice_looping_message);
        AXOLOTL_UNREF(alice_looping_message_message_copy);
    }
    fprintf(stderr, "Interaction complete: Alice -> Bob (looping, repeated)\n");

    /* Looping Bob -> Alice (repeated) */
    for(i = 0; i < 10; i++) {
        axolotl_buffer *looping_message = create_looping_message_short(i);

        ciphertext_message *bob_looping_message = 0;
        result = session_cipher_encrypt(bob_session_cipher,
                axolotl_buffer_data(looping_message),
                axolotl_buffer_len(looping_message),
                &bob_looping_message);
        ck_assert_int_eq(result, 0);

        whisper_message *bob_looping_message_message_copy = 0;
        result = whisper_message_copy(&bob_looping_message_message_copy, (whisper_message *)bob_looping_message, global_context);
        ck_assert_int_eq(result, 0);

        axolotl_buffer *looping_plaintext = 0;
        result = session_cipher_decrypt_whisper_message(alice_session_cipher, bob_looping_message_message_copy, 0, &looping_plaintext);
        ck_assert_int_eq(result, 0);

        ck_assert_int_eq(axolotl_buffer_compare(looping_message, looping_plaintext), 0);

        axolotl_buffer_free(looping_plaintext);
        axolotl_buffer_free(looping_message);
        AXOLOTL_UNREF(bob_looping_message);
        AXOLOTL_UNREF(bob_looping_message_message_copy);
    }
    fprintf(stderr, "Interaction complete: Bob -> Alice (looping, repeated)\n");

    /* Shuffled Alice -> Bob */
    for(i = 0; i < 10; i++) {
        whisper_message *ooo_message_deserialized = 0;
        result = whisper_message_deserialize(&ooo_message_deserialized,
                axolotl_buffer_data(alice_ooo_ciphertext[i]),
                axolotl_buffer_len(alice_ooo_ciphertext[i]),
                global_context);
        ck_assert_int_eq(result, 0);

        axolotl_buffer *ooo_plaintext = 0;
        result = session_cipher_decrypt_whisper_message(bob_session_cipher, ooo_message_deserialized, 0, &ooo_plaintext);
        ck_assert_int_eq(result, 0);

        ck_assert_int_eq(axolotl_buffer_compare(alice_ooo_plaintext[i], ooo_plaintext), 0);

        axolotl_buffer_free(ooo_plaintext);
        AXOLOTL_UNREF(ooo_message_deserialized);
    }
    fprintf(stderr, "Interaction complete: Alice -> Bob (shuffled)\n");

    /* Cleanup */
    for(i = 0; i < 10; i++) {
        axolotl_buffer_free(alice_ooo_plaintext[i]);
        axolotl_buffer_free(alice_ooo_ciphertext[i]);
    }
    session_cipher_free(alice_session_cipher);
    session_cipher_free(bob_session_cipher);
}

Suite *session_builder_suite(void)
{
    Suite *suite = suite_create("session_builder");

    TCase *tcase = tcase_create("case");
    tcase_add_checked_fixture(tcase, test_setup, test_teardown);
    tcase_add_test(tcase, test_basic_pre_key_v2);
    tcase_add_test(tcase, test_basic_pre_key_v3);
    tcase_add_test(tcase, test_bad_signed_pre_key_signature);
    tcase_add_test(tcase, test_repeat_bundle_message_v2);
    tcase_add_test(tcase, test_repeat_bundle_message_v3);
    tcase_add_test(tcase, test_bad_message_bundle);
    tcase_add_test(tcase, test_basic_key_exchange);
    tcase_add_test(tcase, test_simultaneous_key_exchange);
    tcase_add_test(tcase, test_optional_one_time_pre_key);
    suite_add_tcase(suite, tcase);

    return suite;
}

int main(void)
{
    int number_failed;
    Suite *suite;
    SRunner *runner;

    suite = session_builder_suite();
    runner = srunner_create(suite);

    srunner_run_all(runner, CK_VERBOSE);
    number_failed = srunner_ntests_failed(runner);
    srunner_free(runner);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
