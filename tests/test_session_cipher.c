#include <stdio.h>
#include <stdlib.h>
#include <check.h>
#include <pthread.h>

#include "axolotl.h"
#include "session_record.h"
#include "session_state.h"
#include "session_cipher.h"
#include "curve.h"
#include "ratchet.h"
#include "protocol.h"
#include "test_common.h"

axolotl_context *global_context;
pthread_mutex_t global_mutex;
pthread_mutexattr_t global_mutex_attr;

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

void initialize_sessions_v2(session_state *alice_state, session_state *bob_state);
void initialize_sessions_v3(session_state *alice_state, session_state *bob_state);
void run_interaction(session_record *alice_session_record, session_record *bob_session_record);

START_TEST(test_basic_session_v2)
{
    int result = 0;

    /* Create Alice's session record */
    session_record *alice_session_record = 0;
    result = session_record_create(&alice_session_record, 0, global_context);
    ck_assert_int_eq(result, 0);

    /* Create Bob's session record */
    session_record *bob_session_record = 0;
    result = session_record_create(&bob_session_record, 0, global_context);
    ck_assert_int_eq(result, 0);

    initialize_sessions_v2(
            session_record_get_state(alice_session_record),
            session_record_get_state(bob_session_record));

    run_interaction(alice_session_record, bob_session_record);

    /* Cleanup */
    AXOLOTL_UNREF(alice_session_record);
    AXOLOTL_UNREF(bob_session_record);
}
END_TEST

START_TEST(test_basic_session_v3)
{
    int result = 0;

    /* Create Alice's session record */
    session_record *alice_session_record = 0;
    result = session_record_create(&alice_session_record, 0, global_context);
    ck_assert_int_eq(result, 0);

    /* Create Bob's session record */
    session_record *bob_session_record = 0;
    result = session_record_create(&bob_session_record, 0, global_context);
    ck_assert_int_eq(result, 0);

    initialize_sessions_v3(
            session_record_get_state(alice_session_record),
            session_record_get_state(bob_session_record));

    run_interaction(alice_session_record, bob_session_record);

    /* Cleanup */
    AXOLOTL_UNREF(alice_session_record);
    AXOLOTL_UNREF(bob_session_record);
}
END_TEST

void initialize_sessions_v2(session_state *alice_state, session_state *bob_state)
{
    int result = 0;

    /* Generate Alice's identity key */
    ec_key_pair *alice_identity_key_pair = 0;
    result = curve_generate_key_pair(global_context, &alice_identity_key_pair);
    ck_assert_int_eq(result, 0);

    ratchet_identity_key_pair *alice_identity_key = 0;
    result = ratchet_identity_key_pair_create(&alice_identity_key,
            ec_key_pair_get_public(alice_identity_key_pair),
            ec_key_pair_get_private(alice_identity_key_pair));
    ck_assert_int_eq(result, 0);
    AXOLOTL_UNREF(alice_identity_key_pair);

    /* Generate Alice's base key */
    ec_key_pair *alice_base_key = 0;
    result = curve_generate_key_pair(global_context, &alice_base_key);
    ck_assert_int_eq(result, 0);

    /* Generate Alice's ephemeral key */
    ec_key_pair *alice_ephemeral_key = 0;
    result = curve_generate_key_pair(global_context, &alice_ephemeral_key);
    ck_assert_int_eq(result, 0);

    /* Generate Bob's identity key */
    ec_key_pair *bob_identity_key_pair = 0;
    result = curve_generate_key_pair(global_context, &bob_identity_key_pair);
    ck_assert_int_eq(result, 0);

    ratchet_identity_key_pair *bob_identity_key = 0;
    result = ratchet_identity_key_pair_create(&bob_identity_key,
            ec_key_pair_get_public(bob_identity_key_pair),
            ec_key_pair_get_private(bob_identity_key_pair));
    ck_assert_int_eq(result, 0);
    AXOLOTL_UNREF(bob_identity_key_pair);

    /* Generate Bob's base key */
    ec_key_pair *bob_base_key = 0;
    result = curve_generate_key_pair(global_context, &bob_base_key);
    ck_assert_int_eq(result, 0);

    /* Generate Bob's ephemeral key */
    ec_key_pair *bob_ephemeral_key = bob_base_key;
    AXOLOTL_REF(bob_base_key);

    /* Create Alice's parameters */
    alice_axolotl_parameters *alice_parameters = 0;
    result = alice_axolotl_parameters_create(&alice_parameters,
            /* our_identity_key       */ alice_identity_key,
            /* our_base_key           */ alice_base_key,
            /* their_identity_key     */ ratchet_identity_key_pair_get_public(bob_identity_key),
            /* their_signed_pre_key   */ ec_key_pair_get_public(bob_ephemeral_key),
            /* their_one_time_pre_key */ 0,
            /* their_ratchet_key      */ ec_key_pair_get_public(bob_ephemeral_key));
    ck_assert_int_eq(result, 0);

    /* Create Bob's parameters */
    bob_axolotl_parameters *bob_parameters = 0;
    result = bob_axolotl_parameters_create(&bob_parameters,
            /* our_identity_key     */ bob_identity_key,
            /* our_signed_pre_key   */ bob_base_key,
            /* our_one_time_pre_key */ 0,
            /* our_ratchet_key      */ bob_ephemeral_key,
            /* their_identity_key   */ ratchet_identity_key_pair_get_public(alice_identity_key),
            /* their_base_key       */ ec_key_pair_get_public(alice_base_key));
    ck_assert_int_eq(result, 0);

    /* Initialize the ratcheting sessions */
    result = ratcheting_session_alice_initialize(alice_state, 2, alice_parameters, global_context);
    ck_assert_int_eq(result, 0);
    result = ratcheting_session_bob_initialize(bob_state, 2, bob_parameters, global_context);
    ck_assert_int_eq(result, 0);

    /* Unref cleanup */
    AXOLOTL_UNREF(alice_identity_key);
    AXOLOTL_UNREF(alice_base_key);
    AXOLOTL_UNREF(alice_ephemeral_key);
    AXOLOTL_UNREF(bob_identity_key);
    AXOLOTL_UNREF(bob_base_key);
    AXOLOTL_UNREF(bob_ephemeral_key);
    AXOLOTL_UNREF(alice_parameters);
    AXOLOTL_UNREF(bob_parameters);
}

void initialize_sessions_v3(session_state *alice_state, session_state *bob_state)
{
    int result = 0;

    /* Generate Alice's identity key */
    ec_key_pair *alice_identity_key_pair = 0;
    result = curve_generate_key_pair(global_context, &alice_identity_key_pair);
    ck_assert_int_eq(result, 0);

    ratchet_identity_key_pair *alice_identity_key = 0;
    result = ratchet_identity_key_pair_create(&alice_identity_key,
            ec_key_pair_get_public(alice_identity_key_pair),
            ec_key_pair_get_private(alice_identity_key_pair));
    ck_assert_int_eq(result, 0);
    AXOLOTL_UNREF(alice_identity_key_pair);

    /* Generate Alice's base key */
    ec_key_pair *alice_base_key = 0;
    result = curve_generate_key_pair(global_context, &alice_base_key);
    ck_assert_int_eq(result, 0);

    /* Generate Alice's ephemeral key */
    ec_key_pair *alice_ephemeral_key = 0;
    result = curve_generate_key_pair(global_context, &alice_ephemeral_key);
    ck_assert_int_eq(result, 0);

    /* Generate Alice's pre-key */
    ec_key_pair *alice_pre_key = alice_base_key;
    AXOLOTL_REF(alice_base_key);

    /* Generate Bob's identity key */
    ec_key_pair *bob_identity_key_pair = 0;
    result = curve_generate_key_pair(global_context, &bob_identity_key_pair);
    ck_assert_int_eq(result, 0);

    ratchet_identity_key_pair *bob_identity_key = 0;
    result = ratchet_identity_key_pair_create(&bob_identity_key,
            ec_key_pair_get_public(bob_identity_key_pair),
            ec_key_pair_get_private(bob_identity_key_pair));
    ck_assert_int_eq(result, 0);
    AXOLOTL_UNREF(bob_identity_key_pair);

    /* Generate Bob's base key */
    ec_key_pair *bob_base_key = 0;
    result = curve_generate_key_pair(global_context, &bob_base_key);
    ck_assert_int_eq(result, 0);

    /* Generate Bob's ephemeral key */
    ec_key_pair *bob_ephemeral_key = bob_base_key;
    AXOLOTL_REF(bob_base_key);

    /* Generate Bob's pre-key */
    ec_key_pair *bob_pre_key;
    result = curve_generate_key_pair(global_context, &bob_pre_key);
    ck_assert_int_eq(result, 0);

    /* Create Alice's parameters */
    alice_axolotl_parameters *alice_parameters = 0;
    result = alice_axolotl_parameters_create(&alice_parameters,
            /* our_identity_key       */ alice_identity_key,
            /* our_base_key           */ alice_base_key,
            /* their_identity_key     */ ratchet_identity_key_pair_get_public(bob_identity_key),
            /* their_signed_pre_key   */ ec_key_pair_get_public(bob_base_key),
            /* their_one_time_pre_key */ 0,
            /* their_ratchet_key      */ ec_key_pair_get_public(bob_ephemeral_key));
    ck_assert_int_eq(result, 0);

    /* Create Bob's parameters */
    bob_axolotl_parameters *bob_parameters = 0;
    result = bob_axolotl_parameters_create(&bob_parameters,
            /* our_identity_key     */ bob_identity_key,
            /* our_signed_pre_key   */ bob_base_key,
            /* our_one_time_pre_key */ 0,
            /* our_ratchet_key      */ bob_ephemeral_key,
            /* their_identity_key   */ ratchet_identity_key_pair_get_public(alice_identity_key),
            /* their_base_key       */ ec_key_pair_get_public(alice_base_key));
    ck_assert_int_eq(result, 0);

    /* Initialize the ratcheting sessions */
    result = ratcheting_session_alice_initialize(alice_state, 3, alice_parameters, global_context);
    ck_assert_int_eq(result, 0);
    result = ratcheting_session_bob_initialize(bob_state, 3, bob_parameters, global_context);
    ck_assert_int_eq(result, 0);

    /* Unref cleanup */
    AXOLOTL_UNREF(alice_identity_key);
    AXOLOTL_UNREF(alice_base_key);
    AXOLOTL_UNREF(alice_ephemeral_key);
    AXOLOTL_UNREF(alice_pre_key);
    AXOLOTL_UNREF(bob_identity_key);
    AXOLOTL_UNREF(bob_base_key);
    AXOLOTL_UNREF(bob_ephemeral_key);
    AXOLOTL_UNREF(bob_pre_key);
    AXOLOTL_UNREF(alice_parameters);
    AXOLOTL_UNREF(bob_parameters);
}

void generate_test_message_collections(session_cipher *cipher, axolotl_buffer **plaintext_messages, axolotl_buffer **ciphertext_messages, int size)
{
    /*
     * This test message is kept here as a byte array constant, rather than
     * a string literal, since it contains characters not valid in ASCII.
     * A null placeholder is located at the end, which is replaced with an
     * index value when generated derived test messages.
     */
    uint8_t testMessage[] = {
            0xD1, 0x81, 0xD0, 0xBC, 0xD0, 0xB5, 0xD1, 0x80,
            0xD1, 0x82, 0xD1, 0x8C, 0x20, 0xD0, 0xB7, 0xD0,
            0xB0, 0x20, 0xD1, 0x81, 0xD0, 0xBC, 0xD0, 0xB5,
            0xD1, 0x80, 0xD1, 0x82, 0xD1, 0x8C, 0x20, 0x00
    };

    int result = 0;
    int i;
    for(i = 0; i < 50; i++) {
        /* Generate the plaintext */
        axolotl_buffer *plain_buf = axolotl_buffer_create(testMessage, sizeof(testMessage));
        uint8_t *plain_buf_data = axolotl_buffer_data(plain_buf);
        size_t plain_buf_len = axolotl_buffer_len(plain_buf);
        plain_buf_data[plain_buf_len - 1] = (uint8_t)i;

        /* Generate the ciphertext */
        ciphertext_message *encrypted_message = 0;
        result = session_cipher_encrypt(cipher, plain_buf_data, plain_buf_len, &encrypted_message);
        ck_assert_int_eq(result, 0);
        axolotl_buffer *cipher_buf = ciphertext_message_get_serialized(encrypted_message);

        /* Add the generated messages to the arrays */
        plaintext_messages[i] = plain_buf;
        ciphertext_messages[i] = axolotl_buffer_copy(cipher_buf);

        /* Cleanup */
        AXOLOTL_UNREF(encrypted_message);
    }

    /* Randomize the two arrays using the same seed */
    time_t seed = time(0);
    srand(seed);
    shuffle_buffers(plaintext_messages, 50);
    srand(seed);
    shuffle_buffers(ciphertext_messages, 50);
}

void decrypt_and_compare_messages(session_cipher *cipher, axolotl_buffer *ciphertext, axolotl_buffer *plaintext)
{
    int result = 0;

    /* Create a whisper_message from the ciphertext */
    whisper_message *index_message_deserialized = 0;
    result = whisper_message_deserialize(&index_message_deserialized,
            axolotl_buffer_data(ciphertext),
            axolotl_buffer_len(ciphertext),
            global_context);
    ck_assert_int_eq(result, 0);

    /* Decrypt the message */
    axolotl_buffer *index_plaintext = 0;
    result = session_cipher_decrypt_whisper_message(cipher, index_message_deserialized, 0, &index_plaintext);
    ck_assert_int_eq(result, 0);

    /* Compare the messages */
    ck_assert_int_eq(axolotl_buffer_compare(index_plaintext, plaintext), 0);

    /* Cleanup */
    AXOLOTL_UNREF(index_message_deserialized);
    axolotl_buffer_free(index_plaintext);
}

void run_interaction(session_record *alice_session_record, session_record *bob_session_record)
{
    int result = 0;

    axolotl_address alice_address = {
            "+14159999999", 12, 1
    };

    axolotl_address bob_address = {
            "+14158888888", 12, 1
    };

    /* Create the test data stores */
    axolotl_store_context *alice_store = 0;
    setup_test_store_context(&alice_store, global_context);

    axolotl_store_context *bob_store = 0;
    setup_test_store_context(&bob_store, global_context);

    /* Store the two sessions in their data stores */
    result = axolotl_session_store_session(alice_store, &alice_address, alice_session_record);
    ck_assert_int_eq(result, 0);
    result = axolotl_session_store_session(bob_store, &bob_address, bob_session_record);
    ck_assert_int_eq(result, 0);

    /* Create two session cipher instances */
    session_cipher *alice_cipher = 0;
    result = session_cipher_create(&alice_cipher, alice_store, &alice_address, global_context);
    ck_assert_int_eq(result, 0);

    session_cipher *bob_cipher = 0;
    result = session_cipher_create(&bob_cipher, bob_store, &bob_address, global_context);
    ck_assert_int_eq(result, 0);

    /* Encrypt a test message from Alice */
    static const char alice_plaintext[] = "This is a plaintext message.";
    size_t alice_plaintext_len = sizeof(alice_plaintext) - 1;
    ciphertext_message *alice_message = 0;
    result = session_cipher_encrypt(alice_cipher, (uint8_t *)alice_plaintext, alice_plaintext_len, &alice_message);
    ck_assert_int_eq(result, 0);

    /* Serialize and deserialize the test message to create a fresh instance */
    axolotl_buffer *alice_message_serialized = ciphertext_message_get_serialized(alice_message);
    ck_assert_ptr_ne(alice_message_serialized, 0);

    whisper_message *alice_message_deserialized = 0;
    result = whisper_message_deserialize(&alice_message_deserialized,
            axolotl_buffer_data(alice_message_serialized),
            axolotl_buffer_len(alice_message_serialized),
            global_context);
    ck_assert_int_eq(result, 0);

    /* Have Bob decrypt the test message */
    axolotl_buffer *bob_plaintext = 0;
    result = session_cipher_decrypt_whisper_message(bob_cipher, alice_message_deserialized, 0, &bob_plaintext);
    ck_assert_int_eq(result, 0);

    uint8_t *bob_plaintext_data = axolotl_buffer_data(bob_plaintext);
    size_t bob_plaintext_len = axolotl_buffer_len(bob_plaintext);

    ck_assert_int_eq(alice_plaintext_len, bob_plaintext_len);
    ck_assert_int_eq(memcmp(alice_plaintext, bob_plaintext_data, bob_plaintext_len), 0);

    fprintf(stderr, "Interaction complete: Alice -> Bob\n");

    /* Encrypt a reply from Bob */
    static const char bob_reply[] = "This is a message from Bob.";
    size_t bob_reply_len = sizeof(bob_reply) - 1;
    ciphertext_message *reply_message = 0;
    result = session_cipher_encrypt(bob_cipher, (uint8_t *)bob_reply, bob_reply_len, &reply_message);
    ck_assert_int_eq(result, 0);

    /* Serialize and deserialize the reply message to create a fresh instance */
    axolotl_buffer *reply_message_serialized = ciphertext_message_get_serialized(reply_message);
    ck_assert_ptr_ne(reply_message_serialized, 0);

    whisper_message *reply_message_deserialized = 0;
    result = whisper_message_deserialize(&reply_message_deserialized,
            axolotl_buffer_data(reply_message_serialized),
            axolotl_buffer_len(reply_message_serialized),
            global_context);
    ck_assert_int_eq(result, 0);

    /* Have Alice decrypt the reply message */

    axolotl_buffer *reply_plaintext = 0;
    result = session_cipher_decrypt_whisper_message(alice_cipher, reply_message_deserialized, 0, &reply_plaintext);
    ck_assert_int_eq(result, 0);

    uint8_t *reply_plaintext_data = axolotl_buffer_data(reply_plaintext);
    size_t reply_plaintext_len = axolotl_buffer_len(reply_plaintext);

    ck_assert_int_eq(bob_reply_len, reply_plaintext_len);
    ck_assert_int_eq(memcmp(bob_reply, reply_plaintext_data, reply_plaintext_len), 0);

    fprintf(stderr, "Interaction complete: Bob -> Alice\n");

    int i;

    /* Generate 50 indexed Alice test messages */
    axolotl_buffer *alice_plaintext_messages[50];
    axolotl_buffer *alice_ciphertext_messages[50];
    generate_test_message_collections(alice_cipher, alice_plaintext_messages, alice_ciphertext_messages, 50);

    /* Iterate through half the collection and try to decrypt messages */
    for(i = 0; i < 25; i++) {
        decrypt_and_compare_messages(bob_cipher, alice_ciphertext_messages[i], alice_plaintext_messages[i]);
    }

    fprintf(stderr, "Interaction complete: Alice -> Bob (randomized, 0-24)\n");

    /* Generate 50 indexed Bob test messages */
    axolotl_buffer *bob_plaintext_messages[50];
    axolotl_buffer *bob_ciphertext_messages[50];
    generate_test_message_collections(bob_cipher, bob_plaintext_messages, bob_ciphertext_messages, 50);

    /* Iterate through half the collection and try to decrypt messages */
    for(i = 0; i < 25; i++) {
        decrypt_and_compare_messages(alice_cipher, bob_ciphertext_messages[i], bob_plaintext_messages[i]);
    }

    fprintf(stderr, "Interaction complete: Bob -> Alice (randomized, 0-24)\n");

    /* Iterate through the second half of the collection and try to decrypt messages */
    for(i = 25; i < 50; i++) {
        decrypt_and_compare_messages(bob_cipher, alice_ciphertext_messages[i], alice_plaintext_messages[i]);
    }

    fprintf(stderr, "Interaction complete: Alice -> Bob (randomized, 25-49)\n");

    /* Iterate through the second half of the collection and try to decrypt messages */
    for(i = 25; i < 50; i++) {
        decrypt_and_compare_messages(alice_cipher, bob_ciphertext_messages[i], bob_plaintext_messages[i]);
    }

    fprintf(stderr, "Interaction complete: Bob -> Alice (randomized, 25-49)\n");

    /* Cleanup */
    for(i = 0; i < 50; i++) {
        axolotl_buffer_free(alice_plaintext_messages[i]);
        axolotl_buffer_free(alice_ciphertext_messages[i]);
    }
    for(i = 0; i < 50; i++) {
        axolotl_buffer_free(bob_plaintext_messages[i]);
        axolotl_buffer_free(bob_ciphertext_messages[i]);
    }

    AXOLOTL_UNREF(alice_message);
    AXOLOTL_UNREF(reply_message);
    AXOLOTL_UNREF(alice_message_deserialized);
    AXOLOTL_UNREF(reply_message_deserialized);
    axolotl_buffer_free(reply_plaintext);
    axolotl_buffer_free(bob_plaintext);
    session_cipher_free(alice_cipher);
    session_cipher_free(bob_cipher);
    axolotl_store_context_destroy(alice_store);
    axolotl_store_context_destroy(bob_store);
}

START_TEST(test_message_key_limits)
{
    int i;
    int result = 0;

    axolotl_address alice_address = {
            "+14159999999", 12, 1
    };

    axolotl_address bob_address = {
            "+14158888888", 12, 1
    };

    /* Create Alice's session record */
    session_record *alice_session_record = 0;
    result = session_record_create(&alice_session_record, 0, global_context);
    ck_assert_int_eq(result, 0);

    /* Create Bob's session record */
    session_record *bob_session_record = 0;
    result = session_record_create(&bob_session_record, 0, global_context);
    ck_assert_int_eq(result, 0);

    /* Initialize the sessions */
    initialize_sessions_v3(
            session_record_get_state(alice_session_record),
            session_record_get_state(bob_session_record));

    /* Create Alice's data store */
    axolotl_store_context *alice_store = 0;
    setup_test_store_context(&alice_store, global_context);

    /* Create Bob's data store */
    axolotl_store_context *bob_store = 0;
    setup_test_store_context(&bob_store, global_context);

    /* Store the sessions */
    result = axolotl_session_store_session(alice_store, &alice_address, alice_session_record);
    ck_assert_int_eq(result, 0);
    result = axolotl_session_store_session(bob_store, &bob_address, bob_session_record);
    ck_assert_int_eq(result, 0);

    /* Create Alice's session cipher */
    session_cipher *alice_cipher = 0;
    result = session_cipher_create(&alice_cipher, alice_store, &alice_address, global_context);
    ck_assert_int_eq(result, 0);

    /* Create Bob's session cipher */
    session_cipher *bob_cipher = 0;
    result = session_cipher_create(&bob_cipher, bob_store, &bob_address, global_context);
    ck_assert_int_eq(result, 0);

    whisper_message *inflight[2010];
    memset(inflight, 0, sizeof(inflight));

    /* Encrypt enough messages to go past our limit */
    for(i = 0; i < 2010; i++) {
        static const char alice_plaintext[] = "you've never been so hungry, you've never been so cold";
        size_t alice_plaintext_len = sizeof(alice_plaintext) - 1;

        ciphertext_message *alice_message = 0;
        result = session_cipher_encrypt(alice_cipher, (uint8_t *)alice_plaintext, alice_plaintext_len, &alice_message);
        ck_assert_int_eq(result, 0);
        ck_assert_int_eq(ciphertext_message_get_type(alice_message), CIPHERTEXT_WHISPER_TYPE);
        inflight[i] = (whisper_message *)alice_message;
    }

    whisper_message *message_copy = 0;
    axolotl_buffer *buffer = 0;

    /* Try decrypting in-flight message 1000 */
    result = whisper_message_copy(&message_copy, inflight[1000], global_context);
    ck_assert_int_eq(result, 0);
    result = session_cipher_decrypt_whisper_message(bob_cipher, message_copy, 0, &buffer);
    ck_assert_int_eq(result, 0);
    ck_assert_ptr_ne(buffer, 0);
    axolotl_buffer_free(buffer); buffer = 0;
    AXOLOTL_UNREF(message_copy);

    /* Try decrypting in-flight message 2009 */
    result = whisper_message_copy(&message_copy, inflight[2009], global_context);
    ck_assert_int_eq(result, 0);
    result = session_cipher_decrypt_whisper_message(bob_cipher, message_copy, 0, &buffer);
    ck_assert_int_eq(result, 0);
    ck_assert_ptr_ne(buffer, 0);
    axolotl_buffer_free(buffer); buffer = 0;
    AXOLOTL_UNREF(message_copy);

    /* Try decrypting in-flight message 0, which should fail */
    result = whisper_message_copy(&message_copy, inflight[0], global_context);
    ck_assert_int_eq(result, 0);
    result = session_cipher_decrypt_whisper_message(bob_cipher, message_copy, 0, &buffer);
    ck_assert_int_eq(result, AX_ERR_DUPLICATE_MESSAGE);
    axolotl_buffer_free(buffer); buffer = 0;
    AXOLOTL_UNREF(message_copy);

    /* Cleanup */
    for(i = 0; i < 2010; i++) {
        if(inflight[i]) {
            AXOLOTL_UNREF(inflight[i]);
        }
    }
    AXOLOTL_UNREF(alice_session_record);
    AXOLOTL_UNREF(bob_session_record);
    session_cipher_free(alice_cipher);
    session_cipher_free(bob_cipher);
    axolotl_store_context_destroy(alice_store);
    axolotl_store_context_destroy(bob_store);
}
END_TEST

Suite *session_cipher_suite(void)
{
    Suite *suite = suite_create("session_cipher");

    TCase *tcase = tcase_create("case");
    tcase_add_checked_fixture(tcase, test_setup, test_teardown);
    tcase_add_test(tcase, test_basic_session_v2);
    tcase_add_test(tcase, test_basic_session_v3);
    tcase_add_test(tcase, test_message_key_limits);
    suite_add_tcase(suite, tcase);

    return suite;
}

int main(void)
{
    int number_failed;
    Suite *suite;
    SRunner *runner;

    suite = session_cipher_suite();
    runner = srunner_create(suite);

    srunner_run_all(runner, CK_VERBOSE);
    number_failed = srunner_ntests_failed(runner);
    srunner_free(runner);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
