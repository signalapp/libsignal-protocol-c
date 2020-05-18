#include "../src/protocol.c"
#include "../src/protocol.h"
#include "../src/session_builder.h"
#include "../src/session_cipher.h"
#include "../src/signal_protocol.h"
#include "test_common.c"
#include "test_common.h"
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

signal_context *global_context;

static signal_protocol_address alice_address = {"+14159998888", 12, 1};

ec_key_pair *bob_signed_pre_key;
int32_t bob_signed_pre_key_id;

// Fuzz the decrypt routine with Data and Size
extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  int result = 0;

  // Create a new context
  result = signal_context_create(&global_context, 0);
  assert(result == 0);

  // Set up a test crypto provider using OpenSSL
  setup_test_crypto_provider(global_context);

  // Create Bob's data store
  signal_protocol_store_context *bob_store = 0;
  setup_test_store_context(&bob_store, global_context);

  // Register Bob
  uint32_t bob_local_registration_id = 0;
  result = signal_protocol_identity_get_local_registration_id(
      bob_store, &bob_local_registration_id);
  assert(result == 0);

  // Create his keys
  ec_key_pair *bob_pre_key_pair = 0;
  result = curve_generate_key_pair(global_context, &bob_pre_key_pair);
  assert(result == 0);

  ec_key_pair *bob_signed_pre_key_pair = 0;
  result = curve_generate_key_pair(global_context, &bob_signed_pre_key_pair);
  assert(result == 0);

  ratchet_identity_key_pair *bob_identity_key_pair = 0;
  result = signal_protocol_identity_get_key_pair(bob_store, &bob_identity_key_pair);
  assert(result == 0);

  signal_buffer *bob_signed_pre_key_public_serialized = 0;
  result = ec_public_key_serialize(&bob_signed_pre_key_public_serialized,
                              ec_key_pair_get_public(bob_signed_pre_key_pair));
  assert(result == 0);

  signal_buffer *bob_signed_pre_key_signature = 0;
  result = curve_calculate_signature(
      global_context, &bob_signed_pre_key_signature,
      ratchet_identity_key_pair_get_private(bob_identity_key_pair),
      signal_buffer_data(bob_signed_pre_key_public_serialized),
      signal_buffer_len(bob_signed_pre_key_public_serialized));
  assert(result == 0);

  session_pre_key_bundle *bob_pre_key = 0;
  result = session_pre_key_bundle_create(
      &bob_pre_key, bob_local_registration_id, 
      1,   /* device ID */
      31337, /* pre key ID */
      ec_key_pair_get_public(bob_pre_key_pair), 
      22, /* signed pre key ID */
      ec_key_pair_get_public(bob_signed_pre_key_pair),
      signal_buffer_data(bob_signed_pre_key_signature),
      signal_buffer_len(bob_signed_pre_key_signature),
      ratchet_identity_key_pair_get_public(bob_identity_key_pair));
  assert(result == 0);

  // And add Bob's pre keys to his data store 
  session_pre_key *bob_pre_key_record = 0;
  result = session_pre_key_create(
      &bob_pre_key_record, session_pre_key_bundle_get_pre_key_id(bob_pre_key),
      bob_pre_key_pair);
  assert(result == 0);

  result = signal_protocol_pre_key_store_key(bob_store, bob_pre_key_record);
  assert(result == 0);

  session_signed_pre_key *bob_signed_pre_key_record = 0;
  result = session_signed_pre_key_create(
      &bob_signed_pre_key_record, 22, time(0), bob_signed_pre_key_pair,
      signal_buffer_data(bob_signed_pre_key_signature),
      signal_buffer_len(bob_signed_pre_key_signature));
  assert(result == 0);

  result = signal_protocol_signed_pre_key_store_key(bob_store,
                                                    bob_signed_pre_key_record);
  assert(result == 0);

  session_cipher *bob_session_cipher = 0;
  result = session_cipher_create(&bob_session_cipher, bob_store, &alice_address,
                                 global_context);
  assert(result == 0);

  // Start of the actual fuzzing, attempt to deserialize the input data
  pre_key_signal_message *incoming_message_bad = 0;
  result = pre_key_signal_message_deserialize(
      &incoming_message_bad, Data, Size, global_context);
  if (result != 0) {
    goto done;
  }

  // And if it deserialized okay, then decrypt it 
  signal_buffer *plaintext = 0;
  result = session_cipher_decrypt_pre_key_signal_message(
      bob_session_cipher, incoming_message_bad, 0, &plaintext);

  // Then free everything 
  signal_buffer_free(plaintext);
done:
  session_cipher_free(bob_session_cipher);
  SIGNAL_UNREF(incoming_message_bad);
  SIGNAL_UNREF(bob_pre_key);
  SIGNAL_UNREF(bob_pre_key_pair);
  SIGNAL_UNREF(bob_signed_pre_key_pair);
  SIGNAL_UNREF(bob_identity_key_pair);
  SIGNAL_UNREF(bob_signed_pre_key_record);
  SIGNAL_UNREF(bob_pre_key_record);
  signal_buffer_free(bob_signed_pre_key_public_serialized);
  signal_buffer_free(bob_signed_pre_key_signature);
  signal_protocol_store_context_destroy(bob_store);
  signal_context_destroy(global_context);

  return 0;
}
