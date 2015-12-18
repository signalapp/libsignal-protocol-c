#ifndef AXOLOTL_INTERNAL_H
#define AXOLOTL_INTERNAL_H

#include <protobuf-c/protobuf-c.h>
#include "axolotl.h"
#include "LocalStorageProtocol.pb-c.h"

struct axolotl_type_base {
    unsigned int ref_count;
    void (*destroy)(axolotl_type_base *instance);
};

void axolotl_type_init(axolotl_type_base *instance,
        void (*destroy_func)(axolotl_type_base *instance));

#define AXOLOTL_INIT(instance, destroy_func) axolotl_type_init((axolotl_type_base *)instance, destroy_func)

struct axolotl_buffer {
    size_t len;
    uint8_t data[];
};

struct axolotl_context {
    axolotl_crypto_provider crypto_provider;
    void (*lock)(void *user_data);
    void (*unlock)(void *user_data);
    void (*log)(int level, const char *message, size_t len, void *user_data);
    void *user_data;
};

int axolotl_crypto_random(axolotl_context *context, uint8_t *data, size_t len);
int axolotl_hmac_sha256_init(axolotl_context *context, void **hmac_context, const uint8_t *key, size_t key_len);
int axolotl_hmac_sha256_update(axolotl_context *context, void *hmac_context, const uint8_t *data, size_t data_len);
int axolotl_hmac_sha256_final(axolotl_context *context, void *hmac_context, axolotl_buffer **output);
void axolotl_hmac_sha256_cleanup(axolotl_context *context, void *hmac_context);

int axolotl_sha512_digest(axolotl_context *context, axolotl_buffer **output, const uint8_t *data, size_t data_len);

int axolotl_encrypt(axolotl_context *context,
        axolotl_buffer **output,
        int cipher,
        const uint8_t *key, size_t key_len,
        const uint8_t *iv, size_t iv_len,
        const uint8_t *plaintext, size_t plaintext_len);

int axolotl_decrypt(axolotl_context *context,
        axolotl_buffer **output,
        int cipher,
        const uint8_t *key, size_t key_len,
        const uint8_t *iv, size_t iv_len,
        const uint8_t *ciphertext, size_t ciphertext_len);

void axolotl_lock(axolotl_context *context);
void axolotl_unlock(axolotl_context *context);
void axolotl_log(axolotl_context *context, int level, const char *format, ...);
void axolotl_explicit_bzero(void *v, size_t n);
int axolotl_constant_memcmp(const void *s1, const void *s2, size_t n);

/*------------------------------------------------------------------------*/

/*
 * Functions used for internal protocol buffers serialization support.
 */

int ec_public_key_serialize_protobuf(ProtobufCBinaryData *buffer, const ec_public_key *key);
int ec_private_key_serialize_protobuf(ProtobufCBinaryData *buffer, const ec_private_key *key);

int ratchet_chain_key_get_key_protobuf(const ratchet_chain_key *chain_key, ProtobufCBinaryData *buffer);
int ratchet_root_key_get_key_protobuf(const ratchet_root_key *root_key, ProtobufCBinaryData *buffer);

int session_state_serialize_prepare(session_state *state, Textsecure__SessionStructure *session_structure);
void session_state_serialize_prepare_free(Textsecure__SessionStructure *session_structure);
int session_state_deserialize_protobuf(session_state **state, Textsecure__SessionStructure *session_structure, axolotl_context *global_context);

int sender_key_state_serialize_prepare(sender_key_state *state, Textsecure__SenderKeyStateStructure *state_structure);
void sender_key_state_serialize_prepare_free(Textsecure__SenderKeyStateStructure *state_structure);
int sender_key_state_deserialize_protobuf(sender_key_state **state, Textsecure__SenderKeyStateStructure *state_structure, axolotl_context *global_context);

void axolotl_str_serialize_protobuf(ProtobufCBinaryData *buffer, const char *str);
char *axolotl_str_deserialize_protobuf(ProtobufCBinaryData *buffer);

#endif /* AXOLOTL_INTERNAL_H */
