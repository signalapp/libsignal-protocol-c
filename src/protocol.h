#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <stdint.h>
#include <stddef.h>
#include "axolotl_types.h"

#ifdef __cplusplus
extern "C" {
#endif

#define KEY_EXCHANGE_INITIATE_FLAG              0x01
#define KEY_EXCHANGE_RESPONSE_FLAG              0X02
#define KEY_EXCHANGE_SIMULTAENOUS_INITIATE_FLAG 0x04

#define CIPHERTEXT_UNSUPPORTED_VERSION         1
#define CIPHERTEXT_CURRENT_VERSION             3

#define CIPHERTEXT_WHISPER_TYPE                2
#define CIPHERTEXT_PREKEY_TYPE                 3
#define CIPHERTEXT_SENDERKEY_TYPE              4
#define CIPHERTEXT_SENDERKEY_DISTRIBUTION_TYPE 5

/* Worst case overhead. Not always accurate, but good enough for padding. */
#define CIPHERTEXT_ENCRYPTED_MESSAGE_OVERHEAD 53

int key_exchange_message_create(key_exchange_message **message,
        uint8_t message_version, uint32_t sequence, uint32_t flags,
        ec_public_key *base_key, uint8_t *base_key_signature,
        ec_public_key *ratchet_key, ec_public_key *identity_key);

int key_exchange_message_deserialize(key_exchange_message **message, const uint8_t *data, size_t len, axolotl_context *global_context);

axolotl_buffer *key_exchange_message_get_serialized(const key_exchange_message *message);

uint8_t key_exchange_message_get_version(const key_exchange_message *message);
ec_public_key *key_exchange_message_get_base_key(const key_exchange_message *message);
uint8_t *key_exchange_message_get_base_key_signature(key_exchange_message *message);
ec_public_key *key_exchange_message_get_ratchet_key(const key_exchange_message *message);
ec_public_key *key_exchange_message_get_identity_key(const key_exchange_message *message);
int key_exchange_message_has_identity_key(const key_exchange_message *message);
uint8_t key_exchange_message_get_max_version(const key_exchange_message *message);
int key_exchange_message_is_response(const key_exchange_message *message);
int key_exchange_message_is_initiate(const key_exchange_message *message);
int key_exchange_message_is_response_for_simultaneous_initiate(const key_exchange_message *message);
uint32_t key_exchange_message_get_flags(const key_exchange_message *message);
uint32_t key_exchange_message_get_sequence(const key_exchange_message *message);

void key_exchange_message_destroy(axolotl_type_base *type);

int ciphertext_message_get_type(const ciphertext_message *message);
axolotl_buffer *ciphertext_message_get_serialized(const ciphertext_message *message);

int whisper_message_create(whisper_message **message, uint8_t message_version,
        const uint8_t *mac_key, size_t mac_key_len,
        ec_public_key *sender_ratchet_key, uint32_t counter, uint32_t previous_counter,
        const uint8_t *ciphertext, size_t ciphertext_len,
        ec_public_key *sender_identity_key, ec_public_key *receiver_identity_key,
        axolotl_context *global_context);

int whisper_message_deserialize(whisper_message **message, const uint8_t *data, size_t len,
        axolotl_context *global_context);

int whisper_message_copy(whisper_message **message, whisper_message *other_message, axolotl_context *global_context);

ec_public_key *whisper_message_get_sender_ratchet_key(const whisper_message *message);

uint8_t whisper_message_get_message_version(const whisper_message *message);

uint32_t whisper_message_get_counter(const whisper_message *message);

axolotl_buffer *whisper_message_get_body(const whisper_message *message);

/**
 * Verify the MAC on the Whisper message.
 *
 * @return 1 if verified, 0 if invalid, negative on error
 */
int whisper_message_verify_mac(whisper_message *message,
        uint8_t message_version,
        ec_public_key *sender_identity_key,
        ec_public_key *receiver_identity_key,
        const uint8_t *mac_key, size_t mac_key_len,
        axolotl_context *global_context);

int whisper_message_is_legacy(const uint8_t *data, size_t len);

void whisper_message_destroy(axolotl_type_base *type);

int pre_key_whisper_message_create(pre_key_whisper_message **pre_key_message,
        uint8_t message_version, uint32_t registration_id, const uint32_t *pre_key_id,
        uint32_t signed_pre_key_id, ec_public_key *base_key, ec_public_key *identity_key,
        whisper_message *message,
        axolotl_context *global_context);

int pre_key_whisper_message_deserialize(pre_key_whisper_message **message,
        const uint8_t *data, size_t len,
        axolotl_context *global_context);

int pre_key_whisper_message_copy(pre_key_whisper_message **message, pre_key_whisper_message *other_message, axolotl_context *global_context);

uint8_t pre_key_whisper_message_get_message_version(const pre_key_whisper_message *message);
ec_public_key *pre_key_whisper_message_get_identity_key(const pre_key_whisper_message *message);
uint32_t pre_key_whisper_message_get_registration_id(const pre_key_whisper_message *message);
int pre_key_whisper_message_has_pre_key_id(const pre_key_whisper_message *message);
uint32_t pre_key_whisper_message_get_pre_key_id(const pre_key_whisper_message *message);
uint32_t pre_key_whisper_message_get_signed_pre_key_id(const pre_key_whisper_message *message);
ec_public_key *pre_key_whisper_message_get_base_key(const pre_key_whisper_message *message);
whisper_message *pre_key_whisper_message_get_whisper_message(const pre_key_whisper_message *message);

void pre_key_whisper_message_destroy(axolotl_type_base *type);

int sender_key_message_create(sender_key_message **message,
        uint32_t key_id, uint32_t iteration,
        const uint8_t *ciphertext, size_t ciphertext_len,
        ec_private_key *signature_key,
        axolotl_context *global_context);
int sender_key_message_deserialize(sender_key_message **message,
        const uint8_t *data, size_t len,
        axolotl_context *global_context);
int sender_key_message_copy(sender_key_message **message, sender_key_message *other_message, axolotl_context *global_context);

uint32_t sender_key_message_get_key_id(sender_key_message *message);
uint32_t sender_key_message_get_iteration(sender_key_message *message);
axolotl_buffer *sender_key_message_get_ciphertext(sender_key_message *message);
int sender_key_message_verify_signature(sender_key_message *message, ec_public_key *signature_key);

void sender_key_message_destroy(axolotl_type_base *type);

int sender_key_distribution_message_create(sender_key_distribution_message **message,
        uint32_t id, uint32_t iteration,
        const uint8_t *chain_key, size_t chain_key_len,
        ec_public_key *signature_key,
        axolotl_context *global_context);
int sender_key_distribution_message_deserialize(sender_key_distribution_message **message,
        const uint8_t *data, size_t len,
        axolotl_context *global_context);
int sender_key_distribution_message_copy(sender_key_distribution_message **message, sender_key_distribution_message *other_message, axolotl_context *global_context);

uint32_t sender_key_distribution_message_get_id(sender_key_distribution_message *message);
uint32_t sender_key_distribution_message_get_iteration(sender_key_distribution_message *message);
axolotl_buffer *sender_key_distribution_message_get_chain_key(sender_key_distribution_message *message);
ec_public_key *sender_key_distribution_message_get_signature_key(sender_key_distribution_message *message);

void sender_key_distribution_message_destroy(axolotl_type_base *type);

#ifdef __cplusplus
}
#endif

#endif /* PROTOCOL_H */
