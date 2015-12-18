#ifndef AXOLOTL_TYPES_H
#define AXOLOTL_TYPES_H

#include <stdint.h>
#include <stdlib.h>

#ifndef _WINDOWS
#include <unistd.h>
#else
#include <basetsd.h>
typedef SSIZE_T ssize_t;
#endif

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Base library types
 */
typedef struct axolotl_type_base axolotl_type_base;
typedef struct axolotl_buffer axolotl_buffer;
typedef struct axolotl_buffer_list axolotl_buffer_list;
typedef struct axolotl_int_list axolotl_int_list;

/*
 * Global context for the AXOLOTL library
 */
typedef struct axolotl_context axolotl_context;

/*
 * Context for the AXOLOTL data store implementation
 */
typedef struct axolotl_store_context axolotl_store_context;

/*
 * Address of an AXOLOTL message recipient
 */
typedef struct axolotl_address {
    const char *name;
    size_t name_len;
    int32_t device_id;
} axolotl_address;

/*
 * A representation of a (group + sender + device) tuple
 */
typedef struct axolotl_sender_key_name {
    const char *group_id;
    size_t group_id_len;
    axolotl_address sender;
} axolotl_sender_key_name;

/*
 * Curve key types
 */
typedef struct ec_public_key ec_public_key;
typedef struct ec_private_key ec_private_key;
typedef struct ec_key_pair ec_key_pair;

/*
 * HKDF types
 */
typedef struct hkdf_context hkdf_context;

/*
 * Key helper types
 */
typedef struct axolotl_key_helper_pre_key_list_node axolotl_key_helper_pre_key_list_node;

/*
 * Protocol types
 */
typedef struct key_exchange_message key_exchange_message;
typedef struct ciphertext_message ciphertext_message;
typedef struct whisper_message whisper_message;
typedef struct pre_key_whisper_message pre_key_whisper_message;
typedef struct sender_key_message sender_key_message;
typedef struct sender_key_distribution_message sender_key_distribution_message;

/*
 * Ratchet types
 */
#define RATCHET_CIPHER_KEY_LENGTH 32
#define RATCHET_MAC_KEY_LENGTH 32
#define RATCHET_IV_LENGTH 16

typedef struct ratchet_chain_key ratchet_chain_key;
typedef struct ratchet_root_key ratchet_root_key;
typedef struct ratchet_identity_key_pair ratchet_identity_key_pair;

typedef struct ratchet_message_keys {
    uint8_t cipher_key[RATCHET_CIPHER_KEY_LENGTH];
    uint8_t mac_key[RATCHET_MAC_KEY_LENGTH];
    uint8_t iv[RATCHET_IV_LENGTH];
    uint32_t counter;
} ratchet_message_keys;

/*
 * Session types
 */
typedef struct session_pre_key session_pre_key;
typedef struct session_signed_pre_key session_signed_pre_key;
typedef struct session_pre_key_bundle session_pre_key_bundle;
typedef struct session_builder session_builder;
typedef struct session_record session_record;
typedef struct session_record_state_node session_record_state_node;
typedef struct session_state session_state;
typedef struct session_cipher session_cipher;

/*
 * Group types
 */
typedef struct sender_message_key sender_message_key;
typedef struct sender_chain_key sender_chain_key;
typedef struct sender_key_state sender_key_state;
typedef struct sender_key_record sender_key_record;
typedef struct group_session_builder group_session_builder;
typedef struct group_cipher group_cipher;

/*
 * Fingerprint types
 */
typedef struct fingerprint fingerprint;
typedef struct displayable_fingerprint displayable_fingerprint;
typedef struct scannable_fingerprint scannable_fingerprint;
typedef struct fingerprint_generator fingerprint_generator;

#ifdef __cplusplus
}
#endif

#endif // AXOLOTL_TYPES_H
