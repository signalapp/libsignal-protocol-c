#ifndef KEY_HELPER_H
#define KEY_HELPER_H

#include <stdint.h>
#include "axolotl_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
* Generate an identity key pair.  Clients should only do this once,
* at install time.
*
* @param key_pair the generated identity key pair
* @return 0 on success, or negative on failure
*/
int axolotl_key_helper_generate_identity_key_pair(ratchet_identity_key_pair **key_pair, axolotl_context *global_context);

/**
 * Generate a registration ID.  Clients should only do this once,
 * at install time.
 *
 * @param registration_id set to the generated registration ID
 * @param extendedRange By default (0), the generated registration
 *                      ID is sized to require the minimal possible protobuf
 *                      encoding overhead. Specify true (1) if the caller needs
 *                      the full range of MAX_INT at the cost of slightly
 *                      higher encoding overhead.
 * @return 0 on success, or negative on failure
 */
int axolotl_key_helper_generate_registration_id(uint32_t *registration_id, int extended_range, axolotl_context *global_context);

/**
 * Generate a random number bounded by the provided maximum
 *
 * @param value set to the next random number
 * @param max the maximum value of the random number
 * @return 0 on success, or negative on failure
 */
int axolotl_key_helper_get_random_sequence(int *value, int max, axolotl_context *global_context);

/**
 * Generate a list of PreKeys.  Clients should do this at install time, and
 * subsequently any time the list of PreKeys stored on the server runs low.
 *
 * Pre key IDs are shorts, so they will eventually be repeated.  Clients should
 * store pre keys in a circular buffer, so that they are repeated as infrequently
 * as possible.
 *
 * When finished with this list, the caller should free it by calling
 * axolotl_key_helper_key_list_free().
 *
 * @param head pointer to the head of the key list
 * @param start the starting pre key ID, inclusive.
 * @param count the number of pre keys to generate.
 * @return 0 on success, or negative on failure
 */
int axolotl_key_helper_generate_pre_keys(axolotl_key_helper_pre_key_list_node **head,
        unsigned int start, unsigned int count,
        axolotl_context *global_context);

/**
 * Get the pre key element for the current node in the key list.
 *
 * @param current list node
 * @return pre key element
 */
session_pre_key *axolotl_key_helper_key_list_element(const axolotl_key_helper_pre_key_list_node *node);

/**
 * Get the next element in the ket list.
 *
 * @param current list node
 * @return next list node, or 0 if at the end of the list
 */
axolotl_key_helper_pre_key_list_node *axolotl_key_helper_key_list_next(const axolotl_key_helper_pre_key_list_node *node);

/**
 * Free the key list.
 *
 * @param head pointer to the head of the list to free
 */
void axolotl_key_helper_key_list_free(axolotl_key_helper_pre_key_list_node *head);

/**
 * Generate the last resort pre key.  Clients should do this only once, at
 * install time, and durably store it for the length of the install.
 *
 * @param pre_key set to the generated pre key
 * @return 0 on success, or negative on failure
 */
int axolotl_key_helper_generate_last_resort_pre_key(session_pre_key **pre_key, axolotl_context *global_context);

/**
 * Generate a signed pre key
 *
 * @param signed_pre_key set to the generated pre key
 * @param identity_key_pair the local client's identity key pair.
 * @param signed_pre_key_id the pre key ID to assign the generated signed pre key
 * @param timestamp the current time in milliseconds since the UNIX epoch
 *
 * @return 0 on success, or negative on failure
 */
int axolotl_key_helper_generate_signed_pre_key(session_signed_pre_key **signed_pre_key,
        const ratchet_identity_key_pair *identity_key_pair,
        uint32_t signed_pre_key_id,
        uint64_t timestamp,
        axolotl_context *global_context);

/*
 * Generate a sender signing key pair
 *
* @param key_pair the generated key pair
* @return 0 on success, or negative on failure
 */
int axolotl_key_helper_generate_sender_signing_key(ec_key_pair **key_pair, axolotl_context *global_context);

/*
 * Generate a sender key
 *
 * @param key_buffer buffer to be allocated and populated with the result
 * @return 0 on success, or negative on failure
 */
int axolotl_key_helper_generate_sender_key(axolotl_buffer **key_buffer, axolotl_context *global_context);

/*
 * Generate a sender key ID
 *
 * @param key_id assigned to the generated ID
 * @return 0 on success, or negative on failure
 */
int axolotl_key_helper_generate_sender_key_id(uint32_t *key_id, axolotl_context *global_context);

#ifdef __cplusplus
}
#endif

#endif /* KEY_HELPER_H */
