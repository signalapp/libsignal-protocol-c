#ifndef CURVE_H
#define CURVE_H

#include <stdint.h>
#include <stddef.h>
#include "axolotl_types.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CURVE_SIGNATURE_LEN 64

int curve_decode_point(ec_public_key **public_key, const uint8_t *key_data, size_t key_len, axolotl_context *global_context);
int ec_public_key_compare(const ec_public_key *key1, const ec_public_key *key2);
int ec_public_key_memcmp(const ec_public_key *key1, const ec_public_key *key2);

/**
 * Serialize the public key into a buffer that can be stored.
 * The format of this data is compatible with the input format of
 * curve_decode_point().
 *
 * @param buffer Pointer to a buffer that will be allocated by this function
 *     and filled with the contents of the key. The caller is responsible for
 *     freeing this buffer with axolotl_buffer_free().
 * @param key Key to serialize
 * @return 0 on success, negative on failure
 */
int ec_public_key_serialize(axolotl_buffer **buffer, const ec_public_key *key);

void ec_public_key_destroy(axolotl_type_base *type);

int curve_decode_private_point(ec_private_key **private_key, const uint8_t *key_data, size_t key_len, axolotl_context *global_context);
int ec_private_key_compare(const ec_private_key *key1, const ec_private_key *key2);

/**
 * Serialize the private key into a buffer that can be stored.
 * The format of this data is compatible with the input format of
 * curve_decode_private_point().
 *
 * @param buffer Pointer to a buffer that will be allocated by this function
 *     and filled with the contents of the key. The caller is responsible for
 *     freeing this buffer with axolotl_buffer_free().
 * @param key Key to serialize
 * @return 0 on success, negative on failure
 */
int ec_private_key_serialize(axolotl_buffer **buffer, const ec_private_key *key);

void ec_private_key_destroy(axolotl_type_base *type);

int ec_key_pair_create(ec_key_pair **key_pair, ec_public_key *public_key, ec_private_key *private_key);
ec_public_key *ec_key_pair_get_public(const ec_key_pair *key_pair);
ec_private_key *ec_key_pair_get_private(const ec_key_pair *key_pair);
void ec_key_pair_destroy(axolotl_type_base *type);

int curve_generate_private_key(axolotl_context *context, ec_private_key **private_key);
int curve_generate_public_key(ec_public_key **public_key, const ec_private_key *private_key);
int curve_generate_key_pair(axolotl_context *context, ec_key_pair **key_pair);

int curve_calculate_agreement(uint8_t **shared_key_data, const ec_public_key *public_key, const ec_private_key *private_key);
int curve_verify_signature(const ec_public_key *signing_key,
        const uint8_t *message_data, size_t message_len,
        const uint8_t *signature_data, size_t signature_len);
int curve_calculate_signature(axolotl_context *context,
        axolotl_buffer **signature,
        const ec_private_key *signing_key,
        const uint8_t *message_data, size_t message_len);

#ifdef __cplusplus
}
#endif

#endif /* CURVE_H */
