#include "curve.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <protobuf-c/protobuf-c.h>

#include "curve25519/curve25519-donna.h"
#include "curve25519/ed25519/additions/curve_sigs.h"
#include "axolotl_internal.h"

#define DJB_TYPE 0x05
#define DJB_KEY_LEN 32

struct ec_public_key
{
    axolotl_type_base base;
    uint8_t data[DJB_KEY_LEN];
};

struct ec_private_key
{
    axolotl_type_base base;
    uint8_t data[DJB_KEY_LEN];
};

struct ec_key_pair
{
    axolotl_type_base base;
    ec_public_key *public_key;
    ec_private_key *private_key;
};

int curve_decode_point(ec_public_key **public_key, const uint8_t *key_data, size_t key_len, axolotl_context *global_context)
{
    ec_public_key *key = 0;

    if(key_len > 0 && key_data[0] != DJB_TYPE) {
        axolotl_log(global_context, AX_LOG_ERROR, "Invalid key type: %d", key_data[0]);
        return AX_ERR_INVALID_KEY;
    }

    if(key_len != DJB_KEY_LEN + 1) {
        axolotl_log(global_context, AX_LOG_ERROR, "Invalid key length: %d", key_len);
        return AX_ERR_INVALID_KEY;
    }

    key = malloc(sizeof(ec_public_key));
    if(!key) {
        return AX_ERR_NOMEM;
    }

    AXOLOTL_INIT(key, ec_public_key_destroy);

    memcpy(key->data, key_data + 1, DJB_KEY_LEN);

    *public_key = key;

    return 0;
}

int ec_public_key_compare(const ec_public_key *key1, const ec_public_key *key2)
{
    if(key1 == key2) {
        return 0;
    }
    else if(key1 == 0 && key2 != 0) {
        return -1;
    }
    else if(key1 != 0 && key2 == 0) {
        return 1;
    }
    else {
        return axolotl_constant_memcmp(key1->data, key2->data, DJB_KEY_LEN);
    }
}

int ec_public_key_memcmp(const ec_public_key *key1, const ec_public_key *key2)
{
    if(key1 == key2) {
        return 0;
    }
    else if(key1 == 0 && key2 != 0) {
        return -1;
    }
    else if(key1 != 0 && key2 == 0) {
        return 1;
    }
    else {
        return memcmp(key1->data, key2->data, DJB_KEY_LEN);
    }
}

int ec_public_key_serialize(axolotl_buffer **buffer, const ec_public_key *key)
{
    axolotl_buffer *buf = 0;
    uint8_t *data = 0;

    buf = axolotl_buffer_alloc(sizeof(uint8_t) * (DJB_KEY_LEN + 1));
    if(!buf) {
        return AX_ERR_NOMEM;
    }

    data = axolotl_buffer_data(buf);
    data[0] = DJB_TYPE;
    memcpy(data + 1, key->data, DJB_KEY_LEN);

    *buffer = buf;

    return 0;
}

int ec_public_key_serialize_protobuf(ProtobufCBinaryData *buffer, const ec_public_key *key)
{
    size_t len = 0;
    uint8_t *data = 0;

    assert(buffer);
    assert(key);

    len = sizeof(uint8_t) * (DJB_KEY_LEN + 1);
    data = malloc(len);
    if(!data) {
        return AX_ERR_NOMEM;
    }

    data[0] = DJB_TYPE;
    memcpy(data + 1, key->data, DJB_KEY_LEN);

    buffer->data = data;
    buffer->len = len;
    return 0;
}

void ec_public_key_destroy(axolotl_type_base *type)
{
    ec_public_key *public_key = (ec_public_key *)type;
    free(public_key);
}

int curve_decode_private_point(ec_private_key **private_key, const uint8_t *key_data, size_t key_len, axolotl_context *global_context)
{
    ec_private_key *key = 0;

    if(key_len != DJB_KEY_LEN) {
        axolotl_log(global_context, AX_LOG_ERROR, "Invalid key length: %d", key_len);
        return AX_ERR_INVALID_KEY;
    }

    key = malloc(sizeof(ec_private_key));
    if(!key) {
        return AX_ERR_NOMEM;
    }

    AXOLOTL_INIT(key, ec_private_key_destroy);

    memcpy(key->data, key_data, DJB_KEY_LEN);

    *private_key = key;

    return 0;
}

int ec_private_key_compare(const ec_private_key *key1, const ec_private_key *key2)
{
    if(key1 == key2) {
        return 0;
    }
    else if(key1 == 0 && key2 != 0) {
        return -1;
    }
    else if(key1 != 0 && key2 == 0) {
        return 1;
    }
    else {
        return axolotl_constant_memcmp(key1->data, key2->data, DJB_KEY_LEN);
    }
}

int ec_private_key_serialize(axolotl_buffer **buffer, const ec_private_key *key)
{
    axolotl_buffer *buf = 0;
    uint8_t *data = 0 ;
    
    buf = axolotl_buffer_alloc(sizeof(uint8_t) * DJB_KEY_LEN);
    if(!buf) {
        return AX_ERR_NOMEM;
    }

    data = axolotl_buffer_data(buf);
    memcpy(data, key->data, DJB_KEY_LEN);

    *buffer = buf;

    return 0;
}

int ec_private_key_serialize_protobuf(ProtobufCBinaryData *buffer, const ec_private_key *key)
{
    size_t len = 0;
    uint8_t *data = 0;

    assert(buffer);
    assert(key);

    len = sizeof(uint8_t) * DJB_KEY_LEN;
    data = malloc(len);
    if(!data) {
        return AX_ERR_NOMEM;
    }

    memcpy(data, key->data, DJB_KEY_LEN);

    buffer->data = data;
    buffer->len = len;
    return 0;
}

void ec_private_key_destroy(axolotl_type_base *type)
{
    ec_private_key *private_key = (ec_private_key *)type;
    axolotl_explicit_bzero(private_key, sizeof(ec_private_key));
    free(private_key);
}

int ec_key_pair_create(ec_key_pair **key_pair, ec_public_key *public_key, ec_private_key *private_key)
{
    ec_key_pair *result = malloc(sizeof(ec_key_pair));
    if(!result) {
        return AX_ERR_NOMEM;
    }

    AXOLOTL_INIT(result, ec_key_pair_destroy);
    result->public_key = public_key;
    AXOLOTL_REF(public_key);
    result->private_key = private_key;
    AXOLOTL_REF(private_key);

    *key_pair = result;

    return 0;
}

ec_public_key *ec_key_pair_get_public(const ec_key_pair *key_pair)
{
    return key_pair->public_key;
}

ec_private_key *ec_key_pair_get_private(const ec_key_pair *key_pair)
{
    return key_pair->private_key;
}

void ec_key_pair_destroy(axolotl_type_base *type)
{
    ec_key_pair *key_pair = (ec_key_pair *)type;
    AXOLOTL_UNREF(key_pair->public_key);
    AXOLOTL_UNREF(key_pair->private_key);
    free(key_pair);
}

int curve_generate_private_key(axolotl_context *context, ec_private_key **private_key)
{
    int result = 0;
    ec_private_key *key = 0;

    assert(context);

    key = malloc(sizeof(ec_private_key));
    if(!key) {
        result = AX_ERR_NOMEM;
        goto complete;
    }

    AXOLOTL_INIT(key, ec_private_key_destroy);

    result = axolotl_crypto_random(context, key->data, DJB_KEY_LEN);
    if(result < 0) {
        goto complete;
    }

    key->data[0] &= 248;
    key->data[31] &= 127;
    key->data[31] |= 64;

    *private_key = key;

complete:
    return result;
}

int curve_generate_public_key(ec_public_key **public_key, const ec_private_key *private_key)
{
    static const uint8_t basepoint[32] = {9};
    int result = 0;

    ec_public_key *key = malloc(sizeof(ec_public_key));
    if(!key) {
        return AX_ERR_NOMEM;
    }

    AXOLOTL_INIT(key, ec_public_key_destroy);

    result = curve25519_donna(key->data, private_key->data, basepoint);

    if(result == 0) {
        *public_key = key;
        return 0;
    }
    else {
        if(key) {
            AXOLOTL_UNREF(key);
        }
        return AX_ERR_UNKNOWN;
    }
}

int curve_generate_key_pair(axolotl_context *context, ec_key_pair **key_pair)
{
    int result = 0;
    ec_key_pair *pair_result = 0;
    ec_private_key *key_private = 0;
    ec_public_key *key_public = 0;

    assert(context);

    result = curve_generate_private_key(context, &key_private);
    if(result < 0) {
        goto complete;
    }

    result = curve_generate_public_key(&key_public, key_private);
    if(result < 0) {
        goto complete;
    }

    result = ec_key_pair_create(&pair_result, key_public, key_private);
    if(result < 0) {
        goto complete;
    }

complete:
    if(key_public) {
        AXOLOTL_UNREF(key_public);
    }
    if(key_private) {
        AXOLOTL_UNREF(key_private);
    }

    if(result < 0) {
        if(pair_result) {
            AXOLOTL_UNREF(pair_result);
        }
    }
    else {
        *key_pair = pair_result;
    }

    return result;
}

int curve_calculate_agreement(uint8_t **shared_key_data, const ec_public_key *public_key, const ec_private_key *private_key)
{
    uint8_t *key = 0;
    int result = 0;

    if(!public_key || !private_key) {
        return AX_ERR_INVALID_KEY;
    }

    key = malloc(DJB_KEY_LEN);
    if(!key) {
        return AX_ERR_NOMEM;
    }

    result = curve25519_donna(key, private_key->data, public_key->data);

    if(result == 0) {
        *shared_key_data = key;
        return DJB_KEY_LEN;
    }
    else {
        if(key) {
            free(key);
        }
        return AX_ERR_UNKNOWN;
    }
}

int curve_verify_signature(const ec_public_key *signing_key,
        const uint8_t *message_data, size_t message_len,
        const uint8_t *signature_data, size_t signature_len)
{
    if(signature_len != 64) {
        return AX_ERR_INVAL;
    }

    return curve25519_verify(signature_data, signing_key->data, message_data, message_len) == 0;
}

int curve_calculate_signature(axolotl_context *context,
        axolotl_buffer **signature,
        const ec_private_key *signing_key,
        const uint8_t *message_data, size_t message_len)
{
    int result = 0;
    uint8_t random_data[CURVE_SIGNATURE_LEN];
    axolotl_buffer *buffer = 0;

    result = axolotl_crypto_random(context, random_data, sizeof(random_data));
    if(result < 0) {
        goto complete;
    }

    buffer = axolotl_buffer_alloc(CURVE_SIGNATURE_LEN);
    if(!buffer) {
        result = AX_ERR_NOMEM;
        goto complete;
    }

    result = curve25519_sign(axolotl_buffer_data(buffer), signing_key->data, message_data, message_len, random_data);

complete:
    if(result < 0) {
        if(buffer) {
            axolotl_buffer_free(buffer);
        }
    }
    else {
        *signature = buffer;
    }
    return result;
}
