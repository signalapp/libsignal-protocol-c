#include "sender_key.h"

#include <assert.h>
#include <string.h>

#include "hkdf.h"
#include "axolotl_internal.h"

#define HASH_OUTPUT_SIZE 32

struct sender_message_key {
    axolotl_type_base base;
    uint32_t iteration;
    axolotl_buffer *iv;
    axolotl_buffer *cipher_key;
    axolotl_buffer *seed;
    axolotl_context *global_context;
};

struct sender_chain_key {
    axolotl_type_base base;
    uint32_t iteration;
    axolotl_buffer *chain_key;
    axolotl_context *global_context;
};

static int sender_chain_key_get_derivative(axolotl_buffer **derivative, uint8_t seed, axolotl_buffer *key,
        axolotl_context *global_context);

int sender_message_key_create(sender_message_key **key,
        uint32_t iteration, axolotl_buffer *seed,
        axolotl_context *global_context)
{
    sender_message_key *result = 0;
    int ret = 0;
    ssize_t ret_size = 0;
    hkdf_context *kdf = 0;
    static const char info_material[] = "WhisperGroup";
    uint8_t salt[HASH_OUTPUT_SIZE];
    uint8_t *derivative = 0;

    assert(global_context);

    if(!seed) {
        return AX_ERR_INVAL;
    }

    memset(salt, 0, sizeof(salt));

    result = malloc(sizeof(sender_message_key));
    if(!result) {
        return AX_ERR_NOMEM;
    }

    AXOLOTL_INIT(result, sender_message_key_destroy);

    ret = hkdf_create(&kdf, 3, global_context);
    if(ret < 0) {
        goto complete;
    }

    ret_size = hkdf_derive_secrets(kdf, &derivative,
            axolotl_buffer_data(seed), axolotl_buffer_len(seed),
            salt, sizeof(salt),
            (uint8_t *)info_material, sizeof(info_material) - 1, 48);
    if(ret_size != 48) {
        ret = (ret_size < 0) ? (int)ret_size : AX_ERR_UNKNOWN;
        axolotl_log(global_context, AX_LOG_WARNING, "hkdf_derive_secrets failed");
        goto complete;
    }

    result->iteration = iteration;

    result->seed = axolotl_buffer_copy(seed);
    if(!result->seed) {
        ret = AX_ERR_NOMEM;
        goto complete;
    }

    result->iv = axolotl_buffer_create(derivative, 16);
    if(!result->iv) {
        ret = AX_ERR_NOMEM;
        goto complete;
    }

    result->cipher_key = axolotl_buffer_create(derivative + 16, 32);
    if(!result->cipher_key) {
        ret = AX_ERR_NOMEM;
        goto complete;
    }

    result->global_context = global_context;

complete:
    AXOLOTL_UNREF(kdf);
    if(derivative) {
        free(derivative);
    }
    if(ret < 0) {
        AXOLOTL_UNREF(result);
    }
    else {
        ret = 0;
        *key = result;
    }
    return ret;
}

uint32_t sender_message_key_get_iteration(sender_message_key *key)
{
    assert(key);
    return key->iteration;
}

axolotl_buffer *sender_message_key_get_iv(sender_message_key *key)
{
    assert(key);
    return key->iv;
}

axolotl_buffer *sender_message_key_get_cipher_key(sender_message_key *key)
{
    assert(key);
    return key->cipher_key;
}

axolotl_buffer *sender_message_key_get_seed(sender_message_key *key)
{
    assert(key);
    return key->seed;
}

void sender_message_key_destroy(axolotl_type_base *type)
{
    sender_message_key *key = (sender_message_key *)type;
    axolotl_buffer_bzero_free(key->iv);
    axolotl_buffer_bzero_free(key->cipher_key);
    axolotl_buffer_bzero_free(key->seed);
    free(key);
}

int sender_chain_key_create(sender_chain_key **key,
        uint32_t iteration, axolotl_buffer *chain_key,
        axolotl_context *global_context)
{
    sender_chain_key *result = 0;
    int ret = 0;

    assert(global_context);

    if(!chain_key) {
        return AX_ERR_INVAL;
    }

    result = malloc(sizeof(sender_chain_key));
    if(!result) {
        return AX_ERR_NOMEM;
    }

    AXOLOTL_INIT(result, sender_chain_key_destroy);

    result->iteration = iteration;

    result->chain_key = axolotl_buffer_copy(chain_key);
    if(!result->chain_key) {
        ret = AX_ERR_NOMEM;
        goto complete;
    }

    result->global_context = global_context;

complete:
    if(ret < 0) {
        AXOLOTL_UNREF(result);
    }
    else {
        ret = 0;
        *key = result;
    }
    return ret;
}

uint32_t sender_chain_key_get_iteration(sender_chain_key *key)
{
    assert(key);
    return key->iteration;
}

int sender_chain_key_create_message_key(sender_chain_key *key, sender_message_key **message_key)
{
    static const uint8_t MESSAGE_KEY_SEED = 0x01;
    int ret = 0;
    axolotl_buffer *derivative = 0;
    sender_message_key *result = 0;

    assert(key);

    ret = sender_chain_key_get_derivative(&derivative, MESSAGE_KEY_SEED, key->chain_key, key->global_context);
    if(ret < 0) {
        goto complete;
    }

    ret = sender_message_key_create(&result, key->iteration, derivative, key->global_context);

complete:
    axolotl_buffer_free(derivative);
    if(ret >= 0) {
        ret = 0;
        *message_key = result;
    }
    return ret;
}

int sender_chain_key_create_next(sender_chain_key *key, sender_chain_key **next_key)
{
    static const uint8_t CHAIN_KEY_SEED = 0x02;
    int ret = 0;
    axolotl_buffer *derivative = 0;
    sender_chain_key *result = 0;

    assert(key);

    ret = sender_chain_key_get_derivative(&derivative, CHAIN_KEY_SEED, key->chain_key, key->global_context);
    if(ret < 0) {
        goto complete;
    }

    ret = sender_chain_key_create(&result, key->iteration + 1, derivative, key->global_context);

complete:
    axolotl_buffer_free(derivative);
    if(ret >= 0) {
        ret = 0;
        *next_key = result;
    }
    return ret;
}

axolotl_buffer *sender_chain_key_get_seed(sender_chain_key *key)
{
    assert(key);
    return key->chain_key;
}

void sender_chain_key_destroy(axolotl_type_base *type)
{
    sender_chain_key *key = (sender_chain_key *)type;
    axolotl_buffer_bzero_free(key->chain_key);
    free(key);
}

int sender_chain_key_get_derivative(axolotl_buffer **derivative, uint8_t seed, axolotl_buffer *key,
        axolotl_context *global_context)
{
    int result = 0;
    axolotl_buffer *output_buffer = 0;
    void *hmac_context = 0;

    result = axolotl_hmac_sha256_init(global_context, &hmac_context,
            axolotl_buffer_data(key), axolotl_buffer_len(key));
    if(result < 0) {
        goto complete;
    }

    result = axolotl_hmac_sha256_update(global_context, hmac_context, &seed, sizeof(seed));
    if(result < 0) {
        goto complete;
    }

    result = axolotl_hmac_sha256_final(global_context, hmac_context, &output_buffer);
    if(result < 0) {
        goto complete;
    }

complete:
    axolotl_hmac_sha256_cleanup(global_context, hmac_context);

    if(result < 0) {
        axolotl_buffer_free(output_buffer);
    }
    else {
        *derivative = output_buffer;
    }
    return result;
}
