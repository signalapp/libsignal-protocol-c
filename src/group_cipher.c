#include "group_cipher.h"

#include <assert.h>
#include <string.h>
#include "axolotl_internal.h"
#include "protocol.h"
#include "sender_key.h"
#include "sender_key_record.h"
#include "sender_key_state.h"

struct group_cipher
{
    axolotl_store_context *store;
    const axolotl_sender_key_name *sender_key_id;
    axolotl_context *global_context;
    int (*decrypt_callback)(group_cipher *cipher, axolotl_buffer *plaintext, void *decrypt_context);
    int inside_callback;
    void *user_data;
};

static int group_cipher_get_sender_key(group_cipher *cipher, sender_message_key **sender_key, sender_key_state *state, uint32_t iteration);
static int group_cipher_decrypt_callback(group_cipher *cipher, axolotl_buffer *plaintext, void *decrypt_context);

int group_cipher_create(group_cipher **cipher,
        axolotl_store_context *store, const axolotl_sender_key_name *sender_key_id,
        axolotl_context *global_context)
{
    group_cipher *result_cipher;

    assert(store);
    assert(global_context);

    result_cipher = malloc(sizeof(group_cipher));
    if(!result_cipher) {
        return AX_ERR_NOMEM;
    }
    memset(result_cipher, 0, sizeof(group_cipher));

    result_cipher->store = store;
    result_cipher->sender_key_id = sender_key_id;
    result_cipher->global_context = global_context;

    *cipher = result_cipher;
    return 0;
}

void group_cipher_set_user_data(group_cipher *cipher, void *user_data)
{
    assert(cipher);
    cipher->user_data = user_data;
}

void *group_cipher_get_user_data(group_cipher *cipher)
{
    assert(cipher);
    return cipher->user_data;
}

void group_cipher_set_decryption_callback(group_cipher *cipher,
        int (*callback)(group_cipher *cipher, axolotl_buffer *plaintext, void *decrypt_context))
{
    assert(cipher);
    cipher->decrypt_callback = callback;
}

int group_cipher_encrypt(group_cipher *cipher,
        const uint8_t *padded_plaintext, size_t padded_plaintext_len,
        ciphertext_message **encrypted_message)
{
    int result = 0;
    sender_key_message *result_message = 0;
    sender_key_record *record = 0;
    sender_key_state *state = 0;
    sender_message_key *sender_key = 0;
    sender_chain_key *next_chain_key = 0;
    axolotl_buffer *sender_cipher_key = 0;
    axolotl_buffer *sender_cipher_iv = 0;
    axolotl_buffer *ciphertext = 0;

    assert(cipher);
    axolotl_lock(cipher->global_context);

    if(cipher->inside_callback == 1) {
        result = AX_ERR_INVAL;
        goto complete;
    }

    result = axolotl_sender_key_load_key(cipher->store, &record, cipher->sender_key_id);
    if(result < 0) {
        goto complete;
    }

    result = sender_key_record_get_sender_key_state(record, &state);
    if(result < 0) {
        goto complete;
    }

    result = sender_chain_key_create_message_key(sender_key_state_get_chain_key(state), &sender_key);
    if(result < 0) {
        goto complete;
    }

    sender_cipher_key = sender_message_key_get_cipher_key(sender_key);
    sender_cipher_iv = sender_message_key_get_iv(sender_key);

    result = axolotl_encrypt(cipher->global_context, &ciphertext, AX_CIPHER_AES_CBC_PKCS5,
            axolotl_buffer_data(sender_cipher_key), axolotl_buffer_len(sender_cipher_key),
            axolotl_buffer_data(sender_cipher_iv), axolotl_buffer_len(sender_cipher_iv),
            padded_plaintext, padded_plaintext_len);
    if(result < 0) {
        goto complete;
    }

    result = sender_key_message_create(&result_message,
            sender_key_state_get_key_id(state),
            sender_message_key_get_iteration(sender_key),
            axolotl_buffer_data(ciphertext), axolotl_buffer_len(ciphertext),
            sender_key_state_get_signing_key_private(state),
            cipher->global_context);
    if(result < 0) {
        goto complete;
    }

    result = sender_chain_key_create_next(sender_key_state_get_chain_key(state), &next_chain_key);
    if(result < 0) {
        goto complete;
    }

    sender_key_state_set_chain_key(state, next_chain_key);

    result = axolotl_sender_key_store_key(cipher->store, cipher->sender_key_id, record);

complete:
    if(result >= 0) {
        *encrypted_message = (ciphertext_message *)result_message;
    }
    else {
        if(result == AX_ERR_INVALID_KEY_ID) {
            result = AX_ERR_NO_SESSION;
        }
        AXOLOTL_UNREF(result_message);
    }
    axolotl_buffer_free(ciphertext);
    AXOLOTL_UNREF(next_chain_key);
    AXOLOTL_UNREF(sender_key);
    AXOLOTL_UNREF(record);
    axolotl_unlock(cipher->global_context);
    return result;
}

int group_cipher_decrypt(group_cipher *cipher,
        sender_key_message *ciphertext, void *decrypt_context,
        axolotl_buffer **plaintext)
{
    int result = 0;
    axolotl_buffer *result_buf = 0;
    sender_key_record *record = 0;
    sender_key_state *state = 0;
    sender_message_key *sender_key = 0;
    axolotl_buffer *sender_cipher_key = 0;
    axolotl_buffer *sender_cipher_iv = 0;
    axolotl_buffer *ciphertext_body = 0;

    assert(cipher);
    axolotl_lock(cipher->global_context);

    if(cipher->inside_callback == 1) {
        result = AX_ERR_INVAL;
        goto complete;
    }

    result = axolotl_sender_key_load_key(cipher->store, &record, cipher->sender_key_id);
    if(result < 0) {
        goto complete;
    }

    if(sender_key_record_is_empty(record)) {
        result = AX_ERR_NO_SESSION;
        axolotl_log(cipher->global_context, AX_LOG_WARNING, "No sender key for: %s::%s::%d",
                cipher->sender_key_id->group_id,
                cipher->sender_key_id->sender.name,
                cipher->sender_key_id->sender.device_id);
        goto complete;
    }

    result = sender_key_record_get_sender_key_state_by_id(record, &state, sender_key_message_get_key_id(ciphertext));
    if(result < 0) {
        goto complete;
    }

    result = sender_key_message_verify_signature(ciphertext, sender_key_state_get_signing_key_public(state));
    if(result < 0) {
        goto complete;
    }

    result = group_cipher_get_sender_key(cipher, &sender_key, state, sender_key_message_get_iteration(ciphertext));
    if(result < 0) {
        goto complete;
    }

    sender_cipher_key = sender_message_key_get_cipher_key(sender_key);
    sender_cipher_iv = sender_message_key_get_iv(sender_key);
    ciphertext_body = sender_key_message_get_ciphertext(ciphertext);

    result = axolotl_decrypt(cipher->global_context, &result_buf, AX_CIPHER_AES_CBC_PKCS5,
            axolotl_buffer_data(sender_cipher_key), axolotl_buffer_len(sender_cipher_key),
            axolotl_buffer_data(sender_cipher_iv), axolotl_buffer_len(sender_cipher_iv),
            axolotl_buffer_data(ciphertext_body), axolotl_buffer_len(ciphertext_body));
    if(result < 0) {
        goto complete;
    }

    result = group_cipher_decrypt_callback(cipher, result_buf, decrypt_context);
    if(result < 0) {
        goto complete;
    }

    result = axolotl_sender_key_store_key(cipher->store, cipher->sender_key_id, record);

complete:
    AXOLOTL_UNREF(sender_key);
    AXOLOTL_UNREF(record);
    if(result >= 0) {
        *plaintext = result_buf;
    }
    else {
        if(result == AX_ERR_INVALID_KEY || result == AX_ERR_INVALID_KEY_ID) {
            result = AX_ERR_INVALID_MESSAGE;
        }
        axolotl_buffer_free(result_buf);
    }
    axolotl_unlock(cipher->global_context);
    return result;
}

int group_cipher_get_sender_key(group_cipher *cipher, sender_message_key **sender_key, sender_key_state *state, uint32_t iteration)
{
    int result = 0;
    sender_message_key *result_key = 0;
    sender_chain_key *chain_key = 0;
    sender_chain_key *next_chain_key = 0;
    sender_message_key *message_key = 0;

    chain_key = sender_key_state_get_chain_key(state);
    AXOLOTL_REF(chain_key);

    if(sender_chain_key_get_iteration(chain_key) > iteration) {
        if(sender_key_state_has_sender_message_key(state, iteration)) {
            result_key = sender_key_state_remove_sender_message_key(state, iteration);
            if(!result_key) {
                result = AX_ERR_UNKNOWN;
            }
            goto complete;
        }
        else {
            result = AX_ERR_DUPLICATE_MESSAGE;
            axolotl_log(cipher->global_context, AX_LOG_WARNING,
                    "Received message with old counter: %d, %d",
                    sender_chain_key_get_iteration(chain_key), iteration);
            goto complete;
        }
    }

    if(iteration - sender_chain_key_get_iteration(chain_key) > 2000) {
        result = AX_ERR_INVALID_MESSAGE;
        axolotl_log(cipher->global_context, AX_LOG_WARNING, "Over 2000 messages into the future!");
        goto complete;
    }

    while(sender_chain_key_get_iteration(chain_key) < iteration) {
        result = sender_chain_key_create_message_key(chain_key, &message_key);
        if(result < 0) {
            goto complete;
        }

        result = sender_key_state_add_sender_message_key(state, message_key);
        if(result < 0) {
            goto complete;
        }
        AXOLOTL_UNREF(message_key);

        result = sender_chain_key_create_next(chain_key, &next_chain_key);
        if(result < 0) {
            goto complete;
        }

        AXOLOTL_UNREF(chain_key);
        chain_key = next_chain_key;
        next_chain_key = 0;
    }

    result = sender_chain_key_create_next(chain_key, &next_chain_key);
    if(result < 0) {
        goto complete;
    }

    sender_key_state_set_chain_key(state, next_chain_key);
    result = sender_chain_key_create_message_key(chain_key, &result_key);

complete:
    AXOLOTL_UNREF(message_key);
    AXOLOTL_UNREF(chain_key);
    AXOLOTL_UNREF(next_chain_key);
    if(result >= 0) {
        *sender_key = result_key;
    }
    return result;
}

static int group_cipher_decrypt_callback(group_cipher *cipher, axolotl_buffer *plaintext, void *decrypt_context)
{
    int result = 0;
    if(cipher->decrypt_callback) {
        cipher->inside_callback = 1;
        result = cipher->decrypt_callback(cipher, plaintext, decrypt_context);
        cipher->inside_callback = 0;
    }
    return result;
}

void group_cipher_free(group_cipher *cipher)
{
    if(cipher) {
        free(cipher);
    }
}
