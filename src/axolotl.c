#include "axolotl.h"
#include "axolotl_internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdarg.h>
#include <assert.h>
#include "utlist.h"
#include "utarray.h"

#ifdef _WINDOWS
#include "Windows.h"
#include "WinBase.h"
#endif

#ifdef DEBUG_REFCOUNT
int type_ref_count = 0;
int type_unref_count = 0;
#endif

struct axolotl_store_context {
    axolotl_context *global_context;
    axolotl_session_store session_store;
    axolotl_pre_key_store pre_key_store;
    axolotl_signed_pre_key_store signed_pre_key_store;
    axolotl_identity_key_store identity_key_store;
    axolotl_sender_key_store sender_key_store;
};

void axolotl_type_init(axolotl_type_base *instance,
        void (*destroy_func)(axolotl_type_base *instance))
{
    instance->ref_count = 1;
    instance->destroy = destroy_func;
#ifdef DEBUG_REFCOUNT
    type_ref_count++;
#endif
}

void axolotl_type_ref(axolotl_type_base *instance)
{
#ifdef DEBUG_REFCOUNT
    type_ref_count++;
#endif
    assert(instance);
    assert(instance->ref_count > 0);
    instance->ref_count++;
}

void axolotl_type_unref(axolotl_type_base *instance)
{
    if(instance) {
#ifdef DEBUG_REFCOUNT
    type_unref_count++;
#endif
        assert(instance->ref_count > 0);
        if(instance->ref_count > 1) {
            instance->ref_count--;
        }
        else {
            instance->destroy(instance);
        }
    }
}

#ifdef DEBUG_REFCOUNT
int axolotl_type_ref_count(axolotl_type_base *instance)
{
    return instance->ref_count;
}
#endif

/*------------------------------------------------------------------------*/

axolotl_buffer *axolotl_buffer_alloc(size_t len)
{
    axolotl_buffer *buffer;
    if(len > (SIZE_MAX - sizeof(struct axolotl_buffer)) / sizeof(uint8_t)) {
        return 0;
    }

    buffer = malloc(sizeof(struct axolotl_buffer) + (sizeof(uint8_t) * len));
    if(buffer) {
        buffer->len = len;
    }
    return buffer;
}

axolotl_buffer *axolotl_buffer_create(const uint8_t *data, size_t len)
{
    axolotl_buffer *buffer = axolotl_buffer_alloc(len);
    if(!buffer) {
        return 0;
    }

    memcpy(buffer->data, data, len);
    return buffer;
}

axolotl_buffer *axolotl_buffer_copy(const axolotl_buffer *buffer)
{
    return axolotl_buffer_create(buffer->data, buffer->len);
}

axolotl_buffer *axolotl_buffer_append(axolotl_buffer *buffer, const uint8_t *data, size_t len)
{
    size_t previous_size = buffer->len;
    size_t previous_alloc = sizeof(struct axolotl_buffer) + (sizeof(uint8_t) * previous_size);
    axolotl_buffer *tmp_buffer = realloc(buffer, previous_alloc + (sizeof(uint8_t) * len));
    if(!tmp_buffer) {
        return 0;
    }

    memcpy(tmp_buffer->data + previous_size, data, len);
    tmp_buffer->len = previous_size + len;
    return tmp_buffer;
}

uint8_t *axolotl_buffer_data(axolotl_buffer *buffer)
{
    return buffer->data;
}

size_t axolotl_buffer_len(axolotl_buffer *buffer)
{
    return buffer->len;
}

int axolotl_buffer_compare(axolotl_buffer *buffer1, axolotl_buffer *buffer2)
{
    if(buffer1 == buffer2) {
        return 0;
    }
    else if(buffer1 == 0 && buffer2 != 0) {
        return -1;
    }
    else if(buffer1 != 0 && buffer2 == 0) {
        return 1;
    }
    else {
        if(buffer1->len < buffer2->len) {
            return -1;
        }
        else if(buffer1->len > buffer2->len) {
            return 1;
        }
        else {
            return axolotl_constant_memcmp(buffer1->data, buffer2->data, buffer1->len);
        }
    }
}

void axolotl_buffer_free(axolotl_buffer *buffer)
{
    if(buffer) {
        free(buffer);
    }
}

void axolotl_buffer_bzero_free(axolotl_buffer *buffer)
{
    if(buffer) {
        axolotl_explicit_bzero(buffer->data, buffer->len);
        free(buffer);
    }
}

/*------------------------------------------------------------------------*/

typedef struct axolotl_buffer_list_node
{
    axolotl_buffer *buffer;
    struct axolotl_buffer_list_node *next;
} axolotl_buffer_list_node;

struct axolotl_buffer_list
{
    int size;
    axolotl_buffer_list_node *head;
};

struct axolotl_int_list
{
    UT_array *values;
};

axolotl_buffer_list *axolotl_buffer_list_alloc()
{
    axolotl_buffer_list *list = malloc(sizeof(axolotl_buffer_list));
    if(list) {
        memset(list, 0, sizeof(axolotl_buffer_list));
    }
    return list;
}

int axolotl_buffer_list_push(axolotl_buffer_list *list, axolotl_buffer *buffer)
{
    axolotl_buffer_list_node *node = 0;

    assert(list);
    assert(buffer);

    node = malloc(sizeof(axolotl_buffer_list_node));

    if(!node) {
        return AX_ERR_NOMEM;
    }

    node->buffer = buffer;
    LL_PREPEND(list->head, node);
    list->size++;
    return 0;
}

int axolotl_buffer_list_size(axolotl_buffer_list *list)
{
    assert(list);
    return list->size;
}

void axolotl_buffer_list_free(axolotl_buffer_list *list)
{
    axolotl_buffer_list_node *cur_node;
    axolotl_buffer_list_node *tmp_node;

    assert(list);

    LL_FOREACH_SAFE(list->head, cur_node, tmp_node) {
        LL_DELETE(list->head, cur_node);
        if(cur_node->buffer) {
            axolotl_buffer_free(cur_node->buffer);
        }
        free(cur_node);
    }
    free(list);
}
axolotl_int_list *axolotl_int_list_alloc();

/*------------------------------------------------------------------------*/

axolotl_int_list *axolotl_int_list_alloc()
{
    axolotl_int_list *list = malloc(sizeof(axolotl_int_list));
    if(!list) {
        return 0;
    }
    memset(list, 0, sizeof(axolotl_int_list));
    utarray_new(list->values, &ut_int_icd);
    return list;
}

void axolotl_int_list_push_back(axolotl_int_list *list, int value)
{
    assert(list);
    utarray_push_back(list->values, &value);
}

unsigned int axolotl_int_list_size(axolotl_int_list *list)
{
    assert(list);
    return utarray_len(list->values);
}

int axolotl_int_list_at(axolotl_int_list *list, unsigned int index)
{
    int *value = 0;

    assert(list);
    assert(index >= 0 && index < utarray_len(list->values));

    value = (int *)utarray_eltptr(list->values, index);

    assert(value);

    return *value;
}

void axolotl_int_list_free(axolotl_int_list *list)
{
    if(list) {
        utarray_free(list->values);
        free(list);
    }
}

/*------------------------------------------------------------------------*/

int axolotl_context_create(axolotl_context **context, void *user_data)
{
    *context = malloc(sizeof(axolotl_context));
    if(!(*context)) {
        return AX_ERR_NOMEM;
    }
    memset(*context, 0, sizeof(axolotl_context));
    (*context)->user_data = user_data;
#ifdef DEBUG_REFCOUNT
    type_ref_count = 0;
    type_unref_count = 0;
#endif
    return 0;
}

int axolotl_context_set_crypto_provider(axolotl_context *context, const axolotl_crypto_provider *crypto_provider)
{
    assert(context);
    if(!crypto_provider
            || !crypto_provider->hmac_sha256_init_func
            || !crypto_provider->hmac_sha256_update_func
            || !crypto_provider->hmac_sha256_final_func
            || !crypto_provider->hmac_sha256_cleanup_func) {
        return AX_ERR_INVAL;
    }
    memcpy(&(context->crypto_provider), crypto_provider, sizeof(axolotl_crypto_provider));
    return 0;
}

int axolotl_context_set_locking_functions(axolotl_context *context,
        void (*lock)(void *user_data), void (*unlock)(void *user_data))
{
    assert(context);
    if((lock && !unlock) || (!lock && unlock)) {
        return AX_ERR_INVAL;
    }

    context->lock = lock;
    context->unlock = unlock;
    return 0;
}

int axolotl_context_set_log_function(axolotl_context *context,
        void (*log)(int level, const char *message, size_t len, void *user_data))
{
    assert(context);
    context->log = log;
    return 0;
}

void axolotl_context_destroy(axolotl_context *context)
{
#ifdef DEBUG_REFCOUNT
    fprintf(stderr, "Global REF count: %d\n", type_ref_count);
    fprintf(stderr, "Global UNREF count: %d\n", type_unref_count);
#endif
    if(context) {
        free(context);
    }
}

/*------------------------------------------------------------------------*/

int axolotl_crypto_random(axolotl_context *context, uint8_t *data, size_t len)
{
    assert(context);
    assert(context->crypto_provider.random_func);
    return context->crypto_provider.random_func(data, len, context->crypto_provider.user_data);
}

int axolotl_hmac_sha256_init(axolotl_context *context, void **hmac_context, const uint8_t *key, size_t key_len)
{
    assert(context);
    assert(context->crypto_provider.hmac_sha256_init_func);
    return context->crypto_provider.hmac_sha256_init_func(hmac_context, key, key_len, context->crypto_provider.user_data);
}

int axolotl_hmac_sha256_update(axolotl_context *context, void *hmac_context, const uint8_t *data, size_t data_len)
{
    assert(context);
    assert(context->crypto_provider.hmac_sha256_update_func);
    return context->crypto_provider.hmac_sha256_update_func(hmac_context, data, data_len, context->crypto_provider.user_data);
}

int axolotl_hmac_sha256_final(axolotl_context *context, void *hmac_context, axolotl_buffer **output)
{
    assert(context);
    assert(context->crypto_provider.hmac_sha256_final_func);
    return context->crypto_provider.hmac_sha256_final_func(hmac_context, output, context->crypto_provider.user_data);
}

void axolotl_hmac_sha256_cleanup(axolotl_context *context, void *hmac_context)
{
    assert(context);
    assert(context->crypto_provider.hmac_sha256_cleanup_func);
    context->crypto_provider.hmac_sha256_cleanup_func(hmac_context, context->crypto_provider.user_data);
}

int axolotl_sha512_digest(axolotl_context *context, axolotl_buffer **output, const uint8_t *data, size_t data_len)
{
    assert(context);
    assert(context->crypto_provider.sha512_digest_func);
    return context->crypto_provider.sha512_digest_func(output, data, data_len, context->crypto_provider.user_data);
}

int axolotl_encrypt(axolotl_context *context,
        axolotl_buffer **output,
        int cipher,
        const uint8_t *key, size_t key_len,
        const uint8_t *iv, size_t iv_len,
        const uint8_t *plaintext, size_t plaintext_len)
{
    assert(context);
    assert(context->crypto_provider.encrypt_func);
    return context->crypto_provider.encrypt_func(
            output, cipher, key, key_len, iv, iv_len,
            plaintext, plaintext_len,
            context->crypto_provider.user_data);
}

int axolotl_decrypt(axolotl_context *context,
        axolotl_buffer **output,
        int cipher,
        const uint8_t *key, size_t key_len,
        const uint8_t *iv, size_t iv_len,
        const uint8_t *ciphertext, size_t ciphertext_len)
{
    assert(context);
    assert(context->crypto_provider.decrypt_func);
    return context->crypto_provider.decrypt_func(
            output, cipher, key, key_len, iv, iv_len,
            ciphertext, ciphertext_len,
            context->crypto_provider.user_data);
}

void axolotl_lock(axolotl_context *context)
{
    if(context->lock) {
        context->lock(context->user_data);
    }
}

void axolotl_unlock(axolotl_context *context)
{
    if(context->unlock) {
        context->unlock(context->user_data);
    }
}

void axolotl_log(axolotl_context *context, int level, const char *format, ...)
{
    char buf[256];
    int n;
    if(context->log) {
        va_list args;
        va_start(args, format);
        n = vsnprintf(buf, sizeof(buf), format, args);
        va_end(args);
        if(n > 0) {
            context->log(level, buf, strlen(buf), context->user_data);
        }
    }
}

void axolotl_explicit_bzero(void *v, size_t n)
{
#ifdef HAVE_SECUREZEROMEMORY
    SecureZeroMemory(v, n);
#elif HAVE_MEMSET_S
    memset_s(v, n, 0, n);
#else
    volatile unsigned char  *p  =  v;
    while(n--) *p++ = 0;
#endif
}

int axolotl_constant_memcmp(const void *s1, const void *s2, size_t n)
{
    size_t i;
    const unsigned char *c1 = (const unsigned char *) s1;
    const unsigned char *c2 = (const unsigned char *) s2;
    unsigned char result = 0;

    for (i = 0; i < n; i++) {
        result |= c1[i] ^ c2[i];
    }

    return result;
}

void axolotl_str_serialize_protobuf(ProtobufCBinaryData *buffer, const char *str)
{
    assert(buffer);
    assert(str);
    buffer->data = (uint8_t *)str;
    buffer->len = strlen(str);
}

char *axolotl_str_deserialize_protobuf(ProtobufCBinaryData *buffer)
{
    char *str = 0;
    assert(buffer);

    str = malloc(buffer->len + 1);
    if(!str) {
        return 0;
    }

    memcpy(str, buffer->data, buffer->len);
    str[buffer->len] = '\0';

    return str;
}

/*------------------------------------------------------------------------*/

int axolotl_store_context_create(axolotl_store_context **context, axolotl_context *global_context)
{
    assert(global_context);
    *context = malloc(sizeof(axolotl_store_context));
    if(!(*context)) {
        return AX_ERR_NOMEM;
    }
    memset(*context, 0, sizeof(axolotl_store_context));
    (*context)->global_context = global_context;
    return 0;
}

int axolotl_store_context_set_session_store(axolotl_store_context *context, const axolotl_session_store *store)
{
    if(!store) {
        return AX_ERR_INVAL;
    }
    memcpy(&(context->session_store), store, sizeof(axolotl_session_store));
    return 0;
}

int axolotl_store_context_set_pre_key_store(axolotl_store_context *context, const axolotl_pre_key_store *store)
{
    if(!store) {
        return AX_ERR_INVAL;
    }
    memcpy(&(context->pre_key_store), store, sizeof(axolotl_pre_key_store));
    return 0;
}

int axolotl_store_context_set_signed_pre_key_store(axolotl_store_context *context, const axolotl_signed_pre_key_store *store)
{
    if(!store) {
        return AX_ERR_INVAL;
    }
    memcpy(&(context->signed_pre_key_store), store, sizeof(axolotl_signed_pre_key_store));
    return 0;
}

int axolotl_store_context_set_identity_key_store(axolotl_store_context *context, const axolotl_identity_key_store *store)
{
    if(!store) {
        return AX_ERR_INVAL;
    }
    memcpy(&(context->identity_key_store), store, sizeof(axolotl_identity_key_store));
    return 0;
}

int axolotl_store_context_set_sender_key_store(axolotl_store_context *context, const axolotl_sender_key_store *store)
{
    if(!store) {
        return AX_ERR_INVAL;
    }
    memcpy(&(context->sender_key_store), store, sizeof(axolotl_sender_key_store));
    return 0;
}

void axolotl_store_context_destroy(axolotl_store_context *context)
{
    if(context) {
        if(context->session_store.destroy_func) {
            context->session_store.destroy_func(context->session_store.user_data);
        }
        if(context->pre_key_store.destroy_func) {
            context->pre_key_store.destroy_func(context->pre_key_store.user_data);
        }
        if(context->signed_pre_key_store.destroy_func) {
            context->signed_pre_key_store.destroy_func(context->signed_pre_key_store.user_data);
        }
        if(context->identity_key_store.destroy_func) {
            context->identity_key_store.destroy_func(context->identity_key_store.user_data);
        }
        if(context->sender_key_store.destroy_func) {
            context->sender_key_store.destroy_func(context->sender_key_store.user_data);
        }
        free(context);
    }
}

/*------------------------------------------------------------------------*/

int axolotl_session_load_session(axolotl_store_context *context, session_record **record, const axolotl_address *address)
{
    int result = 0;
    axolotl_buffer *buffer = 0;
    session_record *result_record = 0;

    assert(context);
    assert(context->session_store.load_session_func);

    result = context->session_store.load_session_func(
            &buffer, address,
            context->session_store.user_data);
    if(result < 0) {
        goto complete;
    }

    if(result == 0) {
        if(buffer) {
            result = AX_ERR_UNKNOWN;
            goto complete;
        }
        result = session_record_create(&result_record, 0, context->global_context);
    }
    else if(result == 1) {
        if(!buffer) {
            result = -1;
            goto complete;
        }
        result = session_record_deserialize(&result_record,
                axolotl_buffer_data(buffer), axolotl_buffer_len(buffer), context->global_context);
    }
    else {
        result = AX_ERR_UNKNOWN;
    }

complete:
    if(buffer) {
        axolotl_buffer_free(buffer);
    }
    if(result >= 0) {
        *record = result_record;
    }
    return result;
}

int axolotl_session_get_sub_device_sessions(axolotl_store_context *context, axolotl_int_list **sessions, const char *name, size_t name_len)
{
    assert(context);
    assert(context->session_store.get_sub_device_sessions_func);

    return context->session_store.get_sub_device_sessions_func(
            sessions, name, name_len,
            context->session_store.user_data);
}

int axolotl_session_store_session(axolotl_store_context *context, const axolotl_address *address, session_record *record)
{
    int result = 0;
    axolotl_buffer *buffer = 0;

    assert(context);
    assert(context->session_store.store_session_func);
    assert(record);

    result = session_record_serialize(&buffer, record);
    if(result < 0) {
        goto complete;
    }

    result = context->session_store.store_session_func(
            address,
            axolotl_buffer_data(buffer), axolotl_buffer_len(buffer),
            context->session_store.user_data);

complete:
    if(buffer) {
        axolotl_buffer_free(buffer);
    }

    return result;
}

int axolotl_session_contains_session(axolotl_store_context *context, const axolotl_address *address)
{
    assert(context);
    assert(context->session_store.contains_session_func);

    return context->session_store.contains_session_func(
            address,
            context->session_store.user_data);
}

int axolotl_session_delete_session(axolotl_store_context *context, const axolotl_address *address)
{
    assert(context);
    assert(context->session_store.delete_session_func);

    return context->session_store.delete_session_func(
            address,
            context->session_store.user_data);
}

int axolotl_session_delete_all_sessions(axolotl_store_context *context, const char *name, size_t name_len)
{
    assert(context);
    assert(context->session_store.delete_all_sessions_func);

    return context->session_store.delete_all_sessions_func(
            name, name_len,
            context->session_store.user_data);
}

/*------------------------------------------------------------------------*/

int axolotl_pre_key_load_key(axolotl_store_context *context, session_pre_key **pre_key, uint32_t pre_key_id)
{
    int result = 0;
    axolotl_buffer *buffer = 0;
    session_pre_key *result_key = 0;

    assert(context);
    assert(context->pre_key_store.load_pre_key);

    result = context->pre_key_store.load_pre_key(
            &buffer, pre_key_id,
            context->pre_key_store.user_data);
    if(result < 0) {
        goto complete;
    }

    result = session_pre_key_deserialize(&result_key,
            axolotl_buffer_data(buffer), axolotl_buffer_len(buffer), context->global_context);

complete:
    if(buffer) {
        axolotl_buffer_free(buffer);
    }
    if(result >= 0) {
        *pre_key = result_key;
    }
    return result;
}

int axolotl_pre_key_store_key(axolotl_store_context *context, session_pre_key *pre_key)
{
    int result = 0;
    axolotl_buffer *buffer = 0;
    uint32_t id = 0;

    assert(context);
    assert(context->pre_key_store.store_pre_key);
    assert(pre_key);

    id = session_pre_key_get_id(pre_key);

    result = session_pre_key_serialize(&buffer, pre_key);
    if(result < 0) {
        goto complete;
    }

    result = context->pre_key_store.store_pre_key(
            id,
            axolotl_buffer_data(buffer), axolotl_buffer_len(buffer),
            context->pre_key_store.user_data);

complete:
    if(buffer) {
        axolotl_buffer_free(buffer);
    }

    return result;
}

int axolotl_pre_key_contains_key(axolotl_store_context *context, uint32_t pre_key_id)
{
    int result = 0;

    assert(context);
    assert(context->pre_key_store.contains_pre_key);

    result = context->pre_key_store.contains_pre_key(
            pre_key_id, context->pre_key_store.user_data);

    return result;
}

int axolotl_pre_key_remove_key(axolotl_store_context *context, uint32_t pre_key_id)
{
    int result = 0;

    assert(context);
    assert(context->pre_key_store.remove_pre_key);

    result = context->pre_key_store.remove_pre_key(
            pre_key_id, context->pre_key_store.user_data);

    return result;
}

/*------------------------------------------------------------------------*/

int axolotl_signed_pre_key_load_key(axolotl_store_context *context, session_signed_pre_key **pre_key, uint32_t signed_pre_key_id)
{
    int result = 0;
    axolotl_buffer *buffer = 0;
    session_signed_pre_key *result_key = 0;

    assert(context);
    assert(context->signed_pre_key_store.load_signed_pre_key);

    result = context->signed_pre_key_store.load_signed_pre_key(
            &buffer, signed_pre_key_id,
            context->signed_pre_key_store.user_data);
    if(result < 0) {
        goto complete;
    }

    result = session_signed_pre_key_deserialize(&result_key,
            axolotl_buffer_data(buffer), axolotl_buffer_len(buffer), context->global_context);

complete:
    if(buffer) {
        axolotl_buffer_free(buffer);
    }
    if(result >= 0) {
        *pre_key = result_key;
    }
    return result;
}

int axolotl_signed_pre_key_store_key(axolotl_store_context *context, session_signed_pre_key *pre_key)
{
    int result = 0;
    axolotl_buffer *buffer = 0;
    uint32_t id = 0;

    assert(context);
    assert(context->signed_pre_key_store.store_signed_pre_key);
    assert(pre_key);

    id = session_signed_pre_key_get_id(pre_key);

    result = session_signed_pre_key_serialize(&buffer, pre_key);
    if(result < 0) {
        goto complete;
    }

    result = context->signed_pre_key_store.store_signed_pre_key(
            id,
            axolotl_buffer_data(buffer), axolotl_buffer_len(buffer),
            context->signed_pre_key_store.user_data);

complete:
    if(buffer) {
        axolotl_buffer_free(buffer);
    }

    return result;
}

int axolotl_signed_pre_key_contains_key(axolotl_store_context *context, uint32_t signed_pre_key_id)
{
    int result = 0;

    assert(context);
    assert(context->signed_pre_key_store.contains_signed_pre_key);

    result = context->signed_pre_key_store.contains_signed_pre_key(
            signed_pre_key_id, context->signed_pre_key_store.user_data);

    return result;
}

int axolotl_signed_pre_key_remove_key(axolotl_store_context *context, uint32_t signed_pre_key_id)
{
    int result = 0;

    assert(context);
    assert(context->signed_pre_key_store.remove_signed_pre_key);

    result = context->signed_pre_key_store.remove_signed_pre_key(
            signed_pre_key_id, context->signed_pre_key_store.user_data);

    return result;
}

/*------------------------------------------------------------------------*/

int axolotl_identity_get_key_pair(axolotl_store_context *context, ratchet_identity_key_pair **key_pair)
{
    int result = 0;
    axolotl_buffer *public_buf = 0;
    axolotl_buffer *private_buf = 0;
    ec_public_key *public_key = 0;
    ec_private_key *private_key = 0;
    ratchet_identity_key_pair *result_key = 0;

    assert(context);
    assert(context->identity_key_store.get_identity_key_pair);

    result = context->identity_key_store.get_identity_key_pair(
            &public_buf, &private_buf,
            context->identity_key_store.user_data);
    if(result < 0) {
        goto complete;
    }

    result = curve_decode_point(&public_key, public_buf->data, public_buf->len, context->global_context);
    if(result < 0) {
        goto complete;
    }

    result = curve_decode_private_point(&private_key, private_buf->data, private_buf->len, context->global_context);
    if(result < 0) {
        goto complete;
    }

    result = ratchet_identity_key_pair_create(&result_key, public_key, private_key);
    if(result < 0) {
        goto complete;
    }

complete:
    if(public_buf) {
        axolotl_buffer_free(public_buf);
    }
    if(private_buf) {
        axolotl_buffer_free(private_buf);
    }
    if(public_key) {
        AXOLOTL_UNREF(public_key);
    }
    if(private_key) {
        AXOLOTL_UNREF(private_key);
    }
    if(result >= 0) {
        *key_pair = result_key;
    }
    return result;
}

int axolotl_identity_get_local_registration_id(axolotl_store_context *context, uint32_t *registration_id)
{
    int result = 0;

    assert(context);
    assert(context->identity_key_store.get_local_registration_id);

    result = context->identity_key_store.get_local_registration_id(
            context->identity_key_store.user_data, registration_id);

    return result;
}

int axolotl_identity_save_identity(axolotl_store_context *context, const char *name, size_t name_len, ec_public_key *identity_key)
{
    int result = 0;
    axolotl_buffer *buffer = 0;

    assert(context);
    assert(context->identity_key_store.save_identity);

    if(identity_key) {
        result = ec_public_key_serialize(&buffer, identity_key);
        if(result < 0) {
            goto complete;
        }

        result = context->identity_key_store.save_identity(
                name, name_len,
                axolotl_buffer_data(buffer),
                axolotl_buffer_len(buffer),
                context->identity_key_store.user_data);
    }
    else {
        result = context->identity_key_store.save_identity(
                name, name_len, 0, 0,
                context->identity_key_store.user_data);
    }

complete:
    if(buffer) {
        axolotl_buffer_free(buffer);
    }

    return result;
}

int axolotl_identity_is_trusted_identity(axolotl_store_context *context, const char *name, size_t name_len, ec_public_key *identity_key)
{
    int result = 0;
    axolotl_buffer *buffer = 0;

    assert(context);
    assert(context->identity_key_store.is_trusted_identity);

    result = ec_public_key_serialize(&buffer, identity_key);
    if(result < 0) {
        goto complete;
    }

    result = context->identity_key_store.is_trusted_identity(
            name, name_len,
            axolotl_buffer_data(buffer),
            axolotl_buffer_len(buffer),
            context->identity_key_store.user_data);
complete:
    if(buffer) {
        axolotl_buffer_free(buffer);
    }

    return result;
}

int axolotl_sender_key_store_key(axolotl_store_context *context, const axolotl_sender_key_name *sender_key_name, sender_key_record *record)
{
    int result = 0;
    axolotl_buffer *buffer = 0;

    assert(context);
    assert(context->sender_key_store.store_sender_key);
    assert(record);

    result = sender_key_record_serialize(&buffer, record);
    if(result < 0) {
        goto complete;
    }

    result = context->sender_key_store.store_sender_key(
            sender_key_name,
            axolotl_buffer_data(buffer), axolotl_buffer_len(buffer),
            context->sender_key_store.user_data);

complete:
    if(buffer) {
        axolotl_buffer_free(buffer);
    }

    return result;
}

int axolotl_sender_key_load_key(axolotl_store_context *context, sender_key_record **record, const axolotl_sender_key_name *sender_key_name)
{
    int result = 0;
    axolotl_buffer *buffer = 0;
    sender_key_record *result_record = 0;

    assert(context);
    assert(context->sender_key_store.load_sender_key);

    result = context->sender_key_store.load_sender_key(
            &buffer, sender_key_name,
            context->sender_key_store.user_data);
    if(result < 0) {
        goto complete;
    }

    if(result == 0) {
        if(buffer) {
            result = AX_ERR_UNKNOWN;
            goto complete;
        }
        result = sender_key_record_create(&result_record, context->global_context);
    }
    else if(result == 1) {
        if(!buffer) {
            result = -1;
            goto complete;
        }
        result = sender_key_record_deserialize(&result_record,
                axolotl_buffer_data(buffer), axolotl_buffer_len(buffer), context->global_context);
    }
    else {
        result = AX_ERR_UNKNOWN;
    }

complete:
    if(buffer) {
        axolotl_buffer_free(buffer);
    }
    if(result >= 0) {
        *record = result_record;
    }
    return result;
}
