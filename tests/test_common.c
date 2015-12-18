#include "test_common.h"

#include <stdlib.h>
#include <string.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <check.h>

#include "axolotl.h"
#include "curve.h"
#include "uthash.h"
#include "utarray.h"

/*
 * This is an implementation of Jenkin's "One-at-a-Time" hash.
 *
 * http://www.burtleburtle.net/bob/hash/doobs.html
 *
 * It is used to simplify using our new string recipient IDs
 * as part of our keys without having to significantly modify the
 * testing-only implementations of our data stores.
 */
int64_t jenkins_hash(const char *key, size_t len)
{
    uint64_t hash, i;
    for(hash = i = 0; i < len; ++i) {
        hash += key[i];
        hash += (hash << 10);
        hash ^= (hash >> 6);
    }
    hash += (hash << 3);
    hash ^= (hash >> 11);
    hash += (hash << 15);
    return hash;
}

void print_public_key(const char *prefix, ec_public_key *key)
{
    axolotl_buffer *buffer;
    ec_public_key_serialize(&buffer, key);

    fprintf(stderr, "%s ", prefix);
    uint8_t *data = axolotl_buffer_data(buffer);
    int len = axolotl_buffer_len(buffer);
    int i;
    for(i = 0; i < len; i++) {
        if(i > 0 && (i % 40) == 0) {
            fprintf(stderr, "\n");
        }
        fprintf(stderr, "%02X", data[i]);
    }
    fprintf(stderr, "\n");
    axolotl_buffer_free(buffer);
}

void print_buffer(const char *prefix, axolotl_buffer *buffer)
{
    fprintf(stderr, "%s ", prefix);
    uint8_t *data = axolotl_buffer_data(buffer);
    int len = axolotl_buffer_len(buffer);
    int i;
    for(i = 0; i < len; i++) {
        if(i > 0 && (i % 40) == 0) {
            fprintf(stderr, "\n");
        }
        fprintf(stderr, "%02X", data[i]);
    }
    fprintf(stderr, "\n");
}

void shuffle_buffers(axolotl_buffer **array, size_t n)
{
    if (n > 1) {
        size_t i;
        for (i = 0; i < n - 1; i++) {
            size_t j = i + rand() / (RAND_MAX / (n - i) + 1);
            axolotl_buffer *t = array[j];
            array[j] = array[i];
            array[i] = t;
        }
    }
}

ec_public_key *create_test_ec_public_key(axolotl_context *context)
{
    int result = 0;
    ec_key_pair *key_pair;
    result = curve_generate_key_pair(context, &key_pair);
    ck_assert_int_eq(result, 0);

    ec_public_key *public_key = ec_key_pair_get_public(key_pair);
    AXOLOTL_REF(public_key);
    AXOLOTL_UNREF(key_pair);
    return public_key;
}

ec_private_key *create_test_ec_private_key(axolotl_context *context)
{
    int result = 0;
    ec_key_pair *key_pair;
    result = curve_generate_key_pair(context, &key_pair);
    ck_assert_int_eq(result, 0);

    ec_private_key *private_key = ec_key_pair_get_private(key_pair);
    AXOLOTL_REF(private_key);
    AXOLOTL_UNREF(key_pair);
    return private_key;
}

void test_log(int level, const char *message, size_t len, void *user_data)
{
    switch(level) {
    case AX_LOG_ERROR:
        fprintf(stderr, "[ERROR] %s\n", message);
        break;
    case AX_LOG_WARNING:
        fprintf(stderr, "[WARNING] %s\n", message);
        break;
    case AX_LOG_NOTICE:
        fprintf(stderr, "[NOTICE] %s\n", message);
        break;
    case AX_LOG_INFO:
        fprintf(stderr, "[INFO] %s\n", message);
        break;
    case AX_LOG_DEBUG:
        fprintf(stderr, "[DEBUG] %s\n", message);
        break;
    default:
        fprintf(stderr, "[%d] %s\n", level, message);
        break;
    }
}

int test_random_generator(uint8_t *data, size_t len, void *user_data)
{
    if(RAND_bytes(data, len)) {
        return 0;
    }
    else {
        return AX_ERR_UNKNOWN;
    }
}

int test_hmac_sha256_init(void **hmac_context, const uint8_t *key, size_t key_len, void *user_data)
{
    HMAC_CTX *ctx = malloc(sizeof(HMAC_CTX));
    if(!ctx) {
        return AX_ERR_NOMEM;
    }
    HMAC_CTX_init(ctx);
    *hmac_context = ctx;

    if(HMAC_Init_ex(ctx, key, key_len, EVP_sha256(), 0) != 1) {
        return AX_ERR_UNKNOWN;
    }

    return 0;
}

int test_hmac_sha256_update(void *hmac_context, const uint8_t *data, size_t data_len, void *user_data)
{
    HMAC_CTX *ctx = hmac_context;
    int result = HMAC_Update(ctx, data, data_len);
    return (result == 1) ? 0 : -1;
}

int test_hmac_sha256_final(void *hmac_context, axolotl_buffer **output, void *user_data)
{
    int result = 0;
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int len = 0;
    HMAC_CTX *ctx = hmac_context;

    if(HMAC_Final(ctx, md, &len) != 1) {
        return AX_ERR_UNKNOWN;
    }

    axolotl_buffer *output_buffer = axolotl_buffer_create(md, len);
    if(!output_buffer) {
        result = AX_ERR_NOMEM;
        goto complete;
    }

    *output = output_buffer;

complete:
    return result;
}

void test_hmac_sha256_cleanup(void *hmac_context, void *user_data)
{
    if(hmac_context) {
        HMAC_CTX *ctx = hmac_context;
        HMAC_CTX_cleanup(ctx);
        free(ctx);
    }
}

const EVP_CIPHER *aes_cipher(int cipher, size_t key_len)
{
    if(cipher == AX_CIPHER_AES_CBC_PKCS5) {
        if(key_len == 16) {
            return EVP_aes_128_cbc();
        }
        else if(key_len == 24) {
            return EVP_aes_192_cbc();
        }
        else if(key_len == 32) {
            return EVP_aes_256_cbc();
        }
    }
    else if(cipher == AX_CIPHER_AES_CTR_NOPADDING) {
        if(key_len == 16) {
            return EVP_aes_128_ctr();
        }
        else if(key_len == 24) {
            return EVP_aes_192_ctr();
        }
        else if(key_len == 32) {
            return EVP_aes_256_ctr();
        }
    }
    return 0;
}

int test_sha512_digest_func(axolotl_buffer **output, const uint8_t *data, size_t data_len, void *user_data)
{
    int result = 0;
    axolotl_buffer *buffer = 0;
    SHA512_CTX ctx;

    buffer = axolotl_buffer_alloc(SHA512_DIGEST_LENGTH);
    if(!buffer) {
        result = AX_ERR_NOMEM;
        goto complete;
    }

    result = SHA512_Init(&ctx);
    if(!result) {
        result = AX_ERR_UNKNOWN;
        goto complete;
    }

    result = SHA512_Update(&ctx, data, data_len);
    if(!result) {
        result = AX_ERR_UNKNOWN;
        goto complete;
    }

complete:
    if(buffer) {
        result = SHA512_Final(axolotl_buffer_data(buffer), &ctx);
        if(!result) {
            result = AX_ERR_UNKNOWN;
        }
    }

    if(result < 0) {
        axolotl_buffer_free(buffer);
    }
    else {
        *output = buffer;
    }
    return result;
}

int test_encrypt(axolotl_buffer **output,
        int cipher,
        const uint8_t *key, size_t key_len,
        const uint8_t *iv, size_t iv_len,
        const uint8_t *plaintext, size_t plaintext_len,
        void *user_data)
{
    int result = 0;
    uint8_t *out_buf = 0;

    const EVP_CIPHER *evp_cipher = aes_cipher(cipher, key_len);
    if(!evp_cipher) {
        fprintf(stderr, "invalid AES mode or key size: %zu\n", key_len);
        return AX_ERR_UNKNOWN;
    }

    if(iv_len != 16) {
        fprintf(stderr, "invalid AES IV size: %zu\n", iv_len);
        return AX_ERR_UNKNOWN;
    }

    EVP_CIPHER_CTX ctx;
    EVP_CIPHER_CTX_init(&ctx);

    result = EVP_EncryptInit_ex(&ctx, evp_cipher, 0, key, iv);
    if(!result) {
        fprintf(stderr, "cannot initialize cipher\n");
        result = AX_ERR_UNKNOWN;
        goto complete;
    }

    if(cipher == AX_CIPHER_AES_CTR_NOPADDING) {
        result = EVP_CIPHER_CTX_set_padding(&ctx, 0);
        if(!result) {
            fprintf(stderr, "cannot set padding\n");
            result = AX_ERR_UNKNOWN;
            goto complete;
        }
    }

    out_buf = malloc(sizeof(uint8_t) * (plaintext_len + EVP_MAX_BLOCK_LENGTH));
    if(!out_buf) {
        fprintf(stderr, "cannot allocate output buffer\n");
        result = AX_ERR_NOMEM;
        goto complete;
    }

    int out_len = 0;
    result = EVP_EncryptUpdate(&ctx,
        out_buf, &out_len, plaintext, plaintext_len);
    if(!result) {
        fprintf(stderr, "cannot encrypt plaintext\n");
        result = AX_ERR_UNKNOWN;
        goto complete;
    }

    int final_len = 0;
    result = EVP_EncryptFinal_ex(&ctx, out_buf + out_len, &final_len);
    if(!result) {
        fprintf(stderr, "cannot finish encrypting plaintext\n");
        result = AX_ERR_UNKNOWN;
        goto complete;
    }

    *output = axolotl_buffer_create(out_buf, out_len + final_len);

complete:
    EVP_CIPHER_CTX_cleanup(&ctx);
    if(out_buf) {
        free(out_buf);
    }
    return result;
}

int test_decrypt(axolotl_buffer **output,
        int cipher,
        const uint8_t *key, size_t key_len,
        const uint8_t *iv, size_t iv_len,
        const uint8_t *ciphertext, size_t ciphertext_len,
        void *user_data)
{
    int result = 0;
    uint8_t *out_buf = 0;

    const EVP_CIPHER *evp_cipher = aes_cipher(cipher, key_len);
    if(!evp_cipher) {
        fprintf(stderr, "invalid AES mode or key size: %zu\n", key_len);
        return AX_ERR_INVAL;
    }

    if(iv_len != 16) {
        fprintf(stderr, "invalid AES IV size: %zu\n", iv_len);
        return AX_ERR_INVAL;
    }

    EVP_CIPHER_CTX ctx;
    EVP_CIPHER_CTX_init(&ctx);

    result = EVP_DecryptInit_ex(&ctx, evp_cipher, 0, key, iv);
    if(!result) {
        fprintf(stderr, "cannot initialize cipher\n");
        result = AX_ERR_UNKNOWN;
        goto complete;
    }

    if(cipher == AX_CIPHER_AES_CTR_NOPADDING) {
        result = EVP_CIPHER_CTX_set_padding(&ctx, 0);
        if(!result) {
            fprintf(stderr, "cannot set padding\n");
            result = AX_ERR_UNKNOWN;
            goto complete;
        }
    }

    out_buf = malloc(sizeof(uint8_t) * (ciphertext_len + EVP_MAX_BLOCK_LENGTH));
    if(!out_buf) {
        fprintf(stderr, "cannot allocate output buffer\n");
        result = AX_ERR_UNKNOWN;
        goto complete;
    }

    int out_len = 0;
    result = EVP_DecryptUpdate(&ctx,
        out_buf, &out_len, ciphertext, ciphertext_len);
    if(!result) {
        fprintf(stderr, "cannot decrypt ciphertext\n");
        result = AX_ERR_UNKNOWN;
        goto complete;
    }

    int final_len = 0;
    result = EVP_DecryptFinal_ex(&ctx, out_buf + out_len, &final_len);
    if(!result) {
        fprintf(stderr, "cannot finish decrypting ciphertext\n");
        result = AX_ERR_UNKNOWN;
        goto complete;
    }

    *output = axolotl_buffer_create(out_buf, out_len + final_len);

complete:
    EVP_CIPHER_CTX_cleanup(&ctx);
    if(out_buf) {
        free(out_buf);
    }
    return result;
}

void setup_test_crypto_provider(axolotl_context *context)
{
    axolotl_crypto_provider provider = {
            .random_func = test_random_generator,
            .hmac_sha256_init_func = test_hmac_sha256_init,
            .hmac_sha256_update_func = test_hmac_sha256_update,
            .hmac_sha256_final_func = test_hmac_sha256_final,
            .hmac_sha256_cleanup_func = test_hmac_sha256_cleanup,
            .sha512_digest_func = test_sha512_digest_func,
            .encrypt_func = test_encrypt,
            .decrypt_func = test_decrypt,
            .user_data = 0
    };

    axolotl_context_set_crypto_provider(context, &provider);
}

/*------------------------------------------------------------------------*/

void setup_test_store_context(axolotl_store_context **context, axolotl_context *global_context)
{
    int result = 0;

    axolotl_store_context *store_context = 0;
    result = axolotl_store_context_create(&store_context, global_context);
    ck_assert_int_eq(result, 0);

    setup_test_session_store(store_context);
    setup_test_pre_key_store(store_context);
    setup_test_signed_pre_key_store(store_context);
    setup_test_identity_key_store(store_context, global_context);
    setup_test_sender_key_store(store_context, global_context);

    *context = store_context;
}

/*------------------------------------------------------------------------*/

typedef struct {
    int64_t recipient_id;
    int32_t device_id;
} test_session_store_session_key;

typedef struct {
    test_session_store_session_key key;
    axolotl_buffer *record;
    UT_hash_handle hh;
} test_session_store_session;

typedef struct {
    test_session_store_session *sessions;
} test_session_store_data;

int test_session_store_load_session(axolotl_buffer **record, const axolotl_address *address, void *user_data)
{
    test_session_store_data *data = user_data;

    test_session_store_session *s;

    test_session_store_session l;
    memset(&l, 0, sizeof(test_session_store_session));
    l.key.recipient_id = jenkins_hash(address->name, address->name_len);
    l.key.device_id = address->device_id;
    HASH_FIND(hh, data->sessions, &l.key, sizeof(test_session_store_session_key), s);

    if(!s) {
        return 0;
    }
    axolotl_buffer *result = axolotl_buffer_copy(s->record);
    if(!result) {
        return AX_ERR_NOMEM;
    }
    *record = result;
    return 1;
}

int test_session_store_get_sub_device_sessions(axolotl_int_list **sessions, const char *name, size_t name_len, void *user_data)
{
    test_session_store_data *data = user_data;

    axolotl_int_list *result = axolotl_int_list_alloc();
    if(!result) {
        return AX_ERR_NOMEM;
    }

    int64_t recipient_hash = jenkins_hash(name, name_len);
    test_session_store_session *cur_node;
    test_session_store_session *tmp_node;
    HASH_ITER(hh, data->sessions, cur_node, tmp_node) {
        if(cur_node->key.recipient_id == recipient_hash) {
            axolotl_int_list_push_back(result, cur_node->key.device_id);
        }
    }

    *sessions = result;
    return 0;
}

int test_session_store_store_session(const axolotl_address *address, uint8_t *record, size_t record_len, void *user_data)
{
    test_session_store_data *data = user_data;

    test_session_store_session *s;

    test_session_store_session l;
    memset(&l, 0, sizeof(test_session_store_session));
    l.key.recipient_id = jenkins_hash(address->name, address->name_len);
    l.key.device_id = address->device_id;

    axolotl_buffer *record_buf = axolotl_buffer_create(record, record_len);
    if(!record_buf) {
        return AX_ERR_NOMEM;
    }

    HASH_FIND(hh, data->sessions, &l.key, sizeof(test_session_store_session_key), s);

    if(s) {
        axolotl_buffer_free(s->record);
        s->record = record_buf;
    }
    else {
        s = malloc(sizeof(test_session_store_session));
        if(!s) {
            axolotl_buffer_free(record_buf);
            return AX_ERR_NOMEM;
        }
        memset(s, 0, sizeof(test_session_store_session));
        s->key.recipient_id = jenkins_hash(address->name, address->name_len);
        s->key.device_id = address->device_id;
        s->record = record_buf;
        HASH_ADD(hh, data->sessions, key, sizeof(test_session_store_session_key), s);
    }

    return 0;
}

int test_session_store_contains_session(const axolotl_address *address, void *user_data)
{
    test_session_store_data *data = user_data;
    test_session_store_session *s;

    test_session_store_session l;
    memset(&l, 0, sizeof(test_session_store_session));
    l.key.recipient_id = jenkins_hash(address->name, address->name_len);
    l.key.device_id = address->device_id;

    HASH_FIND(hh, data->sessions, &l.key, sizeof(test_session_store_session_key), s);

    return (s == 0) ? 0 : 1;
}

int test_session_store_delete_session(const axolotl_address *address, void *user_data)
{
    int result = 0;
    test_session_store_data *data = user_data;
    test_session_store_session *s;

    test_session_store_session l;
    memset(&l, 0, sizeof(test_session_store_session));
    l.key.recipient_id = jenkins_hash(address->name, address->name_len);
    l.key.device_id = address->device_id;

    HASH_FIND(hh, data->sessions, &l.key, sizeof(test_session_store_session_key), s);

    if(s) {
        HASH_DEL(data->sessions, s);
        axolotl_buffer_free(s->record);
        free(s);
        result = 1;
    }
    return result;
}

int test_session_store_delete_all_sessions(const char *name, size_t name_len, void *user_data)
{
    int result = 0;
    test_session_store_data *data = user_data;

    int64_t recipient_hash = jenkins_hash(name, name_len);
    test_session_store_session *cur_node;
    test_session_store_session *tmp_node;
    HASH_ITER(hh, data->sessions, cur_node, tmp_node) {
        if(cur_node->key.recipient_id == recipient_hash) {
            HASH_DEL(data->sessions, cur_node);
            axolotl_buffer_free(cur_node->record);
            free(cur_node);
            result++;
        }
    }

    return result;
}

void test_session_store_destroy(void *user_data)
{
    test_session_store_data *data = user_data;

    test_session_store_session *cur_node;
    test_session_store_session *tmp_node;
    HASH_ITER(hh, data->sessions, cur_node, tmp_node) {
        HASH_DEL(data->sessions, cur_node);
        axolotl_buffer_free(cur_node->record);
        free(cur_node);
    }

    free(data);
}

void setup_test_session_store(axolotl_store_context *context)
{
    test_session_store_data *data = malloc(sizeof(test_session_store_data));
    memset(data, 0, sizeof(test_session_store_data));

    axolotl_session_store store = {
        .load_session_func = test_session_store_load_session,
        .get_sub_device_sessions_func = test_session_store_get_sub_device_sessions,
        .store_session_func = test_session_store_store_session,
        .contains_session_func = test_session_store_contains_session,
        .delete_session_func = test_session_store_delete_session,
        .delete_all_sessions_func = test_session_store_delete_all_sessions,
        .destroy_func = test_session_store_destroy,
        .user_data = data
    };

    axolotl_store_context_set_session_store(context, &store);
}

/*------------------------------------------------------------------------*/

typedef struct {
    uint32_t key_id;
    axolotl_buffer *key_record;
    UT_hash_handle hh;
} test_pre_key_store_key;

typedef struct {
    test_pre_key_store_key *keys;
} test_pre_key_store_data;

int test_pre_key_store_load_pre_key(axolotl_buffer **record, uint32_t pre_key_id, void *user_data)
{
    test_pre_key_store_data *data = user_data;

    test_pre_key_store_key *s;

    HASH_FIND(hh, data->keys, &pre_key_id, sizeof(uint32_t), s);
    if(s) {
        *record = axolotl_buffer_copy(s->key_record);
        return AX_SUCCESS;
    }
    else {
        return AX_ERR_INVALID_KEY_ID;
    }
}

int test_pre_key_store_store_pre_key(uint32_t pre_key_id, uint8_t *record, size_t record_len, void *user_data)
{
    test_pre_key_store_data *data = user_data;

    test_pre_key_store_key *s;

    axolotl_buffer *key_buf = axolotl_buffer_create(record, record_len);
    if(!key_buf) {
        return AX_ERR_NOMEM;
    }

    HASH_FIND(hh, data->keys, &pre_key_id, sizeof(uint32_t), s);
    if(s) {
        axolotl_buffer_free(s->key_record);
        s->key_record = key_buf;
    }
    else {
        s = malloc(sizeof(test_pre_key_store_key));
        if(!s) {
            axolotl_buffer_free(key_buf);
            return AX_ERR_NOMEM;
        }
        memset(s, 0, sizeof(test_pre_key_store_key));
        s->key_id = pre_key_id;
        s->key_record = key_buf;
        HASH_ADD(hh, data->keys, key_id, sizeof(uint32_t), s);
    }

    return 0;
}

int test_pre_key_store_contains_pre_key(uint32_t pre_key_id, void *user_data)
{
    test_pre_key_store_data *data = user_data;

    test_pre_key_store_key *s;
    HASH_FIND(hh, data->keys, &pre_key_id, sizeof(uint32_t), s);

    return (s == 0) ? 0 : 1;
}

int test_pre_key_store_remove_pre_key(uint32_t pre_key_id, void *user_data)
{
    test_pre_key_store_data *data = user_data;

    test_pre_key_store_key *s;
    HASH_FIND(hh, data->keys, &pre_key_id, sizeof(uint32_t), s);
    if(s) {
        HASH_DEL(data->keys, s);
        axolotl_buffer_free(s->key_record);
        free(s);
    }

    return 0;
}

void test_pre_key_store_destroy(void *user_data)
{
    test_pre_key_store_data *data = user_data;

    test_pre_key_store_key *cur_node;
    test_pre_key_store_key *tmp_node;
    HASH_ITER(hh, data->keys, cur_node, tmp_node) {
        HASH_DEL(data->keys, cur_node);
        axolotl_buffer_free(cur_node->key_record);
        free(cur_node);
    }
    free(data);
}

void setup_test_pre_key_store(axolotl_store_context *context)
{
    test_pre_key_store_data *data = malloc(sizeof(test_pre_key_store_data));
    memset(data, 0, sizeof(test_pre_key_store_data));

    axolotl_pre_key_store store = {
        .load_pre_key = test_pre_key_store_load_pre_key,
        .store_pre_key = test_pre_key_store_store_pre_key,
        .contains_pre_key = test_pre_key_store_contains_pre_key,
        .remove_pre_key = test_pre_key_store_remove_pre_key,
        .destroy_func = test_pre_key_store_destroy,
        .user_data = data
    };

    axolotl_store_context_set_pre_key_store(context, &store);
}

/*------------------------------------------------------------------------*/

typedef struct {
    uint32_t key_id;
    axolotl_buffer *key_record;
    UT_hash_handle hh;
} test_signed_pre_key_store_key;

typedef struct {
    test_signed_pre_key_store_key *keys;
} test_signed_pre_key_store_data;


int test_signed_pre_key_store_load_signed_pre_key(axolotl_buffer **record, uint32_t signed_pre_key_id, void *user_data)
{
    test_signed_pre_key_store_data *data = user_data;
    test_signed_pre_key_store_key *s;

    HASH_FIND(hh, data->keys, &signed_pre_key_id, sizeof(uint32_t), s);
    if(s) {
        *record = axolotl_buffer_copy(s->key_record);
        return AX_SUCCESS;
    }
    else {
        return AX_ERR_INVALID_KEY_ID;
    }
}

int test_signed_pre_key_store_store_signed_pre_key(uint32_t signed_pre_key_id, uint8_t *record, size_t record_len, void *user_data)
{
    test_signed_pre_key_store_data *data = user_data;
    test_signed_pre_key_store_key *s;

    axolotl_buffer *key_buf = axolotl_buffer_create(record, record_len);
    if(!key_buf) {
        return AX_ERR_NOMEM;
    }

    HASH_FIND(hh, data->keys, &signed_pre_key_id, sizeof(uint32_t), s);
    if(s) {
        axolotl_buffer_free(s->key_record);
        s->key_record = key_buf;
    }
    else {
        s = malloc(sizeof(test_signed_pre_key_store_key));
        if(!s) {
            axolotl_buffer_free(key_buf);
            return AX_ERR_NOMEM;
        }
        memset(s, 0, sizeof(test_signed_pre_key_store_key));
        s->key_id = signed_pre_key_id;
        s->key_record = key_buf;
        HASH_ADD(hh, data->keys, key_id, sizeof(uint32_t), s);
    }

    return 0;
}

int test_signed_pre_key_store_contains_signed_pre_key(uint32_t signed_pre_key_id, void *user_data)
{
    test_signed_pre_key_store_data *data = user_data;

    test_signed_pre_key_store_key *s;
    HASH_FIND(hh, data->keys, &signed_pre_key_id, sizeof(uint32_t), s);

    return (s == 0) ? 0 : 1;
}

int test_signed_pre_key_store_remove_signed_pre_key(uint32_t signed_pre_key_id, void *user_data)
{
    test_signed_pre_key_store_data *data = user_data;

    test_signed_pre_key_store_key *s;
    HASH_FIND(hh, data->keys, &signed_pre_key_id, sizeof(uint32_t), s);
    if(s) {
        HASH_DEL(data->keys, s);
        axolotl_buffer_free(s->key_record);
        free(s);
    }

    return 0;
}

void test_signed_pre_key_store_destroy(void *user_data)
{
    test_signed_pre_key_store_data *data = user_data;

    test_signed_pre_key_store_key *cur_node;
    test_signed_pre_key_store_key *tmp_node;
    HASH_ITER(hh, data->keys, cur_node, tmp_node) {
        HASH_DEL(data->keys, cur_node);
        axolotl_buffer_free(cur_node->key_record);
        free(cur_node);
    }
    free(data);
}

void setup_test_signed_pre_key_store(axolotl_store_context *context)
{
    test_signed_pre_key_store_data *data = malloc(sizeof(test_signed_pre_key_store_data));
    memset(data, 0, sizeof(test_signed_pre_key_store_data));

    axolotl_signed_pre_key_store store = {
            .load_signed_pre_key = test_signed_pre_key_store_load_signed_pre_key,
            .store_signed_pre_key = test_signed_pre_key_store_store_signed_pre_key,
            .contains_signed_pre_key = test_signed_pre_key_store_contains_signed_pre_key,
            .remove_signed_pre_key = test_signed_pre_key_store_remove_signed_pre_key,
            .destroy_func = test_signed_pre_key_store_destroy,
            .user_data = data
    };

    axolotl_store_context_set_signed_pre_key_store(context, &store);
}

/*------------------------------------------------------------------------*/

typedef struct {
    int64_t recipient_id;
    axolotl_buffer *identity_key;
    UT_hash_handle hh;
} test_identity_store_key;

typedef struct {
    test_identity_store_key *keys;
    axolotl_buffer *identity_key_public;
    axolotl_buffer *identity_key_private;
    uint32_t local_registration_id;
} test_identity_store_data;

int test_identity_key_store_get_identity_key_pair(axolotl_buffer **public_data, axolotl_buffer **private_data, void *user_data)
{
    test_identity_store_data *data = user_data;
    *public_data = axolotl_buffer_copy(data->identity_key_public);
    *private_data = axolotl_buffer_copy(data->identity_key_private);
    return 0;
}

int test_identity_key_store_get_local_registration_id(void *user_data, uint32_t *registration_id)
{
    test_identity_store_data *data = user_data;
    *registration_id = data->local_registration_id;
    return 0;
}

int test_identity_key_store_save_identity(const char *name, size_t name_len, uint8_t *key_data, size_t key_len, void *user_data)
{
    test_identity_store_data *data = user_data;

    test_identity_store_key *s;

    axolotl_buffer *key_buf = axolotl_buffer_create(key_data, key_len);
    if(!key_buf) {
        return AX_ERR_NOMEM;
    }

    int64_t recipient_hash = jenkins_hash(name, name_len);

    HASH_FIND(hh, data->keys, &recipient_hash, sizeof(int64_t), s);
    if(s) {
        axolotl_buffer_free(s->identity_key);
        s->identity_key = key_buf;
    }
    else {
        s = malloc(sizeof(test_identity_store_key));
        if(!s) {
            axolotl_buffer_free(key_buf);
            return AX_ERR_NOMEM;
        }
        memset(s, 0, sizeof(test_identity_store_key));
        s->recipient_id = recipient_hash;
        s->identity_key = key_buf;
        HASH_ADD(hh, data->keys, recipient_id, sizeof(int64_t), s);
    }

    return 0;
}

int test_identity_key_store_is_trusted_identity(const char *name, size_t name_len, uint8_t *key_data, size_t key_len, void *user_data)
{
    test_identity_store_data *data = user_data;

    int64_t recipient_hash = jenkins_hash(name, name_len);

    test_identity_store_key *s;
    HASH_FIND(hh, data->keys, &recipient_hash, sizeof(int64_t), s);

    if(s) {
        uint8_t *store_data = axolotl_buffer_data(s->identity_key);
        size_t store_len = axolotl_buffer_len(s->identity_key);
        if(store_len != key_len) {
            return 0;
        }
        if(memcmp(key_data, store_data, key_len) == 0) {
            return 1;
        }
        else {
            return 0;
        }
    }
    else {
        return 1;
    }
}

void test_identity_key_store_destroy(void *user_data)
{
    test_identity_store_data *data = user_data;

    test_identity_store_key *cur_node;
    test_identity_store_key *tmp_node;
    HASH_ITER(hh, data->keys, cur_node, tmp_node) {
        HASH_DEL(data->keys, cur_node);
        axolotl_buffer_free(cur_node->identity_key);
        free(cur_node);
    }
    axolotl_buffer_free(data->identity_key_public);
    axolotl_buffer_free(data->identity_key_private);
    free(data);
}

void setup_test_identity_key_store(axolotl_store_context *context, axolotl_context *global_context)
{
    test_identity_store_data *data = malloc(sizeof(test_identity_store_data));
    memset(data, 0, sizeof(test_identity_store_data));

    ec_key_pair *identity_key_pair_keys = 0;
    curve_generate_key_pair(global_context, &identity_key_pair_keys);

    ec_public_key *identity_key_public = ec_key_pair_get_public(identity_key_pair_keys);
    ec_private_key *identity_key_private = ec_key_pair_get_private(identity_key_pair_keys);

    ec_public_key_serialize(&data->identity_key_public, identity_key_public);
    ec_private_key_serialize(&data->identity_key_private, identity_key_private);
    AXOLOTL_UNREF(identity_key_pair_keys);

    data->local_registration_id = (rand() % 16380) + 1;

    axolotl_identity_key_store store = {
            .get_identity_key_pair = test_identity_key_store_get_identity_key_pair,
            .get_local_registration_id = test_identity_key_store_get_local_registration_id,
            .save_identity = test_identity_key_store_save_identity,
            .is_trusted_identity = test_identity_key_store_is_trusted_identity,
            .destroy_func = test_identity_key_store_destroy,
            .user_data = data
    };

    axolotl_store_context_set_identity_key_store(context, &store);
}

/*------------------------------------------------------------------------*/

typedef struct {
    int64_t group_id;
    int64_t recipient_id;
    int32_t device_id;
} test_sender_key_store_key;

typedef struct {
    test_sender_key_store_key key;
    axolotl_buffer *record;
    UT_hash_handle hh;
} test_sender_key_store_record;

typedef struct {
    test_sender_key_store_record *records;
} test_sender_key_store_data;

int test_sender_key_store_store_sender_key(const axolotl_sender_key_name *sender_key_name, uint8_t *record, size_t record_len, void *user_data)
{
    test_sender_key_store_data *data = user_data;

    test_sender_key_store_record *s;

    test_sender_key_store_record l;
    memset(&l, 0, sizeof(test_sender_key_store_record));
    l.key.group_id = jenkins_hash(sender_key_name->group_id, sender_key_name->group_id_len);
    l.key.recipient_id = jenkins_hash(sender_key_name->sender.name, sender_key_name->sender.name_len);
    l.key.device_id = sender_key_name->sender.device_id;

    axolotl_buffer *record_buf = axolotl_buffer_create(record, record_len);
    if(!record_buf) {
        return AX_ERR_NOMEM;
    }

    HASH_FIND(hh, data->records, &l.key, sizeof(test_sender_key_store_key), s);

    if(s) {
        axolotl_buffer_free(s->record);
        s->record = record_buf;
    }
    else {
        s = malloc(sizeof(test_sender_key_store_record));
        if(!s) {
            axolotl_buffer_free(record_buf);
            return AX_ERR_NOMEM;
        }
        memset(s, 0, sizeof(test_sender_key_store_record));
        s->key.group_id = jenkins_hash(sender_key_name->group_id, sender_key_name->group_id_len);
        s->key.recipient_id = jenkins_hash(sender_key_name->sender.name, sender_key_name->sender.name_len);
        s->key.device_id = sender_key_name->sender.device_id;
        s->record = record_buf;
        HASH_ADD(hh, data->records, key, sizeof(test_sender_key_store_key), s);
    }

    return 0;
}

int test_sender_key_store_load_sender_key(axolotl_buffer **record, const axolotl_sender_key_name *sender_key_name, void *user_data)
{
    test_sender_key_store_data *data = user_data;

    test_sender_key_store_record *s;

    test_sender_key_store_record l;
    memset(&l, 0, sizeof(test_session_store_session));
    l.key.group_id = jenkins_hash(sender_key_name->group_id, sender_key_name->group_id_len);
    l.key.recipient_id = jenkins_hash(sender_key_name->sender.name, sender_key_name->sender.name_len);
    l.key.device_id = sender_key_name->sender.device_id;
    HASH_FIND(hh, data->records, &l.key, sizeof(test_sender_key_store_key), s);

    if(!s) {
        return 0;
    }
    axolotl_buffer *result = axolotl_buffer_copy(s->record);
    if(!result) {
        return AX_ERR_NOMEM;
    }
    *record = result;
    return 1;
}

void test_sender_key_store_destroy(void *user_data)
{
    test_sender_key_store_data *data = user_data;

    test_sender_key_store_record *cur_node;
    test_sender_key_store_record *tmp_node;
    HASH_ITER(hh, data->records, cur_node, tmp_node) {
        HASH_DEL(data->records, cur_node);
        axolotl_buffer_free(cur_node->record);
        free(cur_node);
    }
    free(data);
}

void setup_test_sender_key_store(axolotl_store_context *context, axolotl_context *global_context)
{
    test_sender_key_store_data *data = malloc(sizeof(test_sender_key_store_data));
    memset(data, 0, sizeof(test_sender_key_store_data));

    axolotl_sender_key_store store = {
        .store_sender_key = test_sender_key_store_store_sender_key,
        .load_sender_key = test_sender_key_store_load_sender_key,
        .destroy_func = test_sender_key_store_destroy,
        .user_data = data
    };

    axolotl_store_context_set_sender_key_store(context, &store);
}
