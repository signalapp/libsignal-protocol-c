#ifndef AXOLOTL_H
#define AXOLOTL_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include "axolotl_types.h"
#include "ratchet.h"
#include "curve.h"
#include "session_record.h"
#include "session_pre_key.h"
#include "sender_key_record.h"

#ifdef __cplusplus
extern "C" {
#endif

#define AX_SUCCESS 0

/* Standard error codes with values that match errno.h equivalents */
#define AX_ERR_NOMEM -12   /* Not enough space */
#define AX_ERR_INVAL -22   /* Invalid argument */

/* Custom error codes for error conditions specific to the library */
#define AX_ERR_UNKNOWN              -1000
#define AX_ERR_DUPLICATE_MESSAGE    -1001
#define AX_ERR_INVALID_KEY          -1002
#define AX_ERR_INVALID_KEY_ID       -1003
#define AX_ERR_INVALID_MAC          -1004
#define AX_ERR_INVALID_MESSAGE      -1005
#define AX_ERR_INVALID_VERSION      -1006
#define AX_ERR_LEGACY_MESSAGE       -1007
#define AX_ERR_NO_SESSION           -1008
#define AX_ERR_STALE_KEY_EXCHANGE   -1009
#define AX_ERR_UNTRUSTED_IDENTITY   -1010
#define AX_ERR_INVALID_PROTO_BUF    -1100
#define AX_ERR_FP_VERSION_MISMATCH  -1200
#define AX_ERR_FP_IDENT_MISMATCH    -1201

/*
 * Minimum negative error code value that this library may use.
 * When implementing library callback functions, using values
 * less than this constant will ensure that application-specific
 * errors can be distinguished from library errors.
 */
#define AX_ERR_MINIMUM              -9999

/* Log levels */
#define AX_LOG_ERROR   0
#define AX_LOG_WARNING 1
#define AX_LOG_NOTICE  2
#define AX_LOG_INFO    3
#define AX_LOG_DEBUG   4

/* Mode settings for the crypto callbacks */
#define AX_CIPHER_AES_CTR_NOPADDING 1
#define AX_CIPHER_AES_CBC_PKCS5     2

void axolotl_type_ref(axolotl_type_base *instance);
void axolotl_type_unref(axolotl_type_base *instance);

#ifdef DEBUG_REFCOUNT
int axolotl_type_ref_count(axolotl_type_base *instance);
#define AXOLOTL_REF(instance) do { \
    axolotl_type_ref((axolotl_type_base *)instance); \
    fprintf(stderr, "REF: " #instance " = %d\n", axolotl_type_ref_count((axolotl_type_base *)instance)); \
    } while (0)
#define AXOLOTL_UNREF(instance) do { \
    fprintf(stderr, "UNREF: " #instance " = %d\n", axolotl_type_ref_count((axolotl_type_base *)instance)); \
    axolotl_type_unref((axolotl_type_base *)instance); \
    instance = 0; \
    } while(0)
#else
#define AXOLOTL_REF(instance) axolotl_type_ref((axolotl_type_base *)instance)
#define AXOLOTL_UNREF(instance) do { axolotl_type_unref((axolotl_type_base *)instance); instance = 0; } while(0)
#endif

/**
 * Allocate a new buffer to store data of the provided length.
 *
 * @param len length of the buffer to allocate
 * @return pointer to the allocated buffer, or 0 on failure
 */
axolotl_buffer *axolotl_buffer_alloc(size_t len);

/**
 * Create a new buffer and copy the provided data into it.
 *
 * @param data pointer to the start of the data
 * @param len length of the data
 * @return pointer to the allocated buffer, or 0 on failure
 */
axolotl_buffer *axolotl_buffer_create(const uint8_t *data, size_t len);

/**
 * Create a copy of an existing buffer.
 *
 * @param buffer the existing buffer to copy
 * @return pointer to the updated buffer, or 0 on failure
 */
axolotl_buffer *axolotl_buffer_copy(const axolotl_buffer *buffer);

/**
 * Append the provided data to an existing buffer.
 * Note: The underlying buffer is only expanded by an amount sufficient
 * to hold the data being appended. There is no additional reserved space
 * to reduce the need for memory allocations.
 *
 * @param buffer the existing buffer to append to
 * @param data pointer to the start of the data
 * @param len length of the data
 * @return pointer to the updated buffer, or 0 on failure
 */
axolotl_buffer *axolotl_buffer_append(axolotl_buffer *buffer, const uint8_t *data, size_t len);

/**
 * Gets the data pointer for the buffer.
 * This can be used to read and write data stored in the buffer.
 *
 * @param buffer pointer to the buffer instance
 * @return data pointer
 */
uint8_t *axolotl_buffer_data(axolotl_buffer *buffer);

/**
 * Gets the length of the data stored within the buffer.
 *
 * @param buffer pointer to the buffer instance
 * @return data length
 */
size_t axolotl_buffer_len(axolotl_buffer *buffer);

/**
 * Compare two buffers.
 *
 * @param buffer1 first buffer to compare
 * @param buffer2 second buffer to compare
 * @return 0 if the two buffers are equal, negative or positive otherwise
 */
int axolotl_buffer_compare(axolotl_buffer *buffer1, axolotl_buffer *buffer2);

/**
 * Free the data buffer.
 *
 * @param buffer pointer to the buffer instance to free
 */
void axolotl_buffer_free(axolotl_buffer *buffer);

/**
 * Zero and free the data buffer.
 * This function should be used when the buffer contains sensitive
 * data, to make sure the memory is cleared before being freed.
 *
 * @param buffer pointer to the buffer instance to free
 */
void axolotl_buffer_bzero_free(axolotl_buffer *buffer);

/**
 * Allocate a new buffer list.
 *
 * @return pointer to the allocated buffer, or 0 on failure
 */
axolotl_buffer_list *axolotl_buffer_list_alloc();

/**
 * Push the provided buffer onto the head of the list.
 *
 * @param list the buffer list
 * @param buffer the buffer to push
 * @return 0 on success, or negative on failure
 */
int axolotl_buffer_list_push(axolotl_buffer_list *list, axolotl_buffer *buffer);

/**
 * Gets the size of the buffer list.
 *
 * @param list the buffer list
 * @return the size of the list
 */
int axolotl_buffer_list_size(axolotl_buffer_list *list);

/**
 * Free the buffer list, including all the buffers added to it.
 *
 * @param list the buffer list
 */
void axolotl_buffer_list_free(axolotl_buffer_list *list);

/**
 * Allocate a new int list
 *
 * @return pointer to the allocated buffer, or 0 on failure
 */
axolotl_int_list *axolotl_int_list_alloc();

/**
 * Push a new value onto the end of the list
 *
 * @param list the list
 * @param value the value to push
 */
void axolotl_int_list_push_back(axolotl_int_list *list, int value);

/**
 * Gets the size of the list.
 *
 * @param list the list
 * @return the size of the list
 */
unsigned int axolotl_int_list_size(axolotl_int_list *list);

/**
 * Gets the value of the element at a particular index in the list
 *
 * @param list the list
 * @param index the index within the list
 * @return the value
 */
int axolotl_int_list_at(axolotl_int_list *list, unsigned int index);

/**
 * Free the int list
 * @param list the list to free
 */
void axolotl_int_list_free(axolotl_int_list *list);

typedef struct axolotl_crypto_provider {
    /**
     * Callback for a secure random number generator.
     * This function shall fill the provided buffer with random bytes.
     *
     * @param data pointer to the output buffer
     * @param len size of the output buffer
     * @return 0 on success, negative on failure
     */
    int (*random_func)(uint8_t *data, size_t len, void *user_data);

    /**
     * Callback for an HMAC-SHA256 implementation.
     * This function shall initialize an HMAC context with the provided key.
     *
     * @param hmac_context private HMAC context pointer
     * @param key pointer to the key
     * @param key_len length of the key
     * @return 0 on success, negative on failure
     */
    int (*hmac_sha256_init_func)(void **hmac_context, const uint8_t *key, size_t key_len, void *user_data);

    /**
     * Callback for an HMAC-SHA256 implementation.
     * This function shall update the HMAC context with the provided data
     *
     * @param hmac_context private HMAC context pointer
     * @param data pointer to the data
     * @param data_len length of the data
     * @return 0 on success, negative on failure
     */
    int (*hmac_sha256_update_func)(void *hmac_context, const uint8_t *data, size_t data_len, void *user_data);

    /**
     * Callback for an HMAC-SHA256 implementation.
     * This function shall finalize an HMAC calculation and populate the output
     * buffer with the result.
     *
     * @param hmac_context private HMAC context pointer
     * @param output buffer to be allocated and populated with the result
     * @return 0 on success, negative on failure
     */
    int (*hmac_sha256_final_func)(void *hmac_context, axolotl_buffer **output, void *user_data);

    /**
     * Callback for an HMAC-SHA256 implementation.
     * This function shall free the private context allocated in
     * hmac_sha256_init_func.
     *
     * @param hmac_context private HMAC context pointer
     */
    void (*hmac_sha256_cleanup_func)(void *hmac_context, void *user_data);

    /**
     * Callback for a SHA512 message digest implementation.
     * This function is currently only used by the fingerprint generator.
     *
     * @param output buffer to be allocated and populated with the ciphertext
     * @param data pointer to the data
     * @param data_len length of the data
     * @return 0 on success, negative on failure
     */
    int (*sha512_digest_func)(axolotl_buffer **output, const uint8_t *data, size_t data_len, void *user_data);

    /**
     * Callback for an AES encryption implementation.
     *
     * @param output buffer to be allocated and populated with the ciphertext
     * @param cipher specific cipher variant to use, either AX_CIPHER_AES_CTR_NOPADDING or AX_CIPHER_AES_CBC_PKCS5
     * @param key the encryption key
     * @param key_len length of the encryption key
     * @param iv the initialization vector
     * @param iv_len length of the initialization vector
     * @param plaintext the plaintext to encrypt
     * @param plaintext_len length of the plaintext
     * @return 0 on success, negative on failure
     */
    int (*encrypt_func)(axolotl_buffer **output,
            int cipher,
            const uint8_t *key, size_t key_len,
            const uint8_t *iv, size_t iv_len,
            const uint8_t *plaintext, size_t plaintext_len,
            void *user_data);

    /**
     * Callback for an AES decryption implementation.
     *
     * @param output buffer to be allocated and populated with the plaintext
     * @param cipher specific cipher variant to use, either AX_CIPHER_AES_CTR_NOPADDING or AX_CIPHER_AES_CBC_PKCS5
     * @param key the encryption key
     * @param key_len length of the encryption key
     * @param iv the initialization vector
     * @param iv_len length of the initialization vector
     * @param ciphertext the ciphertext to decrypt
     * @param ciphertext_len length of the ciphertext
     * @return 0 on success, negative on failure
     */
    int (*decrypt_func)(axolotl_buffer **output,
            int cipher,
            const uint8_t *key, size_t key_len,
            const uint8_t *iv, size_t iv_len,
            const uint8_t *ciphertext, size_t ciphertext_len,
            void *user_data);

    /** User data pointer */
    void *user_data;
} axolotl_crypto_provider;

typedef struct axolotl_session_store {
    /**
     * Returns a copy of the serialized session record corresponding to the
     * provided recipient ID + device ID tuple.
     *
     * @param record pointer to a freshly allocated buffer containing the
     *     serialized session record. Unset if no record was found.
     *     The axolotl library is responsible for freeing this buffer.
     * @param address the address of the remote client
     * @return 1 if the session was loaded, 0 if the session was not found, negative on failure
     */
    int (*load_session_func)(axolotl_buffer **record, const axolotl_address *address, void *user_data);

    /**
     * Returns all known devices with active sessions for a recipient
     *
     * @param pointer to an array that will be allocated and populated with the result
     * @param name the name of the remote client
     * @param name_len the length of the name
     * @return size of the sessions array, or negative on failure
     */
    int (*get_sub_device_sessions_func)(axolotl_int_list **sessions, const char *name, size_t name_len, void *user_data);

    /**
     * Commit to storage the session record for a given
     * recipient ID + device ID tuple.
     *
     * @param address the address of the remote client
     * @param record pointer to a buffer containing the serialized session
     *     record for the remote client
     * @param record_len length of the serialized session record
     * @return 0 on success, negative on failure
     */
    int (*store_session_func)(const axolotl_address *address, uint8_t *record, size_t record_len, void *user_data);

    /**
     * Determine whether there is a committed session record for a
     * recipient ID + device ID tuple.
     *
     * @param address the address of the remote client
     * @return 1 if a session record exists, 0 otherwise.
     */
    int (*contains_session_func)(const axolotl_address *address, void *user_data);

    /**
     * Remove a session record for a recipient ID + device ID tuple.
     *
     * @param address the address of the remote client
     * @return 1 if a session was deleted, 0 if a session was not deleted, negative on error
     */
    int (*delete_session_func)(const axolotl_address *address, void *user_data);

    /**
     * Remove the session records corresponding to all devices of a recipient ID.
     *
     * @param name the name of the remote client
     * @param name_len the length of the name
     * @return the number of deleted sessions on success, negative on failure
     */
    int (*delete_all_sessions_func)(const char *name, size_t name_len, void *user_data);

    /**
     * Function called to perform cleanup when the data store context is being
     * destroyed.
     */
    void (*destroy_func)(void *user_data);

    /** User data pointer */
    void *user_data;
} axolotl_session_store;

typedef struct axolotl_pre_key_store {
    /**
     * Load a local serialized PreKey record.
     *
     * @param record pointer to a newly allocated buffer containing the record,
     *     if found. Unset if no record was found.
     *     The axolotl library is responsible for freeing this buffer.
     * @param pre_key_id the ID of the local serialized PreKey record
     * @retval AX_SUCCESS if the key was found
     * @retval AX_ERR_INVALID_KEY_ID if the key could not be found
     */
    int (*load_pre_key)(axolotl_buffer **record, uint32_t pre_key_id, void *user_data);

    /**
     * Store a local serialized PreKey record.
     *
     * @param pre_key_id the ID of the PreKey record to store.
     * @param record pointer to a buffer containing the serialized record
     * @param record_len length of the serialized record
     * @return 0 on success, negative on failure
     */
    int (*store_pre_key)(uint32_t pre_key_id, uint8_t *record, size_t record_len, void *user_data);

    /**
     * Determine whether there is a committed PreKey record matching the
     * provided ID.
     *
     * @param pre_key_id A PreKey record ID.
     * @return 1 if the store has a record for the PreKey ID, 0 otherwise
     */
    int (*contains_pre_key)(uint32_t pre_key_id, void *user_data);

    /**
     * Delete a PreKey record from local storage.
     *
     * @param pre_key_id The ID of the PreKey record to remove.
     * @return 0 on success, negative on failure
     */
    int (*remove_pre_key)(uint32_t pre_key_id, void *user_data);

    /**
     * Function called to perform cleanup when the data store context is being
     * destroyed.
     */
    void (*destroy_func)(void *user_data);

    /** User data pointer */
    void *user_data;
} axolotl_pre_key_store;

typedef struct axolotl_signed_pre_key_store {
    /**
     * Load a local serialized signed PreKey record.
     *
     * @param record pointer to a newly allocated buffer containing the record,
     *     if found. Unset if no record was found.
     *     The axolotl library is responsible for freeing this buffer.
     * @param signed_pre_key_id the ID of the local signed PreKey record
     * @retval AX_SUCCESS if the key was found
     * @retval AX_ERR_INVALID_KEY_ID if the key could not be found
     */
    int (*load_signed_pre_key)(axolotl_buffer **record, uint32_t signed_pre_key_id, void *user_data);

    /**
     * Store a local serialized signed PreKey record.
     *
     * @param signed_pre_key_id the ID of the signed PreKey record to store
     * @param record pointer to a buffer containing the serialized record
     * @param record_len length of the serialized record
     * @return 0 on success, negative on failure
     */
    int (*store_signed_pre_key)(uint32_t signed_pre_key_id, uint8_t *record, size_t record_len, void *user_data);

    /**
     * Determine whether there is a committed signed PreKey record matching
     * the provided ID.
     *
     * @param signed_pre_key_id A signed PreKey record ID.
     * @return 1 if the store has a record for the signed PreKey ID, 0 otherwise
     */
    int (*contains_signed_pre_key)(uint32_t signed_pre_key_id, void *user_data);

    /**
     * Delete a SignedPreKeyRecord from local storage.
     *
     * @param signed_pre_key_id The ID of the signed PreKey record to remove.
     * @return 0 on success, negative on failure
     */
    int (*remove_signed_pre_key)(uint32_t signed_pre_key_id, void *user_data);

    /**
     * Function called to perform cleanup when the data store context is being
     * destroyed.
     */
    void (*destroy_func)(void *user_data);

    /** User data pointer */
    void *user_data;
} axolotl_signed_pre_key_store;

typedef struct axolotl_identity_key_store {
    /**
     * Get the local client's identity key pair.
     *
     * @param public_data pointer to a newly allocated buffer containing the
     *     public key, if found. Unset if no record was found.
     *     The axolotl library is responsible for freeing this buffer.
     * @param private_data pointer to a newly allocated buffer containing the
     *     private key, if found. Unset if no record was found.
     *     The axolotl library is responsible for freeing this buffer.
     * @return 0 on success, negative on failure
     */
    int (*get_identity_key_pair)(axolotl_buffer **public_data, axolotl_buffer **private_data, void *user_data);

    /**
     * Return the local client's registration ID.
     *
     * Clients should maintain a registration ID, a random number
     * between 1 and 16380 that's generated once at install time.
     *
     * @param registration_id pointer to be set to the local client's
     *     registration ID, if it was successfully retrieved.
     * @return 0 on success, negative on failure
     */
    int (*get_local_registration_id)(void *user_data, uint32_t *registration_id);

    /**
     * Save a remote client's identity key
     * <p>
     * Store a remote client's identity key as trusted.
     * The value of key_data may be null. In this case remove the key data
     * from the identity store, but retain any metadata that may be kept
     * alongside it.
     *
     * @param name the name of the remote client
     * @param name_len the length of the name
     * @param key_data Pointer to the remote client's identity key, may be null
     * @param key_len Length of the remote client's identity key
     * @return 0 on success, negative on failure
     */
    int (*save_identity)(const char *name, size_t name_len, uint8_t *key_data, size_t key_len, void *user_data);

    /**
     * Verify a remote client's identity key.
     *
     * Determine whether a remote client's identity is trusted.  Convention is
     * that the TextSecure protocol is 'trust on first use.'  This means that
     * an identity key is considered 'trusted' if there is no entry for the recipient
     * in the local store, or if it matches the saved key for a recipient in the local
     * store.  Only if it mismatches an entry in the local store is it considered
     * 'untrusted.'
     *
     * @param name the name of the remote client
     * @param name_len the length of the name
     * @param identityKey The identity key to verify.
     * @param key_data Pointer to the identity key to verify
     * @param key_len Length of the identity key to verify
     * @return 1 if trusted, 0 if untrusted, negative on failure
     */
    int (*is_trusted_identity)(const char *name, size_t name_len, uint8_t *key_data, size_t key_len, void *user_data);

    /**
     * Function called to perform cleanup when the data store context is being
     * destroyed.
     */
    void (*destroy_func)(void *user_data);

    /** User data pointer */
    void *user_data;
} axolotl_identity_key_store;

typedef struct axolotl_sender_key_store {
    /**
     * Store a serialized sender key record for a given
     * (groupId + senderId + deviceId) tuple.
     *
     * @param sender_key_name the (groupId + senderId + deviceId) tuple
     * @param record pointer to a buffer containing the serialized record
     * @param record_len length of the serialized record
     * @return 0 on success, negative on failure
     */
    int (*store_sender_key)(const axolotl_sender_key_name *sender_key_name, uint8_t *record, size_t record_len, void *user_data);

    /**
     * Returns a copy of the sender key record corresponding to the
     * (groupId + senderId + deviceId) tuple.
     *
     * @param record pointer to a newly allocated buffer containing the record,
     *     if found. Unset if no record was found.
     *     The axolotl library is responsible for freeing this buffer.
     * @param sender_key_name the (groupId + senderId + deviceId) tuple
     * @return 1 if the record was loaded, 0 if the record was not found, negative on failure
     */
    int (*load_sender_key)(axolotl_buffer **record, const axolotl_sender_key_name *sender_key_name, void *user_data);

    /**
     * Function called to perform cleanup when the data store context is being
     * destroyed.
     */
    void (*destroy_func)(void *user_data);

    /** User data pointer */
    void *user_data;
} axolotl_sender_key_store;

/**
 * Create a new instance of the global library context.
 */
int axolotl_context_create(axolotl_context **context, void *user_data);

/**
 * Set the crypto provider to be used by the AXOLOTL library.
 *
 * @param crypto_provider Populated structure of crypto provider function
 *     pointers. The contents of this structure are copied, so the caller
 *     does not need to maintain its instance.
 * @return 0 on success, negative on failure
 */
int axolotl_context_set_crypto_provider(axolotl_context *context, const axolotl_crypto_provider *crypto_provider);

/**
 * Set the locking functions to be used by the AXOLOTL library for
 * synchronization.
 *
 * Note: These functions must allow recursive locking (e.g. PTHREAD_MUTEX_RECURSIVE)
 *
 * @param lock function to lock a mutex
 * @param unlock function to unlock a mutex
 * @return 0 on success, negative on failure
 */
int axolotl_context_set_locking_functions(axolotl_context *context,
        void (*lock)(void *user_data), void (*unlock)(void *user_data));

/**
 * Set the log function to be used by the AXOLOTL library for logging.
 *
 * @return 0 on success, negative on failure
 */
int axolotl_context_set_log_function(axolotl_context *context,
        void (*log)(int level, const char *message, size_t len, void *user_data));

void axolotl_context_destroy(axolotl_context *context);

/**
 * Create a new instance of the AXOLOTL data store interface.
 */
int axolotl_store_context_create(axolotl_store_context **context, axolotl_context *global_context);

int axolotl_store_context_set_session_store(axolotl_store_context *context, const axolotl_session_store *store);
int axolotl_store_context_set_pre_key_store(axolotl_store_context *context, const axolotl_pre_key_store *store);
int axolotl_store_context_set_signed_pre_key_store(axolotl_store_context *context, const axolotl_signed_pre_key_store *store);
int axolotl_store_context_set_identity_key_store(axolotl_store_context *context, const axolotl_identity_key_store *store);
int axolotl_store_context_set_sender_key_store(axolotl_store_context *context, const axolotl_sender_key_store *store);

void axolotl_store_context_destroy(axolotl_store_context *context);

/*
 * Interface to the session store.
 * These functions will use the callbacks in the provided
 * axolotl_store_context instance and operate in terms of higher level
 * library data structures.
 */

int axolotl_session_load_session(axolotl_store_context *context, session_record **record, const axolotl_address *address);
int axolotl_session_get_sub_device_sessions(axolotl_store_context *context, axolotl_int_list **sessions, const char *name, size_t name_len);
int axolotl_session_store_session(axolotl_store_context *context, const axolotl_address *address, session_record *record);
int axolotl_session_contains_session(axolotl_store_context *context, const axolotl_address *address);
int axolotl_session_delete_session(axolotl_store_context *context, const axolotl_address *address);
int axolotl_session_delete_all_sessions(axolotl_store_context *context, const char *name, size_t name_len);


/*
 * Interface to the pre-key store.
 * These functions will use the callbacks in the provided
 * axolotl_store_context instance and operate in terms of higher level
 * library data structures.
 */

int axolotl_pre_key_load_key(axolotl_store_context *context, session_pre_key **pre_key, uint32_t pre_key_id);
int axolotl_pre_key_store_key(axolotl_store_context *context, session_pre_key *pre_key);
int axolotl_pre_key_contains_key(axolotl_store_context *context, uint32_t pre_key_id);
int axolotl_pre_key_remove_key(axolotl_store_context *context, uint32_t pre_key_id);


/*
 * Interface to the signed pre-key store.
 * These functions will use the callbacks in the provided
 * axolotl_store_context instance and operate in terms of higher level
 * library data structures.
 */

int axolotl_signed_pre_key_load_key(axolotl_store_context *context, session_signed_pre_key **pre_key, uint32_t signed_pre_key_id);
int axolotl_signed_pre_key_store_key(axolotl_store_context *context, session_signed_pre_key *pre_key);
int axolotl_signed_pre_key_contains_key(axolotl_store_context *context, uint32_t signed_pre_key_id);
int axolotl_signed_pre_key_remove_key(axolotl_store_context *context, uint32_t signed_pre_key_id);


/*
 * Interface to the identity key store.
 * These functions will use the callbacks in the provided
 * axolotl_store_context instance and operate in terms of higher level
 * library data structures.
 */

int axolotl_identity_get_key_pair(axolotl_store_context *context, ratchet_identity_key_pair **key_pair);
int axolotl_identity_get_local_registration_id(axolotl_store_context *context, uint32_t *registration_id);
int axolotl_identity_save_identity(axolotl_store_context *context, const char *name, size_t name_len, ec_public_key *identity_key);
int axolotl_identity_is_trusted_identity(axolotl_store_context *context, const char *name, size_t name_len, ec_public_key *identity_key);


/*
 * Interface to the sender key store.
 * These functions will use the callbacks in the provided
 * axolotl_store_context instance and operate in terms of higher level
 * library data structures.
 */

int axolotl_sender_key_store_key(axolotl_store_context *context, const axolotl_sender_key_name *sender_key_name, sender_key_record *record);
int axolotl_sender_key_load_key(axolotl_store_context *context, sender_key_record **record, const axolotl_sender_key_name *sender_key_name);

#ifdef __cplusplus
}
#endif

#endif /* AXOLOTL_H */
