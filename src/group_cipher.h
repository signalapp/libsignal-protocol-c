#ifndef GROUP_CIPHER_H
#define GROUP_CIPHER_H

#include <stdint.h>
#include <stddef.h>
#include "axolotl_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * The main entry point for Axolotl group encrypt/decrypt operations.
 *
 * Once a session has been established with group_session_builder and a
 * sender_key_distribution_message has been distributed to each member of
 * the group, this class can be used for all subsequent encrypt/decrypt
 * operations within that session (i.e. until group membership changes).
 */

/**
 * Construct a group cipher for encrypt/decrypt operations.
 *
 * The store and global contexts must remain valid for the lifetime of the
 * group cipher.
 *
 * When finished, free the returned instance by calling group_cipher_free().
 *
 * @param cipher set to a freshly allocated group cipher instance
 * @param store the axolotl_store_context to store all state information in
 * @param sender_key_id the sender that messages will be encrypted to or decrypted from
 * @param global_context the global library context
 * @return 0 on success, or negative on failure
 */
int group_cipher_create(group_cipher **cipher,
        axolotl_store_context *store, const axolotl_sender_key_name *sender_key_id,
        axolotl_context *global_context);

/**
 * Set the optional user data pointer for the group cipher.
 *
 * This is to give callback functions a way of accessing app specific
 * context information for this cipher.
 */
void group_cipher_set_user_data(group_cipher *cipher, void *user_data);

/**
 * Get the optional user data pointer for the group cipher.
 *
 * This is to give callback functions a way of accessing app specific
 * context information for this cipher.
 */
void *group_cipher_get_user_data(group_cipher *cipher);

/**
 * Set the callback function that is called during the decrypt process.
 *
 * The callback function is called from within group_cipher_decrypt() after
 * decryption is complete but before the updated session state has been
 * committed to the session store. If the callback function returns a
 * negative value, then the decrypt function will immediately fail with
 * an error.
 *
 * This a callback allows some implementations to store the committed plaintext
 * to their local message store first, in case they are concerned with a crash
 * or write error happening between the time the session state is updated but
 * before they're able to successfully store the plaintext to disk.
 *
 * @param callback the callback function to set
 * @param user_data user data pointer provided to the callback
 */
void group_cipher_set_decryption_callback(group_cipher *cipher,
        int (*callback)(group_cipher *cipher, axolotl_buffer *plaintext, void *decrypt_context));

/**
 * Encrypt a message.
 *
 * @param padded_message The plaintext message bytes, optionally padded to a constant multiple.
 * @param padded_message_len The length of the data pointed to by padded_message
 * @param encrypted_message Set to a ciphertext message encrypted to the group+sender+device tuple.
 *
 * @return AX_SUCCESS on success, negative on error
 */
int group_cipher_encrypt(group_cipher *cipher,
        const uint8_t *padded_plaintext, size_t padded_plaintext_len,
        ciphertext_message **encrypted_message);

/**
 * Decrypt a message.
 *
 * @param ciphertext The sender_key_message to decrypt.
 * @param decrypt_context Optional context pointer associated with the
 *   ciphertext, which is passed to the decryption callback function
 * @param plaintext Set to a newly allocated buffer containing the plaintext.
 *
 * @retval AX_SUCCESS Success
 * @retval AX_ERR_INVALID_MESSAGE if the input is not valid ciphertext.
 * @retval AX_ERR_DUPLICATE_MESSAGE if the input is a message that has already been received.
 * @retval AX_ERR_LEGACY_MESSAGE if the input is a message formatted by a protocol version that
 *                               is no longer supported.
 * @retval AX_ERR_NO_SESSION if there is no established session for this contact.
 */
int group_cipher_decrypt(group_cipher *cipher,
        sender_key_message *ciphertext, void *decrypt_context,
        axolotl_buffer **plaintext);

void group_cipher_free(group_cipher *cipher);

#ifdef __cplusplus
}
#endif

#endif /* GROUP_CIPHER_H */
