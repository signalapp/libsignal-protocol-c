#ifndef SESSION_BUILDER_H
#define SESSION_BUILDER_H

#include <stdint.h>
#include "axolotl_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Session builder is responsible for setting up encrypted sessions.
 * Once a session has been established, session_cipher
 * can be used to encrypt/decrypt messages in that session.
 *
 * Sessions are built from one of three different possible vectors:
 * - A session_pre_key_bundle retrieved from a server
 * - A pre_key_whisper_message received from a client
 * - A key_exchange_message sent to or received from a client
 *
 * Sessions are constructed per AXOLOTL address
 * (recipient name + device ID tuple). Remote logical users are identified by
 * their recipient name, and each logical recipient can have multiple
 * physical devices.
 */

/**
 * Constructs a session builder.
 *
 * The store and global contexts must remain valid for the lifetime of the
 * session builder.
 *
 * When finished, free the returned instance by calling session_builder_free().
 *
 * @param builder set to a freshly allocated session builder instance
 * @param store the axolotl_store_context to store all state information in
 * @param remote_address the address of the remote user to build a session with
 * @param global_context the global library context
 * @return 0 on success, or negative on failure
 */
int session_builder_create(session_builder **builder,
        axolotl_store_context *store, const axolotl_address *remote_address,
        axolotl_context *global_context);

/**
 * Build a new session from a received pre_key_whisper_message.
 *
 * After a session is constructed in this way, the embedded whisper_message
 * can be decrypted.
 *
 * @param message The received pre_key_whisper_message.
 * @param unsigned_pre_key_id set to the unsigned pre key ID, if available.
 *     Return value indicates whether or not this value is available.
 * @retval 0 Success, no unsigned pre key value available
 * @retval 1 Success, an unsigned pre key is available
 * @retval AX_ERR_INVALID_KEY_ID when there is no local pre_key_record that
 *                               corresponds to the PreKey ID in the message.
 * @retval AX_ERR_INVALID_KEY when the message is formatted incorrectly.
 * @retval AX_ERR_UNTRUSTED_IDENTITY when the identity key of the sender is untrusted.
 */
int session_builder_process_pre_key_whisper_message(session_builder *builder,
        session_record *record, pre_key_whisper_message *message, uint32_t *unsigned_pre_key_id);

/**
 * Build a new session from a session_pre_key_bundle retrieved from a server.
 *
 * @param bundle A pre key bundle for the destination recipient, retrieved from a server.
 * @retval AX_SUCCESS Success
 * @retval AX_ERR_INVALID_KEY when the session_pre_key_bundle is badly formatted.
 * @retval AX_ERR_UNTRUSTED_IDENTITY when the sender's identity key is not trusted.
 */
int session_builder_process_pre_key_bundle(session_builder *builder, session_pre_key_bundle *bundle);

/**
 * Build a new session from a key_exchange_message received from a remote client.
 *
 * @param message The received key_exchange_message.
 * @param response_message Set to the key_exchange_message to respond with,
 *     or set to 0 if no response is necessary.
 * @retval AX_SUCCESS Success
 * @retval AX_ERR_INVALID_KEY if the received key_exchange_message is badly formatted.
 * @retval AX_ERR_UNTRUSTED_IDENTITY
 * @retval AX_ERR_STALE_KEY_EXCHANGE
 */
int session_builder_process_key_exchange_message(session_builder *builder, key_exchange_message *message, key_exchange_message **response_message);

/**
 * Initiate a new session by sending an initial key_exchange_message to the recipient.
 *
 * @param message Set to the key_exchange_message to deliver.
 * @return AX_SUCCESS on success, negative on error
 */
int session_builder_process(session_builder *builder, key_exchange_message **message);

void session_builder_free(session_builder *builder);

#ifdef __cplusplus
}
#endif

#endif /* SESSION_BUILDER_H */
