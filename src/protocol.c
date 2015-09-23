#include "protocol.h"

#include <string.h>
#include <assert.h>

#include "axolotl_internal.h"
#include "curve.h"
#include "WhisperTextProtocol.pb-c.h"

#define WHISPER_MESSAGE_MAC_LENGTH 8
#define SIGNATURE_LENGTH 64

struct key_exchange_message
{
    axolotl_type_base base;

    uint8_t version;
    uint8_t supported_version;
    uint32_t sequence;
    uint32_t flags;

    ec_public_key *base_key;
    uint8_t base_key_signature[CURVE_SIGNATURE_LEN];

    ec_public_key *ratchet_key;
    ec_public_key *identity_key;

    axolotl_buffer *serialized;
};

struct ciphertext_message
{
    axolotl_type_base base;
    int message_type;
    axolotl_context *global_context;
    axolotl_buffer *serialized;
};

struct whisper_message
{
    ciphertext_message base_message;
    uint8_t message_version;
    ec_public_key *sender_ratchet_key;
    uint32_t counter;
    uint32_t previous_counter;
    axolotl_buffer *ciphertext;
};

struct pre_key_whisper_message
{
    ciphertext_message base_message;
    uint8_t version;
    uint32_t registration_id;
    int has_pre_key_id;
    uint32_t pre_key_id;
    uint32_t signed_pre_key_id;
    ec_public_key *base_key;
    ec_public_key *identity_key;
    whisper_message *message;
};

struct sender_key_message
{
    ciphertext_message base_message;
    uint8_t message_version;
    uint32_t key_id;
    uint32_t iteration;
    axolotl_buffer *ciphertext;
};

struct sender_key_distribution_message
{
    ciphertext_message base_message;
    uint32_t id;
    uint32_t iteration;
    axolotl_buffer *chain_key;
    ec_public_key *signature_key;
};

static int key_exchange_message_serialize(axolotl_buffer **buffer, const key_exchange_message *message);

static int whisper_message_serialize(axolotl_buffer **buffer, const whisper_message *message);
static int whisper_message_get_mac(axolotl_buffer **buffer,
        uint8_t message_version,
        ec_public_key *sender_identity_key,
        ec_public_key *receiver_identity_key,
        const uint8_t *mac_key, size_t mac_key_len,
        const uint8_t *serialized, size_t serialized_len,
        axolotl_context *global_context);

static int pre_key_whisper_message_serialize(axolotl_buffer **buffer, const pre_key_whisper_message *message);

static int sender_key_message_serialize(axolotl_buffer **buffer, const sender_key_message *message, ec_private_key *signature_key, axolotl_context *global_context);
static int sender_key_distribution_message_serialize(axolotl_buffer **buffer, const sender_key_distribution_message *message);

int key_exchange_message_create(key_exchange_message **message,
        uint8_t message_version, uint32_t sequence, uint32_t flags,
        ec_public_key *base_key, uint8_t *base_key_signature,
        ec_public_key *ratchet_key, ec_public_key *identity_key)
{
    int result = 0;
    key_exchange_message *result_message = 0;

    result_message = malloc(sizeof(key_exchange_message));
    if(!result_message) {
        result = AX_ERR_NOMEM;
        goto complete;
    }
    memset(result_message, 0, sizeof(key_exchange_message));
    AXOLOTL_INIT(result_message, key_exchange_message_destroy);

    result_message->supported_version = CIPHERTEXT_CURRENT_VERSION;
    result_message->version = message_version;
    result_message->sequence = sequence;
    result_message->flags = flags;

    AXOLOTL_REF(base_key);
    result_message->base_key = base_key;

    memcpy(result_message->base_key_signature, base_key_signature, sizeof(result_message->base_key_signature));

    AXOLOTL_REF(ratchet_key);
    result_message->ratchet_key = ratchet_key;

    AXOLOTL_REF(identity_key);
    result_message->identity_key = identity_key;

    result = key_exchange_message_serialize(&result_message->serialized, result_message);
    if(result < 0) {
        goto complete;
    }
    result = 0;

complete:
    if(result >= 0) {
        *message = result_message;
    }
    else {
        if(result_message) {
            AXOLOTL_UNREF(result_message);
        }
    }
    return result;
}

static int key_exchange_message_serialize(axolotl_buffer **buffer, const key_exchange_message *message)
{
    int result = 0;
    size_t result_size = 0;
    axolotl_buffer *result_buf = 0;
    Textsecure__KeyExchangeMessage message_structure = TEXTSECURE__KEY_EXCHANGE_MESSAGE__INIT;
    size_t len = 0;
    uint8_t *data = 0;

    uint8_t version = (message->version << 4) | message->supported_version;

    message_structure.has_id = 1;
    message_structure.id = (message->sequence << 5) | message->flags;

    if(message->base_key) {
        message_structure.has_basekey = 1;
        result = ec_public_key_serialize_protobuf(&message_structure.basekey, message->base_key);
        if(result < 0) {
            goto complete;
        }
    }

    if(message->ratchet_key) {
        message_structure.has_ratchetkey = 1;
        result = ec_public_key_serialize_protobuf(&message_structure.ratchetkey, message->ratchet_key);
        if(result < 0) {
            goto complete;
        }
    }

    if(message->identity_key) {
        message_structure.has_identitykey = 1;
        result = ec_public_key_serialize_protobuf(&message_structure.identitykey, message->identity_key);
        if(result < 0) {
            goto complete;
        }
    }

    if(message->version >= 3) {
        message_structure.has_basekeysignature = 1;
        message_structure.basekeysignature.len = sizeof(message->base_key_signature);
        message_structure.basekeysignature.data = malloc(message_structure.basekeysignature.len);
        if(!message_structure.basekeysignature.data) {
            result = AX_ERR_NOMEM;
            goto complete;
        }
        memcpy(message_structure.basekeysignature.data, message->base_key_signature, message_structure.basekeysignature.len);
    }

    len = textsecure__key_exchange_message__get_packed_size(&message_structure);

    result_buf = axolotl_buffer_alloc(len + 1);
    if(!result_buf) {
        result = AX_ERR_NOMEM;
        goto complete;
    }

    data = axolotl_buffer_data(result_buf);
    data[0] = version;

    result_size = textsecure__key_exchange_message__pack(&message_structure, data + 1);
    if(result_size != len) {
        axolotl_buffer_free(result_buf);
        result = AX_ERR_INVALID_PROTO_BUF;
        result_buf = 0;
        goto complete;
    }

complete:
    if(message_structure.basekey.data) {
        free(message_structure.basekey.data);
    }
    if(message_structure.ratchetkey.data) {
        free(message_structure.ratchetkey.data);
    }
    if(message_structure.identitykey.data) {
        free(message_structure.identitykey.data);
    }
    if(message_structure.basekeysignature.data) {
        free(message_structure.basekeysignature.data);
    }
    if(result >= 0) {
        *buffer = result_buf;
    }
    return result;
}

int key_exchange_message_deserialize(key_exchange_message **message, const uint8_t *data, size_t len, axolotl_context *global_context)
{
    int result = 0;
    key_exchange_message *result_message = 0;
    Textsecure__KeyExchangeMessage *message_structure = 0;
    uint8_t version = 0;
    uint8_t supported_version = 0;

    if(!data || len <= 1) {
        result = AX_ERR_INVAL;
        goto complete;
    }

    version = (data[0] & 0xF0) >> 4;
    supported_version = data[0] & 0x0F;

    if(version <= CIPHERTEXT_UNSUPPORTED_VERSION) {
        axolotl_log(global_context, AX_LOG_WARNING, "Unsupported legacy version: %d", version);
        result = AX_ERR_LEGACY_MESSAGE;
        goto complete;
    }

    if(version > CIPHERTEXT_CURRENT_VERSION) {
        axolotl_log(global_context, AX_LOG_WARNING, "Unknown version: %d", version);
        result = AX_ERR_INVALID_VERSION;
        goto complete;
    }

    message_structure = textsecure__key_exchange_message__unpack(0, len - 1, data + 1);
    if(!message_structure) {
        result = AX_ERR_INVALID_PROTO_BUF;
        goto complete;
    }

    if(!message_structure->has_id || !message_structure->has_basekey
            || !message_structure->has_ratchetkey || !message_structure->has_identitykey
            || (version >= 3 && !message_structure->has_basekeysignature)) {
        axolotl_log(global_context, AX_LOG_WARNING, "Some required fields missing");
        result = AX_ERR_INVALID_MESSAGE;
        goto complete;
    }

    if(message_structure->has_basekeysignature && message_structure->basekeysignature.len != CURVE_SIGNATURE_LEN) {
        axolotl_log(global_context, AX_LOG_WARNING, "Invalid base key signature length: %d", message_structure->basekeysignature.len);
        result = AX_ERR_INVALID_MESSAGE;
        goto complete;
    }

    result_message = malloc(sizeof(key_exchange_message));
    if(!result_message) {
        result = AX_ERR_NOMEM;
        goto complete;
    }
    memset(result_message, 0, sizeof(key_exchange_message));
    AXOLOTL_INIT(result_message, key_exchange_message_destroy);

    result_message->version = version;
    result_message->supported_version = supported_version;
    result_message->sequence = message_structure->id >> 5;
    result_message->flags = message_structure->id & 0x1F;

    result = curve_decode_point(&result_message->base_key,
            message_structure->basekey.data, message_structure->basekey.len, global_context);
    if(result < 0) {
        goto complete;
    }

    if(message_structure->has_basekeysignature) {
        memcpy(result_message->base_key_signature,
                message_structure->basekeysignature.data,
                message_structure->basekeysignature.len);
    }

    result = curve_decode_point(&result_message->ratchet_key,
            message_structure->ratchetkey.data, message_structure->ratchetkey.len, global_context);
    if(result < 0) {
        goto complete;
    }

    result = curve_decode_point(&result_message->identity_key,
            message_structure->identitykey.data, message_structure->identitykey.len, global_context);
    if(result < 0) {
        goto complete;
    }

    result_message->serialized = axolotl_buffer_alloc(len);
    if(!result_message->serialized) {
        result = AX_ERR_NOMEM;
        goto complete;
    }
    memcpy(result_message->serialized, data, len);

complete:
    if(message_structure) {
        textsecure__key_exchange_message__free_unpacked(message_structure, 0);
    }
    if(result >= 0) {
        *message = result_message;
    }
    else {
        if(result_message) {
            AXOLOTL_UNREF(result_message);
        }
    }
    return result;
}

axolotl_buffer *key_exchange_message_get_serialized(const key_exchange_message *message)
{
    assert(message);
    assert(message->serialized);
    return message->serialized;
}

uint8_t key_exchange_message_get_version(const key_exchange_message *message)
{
    assert(message);
    return message->version;
}

ec_public_key *key_exchange_message_get_base_key(const key_exchange_message *message)
{
    assert(message);
    return message->base_key;
}

uint8_t *key_exchange_message_get_base_key_signature(key_exchange_message *message)
{
    assert(message);
    return message->base_key_signature;
}

ec_public_key *key_exchange_message_get_ratchet_key(const key_exchange_message *message)
{
    assert(message);
    return message->ratchet_key;
}

ec_public_key *key_exchange_message_get_identity_key(const key_exchange_message *message)
{
    assert(message);
    return message->identity_key;
}

int key_exchange_message_has_identity_key(const key_exchange_message *message)
{
    assert(message);
    return 1;
}

uint8_t key_exchange_message_get_max_version(const key_exchange_message *message)
{
    assert(message);
    return message->supported_version;
}

int key_exchange_message_is_response(const key_exchange_message *message)
{
    assert(message);
    return (message->flags & KEY_EXCHANGE_RESPONSE_FLAG) != 0;
}

int key_exchange_message_is_initiate(const key_exchange_message *message)
{
    assert(message);
    return (message->flags & KEY_EXCHANGE_INITIATE_FLAG) != 0;
}

int key_exchange_message_is_response_for_simultaneous_initiate(const key_exchange_message *message)
{
    assert(message);
    return (message->flags & KEY_EXCHANGE_SIMULTAENOUS_INITIATE_FLAG) != 0;
}

uint32_t key_exchange_message_get_flags(const key_exchange_message *message)
{
    assert(message);
    return message->flags;
}

uint32_t key_exchange_message_get_sequence(const key_exchange_message *message)
{
    assert(message);
    return message->sequence;
}

void key_exchange_message_destroy(axolotl_type_base *type)
{
    key_exchange_message *message = (key_exchange_message *)type;
    AXOLOTL_UNREF(message->base_key);
    AXOLOTL_UNREF(message->ratchet_key);
    AXOLOTL_UNREF(message->identity_key);
    if(message->serialized) {
        axolotl_buffer_free(message->serialized);
    }
    free(message);
}

/*------------------------------------------------------------------------*/

int ciphertext_message_get_type(const ciphertext_message *message)
{
    assert(message);
    return message->message_type;
}

axolotl_buffer *ciphertext_message_get_serialized(const ciphertext_message *message)
{
    assert(message);
    return message->serialized;
}

/*------------------------------------------------------------------------*/

int whisper_message_create(whisper_message **message, uint8_t message_version,
        const uint8_t *mac_key, size_t mac_key_len,
        ec_public_key *sender_ratchet_key, uint32_t counter, uint32_t previous_counter,
        const uint8_t *ciphertext, size_t ciphertext_len,
        ec_public_key *sender_identity_key, ec_public_key *receiver_identity_key,
        axolotl_context *global_context)
{
    int result = 0;
    axolotl_buffer *message_buf = 0;
    axolotl_buffer *mac_buf = 0;
    whisper_message *result_message = 0;

    assert(global_context);

    result_message = malloc(sizeof(whisper_message));
    if(!result_message) {
        return AX_ERR_NOMEM;
    }
    memset(result_message, 0, sizeof(whisper_message));
    AXOLOTL_INIT(result_message, whisper_message_destroy);

    result_message->base_message.message_type = CIPHERTEXT_WHISPER_TYPE;
    result_message->base_message.global_context = global_context;

    AXOLOTL_REF(sender_ratchet_key);
    result_message->sender_ratchet_key = sender_ratchet_key;

    result_message->counter = counter;
    result_message->previous_counter = previous_counter;

    result_message->ciphertext = axolotl_buffer_create(ciphertext, ciphertext_len);
    if(!result_message->ciphertext) {
        result = AX_ERR_NOMEM;
        goto complete;
    }

    result_message->message_version = message_version;

    result = whisper_message_serialize(&message_buf, result_message);
    if(result < 0) {
        goto complete;
    }

    result = whisper_message_get_mac(&mac_buf,
            message_version, sender_identity_key, receiver_identity_key,
            mac_key, mac_key_len,
            axolotl_buffer_data(message_buf),
            axolotl_buffer_len(message_buf),
            global_context);
    if(result < 0) {
        goto complete;
    }

    result_message->base_message.serialized = axolotl_buffer_append(
            message_buf,
            axolotl_buffer_data(mac_buf),
            axolotl_buffer_len(mac_buf));
    if(result_message->base_message.serialized) {
        message_buf = 0;
    }
    else {
        result = AX_ERR_NOMEM;
    }

complete:
    if(message_buf) {
        axolotl_buffer_free(message_buf);
    }
    if(mac_buf) {
        axolotl_buffer_free(mac_buf);
    }
    if(result >= 0) {
        result = 0;
        *message = result_message;
    }
    else {
        if(result_message) {
            AXOLOTL_UNREF(result_message);
        }
    }
    return result;
}

static int whisper_message_serialize(axolotl_buffer **buffer, const whisper_message *message)
{
    int result = 0;
    size_t result_size = 0;
    axolotl_buffer *result_buf = 0;
    Textsecure__WhisperMessage message_structure = TEXTSECURE__WHISPER_MESSAGE__INIT;
    size_t len = 0;
    uint8_t *data = 0;

    uint8_t version = (message->message_version << 4) | CIPHERTEXT_CURRENT_VERSION;

    result = ec_public_key_serialize_protobuf(&message_structure.ratchetkey, message->sender_ratchet_key);
    if(result < 0) {
        goto complete;
    }
    message_structure.has_ratchetkey = 1;

    message_structure.counter = message->counter;
    message_structure.has_counter = 1;

    message_structure.previouscounter = message->previous_counter;
    message_structure.has_previouscounter = 1;

    message_structure.ciphertext.data = axolotl_buffer_data(message->ciphertext);
    message_structure.ciphertext.len = axolotl_buffer_len(message->ciphertext);
    message_structure.has_ciphertext = 1;

    len = textsecure__whisper_message__get_packed_size(&message_structure);

    result_buf = axolotl_buffer_alloc(len + 1);
    if(!result_buf) {
        result = AX_ERR_NOMEM;
        goto complete;
    }

    data = axolotl_buffer_data(result_buf);
    data[0] = version;

    result_size = textsecure__whisper_message__pack(&message_structure, data + 1);
    if(result_size != len) {
        axolotl_buffer_free(result_buf);
        result = AX_ERR_INVALID_PROTO_BUF;
        result_buf = 0;
        goto complete;
    }

complete:
    if(message_structure.ratchetkey.data) {
        free(message_structure.ratchetkey.data);
    }
    if(result >= 0) {
        *buffer = result_buf;
    }
    return result;
}

int whisper_message_deserialize(whisper_message **message, const uint8_t *data, size_t len, axolotl_context *global_context)
{
    int result = 0;
    whisper_message *result_message = 0;
    Textsecure__WhisperMessage *message_structure = 0;
    uint8_t version = 0;
    uint8_t *ciphertext_data = 0;
    uint8_t *serialized_data = 0;
    const uint8_t *message_data = 0;
    size_t message_len = 0;

    assert(global_context);

    if(!data || len <= 1 + WHISPER_MESSAGE_MAC_LENGTH) {
        result = AX_ERR_INVAL;
        goto complete;
    }

    version = (data[0] & 0xF0) >> 4;

    /* Set some pointers and lengths for the sections of the raw data */
    message_data = data + 1;
    message_len = len - 1 - WHISPER_MESSAGE_MAC_LENGTH;

    if(version <= CIPHERTEXT_UNSUPPORTED_VERSION) {
        axolotl_log(global_context, AX_LOG_WARNING, "Unsupported legacy version: %d", version);
        result = AX_ERR_LEGACY_MESSAGE;
        goto complete;
    }

    if(version > CIPHERTEXT_CURRENT_VERSION) {
        axolotl_log(global_context, AX_LOG_WARNING, "Unknown version: %d", version);
        result = AX_ERR_INVALID_MESSAGE;
        goto complete;
    }

    message_structure = textsecure__whisper_message__unpack(0, message_len, message_data);
    if(!message_structure) {
        result = AX_ERR_INVALID_PROTO_BUF;
        goto complete;
    }

    if(!message_structure->has_ciphertext
            || !message_structure->has_counter
            || !message_structure->has_ratchetkey) {
        axolotl_log(global_context, AX_LOG_WARNING, "Incomplete message");
        result = AX_ERR_INVALID_MESSAGE;
        goto complete;
    }

    result_message = malloc(sizeof(whisper_message));
    if(!result_message) {
        result = AX_ERR_NOMEM;
        goto complete;
    }
    memset(result_message, 0, sizeof(whisper_message));
    AXOLOTL_INIT(result_message, whisper_message_destroy);

    result_message->base_message.message_type = CIPHERTEXT_WHISPER_TYPE;
    result_message->base_message.global_context = global_context;

    result = curve_decode_point(&result_message->sender_ratchet_key,
            message_structure->ratchetkey.data, message_structure->ratchetkey.len, global_context);
    if(result < 0) {
        goto complete;
    }

    result_message->message_version = version;
    result_message->counter = message_structure->counter;
    result_message->previous_counter = message_structure->previouscounter;

    result_message->ciphertext = axolotl_buffer_alloc(message_structure->ciphertext.len);
    if(!result_message->ciphertext) {
        result = AX_ERR_NOMEM;
        goto complete;
    }
    ciphertext_data = axolotl_buffer_data(result_message->ciphertext);
    memcpy(ciphertext_data, message_structure->ciphertext.data, message_structure->ciphertext.len);

    result_message->base_message.serialized = axolotl_buffer_alloc(len);
    if(!result_message->base_message.serialized) {
        result = AX_ERR_NOMEM;
        goto complete;
    }
    serialized_data = axolotl_buffer_data(result_message->base_message.serialized);
    memcpy(serialized_data, data, len);

complete:
    if(message_structure) {
        textsecure__whisper_message__free_unpacked(message_structure, 0);
    }
    if(result >= 0) {
        *message = result_message;
    }
    else {
        if(result_message) {
            AXOLOTL_UNREF(result_message);
        }
    }
    return result;
}

int whisper_message_copy(whisper_message **message, whisper_message *other_message, axolotl_context *global_context)
{
    int result = 0;
    whisper_message *result_message = 0;

    assert(other_message);
    assert(global_context);

    result = whisper_message_deserialize(
            &result_message,
            axolotl_buffer_data(other_message->base_message.serialized),
            axolotl_buffer_len(other_message->base_message.serialized),
            global_context);
    if(result >= 0) {
        *message = result_message;
    }

    return result;
}

ec_public_key *whisper_message_get_sender_ratchet_key(const whisper_message *message)
{
    assert(message);
    return message->sender_ratchet_key;
}

uint8_t whisper_message_get_message_version(const whisper_message *message)
{
    assert(message);
    return message->message_version;
}

uint32_t whisper_message_get_counter(const whisper_message *message)
{
    assert(message);
    return message->counter;
}

axolotl_buffer *whisper_message_get_body(const whisper_message *message)
{
    assert(message);
    return message->ciphertext;
}

int whisper_message_verify_mac(whisper_message *message,
        uint8_t message_version,
        ec_public_key *sender_identity_key,
        ec_public_key *receiver_identity_key,
        const uint8_t *mac_key, size_t mac_key_len,
        axolotl_context *global_context)
{
    int result = 0;
    axolotl_buffer *our_mac_buffer = 0;
    uint8_t *serialized_data = 0;
    size_t serialized_len = 0;
    uint8_t *serialized_message_data = 0;
    size_t serialized_message_len = 0;
    uint8_t *their_mac_data = 0;
    const size_t their_mac_len = WHISPER_MESSAGE_MAC_LENGTH;
    uint8_t *our_mac_data = 0;
    size_t our_mac_len = 0;

    assert(message);
    assert(message->base_message.serialized);

    /* Set some pointers and lengths for the sections of the raw data */
    serialized_data = axolotl_buffer_data(message->base_message.serialized);
    serialized_len = axolotl_buffer_len(message->base_message.serialized);
    serialized_message_data = serialized_data;
    serialized_message_len = serialized_len - WHISPER_MESSAGE_MAC_LENGTH;
    their_mac_data = serialized_data + serialized_message_len;

    result = whisper_message_get_mac(&our_mac_buffer,
            message->message_version,
            sender_identity_key, receiver_identity_key,
            mac_key, mac_key_len,
            serialized_message_data, serialized_message_len,
            message->base_message.global_context);
    if(result < 0) {
        goto complete;
    }

    our_mac_data = axolotl_buffer_data(our_mac_buffer);
    our_mac_len = axolotl_buffer_len(our_mac_buffer);
    if(our_mac_len != their_mac_len) {
        axolotl_log(global_context, AX_LOG_WARNING, "MAC length mismatch: %d != %d", our_mac_len, their_mac_len);
        result = AX_ERR_UNKNOWN;
        goto complete;
    }

    if(axolotl_constant_memcmp(our_mac_data, their_mac_data, our_mac_len) == 0) {
        result = 1;
    }
    else {
        axolotl_log(global_context, AX_LOG_NOTICE, "Bad MAC");
        result = 0;
    }

complete:
    if(our_mac_buffer) {
        axolotl_buffer_free(our_mac_buffer);
    }
    return result;
}

static int whisper_message_get_mac(axolotl_buffer **buffer,
        uint8_t message_version,
        ec_public_key *sender_identity_key,
        ec_public_key *receiver_identity_key,
        const uint8_t *mac_key, size_t mac_key_len,
        const uint8_t *serialized, size_t serialized_len,
        axolotl_context *global_context)
{
    int result = 0;
    void *hmac_context;
    axolotl_buffer *sender_key_buffer = 0;
    axolotl_buffer *receiver_key_buffer = 0;
    axolotl_buffer *full_mac_buffer = 0;
    axolotl_buffer *result_buf = 0;
    uint8_t *result_data = 0;

    assert(global_context);

    result = axolotl_hmac_sha256_init(global_context,
            &hmac_context, mac_key, mac_key_len);
    if(result < 0) {
        goto complete;
    }

    if(message_version >= 3) {
        result = ec_public_key_serialize(&sender_key_buffer, sender_identity_key);
        if(result < 0) {
            goto complete;
        }

        result = axolotl_hmac_sha256_update(global_context, hmac_context,
                axolotl_buffer_data(sender_key_buffer),
                axolotl_buffer_len(sender_key_buffer));
        if(result < 0) {
            goto complete;
        }

        result = ec_public_key_serialize(&receiver_key_buffer, receiver_identity_key);
        if(result < 0) {
            goto complete;
        }

        result = axolotl_hmac_sha256_update(global_context, hmac_context,
                axolotl_buffer_data(receiver_key_buffer),
                axolotl_buffer_len(receiver_key_buffer));
        if(result < 0) {
            goto complete;
        }
    }

    result = axolotl_hmac_sha256_update(global_context, hmac_context,
        serialized, serialized_len);
    if(result < 0) {
        goto complete;
    }

    result = axolotl_hmac_sha256_final(global_context,
            hmac_context, &full_mac_buffer);
    if(result < 0 || axolotl_buffer_len(full_mac_buffer) < WHISPER_MESSAGE_MAC_LENGTH) {
        if(result >= 0) { result = AX_ERR_UNKNOWN; }
        goto complete;
    }

    result_buf = axolotl_buffer_alloc(WHISPER_MESSAGE_MAC_LENGTH);
    if(!result_buf) {
        result = AX_ERR_NOMEM;
        goto complete;
    }

    result_data = axolotl_buffer_data(result_buf);
    memcpy(result_data, axolotl_buffer_data(full_mac_buffer), WHISPER_MESSAGE_MAC_LENGTH);

complete:
    axolotl_hmac_sha256_cleanup(global_context, hmac_context);
    axolotl_buffer_free(sender_key_buffer);
    axolotl_buffer_free(receiver_key_buffer);
    axolotl_buffer_free(full_mac_buffer);
    if(result >= 0) {
        *buffer = result_buf;
    }
    return result;
}

int whisper_message_is_legacy(const uint8_t *data, size_t len)
{
    return data && len >= 1 && ((data[0] & 0xF0) >> 4) <= CIPHERTEXT_UNSUPPORTED_VERSION;
}

void whisper_message_destroy(axolotl_type_base *type)
{
    whisper_message *message = (whisper_message *)type;

    if(message->base_message.serialized) {
        axolotl_buffer_free(message->base_message.serialized);
    }
    AXOLOTL_UNREF(message->sender_ratchet_key);
    if(message->ciphertext) {
        axolotl_buffer_free(message->ciphertext);
    }
    free(message);
}

/*------------------------------------------------------------------------*/

int pre_key_whisper_message_create(pre_key_whisper_message **pre_key_message,
        uint8_t message_version, uint32_t registration_id, const uint32_t *pre_key_id,
        uint32_t signed_pre_key_id, ec_public_key *base_key, ec_public_key *identity_key,
        whisper_message *message,
        axolotl_context *global_context)
{
    int result = 0;
    pre_key_whisper_message *result_message = 0;

    assert(global_context);

    result_message = malloc(sizeof(pre_key_whisper_message));

    if(!result_message) {
        return AX_ERR_NOMEM;
    }
    memset(result_message, 0, sizeof(pre_key_whisper_message));
    AXOLOTL_INIT(result_message, pre_key_whisper_message_destroy);

    result_message->base_message.message_type = CIPHERTEXT_PREKEY_TYPE;
    result_message->base_message.global_context = global_context;

    result_message->version = message_version;
    result_message->registration_id = registration_id;
    if(pre_key_id) {
        result_message->has_pre_key_id = 1;
        result_message->pre_key_id = *pre_key_id;
    }
    result_message->signed_pre_key_id = signed_pre_key_id;

    AXOLOTL_REF(base_key);
    result_message->base_key = base_key;

    AXOLOTL_REF(identity_key);
    result_message->identity_key = identity_key;

    AXOLOTL_REF(message);
    result_message->message = message;

    result = pre_key_whisper_message_serialize(&result_message->base_message.serialized, result_message);

    if(result >= 0) {
        result = 0;
        *pre_key_message = result_message;
    }
    else {
        if(result_message) {
            AXOLOTL_UNREF(result_message);
        }
    }
    return result;
}

static int pre_key_whisper_message_serialize(axolotl_buffer **buffer, const pre_key_whisper_message *message)
{
    int result = 0;
    size_t result_size = 0;
    axolotl_buffer *result_buf = 0;
    Textsecure__PreKeyWhisperMessage message_structure = TEXTSECURE__PRE_KEY_WHISPER_MESSAGE__INIT;
    axolotl_buffer *inner_message_buffer = 0;
    size_t len = 0;
    uint8_t *data = 0;

    uint8_t version = (message->version << 4) | CIPHERTEXT_CURRENT_VERSION;

    message_structure.registrationid = message->registration_id;
    message_structure.has_registrationid = 1;

    if(message->has_pre_key_id) {
        message_structure.prekeyid = message->pre_key_id;
        message_structure.has_prekeyid = 1;
    }

    message_structure.signedprekeyid = message->signed_pre_key_id;
    message_structure.has_signedprekeyid = 1;

    result = ec_public_key_serialize_protobuf(&message_structure.basekey, message->base_key);
    if(result < 0) {
        goto complete;
    }
    message_structure.has_basekey = 1;

    result = ec_public_key_serialize_protobuf(&message_structure.identitykey, message->identity_key);
    if(result < 0) {
        goto complete;
    }
    message_structure.has_identitykey = 1;

    inner_message_buffer = message->message->base_message.serialized;
    message_structure.message.data = axolotl_buffer_data(inner_message_buffer);
    message_structure.message.len = axolotl_buffer_len(inner_message_buffer);
    message_structure.has_message = 1;

    len = textsecure__pre_key_whisper_message__get_packed_size(&message_structure);

    result_buf = axolotl_buffer_alloc(len + 1);
    if(!result_buf) {
        result = AX_ERR_NOMEM;
        goto complete;
    }

    data = axolotl_buffer_data(result_buf);
    data[0] = version;

    result_size = textsecure__pre_key_whisper_message__pack(&message_structure, data + 1);
    if(result_size != len) {
        axolotl_buffer_free(result_buf);
        result = AX_ERR_INVALID_PROTO_BUF;
        result_buf = 0;
        goto complete;
    }

complete:
    if(message_structure.basekey.data) {
        free(message_structure.basekey.data);
    }
    if(message_structure.identitykey.data) {
        free(message_structure.identitykey.data);
    }
    if(result >= 0) {
        *buffer = result_buf;
    }
    return result;
}

int pre_key_whisper_message_deserialize(pre_key_whisper_message **message,
        const uint8_t *data, size_t len,
        axolotl_context *global_context)
{
    int result = 0;
    pre_key_whisper_message *result_message = 0;
    Textsecure__PreKeyWhisperMessage *message_structure = 0;
    uint8_t version = 0;
    const uint8_t *message_data = 0;
    size_t message_len = 0;
    uint8_t *serialized_data = 0;

    assert(global_context);

    if(!data || len <= 1) {
        result = AX_ERR_INVAL;
        goto complete;
    }

    version = (data[0] & 0xF0) >> 4;

    /* Set some pointers and lengths for the sections of the raw data */
    message_data = data + 1;
    message_len = len - 1;

    if(version <= CIPHERTEXT_UNSUPPORTED_VERSION) {
        axolotl_log(global_context, AX_LOG_WARNING, "Unsupported legacy version: %d", version);
        result = AX_ERR_LEGACY_MESSAGE;
        goto complete;
    }

    if(version > CIPHERTEXT_CURRENT_VERSION) {
        axolotl_log(global_context, AX_LOG_WARNING, "Unknown version: %d", version);
        result = AX_ERR_INVALID_VERSION;
        goto complete;
    }

    message_structure = textsecure__pre_key_whisper_message__unpack(0, message_len, message_data);
    if(!message_structure) {
        result = AX_ERR_INVALID_PROTO_BUF;
        goto complete;
    }

    if((version == 2 && !message_structure->has_prekeyid) ||
            (version == 3 && !message_structure->has_signedprekeyid) ||
            !message_structure->has_basekey ||
            !message_structure->has_identitykey ||
            !message_structure->has_message) {
        axolotl_log(global_context, AX_LOG_WARNING, "Incomplete message");
        result = AX_ERR_INVALID_MESSAGE;
        goto complete;
    }

    result_message = malloc(sizeof(pre_key_whisper_message));
    if(!result_message) {
        result = AX_ERR_NOMEM;
        goto complete;
    }
    memset(result_message, 0, sizeof(pre_key_whisper_message));
    AXOLOTL_INIT(result_message, pre_key_whisper_message_destroy);

    result_message->base_message.message_type = CIPHERTEXT_PREKEY_TYPE;
    result_message->base_message.global_context = global_context;

    result_message->version = version;

    if(message_structure->has_registrationid) {
        result_message->registration_id = message_structure->registrationid;
    }

    if(message_structure->has_prekeyid) {
        result_message->pre_key_id = message_structure->prekeyid;
        result_message->has_pre_key_id = 1;
    }

    if(message_structure->has_signedprekeyid) {
        result_message->signed_pre_key_id = message_structure->signedprekeyid;
    }

    if(message_structure->has_basekey) {
        result = curve_decode_point(&result_message->base_key,
                message_structure->basekey.data, message_structure->basekey.len, global_context);
        if(result < 0) {
            goto complete;
        }
    }

    if(message_structure->has_identitykey) {
        result = curve_decode_point(&result_message->identity_key,
                message_structure->identitykey.data, message_structure->identitykey.len, global_context);
        if(result < 0) {
            goto complete;
        }
    }

    if(message_structure->has_message) {
        result = whisper_message_deserialize(&result_message->message,
                message_structure->message.data,
                message_structure->message.len,
                global_context);
        if(result < 0) {
            goto complete;
        }
        if(result_message->message->message_version != version) {
            axolotl_log(global_context, AX_LOG_WARNING, "Inner message version mismatch: %d != %d",
                    result_message->message->message_version, version);
            result = AX_ERR_INVALID_VERSION;
            goto complete;
        }
    }

    result_message->base_message.serialized = axolotl_buffer_alloc(len);
    if(!result_message->base_message.serialized) {
        result = AX_ERR_NOMEM;
        goto complete;
    }
    serialized_data = axolotl_buffer_data(result_message->base_message.serialized);
    memcpy(serialized_data, data, len);

complete:
    if(message_structure) {
        textsecure__pre_key_whisper_message__free_unpacked(message_structure, 0);
    }
    if(result >= 0) {
        *message = result_message;
    }
    else {
        if(result_message) {
            AXOLOTL_UNREF(result_message);
        }
    }
    return result;
}

int pre_key_whisper_message_copy(pre_key_whisper_message **message, pre_key_whisper_message *other_message, axolotl_context *global_context)
{
    int result = 0;
    pre_key_whisper_message *result_message = 0;

    assert(other_message);
    assert(global_context);

    result = pre_key_whisper_message_deserialize(
            &result_message,
            axolotl_buffer_data(other_message->base_message.serialized),
            axolotl_buffer_len(other_message->base_message.serialized),
            global_context);
    if(result >= 0) {
        *message = result_message;
    }

    return result;
}

uint8_t pre_key_whisper_message_get_message_version(const pre_key_whisper_message *message)
{
    assert(message);
    return message->version;
}

ec_public_key *pre_key_whisper_message_get_identity_key(const pre_key_whisper_message *message)
{
    assert(message);
    return message->identity_key;
}

uint32_t pre_key_whisper_message_get_registration_id(const pre_key_whisper_message *message)
{
    assert(message);
    return message->registration_id;
}

int pre_key_whisper_message_has_pre_key_id(const pre_key_whisper_message *message)
{
    assert(message);
    return message->has_pre_key_id;
}

uint32_t pre_key_whisper_message_get_pre_key_id(const pre_key_whisper_message *message)
{
    assert(message);
    assert(message->has_pre_key_id);
    return message->pre_key_id;
}

uint32_t pre_key_whisper_message_get_signed_pre_key_id(const pre_key_whisper_message *message)
{
    assert(message);
    return message->signed_pre_key_id;
}

ec_public_key *pre_key_whisper_message_get_base_key(const pre_key_whisper_message *message)
{
    assert(message);
    return message->base_key;
}

whisper_message *pre_key_whisper_message_get_whisper_message(const pre_key_whisper_message *message)
{
    assert(message);
    return message->message;
}

void pre_key_whisper_message_destroy(axolotl_type_base *type)
{
    pre_key_whisper_message *message = (pre_key_whisper_message *)type;

    if(message->base_message.serialized) {
        axolotl_buffer_free(message->base_message.serialized);
    }
    AXOLOTL_UNREF(message->base_key);
    AXOLOTL_UNREF(message->identity_key);
    AXOLOTL_UNREF(message->message);
    free(message);
}

int sender_key_message_create(sender_key_message **message,
        uint32_t key_id, uint32_t iteration,
        const uint8_t *ciphertext, size_t ciphertext_len,
        ec_private_key *signature_key,
        axolotl_context *global_context)
{
    int result = 0;
    sender_key_message *result_message = 0;
    axolotl_buffer *message_buf = 0;

    assert(global_context);

    result_message = malloc(sizeof(sender_key_message));

    if(!result_message) {
        return AX_ERR_NOMEM;
    }
    memset(result_message, 0, sizeof(sender_key_message));
    AXOLOTL_INIT(result_message, sender_key_message_destroy);

    result_message->base_message.message_type = CIPHERTEXT_SENDERKEY_TYPE;
    result_message->base_message.global_context = global_context;

    result_message->message_version = CIPHERTEXT_CURRENT_VERSION;
    result_message->key_id = key_id;
    result_message->iteration = iteration;

    result_message->ciphertext = axolotl_buffer_create(ciphertext, ciphertext_len);
    if(!result_message->ciphertext) {
        result = AX_ERR_NOMEM;
        goto complete;
    }

    result = sender_key_message_serialize(&message_buf, result_message, signature_key, global_context);
    if(result < 0) {
        goto complete;
    }

    result_message->base_message.serialized = message_buf;

complete:
    if(result >= 0) {
        result = 0;
        *message = result_message;
    }
    else {
        if(result_message) {
            AXOLOTL_UNREF(result_message);
        }
    }
    return result;
}

int sender_key_message_serialize(axolotl_buffer **buffer, const sender_key_message *message, ec_private_key *signature_key, axolotl_context *global_context)
{
    int result = 0;
    uint8_t version = (CIPHERTEXT_CURRENT_VERSION << 4) | CIPHERTEXT_CURRENT_VERSION;
    size_t result_size = 0;
    axolotl_buffer *result_buf = 0;
    axolotl_buffer *signature_buf = 0;
    Textsecure__SenderKeyMessage message_structure = TEXTSECURE__SENDER_KEY_MESSAGE__INIT;
    size_t len = 0;
    uint8_t *data = 0;

    message_structure.id = message->key_id;
    message_structure.has_id = 1;

    message_structure.iteration = message->iteration;
    message_structure.has_iteration = 1;

    message_structure.ciphertext.data = axolotl_buffer_data(message->ciphertext);
    message_structure.ciphertext.len = axolotl_buffer_len(message->ciphertext);
    message_structure.has_ciphertext = 1;

    len = textsecure__sender_key_message__get_packed_size(&message_structure);

    result_buf = axolotl_buffer_alloc(sizeof(version) + len + SIGNATURE_LENGTH);
    if(!result_buf) {
        result = AX_ERR_NOMEM;
        goto complete;
    }

    data = axolotl_buffer_data(result_buf);
    data[0] = version;

    result_size = textsecure__sender_key_message__pack(&message_structure, data + sizeof(version));
    if(result_size != len) {
        axolotl_buffer_free(result_buf);
        result = AX_ERR_INVALID_PROTO_BUF;
        result_buf = 0;
        goto complete;
    }

    result = curve_calculate_signature(global_context, &signature_buf, signature_key,
            data, len + sizeof(version));
    if(result < 0) {
        if(result == AX_ERR_INVALID_KEY) {
            result = AX_ERR_UNKNOWN;
        }
        goto complete;
    }
    else if(axolotl_buffer_len(signature_buf) != SIGNATURE_LENGTH) {
        result = AX_ERR_UNKNOWN;
        goto complete;
    }

    memcpy(data + sizeof(version) + len, axolotl_buffer_data(signature_buf), SIGNATURE_LENGTH);

complete:
    axolotl_buffer_free(signature_buf);
    if(result >= 0) {
        *buffer = result_buf;
    }
    else {
        axolotl_buffer_free(result_buf);
    }
    return result;
}

int sender_key_message_deserialize(sender_key_message **message,
        const uint8_t *data, size_t len,
        axolotl_context *global_context)
{
    int result = 0;
    sender_key_message *result_message = 0;
    uint8_t version = 0;
    const uint8_t *message_data = 0;
    size_t message_len = 0;
    Textsecure__SenderKeyMessage *message_structure = 0;

    assert(global_context);

    if(!data || len <= sizeof(uint8_t) + SIGNATURE_LENGTH) {
        result = AX_ERR_INVAL;
        goto complete;
    }

    version = (data[0] & 0xF0) >> 4;
    message_data = data + sizeof(uint8_t);
    message_len = len - sizeof(uint8_t) - SIGNATURE_LENGTH;

    if(version < CIPHERTEXT_CURRENT_VERSION) {
        axolotl_log(global_context, AX_LOG_WARNING, "Legacy message: %d", version);
        result = AX_ERR_LEGACY_MESSAGE;
        goto complete;
    }

    if(version > CIPHERTEXT_CURRENT_VERSION) {
        axolotl_log(global_context, AX_LOG_WARNING, "Unknown version: %d", version);
        result = AX_ERR_INVALID_VERSION;
        goto complete;
    }

    message_structure = textsecure__sender_key_message__unpack(0, message_len, message_data);
    if(!message_structure) {
        result = AX_ERR_INVALID_PROTO_BUF;
        goto complete;
    }

    if(!message_structure->has_id
            || !message_structure->has_iteration
            || !message_structure->has_ciphertext) {
        axolotl_log(global_context, AX_LOG_WARNING, "Incomplete message");
        result = AX_ERR_INVALID_MESSAGE;
        goto complete;
    }

    result_message = malloc(sizeof(sender_key_message));
    if(!result_message) {
        result = AX_ERR_NOMEM;
        goto complete;
    }
    memset(result_message, 0, sizeof(sender_key_message));
    AXOLOTL_INIT(result_message, sender_key_message_destroy);

    result_message->base_message.message_type = CIPHERTEXT_SENDERKEY_TYPE;
    result_message->base_message.global_context = global_context;

    result_message->key_id = message_structure->id;
    result_message->iteration = message_structure->iteration;
    result_message->message_version = version;

    result_message->ciphertext = axolotl_buffer_create(
            message_structure->ciphertext.data,
            message_structure->ciphertext.len);
    if(!result_message->ciphertext) {
        result = AX_ERR_NOMEM;
        goto complete;
    }

    result_message->base_message.serialized = axolotl_buffer_create(data, len);
    if(!result_message->base_message.serialized) {
        result = AX_ERR_NOMEM;
        goto complete;
    }

complete:
    if(message_structure) {
        textsecure__sender_key_message__free_unpacked(message_structure, 0);
    }
    if(result >= 0) {
        *message = result_message;
    }
    else {
        if(result_message) {
            AXOLOTL_UNREF(result_message);
        }
    }
    return result;
}

int sender_key_message_copy(sender_key_message **message, sender_key_message *other_message, axolotl_context *global_context)
{
    int result = 0;
    sender_key_message *result_message = 0;

    assert(other_message);
    assert(global_context);

    result = sender_key_message_deserialize(
            &result_message,
            axolotl_buffer_data(other_message->base_message.serialized),
            axolotl_buffer_len(other_message->base_message.serialized),
            global_context);
    if(result >= 0) {
        *message = result_message;
    }

    return result;
}

uint32_t sender_key_message_get_key_id(sender_key_message *message)
{
    assert(message);
    return message->key_id;
}

uint32_t sender_key_message_get_iteration(sender_key_message *message)
{
    assert(message);
    return message->iteration;
}

axolotl_buffer *sender_key_message_get_ciphertext(sender_key_message *message)
{
    assert(message);
    return message->ciphertext;
}

int sender_key_message_verify_signature(sender_key_message *message, ec_public_key *signature_key)
{
    int result = 0;
    uint8_t *data;
    size_t data_len;

    assert(message);

    data = axolotl_buffer_data(message->base_message.serialized);
    data_len = axolotl_buffer_len(message->base_message.serialized) - SIGNATURE_LENGTH;

    result = curve_verify_signature(signature_key, data, data_len, data + data_len, SIGNATURE_LENGTH);

    if(result == 0) {
        axolotl_log(message->base_message.global_context, AX_LOG_ERROR, "Invalid signature!");
        result = AX_ERR_INVALID_MESSAGE;
    }
    else if(result < 0) {
        result = AX_ERR_INVALID_MESSAGE;
    }
    else {
        result = 0;
    }

    return result;
}

void sender_key_message_destroy(axolotl_type_base *type)
{
    sender_key_message *message = (sender_key_message *)type;

    if(message->base_message.serialized) {
        axolotl_buffer_free(message->base_message.serialized);
    }
    if(message->ciphertext) {
        axolotl_buffer_free(message->ciphertext);
    }
    free(message);
}

int sender_key_distribution_message_create(sender_key_distribution_message **message,
        uint32_t id, uint32_t iteration,
        const uint8_t *chain_key, size_t chain_key_len,
        ec_public_key *signature_key,
        axolotl_context *global_context)
{
    int result = 0;

    sender_key_distribution_message *result_message = 0;
    axolotl_buffer *message_buf = 0;

    assert(global_context);

    result_message = malloc(sizeof(sender_key_distribution_message));

    if(!result_message) {
        return AX_ERR_NOMEM;
    }
    memset(result_message, 0, sizeof(sender_key_distribution_message));
    AXOLOTL_INIT(result_message, sender_key_distribution_message_destroy);

    result_message->base_message.message_type = CIPHERTEXT_SENDERKEY_DISTRIBUTION_TYPE;
    result_message->base_message.global_context = global_context;

    result_message->id = id;
    result_message->iteration = iteration;

    result_message->chain_key = axolotl_buffer_create(chain_key, chain_key_len);
    if(!result_message->chain_key) {
        goto complete;
    }

    AXOLOTL_REF(signature_key);
    result_message->signature_key = signature_key;

    result = sender_key_distribution_message_serialize(&message_buf, result_message);
    if(result < 0) {
        goto complete;
    }

    result_message->base_message.serialized = message_buf;

complete:
    if(result >= 0) {
        result = 0;
        *message = result_message;
    }
    else {
        if(result_message) {
            AXOLOTL_UNREF(result_message);
        }
    }
    return result;
}

int sender_key_distribution_message_serialize(axolotl_buffer **buffer, const sender_key_distribution_message *message)
{
    int result = 0;
    uint8_t version = (CIPHERTEXT_CURRENT_VERSION << 4) | CIPHERTEXT_CURRENT_VERSION;
    size_t result_size = 0;
    axolotl_buffer *result_buf = 0;
    Textsecure__SenderKeyDistributionMessage message_structure = TEXTSECURE__SENDER_KEY_DISTRIBUTION_MESSAGE__INIT;
    size_t len = 0;
    uint8_t *data = 0;

    message_structure.id = message->id;
    message_structure.has_id = 1;

    message_structure.iteration = message->iteration;
    message_structure.has_iteration = 1;

    message_structure.chainkey.data = axolotl_buffer_data(message->chain_key);
    message_structure.chainkey.len = axolotl_buffer_len(message->chain_key);
    message_structure.has_chainkey = 1;

    result = ec_public_key_serialize_protobuf(&message_structure.signingkey, message->signature_key);
    if(result < 0) {
        goto complete;
    }
    message_structure.has_signingkey = 1;

    len = textsecure__sender_key_distribution_message__get_packed_size(&message_structure);

    result_buf = axolotl_buffer_alloc(sizeof(version) + len);
    if(!result_buf) {
        result = AX_ERR_NOMEM;
        goto complete;
    }

    data = axolotl_buffer_data(result_buf);
    data[0] = version;

    result_size = textsecure__sender_key_distribution_message__pack(&message_structure, data + sizeof(version));
    if(result_size != len) {
        axolotl_buffer_free(result_buf);
        result = AX_ERR_INVALID_PROTO_BUF;
        result_buf = 0;
        goto complete;
    }

complete:
    if(message_structure.has_signingkey) {
        free(message_structure.signingkey.data);
    }
    if(result >= 0) {
        *buffer = result_buf;
    }
    else {
        axolotl_buffer_free(result_buf);
    }
    return result;
}

int sender_key_distribution_message_deserialize(sender_key_distribution_message **message,
        const uint8_t *data, size_t len,
        axolotl_context *global_context)
{
    int result = 0;
    sender_key_distribution_message *result_message = 0;
    uint8_t version = 0;
    const uint8_t *message_data = 0;
    size_t message_len = 0;
    Textsecure__SenderKeyDistributionMessage *message_structure = 0;

    assert(global_context);

    if(!data || len <= sizeof(uint8_t)) {
        result = AX_ERR_INVAL;
        goto complete;
    }

    version = (data[0] & 0xF0) >> 4;
    message_data = data + sizeof(uint8_t);
    message_len = len - sizeof(uint8_t);

    if(version < CIPHERTEXT_CURRENT_VERSION) {
        axolotl_log(global_context, AX_LOG_WARNING, "Legacy message: %d", version);
        result = AX_ERR_LEGACY_MESSAGE;
        goto complete;
    }

    if(version > CIPHERTEXT_CURRENT_VERSION) {
        axolotl_log(global_context, AX_LOG_WARNING, "Unknown version: %d", version);
        result = AX_ERR_INVALID_VERSION;
        goto complete;
    }

    message_structure = textsecure__sender_key_distribution_message__unpack(0, message_len, message_data);
    if(!message_structure) {
        result = AX_ERR_INVALID_PROTO_BUF;
        goto complete;
    }

    if(!message_structure->has_id
            || !message_structure->has_iteration
            || !message_structure->has_chainkey
            || !message_structure->has_signingkey) {
        axolotl_log(global_context, AX_LOG_WARNING, "Incomplete message");
        result = AX_ERR_INVALID_MESSAGE;
        goto complete;
    }

    result_message = malloc(sizeof(sender_key_distribution_message));
    if(!result_message) {
        result = AX_ERR_NOMEM;
        goto complete;
    }
    memset(result_message, 0, sizeof(sender_key_distribution_message));
    AXOLOTL_INIT(result_message, sender_key_distribution_message_destroy);

    result_message->base_message.message_type = CIPHERTEXT_SENDERKEY_DISTRIBUTION_TYPE;
    result_message->base_message.global_context = global_context;

    result_message->id = message_structure->id;
    result_message->iteration = message_structure->iteration;

    result_message->chain_key = axolotl_buffer_create(
            message_structure->chainkey.data,
            message_structure->chainkey.len);
    if(!result_message->chain_key) {
        result = AX_ERR_NOMEM;
        goto complete;
    }

    result = curve_decode_point(&result_message->signature_key,
            message_structure->signingkey.data,
            message_structure->signingkey.len,
            global_context);
    if(result < 0) {
        goto complete;
    }

    result_message->base_message.serialized = axolotl_buffer_create(data, len);
    if(!result_message->base_message.serialized) {
        result = AX_ERR_NOMEM;
        goto complete;
    }

complete:
    if(message_structure) {
        textsecure__sender_key_distribution_message__free_unpacked(message_structure, 0);
    }
    if(result >= 0) {
        *message = result_message;
    }
    else {
        if(result_message) {
            AXOLOTL_UNREF(result_message);
        }
    }
    return result;
}

int sender_key_distribution_message_copy(sender_key_distribution_message **message, sender_key_distribution_message *other_message, axolotl_context *global_context)
{
    int result = 0;
    sender_key_distribution_message *result_message = 0;

    assert(other_message);
    assert(global_context);

    result = sender_key_distribution_message_deserialize(
            &result_message,
            axolotl_buffer_data(other_message->base_message.serialized),
            axolotl_buffer_len(other_message->base_message.serialized),
            global_context);
    if(result >= 0) {
        *message = result_message;
    }

    return result;
}

uint32_t sender_key_distribution_message_get_id(sender_key_distribution_message *message)
{
    assert(message);
    return message->id;
}

uint32_t sender_key_distribution_message_get_iteration(sender_key_distribution_message *message)
{
    assert(message);
    return message->iteration;
}

axolotl_buffer *sender_key_distribution_message_get_chain_key(sender_key_distribution_message *message)
{
    assert(message);
    return message->chain_key;
}

ec_public_key *sender_key_distribution_message_get_signature_key(sender_key_distribution_message *message)
{
    assert(message);
    return message->signature_key;
}

void sender_key_distribution_message_destroy(axolotl_type_base *type)
{
    sender_key_distribution_message *message = (sender_key_distribution_message *)type;

    if(message->base_message.serialized) {
        axolotl_buffer_free(message->base_message.serialized);
    }

    if(message->chain_key) {
        axolotl_buffer_free(message->chain_key);
    }
    AXOLOTL_UNREF(message->signature_key);
    free(message);
}
