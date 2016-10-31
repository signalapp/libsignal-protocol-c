#include "fingerprint.h"

#include <assert.h>
#include <string.h>

#include "FingerprintProtocol.pb-c.h"
#include "signal_protocol_internal.h"

#define VERSION 0
#define SHA512_DIGEST_LENGTH 64

#define MAX(a,b) (((a)>(b))?(a):(b))

struct fingerprint
{
    signal_type_base base;
    displayable_fingerprint *displayable;
    scannable_fingerprint *scannable;
};

struct displayable_fingerprint
{
    signal_type_base base;
    char *local_fingerprint;
    char *remote_fingerprint;
    char *display_text;
};

struct scannable_fingerprint
{
    signal_type_base base;
    uint32_t version;
    char *local_stable_identifier;
    ec_public_key *local_identity_key;
    char *remote_stable_identifier;
    ec_public_key *remote_identity_key;
};

struct fingerprint_generator
{
    int iterations;
    signal_context *global_context;
};

static int fingerprint_generator_create_display_string(fingerprint_generator *generator, char **display_string,
        const char *local_stable_identifier, ec_public_key *identity_key);

int fingerprint_generator_create(fingerprint_generator **generator, int iterations, signal_context *global_context)
{
    fingerprint_generator *result_generator;

    assert(global_context);

    result_generator = malloc(sizeof(fingerprint_generator));
    if(!result_generator) {
        return SG_ERR_NOMEM;
    }
    memset(result_generator, 0, sizeof(fingerprint_generator));

    result_generator->iterations = iterations;
    result_generator->global_context = global_context;

    *generator = result_generator;
    return 0;
}

int fingerprint_generator_create_for(fingerprint_generator *generator,
        const char *local_stable_identifier, ec_public_key *local_identity_key,
        const char *remote_stable_identifier, ec_public_key *remote_identity_key,
        fingerprint **fingerprint_val)
{
    int result = 0;
    fingerprint *result_fingerprint = 0;
    displayable_fingerprint *displayable = 0;
    char *displayable_local = 0;
    char *displayable_remote = 0;
    scannable_fingerprint *scannable = 0;

    result = fingerprint_generator_create_display_string(generator, &displayable_local,
            local_stable_identifier, local_identity_key);
    if(result < 0) {
        goto complete;
    }

    result = fingerprint_generator_create_display_string(generator, &displayable_remote,
            remote_stable_identifier, remote_identity_key);
    if(result < 0) {
        goto complete;
    }

    result = displayable_fingerprint_create(&displayable, displayable_local, displayable_remote);
    if(result < 0) {
        goto complete;
    }

    result = scannable_fingerprint_create(&scannable, VERSION,
            local_stable_identifier, local_identity_key,
            remote_stable_identifier, remote_identity_key);
    if(result < 0) {
        goto complete;
    }

    result = fingerprint_create(&result_fingerprint, displayable, scannable);

complete:
    if(displayable_local) {
        free(displayable_local);
    }
    if(displayable_remote) {
        free(displayable_remote);
    }
    SIGNAL_UNREF(displayable);
    SIGNAL_UNREF(scannable);
    if(result >= 0) {
        *fingerprint_val = result_fingerprint;
    }
    return result;
}

int fingerprint_generator_create_display_string(fingerprint_generator *generator, char **display_string,
        const char *stable_identifier, ec_public_key *identity_key)
{
    int result = 0;
    char *result_string = 0;
    void *digest_context = 0;
    signal_buffer *identity_buffer = 0;
    signal_buffer *hash_buffer = 0;
    signal_buffer *hash_out_buffer = 0;
    uint8_t *data = 0;
    size_t len = 0;
    int i = 0;

    assert(generator);
    assert(stable_identifier);
    assert(identity_key);

    result = signal_sha512_digest_init(generator->global_context, &digest_context);
    if(result < 0) {
        goto complete;
    }

    result = ec_public_key_serialize(&identity_buffer, identity_key);
    if(result < 0) {
        goto complete;
    }

    len = 2 + signal_buffer_len(identity_buffer) + strlen(stable_identifier);

    hash_buffer = signal_buffer_alloc(len);
    if(!hash_buffer) {
        result = SG_ERR_NOMEM;
        goto complete;
    }

    data = signal_buffer_data(hash_buffer);

    memset(data, 0, len);

    data[0] = 0;
    data[1] = (uint8_t)VERSION;
    memcpy(data + 2, signal_buffer_data(identity_buffer), signal_buffer_len(identity_buffer));
    memcpy(data + 2 + signal_buffer_len(identity_buffer), stable_identifier, strlen(stable_identifier));

    for(i = 0; i < generator->iterations; i++) {
        data = signal_buffer_data(hash_buffer);
        len = signal_buffer_len(hash_buffer);

        result = signal_sha512_digest_update(generator->global_context,
                digest_context, data, len);
        if(result < 0) {
            goto complete;
        }

        result = signal_sha512_digest_update(generator->global_context,
                digest_context,
                signal_buffer_data(identity_buffer),
                signal_buffer_len(identity_buffer));
        if(result < 0) {
            goto complete;
        }

        result = signal_sha512_digest_final(generator->global_context,
                digest_context, &hash_out_buffer);
        if(result < 0) {
            goto complete;
        }

        signal_buffer_free(hash_buffer);
        hash_buffer = hash_out_buffer;
        hash_out_buffer = 0;
    }

    data = signal_buffer_data(hash_buffer);
    len = signal_buffer_len(hash_buffer);

    if(len < 30) {
        result = SG_ERR_UNKNOWN;
        goto complete;
    }

    result_string = malloc(31);
    if(!result_string) {
        result = SG_ERR_NOMEM;
        goto complete;
    }

    for(i = 0; i < 30; i += 5) {
        uint64_t chunk = ((uint64_t)data[i] & 0xFFL) << 32 |
                ((uint64_t)data[i + 1] & 0xFFL) << 24 |
                ((uint64_t)data[i + 2] & 0xFFL) << 16 |
                ((uint64_t)data[i + 3] & 0xFFL) << 8 |
                ((uint64_t)data[i + 4] & 0xFFL);
#if _WINDOWS
        sprintf_s(result_string + i, 6, "%05d", (int)(chunk % 100000));
#else
        snprintf(result_string + i, 6, "%05d", (int)(chunk % 100000));
#endif
    }

complete:
    if(digest_context) {
        signal_sha512_digest_cleanup(generator->global_context, digest_context);
    }
    signal_buffer_free(identity_buffer);
    signal_buffer_free(hash_buffer);
    signal_buffer_free(hash_out_buffer);
    if(result >= 0) {
        *display_string = result_string;
    }
    return result;
}

void fingerprint_generator_free(fingerprint_generator *generator)
{
    if(generator) {
        free(generator);
    }
}

int fingerprint_create(fingerprint **fingerprint_val, displayable_fingerprint *displayable, scannable_fingerprint *scannable)
{
    fingerprint *result = malloc(sizeof(fingerprint));
    if(!result) {
        return SG_ERR_NOMEM;
    }

    memset(result, 0, sizeof(fingerprint));
    SIGNAL_INIT(result, fingerprint_destroy);
    if(displayable) {
        result->displayable = displayable;
        SIGNAL_REF(displayable);
    }
    if(scannable) {
        result->scannable = scannable;
        SIGNAL_REF(scannable);
    }

    *fingerprint_val = result;

    return 0;
}

displayable_fingerprint *fingerprint_get_displayable(fingerprint *fingerprint_val)
{
    assert(fingerprint_val);
    return fingerprint_val->displayable;
}

scannable_fingerprint *fingerprint_get_scannable(fingerprint *fingerprint_val)
{
    assert(fingerprint_val);
    return fingerprint_val->scannable;
}

void fingerprint_destroy(signal_type_base *type)
{
    fingerprint *fingerprint_val = (fingerprint *)type;
    SIGNAL_UNREF(fingerprint_val->displayable);
    SIGNAL_UNREF(fingerprint_val->scannable);
    free(fingerprint_val);
}

int displayable_fingerprint_create(displayable_fingerprint **displayable, const char *local_fingerprint, const char *remote_fingerprint)
{
    int result = 0;
    size_t local_len = 0;
    size_t remote_len = 0;
    displayable_fingerprint *result_displayable = 0;
    char *display_text = 0;

    if(!local_fingerprint || !remote_fingerprint) {
        return SG_ERR_INVAL;
    }

    result_displayable = malloc(sizeof(displayable_fingerprint));
    if(!result_displayable) {
        return SG_ERR_NOMEM;
    }

    memset(result_displayable, 0, sizeof(displayable_fingerprint));
    SIGNAL_INIT(result_displayable, displayable_fingerprint_destroy);

    result_displayable->local_fingerprint = strdup(local_fingerprint);
    if(!result_displayable->local_fingerprint) {
        result = SG_ERR_NOMEM;
        goto complete;
    }

    result_displayable->remote_fingerprint = strdup(remote_fingerprint);
    if(!result_displayable->remote_fingerprint) {
        result = SG_ERR_NOMEM;
        goto complete;
    }

    local_len = strlen(local_fingerprint);
    remote_len = strlen(remote_fingerprint);

    display_text = malloc(local_len + remote_len + 1);
    if(!display_text) {
        result = SG_ERR_NOMEM;
        goto complete;
    }

    if(strcmp(local_fingerprint, remote_fingerprint) <= 0) {
        memcpy(display_text, local_fingerprint, local_len);
        memcpy(display_text + local_len, remote_fingerprint, remote_len + 1);
    }
    else {
        memcpy(display_text, remote_fingerprint, remote_len);
        memcpy(display_text + remote_len, local_fingerprint, local_len + 1);
    }

    result_displayable->display_text = display_text;

complete:
    if(result < 0) {
        SIGNAL_UNREF(result_displayable);
    }
    else {
        *displayable = result_displayable;
    }

    return result;
}

const char *displayable_fingerprint_local(displayable_fingerprint *displayable)
{
    assert(displayable);
    return displayable->local_fingerprint;
}

const char *displayable_fingerprint_remote(displayable_fingerprint *displayable)
{
    assert(displayable);
    return displayable->remote_fingerprint;
}

const char *displayable_fingerprint_text(displayable_fingerprint *displayable)
{
    assert(displayable);
    return displayable->display_text;
}

void displayable_fingerprint_destroy(signal_type_base *type)
{
    displayable_fingerprint *displayable = (displayable_fingerprint *)type;
    if(displayable->local_fingerprint) {
        free(displayable->local_fingerprint);
    }
    if(displayable->remote_fingerprint) {
        free(displayable->remote_fingerprint);
    }
    if(displayable->display_text) {
        free(displayable->display_text);
    }
    free(displayable);
}

int scannable_fingerprint_create(scannable_fingerprint **scannable,
        uint32_t version,
        const char *local_stable_identifier, ec_public_key *local_identity_key,
        const char *remote_stable_identifier, ec_public_key *remote_identity_key)
{
    int result = 0;
    scannable_fingerprint *result_scannable = 0;

    if(!local_stable_identifier || !local_identity_key ||
            !remote_stable_identifier || !remote_identity_key) {
        return SG_ERR_INVAL;
    }

    result_scannable = malloc(sizeof(scannable_fingerprint));
    if(!result_scannable) {
        return SG_ERR_NOMEM;
    }

    memset(result_scannable, 0, sizeof(scannable_fingerprint));
    SIGNAL_INIT(result_scannable, scannable_fingerprint_destroy);

    result_scannable->version = version;

    result_scannable->local_stable_identifier = strdup(local_stable_identifier);
    if(!result_scannable->local_stable_identifier) {
        result = SG_ERR_NOMEM;
        goto complete;
    }

    result_scannable->local_identity_key = local_identity_key;
    SIGNAL_REF(local_identity_key);

    result_scannable->remote_stable_identifier = strdup(remote_stable_identifier);
    if(!result_scannable->remote_stable_identifier) {
        result = SG_ERR_NOMEM;
        goto complete;
    }

    result_scannable->remote_identity_key = remote_identity_key;
    SIGNAL_REF(remote_identity_key);

complete:
    if(result < 0) {
        SIGNAL_UNREF(result_scannable);
    }
    else {
        *scannable = result_scannable;
    }

    return result;
}

int scannable_fingerprint_serialize(signal_buffer **buffer, const scannable_fingerprint *scannable)
{
    int result = 0;
    size_t result_size = 0;
    signal_buffer *result_buf = 0;
    Textsecure__CombinedFingerprint combined_fingerprint = TEXTSECURE__COMBINED_FINGERPRINT__INIT;
    Textsecure__FingerprintData local_fingerprint = TEXTSECURE__FINGERPRINT_DATA__INIT;
    Textsecure__FingerprintData remote_fingerprint = TEXTSECURE__FINGERPRINT_DATA__INIT;
    size_t len = 0;
    uint8_t *data = 0;

    combined_fingerprint.version = scannable->version;
    combined_fingerprint.has_version = 1;

    if(scannable->local_stable_identifier && scannable->local_identity_key) {
        signal_protocol_str_serialize_protobuf(&local_fingerprint.identifier, scannable->local_stable_identifier);
        local_fingerprint.has_identifier = 1;

        result = ec_public_key_serialize_protobuf(&local_fingerprint.publickey, scannable->local_identity_key);
        if(result < 0) {
            goto complete;
        }
        local_fingerprint.has_publickey = 1;

        combined_fingerprint.localfingerprint = &local_fingerprint;
    }

    if(scannable->remote_stable_identifier && scannable->remote_identity_key) {
        signal_protocol_str_serialize_protobuf(&remote_fingerprint.identifier, scannable->remote_stable_identifier);
        remote_fingerprint.has_identifier = 1;

        result = ec_public_key_serialize_protobuf(&remote_fingerprint.publickey, scannable->remote_identity_key);
        if(result < 0) {
            goto complete;
        }
        remote_fingerprint.has_publickey = 1;

        combined_fingerprint.remotefingerprint = &remote_fingerprint;
    }

    len = textsecure__combined_fingerprint__get_packed_size(&combined_fingerprint);

    result_buf = signal_buffer_alloc(len);
    if(!result_buf) {
        result = SG_ERR_NOMEM;
        goto complete;
    }

    data = signal_buffer_data(result_buf);
    result_size = textsecure__combined_fingerprint__pack(&combined_fingerprint, data);
    if(result_size != len) {
        signal_buffer_free(result_buf);
        result = SG_ERR_INVALID_PROTO_BUF;
        result_buf = 0;
        goto complete;
    }

complete:
    if(local_fingerprint.publickey.data) {
        free(local_fingerprint.publickey.data);
    }
    if(remote_fingerprint.publickey.data) {
        free(remote_fingerprint.publickey.data);
    }
    if(result >= 0) {
        *buffer = result_buf;
    }
    return result;
}

int scannable_fingerprint_deserialize(scannable_fingerprint **scannable, const uint8_t *data, size_t len, signal_context *global_context)
{
    int result = 0;
    Textsecure__CombinedFingerprint *combined_fingerprint = 0;
    uint32_t version = 0;
    char *local_stable_identifier = 0;
    ec_public_key *local_identity_key = 0;
    char *remote_stable_identifier = 0;
    ec_public_key *remote_identity_key = 0;

    combined_fingerprint = textsecure__combined_fingerprint__unpack(0, len, data);
    if(!combined_fingerprint) {
        result = SG_ERR_INVALID_PROTO_BUF;
        goto complete;
    }

    if(combined_fingerprint->has_version) {
        version = combined_fingerprint->version;
    }

    if(combined_fingerprint->localfingerprint) {
        if(combined_fingerprint->localfingerprint->has_identifier) {
            local_stable_identifier = signal_protocol_str_deserialize_protobuf(&combined_fingerprint->localfingerprint->identifier);
            if(!local_stable_identifier) {
                result = SG_ERR_NOMEM;
                goto complete;
            }
        }
        if(combined_fingerprint->localfingerprint->has_publickey) {
            result = curve_decode_point(&local_identity_key,
                    combined_fingerprint->localfingerprint->publickey.data,
                    combined_fingerprint->localfingerprint->publickey.len,
                    global_context);
            if(result < 0) {
                goto complete;
            }
        }
    }

    if(combined_fingerprint->remotefingerprint) {
        if(combined_fingerprint->remotefingerprint->has_identifier) {
            remote_stable_identifier = signal_protocol_str_deserialize_protobuf(&combined_fingerprint->remotefingerprint->identifier);
            if(!remote_stable_identifier) {
                result = SG_ERR_NOMEM;
                goto complete;
            }
        }
        if(combined_fingerprint->remotefingerprint->has_publickey) {
            result = curve_decode_point(&remote_identity_key,
                    combined_fingerprint->remotefingerprint->publickey.data,
                    combined_fingerprint->remotefingerprint->publickey.len,
                    global_context);
            if(result < 0) {
                goto complete;
            }
        }
    }

    result = scannable_fingerprint_create(scannable, version,
            local_stable_identifier, local_identity_key,
            remote_stable_identifier, remote_identity_key);

complete:
    if(combined_fingerprint) {
        textsecure__combined_fingerprint__free_unpacked(combined_fingerprint, 0);
    }
    if(local_stable_identifier) {
        free(local_stable_identifier);
    }
    if(local_identity_key) {
        SIGNAL_UNREF(local_identity_key);
    }
    if(remote_stable_identifier) {
        free(remote_stable_identifier);
    }
    if(remote_identity_key) {
        SIGNAL_UNREF(remote_identity_key);
    }
    return result;
}

uint32_t scannable_fingerprint_get_version(scannable_fingerprint *scannable)
{
    assert(scannable);
    return scannable->version;
}

const char *scannable_fingerprint_get_local_stable_identifier(scannable_fingerprint *scannable)
{
    assert(scannable);
    return scannable->local_stable_identifier;
}

ec_public_key *scannable_fingerprint_get_local_identity_key(scannable_fingerprint *scannable)
{
    assert(scannable);
    return scannable->local_identity_key;
}

const char *scannable_fingerprint_get_remote_stable_identifier(scannable_fingerprint *scannable)
{
    assert(scannable);
    return scannable->remote_stable_identifier;
}

ec_public_key *scannable_fingerprint_get_remote_identity_key(scannable_fingerprint *scannable)
{
    assert(scannable);
    return scannable->remote_identity_key;
}

int scannable_fingerprint_compare(scannable_fingerprint *scannable, const scannable_fingerprint *other_scannable)
{
    if(!other_scannable->remote_identity_key || !other_scannable->local_identity_key ||
            other_scannable->version != scannable->version) {
        return SG_ERR_FP_VERSION_MISMATCH;
    }

    if(strcmp(scannable->local_stable_identifier, other_scannable->remote_stable_identifier) != 0) {
        return SG_ERR_FP_IDENT_MISMATCH;
    }

    if(strcmp(scannable->remote_stable_identifier, other_scannable->local_stable_identifier) != 0) {
        return SG_ERR_FP_IDENT_MISMATCH;
    }

    if(ec_public_key_compare(scannable->local_identity_key, other_scannable->remote_identity_key) != 0) {
        return 0;
    }

    if(ec_public_key_compare(scannable->remote_identity_key, other_scannable->local_identity_key) != 0) {
        return 0;
    }

    return 1;
}

void scannable_fingerprint_destroy(signal_type_base *type)
{
    scannable_fingerprint *scannable = (scannable_fingerprint *)type;

    if(scannable->local_stable_identifier) {
        free(scannable->local_stable_identifier);
    }

    SIGNAL_UNREF(scannable->local_identity_key);

    if(scannable->remote_stable_identifier) {
        free(scannable->remote_stable_identifier);
    }

    SIGNAL_UNREF(scannable->remote_identity_key);

    free(scannable);
}
