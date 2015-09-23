#include "hkdf.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <assert.h>

#include "axolotl_internal.h"

#define HASH_OUTPUT_SIZE 32

#define MIN(a,b) (((a)<(b))?(a):(b))
#define MAX(a,b) (((a)>(b))?(a):(b))

struct hkdf_context
{
    axolotl_type_base base;
    axolotl_context *global_context;
    int iteration_start_offset;
};

int hkdf_create(hkdf_context **context, int message_version, axolotl_context *global_context)
{
    assert(global_context);
    *context = malloc(sizeof(hkdf_context));
    if(!(*context)) {
        return AX_ERR_NOMEM;
    }

    memset(*context, 0, sizeof(hkdf_context));

    AXOLOTL_INIT(*context, hkdf_destroy);
    (*context)->global_context = global_context;

    if(message_version == 2) {
        (*context)->iteration_start_offset = 0;
    }
    else if(message_version == 3) {
        (*context)->iteration_start_offset = 1;
    }
    else {
        free(*context);
        return AX_ERR_INVAL;
    }

    return 0;
}

ssize_t hkdf_extract(hkdf_context *context,
        uint8_t **output,
        const uint8_t *salt, size_t salt_len,
        const uint8_t *input_key_material, size_t input_key_material_len)
{
    int result = 0;
    axolotl_buffer *mac_buffer = 0;
    uint8_t *mac = 0;
    size_t mac_len = 0;
    void *hmac_context;

    assert(context);

    result = axolotl_hmac_sha256_init(context->global_context,
            &hmac_context, salt, salt_len);
    if(result < 0) {
        goto complete;
    }

    result = axolotl_hmac_sha256_update(context->global_context,
            hmac_context, input_key_material, input_key_material_len);
    if(result < 0) {
        goto complete;
    }

    result = axolotl_hmac_sha256_final(context->global_context,
            hmac_context, &mac_buffer);
    if(result < 0) {
        goto complete;
    }

    mac_len = axolotl_buffer_len(mac_buffer);
    mac = malloc(mac_len);
    if(!mac) {
        result = AX_ERR_NOMEM;
        goto complete;
    }

    memcpy(mac, axolotl_buffer_data(mac_buffer), mac_len);

complete:
    axolotl_hmac_sha256_cleanup(context->global_context, hmac_context);
    axolotl_buffer_free(mac_buffer);

    if(result >= 0) {
        *output = mac;
        return (ssize_t)mac_len;
    }
    else {
        return result;
    }
}

ssize_t hkdf_expand(hkdf_context *context,
        uint8_t **output,
        const uint8_t *prk, size_t prk_len,
        const uint8_t *info, size_t info_len,
        size_t output_len)
{
    int iterations = (int)ceil((double)output_len / (double)HASH_OUTPUT_SIZE);
    size_t remaining_len = output_len;
    axolotl_buffer *step_buffer = 0;
    size_t step_size = 0;
    uint8_t *result_buf = 0;
    size_t result_buf_len = 0;
    void *hmac_context = 0;
    int result = 0;
    uint8_t i;

    assert(context);

    for(i = context->iteration_start_offset; i < iterations + context->iteration_start_offset; i++) {
        result = axolotl_hmac_sha256_init(context->global_context,
                &hmac_context, prk, prk_len);
        if(result < 0) {
            goto complete;
        }

        if(step_buffer) {
            result = axolotl_hmac_sha256_update(context->global_context,
                    hmac_context,
                    axolotl_buffer_data(step_buffer),
                    axolotl_buffer_len(step_buffer));
            if(result < 0) {
                goto complete;
            }
            axolotl_buffer_free(step_buffer);
            step_buffer = 0;
        }

        if(info) {
            result = axolotl_hmac_sha256_update(context->global_context,
                    hmac_context, info, info_len);
            if(result < 0) {
                goto complete;
            }
        }

        result = axolotl_hmac_sha256_update(context->global_context,
                hmac_context, &i, sizeof(uint8_t));
        if(result < 0) {
            goto complete;
        }

        result = axolotl_hmac_sha256_final(context->global_context,
                hmac_context, &step_buffer);
        if(result < 0) {
            goto complete;
        }

        axolotl_hmac_sha256_cleanup(context->global_context, hmac_context);
        hmac_context = 0;

        step_size = MIN(remaining_len, axolotl_buffer_len(step_buffer));

        if(!result_buf) {
            result_buf = malloc(step_size);
            if(!result_buf) {
                result = AX_ERR_NOMEM;
                goto complete;
            }
            memcpy(result_buf, axolotl_buffer_data(step_buffer), step_size);
            result_buf_len = step_size;
        }
        else {
            uint8_t *tmp_buf = realloc(result_buf, result_buf_len + step_size);
            if(!tmp_buf) {
                result = AX_ERR_NOMEM;
                goto complete;
            }
            result_buf = tmp_buf;
            memcpy(result_buf + result_buf_len, axolotl_buffer_data(step_buffer), step_size);
            result_buf_len += step_size;
        }
        remaining_len -= step_size;
    }

complete:
    if(hmac_context) {
        axolotl_hmac_sha256_cleanup(context->global_context, hmac_context);
    }
    axolotl_buffer_free(step_buffer);
    if(result < 0) {
        free(result_buf);
        return result;
    }
    else {
        *output = result_buf;
        return (ssize_t)result_buf_len;
    }
}

ssize_t hkdf_derive_secrets(hkdf_context *context,
        uint8_t **output,
        const uint8_t *input_key_material, size_t input_key_material_len,
        const uint8_t *salt, size_t salt_len,
        const uint8_t *info, size_t info_len,
        size_t output_len)
{
    ssize_t result = 0;
    uint8_t *prk = 0;
    ssize_t prk_len = 0;

    assert(context);

    prk_len = hkdf_extract(context, &prk, salt, salt_len, input_key_material, input_key_material_len);
    if(prk_len < 0) {
        axolotl_log(context->global_context, AX_LOG_ERROR, "hkdf_extract error: %d", prk_len);
        return prk_len;
    }

    result = hkdf_expand(context, output, prk, (size_t)prk_len, info, info_len, output_len);

    if(prk) {
        free(prk);
    }

    return result;
}

int hkdf_compare(const hkdf_context *context1, const hkdf_context *context2)
{
    if(context1 == context2) {
        return 0;
    }
    else if(context1 == 0 && context2 != 0) {
        return -1;
    }
    else if(context1 != 0 && context2 == 0) {
        return 1;
    }
    else if(context1->iteration_start_offset < context2->iteration_start_offset) {
        return -1;
    }
    else if(context1->iteration_start_offset > context2->iteration_start_offset) {
        return 1;
    }
    else {
        return 0;
    }
}

void hkdf_destroy(axolotl_type_base *type)
{
    hkdf_context *context = (hkdf_context *)type;
    free(context);
}
