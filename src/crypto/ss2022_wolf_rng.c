#include "ss2022_internal.h"

int ss2022_random(struct ss2022_client_ctx_impl *ctx, uint8_t *out, size_t len) {
    if (ctx == NULL || out == NULL || ctx->magic != SS2022_MAGIC_CTX || !ctx->rng_initialized) {
        return SS2022_ERR_INVALID_ARG;
    }
    if (len > UINT32_MAX) {
        return SS2022_ERR_INVALID_ARG;
    }
    if (wc_RNG_GenerateBlock(&ctx->rng, out, (word32)len) != 0) {
        return SS2022_ERR_RNG;
    }
    return SS2022_OK;
}
