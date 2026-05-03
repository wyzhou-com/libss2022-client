#include "ss2022_internal.h"

#include <ctype.h>

static int b64_value(unsigned char c) {
    if (c >= (unsigned char)'A' && c <= (unsigned char)'Z') {
        return (int)(c - (unsigned char)'A');
    }
    if (c >= (unsigned char)'a' && c <= (unsigned char)'z') {
        return (int)(26u + c - (unsigned char)'a');
    }
    if (c >= (unsigned char)'0' && c <= (unsigned char)'9') {
        return (int)(52u + c - (unsigned char)'0');
    }
    if (c == (unsigned char)'+') {
        return 62;
    }
    if (c == (unsigned char)'/') {
        return 63;
    }
    return -1;
}

static int decode_base64_psk(const char *in, uint8_t *out, size_t out_cap, size_t *out_len) {
    if (in == NULL || out == NULL || out_len == NULL) {
        return SS2022_ERR_INVALID_ARG;
    }

    size_t len = 0u;
    uint32_t acc = 0u;
    unsigned bits = 0u;
    bool seen_pad = false;

    for (const unsigned char *p = (const unsigned char *)(const void *)in; *p != 0u; p++) {
        if (isspace(*p)) {
            continue;
        }
        if (*p == (unsigned char)'=') {
            seen_pad = true;
            continue;
        }
        if (seen_pad) {
            return SS2022_ERR_BAD_KEY;
        }
        int v = b64_value(*p);
        if (v < 0) {
            return SS2022_ERR_BAD_KEY;
        }
        acc = (acc << 6) | (uint32_t)v;
        bits += 6u;
        if (bits >= 8u) {
            bits -= 8u;
            if (len >= out_cap) {
                return SS2022_ERR_BAD_KEY;
            }
            out[len++] = (uint8_t)(acc >> bits);
            acc &= (1u << bits) - 1u;
        }
    }

    *out_len = len;
    return SS2022_OK;
}

int ss2022_client_ctx_init(ss2022_client_ctx *ctx, ss2022_method_t method, const char *base64_psk) {
    if (ctx == NULL || base64_psk == NULL) {
        return SS2022_ERR_INVALID_ARG;
    }

    size_t key_len = ss2022_method_key_len(method);
    if (key_len == 0u) {
        return SS2022_ERR_BAD_KEY;
    }

    struct ss2022_client_ctx_impl *c = ss2022_ctx_impl(ctx);
    memset(c, 0, sizeof(*c));
    size_t decoded_len = 0u;
    int ret = decode_base64_psk(base64_psk, c->psk, sizeof(c->psk), &decoded_len);
    if (ret != SS2022_OK) {
        memset(c, 0, sizeof(*c));
        return ret;
    }
    if (decoded_len != key_len) {
        memset(c, 0, sizeof(*c));
        return SS2022_ERR_BAD_KEY;
    }

    if (wc_InitRng(&c->rng) != 0) {
        memset(c, 0, sizeof(*c));
        return SS2022_ERR_RNG;
    }

    bool enc_ok = (wc_AesSetKey(&c->aes_block_enc, c->psk, (word32)key_len, NULL, AES_ENCRYPTION) == 0);
    bool dec_ok = enc_ok && (wc_AesSetKey(&c->aes_block_dec, c->psk, (word32)key_len, NULL, AES_DECRYPTION) == 0);
    if (!dec_ok) {
        if (enc_ok) {
            wc_AesFree(&c->aes_block_enc);
        }
        wc_FreeRng(&c->rng);
        memset(c, 0, sizeof(*c));
        return SS2022_ERR_WOLFSSL;
    }

    c->magic = SS2022_MAGIC_CTX;
    c->method = method;
    c->psk_len = key_len;
    c->salt_len = key_len;
    c->rng_initialized = true;
    c->aes_block_initialized = true;
    return SS2022_OK;
}

void ss2022_client_ctx_free(ss2022_client_ctx *ctx) {
    if (ctx == NULL) {
        return;
    }
    struct ss2022_client_ctx_impl *c = ss2022_ctx_impl(ctx);
    if (c->magic == SS2022_MAGIC_CTX) {
        if (c->rng_initialized) {
            wc_FreeRng(&c->rng);
        }
        if (c->aes_block_initialized) {
            wc_AesFree(&c->aes_block_enc);
            wc_AesFree(&c->aes_block_dec);
        }
    }
    memset(c, 0, sizeof(*c));
}
