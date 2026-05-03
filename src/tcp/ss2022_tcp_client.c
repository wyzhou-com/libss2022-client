#include "ss2022_internal.h"

static int tcp_ctx_valid(const struct ss2022_client_ctx_impl *ctx) {
    return ctx != NULL && ctx->magic == SS2022_MAGIC_CTX && ctx->rng_initialized;
}

int ss2022_tcp_stream_init(struct ss2022_tcp_stream *stream,
                           struct ss2022_client_ctx_impl *ctx,
                           const uint8_t *salt, size_t salt_len) {
    if (stream == NULL || !tcp_ctx_valid(ctx) || salt == NULL || salt_len != ctx->salt_len) {
        return SS2022_ERR_INVALID_ARG;
    }
    memset(stream, 0, sizeof(*stream));
    memcpy(stream->salt, salt, salt_len);
    int ret = ss2022_kdf_subkey(ctx->psk, ctx->psk_len, salt, salt_len, stream->subkey);
    if (ret != SS2022_OK) {
        return ret;
    }
    ret = ss2022_aead_set_key(&stream->aes_gcm, stream->subkey, ctx->psk_len);
    if (ret != SS2022_OK) {
        memset(stream, 0, sizeof(*stream));
        return ret;
    }
    stream->initialized = true;
    return SS2022_OK;
}

void ss2022_tcp_stream_free(struct ss2022_tcp_stream *stream) {
    if (stream == NULL) {
        return;
    }
    if (stream->initialized) {
        wc_AesFree(&stream->aes_gcm);
    }
    memset(stream, 0, sizeof(*stream));
}

int ss2022_tcp_client_init(ss2022_tcp_client *tcp, ss2022_client_ctx *ctx) {
    if (tcp == NULL || ctx == NULL) {
        return SS2022_ERR_INVALID_ARG;
    }
    struct ss2022_client_ctx_impl *c = ss2022_ctx_impl(ctx);
    if (!tcp_ctx_valid(c)) {
        return SS2022_ERR_INVALID_ARG;
    }
    struct ss2022_tcp_client_impl *t = ss2022_tcp_impl(tcp);
    memset(t, 0, sizeof(*t));
    t->magic = SS2022_MAGIC_TCP;
    t->ctx = c;
    return SS2022_OK;
}

void ss2022_tcp_client_free(ss2022_tcp_client *tcp) {
    if (tcp == NULL) {
        return;
    }
    struct ss2022_tcp_client_impl *t = ss2022_tcp_impl(tcp);
    if (t->magic == SS2022_MAGIC_TCP) {
        ss2022_tcp_stream_free(&t->req);
        ss2022_tcp_stream_free(&t->resp);
    }
    memset(t, 0, sizeof(*t));
}

static int tcp_valid(struct ss2022_tcp_client_impl *t) {
    return t != NULL && t->magic == SS2022_MAGIC_TCP && tcp_ctx_valid(t->ctx);
}

int ss2022_tcp_client_build_request_header(
    ss2022_tcp_client *tcp,
    const ss2022_addr *target,
    const uint8_t *initial_payload,
    size_t initial_payload_len,
    uint8_t *out,
    size_t out_cap,
    size_t *out_len) {
    if (tcp == NULL || target == NULL || (initial_payload == NULL && initial_payload_len != 0u) ||
            out == NULL || out_len == NULL) {
        return SS2022_ERR_INVALID_ARG;
    }
    struct ss2022_tcp_client_impl *t = ss2022_tcp_impl(tcp);
    if (!tcp_valid(t)) {
        return SS2022_ERR_STATE;
    }
    if (t->request_started) {
        return SS2022_ERR_STATE;
    }

    size_t addr_len = 0u;
    int ret = ss2022_addr_encoded_len(target, &addr_len);
    if (ret != SS2022_OK) {
        return ret;
    }

    size_t padding_len = 0u;
    if (initial_payload_len == 0u) {
        const uint32_t padding_range = SS2022_MAX_PADDING_LEN;
        const uint32_t padding_rand_limit =
            UINT16_MAX - (((uint32_t)UINT16_MAX + 1u) % padding_range);
        uint32_t pad_rand;
        do {
            uint8_t pad_rand_buf[2];
            ret = ss2022_random(t->ctx, pad_rand_buf, sizeof(pad_rand_buf));
            if (ret != SS2022_OK) {
                return ret;
            }
            pad_rand = ss2022_read_u16be(pad_rand_buf);
        } while (pad_rand > padding_rand_limit);
        padding_len = (size_t)(pad_rand % padding_range) + 1u;
    }

    size_t var_len = 0u;
    if (ss2022_checked_add(addr_len, 2u, &var_len) != SS2022_OK ||
            ss2022_checked_add(var_len, padding_len, &var_len) != SS2022_OK ||
            ss2022_checked_add(var_len, initial_payload_len, &var_len) != SS2022_OK ||
            var_len > UINT16_MAX) {
        return SS2022_ERR_INVALID_ARG;
    }

    size_t need = t->ctx->salt_len + SS2022_TCP_FIXED_REQ_LEN + SS2022_TAG_LEN + var_len + SS2022_TAG_LEN;
    if (out_cap < need) {
        return SS2022_ERR_BUFFER_TOO_SMALL;
    }

    ret = ss2022_random(t->ctx, t->request_salt, t->ctx->salt_len);
    if (ret != SS2022_OK) {
        return ret;
    }
    ret = ss2022_tcp_stream_init(&t->req, t->ctx, t->request_salt, t->ctx->salt_len);
    if (ret != SS2022_OK) {
        return ret;
    }

    size_t pos = 0u;
    memcpy(out + pos, t->request_salt, t->ctx->salt_len);
    pos += t->ctx->salt_len;

    uint8_t fixed[SS2022_TCP_FIXED_REQ_LEN];
    fixed[0] = 0u;
    ss2022_write_u64be(fixed + 1u, ss2022_now_seconds());
    ss2022_write_u16be(fixed + 9u, (uint16_t)var_len);
    ret = ss2022_aead_seal(&t->req.aes_gcm, t->req.nonce, fixed, sizeof(fixed), out + pos);
    if (ret != SS2022_OK) {
        return ret;
    }
    pos += sizeof(fixed) + SS2022_TAG_LEN;

    uint8_t *var = out + pos;
    size_t vpos = 0u;
    ret = ss2022_addr_encode(target, var + vpos, var_len - vpos, &addr_len);
    if (ret != SS2022_OK) {
        return ret;
    }
    vpos += addr_len;
    ss2022_write_u16be(var + vpos, (uint16_t)padding_len);
    vpos += 2u;
    if (padding_len != 0u) {
        ret = ss2022_random(t->ctx, var + vpos, padding_len);
        if (ret != SS2022_OK) {
            memset(var, 0, padding_len + vpos);
            return ret;
        }
    }
    vpos += padding_len;
    if (initial_payload_len != 0u) {
        memmove(var + vpos, initial_payload, initial_payload_len);
        vpos += initial_payload_len;
    }
    ret = ss2022_aead_seal(&t->req.aes_gcm, t->req.nonce, var, vpos, var);
    if (ret != SS2022_OK) {
        return ret;
    }
    pos += vpos + SS2022_TAG_LEN;

    t->request_started = true;
    *out_len = pos;
    return SS2022_OK;
}

int ss2022_tcp_client_seal_payload(
    ss2022_tcp_client *tcp,
    const uint8_t *plain,
    size_t plain_len,
    uint8_t *out,
    size_t out_cap,
    size_t *out_len) {
    if (tcp == NULL || (plain == NULL && plain_len != 0u) || out == NULL || out_len == NULL) {
        return SS2022_ERR_INVALID_ARG;
    }
    struct ss2022_tcp_client_impl *t = ss2022_tcp_impl(tcp);
    if (!tcp_valid(t) || !t->request_started || !t->req.initialized) {
        return SS2022_ERR_STATE;
    }

    size_t chunks = (plain_len / UINT16_MAX) + ((plain_len % UINT16_MAX) != 0u ? 1u : 0u);
    size_t chunk_overhead = 2u + SS2022_TAG_LEN + SS2022_TAG_LEN;
    if (chunks != 0u && chunks > (SIZE_MAX - plain_len) / chunk_overhead) {
        return SS2022_ERR_BUFFER_TOO_SMALL;
    }
    size_t need = plain_len + chunks * chunk_overhead;
    if (out_cap < need) {
        return SS2022_ERR_BUFFER_TOO_SMALL;
    }

    size_t in_pos = 0u;
    size_t out_pos = 0u;
    while (in_pos < plain_len) {
        size_t n = plain_len - in_pos;
        if (n > UINT16_MAX) {
            n = UINT16_MAX;
        }
        uint8_t len_plain[2];
        ss2022_write_u16be(len_plain, (uint16_t)n);
        int ret = ss2022_aead_seal(&t->req.aes_gcm, t->req.nonce, len_plain, sizeof(len_plain), out + out_pos);
        if (ret != SS2022_OK) {
            return ret;
        }
        out_pos += 2u + SS2022_TAG_LEN;
        if (out + out_pos != plain + in_pos) {
            memmove(out + out_pos, plain + in_pos, n);
        }
        ret = ss2022_aead_seal(&t->req.aes_gcm, t->req.nonce, out + out_pos, n, out + out_pos);
        if (ret != SS2022_OK) {
            return ret;
        }
        out_pos += n + SS2022_TAG_LEN;
        in_pos += n;
    }
    *out_len = out_pos;
    return SS2022_OK;
}

int ss2022_tcp_client_open_response_header(
    ss2022_tcp_client *tcp,
    const uint8_t *in,
    size_t in_len,
    uint16_t *first_payload_len) {
    if (tcp == NULL || in == NULL || first_payload_len == NULL) {
        return SS2022_ERR_INVALID_ARG;
    }
    struct ss2022_tcp_client_impl *t = ss2022_tcp_impl(tcp);
    if (!tcp_valid(t) || !t->request_started) {
        return SS2022_ERR_STATE;
    }
    size_t fixed_len = 1u + 8u + t->ctx->salt_len + 2u;
    size_t need = t->ctx->salt_len + fixed_len + SS2022_TAG_LEN;
    if (in_len < need) {
        return SS2022_ERR_MALFORMED;
    }

    int ret = ss2022_tcp_stream_init(&t->resp, t->ctx, in, t->ctx->salt_len);
    if (ret != SS2022_OK) {
        return ret;
    }
    uint8_t fixed[1u + 8u + SS2022_SALT_MAX + 2u];
    ret = ss2022_aead_open(&t->resp.aes_gcm, t->resp.nonce,
                           in + t->ctx->salt_len, fixed_len + SS2022_TAG_LEN, fixed);
    if (ret != SS2022_OK) {
        return ret;
    }
    if (fixed[0] != 1u) {
        return SS2022_ERR_BAD_TYPE;
    }
    ret = ss2022_check_timestamp(ss2022_read_u64be(fixed + 1u));
    if (ret != SS2022_OK) {
        return ret;
    }
    if (memcmp(fixed + 9u, t->request_salt, t->ctx->salt_len) != 0) {
        return SS2022_ERR_AUTH;
    }
    *first_payload_len = ss2022_read_u16be(fixed + 9u + t->ctx->salt_len);
    t->response_started = true;
    return SS2022_OK;
}

int ss2022_tcp_client_open_length(
    ss2022_tcp_client *tcp,
    const uint8_t *in,
    size_t in_len,
    uint16_t *payload_len) {
    if (tcp == NULL || in == NULL || payload_len == NULL) {
        return SS2022_ERR_INVALID_ARG;
    }
    struct ss2022_tcp_client_impl *t = ss2022_tcp_impl(tcp);
    if (!tcp_valid(t) || !t->response_started || !t->resp.initialized) {
        return SS2022_ERR_STATE;
    }
    if (in_len != 2u + SS2022_TAG_LEN) {
        return SS2022_ERR_MALFORMED;
    }
    uint8_t len_plain[2];
    int ret = ss2022_aead_open(&t->resp.aes_gcm, t->resp.nonce, in, in_len, len_plain);
    if (ret != SS2022_OK) {
        return ret;
    }
    *payload_len = ss2022_read_u16be(len_plain);
    return SS2022_OK;
}

int ss2022_tcp_client_open_payload(
    ss2022_tcp_client *tcp,
    const uint8_t *in,
    size_t in_len,
    uint8_t *plain,
    size_t plain_cap,
    size_t *plain_len) {
    if (tcp == NULL || in == NULL || plain == NULL || plain_len == NULL) {
        return SS2022_ERR_INVALID_ARG;
    }
    struct ss2022_tcp_client_impl *t = ss2022_tcp_impl(tcp);
    if (!tcp_valid(t) || !t->response_started || !t->resp.initialized) {
        return SS2022_ERR_STATE;
    }
    if (in_len < SS2022_TAG_LEN) {
        return SS2022_ERR_MALFORMED;
    }
    size_t n = in_len - SS2022_TAG_LEN;
    if (plain_cap < n) {
        return SS2022_ERR_BUFFER_TOO_SMALL;
    }
    int ret = ss2022_aead_open(&t->resp.aes_gcm, t->resp.nonce, in, in_len, plain);
    if (ret != SS2022_OK) {
        return ret;
    }
    *plain_len = n;
    return SS2022_OK;
}

size_t ss2022_tcp_client_response_header_size(const ss2022_tcp_client *tcp) {
    if (tcp == NULL) {
        return 0u;
    }
    const struct ss2022_tcp_client_impl *t =
        (const struct ss2022_tcp_client_impl *)(const void *)tcp->storage.bytes;
    if (t->magic != SS2022_MAGIC_TCP || t->ctx == NULL) {
        return 0u;
    }
    return t->ctx->salt_len + 1u + 8u + t->ctx->salt_len + 2u + SS2022_TAG_LEN;
}
