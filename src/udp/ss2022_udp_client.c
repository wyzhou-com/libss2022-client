#include "ss2022_internal.h"

static int udp_ctx_valid(const struct ss2022_client_ctx_impl *ctx) {
    return ctx != NULL && ctx->magic == SS2022_MAGIC_CTX && ctx->rng_initialized;
}

static int udp_valid(struct ss2022_udp_client_session_impl *s) {
    return s != NULL && s->magic == SS2022_MAGIC_UDP && s->initialized && udp_ctx_valid(s->ctx);
}

int ss2022_udp_client_session_init(ss2022_udp_client_session *session, ss2022_client_ctx *ctx) {
    if (session == NULL || ctx == NULL) {
        return SS2022_ERR_INVALID_ARG;
    }
    struct ss2022_client_ctx_impl *c = ss2022_ctx_impl(ctx);
    if (!udp_ctx_valid(c)) {
        return SS2022_ERR_INVALID_ARG;
    }

    struct ss2022_udp_client_session_impl *s = ss2022_udp_impl(session);
    memset(s, 0, sizeof(*s));
    int ret = ss2022_random(c, s->client_sid, sizeof(s->client_sid));
    if (ret != SS2022_OK) {
        return ret;
    }
    ret = ss2022_kdf_subkey(c->psk, c->psk_len, s->client_sid, sizeof(s->client_sid), s->client_subkey);
    if (ret != SS2022_OK) {
        memset(s, 0, sizeof(*s));
        return ret;
    }
    ret = ss2022_aead_set_key(&s->client_aes_gcm, s->client_subkey, c->psk_len);
    if (ret != SS2022_OK) {
        memset(s, 0, sizeof(*s));
        return ret;
    }
    s->magic = SS2022_MAGIC_UDP;
    s->ctx = c;
    s->created_ms = ss2022_now_milliseconds();
    s->last_used_ms = s->created_ms;
    s->initialized = true;
    return SS2022_OK;
}

void ss2022_udp_client_session_free(ss2022_udp_client_session *session) {
    if (session == NULL) {
        return;
    }
    struct ss2022_udp_client_session_impl *s = ss2022_udp_impl(session);
    if (s->initialized) {
        wc_AesFree(&s->client_aes_gcm);
        for (size_t i = 0u; i < SS2022_UDP_MAX_SERVER_ASSOC; i++) {
            if (s->servers[i].used) {
                wc_AesFree(&s->servers[i].aes_gcm);
            }
        }
    }
    memset(s, 0, sizeof(*s));
}

int ss2022_udp_client_seal(
    ss2022_udp_client_session *session,
    const ss2022_addr *target,
    const uint8_t *payload,
    size_t payload_len,
    uint8_t *out,
    size_t out_cap,
    size_t *out_len) {
    if (session == NULL || target == NULL || (payload == NULL && payload_len != 0u) ||
            out == NULL || out_len == NULL) {
        return SS2022_ERR_INVALID_ARG;
    }
    struct ss2022_udp_client_session_impl *s = ss2022_udp_impl(session);
    if (!udp_valid(s)) {
        return SS2022_ERR_STATE;
    }

    size_t addr_len = 0u;
    int ret = ss2022_addr_encoded_len(target, &addr_len);
    if (ret != SS2022_OK) {
        return ret;
    }

    size_t padding_len = 0u;
    if (payload_len == 0u) {
        const uint32_t padding_range = SS2022_MAX_PADDING_LEN + 1u;
        const uint32_t padding_rand_limit =
            UINT16_MAX - (((uint32_t)UINT16_MAX + 1u) % padding_range);
        uint32_t pad_rand;
        do {
            uint8_t pad_rand_buf[2];
            ret = ss2022_random(s->ctx, pad_rand_buf, sizeof(pad_rand_buf));
            if (ret != SS2022_OK) {
                return ret;
            }
            pad_rand = ss2022_read_u16be(pad_rand_buf);
        } while (pad_rand > padding_rand_limit);
        padding_len = (size_t)(pad_rand % padding_range);
    }

    size_t body_len = 0u;
    if (ss2022_checked_add(1u + 8u + 2u, padding_len, &body_len) != SS2022_OK ||
            ss2022_checked_add(body_len, addr_len, &body_len) != SS2022_OK ||
            ss2022_checked_add(body_len, payload_len, &body_len) != SS2022_OK) {
        return SS2022_ERR_BUFFER_TOO_SMALL;
    }
    size_t need = 0u;
    if (ss2022_checked_add(SS2022_UDP_SEPARATE_HEADER_LEN, body_len, &need) != SS2022_OK ||
            ss2022_checked_add(need, SS2022_TAG_LEN, &need) != SS2022_OK) {
        return SS2022_ERR_BUFFER_TOO_SMALL;
    }
    if (out_cap < need) {
        return SS2022_ERR_BUFFER_TOO_SMALL;
    }
    if (s->next_packet_id == UINT64_MAX) {
        return SS2022_ERR_STATE;
    }

    uint8_t sep[SS2022_UDP_SEPARATE_HEADER_LEN];
    memcpy(sep, s->client_sid, 8u);
    ss2022_write_u64be(sep + 8u, s->next_packet_id);

    uint8_t *body = out + SS2022_UDP_SEPARATE_HEADER_LEN;
    size_t pos = 0u;
    body[pos++] = 0u;
    ss2022_write_u64be(body + pos, ss2022_now_seconds());
    pos += 8u;
    ss2022_write_u16be(body + pos, (uint16_t)padding_len);
    pos += 2u;
    if (padding_len != 0u) {
        ret = ss2022_random(s->ctx, body + pos, padding_len);
        if (ret != SS2022_OK) {
            memset(body, 0, pos + padding_len);
            return ret;
        }
    }
    pos += padding_len;
    ret = ss2022_addr_encode(target, body + pos, body_len - pos, &addr_len);
    if (ret != SS2022_OK) {
        memset(body, 0, pos);
        return ret;
    }
    pos += addr_len;
    if (payload_len != 0u) {
        memmove(body + pos, payload, payload_len);
        pos += payload_len;
    }

    uint8_t nonce[SS2022_NONCE_LEN];
    memcpy(nonce, sep + 4u, SS2022_NONCE_LEN);
    ret = ss2022_aead_seal(&s->client_aes_gcm, nonce, body, body_len, body);
    if (ret != SS2022_OK) {
        return ret;
    }
    ret = ss2022_aes_encrypt_block(&s->ctx->aes_block_enc, sep, out);
    if (ret != SS2022_OK) {
        return ret;
    }

    s->next_packet_id++;
    s->last_used_ms = ss2022_now_milliseconds();
    *out_len = need;
    return SS2022_OK;
}

static struct ss2022_udp_server_assoc *find_assoc(struct ss2022_udp_client_session_impl *s,
        const uint8_t sid[8]) {
    for (size_t i = 0u; i < SS2022_UDP_MAX_SERVER_ASSOC; i++) {
        if (s->servers[i].used && memcmp(s->servers[i].server_sid, sid, 8u) == 0) {
            return &s->servers[i];
        }
    }
    return NULL;
}

static struct ss2022_udp_server_assoc *select_assoc_slot(struct ss2022_udp_client_session_impl *s,
        uint64_t now_ms) {
    struct ss2022_udp_server_assoc *oldest = &s->servers[0];
    for (size_t i = 0u; i < SS2022_UDP_MAX_SERVER_ASSOC; i++) {
        if (!s->servers[i].used) {
            return &s->servers[i];
        }
        if (s->servers[i].last_seen_ms < oldest->last_seen_ms) {
            oldest = &s->servers[i];
        }
    }

    if (now_ms < oldest->last_seen_ms || now_ms - oldest->last_seen_ms < SS2022_UDP_ASSOC_KEEP_MS) {
        return NULL;
    }
    return oldest;
}

static int install_assoc(struct ss2022_udp_server_assoc *assoc,
                         const uint8_t sid[8],
                         const uint8_t *subkey,
                         size_t key_len,
                         uint64_t now_ms) {
    if (assoc == NULL) {
        return SS2022_ERR_INVALID_ARG;
    }
    if (assoc->used) {
        wc_AesFree(&assoc->aes_gcm);
    }
    memset(assoc, 0, sizeof(*assoc));
    memcpy(assoc->server_sid, sid, 8u);
    memcpy(assoc->subkey, subkey, SS2022_KEY_MAX);
    ss2022_replay_window_init(&assoc->replay);
    int ret = ss2022_aead_set_key(&assoc->aes_gcm, subkey, key_len);
    if (ret != SS2022_OK) {
        return ret;
    }
    assoc->last_seen_ms = now_ms;
    assoc->used = true;
    return SS2022_OK;
}

int ss2022_udp_client_open(
    ss2022_udp_client_session *session,
    const uint8_t *packet,
    size_t packet_len,
    ss2022_addr *source_addr,
    uint8_t *payload,
    size_t payload_cap,
    size_t *payload_len) {
    if (session == NULL || packet == NULL || source_addr == NULL || payload == NULL || payload_len == NULL) {
        return SS2022_ERR_INVALID_ARG;
    }
    struct ss2022_udp_client_session_impl *s = ss2022_udp_impl(session);
    if (!udp_valid(s)) {
        return SS2022_ERR_STATE;
    }
    if (packet_len < SS2022_UDP_SEPARATE_HEADER_LEN + SS2022_TAG_LEN) {
        return SS2022_ERR_MALFORMED;
    }

    uint8_t sep[SS2022_UDP_SEPARATE_HEADER_LEN];
    int ret = ss2022_aes_decrypt_block(&s->ctx->aes_block_dec, packet, sep);
    if (ret != SS2022_OK) {
        return ret;
    }
    uint64_t packet_id = ss2022_read_u64be(sep + 8u);
    uint64_t now_ms = ss2022_now_milliseconds();
    struct ss2022_udp_server_assoc *assoc = find_assoc(s, sep);
    struct ss2022_udp_server_assoc *new_slot = NULL;
    uint8_t new_subkey[SS2022_KEY_MAX];
    bool new_assoc_key_ready = false;

    if (assoc != NULL) {
        ret = ss2022_replay_window_check(&assoc->replay, packet_id);
        if (ret != SS2022_OK) {
            return ret;
        }
    } else {
        new_slot = select_assoc_slot(s, now_ms);
        if (new_slot == NULL) {
            return SS2022_ERR_STATE;
        }
        ret = ss2022_kdf_subkey(s->ctx->psk, s->ctx->psk_len, sep, 8u, new_subkey);
        if (ret != SS2022_OK) {
            return ret;
        }
        if (!new_slot->used) {
            memset(new_slot, 0, sizeof(*new_slot));
            memcpy(new_slot->server_sid, sep, 8u);
            memcpy(new_slot->subkey, new_subkey, SS2022_KEY_MAX);
            ss2022_replay_window_init(&new_slot->replay);
            ret = ss2022_aead_set_key(&new_slot->aes_gcm, new_subkey, s->ctx->psk_len);
            if (ret != SS2022_OK) {
                memset(new_slot, 0, sizeof(*new_slot));
                return ret;
            }
            new_assoc_key_ready = true;
        }
    }

    size_t body_cipher_len = packet_len - SS2022_UDP_SEPARATE_HEADER_LEN;
    size_t body_plain_len = body_cipher_len - SS2022_TAG_LEN;
    bool inplace = ss2022_ranges_overlap(payload, payload_cap, packet, packet_len);
    if (payload_cap < body_plain_len) {
        return SS2022_ERR_BUFFER_TOO_SMALL;
    }
    uint8_t *body_plain = inplace ? (uint8_t *)(void *)(packet + SS2022_UDP_SEPARATE_HEADER_LEN) : payload;

    uint8_t nonce[SS2022_NONCE_LEN];
    memcpy(nonce, sep + 4u, SS2022_NONCE_LEN);
    if (assoc != NULL) {
        ret = ss2022_aead_open(&assoc->aes_gcm, nonce,
                               packet + SS2022_UDP_SEPARATE_HEADER_LEN, body_cipher_len, body_plain);
        if (ret != SS2022_OK) {
            return ret;
        }
    } else if (new_assoc_key_ready) {
        ret = ss2022_aead_open(&new_slot->aes_gcm, nonce,
                               packet + SS2022_UDP_SEPARATE_HEADER_LEN, body_cipher_len, body_plain);
        if (ret != SS2022_OK) {
            goto fail_new_assoc;
        }
    } else {
        Aes temp_aes;
        ret = ss2022_aead_set_key(&temp_aes, new_subkey, s->ctx->psk_len);
        if (ret != SS2022_OK) {
            return ret;
        }
        ret = ss2022_aead_open(&temp_aes, nonce,
                               packet + SS2022_UDP_SEPARATE_HEADER_LEN, body_cipher_len, body_plain);
        wc_AesFree(&temp_aes);
        if (ret != SS2022_OK) {
            return ret;
        }
    }

    size_t pos = 0u;
    if (body_plain_len < 1u + 8u + 8u + 2u) {
        ret = SS2022_ERR_MALFORMED;
        goto fail_new_assoc;
    }
    if (body_plain[pos++] != 1u) {
        ret = SS2022_ERR_BAD_TYPE;
        goto fail_new_assoc;
    }
    ret = ss2022_check_timestamp(ss2022_read_u64be(body_plain + pos));
    if (ret != SS2022_OK) {
        goto fail_new_assoc;
    }
    pos += 8u;
    if (memcmp(body_plain + pos, s->client_sid, 8u) != 0) {
        ret = SS2022_ERR_AUTH;
        goto fail_new_assoc;
    }
    pos += 8u;
    uint16_t padding_len = ss2022_read_u16be(body_plain + pos);
    pos += 2u;
    if (padding_len > SS2022_MAX_PADDING_LEN || body_plain_len < pos + (size_t)padding_len) {
        ret = SS2022_ERR_MALFORMED;
        goto fail_new_assoc;
    }
    pos += padding_len;

    size_t consumed = 0u;
    ret = ss2022_addr_decode(body_plain + pos, body_plain_len - pos, source_addr, &consumed);
    if (ret != SS2022_OK) {
        goto fail_new_assoc;
    }
    pos += consumed;
    size_t final_payload_len = body_plain_len - pos;
    if (payload_cap < final_payload_len) {
        ret = SS2022_ERR_BUFFER_TOO_SMALL;
        goto fail_new_assoc;
    }
    memmove(payload, body_plain + pos, final_payload_len);
    *payload_len = final_payload_len;

    if (assoc == NULL) {
        if (new_assoc_key_ready) {
            new_slot->last_seen_ms = now_ms;
            new_slot->used = true;
        } else {
            ret = install_assoc(new_slot, sep, new_subkey, s->ctx->psk_len, now_ms);
            if (ret != SS2022_OK) {
                return ret;
            }
        }
        assoc = new_slot;
    }
    ss2022_replay_window_commit(&assoc->replay, packet_id);
    assoc->last_seen_ms = now_ms;
    s->last_used_ms = now_ms;
    return SS2022_OK;

fail_new_assoc:
    if (new_assoc_key_ready) {
        wc_AesFree(&new_slot->aes_gcm);
        memset(new_slot, 0, sizeof(*new_slot));
    }
    return ret;
}
