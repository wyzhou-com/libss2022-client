#include "ss2022_client.h"
#include "ss2022_internal.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

#define PSK128_ZERO "AAAAAAAAAAAAAAAAAAAAAA=="
#define PSK256_ZERO "AAAAAAAAAA" "AAAAAAAAAA" "AAAAAAAAAA" "AAAAAAAAAA" "AAA="

static ss2022_addr make_addr(void) {
    ss2022_addr addr;
    memset(&addr, 0, sizeof(addr));
    addr.type = SS2022_ADDR_DOMAIN;
    addr.port = 443u;
    addr.u.domain.len = 11u;
    memcpy(addr.u.domain.name, "example.com", 11u);
    return addr;
}

static void test_key_and_kdf(void) {
    ss2022_client_ctx ctx;
    assert(ss2022_client_ctx_init(&ctx, SS2022_AES_128_GCM, PSK128_ZERO) == SS2022_OK);
    ss2022_client_ctx_free(&ctx);

    assert(ss2022_client_ctx_init(&ctx, SS2022_AES_256_GCM, PSK128_ZERO) == SS2022_ERR_BAD_KEY);
    assert(ss2022_client_ctx_init(&ctx, SS2022_AES_256_GCM, PSK256_ZERO) == SS2022_OK);
    ss2022_client_ctx_free(&ctx);

    uint8_t psk[16] = {0};
    uint8_t salt_a[16] = {1};
    uint8_t salt_b[16] = {2};
    uint8_t out_a[32];
    uint8_t out_b[32];
    uint8_t out_c[32];
    assert(ss2022_kdf_subkey(psk, sizeof(psk), salt_a, sizeof(salt_a), out_a) == SS2022_OK);
    assert(ss2022_kdf_subkey(psk, sizeof(psk), salt_a, sizeof(salt_a), out_b) == SS2022_OK);
    assert(ss2022_kdf_subkey(psk, sizeof(psk), salt_b, sizeof(salt_b), out_c) == SS2022_OK);
    assert(memcmp(out_a, out_b, sizeof(out_a)) == 0);
    assert(memcmp(out_a, out_c, sizeof(out_a)) != 0);
}

static void test_nonce_and_replay(void) {
    uint8_t nonce[12] = {0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    ss2022_nonce_increment(nonce);
    assert(nonce[0] == 0);
    assert(nonce[1] == 0);
    assert(nonce[2] == 1);

    struct ss2022_replay_window w;
    ss2022_replay_window_init(&w);
    assert(ss2022_replay_window_check(&w, 5) == SS2022_OK);
    ss2022_replay_window_commit(&w, 5);
    assert(ss2022_replay_window_check(&w, 5) == SS2022_ERR_REPLAY);
    assert(ss2022_replay_window_check(&w, 4) == SS2022_OK);
    ss2022_replay_window_commit(&w, 4);
    assert(ss2022_replay_window_check(&w, 4) == SS2022_ERR_REPLAY);
    ss2022_replay_window_commit(&w, 4096u);
    assert(ss2022_replay_window_check(&w, 1u) == SS2022_ERR_REPLAY);
}

static size_t tcp_header_len(ss2022_tcp_client *tcp) {
    struct ss2022_tcp_client_impl *t = ss2022_tcp_impl(tcp);
    return t->ctx->salt_len + SS2022_TCP_FIXED_REQ_LEN + SS2022_TAG_LEN;
}

static void forge_response_header(ss2022_tcp_client *tcp, int good_salt, uint8_t *out, size_t *out_len) {
    struct ss2022_tcp_client_impl *t = ss2022_tcp_impl(tcp);
    uint8_t salt[32] = {0x33};
    struct ss2022_tcp_stream stream;
    assert(ss2022_tcp_stream_init(&stream, t->ctx, salt, t->ctx->salt_len) == SS2022_OK);

    size_t fixed_len = 1u + 8u + t->ctx->salt_len + 2u;
    uint8_t fixed[1u + 8u + 32u + 2u];
    fixed[0] = 1u;
    ss2022_write_u64be(fixed + 1u, ss2022_now_seconds());
    memset(fixed + 9u, good_salt ? 0 : 0x5a, t->ctx->salt_len);
    if (good_salt) {
        memcpy(fixed + 9u, t->request_salt, t->ctx->salt_len);
    }
    ss2022_write_u16be(fixed + 9u + t->ctx->salt_len, 0u);

    memcpy(out, salt, t->ctx->salt_len);
    assert(ss2022_aead_seal(&stream.aes_gcm, stream.nonce, fixed, fixed_len, out + t->ctx->salt_len) == SS2022_OK);
    *out_len = t->ctx->salt_len + fixed_len + SS2022_TAG_LEN;
    ss2022_tcp_stream_free(&stream);
}

static void forge_response_zero_then_payload(ss2022_tcp_client *tcp,
        const uint8_t *plain,
        size_t plain_len,
        uint8_t *out,
        size_t *out_len) {
    struct ss2022_tcp_client_impl *t = ss2022_tcp_impl(tcp);
    uint8_t salt[32] = {0x44};
    struct ss2022_tcp_stream stream;
    assert(plain_len <= UINT16_MAX);
    assert(ss2022_tcp_stream_init(&stream, t->ctx, salt, t->ctx->salt_len) == SS2022_OK);

    size_t fixed_len = 1u + 8u + t->ctx->salt_len + 2u;
    uint8_t fixed[1u + 8u + 32u + 2u];
    fixed[0] = 1u;
    ss2022_write_u64be(fixed + 1u, ss2022_now_seconds());
    memcpy(fixed + 9u, t->request_salt, t->ctx->salt_len);
    ss2022_write_u16be(fixed + 9u + t->ctx->salt_len, 0u);

    size_t pos = 0u;
    memcpy(out + pos, salt, t->ctx->salt_len);
    pos += t->ctx->salt_len;
    assert(ss2022_aead_seal(&stream.aes_gcm, stream.nonce, fixed, fixed_len, out + pos) == SS2022_OK);
    pos += fixed_len + SS2022_TAG_LEN;

    assert(ss2022_aead_seal(&stream.aes_gcm, stream.nonce, out + pos, 0u, out + pos) == SS2022_OK);
    pos += SS2022_TAG_LEN;

    uint8_t len_plain[2];
    ss2022_write_u16be(len_plain, (uint16_t)plain_len);
    assert(ss2022_aead_seal(&stream.aes_gcm, stream.nonce, len_plain, sizeof(len_plain), out + pos) == SS2022_OK);
    pos += sizeof(len_plain) + SS2022_TAG_LEN;

    memcpy(out + pos, plain, plain_len);
    assert(ss2022_aead_seal(&stream.aes_gcm, stream.nonce, out + pos, plain_len, out + pos) == SS2022_OK);
    pos += plain_len + SS2022_TAG_LEN;

    *out_len = pos;
    ss2022_tcp_stream_free(&stream);
}

static void test_tcp(void) {
    ss2022_client_ctx ctx;
    ss2022_tcp_client tcp;
    ss2022_addr addr = make_addr();
    const uint8_t initial[] = "GET / HTTP/1.0\r\n\r\n";
    uint8_t header[1024];
    size_t header_len = 0;
    uint8_t addr_buf[300];
    size_t addr_len = 0u;
    assert(ss2022_addr_encode(&addr, addr_buf, sizeof(addr_buf), &addr_len) == SS2022_OK);

    assert(ss2022_client_ctx_init(&ctx, SS2022_AES_128_GCM, PSK128_ZERO) == SS2022_OK);
    assert(ss2022_tcp_client_init(&tcp, &ctx) == SS2022_OK);
    assert(ss2022_tcp_client_build_request_header(&tcp, &addr, initial, sizeof(initial) - 1u,
            header, sizeof(header), &header_len) == SS2022_OK);
    assert(header_len > tcp_header_len(&tcp));
    size_t tcp_nonempty_base_len =
        tcp_header_len(&tcp) + addr_len + 2u + sizeof(initial) - 1u + SS2022_TAG_LEN;
    assert(header_len == tcp_nonempty_base_len);
    assert(ss2022_tcp_client_build_request_header(&tcp, &addr, initial, sizeof(initial) - 1u,
            header, sizeof(header), &header_len) == SS2022_ERR_STATE);
    assert(ss2022_tcp_client_seal_payload(&tcp, initial, sizeof(initial) - 1u,
                                          header, 8u, &header_len) == SS2022_ERR_BUFFER_TOO_SMALL);
    uint8_t inplace_payload[128];
    memcpy(inplace_payload + SS2022_TCP_PAYLOAD_CHUNK_PREFIX_LEN, initial, sizeof(initial) - 1u);
    assert(ss2022_tcp_client_seal_payload(&tcp,
                                          inplace_payload + SS2022_TCP_PAYLOAD_CHUNK_PREFIX_LEN,
                                          sizeof(initial) - 1u,
                                          inplace_payload, sizeof(inplace_payload),
                                          &header_len) == SS2022_OK);
    assert(header_len == sizeof(initial) - 1u + SS2022_TCP_PAYLOAD_CHUNK_PREFIX_LEN + SS2022_TAG_LEN);

    uint8_t resp[128];
    size_t resp_len = 0;
    uint16_t first_len = 99u;
    forge_response_header(&tcp, 0, resp, &resp_len);
    assert(ss2022_tcp_client_open_response_header(&tcp, resp, resp_len, &first_len) == SS2022_ERR_AUTH);
    forge_response_header(&tcp, 1, resp, &resp_len);
    assert(ss2022_tcp_client_open_response_header(&tcp, resp, resp_len, &first_len) == SS2022_OK);
    assert(first_len == 0u);

    ss2022_tcp_client_free(&tcp);
    ss2022_client_ctx_free(&ctx);

    assert(ss2022_client_ctx_init(&ctx, SS2022_AES_128_GCM, PSK128_ZERO) == SS2022_OK);
    assert(ss2022_tcp_client_init(&tcp, &ctx) == SS2022_OK);
    assert(ss2022_tcp_client_build_request_header(&tcp, &addr, NULL, 0u,
            header, sizeof(header), &header_len) == SS2022_OK);
    size_t tcp_empty_base_len = tcp_header_len(&tcp) + addr_len + 2u + SS2022_TAG_LEN;
    assert(header_len >= tcp_empty_base_len + 1u);
    assert(header_len <= tcp_empty_base_len + SS2022_MAX_PADDING_LEN);
    const uint8_t response_plain[] = "ok";
    uint8_t full_resp[256];
    size_t full_resp_len = 0u;
    forge_response_zero_then_payload(&tcp, response_plain, sizeof(response_plain) - 1u,
                                     full_resp, &full_resp_len);
    size_t response_header_len = ss2022_tcp_client_response_header_size(&tcp);
    assert(ss2022_tcp_client_open_response_header(&tcp, full_resp, response_header_len, &first_len) == SS2022_OK);
    assert(first_len == 0u);
    uint8_t opened[16];
    size_t opened_len = 99u;
    size_t pos = response_header_len;
    assert(ss2022_tcp_client_open_payload(&tcp, full_resp + pos, SS2022_TAG_LEN,
                                          opened, sizeof(opened), &opened_len) == SS2022_OK);
    assert(opened_len == 0u);
    pos += SS2022_TAG_LEN;
    assert(ss2022_tcp_client_open_length(&tcp, full_resp + pos, 2u + SS2022_TAG_LEN, &first_len) == SS2022_OK);
    assert(first_len == sizeof(response_plain) - 1u);
    pos += 2u + SS2022_TAG_LEN;
    assert(ss2022_tcp_client_open_payload(&tcp, full_resp + pos, (size_t)first_len + SS2022_TAG_LEN,
                                          opened, sizeof(opened), &opened_len) == SS2022_OK);
    assert(opened_len == sizeof(response_plain) - 1u);
    assert(memcmp(opened, response_plain, opened_len) == 0);

    ss2022_tcp_client_free(&tcp);
    ss2022_client_ctx_free(&ctx);

    assert(ss2022_client_ctx_init(&ctx, SS2022_AES_128_GCM, PSK128_ZERO) == SS2022_OK);
    for (int i = 0; i < 16; i++) {
        assert(ss2022_tcp_client_init(&tcp, &ctx) == SS2022_OK);
        assert(ss2022_tcp_client_build_request_header(&tcp, &addr, NULL, 0u,
                header, sizeof(header), &header_len) == SS2022_OK);
        tcp_empty_base_len = tcp_header_len(&tcp) + addr_len + 2u + SS2022_TAG_LEN;
        assert(header_len >= tcp_empty_base_len + 1u);
        assert(header_len <= tcp_empty_base_len + SS2022_MAX_PADDING_LEN);
        ss2022_tcp_client_free(&tcp);
    }
    ss2022_client_ctx_free(&ctx);

    assert(ss2022_client_ctx_init(&ctx, SS2022_AES_128_GCM, PSK128_ZERO) == SS2022_OK);
    assert(ss2022_tcp_client_init(&tcp, &ctx) == SS2022_OK);
    assert(ss2022_tcp_client_build_request_header(&tcp, &addr, NULL, 0u,
            header, sizeof(header), &header_len) == SS2022_OK);
    const uint8_t inplace_plain[] = "in-place";
    forge_response_zero_then_payload(&tcp, inplace_plain, sizeof(inplace_plain) - 1u,
                                     full_resp, &full_resp_len);
    response_header_len = ss2022_tcp_client_response_header_size(&tcp);
    assert(ss2022_tcp_client_open_response_header(&tcp, full_resp, response_header_len, &first_len) == SS2022_OK);
    assert(first_len == 0u);
    pos = response_header_len;
    assert(ss2022_tcp_client_open_payload(&tcp, full_resp + pos, SS2022_TAG_LEN,
                                          full_resp + pos, sizeof(full_resp) - pos, &opened_len) == SS2022_OK);
    assert(opened_len == 0u);
    pos += SS2022_TAG_LEN;
    assert(ss2022_tcp_client_open_length(&tcp, full_resp + pos, 2u + SS2022_TAG_LEN, &first_len) == SS2022_OK);
    assert(first_len == sizeof(inplace_plain) - 1u);
    pos += 2u + SS2022_TAG_LEN;
    assert(ss2022_tcp_client_open_payload(&tcp, full_resp + pos, (size_t)first_len + SS2022_TAG_LEN,
                                          full_resp + pos, sizeof(full_resp) - pos, &opened_len) == SS2022_OK);
    assert(opened_len == sizeof(inplace_plain) - 1u);
    assert(memcmp(full_resp + pos, inplace_plain, opened_len) == 0);

    ss2022_tcp_client_free(&tcp);
    ss2022_client_ctx_free(&ctx);
}

static void test_addr(void) {
    ss2022_addr addr = make_addr();
    uint8_t buf[300];
    size_t len = 0;
    assert(ss2022_addr_encode(&addr, buf, sizeof(buf), &len) == SS2022_OK);
    ss2022_addr decoded;
    size_t used = 0;
    assert(ss2022_addr_decode(buf, len, &decoded, &used) == SS2022_OK);
    assert(used == len);
    assert(decoded.type == addr.type);
    assert(decoded.port == addr.port);
    assert(decoded.u.domain.len == addr.u.domain.len);
    assert(memcmp(decoded.u.domain.name, addr.u.domain.name, addr.u.domain.len) == 0);
}

static void forge_udp_server_packet(ss2022_udp_client_session *session,
                                    uint64_t packet_id,
                                    const ss2022_addr *source,
                                    const uint8_t *plain,
                                    size_t plain_len,
                                    uint8_t *out,
                                    size_t *out_len) {
    struct ss2022_udp_client_session_impl *s = ss2022_udp_impl(session);
    uint8_t server_sid[8] = {9, 8, 7, 6, 5, 4, 3, 2};
    uint8_t sep[16];
    memcpy(sep, server_sid, 8u);
    ss2022_write_u64be(sep + 8u, packet_id);

    uint8_t subkey[32];
    assert(ss2022_kdf_subkey(s->ctx->psk, s->ctx->psk_len, server_sid, 8u, subkey) == SS2022_OK);

    uint8_t addr_buf[300];
    size_t addr_len = 0;
    assert(ss2022_addr_encode(source, addr_buf, sizeof(addr_buf), &addr_len) == SS2022_OK);

    uint8_t *body = out + 16u;
    size_t pos = 0u;
    body[pos++] = 1u;
    ss2022_write_u64be(body + pos, ss2022_now_seconds());
    pos += 8u;
    memcpy(body + pos, s->client_sid, 8u);
    pos += 8u;
    ss2022_write_u16be(body + pos, 0u);
    pos += 2u;
    memcpy(body + pos, addr_buf, addr_len);
    pos += addr_len;
    memcpy(body + pos, plain, plain_len);
    pos += plain_len;

    Aes aes;
    assert(ss2022_aead_set_key(&aes, subkey, s->ctx->psk_len) == SS2022_OK);
    uint8_t nonce[12];
    memcpy(nonce, sep + 4u, 12u);
    assert(ss2022_aead_seal(&aes, nonce, body, pos, body) == SS2022_OK);
    wc_AesFree(&aes);
    assert(ss2022_aes_encrypt_block(&s->ctx->aes_block_enc, sep, out) == SS2022_OK);
    *out_len = 16u + pos + 16u;
}

static void test_udp(void) {
    ss2022_client_ctx ctx;
    ss2022_udp_client_session s;
    ss2022_addr addr = make_addr();
    const uint8_t msg[] = "hello";
    uint8_t packet[2048];
    size_t packet_len = 0;
    assert(ss2022_client_ctx_init(&ctx, SS2022_AES_128_GCM, PSK128_ZERO) == SS2022_OK);
    assert(ss2022_udp_client_session_init(&s, &ctx) == SS2022_OK);
    struct ss2022_udp_client_session_impl *impl = ss2022_udp_impl(&s);
    assert(impl->next_packet_id == 0u);
    assert(ss2022_udp_client_seal(&s, &addr, msg, sizeof(msg) - 1u, packet, sizeof(packet), &packet_len) == SS2022_OK);
    assert(packet_len > 32u);
    assert(impl->next_packet_id == 1u);
    size_t addr_len = 0u;
    uint8_t addr_buf[300];
    assert(ss2022_addr_encode(&addr, addr_buf, sizeof(addr_buf), &addr_len) == SS2022_OK);
    size_t udp_empty_base_len = 16u + 1u + 8u + 2u + addr_len + 16u;
    bool saw_udp_padding = false;
    for (int i = 0; i < 16; i++) {
        assert(ss2022_udp_client_seal(&s, &addr, NULL, 0u, packet, sizeof(packet), &packet_len) == SS2022_OK);
        assert(packet_len >= udp_empty_base_len);
        assert(packet_len <= udp_empty_base_len + SS2022_MAX_PADDING_LEN);
        if (packet_len > udp_empty_base_len) {
            saw_udp_padding = true;
        }
    }
    assert(saw_udp_padding);

    const uint8_t reply[] = "world";
    forge_udp_server_packet(&s, 0u, &addr, reply, sizeof(reply) - 1u, packet, &packet_len);
    ss2022_addr source;
    uint8_t out[2048];
    size_t out_len = 0;
    assert(ss2022_udp_client_open(&s, packet, packet_len, &source, out, sizeof(out), &out_len) == SS2022_OK);
    assert(out_len == sizeof(reply) - 1u);
    assert(memcmp(out, reply, out_len) == 0);
    assert(ss2022_udp_client_open(&s, packet, packet_len, &source, out, sizeof(out), &out_len) == SS2022_ERR_REPLAY);

    const uint8_t inplace_reply[] = "in-place udp";
    forge_udp_server_packet(&s, 1u, &addr, inplace_reply, sizeof(inplace_reply) - 1u, packet, &packet_len);
    assert(ss2022_udp_client_open(&s, packet, packet_len, &source, packet, sizeof(packet), &out_len) == SS2022_OK);
    assert(out_len == sizeof(inplace_reply) - 1u);
    assert(memcmp(packet, inplace_reply, out_len) == 0);

    ss2022_udp_client_session_free(&s);
    ss2022_client_ctx_free(&ctx);
}

int main(void) {
    test_key_and_kdf();
    test_nonce_and_replay();
    test_addr();
    test_tcp();
    test_udp();
    puts("ss2022 tests passed");
    return 0;
}
