#ifndef SS2022_INTERNAL_H
#define SS2022_INTERNAL_H

#include "ss2022_client.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/random.h>

#define SS2022_MAGIC_CTX 0x53534358u
#define SS2022_MAGIC_TCP 0x53535458u
#define SS2022_MAGIC_UDP 0x53535558u

#define SS2022_KEY_MAX 32u
#define SS2022_SALT_MAX 32u
#define SS2022_TAG_LEN 16u
#define SS2022_NONCE_LEN 12u
#define SS2022_UDP_SEPARATE_HEADER_LEN 16u
#define SS2022_TCP_FIXED_REQ_LEN 11u
#define SS2022_REPLAY_WINDOW_BITS 2048u
#define SS2022_UDP_MAX_SERVER_ASSOC 2u
#define SS2022_UDP_ASSOC_KEEP_MS 60000u
#define SS2022_MAX_PADDING_LEN 900u

#ifndef SS2022_TIMESTAMP_TOLERANCE_SECONDS
#define SS2022_TIMESTAMP_TOLERANCE_SECONDS 30
#endif

struct ss2022_client_ctx_impl {
    uint32_t magic;
    ss2022_method_t method;
    uint8_t psk[SS2022_KEY_MAX];
    size_t psk_len;
    size_t salt_len;
    WC_RNG rng;
    bool rng_initialized;
    Aes aes_block_enc;       /* PSK ECB context, encryption direction */
    Aes aes_block_dec;       /* PSK ECB context, decryption direction */
    bool aes_block_initialized;
};

struct ss2022_tcp_stream {
    uint8_t salt[SS2022_SALT_MAX];
    uint8_t subkey[SS2022_KEY_MAX];
    uint8_t nonce[SS2022_NONCE_LEN];
    Aes aes_gcm;
    bool initialized;
};

struct ss2022_tcp_client_impl {
    uint32_t magic;
    struct ss2022_client_ctx_impl *ctx;
    struct ss2022_tcp_stream req;
    struct ss2022_tcp_stream resp;
    uint8_t request_salt[SS2022_SALT_MAX];
    bool request_started;
    bool response_started;
};

struct ss2022_replay_window {
    uint64_t highest;
    uint64_t bitmap[SS2022_REPLAY_WINDOW_BITS / 64u];
};

struct ss2022_udp_server_assoc {
    uint8_t server_sid[8];
    uint8_t subkey[SS2022_KEY_MAX];
    struct ss2022_replay_window replay;
    Aes aes_gcm;             /* cached AEAD context for this server session */
    uint64_t last_seen_ms;
    bool used;
};

struct ss2022_udp_client_session_impl {
    uint32_t magic;
    struct ss2022_client_ctx_impl *ctx;
    uint8_t client_sid[8];
    uint8_t client_subkey[SS2022_KEY_MAX];
    Aes client_aes_gcm;      /* cached AEAD context for outgoing packets */
    uint64_t next_packet_id;
    struct ss2022_udp_server_assoc servers[SS2022_UDP_MAX_SERVER_ASSOC];
    uint64_t created_ms;
    uint64_t last_used_ms;
    bool initialized;
};

_Static_assert(sizeof(struct ss2022_client_ctx_impl) <= SS2022_CLIENT_CTX_STORAGE_SIZE,
               "ss2022_client_ctx storage too small");
_Static_assert(sizeof(struct ss2022_tcp_client_impl) <= SS2022_TCP_CLIENT_STORAGE_SIZE,
               "ss2022_tcp_client storage too small");
_Static_assert(sizeof(struct ss2022_udp_client_session_impl) <= SS2022_UDP_CLIENT_SESSION_STORAGE_SIZE,
               "ss2022_udp_client_session storage too small");

static inline struct ss2022_client_ctx_impl *ss2022_ctx_impl(ss2022_client_ctx *ctx) {
    return (struct ss2022_client_ctx_impl *)(void *)ctx->storage.bytes;
}

static inline const struct ss2022_client_ctx_impl *ss2022_ctx_impl_const(const ss2022_client_ctx *ctx) {
    return (const struct ss2022_client_ctx_impl *)(const void *)ctx->storage.bytes;
}

static inline struct ss2022_tcp_client_impl *ss2022_tcp_impl(ss2022_tcp_client *tcp) {
    return (struct ss2022_tcp_client_impl *)(void *)tcp->storage.bytes;
}

static inline struct ss2022_udp_client_session_impl *ss2022_udp_impl(ss2022_udp_client_session *s) {
    return (struct ss2022_udp_client_session_impl *)(void *)s->storage.bytes;
}

static inline bool ss2022_ranges_overlap(const void *a, size_t a_len, const void *b, size_t b_len) {
    if (a_len == 0u || b_len == 0u) {
        return false;
    }
    uintptr_t a0 = (uintptr_t)a;
    uintptr_t b0 = (uintptr_t)b;
    return a0 < b0 + b_len && b0 < a0 + a_len;
}

size_t ss2022_method_key_len(ss2022_method_t method);
int ss2022_checked_add(size_t a, size_t b, size_t *out);
void ss2022_write_u16be(uint8_t out[2], uint16_t value);
uint16_t ss2022_read_u16be(const uint8_t in[2]);
void ss2022_write_u64be(uint8_t out[8], uint64_t value);
uint64_t ss2022_read_u64be(const uint8_t in[8]);
void ss2022_nonce_increment(uint8_t nonce[SS2022_NONCE_LEN]);
uint64_t ss2022_now_seconds(void);
uint64_t ss2022_now_milliseconds(void);
int ss2022_check_timestamp(uint64_t timestamp);

int ss2022_kdf_subkey(const uint8_t *psk, size_t psk_len,
                      const uint8_t *salt, size_t salt_len,
                      uint8_t out_subkey[SS2022_KEY_MAX]);

int ss2022_random(struct ss2022_client_ctx_impl *ctx, uint8_t *out, size_t len);
int ss2022_aead_set_key(Aes *aes, const uint8_t *key, size_t key_len);
int ss2022_aead_seal(Aes *aes, uint8_t nonce[SS2022_NONCE_LEN],
                     const uint8_t *plain, size_t plain_len,
                     uint8_t *out);
int ss2022_aead_open(Aes *aes, uint8_t nonce[SS2022_NONCE_LEN],
                     const uint8_t *cipher, size_t cipher_len,
                     uint8_t *plain);
int ss2022_aes_encrypt_block(Aes *aes, const uint8_t in[16], uint8_t out[16]);
int ss2022_aes_decrypt_block(Aes *aes, const uint8_t in[16], uint8_t out[16]);

int ss2022_addr_encode(const ss2022_addr *addr, uint8_t *out,
                       size_t out_cap, size_t *out_len);
int ss2022_addr_encoded_len(const ss2022_addr *addr, size_t *out_len);
int ss2022_addr_decode(const uint8_t *in, size_t in_len,
                       ss2022_addr *addr, size_t *consumed);

void ss2022_replay_window_init(struct ss2022_replay_window *w);
int ss2022_replay_window_check(const struct ss2022_replay_window *w, uint64_t id);
void ss2022_replay_window_commit(struct ss2022_replay_window *w, uint64_t id);

int ss2022_tcp_stream_init(struct ss2022_tcp_stream *stream,
                           struct ss2022_client_ctx_impl *ctx,
                           const uint8_t *salt, size_t salt_len);
void ss2022_tcp_stream_free(struct ss2022_tcp_stream *stream);

#endif
