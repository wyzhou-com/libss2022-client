#ifndef SS2022_CLIENT_H
#define SS2022_CLIENT_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SS2022_CLIENT_CTX_STORAGE_SIZE 4096u
#define SS2022_TCP_CLIENT_STORAGE_SIZE 8192u
#define SS2022_UDP_CLIENT_SESSION_STORAGE_SIZE 4096u
#define SS2022_TCP_PAYLOAD_CHUNK_PREFIX_LEN 18u

typedef enum {
    SS2022_AES_128_GCM = 1,
    SS2022_AES_256_GCM = 2,
} ss2022_method_t;

typedef enum {
    SS2022_OK = 0,
    SS2022_ERR_INVALID_ARG = -1,
    SS2022_ERR_BAD_KEY = -2,
    SS2022_ERR_RNG = -3,
    SS2022_ERR_AUTH = -4,
    SS2022_ERR_REPLAY = -5,
    SS2022_ERR_STALE_TIMESTAMP = -6,
    SS2022_ERR_BAD_TYPE = -7,
    SS2022_ERR_BAD_ADDR = -8,
    SS2022_ERR_BUFFER_TOO_SMALL = -9,
    SS2022_ERR_MALFORMED = -10,
    SS2022_ERR_STATE = -11,
    SS2022_ERR_WOLFSSL = -12
} ss2022_error_t;

typedef struct ss2022_client_ctx {
    union {
        max_align_t align;
        unsigned char bytes[SS2022_CLIENT_CTX_STORAGE_SIZE];
    } storage;
} ss2022_client_ctx;

typedef struct ss2022_tcp_client {
    union {
        max_align_t align;
        unsigned char bytes[SS2022_TCP_CLIENT_STORAGE_SIZE];
    } storage;
} ss2022_tcp_client;

typedef struct ss2022_udp_client_session {
    union {
        max_align_t align;
        unsigned char bytes[SS2022_UDP_CLIENT_SESSION_STORAGE_SIZE];
    } storage;
} ss2022_udp_client_session;

typedef enum {
    SS2022_ADDR_IPV4 = 1,
    SS2022_ADDR_DOMAIN = 3,
    SS2022_ADDR_IPV6 = 4
} ss2022_addr_type_t;

typedef struct {
    ss2022_addr_type_t type;
    uint16_t port;
    union {
        uint8_t ipv4[4];
        uint8_t ipv6[16];
        struct {
            uint8_t len;
            uint8_t name[255];
        } domain;
    } u;
} ss2022_addr;

int ss2022_client_ctx_init(
    ss2022_client_ctx *ctx,
    ss2022_method_t method,
    const char *base64_psk
);

void ss2022_client_ctx_free(ss2022_client_ctx *ctx);

int ss2022_tcp_client_init(
    ss2022_tcp_client *tcp,
    ss2022_client_ctx *ctx
);

void ss2022_tcp_client_free(ss2022_tcp_client *tcp);

int ss2022_tcp_client_build_request_header(
    ss2022_tcp_client *tcp,
    const ss2022_addr *target,
    const uint8_t *initial_payload,
    size_t initial_payload_len,
    uint8_t *out,
    size_t out_cap,
    size_t *out_len
);

/* For a single payload chunk, callers may read plaintext directly at
 * out + SS2022_TCP_PAYLOAD_CHUNK_PREFIX_LEN and pass that pointer as plain. */
int ss2022_tcp_client_seal_payload(
    ss2022_tcp_client *tcp,
    const uint8_t *plain,
    size_t plain_len,
    uint8_t *out,
    size_t out_cap,
    size_t *out_len
);

int ss2022_tcp_client_open_response_header(
    ss2022_tcp_client *tcp,
    const uint8_t *in,
    size_t in_len,
    uint16_t *first_payload_len
);

/* `plain` may be equal to `in` for exact in-place payload open. */
int ss2022_tcp_client_open_payload(
    ss2022_tcp_client *tcp,
    const uint8_t *in,
    size_t in_len,
    uint8_t *plain,
    size_t plain_cap,
    size_t *plain_len
);

int ss2022_tcp_client_open_length(
    ss2022_tcp_client *tcp,
    const uint8_t *in,
    size_t in_len,
    uint16_t *payload_len
);

/* Returns the exact byte count consumed by ss2022_tcp_client_open_response_header,
 * or 0 if tcp is not initialized. */
size_t ss2022_tcp_client_response_header_size(const ss2022_tcp_client *tcp);

int ss2022_udp_client_session_init(
    ss2022_udp_client_session *s,
    ss2022_client_ctx *ctx
);

void ss2022_udp_client_session_free(
    ss2022_udp_client_session *s
);

int ss2022_udp_client_seal(
    ss2022_udp_client_session *s,
    const ss2022_addr *target,
    const uint8_t *payload,
    size_t payload_len,
    uint8_t *out,
    size_t out_cap,
    size_t *out_len
);

/* `payload` may alias `packet` for in-place open; on success the user payload
 * is moved to the start of `payload`. */
int ss2022_udp_client_open(
    ss2022_udp_client_session *s,
    const uint8_t *packet,
    size_t packet_len,
    ss2022_addr *source_addr,
    uint8_t *payload,
    size_t payload_cap,
    size_t *payload_len
);

#ifdef __cplusplus
}
#endif

#endif
