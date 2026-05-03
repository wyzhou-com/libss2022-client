#include "ss2022_internal.h"

size_t ss2022_method_key_len(ss2022_method_t method) {
    if (method == SS2022_AES_128_GCM) {
        return 16u;
    }
    if (method == SS2022_AES_256_GCM) {
        return 32u;
    }
    return 0u;
}

int ss2022_checked_add(size_t a, size_t b, size_t *out) {
    if (out == NULL) {
        return SS2022_ERR_INVALID_ARG;
    }
    if (a > SIZE_MAX - b) {
        return SS2022_ERR_BUFFER_TOO_SMALL;
    }
    *out = a + b;
    return SS2022_OK;
}

void ss2022_write_u16be(uint8_t out[2], uint16_t value) {
    out[0] = (uint8_t)(value >> 8);
    out[1] = (uint8_t)value;
}

uint16_t ss2022_read_u16be(const uint8_t in[2]) {
    return (uint16_t)(((uint16_t)in[0] << 8) | (uint16_t)in[1]);
}

static uint64_t ss2022_bswap64(uint64_t value) {
#if defined(__GNUC__) || defined(__clang__)
    return __builtin_bswap64(value);
#else
    return ((value & UINT64_C(0x00000000000000ff)) << 56) |
           ((value & UINT64_C(0x000000000000ff00)) << 40) |
           ((value & UINT64_C(0x0000000000ff0000)) << 24) |
           ((value & UINT64_C(0x00000000ff000000)) << 8) |
           ((value & UINT64_C(0x000000ff00000000)) >> 8) |
           ((value & UINT64_C(0x0000ff0000000000)) >> 24) |
           ((value & UINT64_C(0x00ff000000000000)) >> 40) |
           ((value & UINT64_C(0xff00000000000000)) >> 56);
#endif
}

void ss2022_write_u64be(uint8_t out[8], uint64_t value) {
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    value = ss2022_bswap64(value);
    memcpy(out, &value, sizeof(value));
#elif defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    memcpy(out, &value, sizeof(value));
#else
    for (size_t i = 0; i < 8u; i++) {
        out[7u - i] = (uint8_t)(value >> (i * 8u));
    }
#endif
}

uint64_t ss2022_read_u64be(const uint8_t in[8]) {
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    uint64_t value;
    memcpy(&value, in, sizeof(value));
    return ss2022_bswap64(value);
#elif defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    uint64_t value;
    memcpy(&value, in, sizeof(value));
    return value;
#else
    uint64_t value = 0u;
    for (size_t i = 0; i < 8u; i++) {
        value = (value << 8) | (uint64_t)in[i];
    }
    return value;
#endif
}

void ss2022_nonce_increment(uint8_t nonce[SS2022_NONCE_LEN]) {
    for (size_t i = 0; i < SS2022_NONCE_LEN; i++) {
        nonce[i]++;
        if (nonce[i] != 0u) {
            break;
        }
    }
}
