#include "ss2022_internal.h"

#include <blake3.h>

int ss2022_kdf_subkey(const uint8_t *psk, size_t psk_len,
                      const uint8_t *salt, size_t salt_len,
                      uint8_t out_subkey[SS2022_KEY_MAX]) {
    if (psk == NULL || salt == NULL || out_subkey == NULL ||
            (psk_len != 16u && psk_len != 32u) || salt_len == 0u || salt_len > SS2022_SALT_MAX) {
        return SS2022_ERR_INVALID_ARG;
    }

    blake3_hasher hasher;
    blake3_hasher_init_derive_key(&hasher, "shadowsocks 2022 session subkey");
    blake3_hasher_update(&hasher, psk, psk_len);
    blake3_hasher_update(&hasher, salt, salt_len);
    blake3_hasher_finalize(&hasher, out_subkey, psk_len);
    memset(out_subkey + psk_len, 0, SS2022_KEY_MAX - psk_len);
    return SS2022_OK;
}
