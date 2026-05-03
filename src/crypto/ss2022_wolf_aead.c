#include "ss2022_internal.h"

int ss2022_aead_set_key(Aes *aes, const uint8_t *key, size_t key_len) {
    if (aes == NULL || key == NULL || (key_len != 16u && key_len != 32u)) {
        return SS2022_ERR_INVALID_ARG;
    }
    if (wc_AesGcmSetKey(aes, key, (word32)key_len) != 0) {
        return SS2022_ERR_WOLFSSL;
    }
    return SS2022_OK;
}

int ss2022_aead_seal(Aes *aes, uint8_t nonce[SS2022_NONCE_LEN],
                     const uint8_t *plain, size_t plain_len,
                     uint8_t *out) {
    if (aes == NULL || nonce == NULL || (plain == NULL && plain_len != 0u) || out == NULL ||
            plain_len > UINT32_MAX) {
        return SS2022_ERR_INVALID_ARG;
    }

    uint8_t *tag = out + plain_len;
    int ret = wc_AesGcmEncrypt(aes, out, plain, (word32)plain_len,
                               nonce, SS2022_NONCE_LEN, tag, SS2022_TAG_LEN, NULL, 0u);
    if (ret != 0) {
        return SS2022_ERR_WOLFSSL;
    }
    ss2022_nonce_increment(nonce);
    return SS2022_OK;
}

int ss2022_aead_open(Aes *aes, uint8_t nonce[SS2022_NONCE_LEN],
                     const uint8_t *cipher, size_t cipher_len,
                     uint8_t *plain) {
    if (aes == NULL || nonce == NULL || cipher == NULL || plain == NULL ||
            cipher_len < SS2022_TAG_LEN || cipher_len - SS2022_TAG_LEN > UINT32_MAX) {
        return SS2022_ERR_INVALID_ARG;
    }

    size_t plain_len = cipher_len - SS2022_TAG_LEN;
    const uint8_t *tag = cipher + plain_len;
    int ret = wc_AesGcmDecrypt(aes, plain, cipher, (word32)plain_len,
                               nonce, SS2022_NONCE_LEN, tag, SS2022_TAG_LEN, NULL, 0u);
    if (ret != 0) {
        memset(plain, 0, plain_len);
        return SS2022_ERR_AUTH;
    }
    ss2022_nonce_increment(nonce);
    return SS2022_OK;
}
