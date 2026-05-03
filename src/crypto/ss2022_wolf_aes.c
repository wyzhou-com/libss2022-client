#include "ss2022_internal.h"

int ss2022_aes_encrypt_block(Aes *aes, const uint8_t in[16], uint8_t out[16]) {
    if (aes == NULL || in == NULL || out == NULL) {
        return SS2022_ERR_INVALID_ARG;
    }
    wc_AesEncryptDirect(aes, out, in);
    return SS2022_OK;
}

int ss2022_aes_decrypt_block(Aes *aes, const uint8_t in[16], uint8_t out[16]) {
    if (aes == NULL || in == NULL || out == NULL) {
        return SS2022_ERR_INVALID_ARG;
    }
    wc_AesDecryptDirect(aes, out, in);
    return SS2022_OK;
}
