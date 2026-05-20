#include <string>
#include <openssl/evp.h>
#include <openssl/hmac.h>  // 加這行
#include <cstdio>

std::string compute_aes(const std::string& plaintext) {

    unsigned char key[32] = {
        '0','1','2','3','4','5','6','7','8','9','0','1','2','3','4','5',
        '6','7','8','9','0','1','2','3','4','5','6','7','8','9','0','1'
    };
    unsigned char iv[16] = {
        '0','1','2','3','4','5','6','7','8','9','0','1','2','3','4','5'
    };

    unsigned char ciphertext[1024];
    int len = 0, ciphertext_len = 0;

    //Step 1：build evp
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return "ERROR_CTX";

    // Step 2：init
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        EVP_CIPHER_CTX_free(ctx);
        return "ERROR_INIT";
    }

    // Step 3：main
    if (1 != EVP_EncryptUpdate(ctx,
            ciphertext, &len,
            (unsigned char*)plaintext.c_str(), plaintext.length())) {
        EVP_CIPHER_CTX_free(ctx);
        return "ERROR_UPDATE";
    }
    ciphertext_len = len;

    //pading flush
    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + ciphertext_len, &len)) {
        EVP_CIPHER_CTX_free(ctx);
        return "ERROR_FINAL";
    }
    ciphertext_len += len;

    //free
    EVP_CIPHER_CTX_free(ctx);

    //Step 4：byte array to hex
    char hex_str[2048] = {0};
    for (int i = 0; i < ciphertext_len; i++) {
        snprintf(hex_str + i * 2, 3, "%02x", ciphertext[i]);
    }

    //Step 5：HMAC-SHA256
    unsigned char hmac[32];
    unsigned int hmac_len = 0;
    HMAC(EVP_sha256(), key, 32, ciphertext, ciphertext_len, hmac, &hmac_len);

    char hmac_str[65] = {0};
    for (unsigned int i = 0; i < hmac_len; i++) {
        snprintf(hmac_str + i * 2, 3, "%02x", hmac[i]);
    }

    //format cipher:hmac
    return std::string(hex_str) + ":" + std::string(hmac_str);
}