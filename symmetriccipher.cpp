#include "symmetriccipher.hpp"

std::vector<uint32_t> cascadeEncrypt(const std::vector<uint32_t>& plaintext, const std::array<uint32_t, 8>& chacha_key, const std::array<uint32_t, 3>& chacha_nonce, const std::array<uint32_t, 4>& xxtea_key, const std::array<uint32_t, 2> xxtea_nonce) {
    std::vector<uint32_t> encrypted = ChaCha20::crypt(plaintext, chacha_key, chacha_nonce);
    return XXTEA::ctr(encrypted, xxtea_key, xxtea_nonce);
}

std::vector<uint32_t> cascadeDecrypt(const std::vector<uint32_t>& plaintext, const std::array<uint32_t, 8>& chacha_key, const std::array<uint32_t, 3>& chacha_nonce, const std::array<uint32_t, 4>& xxtea_key, const std::array<uint32_t, 2> xxtea_nonce) {
    std::vector<uint32_t> encrypted = XXTEA::ctr(plaintext, xxtea_key, xxtea_nonce);
    return ChaCha20::crypt(encrypted, chacha_key, chacha_nonce);
}