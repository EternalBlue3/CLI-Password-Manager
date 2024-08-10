#ifndef SYMMETRICCIPHER_HPP
#define SYMMETRICCIPHER_HPP

#include <vector>
#include <array>
#include <random>

#include "chacha20.hpp"
#include "xxtea.hpp"

std::vector<uint32_t> cascadeEncrypt(const std::vector<uint32_t>& plaintext, const std::array<uint32_t, 8>& chacha_key, const std::array<uint32_t, 3>& chacha_nonce, const std::array<uint32_t, 4>& xxtea_key, const std::array<uint32_t, 2> xxtea_nonce);
std::vector<uint32_t> cascadeDecrypt(const std::vector<uint32_t>& plaintext, const std::array<uint32_t, 8>& chacha_key, const std::array<uint32_t, 3>& chacha_nonce, const std::array<uint32_t, 4>& xxtea_key, const std::array<uint32_t, 2> xxtea_nonce);

template <size_t length>
std::array<uint32_t, length> generateRandomNonce() {
    std::array<uint32_t, length> nonce;
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint32_t> dis;

    for (size_t i = 0; i < nonce.size(); i++) {
        nonce[i] = dis(gen);
    }
    
    return nonce;
}

#endif