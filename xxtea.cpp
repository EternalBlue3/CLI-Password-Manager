#include "xxtea.hpp"

std::vector<uint32_t> XXTEA::ctr(const std::vector<uint32_t>& data, const std::array<uint32_t, 4>& key, const std::array<uint32_t, 2>& nonce) {
    uint32_t n = static_cast<uint32_t>(data.size());
    if (n < 2) {
        throw std::runtime_error("Data size must be greater than 64 bits. Note: this includes padding so the minimum number of bits the actually must be entered is 40.");
    }

    std::vector<uint32_t> encrypted_data(data);
    uint32_t low_nonce = nonce[1], high_nonce = nonce[0]; // Low 32 bits and high 32 bits on nonce

    uint32_t y, z, sum;
    const uint32_t delta = 0x9e3779b9;
    const uint32_t rounds = 256;

    for (size_t i = 0; i < n; i += 2) {
        y = low_nonce;
        z = high_nonce;
        sum = 0;

        for (uint32_t r = 0; r < rounds; r++) {
            sum += delta;
            uint32_t e = (sum >> 2) & 3;
            y += MX(sum, y, z, 0, e, key);
            z += MX(sum, z, y, 1, e, key);
        }

        encrypted_data[i] ^= y;
        if (i + 1 < n) {
            encrypted_data[i + 1] ^= z;
        }

        if (low_nonce++ == 0) { // If low nonce overflows, increment high nonce
            high_nonce++;
        }
    }

    return encrypted_data;
}

uint32_t XXTEA::MX(const uint32_t& sum, const uint32_t& y, const uint32_t& z, const uint32_t p, const uint32_t& e, const std::array<uint32_t, 4>& key) {
    return ((z >> 5 ^ y << 2) + (y >> 3 ^ z << 4)) ^ ((sum ^ y) + (key[(p & 3) ^ e] ^ z));
}