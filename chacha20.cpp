#include "chacha20.hpp"

std::vector<uint32_t> ChaCha20::crypt(const std::vector<uint32_t>& plaintext, const std::array<uint32_t, 8>& key, const std::array<uint32_t, 3>& nonce) {
    // Initialize ciphertext, input, and output
    std::vector<uint32_t> ciphertext(plaintext.size());
    uint32_t input[16];
    uint32_t output[16];

    // Setup initial state
    input[0] = 0x61707865;
    input[1] = 0x3320646e;
    input[2] = 0x79622d32;
    input[3] = 0x6b206574;
    for (int i = 0; i < 8; i++) {
        input[4 + i] = key[i];
    }    
    input[12] = 0;
    input[13] = nonce[0];
    input[14] = nonce[1];
    input[15] = nonce[2];

    // Encrypt
    for (size_t offset = 0; offset < plaintext.size(); offset += 16) { // 16 * 4 bytes = 64 bytes
        input[12] = static_cast<uint32_t>(offset / 16);
        chacha20Block(output, input);
        for (size_t i = 0; i < 16 && offset + i < plaintext.size(); i++) {
            ciphertext[offset + i] = plaintext[offset + i] ^ output[i];
        }
    }

    return ciphertext;
}

void ChaCha20::chacha20Block(uint32_t (&output)[16], const uint32_t (&input)[16]) {
    for (int i = 0; i < 16; i++) {
        output[i] = input[i];
    }
    
    for (int i = 0; i < 10; i++) { // 10 because 2 double rounds
        quarterRound(output[0], output[4], output[ 8], output[12]);
        quarterRound(output[1], output[5], output[ 9], output[13]);
        quarterRound(output[2], output[6], output[10], output[14]);
        quarterRound(output[3], output[7], output[11], output[15]);
        
        quarterRound(output[0], output[5], output[10], output[15]);
        quarterRound(output[1], output[6], output[11], output[12]);
        quarterRound(output[2], output[7], output[ 8], output[13]);
        quarterRound(output[3], output[4], output[ 9], output[14]);
    }
    
    for (int i = 0; i < 16; i++) {
        output[i] += input[i];
    }
}

void ChaCha20::quarterRound(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d) {
    a += b; d ^= a; d = rotate(d, 16);
    c += d; b ^= c; b = rotate(b, 12);
    a += b; d ^= a; d = rotate(d, 8);
    c += d; b ^= c; b = rotate(b, 7);
}

uint32_t ChaCha20::rotate(const uint32_t& v, const uint32_t c) {
    return (v << c) | (v >> (32 - c));
}