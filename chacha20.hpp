#ifndef CHACHA20_HPP
#define CHACHA20_HPP

#include <cstdint>
#include <cstring>
#include <vector>
#include <array>

class ChaCha20 {
public:
    static std::vector<uint32_t> crypt(const std::vector<uint32_t>& plaintext, const std::array<uint32_t, 8>& key, const std::array<uint32_t, 3>& nonce);
private:
    static void chacha20Block(uint32_t (&output)[16], const uint32_t (&input)[16]);
    static void quarterRound(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d);
    static uint32_t rotate(const uint32_t& v, const uint32_t c);
};

#endif