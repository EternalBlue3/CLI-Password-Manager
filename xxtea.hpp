#ifndef XXTEA_HPP
#define XXTEA_HPP

#include <iostream>
#include <vector>
#include <array>
#include <random>
#include <cstdint>
#include <stdexcept>

class XXTEA {
public:
    static std::vector<uint32_t> ctr(const std::vector<uint32_t>& data, const std::array<uint32_t, 4>& key, const std::array<uint32_t, 2>& nonce);
private:
    static uint32_t MX(const uint32_t& sum, const uint32_t& y, const uint32_t& z, const uint32_t p, const uint32_t& e, const std::array<uint32_t, 4>& key);
};

#endif