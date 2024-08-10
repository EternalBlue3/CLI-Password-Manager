#include "hash.hpp"

std::array<uint8_t, 16> generateRandomSalt() {
    std::array<uint8_t, 16> salt;
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint8_t> dis;

    for (size_t i = 0; i < 16; i++) {
        salt[i] = dis(gen);
    }
    
    return salt;
}

std::array<uint32_t, 12> argon2id(const std::string& password, const std::array<uint8_t, 16>& salt) {
    uint32_t t_cost = 16;            // Number of iterations
    uint32_t m_cost = 1 << 17;      // 128 MiB memory usage
    uint32_t parallelism = 2;       // Number of parallel threads

    std::array<uint8_t, 48> hash; // Length of the hash in bytes (48 bytes == 384 bits)
    int result = argon2id_hash_raw(t_cost, m_cost, parallelism, password.data(), password.size(), salt.data(), salt.size(), hash.data(), hash.size());

    if (result != ARGON2_OK) {
        std::string error_message = std::string("Error hashing password: ") + argon2_error_message(result);
        throw std::runtime_error(error_message);
    }

    // Convert the uint8_t array to a uint32_t array so we are able to pass it to the encryption algorithms
    std::array<uint32_t, 12> hash_uint32;
    std::memcpy(hash_uint32.data(), hash.data(), hash.size());

    return hash_uint32;
}