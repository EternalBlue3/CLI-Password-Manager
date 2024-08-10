#ifndef HASH_HPP
#define HASH_HPP

#include <iostream>
#include <string>
#include <cstring>
#include <vector>
#include <array>
#include <random>
#include <argon2.h>
#include <cstdlib>

std::array<uint8_t, 16> generateRandomSalt();
std::array<uint32_t, 12> argon2id(const std::string& password, const std::array<uint8_t, 16>& salt);

#endif