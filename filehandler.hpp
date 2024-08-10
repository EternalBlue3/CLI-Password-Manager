#ifndef FILEHANDLER_HPP
#define FILEHANDLER_HPP

#include <iostream>
#include <vector>
#include <array>
#include <fstream>
#include <filesystem>
#include <string>
#include <cstring>
#include <cstdio>

struct fileData {
    std::vector<uint32_t> data;
    std::array<uint32_t, 3> chacha_nonce;
    std::array<uint32_t, 2> xxtea_nonce;
    std::array<uint8_t, 16> salt;
};

std::vector<uint32_t> stringToVec(const std::string& data);
std::string vecToString(const std::vector<uint32_t>& vec);
fileData readFile(const std::string& username);
void writeFile(const std::string& username, const std::vector<uint32_t>& data, const std::array<uint32_t, 3>& chacha_nonce, const std::array<uint32_t, 2>& xxtea_nonce, const std::array<uint8_t, 16>& salt);
bool userExists(const std::string& username);
void removeUser(const std::string& username);

#endif