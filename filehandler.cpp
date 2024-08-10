#include "filehandler.hpp"

std::vector<uint32_t> stringToVec(const std::string& data) {
    std::vector<uint32_t> vec((data.size() + 3) / 4);
    std::memcpy(vec.data(), data.data(), data.size());
    return vec;
}

std::string vecToString(const std::vector<uint32_t>& vec) {
    std::string data(vec.size() * 4, '\0');
    std::memcpy(data.data(), vec.data(), vec.size() * 4);
    return data;
}


fileData readFile(const std::string& username) {
    fileData file_contents;

    // Read data file
    std::ifstream dataFile("profiles/" + username + "-data.bin", std::ios::binary | std::ios::ate);
    if (!dataFile.is_open()) {
        throw std::runtime_error("There was an error reading data from a file. This is most likely because you entered an incorrect username.");
    }

    std::ifstream::pos_type fileSize = dataFile.tellg();
    dataFile.seekg(0, std::ios::beg);

    file_contents.data.resize(fileSize / 4); // 4 bytes for 32 bit unsigned integer
    dataFile.read(reinterpret_cast<char*>(file_contents.data.data()), fileSize);
    dataFile.close();

    // Read parameter file 
    std::ifstream parameterFile("profiles/" + username + "-parameters.bin", std::ios::binary);
    if (!parameterFile.is_open()) {
        throw std::runtime_error("Could not open nonce file to read data.");
    }

    parameterFile.read(reinterpret_cast<char*>(file_contents.chacha_nonce.data()), 12); // Read the 96 bit ChaCha20 nonce
    parameterFile.read(reinterpret_cast<char*>(file_contents.xxtea_nonce.data()), 8); // Read the 64 bit XXTEA nonce
    parameterFile.read(reinterpret_cast<char*>(file_contents.salt.data()), 16); // Read the 128 bit salt
    parameterFile.close();
    
    return file_contents;
}

void writeFile(const std::string& username, const std::vector<uint32_t>& data, const std::array<uint32_t, 3>& chacha_nonce, const std::array<uint32_t, 2>& xxtea_nonce, const std::array<uint8_t, 16>& salt) {
    // Store data in data file
    std::ofstream dataFile("profiles/" + username + "-data.bin", std::ios::binary);    
    if (!dataFile.is_open()) {
        throw std::runtime_error("Could not open file to write data.");
    }
    
    dataFile.write(reinterpret_cast<const char*>(data.data()), data.size() * 4); // Multiply by 4 bytes for 32 bit unsigned integer
    dataFile.close();

    // Store nonce and salt in parameters file
    std::ofstream parameterFile("profiles/" + username + "-parameters.bin", std::ios::binary);    
    if (!parameterFile.is_open()) {
        throw std::runtime_error("Could not open file to write data.");
    }

    parameterFile.write(reinterpret_cast<const char*>(chacha_nonce.data()), chacha_nonce.size() * 4); // Multiply by 4 bytes for 32 bit unsigned integer
    parameterFile.write(reinterpret_cast<const char*>(xxtea_nonce.data()), xxtea_nonce.size() * 4);
    parameterFile.write(reinterpret_cast<const char*>(salt.data()), salt.size());
    parameterFile.close();
}

bool userExists(const std::string& username) {
    std::string dataFile = "profiles/" + username + "-data.bin";
    return std::filesystem::exists(dataFile);
}

void removeUser(const std::string& username) {
    std::string dataFile = "profiles/" + username + "-data.bin";
    std::string parameterFile = "profiles/" + username + "-parameters.bin";
    remove(dataFile.c_str());
    remove(parameterFile.c_str());
}