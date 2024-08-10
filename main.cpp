#include <iostream>
#include <sstream>
#include <vector>
#include <array>
#include <string>
#include <algorithm>

#include "filehandler.hpp"
#include "hash.hpp"
#include "symmetriccipher.hpp"

std::vector<std::string> getPasswordLines(const std::string& plaintext_data) {
    std::istringstream stream(plaintext_data);
    std::vector<std::string> lines;
    std::string line;
    while (std::getline(stream, line)) {
        lines.push_back(line);
    }
    return lines;
}

void printPasswords(const std::vector<std::string>& lines) {
    for (size_t i = 1; i < lines.size(); i++) {
        std::cout << ' ' << i << ") " << lines[i] << '\n';
    }
}

void addPassword(std::string& plaintext_data) {
    std::string website, username, password;
    std::cout << "Website or application: ";
    std::getline(std::cin, website);
    std::cout << "Username: ";
    std::getline(std::cin, username);
    std::cout << "Password: ";
    std::getline(std::cin, password);

    plaintext_data += website + ' ' + username + ' ' + password + '\n';
}

void removePassword(std::string& plaintext_data) {
    std::vector<std::string> lines = getPasswordLines(plaintext_data);
    if (lines.size() <= 1) { // Account for the header line
        std::cout << "Password database empty.\n";
        return;
    }

    printPasswords(lines);

    size_t index = 0;
    std::cout << "Enter id of password to remove: ";
    if (!(std::cin >> index) || index <= 0 || index >= lines.size()) {
        std::cout << "Entered invalid password Id.\n";
        std::cin.clear(); // Clear the input buffer
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
        return;
    }
    
    std::cin.ignore(); // Ignore newline character after integer input
    lines.erase(lines.begin() + index);

    plaintext_data.clear();
    for (const std::string& entry : lines) {
        plaintext_data += entry + '\n';
    }
}

void searchPassword(const std::string& plaintext_data) {
    std::string query;
    std::cout << "Search password: ";
    std::getline(std::cin, query);

    std::istringstream stream(plaintext_data);
    std::string line;
    bool found = false;

    for (int lineNumber = 1; std::getline(stream, line); lineNumber++) {
        if (line.find(query) != std::string::npos) {
            std::cout << ' ' << lineNumber << ") " << line << '\n';
            found = true;
        }
    }

    if (!found) {
        std::cout << "Password not found.\n";
    }
}

struct ReadData {
    std::string plaintext_data;
    std::array<uint32_t, 8> chacha_key;
    std::array<uint32_t, 4> xxtea_key;
    std::array<uint8_t, 16> salt;
};

ReadData readAndDecrypt(const std::string& username, const std::string& password) {
    ReadData read_data;

    fileData userData = readFile(username);
    std::array<uint32_t, 12> key = argon2id(password, userData.salt);

    read_data.xxtea_key = {key[0], key[1], key[2], key[3]};
    read_data.chacha_key = {key[4], key[5], key[6], key[7], key[8], key[9], key[10], key[11]};
    read_data.salt = userData.salt;

    std::vector<uint32_t> decrypted_data = cascadeDecrypt(userData.data, read_data.chacha_key, userData.chacha_nonce, read_data.xxtea_key, userData.xxtea_nonce);
    read_data.plaintext_data = vecToString(decrypted_data);

    // Remove padding from data
    read_data.plaintext_data.erase(std::remove(read_data.plaintext_data.end() - 4, read_data.plaintext_data.end(), '\0'), read_data.plaintext_data.end());

    return read_data;
}

void saveAndEncrypt(const std::string& username, const std::array<uint32_t, 8>& chacha_key, const std::array<uint32_t, 4>& xxtea_key, const std::array<uint8_t, 16>& salt, const std::string& plaintext_data) {
    std::vector<uint32_t> unencryptedVec = stringToVec(plaintext_data);
    std::array<uint32_t, 3> chacha_nonce = generateRandomNonce<3>();
    std::array<uint32_t, 2> xxtea_nonce = generateRandomNonce<2>();
    std::vector<uint32_t> encrypted_data = cascadeEncrypt(unencryptedVec, chacha_key, chacha_nonce, xxtea_key, xxtea_nonce);
    writeFile(username, encrypted_data, chacha_nonce, xxtea_nonce, salt);
}

int main() {
    const std::string passwordSuccessCheck = "This is a header to test for successful decryption.\n";
    std::string menu_option, username, password;

    std::cout << "Options:    Login (1)    Create Profile (2)    Delete Profile (3)    Exit (ctrl+c or 4)\n";
    std::cout << "Enter option: ";
    std::getline(std::cin, menu_option);

    if (menu_option == "1") {
        std::cout << "Username: ";
        std::getline(std::cin, username);
        std::cout << "Password: ";
        std::getline(std::cin, password);
        std::cout << "\nReading and Decrypting User Data...\n";

        ReadData read_data = readAndDecrypt(username, password);

        if (read_data.plaintext_data.compare(0, passwordSuccessCheck.length(), passwordSuccessCheck) != 0) {
            std::cout << "Incorrect Password\n";
            return 0;
        }

        while (true) {
            std::string user_option;
            std::cout << "\nOptions:    Save Password (1)    Remove Password (2)    Show Saved Passwords (3)    Search For Password (4)    Exit And Encrypt Data (5)\n";
            std::cout << "Enter option: ";
            std::getline(std::cin, user_option);

            if (user_option == "1") {
                addPassword(read_data.plaintext_data);
            } else if (user_option == "2") {
                removePassword(read_data.plaintext_data);
            } else if (user_option == "3") {
                printPasswords(getPasswordLines(read_data.plaintext_data));
            } else if (user_option == "4") {
                searchPassword(read_data.plaintext_data);
            } else if (user_option == "5") {
                saveAndEncrypt(username, read_data.chacha_key, read_data.xxtea_key, read_data.salt, read_data.plaintext_data);
                return 0;
            } else {
                std::cout << "Invalid menu option selection\n";
            }
        }
    } else if (menu_option == "2") {
        std::cout << "New Username: ";
        std::getline(std::cin, username);

        if (userExists(username)) {
            std::cout << "User already exists. If you would like to replace this user, delete the user profile before recreating.\n";
            return 0;
        }

        std::cout << "New Password: ";
        std::getline(std::cin, password);

        std::array<uint8_t, 16> salt = generateRandomSalt();
        std::array<uint32_t, 12> key = argon2id(password, salt);

        std::array<uint32_t, 3> chacha_nonce = generateRandomNonce<3>();
        std::array<uint32_t, 8> chacha_key = {key[4], key[5], key[6], key[7], key[8], key[9], key[10], key[11]};
        std::array<uint32_t, 2> xxtea_nonce = generateRandomNonce<2>();
        std::array<uint32_t, 4> xxtea_key = {key[0], key[1], key[2], key[3]};

        std::vector<uint32_t> header = stringToVec(passwordSuccessCheck);
        std::vector<uint32_t> encrypted_header = cascadeEncrypt(header, chacha_key, chacha_nonce, xxtea_key, xxtea_nonce);

        writeFile(username, encrypted_header, chacha_nonce, xxtea_nonce, salt);    
        std::cout << "User Created.\n";
    } else if (menu_option == "3") {
        std::cout << "Username: ";
        std::getline(std::cin, username);

        if (!userExists(username)) {
            std::cout << "User does not exist. Please enter name of valid user.\n";
            return 0;
        }

        std::cout << "Confirm Password Before Deletion: ";
        std::getline(std::cin, password);

        ReadData read_data = readAndDecrypt(username, password);
        if (read_data.plaintext_data.compare(0, passwordSuccessCheck.length(), passwordSuccessCheck) != 0) {
            std::cout << "Incorrect Password\n";
            return 0;
        }

        removeUser(username);
        std::cout << "User successfully deleted.\n";
    } else if (menu_option == "4") {
        return 0;
    } else {
        std::cout << "Invalid menu option selection\n";
    }

    return 0;
}