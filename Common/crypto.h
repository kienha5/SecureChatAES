#pragma once
#include <string>
#include <vector>

namespace Crypto {
    // RSA
    bool generateRSAKeyPair(std::string& pubKeyPEM, std::string& privKeyPEM);
    std::vector<unsigned char> signData(const std::string& privKeyPEM, const std::vector<unsigned char>& data);
    bool verifySignature(const std::string& pubKeyPEM, const std::vector<unsigned char>& data, const std::vector<unsigned char>& sig);
    std::vector<unsigned char> encryptRSA(const std::string& pubKeyPEM, const std::vector<unsigned char>& plaintext);
    std::vector<unsigned char> decryptRSA(const std::string& privKeyPEM, const std::vector<unsigned char>& ciphertext);

    // AES
    std::vector<unsigned char> aesEncrypt(const std::vector<unsigned char>& key, const std::vector<unsigned char>& iv, const std::vector<unsigned char>& plaintext);
    std::vector<unsigned char> aesDecrypt(const std::vector<unsigned char>& key, const std::vector<unsigned char>& iv, const std::vector<unsigned char>& ciphertext);

    // Hash & Nonce
    std::vector<unsigned char> sha256(const std::vector<unsigned char>& data);
    std::vector<unsigned char> generateNonce(int size = 32);
}