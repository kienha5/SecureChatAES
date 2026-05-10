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

    // ─── Cert generation ──────────────────────────────────────
    // Tao self-signed root cert (dung cho CA)
    bool generateSelfSignedCert(
        const std::string& commonName,
        int validDays,
        std::string& outCertPEM,
        std::string& outKeyPEM
    );

    // Tao keypair + cert duoc ky boi CA (dung cho RA, KDC, ChatServer)
    bool generateSignedCert(
        const std::string& commonName,
        int validDays,
        const std::string& caCertPEM,
        const std::string& caKeyPEM,
        std::string& outCertPEM,
        std::string& outKeyPEM
    );

    // Load hoac tao moi neu chua co
    bool loadOrCreate(
        const std::string& certPath,
        const std::string& keyPath,
        const std::string& commonName,
        int validDays,
        const std::string& caCertPEM,  // rong neu la self-signed
        const std::string& caKeyPEM,
        std::string& outCertPEM,
        std::string& outKeyPEM
    );

    // Xin CA server ky cert qua network
    bool requestCertFromCA(
        const std::string& commonName,
        int validDays,
        const std::string& caServerIP,
        int caPort,
        const std::string& caCertPEM,
        std::string& outCertPEM,
        std::string& outKeyPEM
    );
}