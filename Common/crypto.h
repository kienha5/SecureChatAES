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
    // Tạo self-signed root cert (dùng cho CA)
    bool generateSelfSignedCert(
        const std::string& commonName,
        int validDays,
        std::string& outCertPEM,
        std::string& outKeyPEM
    );

    // Tạo keypair + cert được ký bởi CA (dùng cho RA, KDC, ChatServer)
    bool generateSignedCert(
        const std::string& commonName,
        int validDays,
        const std::string& caCertPEM,
        const std::string& caKeyPEM,
        std::string& outCertPEM,
        std::string& outKeyPEM
    );

    // Load hoặc tạo mới nếu chưa có
    bool loadOrCreate(
        const std::string& certPath,
        const std::string& keyPath,
        const std::string& commonName,
        int validDays,
        const std::string& caCertPEM,  // rỗng nếu là self-signed
        const std::string& caKeyPEM,
        std::string& outCertPEM,
        std::string& outKeyPEM
    );

    // Xin CA server ký cert qua network
    bool requestCertFromCA(
        const std::string& commonName,
        int validDays,
        const std::string& caServerIP,
        int caPort,
        const std::string& caCertPEM,
        std::string& outCertPEM,
        std::string& outKeyPEM
    );

    // Tạo CA cert được ký bởi CA khác (dùng cho Intermediate CA)
    // isCA = true: thêm Basic Constraints CA:true
    bool generateCACert(
        const std::string& commonName,
        int validDays,
        const std::string& issuerCertPEM,
        const std::string& issuerKeyPEM,
        std::string& outCertPEM,
        std::string& outKeyPEM
    );

    // Verify toàn bộ chain: cert -> intermCA -> rootCA
    bool verifyCertChain(
        const std::string& certPEM,
        const std::string& intermCACertPEM,
        const std::string& rootCACertPEM
    );
}