#include "pch.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include "../Common/utils.h"
#include "../Common/crypto.h"
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/aes.h>
#include <fstream>
#include <openssl/ssl.h>
#include "message.h"
#include <openssl/x509v3.h>

namespace Crypto {

    // ─── RSA ──────────────────────────────────────────────────
    bool generateRSAKeyPair(std::string& pubKeyPEM, std::string& privKeyPEM) {
        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
        if (!ctx) return false;

        if (EVP_PKEY_keygen_init(ctx) <= 0) { EVP_PKEY_CTX_free(ctx); return false; }
        if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0) { EVP_PKEY_CTX_free(ctx); return false; }

        EVP_PKEY* pkey = nullptr;
        if (EVP_PKEY_keygen(ctx, &pkey) <= 0) { EVP_PKEY_CTX_free(ctx); return false; }
        EVP_PKEY_CTX_free(ctx);

        // Public key → PEM string
        BIO* pub = BIO_new(BIO_s_mem());
        PEM_write_bio_PUBKEY(pub, pkey);
        BUF_MEM* pubPtr;
        BIO_get_mem_ptr(pub, &pubPtr);
        pubKeyPEM = std::string(pubPtr->data, pubPtr->length);
        BIO_free(pub);

        // Private key → PEM string
        BIO* priv = BIO_new(BIO_s_mem());
        PEM_write_bio_PrivateKey(priv, pkey, nullptr, nullptr, 0, nullptr, nullptr);
        BUF_MEM* privPtr;
        BIO_get_mem_ptr(priv, &privPtr);
        privKeyPEM = std::string(privPtr->data, privPtr->length);
        BIO_free(priv);

        EVP_PKEY_free(pkey);
        return true;
    }

    std::vector<unsigned char> signData(const std::string& privKeyPEM, const std::vector<unsigned char>& data) {
        BIO* bio = BIO_new_mem_buf(privKeyPEM.data(), (int)privKeyPEM.size());
        EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
        BIO_free(bio);
        if (!pkey) return {};

        EVP_MD_CTX* mdCtx = EVP_MD_CTX_new();
        EVP_DigestSignInit(mdCtx, nullptr, EVP_sha256(), nullptr, pkey);
        EVP_DigestSignUpdate(mdCtx, data.data(), data.size());

        size_t sigLen = 0;
        EVP_DigestSignFinal(mdCtx, nullptr, &sigLen);
        std::vector<unsigned char> sig(sigLen);
        EVP_DigestSignFinal(mdCtx, sig.data(), &sigLen);
        sig.resize(sigLen);

        EVP_MD_CTX_free(mdCtx);
        EVP_PKEY_free(pkey);
        return sig;
    }

    bool verifySignature(const std::string& pubKeyPEM, const std::vector<unsigned char>& data, const std::vector<unsigned char>& sig) {
        BIO* bio = BIO_new_mem_buf(pubKeyPEM.data(), (int)pubKeyPEM.size());
        EVP_PKEY* pkey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
        BIO_free(bio);
        if (!pkey) return false;

        EVP_MD_CTX* mdCtx = EVP_MD_CTX_new();
        EVP_DigestVerifyInit(mdCtx, nullptr, EVP_sha256(), nullptr, pkey);
        EVP_DigestVerifyUpdate(mdCtx, data.data(), data.size());
        int result = EVP_DigestVerifyFinal(mdCtx, sig.data(), sig.size());

        EVP_MD_CTX_free(mdCtx);
        EVP_PKEY_free(pkey);
        return result == 1;
    }

    std::vector<unsigned char> encryptRSA(const std::string& pubKeyPEM, const std::vector<unsigned char>& plaintext) {
        BIO* bio = BIO_new_mem_buf(pubKeyPEM.data(), (int)pubKeyPEM.size());
        EVP_PKEY* pkey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
        BIO_free(bio);
        if (!pkey) return {};

        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, nullptr);
        EVP_PKEY_encrypt_init(ctx);
        EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING);

        size_t outLen = 0;
        EVP_PKEY_encrypt(ctx, nullptr, &outLen, plaintext.data(), plaintext.size());
        std::vector<unsigned char> out(outLen);
        EVP_PKEY_encrypt(ctx, out.data(), &outLen, plaintext.data(), plaintext.size());
        out.resize(outLen);

        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return out;
    }

    std::vector<unsigned char> decryptRSA(const std::string& privKeyPEM, const std::vector<unsigned char>& ciphertext) {
        BIO* bio = BIO_new_mem_buf(privKeyPEM.data(), (int)privKeyPEM.size());
        EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
        BIO_free(bio);
        if (!pkey) return {};

        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, nullptr);
        EVP_PKEY_decrypt_init(ctx);
        EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING);

        size_t outLen = 0;
        EVP_PKEY_decrypt(ctx, nullptr, &outLen, ciphertext.data(), ciphertext.size());
        std::vector<unsigned char> out(outLen);
        EVP_PKEY_decrypt(ctx, out.data(), &outLen, ciphertext.data(), ciphertext.size());
        out.resize(outLen);

        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return out;
    }

    // ─── AES ──────────────────────────────────────────────────
    std::vector<unsigned char> aesEncrypt(const std::vector<unsigned char>& key, const std::vector<unsigned char>& iv, const std::vector<unsigned char>& plaintext) {
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data());

        std::vector<unsigned char> out(plaintext.size() + AES_BLOCK_SIZE);
        int len = 0, totalLen = 0;
        EVP_EncryptUpdate(ctx, out.data(), &len, plaintext.data(), (int)plaintext.size());
        totalLen = len;
        EVP_EncryptFinal_ex(ctx, out.data() + len, &len);
        totalLen += len;
        out.resize(totalLen);

        EVP_CIPHER_CTX_free(ctx);
        return out;
    }

    std::vector<unsigned char> aesDecrypt(const std::vector<unsigned char>& key, const std::vector<unsigned char>& iv, const std::vector<unsigned char>& ciphertext) {
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data());

        std::vector<unsigned char> out(ciphertext.size());
        int len = 0, totalLen = 0;
        EVP_DecryptUpdate(ctx, out.data(), &len, ciphertext.data(), (int)ciphertext.size());
        totalLen = len;
        EVP_DecryptFinal_ex(ctx, out.data() + len, &len);
        totalLen += len;
        out.resize(totalLen);

        EVP_CIPHER_CTX_free(ctx);
        return out;
    }

    // ─── Hash & Nonce ─────────────────────────────────────────
    std::vector<unsigned char> sha256(const std::vector<unsigned char>& data) {
        std::vector<unsigned char> hash(SHA256_DIGEST_LENGTH);
        SHA256(data.data(), data.size(), hash.data());
        return hash;
    }

    std::vector<unsigned char> generateNonce(int size) {
        std::vector<unsigned char> nonce(size);
        RAND_bytes(nonce.data(), size);
        return nonce;
    }

    // ─── Cert Generation ──────────────────────────────────────────

    // Tạo X509 cert va ky
    static X509* buildCert(
        const std::string& commonName,
        int validDays,
        EVP_PKEY* subjectKey,
        X509* issuerCert,    // nullptr = self-signed
        EVP_PKEY* issuerKey,
        int serial
    ) {
        X509* cert = X509_new();
        if (!cert) return nullptr;

        // Serial
        ASN1_INTEGER_set(X509_get_serialNumber(cert), serial);

        // Validity
        X509_gmtime_adj(X509_get_notBefore(cert), 0);
        X509_gmtime_adj(X509_get_notAfter(cert), 60LL * 60 * 24 * validDays);

        // Subject CN
        X509_NAME* name = X509_get_subject_name(cert);
        X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
            (unsigned char*)commonName.c_str(), -1, -1, 0);

        // Issuer: self-signed thi issuer = subject
        X509* issuer = issuerCert ? issuerCert : cert;
        X509_set_issuer_name(cert, X509_get_subject_name(issuer));

        // Public key
        X509_set_pubkey(cert, subjectKey);

        // Sign
        if (X509_sign(cert, issuerKey, EVP_sha256()) == 0) {
            X509_free(cert);
            return nullptr;
        }

        return cert;
    }

    static std::string x509ToPEM(X509* cert) {
        BIO* bio = BIO_new(BIO_s_mem());
        PEM_write_bio_X509(bio, cert);
        BUF_MEM* ptr;
        BIO_get_mem_ptr(bio, &ptr);
        std::string pem(ptr->data, ptr->length);
        BIO_free(bio);
        return pem;
    }

    static std::string pkeyToPEM(EVP_PKEY* pkey) {
        BIO* bio = BIO_new(BIO_s_mem());
        PEM_write_bio_PrivateKey(bio, pkey, nullptr,
            nullptr, 0, nullptr, nullptr);
        BUF_MEM* ptr;
        BIO_get_mem_ptr(bio, &ptr);
        std::string pem(ptr->data, ptr->length);
        BIO_free(bio);
        return pem;
    }

    bool Crypto::generateSelfSignedCert(
        const std::string& commonName,
        int validDays,
        std::string& outCertPEM,
        std::string& outKeyPEM)
    {
        // Sinh keypair
        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
        EVP_PKEY_keygen_init(ctx);
        EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048);
        EVP_PKEY* pkey = nullptr;
        if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            return false;
        }
        EVP_PKEY_CTX_free(ctx);

        // Tao self-signed cert
        X509* cert = buildCert(commonName, validDays,
            pkey, nullptr, pkey, 1);
        if (!cert) { EVP_PKEY_free(pkey); return false; }

        outCertPEM = x509ToPEM(cert);
        outKeyPEM = pkeyToPEM(pkey);

        X509_free(cert);
        EVP_PKEY_free(pkey);
        return true;
    }

    bool Crypto::generateSignedCert(
        const std::string& commonName,
        int validDays,
        const std::string& caCertPEM,
        const std::string& caKeyPEM,
        std::string& outCertPEM,
        std::string& outKeyPEM)
    {
        // Load CA cert + key
        BIO* cb = BIO_new_mem_buf(caCertPEM.data(), (int)caCertPEM.size());
        X509* caCert = PEM_read_bio_X509(cb, nullptr, nullptr, nullptr);
        BIO_free(cb);

        BIO* kb = BIO_new_mem_buf(caKeyPEM.data(), (int)caKeyPEM.size());
        EVP_PKEY* caKey = PEM_read_bio_PrivateKey(kb, nullptr, nullptr, nullptr);
        BIO_free(kb);

        if (!caCert || !caKey) {
            if (caCert) X509_free(caCert);
            if (caKey)  EVP_PKEY_free(caKey);
            return false;
        }

        // Sinh keypair moi cho subject
        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
        EVP_PKEY_keygen_init(ctx);
        EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048);
        EVP_PKEY* pkey = nullptr;
        if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            X509_free(caCert); EVP_PKEY_free(caKey);
            return false;
        }
        EVP_PKEY_CTX_free(ctx);

        // Serial ngau nhien
        int serial = (int)(time(nullptr) & 0xFFFF);

        // Tao cert duoc ky boi CA
        X509* cert = buildCert(commonName, validDays,
            pkey, caCert, caKey, serial);
        if (!cert) {
            EVP_PKEY_free(pkey);
            X509_free(caCert); EVP_PKEY_free(caKey);
            return false;
        }

        outCertPEM = x509ToPEM(cert);
        outKeyPEM = pkeyToPEM(pkey);

        X509_free(cert);
        EVP_PKEY_free(pkey);
        X509_free(caCert);
        EVP_PKEY_free(caKey);
        return true;
    }

    bool Crypto::loadOrCreate(
        const std::string& certPath,
        const std::string& keyPath,
        const std::string& commonName,
        int validDays,
        const std::string& caCertPEM,
        const std::string& caKeyPEM,
        std::string& outCertPEM,
        std::string& outKeyPEM)
    {
        // Thu load truoc
        outCertPEM = Utils::loadPEM(certPath);
        outKeyPEM = Utils::loadPEM(keyPath);

        if (!outCertPEM.empty() && !outKeyPEM.empty()) {
            Utils::log(Utils::LogLevel::INFO, "Crypto",
                "Loaded existing cert: " + certPath);
            return true;
        }

        Utils::log(Utils::LogLevel::INFO, "Crypto",
            "Generating new cert for: " + commonName);

        bool ok = false;
        if (caCertPEM.empty()) {
            // Self-signed (CA)
            ok = generateSelfSignedCert(commonName, validDays,
                outCertPEM, outKeyPEM);
        }
        else if (caKeyPEM.empty()) {
            // Co CA cert nhung khong co CA key
            // -> Khong the tu ky, can CA server ky cho minh
            // Day la truong hop RA/KDC/Chat - phai xin CA ky
            Utils::log(Utils::LogLevel::ERR, "Crypto",
                "CA key not available - cannot self-sign cert for: " + commonName);
            Utils::log(Utils::LogLevel::INFO, "Crypto",
                "Hint: CA key is only on CA server. Use requestCertFromCA() instead.");
            return false;
        }
        else {
            // Co ca CA cert + CA key -> ky truc tiep
            ok = generateSignedCert(commonName, validDays,
                caCertPEM, caKeyPEM,
                outCertPEM, outKeyPEM);
        }

        if (!ok) return false;

        Utils::savePEM(certPath, outCertPEM);
        Utils::savePEM(keyPath, outKeyPEM);
        Utils::log(Utils::LogLevel::INFO, "Crypto",
            "Cert saved: " + certPath);
        return true;
    }

    bool Crypto::requestCertFromCA(
        const std::string& commonName,
        int validDays,
        const std::string& caServerIP,
        int caPort,
        const std::string& caCertPEM,
        std::string& outCertPEM,
        std::string& outKeyPEM)
    {
        // Buoc 1: Sinh keypair
        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
        EVP_PKEY_keygen_init(ctx);
        EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048);
        EVP_PKEY* pkey = nullptr;
        if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            Utils::log(Utils::LogLevel::ERR, "Crypto", "RSA keygen failed");
            return false;
        }
        EVP_PKEY_CTX_free(ctx);

        // Buoc 2: Lay private key PEM - luu truc tiep tu pkey
        BIO* privBio = BIO_new(BIO_s_mem());
        PEM_write_bio_PrivateKey(privBio, pkey, nullptr, nullptr, 0, nullptr, nullptr);
        BUF_MEM* privPtr;
        BIO_get_mem_ptr(privBio, &privPtr);
        outKeyPEM = std::string(privPtr->data, privPtr->length);
        BIO_free(privBio);

        // Buoc 3: Lay public key PEM - lay truc tiep tu pkey (khong load lai)
        BIO* pubBio = BIO_new(BIO_s_mem());
        PEM_write_bio_PUBKEY(pubBio, pkey);
        BUF_MEM* pubPtr;
        BIO_get_mem_ptr(pubBio, &pubPtr);
        std::string pubKeyPEM(pubPtr->data, pubPtr->length);
        BIO_free(pubBio);

        // Da co du private + public key, giai phong pkey
        EVP_PKEY_free(pkey);

        Utils::log(Utils::LogLevel::INFO, "Crypto",
            "Keypair generated for: " + commonName);

        // Buoc 4: Ket noi CA xin cert
        WSADATA wsa;
        WSAStartup(MAKEWORD(2, 2), &wsa);

        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) {
            Utils::log(Utils::LogLevel::ERR, "Crypto", "Socket creation failed");
            return false;
        }

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(caPort);
        inet_pton(AF_INET, caServerIP.c_str(), &addr.sin_addr);

        if (connect(sock, (sockaddr*)&addr, sizeof(addr)) < 0) {
            Utils::log(Utils::LogLevel::ERR, "Crypto",
                "Cannot connect to CA at " + caServerIP);
            closesocket(sock);
            return false;
        }

        // Buoc 5: Wrap TLS - dung SSL_VERIFY_NONE vi lan dau chua co CA cert
        SSL_CTX* sslCtx = SSL_CTX_new(TLS_client_method());
        SSL_CTX_set_verify(sslCtx, SSL_VERIFY_NONE, nullptr);

        SSL* ssl = SSL_new(sslCtx);
        SSL_set_fd(ssl, sock);

        if (SSL_connect(ssl) <= 0) {
            Utils::log(Utils::LogLevel::ERR, "Crypto", "TLS connect to CA failed");
            SSL_free(ssl);
            SSL_CTX_free(sslCtx);
            closesocket(sock);
            return false;
        }

        Utils::log(Utils::LogLevel::INFO, "Crypto",
            "Connected to CA, requesting cert for: " + commonName);

        // Buoc 6: Gui ISSUE_CERT_REQ
        Message req;
        req.type = MessageType::ISSUE_CERT_REQ;
        req.payload["username"] = commonName;
        req.payload["public_key"] = pubKeyPEM;
        Protocol::sendMessage(ssl, req);

        // Buoc 7: Nhan cert tu CA
        bool ok = false;
        try {
            Message resp = Protocol::recvMessage(ssl);
            if (resp.type == MessageType::CERT_RESPONSE &&
                resp.payload["status"] == "OK") {
                outCertPEM = resp.payload["cert"];
                ok = true;
                Utils::log(Utils::LogLevel::INFO, "Crypto",
                    "Cert received from CA for: " + commonName);
            }
            else {
                Utils::log(Utils::LogLevel::ERR, "Crypto",
                    "CA rejected cert request for: " + commonName);
            }
        }
        catch (std::exception& e) {
            Utils::log(Utils::LogLevel::ERR, "Crypto",
                std::string("Error receiving cert: ") + e.what());
        }

        // Cleanup
        SSL_shutdown(ssl);
        SSL_free(ssl);
        SSL_CTX_free(sslCtx);
        closesocket(sock);
        return ok;
    }

	// Bước 1: CA server ký cert cho Intermediate CA
    bool Crypto::generateCACert(
        const std::string& commonName,
        int validDays,
        const std::string& issuerCertPEM,
        const std::string& issuerKeyPEM,
        std::string& outCertPEM,
        std::string& outKeyPEM)
    {
        // Load issuer cert + key
        BIO* cb = BIO_new_mem_buf(issuerCertPEM.data(),
            (int)issuerCertPEM.size());
        X509* issuerCert = PEM_read_bio_X509(cb, nullptr, nullptr, nullptr);
        BIO_free(cb);

        BIO* kb = BIO_new_mem_buf(issuerKeyPEM.data(),
            (int)issuerKeyPEM.size());
        EVP_PKEY* issuerKey = PEM_read_bio_PrivateKey(
            kb, nullptr, nullptr, nullptr);
        BIO_free(kb);

        if (!issuerCert || !issuerKey) return false;

        // Sinh keypair mới cho Intermediate CA
        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
        EVP_PKEY_keygen_init(ctx);
        EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048);
        EVP_PKEY* pkey = nullptr;
        EVP_PKEY_keygen(ctx, &pkey);
        EVP_PKEY_CTX_free(ctx);

        // Tạo X509 cert
        X509* cert = X509_new();
        int serial = (int)(time(nullptr) & 0xFFFF) + 1000;
        ASN1_INTEGER_set(X509_get_serialNumber(cert), serial);

        X509_gmtime_adj(X509_get_notBefore(cert), 0);
        X509_gmtime_adj(X509_get_notAfter(cert),
            60LL * 60 * 24 * validDays);

        // Subject
        X509_NAME* name = X509_get_subject_name(cert);
        X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
            (unsigned char*)commonName.c_str(), -1, -1, 0);

        // Issuer = issuerCert subject
        X509_set_issuer_name(cert,
            X509_get_subject_name(issuerCert));

        // Public key
        X509_set_pubkey(cert, pkey);

        // Basic Constraints: CA:TRUE — đây là điểm khác với end-entity cert
        X509_EXTENSION* ext = X509V3_EXT_conf_nid(
            nullptr, nullptr, NID_basic_constraints, "CA:TRUE");
        if (ext) {
            X509_add_ext(cert, ext, -1);
            X509_EXTENSION_free(ext);
        }

        // Key Usage: keyCertSign, cRLSign
        X509_EXTENSION* ku = X509V3_EXT_conf_nid(
            nullptr, nullptr, NID_key_usage,
            "critical,keyCertSign,cRLSign");
        if (ku) {
            X509_add_ext(cert, ku, -1);
            X509_EXTENSION_free(ku);
        }

        // Ký bằng issuer key
        X509_sign(cert, issuerKey, EVP_sha256());

        outCertPEM = x509ToPEM(cert);
        outKeyPEM = pkeyToPEM(pkey);

        X509_free(cert);
        EVP_PKEY_free(pkey);
        X509_free(issuerCert);
        EVP_PKEY_free(issuerKey);
        return true;
    }

    bool Crypto::verifyCertChain(
        const std::string& certPEM,
        const std::string& intermCACertPEM,
        const std::string& rootCACertPEM)
    {
        // Load certs
        auto loadCert = [](const std::string& pem) -> X509* {
            BIO* bio = BIO_new_mem_buf(pem.data(), (int)pem.size());
            X509* c = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
            BIO_free(bio);
            return c;
            };

        X509* cert = loadCert(certPEM);
        X509* intermCA = loadCert(intermCACertPEM);
        X509* rootCA = loadCert(rootCACertPEM);

        if (!cert || !intermCA || !rootCA) {
            if (cert)    X509_free(cert);
            if (intermCA)X509_free(intermCA);
            if (rootCA)  X509_free(rootCA);
            return false;
        }

        // Tạo trust store với RootCA
        X509_STORE* store = X509_STORE_new();
        X509_STORE_add_cert(store, rootCA);

        // Tạo chain: [intermCA]
        STACK_OF(X509)* chain = sk_X509_new_null();
        sk_X509_push(chain, intermCA);

        // Verify
        X509_STORE_CTX* storeCtx = X509_STORE_CTX_new();
        X509_STORE_CTX_init(storeCtx, store, cert, chain);
        int result = X509_verify_cert(storeCtx);

        if (result != 1) {
            Utils::log(Utils::LogLevel::ERR, "Crypto",
                "Chain verification failed: " +
                std::string(X509_verify_cert_error_string(
                    X509_STORE_CTX_get_error(storeCtx))));
        }

        X509_STORE_CTX_free(storeCtx);
        sk_X509_free(chain);
        X509_STORE_free(store);
        X509_free(cert);
        X509_free(intermCA);
        X509_free(rootCA);

        return result == 1;
    }
}