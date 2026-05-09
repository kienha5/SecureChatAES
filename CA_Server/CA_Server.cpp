#define _CRT_SECURE_NO_WARNINGS

#include <openssl/applink.c>
#include "../Common/pch.h"
#include "../Common/utils.h"
#include "../Common/crypto.h"
#include "../Common/message.h"
#include "../Common/network.h"
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <map>
#include <mutex>

// ─── Global state ─────────────────────────────────────────────
static std::string g_caCertPEM;   // CA cert (PEM)
static std::string g_caKeyPEM;    // CA private key (PEM)
static int g_serialCounter = 1;
static std::map<int, std::string> g_certDB;   // serial → username
static std::map<int, bool>        g_revokedDB; // serial → revoked
static std::mutex g_dbMutex;

// ─── Load CA cert + key từ file ───────────────────────────────
bool loadCA(const std::string& certPath, const std::string& keyPath) {
    // Load cert
    FILE* f = fopen(certPath.c_str(), "r");
    if (!f) { Utils::log(Utils::LogLevel::ERR, "CA", "Cannot open cert: " + certPath); return false; }
    X509* cert = PEM_read_X509(f, nullptr, nullptr, nullptr);
    fclose(f);
    if (!cert) return false;

    BIO* bio = BIO_new(BIO_s_mem());
    PEM_write_bio_X509(bio, cert);
    BUF_MEM* ptr;
    BIO_get_mem_ptr(bio, &ptr);
    g_caCertPEM = std::string(ptr->data, ptr->length);
    BIO_free(bio);
    X509_free(cert);

    // Load key
    FILE* fk = fopen(keyPath.c_str(), "r");
    if (!fk) { Utils::log(Utils::LogLevel::ERR, "CA", "Cannot open key: " + keyPath); return false; }
    EVP_PKEY* pkey = PEM_read_PrivateKey(fk, nullptr, nullptr, nullptr);
    fclose(fk);
    if (!pkey) return false;

    BIO* kbio = BIO_new(BIO_s_mem());
    PEM_write_bio_PrivateKey(kbio, pkey, nullptr, nullptr, 0, nullptr, nullptr);
    BUF_MEM* kptr;
    BIO_get_mem_ptr(kbio, &kptr);
    g_caKeyPEM = std::string(kptr->data, kptr->length);
    BIO_free(kbio);
    EVP_PKEY_free(pkey);

    Utils::log(Utils::LogLevel::INFO, "CA", "CA cert and key loaded");
    return true;
}

// ─── Tạo X.509 cert cho client ────────────────────────────────
std::string issueCert(const std::string& username, const std::string& pubKeyPEM) {
    // Load CA cert
    BIO* cb = BIO_new_mem_buf(g_caCertPEM.data(), (int)g_caCertPEM.size());
    X509* caCert = PEM_read_bio_X509(cb, nullptr, nullptr, nullptr);
    BIO_free(cb);

    // Load CA key
    BIO* kb = BIO_new_mem_buf(g_caKeyPEM.data(), (int)g_caKeyPEM.size());
    EVP_PKEY* caKey = PEM_read_bio_PrivateKey(kb, nullptr, nullptr, nullptr);
    BIO_free(kb);

    // Load client public key
    BIO* pb = BIO_new_mem_buf(pubKeyPEM.data(), (int)pubKeyPEM.size());
    EVP_PKEY* clientPubKey = PEM_read_bio_PUBKEY(pb, nullptr, nullptr, nullptr);
    BIO_free(pb);

    if (!caCert || !caKey || !clientPubKey) {
        Utils::log(Utils::LogLevel::ERR, "CA", "Failed to load keys for cert issuance");
        return "";
    }

    // Tạo cert mới
    X509* cert = X509_new();

    // Serial number
    std::lock_guard<std::mutex> lock(g_dbMutex);
    int serial = g_serialCounter++;
    ASN1_INTEGER_set(X509_get_serialNumber(cert), serial);

    // Validity: 365 ngày
    X509_gmtime_adj(X509_get_notBefore(cert), 0);
    X509_gmtime_adj(X509_get_notAfter(cert), 60 * 60 * 24 * 365);

    // Subject: CN=username
    X509_NAME* name = X509_get_subject_name(cert);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
        (unsigned char*)username.c_str(), -1, -1, 0);

    // Issuer = CA subject
    X509_set_issuer_name(cert, X509_get_subject_name(caCert));

    // Set public key
    X509_set_pubkey(cert, clientPubKey);

    // Ký bằng CA key
    X509_sign(cert, caKey, EVP_sha256());

    // Serialize sang PEM
    BIO* out = BIO_new(BIO_s_mem());
    PEM_write_bio_X509(out, cert);
    BUF_MEM* optr;
    BIO_get_mem_ptr(out, &optr);
    std::string certPEM(optr->data, optr->length);
    BIO_free(out);

    // Lưu vào DB
    g_certDB[serial] = username;
    g_revokedDB[serial] = false;

    Utils::log(Utils::LogLevel::INFO, "CA",
        "Issued cert for [" + username + "] serial=" + std::to_string(serial));

    X509_free(cert);
    EVP_PKEY_free(caKey);
    EVP_PKEY_free(clientPubKey);
    X509_free(caCert);

    return certPEM;
}

// ─── Xử lý 1 client (chạy trong thread) ──────────────────────
void handleClient(SSL* ssl) {
    try {
        Message req = Protocol::recvMessage(ssl);

        if (req.type == MessageType::ISSUE_CERT_REQ) {
            std::string username = req.payload["username"];
            std::string pubKeyPEM = req.payload["public_key"];

            Utils::log(Utils::LogLevel::INFO, "CA",
                "ISSUE_CERT_REQ from RA for user: " + username);

            std::string certPEM = issueCert(username, pubKeyPEM);

            Message resp;
            if (!certPEM.empty()) {
                resp.type = MessageType::CERT_RESPONSE;
                resp.payload["cert"] = certPEM;
                resp.payload["status"] = "OK";
            }
            else {
                resp.type = MessageType::ERROR_MSG;
                resp.payload["reason"] = "Cert issuance failed";
            }
            Protocol::sendMessage(ssl, resp);
        }
        else if (req.type == MessageType::VERIFY_CERT) {
            int serial = req.payload["serial"];
            std::lock_guard<std::mutex> lock(g_dbMutex);
            std::string status = "UNKNOWN";
            if (g_certDB.count(serial)) {
                status = g_revokedDB[serial] ? "REVOKED" : "VALID";
            }
            Utils::log(Utils::LogLevel::INFO, "CA",
                "VERIFY_CERT serial=" + std::to_string(serial) + " → " + status);

            Message resp;
            resp.type = MessageType::CERT_STATUS;
            resp.payload["serial"] = serial;
            resp.payload["status"] = status;
            Protocol::sendMessage(ssl, resp);
        }
    }
    catch (std::exception& e) {
        Utils::log(Utils::LogLevel::ERR, "CA", std::string("Exception: ") + e.what());
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
}

// ─── Main ─────────────────────────────────────────────────────
int main() {
    Utils::log(Utils::LogLevel::INFO, "CA", "Starting CA Server on port 5000...");

    if (!loadCA("C:\\SecureChatCerts\\ca.crt", "C:\\SecureChatCerts\\ca.key")) {
        Utils::log(Utils::LogLevel::ERR, "CA", "Failed to load CA. Exiting.");
        return 1;
    }

    SSL_CTX* ctx = Network::createServerContext(
        "C:\\SecureChatCerts\\ca.crt",
        "C:\\SecureChatCerts\\ca.key"
    );
    if (!ctx) return 1;

    int serverSock = Network::createServerSocket(5000);
    if (serverSock < 0) return 1;

    Utils::log(Utils::LogLevel::INFO, "CA", "CA Server ready. Waiting for connections...");

    while (true) {
        int clientSock = 0;
        SSL* ssl = Network::acceptClient(ctx, serverSock, clientSock);
        if (!ssl) continue;

        // Mỗi client chạy trong thread riêng
        std::thread t(handleClient, ssl);
        t.detach();
    }

    Network::freeContext(ctx);
    return 0;
}