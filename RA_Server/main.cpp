#define _CRT_SECURE_NO_WARNINGS

#include <openssl/applink.c>
#include "../Common/pch.h"
#include "../Common/utils.h"
#include "../Common/crypto.h"
#include "../Common/message.h"
#include "../Common/network.h"
#include "../Common/config.h"
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <set>
#include <mutex>

// ─── Global state ─────────────────────────────────────────────
static std::set<std::string> g_usedNonces;
static std::mutex g_nonceMutex;

// ─── Forward request đến CA ───────────────────────────────────
std::string forwardToCA(const std::string& username, const std::string& pubKeyPEM) {
    SSL_CTX* ctx = Network::createClientContext(Config::CA_CERT());
    if (!ctx) return "";

    SSL* ssl = Network::connectToServer(ctx, "127.0.0.1", Config::PORT_CA);
    if (!ssl) { Network::freeContext(ctx); return ""; }

    // Gửi ISSUE_CERT_REQ đến CA
    Message req;
    req.type = MessageType::ISSUE_CERT_REQ;
    req.payload["username"] = username;
    req.payload["public_key"] = pubKeyPEM;
    Protocol::sendMessage(ssl, req);

    // Nhận cert từ CA
    Message resp = Protocol::recvMessage(ssl);
    std::string certPEM = "";
    if (resp.type == MessageType::CERT_RESPONSE &&
        resp.payload["status"] == "OK") {
        certPEM = resp.payload["cert"];
        Utils::log(Utils::LogLevel::INFO, "RA", "Received cert from CA for: " + username);
    }
    else {
        Utils::log(Utils::LogLevel::ERR, "RA", "CA rejected cert request");
    }

    int sock = SSL_get_fd(ssl);
    Network::closeConnection(ssl, sock);
    Network::freeContext(ctx);
    return certPEM;
}

bool initRA() {
    Config::ensureCertDir();

    // Thu load neu da co san
    std::string certPEM = Utils::loadPEM(Config::RA_CERT());
    std::string keyPEM = Utils::loadPEM(Config::RA_KEY());
    if (!certPEM.empty() && !keyPEM.empty()) {
        Utils::log(Utils::LogLevel::INFO, "RA", "Loaded existing RA cert");
        return true;
    }

    // Download CA cert neu chua co
    std::string caCertPEM = Utils::loadPEM(Config::CA_CERT());
    if (caCertPEM.empty()) {
        Utils::log(Utils::LogLevel::INFO, "RA", "Downloading CA cert...");
        SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);
        SSL* ssl = Network::connectToServer(ctx, "127.0.0.1", Config::PORT_CA);
        if (!ssl) {
            Utils::log(Utils::LogLevel::ERR, "RA", "Cannot connect to CA!");
            SSL_CTX_free(ctx);
            return false;
        }
        Message req; req.type = MessageType::GET_CA_CERT;
        Protocol::sendMessage(ssl, req);
        Message resp = Protocol::recvMessage(ssl);
        if (resp.type == MessageType::CERT_RESPONSE) {
            caCertPEM = resp.payload["cert"];
            Utils::savePEM(Config::CA_CERT(), caCertPEM);
            Utils::log(Utils::LogLevel::INFO, "RA", "CA cert downloaded");
        }
        int s = SSL_get_fd(ssl);
        Network::closeConnection(ssl, s);
        SSL_CTX_free(ctx);
    }

    // Xin CA ky cert cho RA
    Utils::log(Utils::LogLevel::INFO, "RA", "Requesting cert from CA...");
    bool ok = Crypto::requestCertFromCA(
        "SecureChat-RA", 365,
        "127.0.0.1", Config::PORT_CA,
        caCertPEM,
        certPEM, keyPEM
    );
    if (!ok) {
        Utils::log(Utils::LogLevel::ERR, "RA", "Failed to get cert from CA");
        return false;
    }

    Utils::savePEM(Config::RA_CERT(), certPEM);
    Utils::savePEM(Config::RA_KEY(), keyPEM);
    Utils::log(Utils::LogLevel::INFO, "RA", "RA cert saved");
    return true;
}

// ─── Xử lý 1 client ───────────────────────────────────────────
void handleClient(SSL* ssl) {
    try {
        // Bước 1: Gửi challenge nonce cho client
        auto nonce = Crypto::generateNonce(32);
        std::string nonceB64 = Utils::base64Encode(nonce);
        int64_t ts = Utils::getTimestamp();

        Message challenge;
        challenge.type = MessageType::CHALLENGE;
        challenge.payload["nonce"] = nonceB64;
        challenge.payload["timestamp"] = ts;
        Protocol::sendMessage(ssl, challenge);
        Utils::log(Utils::LogLevel::INFO, "RA", "Sent challenge nonce to client");

        // Bước 2: Nhận REGISTER_CERT từ client
        Message req = Protocol::recvMessage(ssl);
        if (req.type != MessageType::REGISTER_CERT) {
            Utils::log(Utils::LogLevel::ERR, "RA", "Expected REGISTER_CERT, got something else");
            goto cleanup;
        }

        {
            std::string username = req.payload["username"];
            std::string pubKeyPEM = req.payload["public_key"];
            std::string sigB64 = req.payload["signature"];
            std::string clientNonce = req.payload["nonce"];
            int64_t clientTs = req.payload["timestamp"];

            Utils::log(Utils::LogLevel::INFO, "RA", "REGISTER_CERT from: " + username);

			// Ghi log audit về request đăng ký (chỉ ghi username, không ghi nonce hay timestamp để tránh log quá nhiều)
            Utils::auditLog("RA", "REGISTER_REQUEST", "username=" + username);

            // Bước 3: Check timestamp
            if (Utils::isExpired(clientTs)) {
                Utils::log(Utils::LogLevel::WARN, "RA", "Timestamp expired");
                Message err; err.type = MessageType::ERROR_MSG;
                err.payload["reason"] = "Timestamp expired";
                Protocol::sendMessage(ssl, err);
                goto cleanup;
            }

            // Bước 4: Check replay (nonce đã dùng chưa)
            {
                std::lock_guard<std::mutex> lock(g_nonceMutex);

                // Safely get up to 16 characters for logging
                std::string safeNonceLog = clientNonce.substr(0, std::min<size_t>(16, clientNonce.length()));

                if (g_usedNonces.count(clientNonce)) {
                    Utils::log(Utils::LogLevel::WARN, "RA",
                        "REPLAY ATTACK DETECTED - nonce already used: " + safeNonceLog + "...");
                    Utils::log(Utils::LogLevel::WARN, "RA",
                        "Request from potential attacker blocked");

					// Ghi log audit về replay attack (ghi cả nonce và username để dễ điều tra, nhưng chỉ ghi một phần nonce)
                    Utils::auditLog("RA", "REPLAY_DETECTED",   
                        "nonce=" + clientNonce.substr(0, 16) +
                        " username=" + username);

                    Message err; err.type = MessageType::ERROR_MSG;
                    err.payload["reason"] = "Replay attack detected - nonce already used";
                    Protocol::sendMessage(ssl, err);
                    goto cleanup;
                }

                g_usedNonces.insert(clientNonce);
                Utils::log(Utils::LogLevel::INFO, "RA",
                    "Nonce accepted and recorded: " + safeNonceLog + "...");
            }

            // Bước 5: Verify nonce match
            if (clientNonce != nonceB64) {
                Utils::log(Utils::LogLevel::WARN, "RA", "Nonce mismatch");
                Message err; err.type = MessageType::ERROR_MSG;
                err.payload["reason"] = "Nonce mismatch";
                Protocol::sendMessage(ssl, err);
                goto cleanup;
            }

            // Bước 6: Verify signature
            auto sig = Utils::base64Decode(sigB64);
            auto nonceBytes = Utils::base64Decode(nonceB64);
            bool valid = Crypto::verifySignature(pubKeyPEM, nonceBytes, sig);
            if (!valid) {
                Utils::log(Utils::LogLevel::WARN, "RA", "Signature verification failed");
                Message err; err.type = MessageType::ERROR_MSG;
                err.payload["reason"] = "Invalid signature";
                Protocol::sendMessage(ssl, err);
                goto cleanup;
            }
            Utils::log(Utils::LogLevel::INFO, "RA", "Signature OK for: " + username);

			// Ghi log audit về việc đăng ký thành công 
            // (ghi username, không ghi nonce hay signature để tránh log quá nhiều và bảo vệ thông tin nhạy cảm)
            Utils::auditLog("RA", "SIGNATURE_OK", "username=" + username);

            // Bước 7: Forward đến CA
            std::string certPEM = forwardToCA(username, pubKeyPEM);
            if (certPEM.empty()) {
                Message err; err.type = MessageType::ERROR_MSG;
                err.payload["reason"] = "CA issuance failed";
                Protocol::sendMessage(ssl, err);
                goto cleanup;
            }

			// Ghi log audit về việc forward request đến CA (chỉ ghi username, không ghi chi tiết cert để tránh log quá nhiều)
            Utils::auditLog("RA", "CERT_FORWARDED_TO_CA", "username=" + username);

            // Bước 8: Trả cert về cho client
            Message resp;
            resp.type = MessageType::CERT_RESPONSE;
            resp.payload["cert"] = certPEM;
            Protocol::sendMessage(ssl, resp);
            Utils::log(Utils::LogLevel::INFO, "RA", "Cert sent to client: " + username);
        }

    cleanup:;
    }
    catch (std::exception& e) {
        Utils::log(Utils::LogLevel::ERR, "RA", std::string("Exception: ") + e.what());
    }

    int sock = SSL_get_fd(ssl);
    Network::closeConnection(ssl, sock);
}

// ─── Main ─────────────────────────────────────────────────────
int main() {
    Utils::initAuditLog(Config::AUDIT_LOG_DIR());

    Utils::log(Utils::LogLevel::INFO, "RA",
        "Starting RA Server on port " +
        std::to_string(Config::PORT_RA) + "...");

    // Phai init truoc de tao cert neu chua co
    if (!initRA()) {
        Utils::log(Utils::LogLevel::ERR, "RA", "Init failed");
        return 1;
    }

    SSL_CTX* ctx = Network::createServerContext(
        Config::RA_CERT(),
        Config::RA_KEY()
    );
    if (!ctx) return 1;

    int serverSock = Network::createServerSocket(Config::PORT_RA);
    if (serverSock < 0) return 1;

    Utils::log(Utils::LogLevel::INFO, "RA", "RA Server ready. Waiting for connections...");

    while (true) {
        int clientSock = 0;
        SSL* ssl = Network::acceptClient(ctx, serverSock, clientSock);
        if (!ssl) continue;
        std::thread t(handleClient, ssl);
        t.detach();
    }

    Network::freeContext(ctx);
    return 0;
}