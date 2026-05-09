#define _CRT_SECURE_NO_WARNINGS

#include <openssl/applink.c>
#include "../Common/pch.h"
#include "../Common/utils.h"
#include "../Common/crypto.h"
#include "../Common/message.h"
#include "../Common/network.h"
#include <set>
#include <mutex>

// ─── Global state ─────────────────────────────────────────────
static std::set<std::string> g_usedNonces;
static std::mutex g_nonceMutex;

// ─── Forward request đến CA ───────────────────────────────────
std::string forwardToCA(const std::string& username, const std::string& pubKeyPEM) {
    SSL_CTX* ctx = Network::createClientContext("C:\\SecureChatCerts\\ca.crt");
    if (!ctx) return "";

    SSL* ssl = Network::connectToServer(ctx, "127.0.0.1", 5000);
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
                if (g_usedNonces.count(clientNonce)) {
                    Utils::log(Utils::LogLevel::WARN, "RA", "Replay detected: nonce reused");
                    Message err; err.type = MessageType::ERROR_MSG;
                    err.payload["reason"] = "Replay detected";
                    Protocol::sendMessage(ssl, err);
                    goto cleanup;
                }
                g_usedNonces.insert(clientNonce);
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

            // Bước 7: Forward đến CA
            std::string certPEM = forwardToCA(username, pubKeyPEM);
            if (certPEM.empty()) {
                Message err; err.type = MessageType::ERROR_MSG;
                err.payload["reason"] = "CA issuance failed";
                Protocol::sendMessage(ssl, err);
                goto cleanup;
            }

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
    Utils::log(Utils::LogLevel::INFO, "RA", "Starting RA Server on port 5001...");

    SSL_CTX* ctx = Network::createServerContext(
        "C:\\SecureChatCerts\\ra.crt",
        "C:\\SecureChatCerts\\ra.key"
    );
    if (!ctx) return 1;

    int serverSock = Network::createServerSocket(5001);
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