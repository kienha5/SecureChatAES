#pragma once
#include "../Common/pch.h"
#include "../Common/utils.h"
#include "../Common/crypto.h"
#include "../Common/message.h"
#include "../Common/network.h"
#include "../Common/config.h" 
#include <fstream>
#include <string>
#include <vector>
#include <functional>

// Callback de cap nhat GUI tu thread khac
using LogCallback = std::function<void(const std::string&, bool)>;
using MsgCallback = std::function<void(const std::string&, const std::string&, bool)>;

// ─── File helpers ─────────────────────────────────────────────
inline std::string loadFile(const std::string& path) {
    std::ifstream f(path);
    if (!f.is_open()) return "";
    return std::string(
        std::istreambuf_iterator<char>(f),
        std::istreambuf_iterator<char>()
    );
}

inline void saveFile(const std::string& path, const std::string& content) {
    std::ofstream f(path);
    f << content;
}

// ─── Register cert voi RA ─────────────────────────────────────
inline bool doRegisterCert(const std::string& username,
    const std::string& serverIP,
    LogCallback log) {
    log("Generating RSA keypair...", false);
    std::string pub, priv;
    Crypto::generateRSAKeyPair(pub, priv);

    // Dùng .c_str() đề phòng hàm Network cần const char*
    // Dùng chain file để verify cert của RA/KDC/Chat (được ký bởi IntermCA)
    std::string chainFile = Config::CA_CHAIN();
    if (chainFile.empty() || !std::filesystem::exists(chainFile)) {
        chainFile = Config::CA_CERT();  // fallback về RootCA nếu chưa có chain
    }
    SSL_CTX* ctx = Network::createClientContext(chainFile);
    if (!ctx) { log("Failed to create SSL context", true); return false; }

    SSL* ssl = Network::connectToServer(ctx, serverIP.c_str(), Config::PORT_RA);
    if (!ssl) {
        log("Cannot connect to RA on port 5001", true);
        Network::freeContext(ctx); return false;
    }
    log("Connected to RA", false);

    Message challenge = Protocol::recvMessage(ssl);
    if (challenge.type != MessageType::CHALLENGE) {
        log("Expected CHALLENGE from RA", true);
        int s = SSL_get_fd(ssl); Network::closeConnection(ssl, s);
        Network::freeContext(ctx); return false;
    }

    std::string nonceB64 = challenge.payload["nonce"];
    auto nonceBytes = Utils::base64Decode(nonceB64);
    auto sig = Crypto::signData(priv, nonceBytes);

    Message req;
    req.type = MessageType::REGISTER_CERT;
    req.payload["username"] = username;
    req.payload["public_key"] = pub;
    req.payload["signature"] = Utils::base64Encode(sig);
    req.payload["nonce"] = nonceB64;
    req.payload["timestamp"] = Utils::getTimestamp();
    Protocol::sendMessage(ssl, req);

    Message resp = Protocol::recvMessage(ssl);
    int sock = SSL_get_fd(ssl);
    Network::closeConnection(ssl, sock);
    Network::freeContext(ctx);

    if (resp.type == MessageType::CERT_RESPONSE) {
        saveFile(Config::userCert(username), resp.payload["cert"]);
        saveFile(Config::userKey(username), priv);
        log("Certificate saved!", false);
        return true;
    }
    log("Cert registration failed: " + resp.payload["reason"].get<std::string>(), true);
    return false;
}

// ─── Register account voi Chat Server ─────────────────────────
inline bool doRegisterAccount(const std::string& username,
    const std::string& serverIP,
    LogCallback log) {
    std::string certPEM = loadFile(Config::userCert(username));
    std::string privKeyPEM = loadFile(Config::userKey(username));
    if (certPEM.empty()) { log("No cert found - register cert first", true); return false; }

    // Dùng chain file để verify cert của RA/KDC/Chat (được ký bởi IntermCA)
    std::string chainFile = Config::CA_CHAIN();
    if (chainFile.empty() || !std::filesystem::exists(chainFile)) {
        chainFile = Config::CA_CERT();  // fallback về RootCA nếu chưa có chain
    }
    SSL_CTX* ctx = Network::createClientContext(chainFile);
    SSL* ssl = Network::connectToServer(ctx, serverIP.c_str(), Config::PORT_CHAT);
    if (!ssl) {
        log("Cannot connect to Chat Server port 5002", true);
        Network::freeContext(ctx); return false;
    }
    log("Connected to Chat Server", false);

    Message req;
    req.type = MessageType::REGISTER_CERT;
    req.payload["username"] = username;
    req.payload["cert"] = certPEM;
    req.payload["timestamp"] = Utils::getTimestamp();
    Protocol::sendMessage(ssl, req);

    Message challenge = Protocol::recvMessage(ssl);
    if (challenge.type != MessageType::CHALLENGE) {
        log("Expected CHALLENGE", true);
        int s = SSL_get_fd(ssl); Network::closeConnection(ssl, s);
        Network::freeContext(ctx); return false;
    }

    std::string nonceB64 = challenge.payload["nonce"];
    auto nonceBytes = Utils::base64Decode(nonceB64);
    auto sig = Crypto::signData(privKeyPEM, nonceBytes);

    Message pop;
    pop.type = MessageType::CERT_RESPONSE;
    pop.payload["signature"] = Utils::base64Encode(sig);
    pop.payload["nonce"] = nonceB64;
    Protocol::sendMessage(ssl, pop);

    Message resp = Protocol::recvMessage(ssl);
    int sock = SSL_get_fd(ssl);
    Network::closeConnection(ssl, sock);
    Network::freeContext(ctx);

    if (resp.type == MessageType::SUCCESS) {
        log("Account registered on Chat Server!", false);
        return true;
    }
    log("Account registration failed: " + resp.payload["reason"].get<std::string>(), true);
    return false;
}

// ─── Register KDC ─────────────────────────────────────────────
inline bool doRegisterKDC(const std::string& username,
    const std::string& password,
    const std::string& serverIP,
    std::vector<unsigned char>& outKc,
    LogCallback log) {
    std::string certPEM = loadFile(Config::userCert(username));
    std::string privKeyPEM = loadFile(Config::userKey(username));
    if (certPEM.empty()) { log("No cert found", true); return false; }

    std::vector<unsigned char> pwBytes(password.begin(), password.end());
    auto clientHash = Crypto::sha256(pwBytes);
    outKc = Crypto::sha256(clientHash);

    // Dùng chain file để verify cert của RA/KDC/Chat (được ký bởi IntermCA)
    std::string chainFile = Config::CA_CHAIN();
    if (chainFile.empty() || !std::filesystem::exists(chainFile)) {
        chainFile = Config::CA_CERT();  // fallback về RootCA nếu chưa có chain
    }
    SSL_CTX* ctx = Network::createClientContext(chainFile);
    SSL* ssl = Network::connectToServer(ctx, serverIP.c_str(), Config::PORT_KDC);
    if (!ssl) {
        log("Cannot connect to KDC port 5003", true);
        Network::freeContext(ctx); return false;
    }
    log("Connected to KDC", false);

    Message init;
    init.type = MessageType::KDC_REGISTER_INIT;
    init.payload["username"] = username;
    init.payload["cert"] = certPEM;
    Protocol::sendMessage(ssl, init);

    Message challenge = Protocol::recvMessage(ssl);
    if (challenge.type != MessageType::CHALLENGE) {
        log("Expected CHALLENGE from KDC", true);
        int s = SSL_get_fd(ssl); Network::closeConnection(ssl, s);
        Network::freeContext(ctx); return false;
    }

    std::string nonceB64 = challenge.payload["nonce"];
    auto nonceBytes = Utils::base64Decode(nonceB64);
    auto sig = Crypto::signData(privKeyPEM, nonceBytes);

    Message reg;
    reg.type = MessageType::KDC_REGISTER;
    reg.payload["client_hash"] = Utils::base64Encode(clientHash);
    reg.payload["signature"] = Utils::base64Encode(sig);
    reg.payload["nonce"] = nonceB64;
    Protocol::sendMessage(ssl, reg);

    Message resp = Protocol::recvMessage(ssl);
    int sock = SSL_get_fd(ssl);
    Network::closeConnection(ssl, sock);
    Network::freeContext(ctx);

    if (resp.type == MessageType::KDC_REGISTER_SUCCESS) {
        log("KDC registration successful!", false);
        return true;
    }
    log("KDC registration failed", true);
    return false;
}

// ─── Login: AS -> TGS -> ChatServer ───────────────────────────
inline bool doLogin(const std::string& username,
    const std::string& password,
    const std::string& serverIP,
    // outputs
    std::vector<unsigned char>& outKc,
    std::vector<unsigned char>& outKc_tgs,
    std::string& outTicket_tgs,
    std::string& outIv_tgt,
    std::vector<unsigned char>& outKc_v,
    std::string& outTicket_v,
    std::string& outIv_tv,
    SSL*& outSSL,
    SSL_CTX*& outCtx,
    LogCallback log) {
    // Tao Kc tu password
    std::vector<unsigned char> pwBytes(password.begin(), password.end());
    auto clientHash = Crypto::sha256(pwBytes);
    outKc = Crypto::sha256(clientHash);

    // ── AS request ────────────────────────────────────────────
    log("Requesting TGT from AS...", false);
    {
        // Dùng chain file để verify cert của RA/KDC/Chat (được ký bởi IntermCA)
        std::string chainFile = Config::CA_CHAIN();
        if (chainFile.empty() || !std::filesystem::exists(chainFile)) {
            chainFile = Config::CA_CERT();  // fallback về RootCA nếu chưa có chain
        }
        SSL_CTX* ctx = Network::createClientContext(chainFile);

        SSL* ssl = Network::connectToServer(ctx, serverIP.c_str(), Config::PORT_KDC);
        if (!ssl) {
            log("Cannot connect to KDC", true);
            Network::freeContext(ctx); return false;
        }

        Message req;
        req.type = MessageType::AS_REQUEST;
        req.payload["username"] = username;
        req.payload["timestamp"] = Utils::getTimestamp();
        Protocol::sendMessage(ssl, req);

        Message resp = Protocol::recvMessage(ssl);
        int sock = SSL_get_fd(ssl);
        Network::closeConnection(ssl, sock);
        Network::freeContext(ctx);

        if (resp.type != MessageType::AS_RESPONSE) {
            log("AS request failed - wrong password?", true);
            return false;
        }

        auto encResp = Utils::base64Decode(resp.payload["enc_response"]);
        auto iv_resp = Utils::base64Decode(resp.payload["iv_resp"]);

        try {
            auto dec = Crypto::aesDecrypt(outKc, iv_resp, encResp);
            if (dec.empty() || dec[0] != '{') {
                log("Wrong password - cannot decrypt TGT", true);
                return false;
            }
            json j = json::parse(std::string(dec.begin(), dec.end()));
            outKc_tgs = Utils::base64Decode(j["Kc_tgs"].get<std::string>());
            outTicket_tgs = j["ticket_tgs"];
            outIv_tgt = j["iv_tgt"];
        }
        catch (...) {
            log("Wrong password - TGT decryption failed", true);
            return false;
        }
        log("TGT received OK", false);
    }

    // ── TGS request ───────────────────────────────────────────
    log("Requesting Service Ticket from TGS...", false);
    {
        // Dùng chain file để verify cert của RA/KDC/Chat (được ký bởi IntermCA)
        std::string chainFile = Config::CA_CHAIN();
        if (chainFile.empty() || !std::filesystem::exists(chainFile)) {
            chainFile = Config::CA_CERT();  // fallback về RootCA nếu chưa có chain
        }
        SSL_CTX* ctx = Network::createClientContext(chainFile);
        SSL* ssl = Network::connectToServer(ctx, serverIP.c_str(), Config::PORT_KDC);
        if (!ssl) {
            log("Cannot connect to TGS", true);
            Network::freeContext(ctx); return false;
        }

        auto iv_auth = Crypto::generateNonce(16);
        json authP;
        authP["username"] = username;
        authP["timestamp"] = Utils::getTimestamp();
        std::string as = authP.dump();
        std::vector<unsigned char> ab(as.begin(), as.end());
        auto authEnc = Crypto::aesEncrypt(outKc_tgs, iv_auth, ab);

        Message req;
        req.type = MessageType::TGS_REQUEST;
        req.payload["username"] = username;
        req.payload["ticket_tgs"] = outTicket_tgs;
        req.payload["authenticator"] = Utils::base64Encode(authEnc);
        req.payload["iv_tgt"] = outIv_tgt;
        req.payload["iv_auth"] = Utils::base64Encode(iv_auth);
        Protocol::sendMessage(ssl, req);

        Message resp = Protocol::recvMessage(ssl);
        int sock = SSL_get_fd(ssl);
        Network::closeConnection(ssl, sock);
        Network::freeContext(ctx);

        if (resp.type != MessageType::TGS_RESPONSE) {
            log("TGS request failed", true);
            return false;
        }

        auto encResp = Utils::base64Decode(resp.payload["enc_response"]);
        auto iv_resp = Utils::base64Decode(resp.payload["iv_resp"]);
        auto dec = Crypto::aesDecrypt(outKc_tgs, iv_resp, encResp);
        json j = json::parse(std::string(dec.begin(), dec.end()));
        outKc_v = Utils::base64Decode(j["Kc_v"].get<std::string>());
        outTicket_v = j["ticket_v"];
        outIv_tv = j["iv_tv"];
        log("Service ticket received OK", false);
    }

    // ── Chat Server login ─────────────────────────────────────
    log("Logging in to Chat Server...", false);
    {
        // Dùng chain file để verify cert của RA/KDC/Chat (được ký bởi IntermCA)
        std::string chainFile = Config::CA_CHAIN();
        if (chainFile.empty() || !std::filesystem::exists(chainFile)) {
            chainFile = Config::CA_CERT();  // fallback về RootCA nếu chưa có chain
        }
        SSL_CTX* ctx = Network::createClientContext(chainFile);
        // Dùng Config::PORT_CHAT thay vì gõ cứng 5002
        SSL* ssl = Network::connectToServer(ctx, serverIP.c_str(), Config::PORT_CHAT);
        if (!ssl) {
            log("Cannot connect to Chat Server", true);
            Network::freeContext(ctx); return false;
        }

        auto iv_auth = Crypto::generateNonce(16);
        int64_t ts5 = Utils::getTimestamp();
        json authP;
        authP["username"] = username;
        authP["timestamp"] = ts5;
        std::string as = authP.dump();
        std::vector<unsigned char> ab(as.begin(), as.end());
        auto authEnc = Crypto::aesEncrypt(outKc_v, iv_auth, ab);

        Message req;
        req.type = MessageType::CLIENT_AUTH;
        req.payload["username"] = username;
        req.payload["ticket_v"] = outTicket_v;
        req.payload["authenticator"] = Utils::base64Encode(authEnc);
        req.payload["iv_tv"] = outIv_tv;
        req.payload["iv_auth"] = Utils::base64Encode(iv_auth);
        Protocol::sendMessage(ssl, req);

        Message resp = Protocol::recvMessage(ssl);

		// Xử lý trường hợp lỗi trước khi kiểm tra loại message
        if (resp.type == MessageType::ERROR_MSG) {
            std::string reason = resp.payload.value("reason", "unknown");
            if (reason == "already_logged_in") {
                log("Account '" + username + "' is already logged in!", true);
            }
            else {
                log("Login rejected: " + reason, true);
            }
            int s = SSL_get_fd(ssl);
            Network::closeConnection(ssl, s);
            Network::freeContext(ctx);
            return false;
        }

        if (resp.type != MessageType::SERVER_AUTH) {
            log("Chat Server login failed", true);
            int s = SSL_get_fd(ssl);
            Network::closeConnection(ssl, s);
            Network::freeContext(ctx);
            return false;
        }

        // Verify mutual auth
        auto encResp = Utils::base64Decode(resp.payload["enc_response"]);
        auto iv_resp = Utils::base64Decode(resp.payload["iv_resp"]);
        auto dec = Crypto::aesDecrypt(outKc_v, iv_resp, encResp);
        json j = json::parse(std::string(dec.begin(), dec.end()));
        if (j["timestamp"] != ts5 + 1) {
            log("Mutual auth failed!", true);
            int s = SSL_get_fd(ssl);
            Network::closeConnection(ssl, s);
            Network::freeContext(ctx);
            return false;
        }

        outSSL = ssl;
        outCtx = ctx;
        log("Login successful! Mutual auth verified.", false);
    }
    return true;
}