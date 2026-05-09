#define _CRT_SECURE_NO_WARNINGS

#include <openssl/applink.c>
#include "../Common/pch.h"
#include "../Common/utils.h"
#include "../Common/crypto.h"
#include "../Common/message.h"
#include "../Common/network.h"
#include <fstream>
#include <iostream>

// ─── Lưu string ra file ───────────────────────────────────────
void saveToFile(const std::string& path, const std::string& content) {
    std::ofstream f(path);
    f << content;
    f.close();
    Utils::log(Utils::LogLevel::INFO, "Client", "Saved to: " + path);
}

// ─── Load string từ file ──────────────────────────────────────
std::string loadFromFile(const std::string& path) {
    std::ifstream f(path);
    if (!f.is_open()) return "";
    std::string content((std::istreambuf_iterator<char>(f)),
        std::istreambuf_iterator<char>());
    return content;
}

// ─── Đăng ký cert với RA ──────────────────────────────────────
bool registerCert(const std::string& username) {
    Utils::log(Utils::LogLevel::INFO, "Client", "Starting cert registration for: " + username);

    // Bước 1: Kết nối TLS đến RA
    SSL_CTX* ctx = Network::createClientContext("C:\\SecureChatCerts\\ca.crt");
    if (!ctx) return false;

    SSL* ssl = Network::connectToServer(ctx, "127.0.0.1", 5001);
    if (!ssl) {
        Network::freeContext(ctx);
        return false;
    }
    Utils::log(Utils::LogLevel::INFO, "Client", "Connected to RA via TLS");

    // Bước 2: Sinh RSA keypair
    std::string pubKeyPEM, privKeyPEM;
    Crypto::generateRSAKeyPair(pubKeyPEM, privKeyPEM);
    Utils::log(Utils::LogLevel::INFO, "Client", "RSA keypair generated");

    // Bước 3: Nhận challenge nonce từ RA
    Message challenge = Protocol::recvMessage(ssl);
    if (challenge.type != MessageType::CHALLENGE) {
        Utils::log(Utils::LogLevel::ERR, "Client", "Expected CHALLENGE from RA");
        goto cleanup;
    }

    {
        std::string nonceB64 = challenge.payload["nonce"];
        int64_t     ts = challenge.payload["timestamp"];
        Utils::log(Utils::LogLevel::INFO, "Client", "Received nonce from RA");

        // Bước 4: Ký nonce bằng private key
        auto nonceBytes = Utils::base64Decode(nonceB64);
        auto sig = Crypto::signData(privKeyPEM, nonceBytes);
        std::string sigB64 = Utils::base64Encode(sig);

        // Bước 5: Gửi REGISTER_CERT
        Message req;
        req.type = MessageType::REGISTER_CERT;
        req.payload["username"] = username;
        req.payload["public_key"] = pubKeyPEM;
        req.payload["signature"] = sigB64;
        req.payload["nonce"] = nonceB64;
        req.payload["timestamp"] = Utils::getTimestamp();
        Protocol::sendMessage(ssl, req);
        Utils::log(Utils::LogLevel::INFO, "Client", "Sent REGISTER_CERT to RA");

        // Bước 6: Nhận cert từ RA
        Message resp = Protocol::recvMessage(ssl);
        if (resp.type == MessageType::CERT_RESPONSE) {
            std::string certPEM = resp.payload["cert"];
            Utils::log(Utils::LogLevel::INFO, "Client", "Certificate received!");

            // Lưu cert + key ra file
            saveToFile("C:\\SecureChatCerts\\" + username + ".crt", certPEM);
            saveToFile("C:\\SecureChatCerts\\" + username + ".key", privKeyPEM);

            Utils::log(Utils::LogLevel::INFO, "Client",
                "Cert saved to C:\\SecureChatCerts\\" + username + ".crt");
            Utils::log(Utils::LogLevel::INFO, "Client",
                "Key  saved to C:\\SecureChatCerts\\" + username + ".key");

            int sock = SSL_get_fd(ssl);
            Network::closeConnection(ssl, sock);
            Network::freeContext(ctx);
            return true;
        }
        else if (resp.type == MessageType::ERROR_MSG) {
            std::string reason = resp.payload["reason"];
            Utils::log(Utils::LogLevel::ERR, "Client", "Registration failed: " + reason);
        }
    }

cleanup:
    {
        int sock = SSL_get_fd(ssl);
        Network::closeConnection(ssl, sock);
        Network::freeContext(ctx);
        return false;
    }
}

// ─── Đăng ký account với Chat Server ─────────────────────────
bool registerAccount(const std::string& username) {
    Utils::log(Utils::LogLevel::INFO, "Client",
        "Starting account registration with Chat Server for: " + username);

    // Load cert và private key đã lưu từ bước trước
    std::string certPEM = loadFromFile("C:\\SecureChatCerts\\" + username + ".crt");
    std::string privKeyPEM = loadFromFile("C:\\SecureChatCerts\\" + username + ".key");

    if (certPEM.empty() || privKeyPEM.empty()) {
        Utils::log(Utils::LogLevel::ERR, "Client",
            "Cert or key not found. Run cert registration first.");
        return false;
    }

    // Bước 1: Kết nối TLS đến Chat Server
    SSL_CTX* ctx = Network::createClientContext("C:\\SecureChatCerts\\ca.crt");
    if (!ctx) return false;

    SSL* ssl = Network::connectToServer(ctx, "127.0.0.1", 5002);
    if (!ssl) {
        Network::freeContext(ctx);
        return false;
    }
    Utils::log(Utils::LogLevel::INFO, "Client", "Connected to Chat Server via TLS");

    // Bước 2: Gửi REGISTER_CERT kèm cert
    Message req;
    req.type = MessageType::REGISTER_CERT;
    req.payload["username"] = username;
    req.payload["cert"] = certPEM;
    req.payload["timestamp"] = Utils::getTimestamp();
    Protocol::sendMessage(ssl, req);
    Utils::log(Utils::LogLevel::INFO, "Client", "Sent cert to Chat Server");

    // Bước 3: Nhận challenge nonce (PoP)
    Message challenge = Protocol::recvMessage(ssl);
    if (challenge.type != MessageType::CHALLENGE) {
        Utils::log(Utils::LogLevel::ERR, "Client", "Expected CHALLENGE from Chat Server");
        goto cleanup;
    }

    {
        std::string nonceB64 = challenge.payload["nonce"];
        Utils::log(Utils::LogLevel::INFO, "Client", "Received PoP challenge from Chat Server");

        // Bước 4: Ký nonce bằng private key
        auto nonceBytes = Utils::base64Decode(nonceB64);
        auto sig = Crypto::signData(privKeyPEM, nonceBytes);
        std::string sigB64 = Utils::base64Encode(sig);

        // Bước 5: Gửi signature
        Message popResp;
        popResp.type = MessageType::CERT_RESPONSE;
        popResp.payload["signature"] = sigB64;
        popResp.payload["nonce"] = nonceB64;
        Protocol::sendMessage(ssl, popResp);
        Utils::log(Utils::LogLevel::INFO, "Client", "Sent PoP signature to Chat Server");

        // Bước 6: Nhận kết quả
        Message result = Protocol::recvMessage(ssl);
        if (result.type == MessageType::SUCCESS) {
            Utils::log(Utils::LogLevel::INFO, "Client",
                "Account registered successfully on Chat Server!");
            int sock = SSL_get_fd(ssl);
            Network::closeConnection(ssl, sock);
            Network::freeContext(ctx);
            return true;
        }
        else if (result.type == MessageType::ERROR_MSG) {
            std::string reason = result.payload["reason"];
            Utils::log(Utils::LogLevel::ERR, "Client",
                "Account registration failed: " + reason);
        }
    }

cleanup:
    {
        int sock = SSL_get_fd(ssl);
        Network::closeConnection(ssl, sock);
        Network::freeContext(ctx);
        return false;
    }
}

// ========================================= KDC Server =========================================
// ─── Struct lưu Kerberos session ──────────────────────────────
struct KerberosSession {
    std::vector<unsigned char> Kc;          // key từ password
    std::vector<unsigned char> Kc_tgs;      // session key với TGS
    std::string ticket_tgs_b64;             // TGT
    std::string iv_tgt_b64;                 // IV của TGT
    std::vector<unsigned char> Kc_v;        // session key với ChatServer
    std::string ticket_v_b64;               // Service ticket
    std::string iv_tv_b64;                  // IV của Service ticket
};

// ─── Đăng ký KDC ──────────────────────────────────────────────
bool registerKDC(const std::string& username, KerberosSession& session) {
    Utils::log(Utils::LogLevel::INFO, "Client",
        "Starting KDC registration for: " + username);

    // Load cert + private key
    std::string certPEM = loadFromFile("C:\\SecureChatCerts\\" + username + ".crt");
    std::string privKeyPEM = loadFromFile("C:\\SecureChatCerts\\" + username + ".key");
    if (certPEM.empty() || privKeyPEM.empty()) {
        Utils::log(Utils::LogLevel::ERR, "Client", "Cert/key not found");
        return false;
    }

    // Nhập password
    std::string password;
    std::cout << "Enter password for KDC registration: ";
    std::cin >> password;

    // Hash password
    std::vector<unsigned char> pwBytes(password.begin(), password.end());
    auto clientHash = Crypto::sha256(pwBytes);
    session.Kc = Crypto::sha256(clientHash); // Kc = Hash(Hash(password))

    // Kết nối KDC
    SSL_CTX* ctx = Network::createClientContext("C:\\SecureChatCerts\\ca.crt");
    if (!ctx) return false;

    SSL* ssl = Network::connectToServer(ctx, "127.0.0.1", 5003);
    if (!ssl) { Network::freeContext(ctx); return false; }
    Utils::log(Utils::LogLevel::INFO, "Client", "Connected to KDC via TLS");

    // Bước 1: Gửi KDC_REGISTER_INIT
    Message init;
    init.type = MessageType::KDC_REGISTER_INIT;
    init.payload["username"] = username;
    init.payload["cert"] = certPEM;
    Protocol::sendMessage(ssl, init);

    // Bước 2: Nhận challenge
    Message challenge = Protocol::recvMessage(ssl);
    if (challenge.type != MessageType::CHALLENGE) {
        Utils::log(Utils::LogLevel::ERR, "Client", "Expected CHALLENGE from KDC");
        goto cleanup;
    }

    {
        std::string nonceB64 = challenge.payload["nonce"];
        Utils::log(Utils::LogLevel::INFO, "Client", "Received KDC challenge");

        // Bước 3: Ký nonce
        auto nonceBytes = Utils::base64Decode(nonceB64);
        auto sig = Crypto::signData(privKeyPEM, nonceBytes);
        std::string sigB64 = Utils::base64Encode(sig);

        // Bước 4: Gửi KDC_REGISTER
        Message reg;
        reg.type = MessageType::KDC_REGISTER;
        reg.payload["client_hash"] = Utils::base64Encode(clientHash);
        reg.payload["signature"] = sigB64;
        reg.payload["nonce"] = nonceB64;
        Protocol::sendMessage(ssl, reg);
        Utils::log(Utils::LogLevel::INFO, "Client", "Sent KDC_REGISTER");

        // Bước 5: Nhận kết quả
        Message result = Protocol::recvMessage(ssl);
        if (result.type == MessageType::KDC_REGISTER_SUCCESS) {
            Utils::log(Utils::LogLevel::INFO, "Client",
                "KDC registration successful!");
            int sock = SSL_get_fd(ssl);
            Network::closeConnection(ssl, sock);
            Network::freeContext(ctx);
            return true;
        }
        else {
            std::string reason = result.payload["reason"];
            Utils::log(Utils::LogLevel::ERR, "Client",
                "KDC registration failed: " + reason);
        }
    }

cleanup:
    {
        int sock = SSL_get_fd(ssl);
        Network::closeConnection(ssl, sock);
        Network::freeContext(ctx);
        return false;
    }
}

// ─── Lấy TGT từ AS ────────────────────────────────────────────
bool getTicketFromAS(const std::string& username, KerberosSession& session) {
    Utils::log(Utils::LogLevel::INFO, "Client", "Requesting TGT from AS...");

    SSL_CTX* ctx = Network::createClientContext("C:\\SecureChatCerts\\ca.crt");
    if (!ctx) return false;

    SSL* ssl = Network::connectToServer(ctx, "127.0.0.1", 5003);
    if (!ssl) { Network::freeContext(ctx); return false; }

    // Gửi AS_REQUEST
    Message req;
    req.type = MessageType::AS_REQUEST;
    req.payload["username"] = username;
    req.payload["timestamp"] = Utils::getTimestamp();
    Protocol::sendMessage(ssl, req);

    // Nhận AS_RESPONSE
    Message resp = Protocol::recvMessage(ssl);
    if (resp.type != MessageType::AS_RESPONSE) {
        Utils::log(Utils::LogLevel::ERR, "Client", "AS request failed");
        goto cleanup;
    }

    {
        auto encResp = Utils::base64Decode(resp.payload["enc_response"]);
        auto iv_resp = Utils::base64Decode(resp.payload["iv_resp"]);

        // Giải mã bằng Kc
        std::vector<unsigned char> decResp;
        try {
            decResp = Crypto::aesDecrypt(session.Kc, iv_resp, encResp);
            if (decResp.empty()) {
                Utils::log(Utils::LogLevel::ERR, "Client",
                    "Wrong password - failed to decrypt TGT");
                goto cleanup;
            }
            std::string decStr(decResp.begin(), decResp.end());

            // Kiem tra JSON hop le truoc khi parse
            if (decStr.empty() || decStr[0] != '{') {
                Utils::log(Utils::LogLevel::ERR, "Client",
                    "Wrong password - decrypted data is not valid JSON");
                goto cleanup;
            }

            json decJson = json::parse(decStr);

            // Kiem tra co du fields khong
            if (!decJson.contains("Kc_tgs") ||
                !decJson.contains("ticket_tgs") ||
                !decJson.contains("iv_tgt")) {
                Utils::log(Utils::LogLevel::ERR, "Client",
                    "Wrong password - missing fields in decrypted TGT");
                goto cleanup;
            }

            session.Kc_tgs = Utils::base64Decode(decJson["Kc_tgs"]);
            session.ticket_tgs_b64 = decJson["ticket_tgs"];
            session.iv_tgt_b64 = decJson["iv_tgt"];

            Utils::log(Utils::LogLevel::INFO, "Client", "TGT received and decrypted OK");

            int sock = SSL_get_fd(ssl);
            Network::closeConnection(ssl, sock);
            Network::freeContext(ctx);
            return true;
        }
        catch (std::exception& e) {
            Utils::log(Utils::LogLevel::ERR, "Client",
                "Wrong password - decryption failed: " + std::string(e.what()));
            goto cleanup;
        }
    }

cleanup:
    {
        int sock = SSL_get_fd(ssl);
        Network::closeConnection(ssl, sock);
        Network::freeContext(ctx);
        return false;
    }
}

// ─── Lấy Service Ticket từ TGS ────────────────────────────────
bool getServiceTicket(const std::string& username, KerberosSession& session) {
    Utils::log(Utils::LogLevel::INFO, "Client", "Requesting Service Ticket from TGS...");

    SSL_CTX* ctx = Network::createClientContext("C:\\SecureChatCerts\\ca.crt");
    if (!ctx) return false;

    SSL* ssl = Network::connectToServer(ctx, "127.0.0.1", 5003);
    if (!ssl) { Network::freeContext(ctx); return false; }

    // Tạo Authenticator mã hóa bằng Kc_tgs
    auto iv_auth = Crypto::generateNonce(16);
    json authPayload;
    authPayload["username"] = username;
    authPayload["timestamp"] = Utils::getTimestamp();
    std::string authStr = authPayload.dump();
    std::vector<unsigned char> authBytes(authStr.begin(), authStr.end());
    auto authEnc = Crypto::aesEncrypt(session.Kc_tgs, iv_auth, authBytes);

    // Gửi TGS_REQUEST
    Message req;
    req.type = MessageType::TGS_REQUEST;
    req.payload["username"] = username;
    req.payload["ticket_tgs"] = session.ticket_tgs_b64;
    req.payload["authenticator"] = Utils::base64Encode(authEnc);
    req.payload["iv_tgt"] = session.iv_tgt_b64;
    req.payload["iv_auth"] = Utils::base64Encode(iv_auth);
    Protocol::sendMessage(ssl, req);

    // Nhận TGS_RESPONSE
    Message resp = Protocol::recvMessage(ssl);
    if (resp.type != MessageType::TGS_RESPONSE) {
        Utils::log(Utils::LogLevel::ERR, "Client", "TGS request failed");
        goto cleanup;
    }

    {
        auto encResp = Utils::base64Decode(resp.payload["enc_response"]);
        auto iv_resp = Utils::base64Decode(resp.payload["iv_resp"]);

        // Giải mã bằng Kc_tgs
        auto decResp = Crypto::aesDecrypt(session.Kc_tgs, iv_resp, encResp);
        std::string decStr(decResp.begin(), decResp.end());
        json decJson = json::parse(decStr);

        // Lưu Kc_v + Service ticket
        session.Kc_v = Utils::base64Decode(decJson["Kc_v"]);
        session.ticket_v_b64 = decJson["ticket_v"];
        session.iv_tv_b64 = decJson["iv_tv"];

        Utils::log(Utils::LogLevel::INFO, "Client",
            "Service ticket received and decrypted OK");

        int sock = SSL_get_fd(ssl);
        Network::closeConnection(ssl, sock);
        Network::freeContext(ctx);
        return true;
    }

cleanup:
    {
        int sock = SSL_get_fd(ssl);
        Network::closeConnection(ssl, sock);
        Network::freeContext(ctx);
        return false;
    }
}

// ─── E2EE Chat Session ────────────────────────────────────────
void chatSession(SSL* ssl, const std::string& username,
    const std::vector<unsigned char>& Kc_v) {
    Utils::log(Utils::LogLevel::INFO, "Client", "Entering chat mode...");

    std::string targetUser;
    std::cout << "Chat with (username): ";
    std::cin >> targetUser;

    // ── Buoc 1: Xin public key cua B tu Server ────────────────
    Message sessionReq;
    sessionReq.type = MessageType::SESSION_REQUEST;
    sessionReq.payload["target"] = targetUser;
    Protocol::sendMessage(ssl, sessionReq);

    Message sessionResp = Protocol::recvMessage(ssl);
    if (sessionResp.type != MessageType::SESSION_RESPONSE) {
        Utils::log(Utils::LogLevel::ERR, "Client", "Failed to get pubkey of " + targetUser);
        return;
    }

    std::string targetPubKey = sessionResp.payload["public_key"];
    Utils::log(Utils::LogLevel::INFO, "Client",
        "Got public key of " + targetUser);

    // ── Buoc 2: Sinh K_AB va nonce ────────────────────────────
    auto K_AB = Crypto::generateNonce(32);
    auto nonce_A = Crypto::generateNonce(16);

    // ── Buoc 3: Ma hoa K_AB bang public key cua B ─────────────
    json keyPayload;
    keyPayload["K_AB"] = Utils::base64Encode(K_AB);
    keyPayload["from"] = username;
    keyPayload["nonce_A"] = Utils::base64Encode(nonce_A);
    std::string keyStr = keyPayload.dump();
    std::vector<unsigned char> keyBytes(keyStr.begin(), keyStr.end());
    auto encKeyExchange = Crypto::encryptRSA(targetPubKey, keyBytes);

    // ── Buoc 4: Gui KEY_EXCHANGE den B qua Server ─────────────
    Message keyMsg;
    keyMsg.type = MessageType::KEY_EXCHANGE;
    keyMsg.payload["target"] = targetUser;
    keyMsg.payload["data"] = Utils::base64Encode(encKeyExchange);
    Protocol::sendMessage(ssl, keyMsg);
    Utils::log(Utils::LogLevel::INFO, "Client",
        "Sent K_AB to " + targetUser + " (encrypted with their public key)");

    // ── Buoc 5: Nhan KEY_ACK tu B ─────────────────────────────
    Utils::log(Utils::LogLevel::INFO, "Client", "Waiting for KEY_ACK from " + targetUser + "...");
    Message ack = Protocol::recvMessage(ssl);
    if (ack.type != MessageType::KEY_ACK) {
        Utils::log(Utils::LogLevel::ERR, "Client", "Expected KEY_ACK");
        return;
    }

    {
        // Giai ma ACK bang K_AB
        auto ackEnc = Utils::base64Decode(ack.payload["data"]);
        auto iv_ack = Utils::base64Decode(ack.payload["iv"]);
        auto ackBytes = Crypto::aesDecrypt(K_AB, iv_ack, ackEnc);
        std::string ackStr(ackBytes.begin(), ackBytes.end());
        json ackJson = json::parse(ackStr);

        std::string ackNonceA = ackJson["nonce_A"];
        std::string nonce_B = ackJson["nonce_B"];

        // Verify nonce_A
        if (ackNonceA != Utils::base64Encode(nonce_A)) {
            Utils::log(Utils::LogLevel::ERR, "Client",
                "nonce_A mismatch - possible attack!");
            return;
        }
        Utils::log(Utils::LogLevel::INFO, "Client",
            "KEY_ACK verified - B has K_AB!");

        // Gui xac nhan nonce_B ve B
        auto iv_conf = Crypto::generateNonce(16);
        json confPayload;
        confPayload["nonce_B"] = nonce_B;
        std::string confStr = confPayload.dump();
        std::vector<unsigned char> confBytes(confStr.begin(), confStr.end());
        auto encConf = Crypto::aesEncrypt(K_AB, iv_conf, confBytes);

        Message conf;
        conf.type = MessageType::KEY_ACK;
        conf.payload["target"] = targetUser;
        conf.payload["data"] = Utils::base64Encode(encConf);
        conf.payload["iv"] = Utils::base64Encode(iv_conf);
        Protocol::sendMessage(ssl, conf);
        Utils::log(Utils::LogLevel::INFO, "Client",
            "Sent nonce_B confirmation - E2EE established!");
    }

    // ── Buoc 6: Chat loop ─────────────────────────────────────
    Utils::log(Utils::LogLevel::INFO, "Client",
        "=== E2EE Chat started with " + targetUser + " (type 'quit' to exit) ===");

    // Thread nhan tin
    std::thread recvThread([&]() {
        try {
            while (true) {
                Message msg = Protocol::recvMessage(ssl);
                if (msg.type == MessageType::CHAT_MESSAGE) {
                    auto encMsg = Utils::base64Decode(msg.payload["data"]);
                    auto iv_msg = Utils::base64Decode(msg.payload["iv"]);
                    auto decBytes = Crypto::aesDecrypt(K_AB, iv_msg, encMsg);
                    std::string plaintext(decBytes.begin(), decBytes.end());
                    std::cout << "\n[" << targetUser << "]: " << plaintext << "\n> ";
                    std::cout.flush();
                }
            }
        }
        catch (...) {
            Utils::log(Utils::LogLevel::INFO, "Client", "Receive thread stopped");
        }
        });
    recvThread.detach();

    // Thread gui tin
    std::string input;
    std::cout << "> ";
    std::cin.ignore();
    while (std::getline(std::cin, input)) {
        if (input == "quit") break;
        if (input.empty()) { std::cout << "> "; continue; }

        std::vector<unsigned char> msgBytes(input.begin(), input.end());
        auto iv_msg = Crypto::generateNonce(16);
        auto encMsg = Crypto::aesEncrypt(K_AB, iv_msg, msgBytes);

        Message chatMsg;
        chatMsg.type = MessageType::CHAT_MESSAGE;
        chatMsg.payload["target"] = targetUser;
        chatMsg.payload["data"] = Utils::base64Encode(encMsg);
        chatMsg.payload["iv"] = Utils::base64Encode(iv_msg);
        Protocol::sendMessage(ssl, chatMsg);
        std::cout << "> ";
    }

    Utils::log(Utils::LogLevel::INFO, "Client", "Chat session ended");
}

// ─── Xử lí tin K_AB từ A (phia B) ───────────────────────────
void receiveChatSession(SSL* ssl, const std::string& username,
    const std::string& privKeyPEM,
    const std::vector<unsigned char>& Kc_v) {
    Utils::log(Utils::LogLevel::INFO, "Client",
        "Waiting for incoming chat session...");

    // Nhan KEY_EXCHANGE tu A
    Message keyMsg = Protocol::recvMessage(ssl);
    if (keyMsg.type != MessageType::KEY_EXCHANGE) {
        Utils::log(Utils::LogLevel::ERR, "Client", "Expected KEY_EXCHANGE");
        return;
    }

    std::string fromUser = keyMsg.payload["from"];
    Utils::log(Utils::LogLevel::INFO, "Client",
        "Incoming chat session from: " + fromUser);

    // Giai ma K_AB bang private key
    auto encData = Utils::base64Decode(keyMsg.payload["data"]);
    auto decBytes = Crypto::decryptRSA(privKeyPEM, encData);
    std::string decStr(decBytes.begin(), decBytes.end());
    json decJson = json::parse(decStr);

    auto K_AB = Utils::base64Decode(decJson["K_AB"].get<std::string>());
    std::string nonce_A = decJson["nonce_A"];
    Utils::log(Utils::LogLevel::INFO, "Client",
        "K_AB decrypted successfully!");

    // Sinh nonce_B, gui KEY_ACK ve A
    auto nonce_B = Crypto::generateNonce(16);
    auto iv_ack = Crypto::generateNonce(16);

    json ackPayload;
    ackPayload["nonce_A"] = nonce_A;
    ackPayload["nonce_B"] = Utils::base64Encode(nonce_B);
    std::string ackStr = ackPayload.dump();
    std::vector<unsigned char> ackBytes(ackStr.begin(), ackStr.end());
    auto encAck = Crypto::aesEncrypt(K_AB, iv_ack, ackBytes);

    Message ack;
    ack.type = MessageType::KEY_ACK;
    ack.payload["target"] = fromUser;
    ack.payload["data"] = Utils::base64Encode(encAck);
    ack.payload["iv"] = Utils::base64Encode(iv_ack);
    Protocol::sendMessage(ssl, ack);
    Utils::log(Utils::LogLevel::INFO, "Client", "Sent KEY_ACK to " + fromUser);

    // Nhan xac nhan nonce_B tu A
    Message conf = Protocol::recvMessage(ssl);
    if (conf.type != MessageType::KEY_ACK) {
        Utils::log(Utils::LogLevel::ERR, "Client", "Expected nonce_B confirmation");
        return;
    }

    {
        auto confEnc = Utils::base64Decode(conf.payload["data"]);
        auto iv_conf = Utils::base64Decode(conf.payload["iv"]);
        auto confBytes = Crypto::aesDecrypt(K_AB, iv_conf, confEnc);
        std::string confStr(confBytes.begin(), confBytes.end());
        json confJson = json::parse(confStr);

        if (confJson["nonce_B"] != Utils::base64Encode(nonce_B)) {
            Utils::log(Utils::LogLevel::ERR, "Client",
                "nonce_B mismatch - possible attack!");
            return;
        }
        Utils::log(Utils::LogLevel::INFO, "Client",
            "E2EE established with " + fromUser + "!");
    }

    // Chat loop phia B
    Utils::log(Utils::LogLevel::INFO, "Client",
        "=== E2EE Chat started with " + fromUser + " (type 'quit' to exit) ===");

    std::thread recvThread([&]() {
        try {
            while (true) {
                Message msg = Protocol::recvMessage(ssl);
                if (msg.type == MessageType::CHAT_MESSAGE) {
                    auto encMsg = Utils::base64Decode(msg.payload["data"]);
                    auto iv_msg = Utils::base64Decode(msg.payload["iv"]);
                    auto decBytes = Crypto::aesDecrypt(K_AB, iv_msg, encMsg);
                    std::string plaintext(decBytes.begin(), decBytes.end());
                    std::cout << "\n[" << fromUser << "]: " << plaintext << "\n> ";
                    std::cout.flush();
                }
            }
        }
        catch (...) {
            Utils::log(Utils::LogLevel::INFO, "Client", "Receive thread stopped");
        }
        });
    recvThread.detach();

    std::string input;
    std::cout << "> ";
    std::cin.ignore();
    while (std::getline(std::cin, input)) {
        if (input == "quit") break;
        if (input.empty()) { std::cout << "> "; continue; }

        std::vector<unsigned char> msgBytes(input.begin(), input.end());
        auto iv_msg = Crypto::generateNonce(16);
        auto encMsg = Crypto::aesEncrypt(K_AB, iv_msg, msgBytes);

        Message chatMsg;
        chatMsg.type = MessageType::CHAT_MESSAGE;
        chatMsg.payload["target"] = fromUser;
        chatMsg.payload["data"] = Utils::base64Encode(encMsg);
        chatMsg.payload["iv"] = Utils::base64Encode(iv_msg);
        Protocol::sendMessage(ssl, chatMsg);
        std::cout << "> ";
    }
}

// ─── Login Chat Server bằng Kerberos ticket và vào chat mode ───────────────
bool loginToServer(const std::string& username,
    KerberosSession& session,
    const std::string& privKeyPEM) {
    Utils::log(Utils::LogLevel::INFO, "Client",
        "Logging in to Chat Server...");

    SSL_CTX* ctx = Network::createClientContext("C:\\SecureChatCerts\\ca.crt");
    if (!ctx) return false;

    SSL* ssl = Network::connectToServer(ctx, "127.0.0.1", 5002);
    if (!ssl) { Network::freeContext(ctx); return false; }

    // Tao Authenticator
    auto iv_auth = Crypto::generateNonce(16);
    int64_t ts5 = Utils::getTimestamp();
    json authPayload;
    authPayload["username"] = username;
    authPayload["timestamp"] = ts5;
    std::string authStr = authPayload.dump();
    std::vector<unsigned char> authBytes(authStr.begin(), authStr.end());
    auto authEnc = Crypto::aesEncrypt(session.Kc_v, iv_auth, authBytes);

    // Gui CLIENT_AUTH
    Message req;
    req.type = MessageType::CLIENT_AUTH;
    req.payload["username"] = username;
    req.payload["ticket_v"] = session.ticket_v_b64;
    req.payload["authenticator"] = Utils::base64Encode(authEnc);
    req.payload["iv_tv"] = session.iv_tv_b64;
    req.payload["iv_auth"] = Utils::base64Encode(iv_auth);
    Protocol::sendMessage(ssl, req);

    // Nhan SERVER_AUTH
    Message resp = Protocol::recvMessage(ssl);
    if (resp.type != MessageType::SERVER_AUTH) {
        Utils::log(Utils::LogLevel::ERR, "Client", "Login failed");
        int sock = SSL_get_fd(ssl);
        Network::closeConnection(ssl, sock);
        Network::freeContext(ctx);
        return false;
    }

    {
        auto encResp = Utils::base64Decode(resp.payload["enc_response"]);
        auto iv_resp = Utils::base64Decode(resp.payload["iv_resp"]);
        auto decResp = Crypto::aesDecrypt(session.Kc_v, iv_resp, encResp);
        std::string decStr(decResp.begin(), decResp.end());
        json decJson = json::parse(decStr);

        int64_t serverTs = decJson["timestamp"];
        if (serverTs != ts5 + 1) {
            Utils::log(Utils::LogLevel::ERR, "Client",
                "Mutual auth failed!");
            int sock = SSL_get_fd(ssl);
            Network::closeConnection(ssl, sock);
            Network::freeContext(ctx);
            return false;
        }
        Utils::log(Utils::LogLevel::INFO, "Client",
            "Mutual authentication OK!");
    }

    // Chon mode: A (gui truoc) hay B (nhan truoc)
    int mode = 0;
    std::cout << "\n[1] Start chat (send first)\n";
    std::cout << "[2] Wait for incoming chat (receive first)\n";
    std::cout << "Choice: ";
    std::cin >> mode;

    if (mode == 1) {
        chatSession(ssl, username, session.Kc_v);
    }
    else {
        receiveChatSession(ssl, username, privKeyPEM, session.Kc_v);
    }

    int sock = SSL_get_fd(ssl);
    Network::closeConnection(ssl, sock);
    Network::freeContext(ctx);
    return true;
}

// ─── Test replay attack ───────────────────────────────────────
void testReplayAttack(const std::string& username) {
    Utils::log(Utils::LogLevel::INFO, "Client",
        "=== REPLAY ATTACK TEST ===");

    std::string certPEM = loadFromFile("C:\\SecureChatCerts\\" + username + ".crt");
    std::string privKeyPEM = loadFromFile("C:\\SecureChatCerts\\" + username + ".key");
    if (certPEM.empty() || privKeyPEM.empty()) {
        Utils::log(Utils::LogLevel::ERR, "Client", "No cert/key found");
        return;
    }

    // ── Lan 1: Ket noi binh thuong, lay nonce ─────────────────
    SSL_CTX* ctx1 = Network::createClientContext("C:\\SecureChatCerts\\ca.crt");
    SSL* ssl1 = Network::connectToServer(ctx1, "127.0.0.1", 5001);
    if (!ssl1) { Network::freeContext(ctx1); return; }

    // Nhan challenge
    Message challenge = Protocol::recvMessage(ssl1);
    std::string nonceB64 = challenge.payload["nonce"];
    Utils::log(Utils::LogLevel::INFO, "Client",
        "Got nonce from RA: " + nonceB64.substr(0, 16) + "...");

    // Ky nonce
    auto nonceBytes = Utils::base64Decode(nonceB64);
    auto sig = Crypto::signData(privKeyPEM, nonceBytes);
    std::string sigB64 = Utils::base64Encode(sig);

    // Gui lan 1 - hop le
    Message req1;
    req1.type = MessageType::REGISTER_CERT;
    req1.payload["username"] = username + "_replay_test";
    req1.payload["public_key"] = certPEM;
    req1.payload["signature"] = sigB64;
    req1.payload["nonce"] = nonceB64;
    req1.payload["timestamp"] = Utils::getTimestamp();
    Protocol::sendMessage(ssl1, req1);

    Message resp1 = Protocol::recvMessage(ssl1);
    Utils::log(Utils::LogLevel::INFO, "Client",
        "Attempt 1 (legitimate): " +
        std::string(resp1.type != MessageType::ERROR_MSG ? "ACCEPTED" : "REJECTED"));

    int sock1 = SSL_get_fd(ssl1);
    Network::closeConnection(ssl1, sock1);
    Network::freeContext(ctx1);

    // ── Lan 2: Replay - dung lai nonce cu ─────────────────────
    Sleep(500);
    Utils::log(Utils::LogLevel::WARN, "Client",
        "Attempting REPLAY with same nonce...");

    SSL_CTX* ctx2 = Network::createClientContext("C:\\SecureChatCerts\\ca.crt");
    SSL* ssl2 = Network::connectToServer(ctx2, "127.0.0.1", 5001);
    if (!ssl2) { Network::freeContext(ctx2); return; }

    // Bo qua challenge moi, dung nonce cu
    Message newChallenge = Protocol::recvMessage(ssl2);
    // INTENTIONALLY ignore newChallenge.payload["nonce"]
    // va dung lai nonceB64 cu

    Message req2;
    req2.type = MessageType::REGISTER_CERT;
    req2.payload["username"] = username + "_replay_test";
    req2.payload["public_key"] = certPEM;
    req2.payload["signature"] = sigB64;     // sig cu
    req2.payload["nonce"] = nonceB64;   // nonce cu - day la replay
    req2.payload["timestamp"] = Utils::getTimestamp();
    Protocol::sendMessage(ssl2, req2);

    Message resp2 = Protocol::recvMessage(ssl2);
    if (resp2.type == MessageType::ERROR_MSG) {
        std::string reason = resp2.payload["reason"];
        Utils::log(Utils::LogLevel::INFO, "Client",
            "Attempt 2 (REPLAY): BLOCKED - " + reason);
        Utils::log(Utils::LogLevel::INFO, "Client",
            "=== REPLAY ATTACK TEST PASSED ===");
    }
    else {
        Utils::log(Utils::LogLevel::ERR, "Client",
            "Attempt 2 (REPLAY): NOT BLOCKED - SECURITY ISSUE!");
    }

    int sock2 = SSL_get_fd(ssl2);
    Network::closeConnection(ssl2, sock2);
    Network::freeContext(ctx2);
}

int main() {
    Utils::log(Utils::LogLevel::INFO, "Client", "=== Secure Chat Client ===");
    Sleep(2000);

    std::string username;
    std::cout << "Enter username: ";
    std::cin >> username;

    // Load private key neu co san
    std::string privKeyPEM = loadFromFile("C:\\SecureChatCerts\\" + username + ".key");

    KerberosSession session;

    int choice = 0;
    std::cout << "\n[1] Register Certificate (RA)\n";
    std::cout << "[2] Register Account (Chat Server)\n";
    std::cout << "[3] Register KDC\n";
    std::cout << "[4] Login (AS -> TGS -> Chat Server)\n";
    std::cout << "[5] Do all steps\n";
    std::cout << "[6] Test replay attack\n";      
    std::cout << "[7] Test expired ticket\n";
    std::cout << "Choice: ";
    std::cin >> choice;

    if (choice == 1 || choice == 5) {
        if (!registerCert(username)) {
            Utils::log(Utils::LogLevel::ERR, "Client", "Cert registration failed.");
            system("pause"); return 1;
        }
        // Reload sau khi register
        privKeyPEM = loadFromFile("C:\\SecureChatCerts\\" + username + ".key");
    }

    if (choice == 2 || choice == 5) {
        if (!registerAccount(username)) {
            Utils::log(Utils::LogLevel::ERR, "Client", "Account registration failed.");
            system("pause"); return 1;
        }
    }

    if (choice == 3 || choice == 5) {
        if (!registerKDC(username, session)) {
            Utils::log(Utils::LogLevel::ERR, "Client", "KDC registration failed.");
            system("pause"); return 1;
        }
    }

    if (choice == 4 || choice == 5) {
        if (choice == 4) {
            std::string password;
            std::cout << "Enter password: ";
            std::cin >> password;
            std::vector<unsigned char> pwBytes(password.begin(), password.end());
            auto clientHash = Crypto::sha256(pwBytes);
            session.Kc = Crypto::sha256(clientHash);
        }

        if (!getTicketFromAS(username, session)) {
            Utils::log(Utils::LogLevel::ERR, "Client", "AS request failed.");
            system("pause"); return 1;
        }

        if (!getServiceTicket(username, session)) {
            Utils::log(Utils::LogLevel::ERR, "Client", "TGS request failed.");
            system("pause"); return 1;
        }

        if (!loginToServer(username, session, privKeyPEM)) {
            Utils::log(Utils::LogLevel::ERR, "Client", "Chat Server login failed.");
            system("pause"); return 1;
        }
    }

    if (choice == 6) {
        testReplayAttack(username);
        system("pause");
        return 0;
    }

    if (choice == 7) {
        Utils::log(Utils::LogLevel::INFO, "Client",
            "=== EXPIRED TICKET TEST ===");
        Utils::log(Utils::LogLevel::INFO, "Client",
            "Make sure KDC was started with: KDC_Server.exe 10");

        // Tao Kc tu password
        std::string password;
        std::cout << "Enter password: ";
        std::cin >> password;
        std::vector<unsigned char> pwBytes(password.begin(), password.end());
        auto clientHash = Crypto::sha256(pwBytes);
        session.Kc = Crypto::sha256(clientHash);

        // Lay ticket
        if (!getTicketFromAS(username, session)) {
            Utils::log(Utils::LogLevel::ERR, "Client", "AS failed");
            system("pause"); return 1;
        }
        if (!getServiceTicket(username, session)) {
            Utils::log(Utils::LogLevel::ERR, "Client", "TGS failed");
            system("pause"); return 1;
        }

        // Doi ticket het han
        Utils::log(Utils::LogLevel::WARN, "Client",
            "Waiting 15 seconds for ticket to expire...");
        Sleep(7000);

        // Thu login voi ticket het han
        Utils::log(Utils::LogLevel::WARN, "Client",
            "Attempting login with EXPIRED ticket...");
        if (!loginToServer(username, session, privKeyPEM)) {
            Utils::log(Utils::LogLevel::INFO, "Client",
                "=== EXPIRED TICKET TEST PASSED - login rejected ===");
        }
        else {
            Utils::log(Utils::LogLevel::ERR, "Client",
                "EXPIRED TICKET NOT REJECTED - SECURITY ISSUE!");
        }
        system("pause");
        return 0;
    }

    Utils::log(Utils::LogLevel::INFO, "Client", "All done!");
    system("pause");
    return 0;
}