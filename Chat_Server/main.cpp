#define _CRT_SECURE_NO_WARNINGS

#include <openssl/applink.c>
#include "../Common/pch.h"
#include "../Common/utils.h"
#include "../Common/crypto.h"
#include "../Common/message.h"
#include "../Common/network.h"
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <map>
#include <mutex>
#include <set>


// ─── Account DB ───────────────────────────────────────────────
struct Account {
    std::string username;
    std::string certPEM;
    std::string pubKeyPEM;
};

static std::map<std::string, Account> g_accounts;
static std::mutex g_accountMutex;
static std::set<std::string> g_usedNonces;
static std::mutex g_nonceMutex;

// ─── Online clients: username -> SSL* (relay message) ─────────
static std::map<std::string, SSL*> g_onlineClients;
static std::mutex g_onlineMutex;

// ─── Load/Save DB ─────────
static const std::string CHAT_DB_FILE = Config::CHAT_DB();

void saveChatDB() {
    std::lock_guard<std::mutex> lock(g_accountMutex);
    json j;
    json accounts = json::array();
    for (auto& [username, acc] : g_accounts) {
        json entry;
        entry["username"] = acc.username;
        entry["cert"] = acc.certPEM;
        entry["public_key"] = acc.pubKeyPEM;
        accounts.push_back(entry);
    }
    j["accounts"] = accounts;

    std::ofstream f(CHAT_DB_FILE);
    f << j.dump(2);
    Utils::log(Utils::LogLevel::INFO, "ChatServer", "DB saved");
}

void loadChatDB() {
    std::ifstream f(CHAT_DB_FILE);
    if (!f.is_open()) {
        Utils::log(Utils::LogLevel::INFO, "ChatServer", "No DB file, starting fresh");
        return;
    }

    try {
        json j = json::parse(f);
        std::lock_guard<std::mutex> lock(g_accountMutex);
        for (auto& entry : j["accounts"]) {
            Account acc;
            acc.username = entry["username"];
            acc.certPEM = entry["cert"];
            acc.pubKeyPEM = entry["public_key"];
            g_accounts[acc.username] = acc;
        }
        Utils::log(Utils::LogLevel::INFO, "ChatServer",
            "DB loaded: " + std::to_string(g_accounts.size()) + " accounts");
    }
    catch (std::exception& e) {
        Utils::log(Utils::LogLevel::ERR, "ChatServer",
            "Failed to load DB: " + std::string(e.what()));
    }
}

// ─── Verify cert với CA (online) ──────────────────────────────
bool verifyCertWithCA(const std::string& certPEM, int& outSerial) {
    // Parse cert lấy serial
    BIO* bio = BIO_new_mem_buf(certPEM.data(), (int)certPEM.size());
    X509* cert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (!cert) return false;

    outSerial = (int)ASN1_INTEGER_get(X509_get_serialNumber(cert));
    X509_free(cert);

    // Kết nối CA hỏi trạng thái
    SSL_CTX* ctx = Network::createClientContext(Config::CA_CERT());
    if (!ctx) return false;

    SSL* ssl = Network::connectToServer(ctx, "127.0.0.1", Config::PORT_CA);
    if (!ssl) { Network::freeContext(ctx); return false; }

    Message req;
    req.type = MessageType::VERIFY_CERT;
    req.payload["serial"] = outSerial;
    Protocol::sendMessage(ssl, req);

    Message resp = Protocol::recvMessage(ssl);
    bool valid = (resp.type == MessageType::CERT_STATUS &&
        resp.payload["status"] == "VALID");

    int sock = SSL_get_fd(ssl);
    Network::closeConnection(ssl, sock);
    Network::freeContext(ctx);
    return valid;
}

// ─── Lấy public key từ cert PEM ───────────────────────────────
std::string extractPublicKey(const std::string& certPEM) {
    BIO* bio = BIO_new_mem_buf(certPEM.data(), (int)certPEM.size());
    X509* cert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (!cert) return "";

    EVP_PKEY* pkey = X509_get_pubkey(cert);
    X509_free(cert);
    if (!pkey) return "";

    BIO* out = BIO_new(BIO_s_mem());
    PEM_write_bio_PUBKEY(out, pkey);
    BUF_MEM* ptr;
    BIO_get_mem_ptr(out, &ptr);
    std::string pubKeyPEM(ptr->data, ptr->length);
    BIO_free(out);
    EVP_PKEY_free(pkey);
    return pubKeyPEM;
}

// ─── Thêm kerberos login ───────────────────────────────────────────
// Kv phải giống với KDC
static std::vector<unsigned char> g_Kv;

// Lưu session đã login (username -> Kc_v)
struct LoginSession {
    std::string username;
    std::vector<unsigned char> Kc_v;
    int64_t timestamp;
};
static std::map<std::string, LoginSession> g_loginSessions;
static std::mutex g_loginMutex;

void handleLogin(SSL* ssl) {
    try {
        // Bước 1: Nhận CLIENT_AUTH (ticket + authenticator)
        Message req = Protocol::recvMessage(ssl);
        if (req.type != MessageType::CLIENT_AUTH) {
            Utils::log(Utils::LogLevel::ERR, "ChatServer", "Expected CLIENT_AUTH");
            return;
        }

        std::string username = req.payload["username"];
        std::string ticket_v_b64 = req.payload["ticket_v"];
        std::string auth_b64 = req.payload["authenticator"];
        std::string iv_tv_b64 = req.payload["iv_tv"];
        std::string iv_auth_b64 = req.payload["iv_auth"];
        Utils::log(Utils::LogLevel::INFO, "ChatServer",
            "CLIENT_AUTH from: " + username);

        // Bước 2: Giai ma Ticket_v bang Kv
        auto ticket_enc = Utils::base64Decode(ticket_v_b64);
        auto iv_tv = Utils::base64Decode(iv_tv_b64);
        auto ticketBytes = Crypto::aesDecrypt(g_Kv, iv_tv, ticket_enc);
        std::string ticketStr(ticketBytes.begin(), ticketBytes.end());
        json ticketJson = json::parse(ticketStr);

        std::string ticketUser = ticketJson["username"];
        int64_t     ticketTs = ticketJson["timestamp"];
        int64_t     lifetime = ticketJson["lifetime"];
        auto Kc_v = Utils::base64Decode(ticketJson["Kc_v"].get<std::string>());

        // Bước 3: Verify ticket
        if (ticketUser != username) {
            Utils::log(Utils::LogLevel::WARN, "ChatServer", "Ticket username mismatch");
            Message err; err.type = MessageType::ERROR_MSG;
            err.payload["reason"] = "Ticket mismatch";
            Protocol::sendMessage(ssl, err);
            return;
        }
        if (Utils::isExpired(ticketTs, (int)lifetime)) {
            Utils::log(Utils::LogLevel::WARN, "ChatServer", "Ticket expired");
            Message err; err.type = MessageType::ERROR_MSG;
            err.payload["reason"] = "Ticket expired";
            Protocol::sendMessage(ssl, err);
            return;
        }
        Utils::log(Utils::LogLevel::INFO, "ChatServer", "Ticket OK for: " + username);

        // Bước 4: Giai ma Authenticator bang Kc_v
        auto auth_enc = Utils::base64Decode(auth_b64);
        auto iv_auth = Utils::base64Decode(iv_auth_b64);
        auto authBytes = Crypto::aesDecrypt(Kc_v, iv_auth, auth_enc);
        std::string authStr(authBytes.begin(), authBytes.end());
        json authJson = json::parse(authStr);

        std::string authUser = authJson["username"];
        int64_t     authTs = authJson["timestamp"];

        if (authUser != username || Utils::isExpired(authTs, 300)) {
            Utils::log(Utils::LogLevel::WARN, "ChatServer",
                "Authenticator invalid for: " + username);
            Message err; err.type = MessageType::ERROR_MSG;
            err.payload["reason"] = "Authenticator invalid";
            Protocol::sendMessage(ssl, err);
            return;
        }
        Utils::log(Utils::LogLevel::INFO, "ChatServer",
            "Authenticator OK for: " + username);

        // Bước 5: Luu session
        {
            std::lock_guard<std::mutex> lock(g_loginMutex);
            LoginSession ls;
            ls.username = username;
            ls.Kc_v = Kc_v;
            ls.timestamp = Utils::getTimestamp();
            g_loginSessions[username] = ls;
        }

        // Bước 6: Mutual auth - tra loi TS + 1
        auto iv_resp = Crypto::generateNonce(16);
        json respPayload;
        respPayload["timestamp"] = authTs + 1;
        respPayload["username"] = username;
        std::string respStr = respPayload.dump();
        std::vector<unsigned char> respBytes(respStr.begin(), respStr.end());
        auto encResp = Crypto::aesEncrypt(Kc_v, iv_resp, respBytes);

        Message resp;
        resp.type = MessageType::SERVER_AUTH;
        resp.payload["enc_response"] = Utils::base64Encode(encResp);
        resp.payload["iv_resp"] = Utils::base64Encode(iv_resp);
        Protocol::sendMessage(ssl, resp);

        Utils::log(Utils::LogLevel::INFO, "ChatServer",
            "Login successful for: " + username);

		// Ghi log audit cho sự kiện login thành công
        Utils::auditLog("ChatServer", "LOGIN_SUCCESS", "username=" + username);
    }
    catch (std::exception& e) {
        Utils::log(Utils::LogLevel::ERR, "ChatServer",
            std::string("Exception: ") + e.what());
    }

    int sock = SSL_get_fd(ssl);
    Network::closeConnection(ssl, sock);
}

// ─── Xử lý chat ───────────────────────────────────────────
void handleChat(SSL* ssl, const std::string& username,
    const std::vector<unsigned char>& Kc_v) {
    Utils::log(Utils::LogLevel::INFO, "ChatServer",
        username + " entered chat mode");

    // Đăng ký online trước
    {
        std::lock_guard<std::mutex> lock(g_onlineMutex);
        g_onlineClients[username] = ssl;
    }

    // Gửi danh sách online hiện tại cho user mới vào
    {
        std::lock_guard<std::mutex> lock(g_onlineMutex);
        json userList = json::array();
        for (auto& [u, _] : g_onlineClients) {
            if (u != username) userList.push_back(u);
        }
        Message listMsg;
        listMsg.type = MessageType::ONLINE_USERS_LIST;
        listMsg.payload["users"] = userList;
        try { Protocol::sendMessage(ssl, listMsg); }
        catch (...) {}
    }

    // Broadcast USER_ONLINE đến tất cả (trừ bản thân)
    {
        std::lock_guard<std::mutex> lock(g_onlineMutex);
        Message onlineMsg;
        onlineMsg.type = MessageType::USER_ONLINE;
        onlineMsg.payload["user"] = username;

        for (auto& [u, uSSL] : g_onlineClients) {
            if (u != username) {
                try { Protocol::sendMessage(uSSL, onlineMsg); }
                catch (...) {}
            }
        }
    }

    try {
        while (true) {
            Message req = Protocol::recvMessage(ssl);

            // A xin public key cua B
            if (req.type == MessageType::SESSION_REQUEST) {
                std::string targetUser = req.payload["target"];
                Utils::log(Utils::LogLevel::INFO, "ChatServer",
                    username + " requests pubkey of " + targetUser);

                std::string pubKeyPEM = "";
                {
                    std::lock_guard<std::mutex> lock(g_accountMutex);
                    if (g_accounts.count(targetUser)) {
                        pubKeyPEM = g_accounts[targetUser].pubKeyPEM;
                    }
                }

                if (pubKeyPEM.empty()) {
                    Message err; err.type = MessageType::ERROR_MSG;
                    err.payload["reason"] = "User not found: " + targetUser;
                    Protocol::sendMessage(ssl, err);
                }
                else {
                    Message resp;
                    resp.type = MessageType::SESSION_RESPONSE;
                    resp.payload["target"] = targetUser;
                    resp.payload["public_key"] = pubKeyPEM;
                    Protocol::sendMessage(ssl, resp);
                    Utils::log(Utils::LogLevel::INFO, "ChatServer",
                        "Sent pubkey of " + targetUser + " to " + username);
                }
            }

            // A gửi KEY_EXCHANGE đến B (relay)
            else if (req.type == MessageType::KEY_EXCHANGE) {
                std::string targetUser = req.payload["target"];
                std::string encData = req.payload["data"];

                Utils::log(Utils::LogLevel::INFO, "ChatServer",
                    "KEY_EXCHANGE from [" + username + "] to [" + targetUser + "]");
                Utils::log(Utils::LogLevel::INFO, "ChatServer",
                    "K_AB is RSA-encrypted - server cannot read it: " + encData.substr(0, 32) + "...");

                std::lock_guard<std::mutex> lock(g_onlineMutex);
                if (g_onlineClients.count(targetUser)) {
                    req.payload["from"] = username;
                    Protocol::sendMessage(g_onlineClients[targetUser], req);
                    Utils::log(Utils::LogLevel::INFO, "ChatServer",
                        "KEY_EXCHANGE relayed to " + targetUser);

					// Ghi log audit cho sự kiện trao đổi khóa
                    Utils::auditLog("ChatServer", "KEY_EXCHANGE_RELAYED",
                        "from=" + username + " to=" + targetUser);
                }
                else {
                    Message err; err.type = MessageType::ERROR_MSG;
                    err.payload["reason"] = targetUser + " is not online";
                    Protocol::sendMessage(ssl, err);
                }
            }

            // B gửi KEY_ACK về A (relay)
            else if (req.type == MessageType::KEY_ACK) {
                std::string targetUser = req.payload["target"];
                Utils::log(Utils::LogLevel::INFO, "ChatServer",
                    "Relaying KEY_ACK from " + username + " to " + targetUser);

                std::lock_guard<std::mutex> lock(g_onlineMutex);
                if (g_onlineClients.count(targetUser)) {
                    req.payload["from"] = username;
                    Protocol::sendMessage(g_onlineClients[targetUser], req);
                }
            }

            // Chat message (relay, server khong doc duoc)
            else if (req.type == MessageType::CHAT_MESSAGE) {
                std::string targetUser = req.payload["target"];
                std::string encData = req.payload["data"]; // ciphertext, server khong doc duoc

                Utils::log(Utils::LogLevel::INFO, "ChatServer",
                    "Relaying message from [" + username + "] to [" + targetUser + "]");
                Utils::log(Utils::LogLevel::INFO, "ChatServer",
                    "Encrypted payload (server cannot read): " + encData.substr(0, 32) + "...");

                std::lock_guard<std::mutex> lock(g_onlineMutex);
                if (g_onlineClients.count(targetUser)) {
                    req.payload["from"] = username;
                    Protocol::sendMessage(g_onlineClients[targetUser], req);
                    Utils::log(Utils::LogLevel::INFO, "ChatServer",
                        "Message relayed successfully");
                }
                else {
                    Message err; err.type = MessageType::ERROR_MSG;
                    err.payload["reason"] = targetUser + " is not online";
                    Protocol::sendMessage(ssl, err);
                    Utils::log(Utils::LogLevel::WARN, "ChatServer",
                        targetUser + " is not online");
                }
            }

			// Client xin danh sách online users
            else if (req.type == MessageType::GET_ONLINE_USERS) {
                std::lock_guard<std::mutex> lock(g_onlineMutex);
                json userList = json::array();
                for (auto& [u, _] : g_onlineClients) {
                    if (u != username) userList.push_back(u);
                }
                Message resp;
                resp.type = MessageType::ONLINE_USERS_LIST;
                resp.payload["users"] = userList;
                try { Protocol::sendMessage(ssl, resp); }
                catch (...) {}
            }

			// Client báo offline — relay đến peer nếu đang chat
            else if (req.type == MessageType::ERROR_MSG) {
                // Client báo kết thúc session — relay đến peer
                std::string targetUser = req.payload.value("target", "");
                std::string reason = req.payload.value("reason", "");
                if (reason == "session_ended" && !targetUser.empty()) {
                    std::lock_guard<std::mutex> lock(g_onlineMutex);
                    if (g_onlineClients.count(targetUser)) {
                        req.payload["from"] = username;
                        Protocol::sendMessage(g_onlineClients[targetUser], req);
                    }
                }
            }   

            else {
                Utils::log(Utils::LogLevel::WARN, "ChatServer",
                    "Unknown message type in chat mode");
                break;
            }
        }
    }
    catch (std::exception& e) {
        Utils::log(Utils::LogLevel::INFO, "ChatServer",
            username + " disconnected: " + e.what());
    }

    // Xóa khỏi online list
    // Notify đối phương nếu đang chat
    // Tìm xem username này đang chat với ai
    // bằng cách broadcast USER_OFFLINE đến tất cả online clients
    {
        std::lock_guard<std::mutex> lock(g_onlineMutex);

        // Gửi USER_OFFLINE đến tất cả client còn online
        // Họ sẽ tự biết mình có liên quan không
        Message offlineMsg;
        offlineMsg.type = MessageType::USER_OFFLINE;
        offlineMsg.payload["user"] = username;
        offlineMsg.payload["reason"] = "User disconnected";

        for (auto& [onlineUser, onlineSSL] : g_onlineClients) {
            if (onlineUser != username) {
                try {
                    Protocol::sendMessage(onlineSSL, offlineMsg);
                }
                catch (...) {
                    // Nếu gửi thất bại thì bỏ qua
                }
            }
        }

        g_onlineClients.erase(username);
    }
    Utils::log(Utils::LogLevel::INFO, "ChatServer",
        username + " went offline - notified online clients");

	// Ghi log audit cho sự kiện user offline
    Utils::auditLog("ChatServer", "USER_OFFLINE", "username=" + username);
}

// ─── Xử lý 1 client ───────────────────────────────────────────
void handleClient(SSL* ssl) {
    try {
        Message req = Protocol::recvMessage(ssl);

        if (req.type == MessageType::REGISTER_CERT) {
            // Đăng ký account - xử lý như cũ
            std::string username = req.payload["username"];
            std::string certPEM = req.payload["cert"];
            int64_t     timestamp = req.payload["timestamp"];

            Utils::log(Utils::LogLevel::INFO, "ChatServer",
                "REGISTER_CERT from: " + username);

            if (Utils::isExpired(timestamp)) {
                Message err; err.type = MessageType::ERROR_MSG;
                err.payload["reason"] = "Timestamp expired";
                Protocol::sendMessage(ssl, err);
                goto cleanup;
            }

            int serial = 0;
            if (!verifyCertWithCA(certPEM, serial)) {
                Message err; err.type = MessageType::ERROR_MSG;
                err.payload["reason"] = "Certificate invalid or revoked";
                Protocol::sendMessage(ssl, err);

                Utils::auditLog("ChatServer", "LOGIN_REJECTED_REVOKED_CERT", "username=" + username);

                goto cleanup;
            }
            Utils::log(Utils::LogLevel::INFO, "ChatServer",
                "Cert verified for: " + username + " serial=" + std::to_string(serial));

            auto nonce = Crypto::generateNonce(32);
            std::string nonceB64 = Utils::base64Encode(nonce);
            Message challenge;
            challenge.type = MessageType::CHALLENGE;
            challenge.payload["nonce"] = nonceB64;
            Protocol::sendMessage(ssl, challenge);

            Message popResp = Protocol::recvMessage(ssl);
            if (popResp.type != MessageType::CERT_RESPONSE) goto cleanup;

            std::string sigB64 = popResp.payload["signature"];
            std::string clientNonce = popResp.payload["nonce"];

			// --- Thêm nonce check để chống replay attack ---
			// So sánh nonce nhận được với nonce đã gửi
            if (clientNonce != nonceB64) {
                Utils::log(Utils::LogLevel::WARN, "ChatServer", "Nonce mismatch: Challenge failed");
                Message err; err.type = MessageType::ERROR_MSG;
                err.payload["reason"] = "Nonce mismatch";
                Protocol::sendMessage(ssl, err);
                goto cleanup;
            }

            {
                std::lock_guard<std::mutex> lock(g_nonceMutex);

                // Safely get up to 16 characters for logging
                std::string safeNonceLog = nonceB64.substr(0, std::min<size_t>(16, nonceB64.length()));

                if (g_usedNonces.count(nonceB64)) {
                    Utils::log(Utils::LogLevel::WARN, "ChatServer",
                        "REPLAY ATTACK DETECTED - nonce already used: " + safeNonceLog + "...");
                    Utils::log(Utils::LogLevel::WARN, "ChatServer",
                        "Request from potential attacker blocked");

                    Message err; err.type = MessageType::ERROR_MSG;
                    err.payload["reason"] = "Replay attack detected";
                    Protocol::sendMessage(ssl, err);
                    goto cleanup;
                }

                g_usedNonces.insert(nonceB64);
                Utils::log(Utils::LogLevel::INFO, "ChatServer",
                    "Nonce accepted and recorded: " + safeNonceLog + "...");
            }

            std::string pubKeyPEM = extractPublicKey(certPEM);
            auto sig = Utils::base64Decode(sigB64);
            auto nonceBytes = Utils::base64Decode(nonceB64);
            if (!Crypto::verifySignature(pubKeyPEM, nonceBytes, sig)) {
                Message err; err.type = MessageType::ERROR_MSG;
                err.payload["reason"] = "Proof of Possession failed";
                Protocol::sendMessage(ssl, err);
                goto cleanup;
            }

            {
                std::lock_guard<std::mutex> lock(g_accountMutex);
                Account acc;
                acc.username = username;
                acc.certPEM = certPEM;
                acc.pubKeyPEM = pubKeyPEM;
                g_accounts[username] = acc;
            }
            // Gọi saveChatDB() NGOÀI block của lock để tránh deadlock
            saveChatDB();
            // -----------------------

            Utils::log(Utils::LogLevel::INFO, "ChatServer",
                "Account created for: " + username);

			// Ghi log audit cho CA về việc đăng ký account mới
            Utils::auditLog("ChatServer", "ACCOUNT_REGISTERED", "username=" + username);

            Message success;
            success.type = MessageType::SUCCESS;
            success.payload["message"] = "Account registered successfully";
            Protocol::sendMessage(ssl, success);
        }

        else if (req.type == MessageType::CLIENT_AUTH) {
            // Route sang login handler
            // Re-inject message vào handleLogin
            // Xử lý trực tiếp ở đây để tránh mất message
            std::string username = req.payload["username"];
            std::string ticket_v_b64 = req.payload["ticket_v"];
            std::string auth_b64 = req.payload["authenticator"];
            std::string iv_tv_b64 = req.payload["iv_tv"];
            std::string iv_auth_b64 = req.payload["iv_auth"];

            Utils::log(Utils::LogLevel::INFO, "ChatServer",
                "CLIENT_AUTH from: " + username);

            auto ticket_enc = Utils::base64Decode(ticket_v_b64);
            auto iv_tv = Utils::base64Decode(iv_tv_b64);
            auto ticketBytes = Crypto::aesDecrypt(g_Kv, iv_tv, ticket_enc);
            std::string ticketStr(ticketBytes.begin(), ticketBytes.end());
            json ticketJson = json::parse(ticketStr);

            std::string ticketUser = ticketJson["username"];
            int64_t     ticketTs = ticketJson["timestamp"];
            int64_t     lifetime = ticketJson["lifetime"];
            auto Kc_v = Utils::base64Decode(ticketJson["Kc_v"].get<std::string>());

            if (ticketUser != username || Utils::isExpired(ticketTs, (int)lifetime)) {
                Message err; err.type = MessageType::ERROR_MSG;
                err.payload["reason"] = "Ticket invalid or expired";
                Protocol::sendMessage(ssl, err);
                goto cleanup;
            }

            auto auth_enc = Utils::base64Decode(auth_b64);
            auto iv_auth = Utils::base64Decode(iv_auth_b64);
            auto authBytes = Crypto::aesDecrypt(Kc_v, iv_auth, auth_enc);
            std::string authStr(authBytes.begin(), authBytes.end());
            json authJson = json::parse(authStr);

            int64_t authTs = authJson["timestamp"];
            if (Utils::isExpired(authTs, 300)) {
                Message err; err.type = MessageType::ERROR_MSG;
                err.payload["reason"] = "Authenticator expired";
                Protocol::sendMessage(ssl, err);
                goto cleanup;
            }

            // ── Check duplicate login ──────────────────────────────
            {
                std::lock_guard<std::mutex> lock(g_onlineMutex);
                if (g_onlineClients.count(username)) {
                    Utils::log(Utils::LogLevel::WARN, "ChatServer",
                        "Duplicate login attempt for: " + username);
                    Message err;
                    err.type = MessageType::ERROR_MSG;
                    err.payload["reason"] = "already_logged_in";
                    Protocol::sendMessage(ssl, err);
                    goto cleanup;
                }
            }

            {
                std::lock_guard<std::mutex> lock(g_loginMutex);
                LoginSession ls;
                ls.username = username;
                ls.Kc_v = Kc_v;
                ls.timestamp = Utils::getTimestamp();
                g_loginSessions[username] = ls;
            }

            auto iv_resp = Crypto::generateNonce(16);
            json respPayload;
            respPayload["timestamp"] = authTs + 1;
            respPayload["username"] = username;
            std::string respStr = respPayload.dump();
            std::vector<unsigned char> respBytes(respStr.begin(), respStr.end());
            auto encResp = Crypto::aesEncrypt(Kc_v, iv_resp, respBytes);

            Message resp;
            resp.type = MessageType::SERVER_AUTH;
            resp.payload["enc_response"] = Utils::base64Encode(encResp);
            resp.payload["iv_resp"] = Utils::base64Encode(iv_resp);
            Protocol::sendMessage(ssl, resp);

            Utils::log(Utils::LogLevel::INFO, "ChatServer",
                "Login successful for: " + username);

			// Ghi log audit cho sự kiện login thành công
            Utils::auditLog("ChatServer", "LOGIN_SUCCESS", "username=" + username);

            handleChat(ssl, username, Kc_v);

            {
                int sock = SSL_get_fd(ssl);
                Network::closeConnection(ssl, sock);
            }
            return; // return truoc khi xuong cleanup
        }

    cleanup:;
    }
    catch (std::exception& e) {
        Utils::log(Utils::LogLevel::ERR, "ChatServer",
            std::string("Exception: ") + e.what());
    }

    int sock = SSL_get_fd(ssl);
    Network::closeConnection(ssl, sock);
}

bool initChatServer() {
    Config::ensureCertDir();

    // Thu load neu da co san
    std::string certPEM = Utils::loadPEM(Config::CHAT_CERT());
    std::string keyPEM = Utils::loadPEM(Config::CHAT_KEY());

    if (certPEM.empty() || keyPEM.empty()) {
        // Download CA cert neu chua co
        std::string caCertPEM = Utils::loadPEM(Config::CA_CERT());
        if (caCertPEM.empty()) {
            Utils::log(Utils::LogLevel::INFO, "ChatServer", "Downloading CA cert...");
            SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
            SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);
            SSL* ssl = Network::connectToServer(ctx, "127.0.0.1", Config::PORT_CA);
            if (!ssl) {
                Utils::log(Utils::LogLevel::ERR, "ChatServer", "Cannot connect to CA - start CA first!");
                SSL_CTX_free(ctx);
                return false;
            }
            Message req; req.type = MessageType::GET_CA_CERT;
            Protocol::sendMessage(ssl, req);
            Message resp = Protocol::recvMessage(ssl);
            if (resp.type == MessageType::CERT_RESPONSE) {
                caCertPEM = resp.payload["cert"];
                Utils::savePEM(Config::CA_CERT(), caCertPEM);
                Utils::log(Utils::LogLevel::INFO, "ChatServer", "CA cert downloaded");
            }
            int s = SSL_get_fd(ssl);
            Network::closeConnection(ssl, s);
            SSL_CTX_free(ctx);
        }

        // Xin CA ky cert cho Chat Server
        Utils::log(Utils::LogLevel::INFO, "ChatServer", "Requesting cert from CA...");
        bool ok = Crypto::requestCertFromCA(
            "SecureChat-ChatServer", 365,
            "127.0.0.1", Config::PORT_CA,
            caCertPEM,
            certPEM, keyPEM
        );
        if (!ok) {
            Utils::log(Utils::LogLevel::ERR, "ChatServer", "Failed to get cert from CA");
            return false;
        }

        Utils::savePEM(Config::CHAT_CERT(), certPEM);
        Utils::savePEM(Config::CHAT_KEY(), keyPEM);
        Utils::log(Utils::LogLevel::INFO, "ChatServer", "Chat Server cert saved");
    }
    else {
        Utils::log(Utils::LogLevel::INFO, "ChatServer", "Loaded existing Chat Server cert");
    }

    // Giu nguyen phan sinh Kv
    std::vector<unsigned char> kvBytes(
        Config::KV_SECRET().begin(), Config::KV_SECRET().end());
    g_Kv = Crypto::sha256(kvBytes);

    loadChatDB();
    Utils::log(Utils::LogLevel::INFO, "ChatServer", "Chat Server ready");
    return true;
}

// ─── Main ─────────────────────────────────────────────────────
int main() {
    Utils::initAuditLog(Config::AUDIT_LOG_DIR());

    Utils::log(Utils::LogLevel::INFO, "ChatServer",
        "Starting Chat Server on port " +
        std::to_string(Config::PORT_CHAT) + "...");

    if (!initChatServer()) {
        Utils::log(Utils::LogLevel::ERR, "ChatServer", "Init failed");
        return 1;
    }

    SSL_CTX* ctx = Network::createServerContext(
        Config::CHAT_CERT(), Config::CHAT_KEY());
    if (!ctx) return 1;

    int serverSock = Network::createServerSocket(Config::PORT_CHAT);
    if (serverSock < 0) return 1;

    Utils::log(Utils::LogLevel::INFO, "ChatServer",
        "Chat Server ready. Waiting for connections...");

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