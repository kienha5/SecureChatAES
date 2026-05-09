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

// ─── Principal DB ─────────────────────────────────────────────
struct Principal {
    std::string username;
    std::vector<unsigned char> Kc;  // Hash(client_hash)
    std::string pubKeyPEM;
};

// ─── Session Key DB (TGT tracking) ────────────────────────────
struct TGTSession {
    std::string username;
    std::vector<unsigned char> Kc_tgs;  // session key Client↔TGS
    int64_t timestamp;
    int64_t lifetime;
};

static std::map<std::string, Principal>  g_principals;
static std::map<std::string, TGTSession> g_tgtSessions; // nonce → session
static std::mutex g_principalMutex;
static std::mutex g_sessionMutex;
static std::set<std::string> g_usedNonces;
static std::mutex g_nonceMutex;

// ─── KDC master key (Ktgs) ────────────────────────────────────
// Dùng để mã hóa Ticket_tgs
static std::vector<unsigned char> g_Ktgs;
static std::vector<unsigned char> g_Kv;   // Chat Server key

// ─── Lấy public key từ cert PEM ──────────────────────────────
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

// ─── Verify cert với CA ───────────────────────────────────────
bool verifyCertWithCA(const std::string& certPEM) {
    BIO* bio = BIO_new_mem_buf(certPEM.data(), (int)certPEM.size());
    X509* cert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (!cert) return false;

    int serial = (int)ASN1_INTEGER_get(X509_get_serialNumber(cert));
    X509_free(cert);

    SSL_CTX* ctx = Network::createClientContext("C:\\SecureChatCerts\\ca.crt");
    if (!ctx) return false;

    SSL* ssl = Network::connectToServer(ctx, "127.0.0.1", 5000);
    if (!ssl) { Network::freeContext(ctx); return false; }

    Message req;
    req.type = MessageType::VERIFY_CERT;
    req.payload["serial"] = serial;
    Protocol::sendMessage(ssl, req);

    Message resp = Protocol::recvMessage(ssl);
    bool valid = (resp.type == MessageType::CERT_STATUS &&
        resp.payload["status"] == "VALID");

    int sock = SSL_get_fd(ssl);
    Network::closeConnection(ssl, sock);
    Network::freeContext(ctx);
    return valid;
}

// ─── Xử lý đăng ký KDC ───────────────────────────────────────
void handleRegister(SSL* ssl) {
    // Bước 1: Nhận REGISTER_INIT
    Message init = Protocol::recvMessage(ssl);
    if (init.type != MessageType::KDC_REGISTER_INIT) {
        Utils::log(Utils::LogLevel::ERR, "KDC", "Expected KDC_REGISTER_INIT");
        return;
    }

    std::string username = init.payload["username"];
    std::string certPEM = init.payload["cert"];
    Utils::log(Utils::LogLevel::INFO, "KDC", "REGISTER_INIT from: " + username);

    // Bước 2: Verify cert với CA
    if (!verifyCertWithCA(certPEM)) {
        Utils::log(Utils::LogLevel::WARN, "KDC", "Cert invalid for: " + username);
        Message err; err.type = MessageType::ERROR_MSG;
        err.payload["reason"] = "Certificate invalid";
        Protocol::sendMessage(ssl, err);
        return;
    }
    Utils::log(Utils::LogLevel::INFO, "KDC", "Cert verified OK for: " + username);

    // Bước 3: Gửi challenge nonce
    auto nonce = Crypto::generateNonce(32);
    std::string nonceB64 = Utils::base64Encode(nonce);

    Message challenge;
    challenge.type = MessageType::CHALLENGE;
    challenge.payload["nonce"] = nonceB64;
    Protocol::sendMessage(ssl, challenge);
    Utils::log(Utils::LogLevel::INFO, "KDC", "Sent challenge to: " + username);

    // Bước 4: Nhận KDC_REGISTER (password hash + signature)
    Message reg = Protocol::recvMessage(ssl);
    if (reg.type != MessageType::KDC_REGISTER) {
        Utils::log(Utils::LogLevel::ERR, "KDC", "Expected KDC_REGISTER");
        return;
    }

    std::string clientHashB64 = reg.payload["client_hash"];
    std::string sigB64 = reg.payload["signature"];
    std::string clientNonce = reg.payload["nonce"];

    // Bước 5: Verify nonce + replay
    if (clientNonce != nonceB64) {
        Utils::log(Utils::LogLevel::WARN, "KDC", "Nonce mismatch");
        return;
    }
    {
        std::lock_guard<std::mutex> lock(g_nonceMutex);
        if (g_usedNonces.count(nonceB64)) {
            Utils::log(Utils::LogLevel::WARN, "KDC", "Replay detected");
            return;
        }
        g_usedNonces.insert(nonceB64);
    }

    // Bước 6: Verify signature
    std::string pubKeyPEM = extractPublicKey(certPEM);
    auto sig = Utils::base64Decode(sigB64);
    auto nonceBytes = Utils::base64Decode(nonceB64);
    if (!Crypto::verifySignature(pubKeyPEM, nonceBytes, sig)) {
        Utils::log(Utils::LogLevel::WARN, "KDC", "Signature failed for: " + username);
        Message err; err.type = MessageType::ERROR_MSG;
        err.payload["reason"] = "Invalid signature";
        Protocol::sendMessage(ssl, err);
        return;
    }
    Utils::log(Utils::LogLevel::INFO, "KDC", "Signature OK for: " + username);

    // Bước 7: Tạo Kc = Hash(client_hash)
    auto clientHashBytes = Utils::base64Decode(clientHashB64);
    auto Kc = Crypto::sha256(clientHashBytes);

    // Bước 8: Lưu principal
    {
        std::lock_guard<std::mutex> lock(g_principalMutex);
        Principal p;
        p.username = username;
        p.Kc = Kc;
        p.pubKeyPEM = pubKeyPEM;
        g_principals[username] = p;
    }
    Utils::log(Utils::LogLevel::INFO, "KDC", "Principal created for: " + username);

    // Bước 9: Trả success
    Message success;
    success.type = MessageType::KDC_REGISTER_SUCCESS;
    success.payload["message"] = "KDC registration successful";
    Protocol::sendMessage(ssl, success);
}

// ─── Xử lý AS Request (xin TGT) ──────────────────────────────
void handleAS(SSL* ssl) {
    Message req = Protocol::recvMessage(ssl);
    if (req.type != MessageType::AS_REQUEST) {
        Utils::log(Utils::LogLevel::ERR, "KDC", "Expected AS_REQUEST");
        return;
    }

    std::string username = req.payload["username"];
    int64_t     ts = req.payload["timestamp"];
    Utils::log(Utils::LogLevel::INFO, "KDC", "AS_REQUEST from: " + username);

    // Check timestamp
    if (Utils::isExpired(ts)) {
        Message err; err.type = MessageType::ERROR_MSG;
        err.payload["reason"] = "Timestamp expired";
        Protocol::sendMessage(ssl, err);
        return;
    }

    // Lấy principal
    Principal p;
    {
        std::lock_guard<std::mutex> lock(g_principalMutex);
        if (!g_principals.count(username)) {
            Utils::log(Utils::LogLevel::WARN, "KDC", "Unknown principal: " + username);
            Message err; err.type = MessageType::ERROR_MSG;
            err.payload["reason"] = "Unknown user";
            Protocol::sendMessage(ssl, err);
            return;
        }
        p = g_principals[username];
    }

    // Sinh Kc,tgs (session key)
    auto Kc_tgs = Crypto::generateNonce(32);
    auto iv_tgt = Crypto::generateNonce(16);
    int64_t ts2 = Utils::getTimestamp();
    int64_t lifetime = 3600; // 1 giờ

    // Tạo Ticket_tgs payload
    json ticketPayload;
    ticketPayload["Kc_tgs"] = Utils::base64Encode(Kc_tgs);
    ticketPayload["username"] = username;
    ticketPayload["timestamp"] = ts2;
    ticketPayload["lifetime"] = lifetime;
    std::string ticketStr = ticketPayload.dump();
    std::vector<unsigned char> ticketBytes(ticketStr.begin(), ticketStr.end());

    // Mã hóa Ticket_tgs bằng Ktgs
    auto ticket_tgs_enc = Crypto::aesEncrypt(g_Ktgs, iv_tgt, ticketBytes);

    // Tạo response payload cho client, mã hóa bằng Kc
    auto iv_resp = Crypto::generateNonce(16);
    json respPayload;
    respPayload["Kc_tgs"] = Utils::base64Encode(Kc_tgs);
    respPayload["timestamp"] = ts2;
    respPayload["lifetime"] = lifetime;
    respPayload["ticket_tgs"] = Utils::base64Encode(ticket_tgs_enc);
    respPayload["iv_tgt"] = Utils::base64Encode(iv_tgt);
    std::string respStr = respPayload.dump();
    std::vector<unsigned char> respBytes(respStr.begin(), respStr.end());

    // Mã hóa bằng Kc
    auto encResp = Crypto::aesEncrypt(p.Kc, iv_resp, respBytes);

    Message resp;
    resp.type = MessageType::AS_RESPONSE;
    resp.payload["enc_response"] = Utils::base64Encode(encResp);
    resp.payload["iv_resp"] = Utils::base64Encode(iv_resp);
    Protocol::sendMessage(ssl, resp);

    Utils::log(Utils::LogLevel::INFO, "KDC",
        "TGT issued for: " + username);
}

// ─── Xử lý TGS Request (xin Service Ticket) ──────────────────
void handleTGS(SSL* ssl) {
    Message req = Protocol::recvMessage(ssl);
    if (req.type != MessageType::TGS_REQUEST) {
        Utils::log(Utils::LogLevel::ERR, "KDC", "Expected TGS_REQUEST");
        return;
    }

    std::string username = req.payload["username"];
    std::string ticket_tgs_b64 = req.payload["ticket_tgs"];
    std::string auth_b64 = req.payload["authenticator"];
    std::string iv_tgt_b64 = req.payload["iv_tgt"];
    std::string iv_auth_b64 = req.payload["iv_auth"];
    Utils::log(Utils::LogLevel::INFO, "KDC", "TGS_REQUEST from: " + username);

    // Giải mã Ticket_tgs bằng Ktgs
    auto ticket_enc = Utils::base64Decode(ticket_tgs_b64);
    auto iv_tgt = Utils::base64Decode(iv_tgt_b64);
    auto ticketBytes = Crypto::aesDecrypt(g_Ktgs, iv_tgt, ticket_enc);
    std::string ticketStr(ticketBytes.begin(), ticketBytes.end());

    json ticketJson = json::parse(ticketStr);
    std::string Kc_tgs_b64 = ticketJson["Kc_tgs"];
    std::string ticketUser = ticketJson["username"];
    int64_t     ticketTs = ticketJson["timestamp"];
    int64_t     lifetime = ticketJson["lifetime"];
    auto Kc_tgs = Utils::base64Decode(Kc_tgs_b64);

    // Verify ticket chưa hết hạn
    if (Utils::isExpired(ticketTs, (int)lifetime)) {
        Utils::log(Utils::LogLevel::WARN, "KDC", "TGT expired for: " + username);
        Message err; err.type = MessageType::ERROR_MSG;
        err.payload["reason"] = "TGT expired";
        Protocol::sendMessage(ssl, err);
        return;
    }

    // Giải mã Authenticator bằng Kc_tgs
    auto auth_enc = Utils::base64Decode(auth_b64);
    auto iv_auth = Utils::base64Decode(iv_auth_b64);
    auto authBytes = Crypto::aesDecrypt(Kc_tgs, iv_auth, auth_enc);
    std::string authStr(authBytes.begin(), authBytes.end());

    json authJson = json::parse(authStr);
    std::string authUser = authJson["username"];
    int64_t     authTs = authJson["timestamp"];

    // Verify authenticator
    if (authUser != ticketUser || authUser != username) {
        Utils::log(Utils::LogLevel::WARN, "KDC", "Authenticator username mismatch");
        Message err; err.type = MessageType::ERROR_MSG;
        err.payload["reason"] = "Authenticator mismatch";
        Protocol::sendMessage(ssl, err);
        return;
    }
    if (Utils::isExpired(authTs, 300)) {
        Utils::log(Utils::LogLevel::WARN, "KDC", "Authenticator timestamp expired");
        Message err; err.type = MessageType::ERROR_MSG;
        err.payload["reason"] = "Authenticator expired";
        Protocol::sendMessage(ssl, err);
        return;
    }

    // Sinh Kc,v (session key Client↔ChatServer)
    auto Kc_v = Crypto::generateNonce(32);
    auto iv_tv = Crypto::generateNonce(16);
    int64_t ts4 = Utils::getTimestamp();
    int64_t lt4 = 3600;

    // Tạo Ticket_v mã hóa bằng Kv
    json tvPayload;
    tvPayload["Kc_v"] = Utils::base64Encode(Kc_v);
    tvPayload["username"] = username;
    tvPayload["timestamp"] = ts4;
    tvPayload["lifetime"] = lt4;
    std::string tvStr = tvPayload.dump();
    std::vector<unsigned char> tvBytes(tvStr.begin(), tvStr.end());
    auto ticket_v_enc = Crypto::aesEncrypt(g_Kv, iv_tv, tvBytes);

    // Mã hóa response bằng Kc_tgs
    auto iv_resp = Crypto::generateNonce(16);
    json respPayload;
    respPayload["Kc_v"] = Utils::base64Encode(Kc_v);
    respPayload["timestamp"] = ts4;
    respPayload["ticket_v"] = Utils::base64Encode(ticket_v_enc);
    respPayload["iv_tv"] = Utils::base64Encode(iv_tv);
    std::string respStr = respPayload.dump();
    std::vector<unsigned char> respBytes(respStr.begin(), respStr.end());
    auto encResp = Crypto::aesEncrypt(Kc_tgs, iv_resp, respBytes);

    Message resp;
    resp.type = MessageType::TGS_RESPONSE;
    resp.payload["enc_response"] = Utils::base64Encode(encResp);
    resp.payload["iv_resp"] = Utils::base64Encode(iv_resp);
    Protocol::sendMessage(ssl, resp);

    Utils::log(Utils::LogLevel::INFO, "KDC",
        "Service ticket issued for: " + username);
}

// ─── Router: phân biệt loại request ──────────────────────────
void handleClient(SSL* ssl) {
    try {
        // Peek message type để route đúng handler
        Message peek = Protocol::recvMessage(ssl);

        if (peek.type == MessageType::KDC_REGISTER_INIT) {
            // Push back bằng cách xử lý trực tiếp
            std::string username = peek.payload["username"];
            std::string certPEM = peek.payload["cert"];
            Utils::log(Utils::LogLevel::INFO, "KDC",
                "Routing to REGISTER handler for: " + username);

            // Verify cert
            if (!verifyCertWithCA(certPEM)) {
                Message err; err.type = MessageType::ERROR_MSG;
                err.payload["reason"] = "Certificate invalid";
                Protocol::sendMessage(ssl, err);
                goto cleanup;
            }

            // Gửi challenge
            auto nonce = Crypto::generateNonce(32);
            std::string nonceB64 = Utils::base64Encode(nonce);
            Message challenge;
            challenge.type = MessageType::CHALLENGE;
            challenge.payload["nonce"] = nonceB64;
            Protocol::sendMessage(ssl, challenge);

            // Nhận KDC_REGISTER
            Message reg = Protocol::recvMessage(ssl);
            if (reg.type != MessageType::KDC_REGISTER) goto cleanup;

            std::string clientHashB64 = reg.payload["client_hash"];
            std::string sigB64 = reg.payload["signature"];
            std::string clientNonce = reg.payload["nonce"];

            if (clientNonce != nonceB64) goto cleanup;
            {
                std::lock_guard<std::mutex> lock(g_nonceMutex);
                if (g_usedNonces.count(nonceB64)) goto cleanup;
                g_usedNonces.insert(nonceB64);
            }

            std::string pubKeyPEM = extractPublicKey(certPEM);
            auto sig = Utils::base64Decode(sigB64);
            auto nonceBytes = Utils::base64Decode(nonceB64);
            if (!Crypto::verifySignature(pubKeyPEM, nonceBytes, sig)) {
                Message err; err.type = MessageType::ERROR_MSG;
                err.payload["reason"] = "Invalid signature";
                Protocol::sendMessage(ssl, err);
                goto cleanup;
            }

            auto clientHashBytes = Utils::base64Decode(clientHashB64);
            auto Kc = Crypto::sha256(clientHashBytes);

            {
                std::lock_guard<std::mutex> lock(g_principalMutex);
                Principal p;
                p.username = username;
                p.Kc = Kc;
                p.pubKeyPEM = pubKeyPEM;
                g_principals[username] = p;
            }
            Utils::log(Utils::LogLevel::INFO, "KDC",
                "Principal created for: " + username);

            Message success;
            success.type = MessageType::KDC_REGISTER_SUCCESS;
            success.payload["message"] = "KDC registration successful";
            Protocol::sendMessage(ssl, success);
        }
        else if (peek.type == MessageType::AS_REQUEST) {
            std::string username = peek.payload["username"];
            int64_t     ts = peek.payload["timestamp"];
            Utils::log(Utils::LogLevel::INFO, "KDC",
                "Routing to AS handler for: " + username);

            if (Utils::isExpired(ts)) {
                Message err; err.type = MessageType::ERROR_MSG;
                err.payload["reason"] = "Timestamp expired";
                Protocol::sendMessage(ssl, err);
                goto cleanup;
            }

            Principal p;
            {
                std::lock_guard<std::mutex> lock(g_principalMutex);
                if (!g_principals.count(username)) {
                    Message err; err.type = MessageType::ERROR_MSG;
                    err.payload["reason"] = "Unknown user";
                    Protocol::sendMessage(ssl, err);
                    goto cleanup;
                }
                p = g_principals[username];
            }

            auto Kc_tgs = Crypto::generateNonce(32);
            auto iv_tgt = Crypto::generateNonce(16);
            int64_t ts2 = Utils::getTimestamp();
            int64_t lifetime = 3600;

            json ticketPayload;
            ticketPayload["Kc_tgs"] = Utils::base64Encode(Kc_tgs);
            ticketPayload["username"] = username;
            ticketPayload["timestamp"] = ts2;
            ticketPayload["lifetime"] = lifetime;
            std::string ticketStr = ticketPayload.dump();
            std::vector<unsigned char> ticketBytes(ticketStr.begin(), ticketStr.end());
            auto ticket_tgs_enc = Crypto::aesEncrypt(g_Ktgs, iv_tgt, ticketBytes);

            auto iv_resp = Crypto::generateNonce(16);
            json respPayload;
            respPayload["Kc_tgs"] = Utils::base64Encode(Kc_tgs);
            respPayload["timestamp"] = ts2;
            respPayload["lifetime"] = lifetime;
            respPayload["ticket_tgs"] = Utils::base64Encode(ticket_tgs_enc);
            respPayload["iv_tgt"] = Utils::base64Encode(iv_tgt);
            std::string respStr = respPayload.dump();
            std::vector<unsigned char> respBytes(respStr.begin(), respStr.end());
            auto encResp = Crypto::aesEncrypt(p.Kc, iv_resp, respBytes);

            Message resp;
            resp.type = MessageType::AS_RESPONSE;
            resp.payload["enc_response"] = Utils::base64Encode(encResp);
            resp.payload["iv_resp"] = Utils::base64Encode(iv_resp);
            Protocol::sendMessage(ssl, resp);
            Utils::log(Utils::LogLevel::INFO, "KDC", "TGT issued for: " + username);
        }
        else if (peek.type == MessageType::TGS_REQUEST) {
            std::string username = peek.payload["username"];
            std::string ticket_tgs_b64 = peek.payload["ticket_tgs"];
            std::string auth_b64 = peek.payload["authenticator"];
            std::string iv_tgt_b64 = peek.payload["iv_tgt"];
            std::string iv_auth_b64 = peek.payload["iv_auth"];
            Utils::log(Utils::LogLevel::INFO, "KDC",
                "Routing to TGS handler for: " + username);

            auto ticket_enc = Utils::base64Decode(ticket_tgs_b64);
            auto iv_tgt = Utils::base64Decode(iv_tgt_b64);
            auto ticketBytes = Crypto::aesDecrypt(g_Ktgs, iv_tgt, ticket_enc);
            std::string ticketStr(ticketBytes.begin(), ticketBytes.end());
            json ticketJson = json::parse(ticketStr);

            std::string Kc_tgs_b64 = ticketJson["Kc_tgs"];
            int64_t     ticketTs = ticketJson["timestamp"];
            int64_t     lt = ticketJson["lifetime"];
            auto Kc_tgs = Utils::base64Decode(Kc_tgs_b64);

            if (Utils::isExpired(ticketTs, (int)lt)) {
                Message err; err.type = MessageType::ERROR_MSG;
                err.payload["reason"] = "TGT expired";
                Protocol::sendMessage(ssl, err);
                goto cleanup;
            }

            auto auth_enc = Utils::base64Decode(auth_b64);
            auto iv_auth = Utils::base64Decode(iv_auth_b64);
            auto authBytes = Crypto::aesDecrypt(Kc_tgs, iv_auth, auth_enc);
            std::string authStr(authBytes.begin(), authBytes.end());
            json authJson = json::parse(authStr);
            int64_t authTs = authJson["timestamp"];

            if (Utils::isExpired(authTs, 300)) {
                Message err; err.type = MessageType::ERROR_MSG;
                err.payload["reason"] = "Authenticator expired";
                Protocol::sendMessage(ssl, err);
                goto cleanup;
            }

            auto Kc_v = Crypto::generateNonce(32);
            auto iv_tv = Crypto::generateNonce(16);
            int64_t ts4 = Utils::getTimestamp();

            json tvPayload;
            tvPayload["Kc_v"] = Utils::base64Encode(Kc_v);
            tvPayload["username"] = username;
            tvPayload["timestamp"] = ts4;
            tvPayload["lifetime"] = (int64_t)3600;
            std::string tvStr = tvPayload.dump();
            std::vector<unsigned char> tvBytes(tvStr.begin(), tvStr.end());
            auto ticket_v_enc = Crypto::aesEncrypt(g_Kv, iv_tv, tvBytes);

            auto iv_resp = Crypto::generateNonce(16);
            json respPayload;
            respPayload["Kc_v"] = Utils::base64Encode(Kc_v);
            respPayload["timestamp"] = ts4;
            respPayload["ticket_v"] = Utils::base64Encode(ticket_v_enc);
            respPayload["iv_tv"] = Utils::base64Encode(iv_tv);
            std::string respStr = respPayload.dump();
            std::vector<unsigned char> respBytes(respStr.begin(), respStr.end());
            auto encResp = Crypto::aesEncrypt(Kc_tgs, iv_resp, respBytes);

            Message resp;
            resp.type = MessageType::TGS_RESPONSE;
            resp.payload["enc_response"] = Utils::base64Encode(encResp);
            resp.payload["iv_resp"] = Utils::base64Encode(iv_resp);
            Protocol::sendMessage(ssl, resp);
            Utils::log(Utils::LogLevel::INFO, "KDC",
                "Service ticket issued for: " + username);
        }

    cleanup:;
    }
    catch (std::exception& e) {
        Utils::log(Utils::LogLevel::ERR, "KDC",
            std::string("Exception: ") + e.what());
    }

    int sock = SSL_get_fd(ssl);
    Network::closeConnection(ssl, sock);
}

// ─── Main ─────────────────────────────────────────────────────
int main() {
    Utils::log(Utils::LogLevel::INFO, "KDC", "Starting KDC Server on port 5003...");

    // Sinh Ktgs và Kv cố định (trong thực tế load từ file bảo mật)
    g_Ktgs = Crypto::sha256({ 'K','t','g','s','_','S','e','c','r','e','t' });
    g_Kv = Crypto::sha256({ 'K','v','_','S','e','c','r','e','t','_','C','h','a','t' });

    SSL_CTX* ctx = Network::createServerContext(
        "C:\\SecureChatCerts\\kdc.crt",
        "C:\\SecureChatCerts\\kdc.key"
    );
    if (!ctx) return 1;

    int serverSock = Network::createServerSocket(5003);
    if (serverSock < 0) return 1;

    Utils::log(Utils::LogLevel::INFO, "KDC", "KDC ready. Waiting for connections...");

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