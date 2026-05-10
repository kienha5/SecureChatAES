#define _CRT_SECURE_NO_WARNINGS
#define NOMINMAX

#include "../Common/pch.h"
#include "../Common/crypto.h"
#include "../Common/message.h"
#include "../Common/network.h"
#include "../Common/config.h"
#include "app_state.h"
#include "network_ops.h"
#include "network_thread.h"
#include <fstream>

// ─── E2EE handshake phía A (Start Session) ───────────────────
static bool doHandshakeAsA(const std::string& me,
    const std::string& target)
{
    auto logCb = [](const std::string& m, bool e) { addLog(m, e); };

    // Tuần tự y hệt CLI — không cần mutex vì chỉ 1 thread dùng SSL
    Message req;
    req.type = MessageType::SESSION_REQUEST;
    req.payload["target"] = target;
    Protocol::sendMessage(g_app.chatSSL, req);

    Message resp = Protocol::recvMessage(g_app.chatSSL);
    if (resp.type != MessageType::SESSION_RESPONSE) {
        logCb("Failed to get pubkey of " + target, true);
        return false;
    }

    std::string targetPubKey = resp.payload["public_key"];
    logCb("Got public key of " + target, false);

    auto K_AB = Crypto::generateNonce(32);
    auto nonce_A = Crypto::generateNonce(16);
    g_app.K_AB = K_AB;

    json kp;
    kp["K_AB"] = Utils::base64Encode(K_AB);
    kp["from"] = me;
    kp["nonce_A"] = Utils::base64Encode(nonce_A);
    std::string ks = kp.dump();
    std::vector<unsigned char> kb(ks.begin(), ks.end());
    auto encKex = Crypto::encryptRSA(targetPubKey, kb);

    Message kexMsg;
    kexMsg.type = MessageType::KEY_EXCHANGE;
    kexMsg.payload["target"] = target;
    kexMsg.payload["data"] = Utils::base64Encode(encKex);
    Protocol::sendMessage(g_app.chatSSL, kexMsg);
    logCb("Sent K_AB to " + target, false);

    Message ack = Protocol::recvMessage(g_app.chatSSL);
    if (ack.type != MessageType::KEY_ACK) {
        logCb("Expected KEY_ACK", true);
        return false;
    }

    auto ackEnc = Utils::base64Decode(ack.payload["data"]);
    auto iv_ack = Utils::base64Decode(ack.payload["iv"]);
    auto ackDec = Crypto::aesDecrypt(K_AB, iv_ack, ackEnc);
    json ackJson = json::parse(std::string(ackDec.begin(), ackDec.end()));

    if (ackJson["nonce_A"] != Utils::base64Encode(nonce_A)) {
        logCb("nonce_A mismatch!", true);
        return false;
    }

    std::string nonce_B = ackJson["nonce_B"];
    auto iv_conf = Crypto::generateNonce(16);
    json cp; cp["nonce_B"] = nonce_B;
    std::string cs = cp.dump();
    std::vector<unsigned char> cb2(cs.begin(), cs.end());
    auto encConf = Crypto::aesEncrypt(K_AB, iv_conf, cb2);

    Message conf;
    conf.type = MessageType::KEY_ACK;
    conf.payload["target"] = target;
    conf.payload["data"] = Utils::base64Encode(encConf);
    conf.payload["iv"] = Utils::base64Encode(iv_conf);
    Protocol::sendMessage(g_app.chatSSL, conf);

    logCb("E2EE established with " + target + "!", false);
    return true;
}

// ─── E2EE handshake phía B (Wait Session) ────────────────────
static bool doHandshakeAsB(const std::string& me)
{
    auto logCb = [](const std::string& m, bool e) { addLog(m, e); };
    logCb("Waiting for incoming session...", false);

    Message kexMsg = Protocol::recvMessage(g_app.chatSSL);
    if (kexMsg.type != MessageType::KEY_EXCHANGE) {
        logCb("Expected KEY_EXCHANGE, got: " +
            std::to_string((int)kexMsg.type), true);
        return false;
    }

    std::string fromUser = kexMsg.payload["from"];
    logCb("Incoming session from: " + fromUser, false);
    snprintf(g_app.targetUser, sizeof(g_app.targetUser),
        "%s", fromUser.c_str());

    // Load private key — kiểm tra ngay
    std::string privKey = loadFile(Config::userKey(me));
    if (privKey.empty()) {
        logCb("Private key not found for: " + me, true);
        return false;
    }
    logCb("Loaded private key for: " + me, false);

    // Kiểm tra data field tồn tại
    if (!kexMsg.payload.contains("data") ||
        kexMsg.payload["data"].get<std::string>().empty()) {
        logCb("KEY_EXCHANGE missing data field", true);
        return false;
    }

    // Decode base64
    auto encData = Utils::base64Decode(
        kexMsg.payload["data"].get<std::string>());
    if (encData.empty()) {
        logCb("base64Decode returned empty", true);
        return false;
    }

    // Decrypt RSA
    std::vector<unsigned char> decData;
    try {
        decData = Crypto::decryptRSA(privKey, encData);
    }
    catch (const std::exception& e) {
        logCb("RSA decrypt exception: " + std::string(e.what()), true);
        return false;
    }

    // Debug log
    logCb("decryptRSA result size: " + std::to_string(decData.size()), false);

    if (decData.empty()) {
        logCb("RSA decrypt returned empty — wrong key?", true);
        return false;
    }

    // Validate JSON
    std::string decStr(decData.begin(), decData.end());
    logCb("Decrypted first 32 chars: " +
        decStr.substr(0, std::min((size_t)32, decStr.size())), false);

    if (decStr[0] != '{') {
        logCb("Decrypted data is not valid JSON", true);
        return false;
    }

    // Parse JSON
    json kj;
    try {
        kj = json::parse(decStr);
    }
    catch (const std::exception& e) {
        logCb("JSON parse failed: " + std::string(e.what()), true);
        return false;
    }

    // Validate fields
    if (!kj.contains("K_AB") || !kj.contains("nonce_A") || !kj.contains("from")) {
        logCb("Missing fields in decrypted payload", true);
        return false;
    }

    auto K_AB = Utils::base64Decode(kj["K_AB"].get<std::string>());
    if (K_AB.size() != 32) {
        logCb("K_AB size invalid: " + std::to_string(K_AB.size()), true);
        return false;
    }

    std::string nonce_A = kj["nonce_A"];
    g_app.K_AB = K_AB;
    logCb("K_AB decrypted OK!", false);

    // Gửi KEY_ACK
    auto nonce_B = Crypto::generateNonce(16);
    auto iv_ack = Crypto::generateNonce(16);
    json ap;
    ap["nonce_A"] = nonce_A;
    ap["nonce_B"] = Utils::base64Encode(nonce_B);
    std::string as2 = ap.dump();
    std::vector<unsigned char> ab2(as2.begin(), as2.end());
    auto encAck = Crypto::aesEncrypt(K_AB, iv_ack, ab2);

    Message ack;
    ack.type = MessageType::KEY_ACK;
    ack.payload["target"] = fromUser;
    ack.payload["data"] = Utils::base64Encode(encAck);
    ack.payload["iv"] = Utils::base64Encode(iv_ack);
    Protocol::sendMessage(g_app.chatSSL, ack);
    logCb("Sent KEY_ACK to " + fromUser, false);

    // Nhận xác nhận nonce_B
    Message conf = Protocol::recvMessage(g_app.chatSSL);

    std::vector<unsigned char> cd;
    try {
        auto ce = Utils::base64Decode(conf.payload["data"].get<std::string>());
        auto ci = Utils::base64Decode(conf.payload["iv"].get<std::string>());
        cd = Crypto::aesDecrypt(K_AB, ci, ce);
    }
    catch (const std::exception& e) {
        logCb("nonce_B confirm decrypt failed: " + std::string(e.what()), true);
        return false;
    }

    json cj;
    try {
        cj = json::parse(std::string(cd.begin(), cd.end()));
    }
    catch (const std::exception& e) {
        logCb("nonce_B confirm JSON parse failed: " + std::string(e.what()), true);
        return false;
    }

    if (cj["nonce_B"] != Utils::base64Encode(nonce_B)) {
        logCb("nonce_B mismatch!", true);
        return false;
    }

    logCb("E2EE established with " + fromUser + "!", false);
    return true;
}

// ─── Chat loop: send + recv tuần tự trên 1 thread ────────────
static void chatLoop(const std::string& target)
{
    // Spawn recv thread riêng — giống CLI
    // Lý do: recv là blocking, cần chạy song song với send
    // Nhưng đây là 2 operations khác nhau (read vs write)
    // OpenSSL hỗ trợ đồng thời 1 read + 1 write trên cùng SSL*
    std::thread recvThread([]() {
        while (g_app.connected) {
            try {
                Message msg = Protocol::recvMessage(g_app.chatSSL);
                if (msg.type == MessageType::CHAT_MESSAGE) {
                    auto enc = Utils::base64Decode(msg.payload["data"]);
                    auto iv = Utils::base64Decode(msg.payload["iv"]);
                    auto dec = Crypto::aesDecrypt(g_app.K_AB, iv, enc);
                    std::string text(dec.begin(), dec.end());
                    addMsg(msg.payload["from"], text, false);
                }
            }
            catch (...) { break; }
        }
        });
    recvThread.detach();

    // Send loop: chờ GUI push vào inputQueue rồi encrypt + send
    // Giống CLI's getline loop, nhưng thay stdin bằng inputQueue
    while (g_app.connected) {
        AppState::PendingMsg pending;
        {
            std::unique_lock<std::mutex> lock(g_app.inputQueueMutex);
            g_app.inputQueueCV.wait(lock, [] {
                return !g_app.inputQueue.empty() || !g_app.connected;
                });
            if (!g_app.connected && g_app.inputQueue.empty()) break;
            pending = g_app.inputQueue.front();
            g_app.inputQueue.pop();
        }

        // Encrypt + send — không cần lock SSL vì recvThread đang read
        // send thread đang write — OpenSSL OK với 1 reader + 1 writer
        std::vector<unsigned char> msgBytes(
            pending.text.begin(), pending.text.end());
        auto iv = Crypto::generateNonce(16);
        auto enc = Crypto::aesEncrypt(g_app.K_AB, iv, msgBytes);

        Message chatMsg;
        chatMsg.type = MessageType::CHAT_MESSAGE;
        chatMsg.payload["target"] = pending.target;
        chatMsg.payload["data"] = Utils::base64Encode(enc);
        chatMsg.payload["iv"] = Utils::base64Encode(iv);

        try {
            Protocol::sendMessage(g_app.chatSSL, chatMsg);
        }
        catch (...) { break; }
    }
}

// ─── Entry point — gọi từ GUI khi bấm Start/Wait ─────────────
void startNetworkThread(bool asInitiator)
{
    std::string me = g_app.myUsername;
    std::string target = g_app.targetUser;

    std::thread([me, target, asInitiator]() {
        bool ok = false;

        if (asInitiator)
            ok = doHandshakeAsA(me, target);
        else
            ok = doHandshakeAsB(me);

        if (!ok) {
            addLog("Handshake failed", true);
            return;
        }

        g_app.chatReady = true;

        // Lấy target thực (phía B cập nhật targetUser trong handshake)
        std::string actualTarget = g_app.targetUser;
        chatLoop(actualTarget);

        }).detach();
}