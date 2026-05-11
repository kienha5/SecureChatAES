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

// Helper: doc tu handshake queue thay vi truc tiep tu SSL
static Message recvHandshakeMsg(int timeoutMs = 10000) {
    std::unique_lock<std::mutex> lock(g_app.handshakeQueueMutex);
    bool ok = g_app.handshakeQueueCV.wait_for(
        lock,
        std::chrono::milliseconds(timeoutMs),
        [] { return !g_app.handshakeQueue.empty(); }
    );
    if (!ok) throw std::runtime_error("Handshake timeout");
    Message msg = g_app.handshakeQueue.front();
    g_app.handshakeQueue.pop();
    return msg;
}

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

    Message resp = recvHandshakeMsg();
    if (resp.type != MessageType::SESSION_RESPONSE) {
        if (resp.type == MessageType::ERROR_MSG &&
            resp.payload.contains("reason")) {
            std::string reason = resp.payload["reason"];
            addLog("Cannot chat with " + target + ": " + reason, true);
        }
        else {
            addLog(target + " is not available", true);
        }
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

    Message ack = recvHandshakeMsg();
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
static bool doHandshakeAsB(const std::string& me, const Message& kexMsg)
{
    auto logCb = [](const std::string& m, bool e) { addLog(m, e); };
    logCb("Waiting for incoming session...", false);

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

static void dispatchChatLoop(const std::string& target) {
    // Send loop: doc inputQueue, encrypt, gui
    // Recv: dispatcher thread tu dong push vao chatMsgQueue
    // Day thread xu ly chat msg tu queue

    std::thread chatRecvThread([target]() {
        while (g_app.connected && g_app.chatReady) {
            Message msg;
            {
                std::unique_lock<std::mutex> lock(g_app.chatMsgQueueMutex);
                g_app.chatMsgQueueCV.wait(lock, [] {
                    return !g_app.chatMsgQueue.empty()
                        || !g_app.chatReady
                        || !g_app.connected;
                    });
                if (!g_app.chatReady || !g_app.connected) break;
                msg = g_app.chatMsgQueue.front();
                g_app.chatMsgQueue.pop();
            }

            auto enc = Utils::base64Decode(msg.payload["data"]);
            auto iv = Utils::base64Decode(msg.payload["iv"]);
            auto dec = Crypto::aesDecrypt(g_app.K_AB, iv, enc);
            addMsg(msg.payload["from"],
                std::string(dec.begin(), dec.end()), false);
        }
        });
    chatRecvThread.detach();

    // Send loop
    while (g_app.connected && g_app.chatReady) {
        AppState::PendingMsg pending;
        {
            std::unique_lock<std::mutex> lock(g_app.inputQueueMutex);
            g_app.inputQueueCV.wait(lock, [] {
                return !g_app.inputQueue.empty()
                    || !g_app.connected
                    || !g_app.chatReady;
                });
            if (!g_app.connected || !g_app.chatReady) break;
            pending = g_app.inputQueue.front();
            g_app.inputQueue.pop();
        }

        if (g_app.chatSSL && g_app.chatReady) {
            try {
                std::vector<unsigned char> msgBytes(
                    pending.text.begin(), pending.text.end());
                auto iv = Crypto::generateNonce(16);
                auto enc = Crypto::aesEncrypt(g_app.K_AB, iv, msgBytes);

                Message chatMsg;
                chatMsg.type = MessageType::CHAT_MESSAGE;
                chatMsg.payload["target"] = pending.target;
                chatMsg.payload["data"] = Utils::base64Encode(enc);
                chatMsg.payload["iv"] = Utils::base64Encode(iv);
                Protocol::sendMessage(g_app.chatSSL, chatMsg);
            }
            catch (...) {
                addLog("Send failed", true);
                resetChatSession();
                break;
            }
        }
    }
}

// ─── Chat loop: send + recv tuần tự trên 1 thread ────────────
static void chatLoop(const std::string& target)
{
    // Spawn recv thread riêng — giống CLI
    // Lý do: recv là blocking, cần chạy song song với send
    // Nhưng đây là 2 operations khác nhau (read vs write)
    // OpenSSL hỗ trợ đồng thời 1 read + 1 write trên cùng SSL*
    // Recv thread trong chatLoop
    std::thread recvThread([target]() {
        while (g_app.connected && g_app.chatReady) {
            try {
                Message msg = Protocol::recvMessage(g_app.chatSSL);

                if (msg.type == MessageType::CHAT_MESSAGE) {
                    auto enc = Utils::base64Decode(msg.payload["data"]);
                    auto iv = Utils::base64Decode(msg.payload["iv"]);
                    auto dec = Crypto::aesDecrypt(g_app.K_AB, iv, enc);
                    std::string text(dec.begin(), dec.end());
                    addMsg(msg.payload["from"], text, false);
                }
                else if (msg.type == MessageType::USER_OFFLINE) {
                    std::string offlineUser = msg.payload["user"];
                    removeOnlineUser(offlineUser); // cap nhat list

                    if (offlineUser == target) {
                        addMsg("System",
                            "[" + offlineUser + " has disconnected. Session closed.]",
                            false);
                        addLog(offlineUser + " went offline", true);
                        resetChatSession();
                        break;
                    }
                    else {
                        addLog(offlineUser + " went offline", false);
                    }
                }
                else if (msg.type == MessageType::USER_ONLINE) {
                    // Van co the nhan trong luc chat
                    std::string user = msg.payload["user"];
                    addOnlineUser(user);
                    addLog(user + " is now online", false);
                }
                else if (msg.type == MessageType::ONLINE_USERS_LIST) {
                    json users = msg.payload["users"];
                    std::vector<std::string> list;
                    for (auto& u : users) {
                        std::string uStr = u.get<std::string>();
                        if (uStr != g_app.myUsername)
                            list.push_back(uStr);
                    }
                    setOnlineUsers(list);
                }
            }
            catch (...) {
                addMsg("System", "[Connection lost. Session closed.]", false);
                addLog("Connection lost", true);
                resetChatSession();
                break;
            }
        }
        });
    recvThread.detach();

    // Send loop: chờ GUI push vào inputQueue rồi encrypt + send
    // Giống CLI's getline loop, nhưng thay stdin bằng inputQueue
    // Send loop
    while (g_app.connected && g_app.chatReady) {
        AppState::PendingMsg pending;
        {
            std::unique_lock<std::mutex> lock(g_app.inputQueueMutex);
            g_app.inputQueueCV.wait(lock, [] {
                return !g_app.inputQueue.empty() ||
                    !g_app.connected ||
                    !g_app.chatReady;          
                });

            if (!g_app.connected || !g_app.chatReady) break;

            pending = g_app.inputQueue.front();
            g_app.inputQueue.pop();
        }

        // Encrypt va gui
        if (g_app.chatSSL && g_app.chatReady) {
            try {
                std::vector<unsigned char> msgBytes(
                    pending.text.begin(), pending.text.end());
                auto iv = Crypto::generateNonce(16);
                auto enc = Crypto::aesEncrypt(g_app.K_AB, iv, msgBytes);

                Message chatMsg;
                chatMsg.type = MessageType::CHAT_MESSAGE;
                chatMsg.payload["target"] = pending.target;
                chatMsg.payload["data"] = Utils::base64Encode(enc);
                chatMsg.payload["iv"] = Utils::base64Encode(iv);
                Protocol::sendMessage(g_app.chatSSL, chatMsg);
            }
            catch (...) {
                addLog("Send failed - connection lost", true);
                resetChatSession();
                break;
            }
        }
    }
}

// ─── Entry point — gọi từ GUI khi bấm Start/Wait ─────────────
void startNetworkThread(bool asInitiator)
{
    if (!asInitiator) return;

    std::string me = g_app.myUsername;
    std::string target = g_app.targetUser;

    std::thread([me, target]() {
        // Báo startAutoWait nhường SSL
        g_app.isHandshaking = true;

        // Cho startAutoWait thoát khỏi recvMessage hiện tại
        // recvMessage là blocking nên cần đợi nó timeout hoặc finish
        // --> đợi 1 chút để nó xử lý xong message hiện tại
        Sleep(100);

        bool ok = doHandshakeAsA(me, target);
        g_app.isHandshaking = false;

        if (!ok) {
            addLog("Handshake failed", true);
            return;
        }

        g_app.chatReady = true;
		dispatchChatLoop(target);

        resetChatSession();
        addLog("Session ended. Ready for new session.", false);
        }).detach();
}

void startAutoWait() {
    std::thread([]() {
        std::string me = g_app.myUsername;
        addLog("Ready to receive chat sessions", false);

        while (g_app.connected) {
            try {
                // Chi co thread nay doc SSL
                Message msg = Protocol::recvMessage(g_app.chatSSL);

                switch (msg.type) {

                case MessageType::KEY_EXCHANGE: {
                    // Incoming session tu nguoi khac
                    std::string fromUser = msg.payload["from"];
                    addLog("Incoming session from: " + fromUser, false);
                    snprintf(g_app.targetUser, sizeof(g_app.targetUser),
                        "%s", fromUser.c_str());

                    bool ok = doHandshakeAsB(me, msg);
                    if (!ok) {
                        addLog("Handshake failed", true);
                        resetChatSession();
                        break;
                    }

                    g_app.chatReady = true;
                    addLog("E2EE established with " + fromUser + "!", false);

                    // chatLoop spawn recv thread — nhung recv thread do
                    // se conflict voi dispatcher nay!
                    // Nen khong dung chatLoop nua, xu ly recv truc tiep o day
                    dispatchChatLoop(fromUser);

                    resetChatSession();
                    addLog("Session ended. Ready for new session.", false);
                    break;
                }

                case MessageType::SESSION_RESPONSE:
                case MessageType::KEY_ACK: {
                    // Day vao handshake queue cho doHandshakeAsA doc
                    std::lock_guard<std::mutex> lock(
                        g_app.handshakeQueueMutex);
                    g_app.handshakeQueue.push(msg);
                    g_app.handshakeQueueCV.notify_one();
                    break;
                }

                case MessageType::CHAT_MESSAGE: {
                    // Day vao chat queue
                    std::lock_guard<std::mutex> lock(
                        g_app.chatMsgQueueMutex);
                    g_app.chatMsgQueue.push(msg);
                    g_app.chatMsgQueueCV.notify_one();
                    break;
                }

                case MessageType::USER_ONLINE: {
                    addOnlineUser(msg.payload["user"]);
                    addLog(msg.payload["user"].get<std::string>()
                        + " is now online", false);
                    break;
                }

                case MessageType::USER_OFFLINE: {
                    std::string user = msg.payload["user"];
                    removeOnlineUser(user);
                    if (g_app.chatReady &&
                        std::string(g_app.targetUser) == user) {
                        addMsg("System",
                            "[" + user + " has disconnected. Session closed.]",
                            false);
                        resetChatSession();
                    }
                    else {
                        addLog(user + " went offline", false);
                    }
                    break;
                }

                case MessageType::ONLINE_USERS_LIST: {
                    json users = msg.payload["users"];
                    std::vector<std::string> list;
                    for (auto& u : users)
                        list.push_back(u.get<std::string>());
                    setOnlineUsers(list);
                    break;
                }

                default: break;
                }
            }
            catch (...) {
                if (g_app.connected) {
                    addLog("Connection lost", true);
                    g_app.connected = false;
                }
                break;
            }
        }
        }).detach();
}