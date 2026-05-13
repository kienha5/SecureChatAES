#pragma once
#include "../Common/pch.h"
#include "../Common/crypto.h"
#include "../Common/message.h"
#include <string>
#include <deque>
#include <mutex>
#include <atomic>
#include <vector>
#include <openssl/ssl.h>
#include <queue>

enum class AppScreen { LOGIN, MAIN, SECURITY_TEST};

struct ChatMessage {
    std::string from;
    std::string text;
    bool isMe;
};

// Kết quả security test
struct TestResult {
    std::string name;
    bool        passed;
    std::string detail;
    bool        done = false;
};

struct AppState {
    AppScreen screen = AppScreen::LOGIN;

    // Login fields
    char username[64] = {};
    char password[64] = {};
    char serverIP[64] = "127.0.0.1";
    bool isRegistering = false;

    // Status
    std::string statusMsg = "Ready";
    bool        statusIsOk = true;

    // Chat
    std::string myUsername;
    char targetUser[64] = {};
    char inputBuf[512] = {};
    std::deque<ChatMessage> messages;
    std::mutex              msgMutex;

    // Network
    SSL* chatSSL = nullptr;
    SSL_CTX* chatCtx = nullptr;
    std::atomic<bool> connected{ false };
    std::atomic<bool> chatReady{ false };

    // Kerberos session
    std::vector<unsigned char> Kc;
    std::vector<unsigned char> Kc_tgs;
    std::string ticket_tgs_b64;
    std::string iv_tgt_b64;
    std::vector<unsigned char> Kc_v;
    std::string ticket_v_b64;
    std::string iv_tv_b64;
    std::vector<unsigned char> K_AB;

    // Log panel
    std::deque<std::pair<std::string, bool>> logs;
    std::mutex logMutex;

	// Kết quả security tests
    std::vector<TestResult> testResults;
    std::mutex testResultsMutex;

    // ── Input queue: GUI push, network thread pop ──────────────
    // Thay thế toàn bộ sendQueue + sendQueueMutex + sendQueueCV
    // + handshakeMutex + sslMutex
    struct PendingMsg {
        std::string target;
        std::string text;       // plaintext, network thread sẽ encrypt
    };
    std::queue<PendingMsg>   inputQueue;
    std::mutex               inputQueueMutex;
    std::condition_variable  inputQueueCV;

    // ── Network thread control ─────────────────────────────────
    // Dùng để báo network thread bắt đầu E2EE
    enum class NetCmd { NONE, START_SESSION, WAIT_SESSION };
    std::atomic<NetCmd> netCmd{ NetCmd::NONE };

    // Online users list
    std::vector<std::string> onlineUsers;
    std::mutex onlineUsersMutex;

	// Handshaking flag để tránh
    std::atomic<bool> isHandshaking{ false };

    // Queue cho handshake messages (KEY_EXCHANGE từ phía A gửi đến)
    std::queue<Message> handshakeQueue;
    std::mutex          handshakeQueueMutex;
    std::condition_variable handshakeQueueCV;

    // Queue cho chat messages
    std::queue<Message> chatMsgQueue;
    std::mutex          chatMsgQueueMutex;
    std::condition_variable chatMsgQueueCV;
};

extern AppState g_app;

// Helpers — defined in main.cpp
void addLog(const std::string& msg, bool isError = false);
void addMsg(const std::string& from, const std::string& text, bool isMe);

// GUI gọi cái này để gửi tin chat
inline void pushInputQueue(const std::string& target, const std::string& text) {
    std::lock_guard<std::mutex> lock(g_app.inputQueueMutex);
    g_app.inputQueue.push({ target, text });
    g_app.inputQueueCV.notify_one();
}

inline void resetChatSession() {
    g_app.chatReady = false;
    g_app.K_AB.clear();
    memset(g_app.targetUser, 0, sizeof(g_app.targetUser));

    g_app.inputQueueCV.notify_all();
    g_app.chatMsgQueueCV.notify_all();

    {
        std::lock_guard<std::mutex> lock(g_app.msgMutex);
        g_app.messages.clear();
    }
    {
        std::lock_guard<std::mutex> lock(g_app.inputQueueMutex);
        while (!g_app.inputQueue.empty())
            g_app.inputQueue.pop();
    }
    {
        std::lock_guard<std::mutex> lock(g_app.chatMsgQueueMutex);
        while (!g_app.chatMsgQueue.empty())
            g_app.chatMsgQueue.pop();
    }
    {
        std::lock_guard<std::mutex> lock(g_app.handshakeQueueMutex);
        while (!g_app.handshakeQueue.empty())
            g_app.handshakeQueue.pop();
    }
}

inline void setOnlineUsers(const std::vector<std::string>& users) {
    std::lock_guard<std::mutex> lock(g_app.onlineUsersMutex);
    g_app.onlineUsers = users;
}

inline void addOnlineUser(const std::string& user) {
    std::lock_guard<std::mutex> lock(g_app.onlineUsersMutex);
    // Không thêm bản thân và không thêm trùng
    if (user != g_app.myUsername &&
        std::find(g_app.onlineUsers.begin(),
            g_app.onlineUsers.end(), user)
        == g_app.onlineUsers.end()) {
        g_app.onlineUsers.push_back(user);
    }
}

inline void removeOnlineUser(const std::string& user) {
    std::lock_guard<std::mutex> lock(g_app.onlineUsersMutex);
    g_app.onlineUsers.erase(
        std::remove(g_app.onlineUsers.begin(),
            g_app.onlineUsers.end(), user),
        g_app.onlineUsers.end()
    );
}

inline void addTestResult(const std::string& name,
    bool passed,
    const std::string& detail) {
    std::lock_guard<std::mutex> lock(g_app.testResultsMutex);
    // Tìm xem đã có result cho test này chưa
    for (auto& r : g_app.testResults) {
        if (r.name == name) {
            r.passed = passed;
            r.detail = detail;
            r.done = true;
            return;
        }
    }
    g_app.testResults.push_back({ name, passed, detail, true });
}

inline void shutdownApp() {
    // Bước 1: Set flag dừng tất cả thread
    g_app.connected = false;
    g_app.chatReady = false;

    // Bước 2: Wake up tất cả thread đang wait
    g_app.inputQueueCV.notify_all();
    g_app.chatMsgQueueCV.notify_all();
    g_app.handshakeQueueCV.notify_all();

    // Bước 3: Đợi để dispatcher thread thoát khỏi SSL_read
    // SSL_read sẽ return lỗi sau khi socket đóng
    // Đợi tối đa 500ms
    Sleep(500);

    // Bước 4: Giờ mới đóng SSL
    if (g_app.chatSSL) {
        // Lấy socket trước khi shutdown
        int sock = SSL_get_fd(g_app.chatSSL);

        // shutdown SSL gracefully
        SSL_shutdown(g_app.chatSSL);
        SSL_free(g_app.chatSSL);
        g_app.chatSSL = nullptr;

        // Đóng socket
        if (sock >= 0) closesocket(sock);
    }

    if (g_app.chatCtx) {
        SSL_CTX_free(g_app.chatCtx);
        g_app.chatCtx = nullptr;
    }
}