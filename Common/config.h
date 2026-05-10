#pragma once
#include <string>
#include <filesystem>
#include <windows.h>

namespace Config {

    // ─── Tim Solution folder tu dong ──────────────────────────
    inline std::string getSolutionDir() {
        char buf[MAX_PATH];
        GetModuleFileNameA(nullptr, buf, MAX_PATH);
        std::filesystem::path currentPath(buf);
        currentPath = currentPath.parent_path(); // Thư mục chứa file exe

        // Trèo ngược lên cây thư mục cho đến khi thấy folder "Common"
        while (currentPath.has_parent_path()) {
            if (std::filesystem::exists(currentPath / "Common")) {
                return currentPath.string() + "\\";
            }
            currentPath = currentPath.parent_path();
        }

        // Fallback: nếu không tìm thấy, trả về thư mục hiện tại của exe
        return std::filesystem::path(buf).parent_path().string() + "\\";
    }

    // ─── Thu muc chua certs (nam tai Solution root) ───────────
    inline std::string CERT_DIR() {
        return getSolutionDir() + "SecureChatCerts\\";
    }

    inline std::string certPath(const std::string& filename) {
        return CERT_DIR() + filename;
    }

    inline void ensureCertDir() {
        std::filesystem::create_directories(CERT_DIR());
    }

    // ─── CA ───────────────────────────────────────────────────
    inline std::string CA_CERT() { return certPath("ca.crt"); }
    inline std::string CA_KEY() { return certPath("ca.key"); }
    inline std::string CA_DB() { return certPath("ca_db.json"); }

    // ─── RA ───────────────────────────────────────────────────
    inline std::string RA_CERT() { return certPath("ra.crt"); }
    inline std::string RA_KEY() { return certPath("ra.key"); }

    // ─── KDC ──────────────────────────────────────────────────
    inline std::string KDC_CERT() { return certPath("kdc.crt"); }
    inline std::string KDC_KEY() { return certPath("kdc.key"); }
    inline std::string KDC_DB() { return certPath("kdc_db.json"); }

    // ─── Chat Server ──────────────────────────────────────────
    inline std::string CHAT_CERT() { return certPath("chatserver.crt"); }
    inline std::string CHAT_KEY() { return certPath("chatserver.key"); }
    inline std::string CHAT_DB() { return certPath("chat_db.json"); }

    // ─── User certs ───────────────────────────────────────────
    inline std::string userCert(const std::string& u) { return certPath(u + ".crt"); }
    inline std::string userKey(const std::string& u) { return certPath(u + ".key"); }

    // ─── Ports ────────────────────────────────────────────────
    constexpr int PORT_CA = 5000;
    constexpr int PORT_RA = 5001;
    constexpr int PORT_CHAT = 5002;
    constexpr int PORT_KDC = 5003;

    // ─── Kerberos ─────────────────────────────────────────────
    constexpr int64_t TICKET_LIFETIME = 3600;
    constexpr int     NONCE_WINDOW = 300;
    constexpr int     MAX_LOGIN_RETRY = 5;

    // ─── Network ──────────────────────────────────────────────
    constexpr int MAX_MSG_SIZE = 10 * 1024 * 1024;
    constexpr int SOCKET_TIMEOUT_SEC = 30;

    // ─── KDC master keys ──────────────────────────────────────
    inline const std::string& KTGS_SECRET() {
        static const std::string s = "Ktgs_Secret";
        return s;
    }
    inline const std::string& KV_SECRET() {
        static const std::string s = "Kv_Secret_Chat";
        return s;
    }
}