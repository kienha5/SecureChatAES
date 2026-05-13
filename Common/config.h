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
        currentPath = currentPath.parent_path();

        // Thử tìm folder chứa "Common" hoặc "SecureChatCerts"
        std::filesystem::path search = currentPath;
        while (search.has_parent_path()) {
            if (std::filesystem::exists(search / "Common") ||
                std::filesystem::exists(search / "SecureChatCerts")) {
                return search.string() + "\\";
            }
            auto parent = search.parent_path();
            if (parent == search) break;  // đã lên root, dừng
            search = parent;
        }

        // Fallback: thư mục chứa exe
        return currentPath.string() + "\\";
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

	// ─── Audit log ─────────────────────────────────────────────
    inline std::string AUDIT_LOG_DIR() {
        return getSolutionDir() + "AuditLogs\\";
    }

    // Thêm port và cert cho Intermediate CA
    constexpr int PORT_INTERMED_CA = 5004;

    inline std::string INTERMED_CA_CERT() { return certPath("intermed_ca.crt"); }
    inline std::string INTERMED_CA_KEY() { return certPath("intermed_ca.key"); }
    inline std::string INTERMED_CA_DB() { return certPath("intermed_ca_db.json"); }

    // Chain file: chứa cả Root CA cert + Intermed CA cert
    // Client dùng để verify toàn bộ chain
    inline std::string CA_CHAIN() { return certPath("ca_chain.crt"); }
}