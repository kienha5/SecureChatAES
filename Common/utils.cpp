#include "pch.h"
#include "../Common/utils.h"
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <iostream>
#include <chrono>
#include <sstream>
#include <iomanip>
#include <fstream>
#include <filesystem>
#include <mutex>

namespace Utils {

    // ─── Base64 ───────────────────────────────────────────────
    std::string base64Encode(const std::vector<unsigned char>& data) {
        BIO* b64 = BIO_new(BIO_f_base64());
        BIO* mem = BIO_new(BIO_s_mem());
        BIO_push(b64, mem);
        BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
        BIO_write(b64, data.data(), (int)data.size());
        BIO_flush(b64);

        BUF_MEM* bptr;
        BIO_get_mem_ptr(b64, &bptr);
        std::string result(bptr->data, bptr->length);
        BIO_free_all(b64);
        return result;
    }

    std::vector<unsigned char> base64Decode(const std::string& encoded) {
        BIO* b64 = BIO_new(BIO_f_base64());
        BIO* mem = BIO_new_mem_buf(encoded.data(), (int)encoded.size());
        BIO_push(b64, mem);
        BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

        std::vector<unsigned char> result(encoded.size());
        int len = BIO_read(b64, result.data(), (int)result.size());
        BIO_free_all(b64);
        result.resize(len > 0 ? len : 0);
        return result;
    }

    // ─── Timestamp ────────────────────────────────────────────
    int64_t getTimestamp() {
        return std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()
        ).count();
    }

    bool isExpired(int64_t timestamp, int secondsWindow) {
        int64_t now = getTimestamp();
        int64_t diff = now - timestamp;
        return diff > secondsWindow || diff < -secondsWindow;
    }

    // ─── Logger ───────────────────────────────────────────────
    void log(LogLevel level, const std::string& module, const std::string& message) {
        // Timestamp
        auto now = std::chrono::system_clock::now();
        std::time_t t = std::chrono::system_clock::to_time_t(now);
        std::tm tm;
        localtime_s(&tm, &t);

        std::ostringstream ts;
        ts << std::setfill('0')
            << std::setw(2) << tm.tm_hour << ":"
            << std::setw(2) << tm.tm_min << ":"
            << std::setw(2) << tm.tm_sec;

        // Color
        std::string color;
        std::string label;
        switch (level) {
        case LogLevel::INFO: color = "\033[32m"; label = "INFO"; break;  // green
        case LogLevel::WARN: color = "\033[33m"; label = "WARN"; break;  // yellow
        case LogLevel::ERR:  color = "\033[31m"; label = "ERR ";  break;  // red
        }

        std::cout << color
            << "[" << ts.str() << "]"
            << "[" << label << "]"
            << "[" << module << "] "
            << "\033[0m"
            << message << "\n";
    }

    std::string Utils::loadPEM(const std::string& path) {
        std::ifstream f(path);
        if (!f.is_open()) return "";
        return std::string(
            std::istreambuf_iterator<char>(f),
            std::istreambuf_iterator<char>()
        );
    }

    bool Utils::savePEM(const std::string& path, const std::string& content) {
        std::ofstream f(path);
        if (!f.is_open()) return false;
        f << content;
        return true;
    }

    // ─── Audit Log ────────────────────────────────────────────────
    static std::ofstream g_auditFile;
    static std::mutex    g_auditMutex;

    void Utils::initAuditLog(const std::string& logDir) {
        std::filesystem::create_directories(logDir);

        // Ten file: audit_YYYY-MM-DD_HH-MM-SS.log
        auto now = std::chrono::system_clock::now();
        std::time_t t = std::chrono::system_clock::to_time_t(now);
        std::tm tm;
        localtime_s(&tm, &t);

        std::ostringstream fname;
        fname << logDir << "\\audit_"
            << std::setfill('0')
            << std::setw(4) << (tm.tm_year + 1900) << "-"
            << std::setw(2) << (tm.tm_mon + 1) << "-"
            << std::setw(2) << tm.tm_mday << "_"
            << std::setw(2) << tm.tm_hour << "-"
            << std::setw(2) << tm.tm_min << "-"
            << std::setw(2) << tm.tm_sec
            << ".log";

        std::lock_guard<std::mutex> lock(g_auditMutex);
        g_auditFile.open(fname.str(), std::ios::app);
        if (g_auditFile.is_open()) {
            g_auditFile << "=== Audit Log Started: "
                << fname.str() << " ===\n";
            g_auditFile.flush();
            log(LogLevel::INFO, "Audit",
                "Log file opened: " + fname.str());
        }
        else {
            log(LogLevel::ERR, "Audit",
                "Failed to open log file: " + fname.str());
        }
    }

    void Utils::auditLog(const std::string& module,
        const std::string& event,
        const std::string& detail) {
        // Lay timestamp
        auto now = std::chrono::system_clock::now();
        std::time_t t = std::chrono::system_clock::to_time_t(now);
        std::tm tm;
        localtime_s(&tm, &t);

        std::ostringstream entry;
        entry << std::setfill('0')
            << "[" << std::setw(4) << (tm.tm_year + 1900)
            << "-" << std::setw(2) << (tm.tm_mon + 1)
            << "-" << std::setw(2) << tm.tm_mday
            << " " << std::setw(2) << tm.tm_hour
            << ":" << std::setw(2) << tm.tm_min
            << ":" << std::setw(2) << tm.tm_sec << "]"
            << "[" << module << "]"
            << "[" << event << "]";

        if (!detail.empty())
            entry << " " << detail;
        entry << "\n";

        std::lock_guard<std::mutex> lock(g_auditMutex);
        if (g_auditFile.is_open()) {
            g_auditFile << entry.str();
            g_auditFile.flush();
        }
    }
}