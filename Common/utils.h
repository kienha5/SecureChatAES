#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <fstream>

namespace Utils {
    // Base64
    std::string base64Encode(const std::vector<unsigned char>& data);
    std::vector<unsigned char> base64Decode(const std::string& encoded);

    // Timestamp
    int64_t getTimestamp();
    bool isExpired(int64_t timestamp, int secondsWindow = 300);

    // Logger
    enum class LogLevel { INFO, WARN, ERR };
    void log(LogLevel level, const std::string& module, const std::string& message);

    // Save PEM string to file. Returns true on success.
    //inline bool savePEM(const std::string& path, const std::string& pem) {
    //    std::ofstream ofs(path, std::ios::binary);
    //    if (!ofs) return false;
    //    ofs << pem;
    //    return ofs.good();
    //}

    // File helpers
    std::string loadPEM(const std::string& path);
    bool        savePEM(const std::string& path, const std::string& content);

    // Audit log
    void initAuditLog(const std::string& logDir);
    void auditLog(const std::string& module,
        const std::string& event,
        const std::string& detail = "");
}