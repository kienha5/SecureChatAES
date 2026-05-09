#pragma once

#include <string>
#include <vector>
#include <cstdint>

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
}