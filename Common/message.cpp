#include "pch.h"
#include "../Common/message.h"
#include "../Common/utils.h"
#include <openssl/ssl.h>
#include <stdexcept>
#include <winsock2.h>

namespace Protocol {

    // ─── MessageType -> string ─────────────────────────────────
    static std::string typeToString(MessageType t) {
        switch (t) {
        case MessageType::CHALLENGE:     return "CHALLENGE";
        case MessageType::REGISTER_CERT: return "REGISTER_CERT";
        case MessageType::CERT_RESPONSE: return "CERT_RESPONSE";
        case MessageType::ISSUE_CERT_REQ:return "ISSUE_CERT_REQ";
        case MessageType::VERIFY_CERT:   return "VERIFY_CERT";
        case MessageType::CERT_STATUS:   return "CERT_STATUS";
        case MessageType::SUCCESS:       return "SUCCESS";
        case MessageType::ERROR_MSG:     return "ERROR_MSG";
        case MessageType::GET_CA_CERT: return "GET_CA_CERT";

        case MessageType::REVOKE_CERT:    return "REVOKE_CERT";
        case MessageType::REVOKE_SUCCESS: return "REVOKE_SUCCESS";

        case MessageType::KDC_REGISTER_INIT:    return "KDC_REGISTER_INIT";
        case MessageType::KDC_REGISTER:         return "KDC_REGISTER";
        case MessageType::KDC_REGISTER_SUCCESS: return "KDC_REGISTER_SUCCESS";
        case MessageType::AS_REQUEST:           return "AS_REQUEST";
        case MessageType::AS_RESPONSE:          return "AS_RESPONSE";
        case MessageType::TGS_REQUEST:          return "TGS_REQUEST";
        case MessageType::TGS_RESPONSE:         return "TGS_RESPONSE";
        case MessageType::CLIENT_AUTH:          return "CLIENT_AUTH";
        case MessageType::SERVER_AUTH:          return "SERVER_AUTH";

        case MessageType::SESSION_REQUEST:  return "SESSION_REQUEST";
        case MessageType::SESSION_RESPONSE: return "SESSION_RESPONSE";
        case MessageType::KEY_EXCHANGE:     return "KEY_EXCHANGE";
        case MessageType::KEY_ACK:          return "KEY_ACK";
        case MessageType::CHAT_MESSAGE:     return "CHAT_MESSAGE";

        default:                         return "UNKNOWN";
        }
    }

    static MessageType stringToType(const std::string& s) {
        if (s == "CHALLENGE")      return MessageType::CHALLENGE;
        if (s == "REGISTER_CERT")  return MessageType::REGISTER_CERT;
        if (s == "CERT_RESPONSE")  return MessageType::CERT_RESPONSE;
        if (s == "ISSUE_CERT_REQ") return MessageType::ISSUE_CERT_REQ;
        if (s == "VERIFY_CERT")    return MessageType::VERIFY_CERT;
        if (s == "CERT_STATUS")    return MessageType::CERT_STATUS;
        if (s == "SUCCESS")        return MessageType::SUCCESS;
        if (s == "ERROR_MSG")      return MessageType::ERROR_MSG;
        if (s == "GET_CA_CERT") return MessageType::GET_CA_CERT;

        if (s == "REVOKE_CERT")    return MessageType::REVOKE_CERT;
        if (s == "REVOKE_SUCCESS") return MessageType::REVOKE_SUCCESS;

        if (s == "KDC_REGISTER_INIT")    return MessageType::KDC_REGISTER_INIT;
        if (s == "KDC_REGISTER")         return MessageType::KDC_REGISTER;
        if (s == "KDC_REGISTER_SUCCESS") return MessageType::KDC_REGISTER_SUCCESS;
        if (s == "AS_REQUEST")           return MessageType::AS_REQUEST;
        if (s == "AS_RESPONSE")          return MessageType::AS_RESPONSE;
        if (s == "TGS_REQUEST")          return MessageType::TGS_REQUEST;
        if (s == "TGS_RESPONSE")         return MessageType::TGS_RESPONSE;
        if (s == "CLIENT_AUTH")          return MessageType::CLIENT_AUTH;
        if (s == "SERVER_AUTH")          return MessageType::SERVER_AUTH;

        if (s == "SESSION_REQUEST")  return MessageType::SESSION_REQUEST;
        if (s == "SESSION_RESPONSE") return MessageType::SESSION_RESPONSE;
        if (s == "KEY_EXCHANGE")     return MessageType::KEY_EXCHANGE;
        if (s == "KEY_ACK")          return MessageType::KEY_ACK;
        if (s == "CHAT_MESSAGE")     return MessageType::CHAT_MESSAGE;

        throw std::runtime_error("Unknown message type: " + s);
    }

    // ─── Serialize / Deserialize ──────────────────────────────
    std::string serialize(const Message& msg) {
        json j;
        j["type"] = typeToString(msg.type);
        j["payload"] = msg.payload;
        return j.dump();
    }

    Message deserialize(const std::string& raw) {
        json j = json::parse(raw);
        Message msg;
        msg.type = stringToType(j["type"].get<std::string>());
        msg.payload = j["payload"];
        return msg;
    }

    // ─── Send / Recv qua SSL ──────────────────────────────────
    // Wire format: [4-byte length (big-endian)][JSON bytes]

    // CHANGE 1: Use void* here to match your header
    bool sendMessage(void* ptr, const Message& msg) {
        // Cast it back to SSL* inside the function
        SSL* ssl = static_cast<SSL*>(ptr);

        std::string data = serialize(msg);
        uint32_t len = htonl((uint32_t)data.size());

        // Gửi length header
        if (SSL_write(ssl, &len, 4) <= 0) {
            Utils::log(Utils::LogLevel::ERR, "Protocol", "Failed to send length");
            return false;
        }
        // Gửi payload
        if (SSL_write(ssl, data.data(), (int)data.size()) <= 0) {
            Utils::log(Utils::LogLevel::ERR, "Protocol", "Failed to send payload");
            return false;
        }
        return true;
    }

    // CHANGE 2: Use void* here to match your header
    Message recvMessage(void* ptr) {
        // Cast it back to SSL* inside the function
        SSL* ssl = static_cast<SSL*>(ptr);

        // Đọc length header
        uint32_t len = 0;
        if (SSL_read(ssl, &len, 4) <= 0)
            throw std::runtime_error("Failed to read message length");
        len = ntohl(len);

        if (len == 0 || len > 10 * 1024 * 1024) // max 10MB
            throw std::runtime_error("Invalid message length: " + std::to_string(len));

        // Đọc payload
        std::string data(len, '\0');
        int received = 0;
        while (received < (int)len) {
            int r = SSL_read(ssl, &data[received], len - received);
            if (r <= 0) throw std::runtime_error("Failed to read message payload");
            received += r;
        }

        return deserialize(data);
    }
}