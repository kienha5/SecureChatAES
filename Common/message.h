#pragma once
#include <string>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

enum class MessageType {
    // PKI flow
    CHALLENGE,
    REGISTER_CERT,
    CERT_RESPONSE,
    ISSUE_CERT_REQ,
    VERIFY_CERT,
    CERT_STATUS,

    // General
    SUCCESS,
    ERROR_MSG,
    REVOKE_CERT,    // Admin -> CA: thu hồi cert
    REVOKE_SUCCESS, // CA -> Admin: xác nhận thu hồi

    // Kerberos flow
    KDC_REGISTER_INIT,    // Client → KDC: đăng ký principal
    KDC_REGISTER,         // Client → KDC: gửi password hash + signature
    KDC_REGISTER_SUCCESS, // KDC → Client: đăng ký OK
    AS_REQUEST,           // Client → AS: xin TGT
    AS_RESPONSE,          // AS → Client: TGT
    TGS_REQUEST,          // Client → TGS: xin Service Ticket
    TGS_RESPONSE,         // TGS → Client: Service Ticket
    CLIENT_AUTH,          // Client → ChatServer: login bằng ticket
    SERVER_AUTH,          // ChatServer → Client: mutual auth

    // E2EE Chat
    SESSION_REQUEST,   // A -> Server: xin public key cua B
    SESSION_RESPONSE,  // Server -> A: tra public key B
    KEY_EXCHANGE,      // A -> Server -> B: gui K_AB ma hoa
    KEY_ACK,           // B -> Server -> A: xac nhan nhan duoc K_AB
    CHAT_MESSAGE,      // A <-> B: tin nhan ma hoa
};

struct Message {
    MessageType type;
    json payload;
};

namespace Protocol {
    std::string serialize(const Message& msg);
    Message deserialize(const std::string& raw);

    // Dùng trên socket
    bool sendMessage(void* ssl, const Message& msg);
    Message recvMessage(void* ssl);
}