#define _CRT_SECURE_NO_WARNINGS

#include <iostream>
#include <openssl/applink.c>
#include "../Common/pch.h"
#include "../Common/utils.h"
#include "../Common/message.h"
#include "../Common/network.h"

int main() {
    Utils::log(Utils::LogLevel::INFO, "Admin", "=== Admin Tool ===");
    Sleep(1000);

    int serial = 0;
    std::cout << "Enter serial number to revoke: ";
    std::cin >> serial;

    SSL_CTX* ctx = Network::createClientContext("C:\\SecureChatCerts\\ca.crt");
    if (!ctx) return 1;

    SSL* ssl = Network::connectToServer(ctx, "127.0.0.1", 5000);
    if (!ssl) {
        Utils::log(Utils::LogLevel::ERR, "Admin", "Cannot connect to CA");
        return 1;
    }

    // Gửi REVOKE_CERT
    Message req;
    req.type = MessageType::REVOKE_CERT;
    req.payload["serial"] = serial;
    Protocol::sendMessage(ssl, req);
    Utils::log(Utils::LogLevel::INFO, "Admin",
        "Sent revoke request for serial=" + std::to_string(serial));

    // Nhan ket qua
    Message resp = Protocol::recvMessage(ssl);
    if (resp.type == MessageType::REVOKE_SUCCESS) {
        std::string username = resp.payload["username"];
        Utils::log(Utils::LogLevel::WARN, "Admin",
            "SUCCESS - Cert revoked for user: " + username +
            " serial=" + std::to_string(serial));
    }
    else if (resp.type == MessageType::ERROR_MSG) {
        Utils::log(Utils::LogLevel::ERR, "Admin",
            "FAILED: " + resp.payload["reason"].get<std::string>());
    }

    int sock = SSL_get_fd(ssl);
    Network::closeConnection(ssl, sock);
    Network::freeContext(ctx);

    system("pause");
    return 0;
}