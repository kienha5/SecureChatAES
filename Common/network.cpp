#include "pch.h"
#include "../Common/network.h"
#include "../Common/utils.h"
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <WinSock2.h>
#include <WS2tcpip.h>

namespace Network {

    // ─── Server ───────────────────────────────────────────────
    SSL_CTX* createServerContext(const std::string& certFile, const std::string& keyFile) {
        SSL_CTX* ctx = SSL_CTX_new(TLS_server_method());
        if (!ctx) {
            Utils::log(Utils::LogLevel::ERR, "Network", "Failed to create server SSL_CTX");
            return nullptr;
        }

        if (SSL_CTX_use_certificate_file(ctx, certFile.c_str(), SSL_FILETYPE_PEM) <= 0) {
            Utils::log(Utils::LogLevel::ERR, "Network", "Failed to load server cert: " + certFile);
            SSL_CTX_free(ctx);
            return nullptr;
        }

        if (SSL_CTX_use_PrivateKey_file(ctx, keyFile.c_str(), SSL_FILETYPE_PEM) <= 0) {
            Utils::log(Utils::LogLevel::ERR, "Network", "Failed to load server key: " + keyFile);
            SSL_CTX_free(ctx);
            return nullptr;
        }

        Utils::log(Utils::LogLevel::INFO, "Network", "Server SSL context created");
        return ctx;
    }

    int createServerSocket(int port) {
        WSADATA wsa;
        WSAStartup(MAKEWORD(2, 2), &wsa);

        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) {
            Utils::log(Utils::LogLevel::ERR, "Network", "Failed to create socket");
            return -1;
        }

        // Cho phép reuse port
        int opt = 1;
        setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt));

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        addr.sin_addr.s_addr = INADDR_ANY;

        if (bind(sock, (sockaddr*)&addr, sizeof(addr)) < 0) {
            Utils::log(Utils::LogLevel::ERR, "Network", "Bind failed on port " + std::to_string(port));
            return -1;
        }

        listen(sock, 5);
        Utils::log(Utils::LogLevel::INFO, "Network", "Listening on port " + std::to_string(port));
        return sock;
    }

    SSL* acceptClient(SSL_CTX* ctx, int serverSock, int& clientSock) {
        sockaddr_in clientAddr{};
        int addrLen = sizeof(clientAddr);
        clientSock = accept(serverSock, (sockaddr*)&clientAddr, &addrLen);
        if (clientSock < 0) {
            Utils::log(Utils::LogLevel::ERR, "Network", "Accept failed");
            return nullptr;
        }

        // Log IP client
        char ipStr[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &clientAddr.sin_addr, ipStr, sizeof(ipStr));
        Utils::log(Utils::LogLevel::INFO, "Network", "Client connected: " + std::string(ipStr));

        SSL* ssl = SSL_new(ctx);
        SSL_set_fd(ssl, clientSock);

        if (SSL_accept(ssl) <= 0) {
            Utils::log(Utils::LogLevel::ERR, "Network", "TLS handshake failed");
            SSL_free(ssl);
            closesocket(clientSock);
            return nullptr;
        }

        Utils::log(Utils::LogLevel::INFO, "Network", "TLS handshake OK");
        return ssl;
    }

    // ─── Client ───────────────────────────────────────────────
    SSL_CTX* createClientContext(const std::string& caCertFile) {
        SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
        if (!ctx) {
            Utils::log(Utils::LogLevel::ERR, "Network", "Failed to create client SSL_CTX");
            return nullptr;
        }

        if (SSL_CTX_load_verify_locations(ctx, caCertFile.c_str(), nullptr) <= 0) {
            Utils::log(Utils::LogLevel::ERR, "Network", "Failed to load CA cert: " + caCertFile);
            SSL_CTX_free(ctx);
            return nullptr;
        }

        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);
        Utils::log(Utils::LogLevel::INFO, "Network", "Client SSL context created");
        return ctx;
    }

    SSL* connectToServer(SSL_CTX* ctx, const std::string& host, int port) {
        WSADATA wsa;
        WSAStartup(MAKEWORD(2, 2), &wsa);

        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) {
            Utils::log(Utils::LogLevel::ERR, "Network", "Failed to create socket");
            return nullptr;
        }

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        inet_pton(AF_INET, host.c_str(), &addr.sin_addr);

        if (connect(sock, (sockaddr*)&addr, sizeof(addr)) < 0) {
            Utils::log(Utils::LogLevel::ERR, "Network", "Connect failed to " + host + ":" + std::to_string(port));
            return nullptr;
        }

        SSL* ssl = SSL_new(ctx);
        SSL_set_fd(ssl, sock);

        if (SSL_connect(ssl) <= 0) {
            Utils::log(Utils::LogLevel::ERR, "Network", "TLS handshake failed");
            SSL_free(ssl);
            closesocket(sock);
            return nullptr;
        }

        Utils::log(Utils::LogLevel::INFO, "Network", "Connected to " + host + ":" + std::to_string(port));
        return ssl;
    }

    // ─── Cleanup ──────────────────────────────────────────────
    void closeConnection(SSL* ssl, int sock) {
        if (ssl) {
            SSL_shutdown(ssl);
            SSL_free(ssl);
        }
        if (sock >= 0) closesocket(sock);
    }

    void freeContext(SSL_CTX* ctx) {
        if (ctx) SSL_CTX_free(ctx);
    }
}