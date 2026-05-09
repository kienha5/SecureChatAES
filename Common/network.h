#pragma once
#include <string>
#include <openssl/ssl.h>
#include <openssl/err.h>

namespace Network {
    // Server
    SSL_CTX* createServerContext(const std::string& certFile, const std::string& keyFile);
    int createServerSocket(int port);
    SSL* acceptClient(SSL_CTX* ctx, int serverSock, int& clientSock);

    // Client
    SSL_CTX* createClientContext(const std::string& caCertFile);
    SSL* connectToServer(SSL_CTX* ctx, const std::string& host, int port);

    // Cleanup
    void closeConnection(SSL* ssl, int sock);
    void freeContext(SSL_CTX* ctx);
}