#include "pch.h"
// Common.cpp - test OpenSSL
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/rand.h>

#include <openssl/evp.h>
#include <openssl/sha.h>
#include <iostream>
#include <cstring>

void testOpenSSL() {
    // Test 1: Random bytes
    unsigned char buf[32];
    RAND_bytes(buf, sizeof(buf));
    std::cout << "[OK] RAND_bytes works\n";

    // Test 2: RSA keygen
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    EVP_PKEY_keygen_init(ctx);
    EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048);
    EVP_PKEY* pkey = nullptr;
    EVP_PKEY_keygen(ctx, &pkey);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    std::cout << "[OK] RSA 2048 keygen works\n";

    // Test 3: SHA256
    const char* msg = "hello";
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)msg, strlen(msg), hash);
    std::cout << "[OK] SHA256 works\n";
}