#include "pch.h"
#include "../Common/utils.h"
#include "../Common/crypto.h"
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/aes.h>

namespace Crypto {

    // ─── RSA ──────────────────────────────────────────────────
    bool generateRSAKeyPair(std::string& pubKeyPEM, std::string& privKeyPEM) {
        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
        if (!ctx) return false;

        if (EVP_PKEY_keygen_init(ctx) <= 0) { EVP_PKEY_CTX_free(ctx); return false; }
        if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0) { EVP_PKEY_CTX_free(ctx); return false; }

        EVP_PKEY* pkey = nullptr;
        if (EVP_PKEY_keygen(ctx, &pkey) <= 0) { EVP_PKEY_CTX_free(ctx); return false; }
        EVP_PKEY_CTX_free(ctx);

        // Public key → PEM string
        BIO* pub = BIO_new(BIO_s_mem());
        PEM_write_bio_PUBKEY(pub, pkey);
        BUF_MEM* pubPtr;
        BIO_get_mem_ptr(pub, &pubPtr);
        pubKeyPEM = std::string(pubPtr->data, pubPtr->length);
        BIO_free(pub);

        // Private key → PEM string
        BIO* priv = BIO_new(BIO_s_mem());
        PEM_write_bio_PrivateKey(priv, pkey, nullptr, nullptr, 0, nullptr, nullptr);
        BUF_MEM* privPtr;
        BIO_get_mem_ptr(priv, &privPtr);
        privKeyPEM = std::string(privPtr->data, privPtr->length);
        BIO_free(priv);

        EVP_PKEY_free(pkey);
        return true;
    }

    std::vector<unsigned char> signData(const std::string& privKeyPEM, const std::vector<unsigned char>& data) {
        BIO* bio = BIO_new_mem_buf(privKeyPEM.data(), (int)privKeyPEM.size());
        EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
        BIO_free(bio);
        if (!pkey) return {};

        EVP_MD_CTX* mdCtx = EVP_MD_CTX_new();
        EVP_DigestSignInit(mdCtx, nullptr, EVP_sha256(), nullptr, pkey);
        EVP_DigestSignUpdate(mdCtx, data.data(), data.size());

        size_t sigLen = 0;
        EVP_DigestSignFinal(mdCtx, nullptr, &sigLen);
        std::vector<unsigned char> sig(sigLen);
        EVP_DigestSignFinal(mdCtx, sig.data(), &sigLen);
        sig.resize(sigLen);

        EVP_MD_CTX_free(mdCtx);
        EVP_PKEY_free(pkey);
        return sig;
    }

    bool verifySignature(const std::string& pubKeyPEM, const std::vector<unsigned char>& data, const std::vector<unsigned char>& sig) {
        BIO* bio = BIO_new_mem_buf(pubKeyPEM.data(), (int)pubKeyPEM.size());
        EVP_PKEY* pkey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
        BIO_free(bio);
        if (!pkey) return false;

        EVP_MD_CTX* mdCtx = EVP_MD_CTX_new();
        EVP_DigestVerifyInit(mdCtx, nullptr, EVP_sha256(), nullptr, pkey);
        EVP_DigestVerifyUpdate(mdCtx, data.data(), data.size());
        int result = EVP_DigestVerifyFinal(mdCtx, sig.data(), sig.size());

        EVP_MD_CTX_free(mdCtx);
        EVP_PKEY_free(pkey);
        return result == 1;
    }

    std::vector<unsigned char> encryptRSA(const std::string& pubKeyPEM, const std::vector<unsigned char>& plaintext) {
        BIO* bio = BIO_new_mem_buf(pubKeyPEM.data(), (int)pubKeyPEM.size());
        EVP_PKEY* pkey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
        BIO_free(bio);
        if (!pkey) return {};

        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, nullptr);
        EVP_PKEY_encrypt_init(ctx);
        EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING);

        size_t outLen = 0;
        EVP_PKEY_encrypt(ctx, nullptr, &outLen, plaintext.data(), plaintext.size());
        std::vector<unsigned char> out(outLen);
        EVP_PKEY_encrypt(ctx, out.data(), &outLen, plaintext.data(), plaintext.size());
        out.resize(outLen);

        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return out;
    }

    std::vector<unsigned char> decryptRSA(const std::string& privKeyPEM, const std::vector<unsigned char>& ciphertext) {
        BIO* bio = BIO_new_mem_buf(privKeyPEM.data(), (int)privKeyPEM.size());
        EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
        BIO_free(bio);
        if (!pkey) return {};

        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, nullptr);
        EVP_PKEY_decrypt_init(ctx);
        EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING);

        size_t outLen = 0;
        EVP_PKEY_decrypt(ctx, nullptr, &outLen, ciphertext.data(), ciphertext.size());
        std::vector<unsigned char> out(outLen);
        EVP_PKEY_decrypt(ctx, out.data(), &outLen, ciphertext.data(), ciphertext.size());
        out.resize(outLen);

        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return out;
    }

    // ─── AES ──────────────────────────────────────────────────
    std::vector<unsigned char> aesEncrypt(const std::vector<unsigned char>& key, const std::vector<unsigned char>& iv, const std::vector<unsigned char>& plaintext) {
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data());

        std::vector<unsigned char> out(plaintext.size() + AES_BLOCK_SIZE);
        int len = 0, totalLen = 0;
        EVP_EncryptUpdate(ctx, out.data(), &len, plaintext.data(), (int)plaintext.size());
        totalLen = len;
        EVP_EncryptFinal_ex(ctx, out.data() + len, &len);
        totalLen += len;
        out.resize(totalLen);

        EVP_CIPHER_CTX_free(ctx);
        return out;
    }

    std::vector<unsigned char> aesDecrypt(const std::vector<unsigned char>& key, const std::vector<unsigned char>& iv, const std::vector<unsigned char>& ciphertext) {
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data());

        std::vector<unsigned char> out(ciphertext.size());
        int len = 0, totalLen = 0;
        EVP_DecryptUpdate(ctx, out.data(), &len, ciphertext.data(), (int)ciphertext.size());
        totalLen = len;
        EVP_DecryptFinal_ex(ctx, out.data() + len, &len);
        totalLen += len;
        out.resize(totalLen);

        EVP_CIPHER_CTX_free(ctx);
        return out;
    }

    // ─── Hash & Nonce ─────────────────────────────────────────
    std::vector<unsigned char> sha256(const std::vector<unsigned char>& data) {
        std::vector<unsigned char> hash(SHA256_DIGEST_LENGTH);
        SHA256(data.data(), data.size(), hash.data());
        return hash;
    }

    std::vector<unsigned char> generateNonce(int size) {
        std::vector<unsigned char> nonce(size);
        RAND_bytes(nonce.data(), size);
        return nonce;
    }
}