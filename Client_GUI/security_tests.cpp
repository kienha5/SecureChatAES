#define _CRT_SECURE_NO_WARNINGS
#include "../Common/pch.h"
#include "../Common/utils.h"
#include "../Common/crypto.h"
#include "../Common/message.h"
#include "../Common/network.h"
#include "../Common/config.h"
#include "security_tests.h"
#include "network_ops.h"
#include <fstream>
#include <thread>
#include <chrono>

namespace SecurityTests {

    // ─── Test 1: Replay Attack ─────────────────────────────────────
    void testReplayAttack(const std::string& username,
        const std::string& serverIP,
        TestResultCallback cb) {
        std::thread([username, serverIP, cb]() {
            cb("Replay Attack", false, "Starting...");

            std::string certPEM = Utils::loadPEM(
                Config::userCert(username));
            std::string privKeyPEM = Utils::loadPEM(
                Config::userKey(username));
            if (certPEM.empty() || privKeyPEM.empty()) {
                cb("Replay Attack", false,
                    "No cert/key found for " + username);
                return;
            }

            // ── Attempt 1: Ket noi binh thuong, lay nonce ─────────
            SSL_CTX* ctx1 = Network::createClientContext(
                Config::CA_CERT());
            SSL* ssl1 = Network::connectToServer(
                ctx1, serverIP, Config::PORT_RA);
            if (!ssl1) {
                cb("Replay Attack", false, "Cannot connect to RA");
                Network::freeContext(ctx1);
                return;
            }

            Message challenge = Protocol::recvMessage(ssl1);
            std::string nonceB64 = challenge.payload["nonce"];

            auto nonceBytes = Utils::base64Decode(nonceB64);
            auto sig = Crypto::signData(privKeyPEM, nonceBytes);
            std::string sigB64 = Utils::base64Encode(sig);

            // Lay public key tu cert
            BIO* bio = BIO_new_mem_buf(certPEM.data(),
                (int)certPEM.size());
            X509* x509 = PEM_read_bio_X509(bio, nullptr,
                nullptr, nullptr);
            BIO_free(bio);
            EVP_PKEY* pk = X509_get_pubkey(x509);
            BIO* pubBio = BIO_new(BIO_s_mem());
            PEM_write_bio_PUBKEY(pubBio, pk);
            BUF_MEM* ptr;
            BIO_get_mem_ptr(pubBio, &ptr);
            std::string pubKeyPEM(ptr->data, ptr->length);
            BIO_free(pubBio);
            EVP_PKEY_free(pk);
            X509_free(x509);

            // Gui attempt 1
            Message req1;
            req1.type = MessageType::REGISTER_CERT;
            req1.payload["username"] = username + "_replaytest";
            req1.payload["public_key"] = pubKeyPEM;
            req1.payload["signature"] = sigB64;
            req1.payload["nonce"] = nonceB64;
            req1.payload["timestamp"] = Utils::getTimestamp();
            Protocol::sendMessage(ssl1, req1);

            Message resp1 = Protocol::recvMessage(ssl1);
            bool attempt1Passed = (resp1.type != MessageType::ERROR_MSG);
            int sock1 = SSL_get_fd(ssl1);
            Network::closeConnection(ssl1, sock1);
            Network::freeContext(ctx1);

            cb("Replay Attack",
                attempt1Passed,
                "Attempt 1 (legitimate): " +
                std::string(attempt1Passed ? "ACCEPTED" : "REJECTED"));

            // ── Attempt 2: Dung lai nonce cu ──────────────────────
            Sleep(500);

            SSL_CTX* ctx2 = Network::createClientContext(
                Config::CA_CERT());
            SSL* ssl2 = Network::connectToServer(
                ctx2, serverIP, Config::PORT_RA);
            if (!ssl2) {
                Network::freeContext(ctx2);
                return;
            }

            // Nhan challenge moi nhung KHONG dung
            // Intentionally dung lai nonce cu
            Message newChallenge = Protocol::recvMessage(ssl2);

            Message req2;
            req2.type = MessageType::REGISTER_CERT;
            req2.payload["username"] = username + "_replaytest";
            req2.payload["public_key"] = pubKeyPEM;
            req2.payload["signature"] = sigB64;    // sig cu
            req2.payload["nonce"] = nonceB64;  // nonce cu
            req2.payload["timestamp"] = Utils::getTimestamp();
            Protocol::sendMessage(ssl2, req2);

            Message resp2 = Protocol::recvMessage(ssl2);
            bool attempt2Blocked =
                (resp2.type == MessageType::ERROR_MSG);
            int sock2 = SSL_get_fd(ssl2);
            Network::closeConnection(ssl2, sock2);
            Network::freeContext(ctx2);

            cb("Replay Attack",
                attempt2Blocked,
                "Attempt 2 (REPLAY): " +
                std::string(attempt2Blocked
                    ? "BLOCKED - " + resp2.payload["reason"]
                    .get<std::string>()
                    : "NOT BLOCKED - SECURITY ISSUE!"));

            bool testPassed = attempt1Passed && attempt2Blocked;
            cb("Replay Attack", testPassed,
                testPassed ? "TEST PASSED" : "TEST FAILED");
            }).detach();
    }

    // ─── Test 2: Wrong Password ────────────────────────────────────
    void testWrongPassword(const std::string& username,
        const std::string& serverIP,
        TestResultCallback cb) {
        std::thread([username, serverIP, cb]() {
            cb("Wrong Password", false, "Starting...");

            std::string wrongPass = "wrong_password_12345";
            std::vector<unsigned char> pwBytes(
                wrongPass.begin(), wrongPass.end());
            auto clientHash = Crypto::sha256(pwBytes);
            auto wrongKc = Crypto::sha256(clientHash);

            // Xin TGT voi Kc sai
            SSL_CTX* ctx = Network::createClientContext(
                Config::CA_CERT());
            SSL* ssl = Network::connectToServer(
                ctx, serverIP, Config::PORT_KDC);
            if (!ssl) {
                cb("Wrong Password", false,
                    "Cannot connect to KDC");
                Network::freeContext(ctx);
                return;
            }

            Message req;
            req.type = MessageType::AS_REQUEST;
            req.payload["username"] = username;
            req.payload["timestamp"] = Utils::getTimestamp();
            Protocol::sendMessage(ssl, req);

            Message resp = Protocol::recvMessage(ssl);
            int sock = SSL_get_fd(ssl);
            Network::closeConnection(ssl, sock);
            Network::freeContext(ctx);

            if (resp.type != MessageType::AS_RESPONSE) {
                cb("Wrong Password", false,
                    "AS rejected outright (user not registered?)");
                return;
            }

            // Thu giai ma TGT bang Kc sai
            auto encResp = Utils::base64Decode(
                resp.payload["enc_response"]);
            auto iv_resp = Utils::base64Decode(
                resp.payload["iv_resp"]);

            bool decryptFailed = false;
            try {
                auto dec = Crypto::aesDecrypt(
                    wrongKc, iv_resp, encResp);
                if (dec.empty() || dec[0] != '{') {
                    decryptFailed = true;
                }
                else {
                    // Parse thu
                    json j = json::parse(
                        std::string(dec.begin(), dec.end()));
                    if (!j.contains("Kc_tgs"))
                        decryptFailed = true;
                }
            }
            catch (...) {
                decryptFailed = true;
            }

            cb("Wrong Password", decryptFailed,
                decryptFailed
                ? "TEST PASSED - Wrong password correctly rejected"
                : "TEST FAILED - Wrong password was accepted!");
            }).detach();
    }

    // ─── Test 3: Expired Ticket ────────────────────────────────────
    void testExpiredTicket(const std::string& username,
        const std::string& password,
        const std::string& serverIP,
        int lifetimeSeconds,
        TestResultCallback cb) {
        std::thread([username, password, serverIP,
            lifetimeSeconds, cb]() {
                cb("Expired Ticket", false,
                    "Starting... (KDC must be in test mode with " +
                    std::to_string(lifetimeSeconds) + "s lifetime)");

                auto logCb = [](const std::string&, bool) {};

                // Tao Kc tu password
                std::vector<unsigned char> pwBytes(
                    password.begin(), password.end());
                auto clientHash = Crypto::sha256(pwBytes);
                std::vector<unsigned char> Kc = Crypto::sha256(clientHash);

                // Lay TGT
                std::vector<unsigned char> Kc_tgs;
                std::string ticket_tgs_b64, iv_tgt_b64;

                SSL_CTX* ctx = Network::createClientContext(
                    Config::CA_CERT());
                SSL* ssl = Network::connectToServer(
                    ctx, serverIP, Config::PORT_KDC);
                if (!ssl) {
                    cb("Expired Ticket", false, "Cannot connect to KDC");
                    Network::freeContext(ctx);
                    return;
                }

                Message req;
                req.type = MessageType::AS_REQUEST;
                req.payload["username"] = username;
                req.payload["timestamp"] = Utils::getTimestamp();
                Protocol::sendMessage(ssl, req);

                Message resp = Protocol::recvMessage(ssl);
                int s = SSL_get_fd(ssl);
                Network::closeConnection(ssl, s);
                Network::freeContext(ctx);

                if (resp.type != MessageType::AS_RESPONSE) {
                    cb("Expired Ticket", false, "AS request failed");
                    return;
                }

                // Giai ma TGT
                try {
                    auto enc = Utils::base64Decode(
                        resp.payload["enc_response"]);
                    auto iv = Utils::base64Decode(
                        resp.payload["iv_resp"]);
                    auto dec = Crypto::aesDecrypt(Kc, iv, enc);
                    json j = json::parse(
                        std::string(dec.begin(), dec.end()));
                    Kc_tgs = Utils::base64Decode(j["Kc_tgs"]);
                    ticket_tgs_b64 = j["ticket_tgs"];
                    iv_tgt_b64 = j["iv_tgt"];
                }
                catch (...) {
                    cb("Expired Ticket", false,
                        "Wrong password or TGT decrypt failed");
                    return;
                }

                cb("Expired Ticket", false,
                    "TGT received. Waiting " +
                    std::to_string(lifetimeSeconds + 2) +
                    "s for expiry...");

                // Doi het han
                Sleep((lifetimeSeconds + 2) * 1000);

                // Thu dung ticket het han xin service ticket
                SSL_CTX* ctx2 = Network::createClientContext(
                    Config::CA_CERT());
                SSL* ssl2 = Network::connectToServer(
                    ctx2, serverIP, Config::PORT_KDC);
                if (!ssl2) {
                    Network::freeContext(ctx2);
                    return;
                }

                auto iv_auth = Crypto::generateNonce(16);
                json authP;
                authP["username"] = username;
                authP["timestamp"] = Utils::getTimestamp();
                std::string as2 = authP.dump();
                std::vector<unsigned char> ab(as2.begin(), as2.end());
                auto authEnc = Crypto::aesEncrypt(Kc_tgs, iv_auth, ab);

                Message tgsReq;
                tgsReq.type = MessageType::TGS_REQUEST;
                tgsReq.payload["username"] = username;
                tgsReq.payload["ticket_tgs"] = ticket_tgs_b64;
                tgsReq.payload["authenticator"] =
                    Utils::base64Encode(authEnc);
                tgsReq.payload["iv_tgt"] = iv_tgt_b64;
                tgsReq.payload["iv_auth"] =
                    Utils::base64Encode(iv_auth);
                Protocol::sendMessage(ssl2, tgsReq);

                Message tgsResp = Protocol::recvMessage(ssl2);
                int s2 = SSL_get_fd(ssl2);
                Network::closeConnection(ssl2, s2);
                Network::freeContext(ctx2);

                bool rejected = (tgsResp.type == MessageType::ERROR_MSG);
                cb("Expired Ticket", rejected,
                    rejected
                    ? "TEST PASSED - Expired ticket rejected: " +
                    tgsResp.payload["reason"].get<std::string>()
                    : "TEST FAILED - Expired ticket was accepted!");
            }).detach();
    }

    // ─── Test 4: Revoked Certificate ──────────────────────────────
    void testRevokedCert(const std::string& username,
        const std::string& serverIP,
        int certSerial,
        TestResultCallback cb) {
        std::thread([username, serverIP, certSerial, cb]() {
            cb("Revoked Cert", false,
                "Revoking cert serial " +
                std::to_string(certSerial) + "...");

            // Revoke cert qua Admin (goi CA truc tiep)
            SSL_CTX* ctx = Network::createClientContext(
                Config::CA_CERT());
            SSL* ssl = Network::connectToServer(
                ctx, serverIP, Config::PORT_CA);
            if (!ssl) {
                cb("Revoked Cert", false, "Cannot connect to CA");
                Network::freeContext(ctx);
                return;
            }

            Message revokeReq;
            revokeReq.type = MessageType::REVOKE_CERT;
            revokeReq.payload["serial"] = certSerial;
            Protocol::sendMessage(ssl, revokeReq);

            Message revokeResp = Protocol::recvMessage(ssl);
            int s = SSL_get_fd(ssl);
            Network::closeConnection(ssl, s);
            Network::freeContext(ctx);

            if (revokeResp.type != MessageType::REVOKE_SUCCESS) {
                cb("Revoked Cert", false, "Revoke failed");
                return;
            }
            cb("Revoked Cert", false,
                "Cert revoked. Attempting account registration...");

            // Thu dang ky account voi cert da revoke
            std::string certPEM = Utils::loadPEM(
                Config::userCert(username));
            if (certPEM.empty()) {
                cb("Revoked Cert", false, "No cert file found");
                return;
            }

            SSL_CTX* ctx2 = Network::createClientContext(
                Config::CA_CERT());
            SSL* ssl2 = Network::connectToServer(
                ctx2, serverIP, Config::PORT_CHAT);
            if (!ssl2) {
                Network::freeContext(ctx2);
                return;
            }

            Message regReq;
            regReq.type = MessageType::REGISTER_CERT;
            regReq.payload["username"] = username;
            regReq.payload["cert"] = certPEM;
            regReq.payload["timestamp"] = Utils::getTimestamp();
            Protocol::sendMessage(ssl2, regReq);

            Message regResp = Protocol::recvMessage(ssl2);
            int s2 = SSL_get_fd(ssl2);
            Network::closeConnection(ssl2, s2);
            Network::freeContext(ctx2);

            bool rejected = (regResp.type == MessageType::ERROR_MSG);
            cb("Revoked Cert", rejected,
                rejected
                ? "TEST PASSED - Revoked cert rejected: " +
                regResp.payload["reason"].get<std::string>()
                : "TEST FAILED - Revoked cert was accepted!");
            }).detach();
    }

    // ─── Test 5: Chain Validation ──────────────────────────────────
    void testChainValidation(const std::string& username,
        TestResultCallback cb) {
        std::thread([username, cb]() {
            cb("Chain Validation", false, "Starting...");

            std::string certPEM = Utils::loadPEM(
                Config::userCert(username));
            std::string intermCAPEM = Utils::loadPEM(
                Config::INTERMED_CA_CERT());
            std::string rootCAPEM = Utils::loadPEM(
                Config::CA_CERT());

            if (certPEM.empty()) {
                cb("Chain Validation", false,
                    "No cert found for " + username);
                return;
            }
            if (intermCAPEM.empty()) {
                cb("Chain Validation", false,
                    "No Intermediate CA cert found");
                return;
            }
            if (rootCAPEM.empty()) {
                cb("Chain Validation", false,
                    "No Root CA cert found");
                return;
            }

            // Test 5a: Valid chain
            bool validChain = Crypto::verifyCertChain(
                certPEM, intermCAPEM, rootCAPEM);
            cb("Chain Validation", validChain,
                "Valid chain: " +
                std::string(validChain ? "PASSED" : "FAILED"));

            // Test 5b: Tampered cert (dung cert cua user khac)
            // Tao 1 cert gia tu ky
            std::string fakeCertPEM, fakeKeyPEM;
            Crypto::generateSelfSignedCert(
                "Fake-" + username, 365,
                fakeCertPEM, fakeKeyPEM);

            bool fakeRejected = !Crypto::verifyCertChain(
                fakeCertPEM, intermCAPEM, rootCAPEM);
            cb("Chain Validation", fakeRejected,
                "Self-signed cert rejected: " +
                std::string(fakeRejected ? "PASSED" : "FAILED"));

            bool allPassed = validChain && fakeRejected;
            cb("Chain Validation", allPassed,
                allPassed ? "ALL TESTS PASSED" : "SOME TESTS FAILED");
            }).detach();
    }

    // ─── Test 6: MITM Detection ────────────────────────────────────
    void testMITMDetection(const std::string& serverIP,
        TestResultCallback cb) {
        std::thread([serverIP, cb]() {
            cb("MITM Detection", false, "Starting...");

            // Tao fake cert tu ky (khong co CA sign)
            std::string fakeCertPEM, fakeKeyPEM;
            Crypto::generateSelfSignedCert(
                "MITM-Attacker", 365,
                fakeCertPEM, fakeKeyPEM);

            // Thu dang ky account voi fake cert
            // Chat Server phai reject vi khong verify duoc voi CA
            SSL_CTX* ctx = Network::createClientContext(
                Config::CA_CERT());
            SSL* ssl = Network::connectToServer(
                ctx, serverIP, Config::PORT_CHAT);
            if (!ssl) {
                cb("MITM Detection", false,
                    "Cannot connect to Chat Server");
                Network::freeContext(ctx);
                return;
            }

            Message req;
            req.type = MessageType::REGISTER_CERT;
            req.payload["username"] = "mitm_attacker";
            req.payload["cert"] = fakeCertPEM;
            req.payload["timestamp"] = Utils::getTimestamp();
            Protocol::sendMessage(ssl, req);

            Message resp = Protocol::recvMessage(ssl);
            int s = SSL_get_fd(ssl);
            Network::closeConnection(ssl, s);
            Network::freeContext(ctx);

            bool rejected = (resp.type == MessageType::ERROR_MSG);
            cb("MITM Detection", rejected,
                rejected
                ? "TEST PASSED - Fake cert rejected: " +
                resp.payload["reason"].get<std::string>()
                : "TEST FAILED - Fake cert was accepted!");
            }).detach();
    }

}