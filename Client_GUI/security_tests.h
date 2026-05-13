#pragma once
#include <string>
#include <functional>

// Callback để hiển thị kết quả trong GUI
using TestResultCallback = std::function<void(
    const std::string& testName,
    bool passed,
    const std::string& detail)>;

namespace SecurityTests {

    // ─── Test 1: Replay Attack ─────────────────────────────────
    // Gửi nonce cũ đến RA, kết quả phải bị reject
    void testReplayAttack(
        const std::string& username,
        const std::string& serverIP,
        TestResultCallback cb);

    // ─── Test 2: Wrong Password ────────────────────────────────
    // Dùng sai password, TGT decrypt phải fail
    void testWrongPassword(
        const std::string& username,
        const std::string& serverIP,
        TestResultCallback cb);

    // ─── Test 3: Expired Ticket ────────────────────────────────
    // Đổi ticket hết hạn rồi login, phải bị reject
    // Cần KDC chạy với lifetime ngắn (test mode)
    void testExpiredTicket(
        const std::string& username,
        const std::string& password,
        const std::string& serverIP,
        int lifetimeSeconds,
        TestResultCallback cb);

    // ─── Test 4: Revoked Certificate ──────────────────────────
    // Revoke cert rồi thử đăng ký account, phải bị reject
    void testRevokedCert(
        const std::string& username,
        const std::string& serverIP,
        int certSerial,
        TestResultCallback cb);

    // ─── Test 5: Chain Validation ─────────────────────────────
    // Verify cert chain: client cert -> IntermCA -> RootCA
    void testChainValidation(
        const std::string& username,
        TestResultCallback cb);

    // ─── Test 6: MITM Detection ────────────────────────────────
    // Thử dùng cert giả (tự ký, không có CA), phải bị reject
    void testMITMDetection(
        const std::string& serverIP,
        TestResultCallback cb);
}