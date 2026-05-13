#define _CRT_SECURE_NO_WARNINGS

#include <openssl/applink.c>
#include "../Common/pch.h"
#include "../Common/utils.h"
#include "../Common/crypto.h"
#include "../Common/message.h"
#include "../Common/network.h"
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <map>
#include <mutex>

// ─── Global state ─────────────────────────────────────────────
static std::string g_caCertPEM;   // CA cert (PEM)
static std::string g_caKeyPEM;    // CA private key (PEM)
static int g_serialCounter = 1;
static std::map<int, std::string> g_certDB;   // serial → username
static std::map<int, bool>        g_revokedDB; // serial → revoked
static std::mutex g_dbMutex;

// ─── File paths ───────────────────────────────────────────────
static const std::string DB_FILE = Config::CA_DB();

// ─── Luu DB ra file ───────────────────────────────────────────
void saveDB() {
    std::lock_guard<std::mutex> lock(g_dbMutex);
    json j;
    j["serial_counter"] = g_serialCounter;

    json certs = json::array();
    for (auto& [serial, username] : g_certDB) {
        json entry;
        entry["serial"] = serial;
        entry["username"] = username;
        entry["revoked"] = g_revokedDB[serial];
        certs.push_back(entry);
    }
    j["certs"] = certs;

    std::ofstream f(DB_FILE);
    f << j.dump(2);
    Utils::log(Utils::LogLevel::INFO, "CA", "DB saved to " + DB_FILE);
}

// ─── Load DB tu file ──────────────────────────────────────────
void loadDB() {
    std::ifstream f(DB_FILE);
    if (!f.is_open()) {
        Utils::log(Utils::LogLevel::INFO, "CA", "No DB file found, starting fresh");
        return;
    }

    try {
        json j = json::parse(f);
        std::lock_guard<std::mutex> lock(g_dbMutex);

        g_serialCounter = j["serial_counter"];
        for (auto& entry : j["certs"]) {
            int serial = entry["serial"];
            g_certDB[serial] = entry["username"];
            g_revokedDB[serial] = entry["revoked"];
        }
        Utils::log(Utils::LogLevel::INFO, "CA",
            "DB loaded: " + std::to_string(g_certDB.size()) + " certs");
    }
    catch (std::exception& e) {
        Utils::log(Utils::LogLevel::ERR, "CA",
            "Failed to load DB: " + std::string(e.what()));
    }
}

// ─── Load CA cert + key từ file ───────────────────────────────
bool initCA() {
    Config::ensureCertDir();
    std::string certPEM, keyPEM;

    // Self-signed: khong can CA ben ngoai
    bool ok = Crypto::loadOrCreate(
        Config::CA_CERT(), Config::CA_KEY(),
        "SecureChat-CA", 3650,  // 10 nam
        "", "",                  // self-signed
        certPEM, keyPEM
    );
    if (!ok) return false;

    g_caCertPEM = certPEM;
    g_caKeyPEM = keyPEM;
    loadDB();
    Utils::log(Utils::LogLevel::INFO, "CA", "CA ready");
    return true;
}

// ─── Tạo X.509 cert cho client ────────────────────────────────
std::string issueCert(const std::string& username, const std::string& pubKeyPEM) {
    // Load CA cert
    BIO* cb = BIO_new_mem_buf(g_caCertPEM.data(), (int)g_caCertPEM.size());
    X509* caCert = PEM_read_bio_X509(cb, nullptr, nullptr, nullptr);
    BIO_free(cb);

    // Load CA key
    BIO* kb = BIO_new_mem_buf(g_caKeyPEM.data(), (int)g_caKeyPEM.size());
    EVP_PKEY* caKey = PEM_read_bio_PrivateKey(kb, nullptr, nullptr, nullptr);
    BIO_free(kb);

    // Load client public key
    BIO* pb = BIO_new_mem_buf(pubKeyPEM.data(), (int)pubKeyPEM.size());
    EVP_PKEY* clientPubKey = PEM_read_bio_PUBKEY(pb, nullptr, nullptr, nullptr);
    BIO_free(pb);

    if (!caCert || !caKey || !clientPubKey) {
        Utils::log(Utils::LogLevel::ERR, "CA", "Failed to load keys for cert issuance");
        return "";
    }

    // Tạo cert mới
    X509* cert = X509_new();

    // --- LOCK 1: Lấy serial number an toàn ---
    int serial;
    {
        std::lock_guard<std::mutex> lock(g_dbMutex);
        serial = g_serialCounter++;
    }

    ASN1_INTEGER_set(X509_get_serialNumber(cert), serial);

    // Validity: 365 ngày
    X509_gmtime_adj(X509_get_notBefore(cert), 0);
    X509_gmtime_adj(X509_get_notAfter(cert), 60 * 60 * 24 * 365);

    // Subject: CN=username
    X509_NAME* name = X509_get_subject_name(cert);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
        (unsigned char*)username.c_str(), -1, -1, 0);

    // Issuer = CA subject
    X509_set_issuer_name(cert, X509_get_subject_name(caCert));

    // Set public key
    X509_set_pubkey(cert, clientPubKey);

    // Ký bằng CA key
    X509_sign(cert, caKey, EVP_sha256());

    // Serialize sang PEM
    BIO* out = BIO_new(BIO_s_mem());
    PEM_write_bio_X509(out, cert);
    BUF_MEM* optr;
    BIO_get_mem_ptr(out, &optr);
    std::string certPEM(optr->data, optr->length);
    BIO_free(out);

    // --- LOCK 2: Cập nhật CSDL trong RAM ---
    {
        std::lock_guard<std::mutex> lock(g_dbMutex);
        g_certDB[serial] = username;
        g_revokedDB[serial] = false;
    }

	// --- Ghi log audit (không cần lock vì chỉ đọc serial và username) ---
    Utils::auditLog("CA", "CERT_ISSUED",   
        "username=" + username +
        " serial=" + std::to_string(serial));

    // --- Ghi ra file mà KHÔNG giữ lock của hàm này (vì saveDB đã tự lock) ---
    saveDB();

    Utils::log(Utils::LogLevel::INFO, "CA",
        "Issued cert for [" + username + "] serial=" + std::to_string(serial));

    X509_free(cert);
    EVP_PKEY_free(caKey);
    EVP_PKEY_free(clientPubKey);
    X509_free(caCert);

    return certPEM;
}

// ─── Xử lý 1 client (chạy trong thread) ──────────────────────
void handleClient(SSL* ssl) {
    try {
        Message req = Protocol::recvMessage(ssl);

        if (req.type == MessageType::ISSUE_CERT_REQ) {
            std::string username = req.payload["username"];
            std::string pubKeyPEM = req.payload["public_key"];

            Utils::log(Utils::LogLevel::INFO, "CA",
                "ISSUE_CERT_REQ from RA for user: " + username);

            std::string certPEM = issueCert(username, pubKeyPEM);

            Message resp;
            if (!certPEM.empty()) {
                resp.type = MessageType::CERT_RESPONSE;
                resp.payload["cert"] = certPEM;
                resp.payload["status"] = "OK";
            }
            else {
                resp.type = MessageType::ERROR_MSG;
                resp.payload["reason"] = "Cert issuance failed";
            }
            Protocol::sendMessage(ssl, resp);
        }

        else if (req.type == MessageType::VERIFY_CERT) {
            int serial = req.payload["serial"];
            std::string status = "UNKNOWN";

            // Lock chỉ để đọc trạng thái
            {
                std::lock_guard<std::mutex> lock(g_dbMutex);
                if (g_certDB.count(serial)) {
                    status = g_revokedDB[serial] ? "REVOKED" : "VALID";
                }
            }

			// Ghi log audit về việc verify (chỉ có serial và status, không cần lock nữa)
            Utils::auditLog("CA", "CERT_VERIFIED",
                "serial=" + std::to_string(serial) +
                " status=" + status);

            Utils::log(Utils::LogLevel::INFO, "CA",
                "VERIFY_CERT serial=" + std::to_string(serial) + " → " + status);

            Message resp;
            resp.type = MessageType::CERT_STATUS;
            resp.payload["serial"] = serial;
            resp.payload["status"] = status;
            Protocol::sendMessage(ssl, resp);
        }

        else if (req.type == MessageType::REVOKE_CERT) {
            int serial = req.payload["serial"];
            bool found = false;
            std::string revokedUser;

            // --- LOCK 1: Cập nhật trạng thái revoke trong RAM ---
            {
                std::lock_guard<std::mutex> lock(g_dbMutex);
                if (g_certDB.count(serial)) {
                    g_revokedDB[serial] = true;
                    found = true;
                    revokedUser = g_certDB[serial];
                }
            }

            // --- Xử lý việc lưu và gửi tin nhắn ở NGOÀI lock ---
            if (found) {
				// Ghi log audit về việc revoke (đã có serial và username từ RAM, nên không cần lock nữa)
                Utils::auditLog("CA", "CERT_REVOKED",  
                    "username=" + revokedUser +
                    " serial=" + std::to_string(serial));

                saveDB(); // Persist an toàn (không bị deadlock)
                Utils::log(Utils::LogLevel::WARN, "CA",
                    "Cert REVOKED: serial=" + std::to_string(serial) +
                    " username=" + revokedUser);

                Message resp;
                resp.type = MessageType::REVOKE_SUCCESS;
                resp.payload["serial"] = serial;
                resp.payload["username"] = revokedUser;
                resp.payload["status"] = "REVOKED";
                Protocol::sendMessage(ssl, resp);
            }
            else {
                Utils::log(Utils::LogLevel::WARN, "CA",
                    "Revoke failed - serial not found: " + std::to_string(serial));
                Message err; err.type = MessageType::ERROR_MSG;
                err.payload["reason"] = "Serial not found";
                Protocol::sendMessage(ssl, err);
            }
        }

        else if (req.type == MessageType::GET_CA_CERT) {
            Utils::log(Utils::LogLevel::INFO, "CA",
                "Sending CA cert to requester");
            Message resp;
            resp.type = MessageType::CERT_RESPONSE;
            resp.payload["cert"] = g_caCertPEM;
            Protocol::sendMessage(ssl, resp);
        }
    }
    catch (std::exception& e) {
        Utils::log(Utils::LogLevel::ERR, "CA", std::string("Exception: ") + e.what());
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
}

// ─── Main ─────────────────────────────────────────────────────
int main() {
    Utils::initAuditLog(Config::AUDIT_LOG_DIR());

    Utils::log(Utils::LogLevel::INFO, "CA",
        "Starting CA Server on port " +
        std::to_string(Config::PORT_CA) + "...");

    if (!initCA()) {
        Utils::log(Utils::LogLevel::ERR, "CA", "Init failed");
        return 1;
    }

    SSL_CTX* ctx = Network::createServerContext(
        Config::CA_CERT(), Config::CA_KEY());
    if (!ctx) return 1;

    int serverSock = Network::createServerSocket(Config::PORT_CA);
    if (serverSock < 0) return 1;

    Utils::log(Utils::LogLevel::INFO, "CA",
        "CA Server ready. Waiting for connections...");

    while (true) {
        int clientSock = 0;
        SSL* ssl = Network::acceptClient(ctx, serverSock, clientSock);
        if (!ssl) continue;
        std::thread t(handleClient, ssl);
        t.detach();
    }
    Network::freeContext(ctx);
    return 0;
}