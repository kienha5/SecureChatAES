#define _CRT_SECURE_NO_WARNINGS

#include <openssl/applink.c>
#include "../Common/pch.h"
#include "../Common/utils.h"
#include "../Common/crypto.h"
#include "../Common/message.h"
#include "../Common/network.h"
#include "../Common/config.h"
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <map>
#include <mutex>

// ─── Global state ─────────────────────────────────────────────
static std::string g_intermCertPEM;
static std::string g_intermKeyPEM;
static std::string g_rootCACertPEM; // de verify + include trong chain

static int g_serialCounter = 2000; // bat dau tu 2000 tranh trung Root CA
static std::map<int, std::string> g_certDB;
static std::map<int, bool>        g_revokedDB;
static std::mutex g_dbMutex;

// ─── Save/Load DB ─────────────────────────────────────────────
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
    std::ofstream f(Config::INTERMED_CA_DB());
    f << j.dump(2);
}

void loadDB() {
    std::ifstream f(Config::INTERMED_CA_DB());
    if (!f.is_open()) {
        Utils::log(Utils::LogLevel::INFO,
            "IntermCA", "No DB, starting fresh");
        return;
    }
    try {
        json j = json::parse(f);
        std::lock_guard<std::mutex> lock(g_dbMutex);
        g_serialCounter = j["serial_counter"];
        for (auto& e : j["certs"]) {
            int s = e["serial"];
            g_certDB[s] = e["username"];
            g_revokedDB[s] = e["revoked"];
        }
        Utils::log(Utils::LogLevel::INFO, "IntermCA",
            "DB loaded: " + std::to_string(g_certDB.size()) + " certs");
    }
    catch (std::exception& e) {
        Utils::log(Utils::LogLevel::ERR, "IntermCA",
            std::string("Load DB failed: ") + e.what());
    }
}

// ─── Init: xin cert tu Root CA ────────────────────────────────
bool initIntermCA() {
    Config::ensureCertDir();

    // Thu load neu da co
    g_intermCertPEM = Utils::loadPEM(Config::INTERMED_CA_CERT());
    g_intermKeyPEM = Utils::loadPEM(Config::INTERMED_CA_KEY());
    g_rootCACertPEM = Utils::loadPEM(Config::CA_CERT());

    if (!g_intermCertPEM.empty() && !g_intermKeyPEM.empty()
        && !g_rootCACertPEM.empty()) {
        Utils::log(Utils::LogLevel::INFO,
            "IntermCA", "Loaded existing certs");
        loadDB();
        return true;
    }

    // Download Root CA cert
    if (g_rootCACertPEM.empty()) {
        Utils::log(Utils::LogLevel::INFO,
            "IntermCA", "Downloading Root CA cert...");
        SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);
        SSL* ssl = Network::connectToServer(
            ctx, "127.0.0.1", Config::PORT_CA);
        if (!ssl) {
            Utils::log(Utils::LogLevel::ERR,
                "IntermCA", "Cannot connect to Root CA!");
            SSL_CTX_free(ctx);
            return false;
        }
        Message req; req.type = MessageType::GET_CA_CERT;
        Protocol::sendMessage(ssl, req);
        Message resp = Protocol::recvMessage(ssl);
        if (resp.type == MessageType::CERT_RESPONSE) {
            g_rootCACertPEM = resp.payload["cert"];
            Utils::savePEM(Config::CA_CERT(), g_rootCACertPEM);
        }
        int s = SSL_get_fd(ssl);
        Network::closeConnection(ssl, s);
        SSL_CTX_free(ctx);
    }

    // Xin Root CA ky cert cho Intermediate CA
    Utils::log(Utils::LogLevel::INFO,
        "IntermCA", "Requesting CA cert from Root CA...");

    // Can Root CA key de ky — nhung Root CA key chi co tren Root CA
    // Nen phai xin Root CA ky qua network
    // Dung SIGN_CERT_REQ message type moi
    std::string rootCAKeyPEM = Utils::loadPEM(Config::CA_KEY());

    if (rootCAKeyPEM.empty()) {
        // Root CA key khong co tren may nay
        // Xin Root CA tu ky cho IntermCA qua requestCertFromCA
        bool ok = Crypto::requestCertFromCA(
            "SecureChat-IntermediateCA", 1825, // 5 nam
            "127.0.0.1", Config::PORT_CA,
            g_rootCACertPEM,
            g_intermCertPEM, g_intermKeyPEM
        );
        if (!ok) {
            Utils::log(Utils::LogLevel::ERR,
                "IntermCA", "Failed to get cert from Root CA");
            return false;
        }
    }
    else {
        // Co Root CA key -> tu ky CA cert
        bool ok = Crypto::generateCACert(
            "SecureChat-IntermediateCA", 1825,
            g_rootCACertPEM, rootCAKeyPEM,
            g_intermCertPEM, g_intermKeyPEM
        );
        if (!ok) return false;
    }

    Utils::savePEM(Config::INTERMED_CA_CERT(), g_intermCertPEM);
    Utils::savePEM(Config::INTERMED_CA_KEY(), g_intermKeyPEM);

    // Tao chain file: IntermCA cert + Root CA cert
    std::string chain = g_intermCertPEM + g_rootCACertPEM;
    Utils::savePEM(Config::CA_CHAIN(), chain);

    Utils::log(Utils::LogLevel::INFO,
        "IntermCA", "Intermediate CA ready");
    loadDB();
    return true;
}

// ─── Cap cert cho entity (RA, KDC, ChatServer, Client) ────────
std::string issueCert(const std::string& username,
    const std::string& pubKeyPEM) {
    BIO* cb = BIO_new_mem_buf(g_intermCertPEM.data(),
        (int)g_intermCertPEM.size());
    X509* caCert = PEM_read_bio_X509(cb, nullptr, nullptr, nullptr);
    BIO_free(cb);

    BIO* kb = BIO_new_mem_buf(g_intermKeyPEM.data(),
        (int)g_intermKeyPEM.size());
    EVP_PKEY* caKey = PEM_read_bio_PrivateKey(
        kb, nullptr, nullptr, nullptr);
    BIO_free(kb);

    BIO* pb = BIO_new_mem_buf(pubKeyPEM.data(),
        (int)pubKeyPEM.size());
    EVP_PKEY* clientPubKey = PEM_read_bio_PUBKEY(
        pb, nullptr, nullptr, nullptr);
    BIO_free(pb);

    if (!caCert || !caKey || !clientPubKey) return "";

    X509* cert = X509_new();
    int serial;
    {
        std::lock_guard<std::mutex> lock(g_dbMutex);
        serial = g_serialCounter++;
    }
    ASN1_INTEGER_set(X509_get_serialNumber(cert), serial);
    X509_gmtime_adj(X509_get_notBefore(cert), 0);
    X509_gmtime_adj(X509_get_notAfter(cert), 60LL * 60 * 24 * 365);

    X509_NAME* name = X509_get_subject_name(cert);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
        (unsigned char*)username.c_str(), -1, -1, 0);
    X509_set_issuer_name(cert,
        X509_get_subject_name(caCert));
    X509_set_pubkey(cert, clientPubKey);
    X509_sign(cert, caKey, EVP_sha256());

    BIO* out = BIO_new(BIO_s_mem());
    PEM_write_bio_X509(out, cert);
    BUF_MEM* optr;
    BIO_get_mem_ptr(out, &optr);
    std::string certPEM(optr->data, optr->length);
    BIO_free(out);

    {
        std::lock_guard<std::mutex> lock(g_dbMutex);
        g_certDB[serial] = username;
        g_revokedDB[serial] = false;
    }
    saveDB();

    Utils::auditLog("IntermCA", "CERT_ISSUED",
        "username=" + username +
        " serial=" + std::to_string(serial));

    X509_free(cert);
    EVP_PKEY_free(caKey);
    EVP_PKEY_free(clientPubKey);
    X509_free(caCert);
    return certPEM;
}

// ─── Handle client ────────────────────────────────────────────
void handleClient(SSL* ssl) {
    try {
        Message req = Protocol::recvMessage(ssl);

        if (req.type == MessageType::ISSUE_CERT_REQ) {
            std::string username = req.payload["username"];
            std::string pubKeyPEM = req.payload["public_key"];
            Utils::log(Utils::LogLevel::INFO, "IntermCA",
                "ISSUE_CERT_REQ for: " + username);

            std::string certPEM = issueCert(username, pubKeyPEM);
            Message resp;
            if (!certPEM.empty()) {
                resp.type = MessageType::CERT_RESPONSE;
                resp.payload["cert"] = certPEM;
                resp.payload["status"] = "OK";
                // Them ca chain de client verify
                resp.payload["chain"] =
                    g_intermCertPEM + g_rootCACertPEM;
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
            {
                std::lock_guard<std::mutex> lock(g_dbMutex);
                if (g_certDB.count(serial))
                    status = g_revokedDB[serial] ? "REVOKED" : "VALID";
            }
            Message resp;
            resp.type = MessageType::CERT_STATUS;
            resp.payload["serial"] = serial;
            resp.payload["status"] = status;
            Protocol::sendMessage(ssl, resp);
        }
        else if (req.type == MessageType::GET_INTERMED_CA_CERT) {
            // Tra ve IntermCA cert + chain
            Message resp;
            resp.type = MessageType::CERT_RESPONSE;
            resp.payload["cert"] = g_intermCertPEM;
            resp.payload["chain"] =
                g_intermCertPEM + g_rootCACertPEM;
            Protocol::sendMessage(ssl, resp);
        }
        else if (req.type == MessageType::REVOKE_CERT) {
            int serial = req.payload["serial"];
            bool found = false;
            std::string revokedUser;
            {
                std::lock_guard<std::mutex> lock(g_dbMutex);
                if (g_certDB.count(serial)) {
                    g_revokedDB[serial] = true;
                    found = true;
                    revokedUser = g_certDB[serial];
                }
            }
            if (found) {
                saveDB();
                Utils::auditLog("IntermCA", "CERT_REVOKED",
                    "username=" + revokedUser +
                    " serial=" + std::to_string(serial));
                Message resp;
                resp.type = MessageType::REVOKE_SUCCESS;
                resp.payload["serial"] = serial;
                resp.payload["username"] = revokedUser;
                resp.payload["status"] = "REVOKED";
                Protocol::sendMessage(ssl, resp);
            }
            else {
                Message err;
                err.type = MessageType::ERROR_MSG;
                err.payload["reason"] = "Serial not found";
                Protocol::sendMessage(ssl, err);
            }
        }
    }
    catch (std::exception& e) {
        Utils::log(Utils::LogLevel::ERR, "IntermCA",
            std::string("Exception: ") + e.what());
    }
    SSL_shutdown(ssl);
    SSL_free(ssl);
}

// ─── Main ─────────────────────────────────────────────────────
int main() {
    Utils::initAuditLog(Config::AUDIT_LOG_DIR());
    Utils::log(Utils::LogLevel::INFO, "IntermCA",
        "Starting Intermediate CA on port " +
        std::to_string(Config::PORT_INTERMED_CA) + "...");

    if (!initIntermCA()) {
        Utils::log(Utils::LogLevel::ERR,
            "IntermCA", "Init failed");
        return 1;
    }

    SSL_CTX* ctx = Network::createServerContext(
        Config::INTERMED_CA_CERT(),
        Config::INTERMED_CA_KEY());
    if (!ctx) return 1;

    int serverSock = Network::createServerSocket(
        Config::PORT_INTERMED_CA);
    if (serverSock < 0) return 1;

    Utils::log(Utils::LogLevel::INFO, "IntermCA",
        "Intermediate CA ready. Waiting for connections...");

    while (true) {
        int clientSock = 0;
        SSL* ssl = Network::acceptClient(
            ctx, serverSock, clientSock);
        if (!ssl) continue;
        std::thread t(handleClient, ssl);
        t.detach();
    }

    Network::freeContext(ctx);
    return 0;
}