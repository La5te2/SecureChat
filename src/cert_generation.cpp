// 证书生成实现。
// 当前只实现本地/局域网 WSS 证书；该模块不申请公网域名证书。
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <windows.h>
#else
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <unistd.h>
#endif

#include "cert_generation.hpp"

#include <cstdlib>
#include <filesystem>
#include <memory>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509v3.h>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace chat::certs {
namespace {
constexpr const char* defaultTlsAutoDir = "certs";
constexpr const char* localCaKeyName = "local-root-ca-key.pem";
constexpr const char* localCaCertName = "local-root-ca.pem";
constexpr const char* localServerKeyName = "server-key.pem";
constexpr const char* localServerCertName = "server-cert.pem";
constexpr const char* localServerChainName = "server-chain.pem";

using EvpPkeyPtr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using EvpPkeyCtxPtr = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>;
using X509Ptr = std::unique_ptr<X509, decltype(&X509_free)>;
using BioPtr = std::unique_ptr<BIO, decltype(&BIO_free)>;

std::string envValue(const char* name) {
    const char* value = std::getenv(name);
    return value == nullptr ? std::string() : std::string(value);
}

std::filesystem::path pathFromUtf8(const std::string& value) {
    return std::filesystem::u8path(value);
}

std::string pathToUtf8(const std::filesystem::path& path) {
    return path.u8string();
}

bool fileExists(const std::filesystem::path& path) {
    std::error_code ec;
    return std::filesystem::is_regular_file(path, ec);
}

void ensureDirectory(const std::filesystem::path& dir) {
    std::error_code ec;
    std::filesystem::create_directories(dir, ec);
    if (ec) {
        throw std::runtime_error("failed to create TLS directory: " + pathToUtf8(dir) + ": " + ec.message());
    }
}

void restrictPrivateFile(const std::filesystem::path& path) {
#ifndef _WIN32
    std::error_code ec;
    std::filesystem::permissions(
        path,
        std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
        std::filesystem::perm_options::replace,
        ec);
    if (ec) {
        throw std::runtime_error("failed to restrict private key permissions: " + ec.message());
    }
#else
    (void)path;
#endif
}

std::string localHostname() {
#ifdef _WIN32
    char name[MAX_COMPUTERNAME_LENGTH + 1] = {};
    DWORD size = static_cast<DWORD>(sizeof(name));
    if (GetComputerNameA(name, &size) != 0 && size > 0) {
        return std::string(name, size);
    }
    return "";
#else
    char name[256] = {};
    if (gethostname(name, sizeof(name) - 1) == 0) {
        return std::string(name);
    }
    return "";
#endif
}

void addLocalInterfaceIps(std::set<std::string>& ips) {
#ifdef _WIN32
    ULONG flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
    ULONG size = 15 * 1024;
    std::vector<unsigned char> buffer(size);
    auto* adapters = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data());
    ULONG result = GetAdaptersAddresses(AF_UNSPEC, flags, nullptr, adapters, &size);
    if (result == ERROR_BUFFER_OVERFLOW) {
        buffer.resize(size);
        adapters = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data());
        result = GetAdaptersAddresses(AF_UNSPEC, flags, nullptr, adapters, &size);
    }
    if (result != NO_ERROR) return;

    for (auto* adapter = adapters; adapter != nullptr; adapter = adapter->Next) {
        if (adapter->OperStatus != IfOperStatusUp || adapter->IfType == IF_TYPE_SOFTWARE_LOOPBACK) continue;
        for (auto* addr = adapter->FirstUnicastAddress; addr != nullptr; addr = addr->Next) {
            const auto* sockaddr = addr->Address.lpSockaddr;
            if (sockaddr == nullptr) continue;
            char text[INET6_ADDRSTRLEN] = {};
            if (sockaddr->sa_family == AF_INET) {
                const auto* in = reinterpret_cast<const sockaddr_in*>(sockaddr);
                if (InetNtopA(AF_INET, const_cast<IN_ADDR*>(&in->sin_addr), text, sizeof(text)) != nullptr) {
                    std::string value(text);
                    if (value.rfind("127.", 0) != 0) ips.insert(std::move(value));
                }
            }
            else if (sockaddr->sa_family == AF_INET6) {
                const auto* in6 = reinterpret_cast<const sockaddr_in6*>(sockaddr);
                if (InetNtopA(AF_INET6, const_cast<IN6_ADDR*>(&in6->sin6_addr), text, sizeof(text)) != nullptr) {
                    std::string value(text);
                    if (value != "::1" && value.rfind("fe80", 0) != 0) ips.insert(std::move(value));
                }
            }
        }
    }
#else
    ifaddrs* raw = nullptr;
    if (getifaddrs(&raw) != 0 || raw == nullptr) return;
    std::unique_ptr<ifaddrs, decltype(&freeifaddrs)> addresses(raw, freeifaddrs);
    for (auto* item = addresses.get(); item != nullptr; item = item->ifa_next) {
        if (item->ifa_addr == nullptr) continue;
        if ((item->ifa_flags & IFF_UP) == 0 || (item->ifa_flags & IFF_LOOPBACK) != 0) continue;
        char text[INET6_ADDRSTRLEN] = {};
        if (item->ifa_addr->sa_family == AF_INET) {
            const auto* in = reinterpret_cast<const sockaddr_in*>(item->ifa_addr);
            if (inet_ntop(AF_INET, &in->sin_addr, text, sizeof(text)) != nullptr) {
                std::string value(text);
                if (value.rfind("127.", 0) != 0) ips.insert(std::move(value));
            }
        }
        else if (item->ifa_addr->sa_family == AF_INET6) {
            const auto* in6 = reinterpret_cast<const sockaddr_in6*>(item->ifa_addr);
            if (inet_ntop(AF_INET6, &in6->sin6_addr, text, sizeof(text)) != nullptr) {
                std::string value(text);
                if (value != "::1" && value.rfind("fe80", 0) != 0) ips.insert(std::move(value));
            }
        }
    }
#endif
}

EvpPkeyPtr generateRsaKey(int bits) {
    EvpPkeyCtxPtr ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr), EVP_PKEY_CTX_free);
    EVP_PKEY* raw = nullptr;
    if (!ctx ||
        EVP_PKEY_keygen_init(ctx.get()) != 1 ||
        EVP_PKEY_CTX_set_rsa_keygen_bits(ctx.get(), bits) != 1 ||
        EVP_PKEY_keygen(ctx.get(), &raw) != 1) {
        throw std::runtime_error("failed to generate local TLS RSA key");
    }
    return EvpPkeyPtr(raw, EVP_PKEY_free);
}

void addNameEntry(X509_NAME* name, const char* field, const std::string& value) {
    if (X509_NAME_add_entry_by_txt(
            name,
            field,
            MBSTRING_ASC,
            reinterpret_cast<const unsigned char*>(value.data()),
            static_cast<int>(value.size()),
            -1,
            0) != 1) {
        throw std::runtime_error(std::string("failed to set certificate subject field: ") + field);
    }
}

void addExtension(X509* cert, X509* issuer, int nid, const std::string& value) {
    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, issuer, cert, nullptr, nullptr, 0);
    X509_EXTENSION* raw = X509V3_EXT_conf_nid(nullptr, &ctx, nid, value.c_str());
    if (raw == nullptr) {
        throw std::runtime_error("failed to add certificate extension: " + value);
    }
    std::unique_ptr<X509_EXTENSION, decltype(&X509_EXTENSION_free)> ext(raw, X509_EXTENSION_free);
    if (X509_add_ext(cert, ext.get(), -1) != 1) {
        throw std::runtime_error("failed to attach certificate extension: " + value);
    }
}

X509Ptr createLocalCaCertificate(EVP_PKEY* caKey) {
    X509Ptr cert(X509_new(), X509_free);
    if (!cert) throw std::runtime_error("failed to allocate local TLS CA certificate");
    X509_set_version(cert.get(), 2);
    ASN1_INTEGER_set(X509_get_serialNumber(cert.get()), 1);
    X509_gmtime_adj(X509_get_notBefore(cert.get()), 0);
    X509_gmtime_adj(X509_get_notAfter(cert.get()), 10L * 365 * 24 * 60 * 60);
    if (X509_set_pubkey(cert.get(), caKey) != 1) {
        throw std::runtime_error("failed to set local TLS CA public key");
    }
    auto* subject = X509_get_subject_name(cert.get());
    addNameEntry(subject, "CN", "SecureChat Local WSS Root CA");
    if (X509_set_issuer_name(cert.get(), subject) != 1) {
        throw std::runtime_error("failed to set local TLS CA issuer");
    }
    addExtension(cert.get(), cert.get(), NID_basic_constraints, "critical,CA:TRUE");
    addExtension(cert.get(), cert.get(), NID_key_usage, "critical,keyCertSign,cRLSign");
    addExtension(cert.get(), cert.get(), NID_subject_key_identifier, "hash");
    if (X509_sign(cert.get(), caKey, EVP_sha256()) <= 0) {
        throw std::runtime_error("failed to sign local TLS CA certificate");
    }
    return cert;
}

std::string joinSubjectAltNames(const std::set<std::string>& dnsNames, const std::set<std::string>& ipNames) {
    std::vector<std::string> parts;
    for (const auto& name : dnsNames) parts.push_back("DNS:" + name);
    for (const auto& ip : ipNames) parts.push_back("IP:" + ip);
    std::ostringstream out;
    for (std::size_t i = 0; i < parts.size(); ++i) {
        if (i > 0) out << ",";
        out << parts[i];
    }
    return out.str();
}

X509Ptr createLocalServerCertificate(EVP_PKEY* serverKey, X509* caCert, EVP_PKEY* caKey) {
    std::set<std::string> dnsNames{"localhost"};
    std::set<std::string> ipNames{"127.0.0.1", "::1"};
    const auto host = localHostname();
    if (!host.empty() && host != "localhost") dnsNames.insert(host);
    addLocalInterfaceIps(ipNames);

    X509Ptr cert(X509_new(), X509_free);
    if (!cert) throw std::runtime_error("failed to allocate local TLS server certificate");
    X509_set_version(cert.get(), 2);
    ASN1_INTEGER_set(X509_get_serialNumber(cert.get()), 2);
    X509_gmtime_adj(X509_get_notBefore(cert.get()), 0);
    X509_gmtime_adj(X509_get_notAfter(cert.get()), 825L * 24 * 60 * 60);
    if (X509_set_pubkey(cert.get(), serverKey) != 1) {
        throw std::runtime_error("failed to set local TLS server public key");
    }
    auto* subject = X509_get_subject_name(cert.get());
    addNameEntry(subject, "CN", "SecureChat Local WSS");
    if (X509_set_issuer_name(cert.get(), X509_get_subject_name(caCert)) != 1) {
        throw std::runtime_error("failed to set local TLS server issuer");
    }
    addExtension(cert.get(), caCert, NID_basic_constraints, "CA:FALSE");
    addExtension(cert.get(), caCert, NID_key_usage, "digitalSignature,keyEncipherment");
    addExtension(cert.get(), caCert, NID_ext_key_usage, "serverAuth");
    addExtension(cert.get(), caCert, NID_subject_alt_name, joinSubjectAltNames(dnsNames, ipNames));
    if (X509_sign(cert.get(), caKey, EVP_sha256()) <= 0) {
        throw std::runtime_error("failed to sign local TLS server certificate");
    }
    return cert;
}

BioPtr openBioFileForWrite(const std::filesystem::path& path) {
    BioPtr file(BIO_new_file(pathToUtf8(path).c_str(), "wb"), BIO_free);
    if (!file) {
        throw std::runtime_error("failed to open file for writing: " + pathToUtf8(path));
    }
    return file;
}

void writePrivateKey(const std::filesystem::path& path, EVP_PKEY* key) {
    // Windows 下 OpenSSL 需要使用 BIO 文件接口；直接传 CRT FILE*
    // 给 PEM_write_* 可能触发 OPENSSL_Applink 错误。
    auto file = openBioFileForWrite(path);
    if (PEM_write_bio_PrivateKey(file.get(), key, nullptr, nullptr, 0, nullptr, nullptr) != 1) {
        throw std::runtime_error("failed to write private key: " + pathToUtf8(path));
    }
    file.reset();
    restrictPrivateFile(path);
}

void writeCertificate(const std::filesystem::path& path, X509* cert) {
    auto file = openBioFileForWrite(path);
    if (PEM_write_bio_X509(file.get(), cert) != 1) {
        throw std::runtime_error("failed to write certificate: " + pathToUtf8(path));
    }
}

void writeCertificateChain(const std::filesystem::path& path, X509* leaf, X509* ca) {
    auto file = openBioFileForWrite(path);
    if (PEM_write_bio_X509(file.get(), leaf) != 1 || PEM_write_bio_X509(file.get(), ca) != 1) {
        throw std::runtime_error("failed to write certificate chain: " + pathToUtf8(path));
    }
}

ServerTlsMaterial ensureLocalTlsMaterial() {
    const auto dirValue = envValue("SECURECHAT_TLS_AUTO_DIR");
    const auto dir = pathFromUtf8(dirValue.empty() ? defaultTlsAutoDir : dirValue);
    const auto caKeyPath = dir / localCaKeyName;
    const auto caCertPath = dir / localCaCertName;
    const auto serverKeyPath = dir / localServerKeyName;
    const auto serverCertPath = dir / localServerCertName;
    const auto serverChainPath = dir / localServerChainName;

    if (fileExists(caCertPath) && fileExists(serverKeyPath) && fileExists(serverChainPath)) {
        return {
            pathToUtf8(serverChainPath),
            pathToUtf8(serverKeyPath),
            pathToUtf8(caCertPath),
            false,
            true};
    }

    ensureDirectory(dir);
    // 环境变量为空时才走本地开发证书路径。这里不会读取 certs/fullchain.pem，
    // 避免 Windows 本地启动误用云端域名证书。
    auto caKey = generateRsaKey(3072);
    auto caCert = createLocalCaCertificate(caKey.get());
    auto serverKey = generateRsaKey(2048);
    auto serverCert = createLocalServerCertificate(serverKey.get(), caCert.get(), caKey.get());

    writePrivateKey(caKeyPath, caKey.get());
    writeCertificate(caCertPath, caCert.get());
    writePrivateKey(serverKeyPath, serverKey.get());
    writeCertificate(serverCertPath, serverCert.get());
    writeCertificateChain(serverChainPath, serverCert.get(), caCert.get());

    return {
        pathToUtf8(serverChainPath),
        pathToUtf8(serverKeyPath),
        pathToUtf8(caCertPath),
        true,
        false};
}

}

ServerTlsMaterial resolveServerTlsMaterial() {
    const auto certFile = envValue("SECURECHAT_TLS_CERT_FILE");
    const auto keyFile = envValue("SECURECHAT_TLS_KEY_FILE");
    if (!certFile.empty() && !keyFile.empty()) {
        return {certFile, keyFile, "", false, false};
    }
    if (!certFile.empty() || !keyFile.empty()) {
        throw std::runtime_error("SECURECHAT_TLS_CERT_FILE and SECURECHAT_TLS_KEY_FILE must be set together");
    }
    return ensureLocalTlsMaterial();
}

}
