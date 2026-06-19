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
#include "cert_utils.hpp"

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iomanip>
#include <memory>
#include <openssl/buffer.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/x509v3.h>
#include <argon2.h>
#include <nlohmann/json.hpp>
#include <algorithm>
#include <array>
#include <cctype>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace chat::certs {
namespace {
using json = nlohmann::json;
using chat::cert_utils::appendCanonicalField;
using chat::cert_utils::base64Decode;
using chat::cert_utils::base64Encode;
using chat::cert_utils::hexEncode;
using chat::cert_utils::randomBytes;
using chat::cert_utils::sha256Hex;
using chat::cert_utils::signBytes;
using chat::cert_utils::verifyBytes;

constexpr const char* defaultTlsAutoDir = "certs";
constexpr const char* localCaKeyName = "local-root-ca-key.pem";
constexpr const char* localCaCertName = "local-root-ca.pem";
constexpr const char* localServerKeyName = "server-key.pem";
constexpr const char* localServerCertName = "server-cert.pem";
constexpr const char* localServerChainName = "server-chain.pem";
constexpr const char* entranceMagic = "SECURECHAT_SCP";
constexpr const char* admissionMagic = "SECURECHAT_ADMISSION";
constexpr std::size_t admissionKeyBytes = 32;
constexpr std::size_t admissionNonceBytes = 12;
constexpr std::size_t admissionTagBytes = 16;

using EvpPkeyPtr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using EvpPkeyCtxPtr = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>;
using EvpCipherCtxPtr = std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>;
using X509Ptr = std::unique_ptr<X509, decltype(&X509_free)>;
using X509ReqPtr = std::unique_ptr<X509_REQ, decltype(&X509_REQ_free)>;
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
            MBSTRING_UTF8,
            reinterpret_cast<const unsigned char*>(value.data()),
            static_cast<int>(value.size()),
            -1,
            0) != 1) {
        throw std::runtime_error(std::string("failed to set certificate subject field: ") + field);
    }
}

void addNameEntryIfNotEmpty(X509_NAME* name, const char* field, const std::string& value) {
    if (!value.empty()) addNameEntry(name, field, value);
}

std::string truncateSubjectValue(const std::string& value, std::size_t maxSize = 60) {
    if (value.size() <= maxSize) return value;
    return value.substr(0, maxSize);
}

void addSecureChatSubjectFields(
    X509_NAME* subject,
    const std::string& roomInstanceTokenDigest,
    const std::string& role,
    const std::string& deviceName) {
    // 房间级证书把项目、房间实例摘要、角色和设备名写入 X.509 subject。
    // openssl x509 -text 可以直接看到这些字段，便于审计证书是否属于当前房间。
    addNameEntry(subject, "O", "SecureChat");
    addNameEntryIfNotEmpty(subject, "serialNumber", roomInstanceTokenDigest);
    addNameEntryIfNotEmpty(subject, "OU", "Role:" + truncateSubjectValue(role));
    addNameEntryIfNotEmpty(subject, "OU", "Device:" + truncateSubjectValue(deviceName));
}

std::string roomCertificateComment(
    const std::string& roomInstanceTokenDigest,
    const std::string& roomInstanceId,
    const std::string& role) {
    // 这里保留 ASCII 内容，避免不同 OpenSSL 版本解析 nsComment 时受编码影响。
    return "SecureChat roomInstanceTokenDigest=" + roomInstanceTokenDigest +
        "; roomInstanceId=" + roomInstanceId +
        "; role=" + role;
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

std::string certFingerprint(X509* cert) {
    unsigned char digest[SHA256_DIGEST_LENGTH] = {};
    unsigned int digestSize = 0;
    if (X509_digest(cert, EVP_sha256(), digest, &digestSize) != 1) {
        throw std::runtime_error("certificate fingerprint failed");
    }
    return hexEncode(digest, digestSize);
}

std::string publicKeyFingerprint(EVP_PKEY* key) {
    int size = i2d_PUBKEY(key, nullptr);
    if (size <= 0) throw std::runtime_error("public key serialization failed");
    std::vector<unsigned char> der(static_cast<std::size_t>(size));
    unsigned char* cursor = der.data();
    if (i2d_PUBKEY(key, &cursor) != size) throw std::runtime_error("public key DER encoding failed");
    return sha256Hex(der.data(), der.size());
}

std::string deriveRoomInstanceToken(
    const std::string& canonicalName,
    const std::string& roomInstanceId,
    const std::string& admissionSecret,
    const std::string& rootPublicKeyFingerprint,
    const std::string& intermediatePublicKeyFingerprint,
    const std::string& hostPublicKeyFingerprint) {
    // token 绑定房间名、一次性随机材料和房间级 CA/Host 公钥。
    // 绑定公钥而不是证书指纹，可以让证书本体安全地写入 token 摘要。
    return sha256Hex(
        "securechat-room-instance-v2|" +
        canonicalName + "|" +
        roomInstanceId + "|" +
        admissionSecret + "|" +
        rootPublicKeyFingerprint + "|" +
        intermediatePublicKeyFingerprint + "|" +
        hostPublicKeyFingerprint);
}

std::string canonicalRoomDescriptor(const json& descriptor) {
    // 只签名房间身份和证书绑定字段，signature 本身不进入签名字节串。
    std::string out = "securechat-room-descriptor-v1\n";
    appendCanonicalField(out, "roomName", descriptor.value("roomName", ""));
    appendCanonicalField(out, "canonicalRoomName", descriptor.value("canonicalRoomName", ""));
    appendCanonicalField(out, "roomInstanceId", descriptor.value("roomInstanceId", ""));
    appendCanonicalField(out, "roomInstanceTokenDigest", descriptor.value("roomInstanceTokenDigest", ""));
    appendCanonicalField(out, "rootFingerprint", descriptor.value("rootFingerprint", ""));
    appendCanonicalField(out, "intermediateFingerprint", descriptor.value("intermediateFingerprint", ""));
    appendCanonicalField(out, "hostFingerprint", descriptor.value("hostFingerprint", ""));
    appendCanonicalField(out, "rootPublicKeyFingerprint", descriptor.value("rootPublicKeyFingerprint", ""));
    appendCanonicalField(out, "intermediatePublicKeyFingerprint", descriptor.value("intermediatePublicKeyFingerprint", ""));
    appendCanonicalField(out, "hostPublicKeyFingerprint", descriptor.value("hostPublicKeyFingerprint", ""));
    appendCanonicalField(out, "hostName", descriptor.value("hostName", ""));
    appendCanonicalField(out, "hostDevice", descriptor.value("hostDevice", ""));
    return out;
}

std::string canonicalCsrBundle(const json& bundle) {
    // CSR 绑定证明由成员本机私钥签名，Host 签发前必须验证。
    std::string out = "securechat-room-csr-v1\n";
    appendCanonicalField(out, "roomInstanceTokenDigest", bundle.value("roomInstanceTokenDigest", ""));
    appendCanonicalField(out, "username", bundle.value("username", ""));
    appendCanonicalField(out, "deviceName", bundle.value("deviceName", ""));
    appendCanonicalField(out, "csrSha256", bundle.value("csrSha256", ""));
    appendCanonicalField(out, "publicKeyFingerprint", bundle.value("publicKeyFingerprint", ""));
    appendCanonicalField(out, "nonce", bundle.value("nonce", ""));
    return out;
}

std::string canonicalSignResponse(const json& response) {
    std::string out = "securechat-room-sign-response-v1\n";
    appendCanonicalField(out, "roomInstanceTokenDigest", response.value("roomInstanceTokenDigest", ""));
    appendCanonicalField(out, "username", response.value("username", ""));
    appendCanonicalField(out, "csrSha256", response.value("csrSha256", ""));
    appendCanonicalField(out, "memberFingerprint", response.value("memberFingerprint", ""));
    appendCanonicalField(out, "issuerFingerprint", response.value("issuerFingerprint", ""));
    appendCanonicalField(out, "nonce", response.value("nonce", ""));
    return out;
}

std::string canonicalPendingJoinProof(const json& proof) {
    // 该证明把未签发成员证书前的 CSR 私钥绑定到本次 join_room 临时 X25519 公钥。
    // Host 签发成员证书前验证它，避免 Server 或中间人替换 X25519 公钥。
    std::string out = "securechat-room-pending-join-v1\n";
    appendCanonicalField(out, "roomInstanceTokenDigest", proof.value("roomInstanceTokenDigest", ""));
    appendCanonicalField(out, "username", proof.value("username", ""));
    appendCanonicalField(out, "publicKey", proof.value("publicKey", ""));
    appendCanonicalField(out, "nonce", proof.value("nonce", ""));
    return out;
}

std::string trimAscii(std::string value) {
    const auto first = value.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) return "";
    const auto last = value.find_last_not_of(" \t\r\n");
    return value.substr(first, last - first + 1);
}

std::string canonicalRoomName(const std::string& value) {
    auto out = trimAscii(value);
    std::transform(out.begin(), out.end(), out.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return out;
}

std::string pemFromCertificate(X509* cert) {
    BioPtr bio(BIO_new(BIO_s_mem()), BIO_free);
    if (!bio || PEM_write_bio_X509(bio.get(), cert) != 1) {
        throw std::runtime_error("certificate PEM serialization failed");
    }
    BUF_MEM* mem = nullptr;
    BIO_get_mem_ptr(bio.get(), &mem);
    return std::string(mem->data, mem->length);
}

std::string pemFromCsr(X509_REQ* req) {
    BioPtr bio(BIO_new(BIO_s_mem()), BIO_free);
    if (!bio || PEM_write_bio_X509_REQ(bio.get(), req) != 1) {
        throw std::runtime_error("CSR PEM serialization failed");
    }
    BUF_MEM* mem = nullptr;
    BIO_get_mem_ptr(bio.get(), &mem);
    return std::string(mem->data, mem->length);
}

void writeTextFile(const std::filesystem::path& path, const std::string& value) {
    std::ofstream file(path, std::ios::binary);
    if (!file) throw std::runtime_error("failed to open file for writing: " + pathToUtf8(path));
    file.write(value.data(), static_cast<std::streamsize>(value.size()));
}

std::string readTextFile(const std::filesystem::path& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file) throw std::runtime_error("failed to open file: " + pathToUtf8(path));
    std::ostringstream buffer;
    buffer << file.rdbuf();
    return buffer.str();
}

json readRuntimeFile(const std::filesystem::path& roomDir) {
    return json::parse(readTextFile(roomDir / "room-runtime.json"));
}

int pemPasswordCallback(char* buffer, int size, int, void* userData) {
    if (!userData) return 0;
    const auto* password = static_cast<const std::string*>(userData);
    if (password->empty()) return 0;
    const auto copied = (std::min)(static_cast<int>(password->size()), size);
    std::copy(password->begin(), password->begin() + copied, buffer);
    return copied;
}

void writePrivateKeyMaybeEncrypted(const std::filesystem::path& path, EVP_PKEY* key, const std::string& password) {
    auto file = openBioFileForWrite(path);
    const EVP_CIPHER* cipher = password.empty() ? nullptr : EVP_aes_256_cbc();
    void* passData = password.empty() ? nullptr : const_cast<std::string*>(&password);
    if (PEM_write_bio_PrivateKey(file.get(), key, cipher, nullptr, 0, pemPasswordCallback, passData) != 1) {
        throw std::runtime_error("failed to write private key: " + pathToUtf8(path));
    }
    file.reset();
    restrictPrivateFile(path);
}

EvpPkeyPtr readPrivateKey(const std::filesystem::path& path, const std::string& password = {}) {
    auto text = readTextFile(path);
    BioPtr bio(BIO_new_mem_buf(text.data(), static_cast<int>(text.size())), BIO_free);
    if (!bio) throw std::runtime_error("private key BIO allocation failed");
    EVP_PKEY* raw = PEM_read_bio_PrivateKey(
        bio.get(),
        nullptr,
        pemPasswordCallback,
        password.empty() ? nullptr : const_cast<std::string*>(&password));
    if (!raw) throw std::runtime_error("failed to read private key: " + pathToUtf8(path));
    return EvpPkeyPtr(raw, EVP_PKEY_free);
}

X509Ptr readCertificate(const std::filesystem::path& path) {
    auto text = readTextFile(path);
    BioPtr bio(BIO_new_mem_buf(text.data(), static_cast<int>(text.size())), BIO_free);
    if (!bio) throw std::runtime_error("certificate BIO allocation failed");
    X509* raw = PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr);
    if (!raw) throw std::runtime_error("failed to read certificate: " + pathToUtf8(path));
    return X509Ptr(raw, X509_free);
}

X509Ptr certificateFromPem(const std::string& pem, const std::string& label) {
    BioPtr bio(BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())), BIO_free);
    if (!bio) throw std::runtime_error(label + " certificate BIO allocation failed");
    X509* raw = PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr);
    if (!raw) throw std::runtime_error("failed to parse " + label + " certificate");
    return X509Ptr(raw, X509_free);
}

X509ReqPtr readCsr(const std::filesystem::path& path) {
    auto text = readTextFile(path);
    BioPtr bio(BIO_new_mem_buf(text.data(), static_cast<int>(text.size())), BIO_free);
    if (!bio) throw std::runtime_error("CSR BIO allocation failed");
    X509_REQ* raw = PEM_read_bio_X509_REQ(bio.get(), nullptr, nullptr, nullptr);
    if (!raw) throw std::runtime_error("failed to read CSR: " + pathToUtf8(path));
    return X509ReqPtr(raw, X509_REQ_free);
}

X509ReqPtr csrFromPem(const std::string& pem) {
    BioPtr bio(BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())), BIO_free);
    if (!bio) throw std::runtime_error("CSR BIO allocation failed");
    X509_REQ* raw = PEM_read_bio_X509_REQ(bio.get(), nullptr, nullptr, nullptr);
    if (!raw) throw std::runtime_error("failed to parse CSR PEM");
    return X509ReqPtr(raw, X509_REQ_free);
}

void verifyIssuedBy(X509* subject, X509* issuer, const std::string& label) {
    EvpPkeyPtr issuerKey(X509_get_pubkey(issuer), EVP_PKEY_free);
    if (!issuerKey) throw std::runtime_error(label + " issuer public key missing");
    if (X509_verify(subject, issuerKey.get()) != 1) {
        throw std::runtime_error(label + " certificate signature verification failed");
    }
}

struct VerifiedRoomCsr {
    std::string expectedDigest;
    std::string csrPem;
    std::string publicKeyFingerprintValue;
    std::string deviceName;
    EvpPkeyPtr publicKey{nullptr, EVP_PKEY_free};
};

X509Ptr createMemberCertificate(
    EVP_PKEY* publicKey,
    X509* issuerCert,
    EVP_PKEY* issuerKey,
    const std::string& commonName,
    int serial,
    const std::string& roomInstanceTokenDigest,
    const std::string& roomInstanceId,
    const std::string& deviceName,
    const std::string& role);

VerifiedRoomCsr verifyRoomCsrBundle(
    const std::filesystem::path& roomDir,
    const json& csrBundle,
    const std::string& memberName) {
    const auto descriptor = json::parse(readTextFile(roomDir / "room-descriptor.json"));
    const auto expectedDigest = descriptor.value("roomInstanceTokenDigest", "");
    if (expectedDigest.empty()) throw std::runtime_error("room descriptor missing roomInstanceTokenDigest");
    if (!csrBundle.is_object() ||
        csrBundle.value("kind", "") != "securechat-room-csr" ||
        csrBundle.value("roomInstanceTokenDigest", "") != expectedDigest ||
        csrBundle.value("username", "") != memberName) {
        throw std::runtime_error("CSR bundle does not match room or member");
    }

    const auto csrPem = csrBundle.value("csrPem", "");
    if (sha256Hex(csrPem) != csrBundle.value("csrSha256", "")) {
        throw std::runtime_error("CSR bundle hash mismatch");
    }
    auto csr = csrFromPem(csrPem);
    EvpPkeyPtr publicKey(X509_REQ_get_pubkey(csr.get()), EVP_PKEY_free);
    if (!publicKey) throw std::runtime_error("CSR public key missing");
    if (X509_REQ_verify(csr.get(), publicKey.get()) != 1) {
        throw std::runtime_error("CSR signature verification failed");
    }
    const auto publicFp = publicKeyFingerprint(publicKey.get());
    if (csrBundle.value("publicKeyFingerprint", "") != publicFp) {
        throw std::runtime_error("CSR public key fingerprint mismatch");
    }

    const auto proofObject = csrBundle.value("proof", json::object());
    if (!proofObject.is_object() || proofObject.value("alg", "") != "RSA-SHA256") {
        throw std::runtime_error("CSR bundle proof is missing");
    }
    const auto proof = base64Decode(proofObject.value("value", ""));
    if (!verifyBytes(publicKey.get(), canonicalCsrBundle(csrBundle), proof)) {
        throw std::runtime_error("CSR bundle proof verification failed");
    }

    return {
        expectedDigest,
        csrPem,
        publicFp,
        csrBundle.value("deviceName", ""),
        std::move(publicKey)};
}

void verifyPendingJoinProofObject(
    EVP_PKEY* csrPublicKey,
    const std::string& expectedDigest,
    const json& joinProof,
    const std::string& username,
    const std::string& publicKey) {
    if (!joinProof.is_object() ||
        joinProof.value("kind", "") != "securechat-room-pending-join" ||
        joinProof.value("roomInstanceTokenDigest", "") != expectedDigest ||
        joinProof.value("username", "") != username ||
        joinProof.value("publicKey", "") != publicKey) {
        throw std::runtime_error("pending join proof does not match request");
    }
    if (joinProof.value("alg", "") != "RSA-SHA256") {
        throw std::runtime_error("pending join proof has unsupported signature algorithm");
    }
    const auto signature = base64Decode(joinProof.value("signature", ""));
    if (!verifyBytes(csrPublicKey, canonicalPendingJoinProof(joinProof), signature)) {
        throw std::runtime_error("pending join proof verification failed");
    }
}

RoomMemberSignResult signVerifiedRoomCsr(
    const std::filesystem::path& roomDir,
    const VerifiedRoomCsr& verified,
    const std::string& memberName) {
    auto intermediateKey = readPrivateKey(roomDir / "intermediate-ca-key.pem");
    auto intermediateCert = readCertificate(roomDir / "intermediate-ca.pem");
    const auto descriptor = json::parse(readTextFile(roomDir / "room-descriptor.json"));
    const auto roomInstanceId = descriptor.value("roomInstanceId", "");
    const auto serial = 2000 + static_cast<int>(std::hash<std::string>{}(memberName) & 0x3fffffff);
    auto cert = createMemberCertificate(
        verified.publicKey.get(),
        intermediateCert.get(),
        intermediateKey.get(),
        memberName,
        serial,
        verified.expectedDigest,
        roomInstanceId,
        verified.deviceName,
        "member");
    const auto certPath = roomDir / (memberName + "-cert.pem");
    const auto chainPath = roomDir / (memberName + "-chain.pem");
    const auto responsePath = roomDir / (memberName + "-sign-response.json");
    writeCertificate(certPath, cert.get());
    writeCertificateChain(chainPath, cert.get(), intermediateCert.get());
    const auto memberFp = certFingerprint(cert.get());
    const auto issuerFp = certFingerprint(intermediateCert.get());
    json response = {
        {"version", 1},
        {"kind", "securechat-room-sign-response"},
        {"roomInstanceTokenDigest", verified.expectedDigest},
        {"username", memberName},
        {"csrSha256", sha256Hex(verified.csrPem)},
        {"memberFingerprint", memberFp},
        {"issuerFingerprint", issuerFp},
        {"memberCertPem", pemFromCertificate(cert.get())},
        {"memberChainPem", readTextFile(chainPath)},
        {"nonce", base64Encode(randomBytes(16).data(), 16)}
    };
    const auto signature = signBytes(intermediateKey.get(), canonicalSignResponse(response));
    response["signature"] = {
        {"alg", "RSA-SHA256"},
        {"value", base64Encode(signature.data(), signature.size())}
    };
    writeTextFile(responsePath, response.dump(2));
    return {
        pathToUtf8(certPath),
        pathToUtf8(chainPath),
        pathToUtf8(responsePath),
        memberFp};
}

X509Ptr createRoomCaCertificate(
    EVP_PKEY* key,
    const std::string& commonName,
    int serial,
    long days,
    const std::string& roomInstanceTokenDigest,
    const std::string& roomInstanceId,
    const std::string& role,
    const std::string& deviceName) {
    X509Ptr cert(X509_new(), X509_free);
    if (!cert) throw std::runtime_error("failed to allocate room CA certificate");
    X509_set_version(cert.get(), 2);
    ASN1_INTEGER_set(X509_get_serialNumber(cert.get()), serial);
    X509_gmtime_adj(X509_get_notBefore(cert.get()), 0);
    X509_gmtime_adj(X509_get_notAfter(cert.get()), days * 24L * 60L * 60L);
    if (X509_set_pubkey(cert.get(), key) != 1) throw std::runtime_error("failed to set room CA public key");
    auto* subject = X509_get_subject_name(cert.get());
    addNameEntry(subject, "CN", commonName);
    addSecureChatSubjectFields(subject, roomInstanceTokenDigest, role, deviceName);
    if (X509_set_issuer_name(cert.get(), subject) != 1) throw std::runtime_error("failed to set room CA issuer");
    addExtension(cert.get(), cert.get(), NID_basic_constraints, "critical,CA:TRUE");
    addExtension(cert.get(), cert.get(), NID_key_usage, "critical,keyCertSign,cRLSign");
    addExtension(cert.get(), cert.get(), NID_subject_key_identifier, "hash");
    addExtension(cert.get(), cert.get(), NID_netscape_comment, roomCertificateComment(roomInstanceTokenDigest, roomInstanceId, role));
    if (X509_sign(cert.get(), key, EVP_sha256()) <= 0) throw std::runtime_error("failed to sign room CA certificate");
    return cert;
}

X509Ptr createIntermediateCertificate(
    EVP_PKEY* key,
    X509* rootCert,
    EVP_PKEY* rootKey,
    const std::string& commonName,
    const std::string& roomInstanceTokenDigest,
    const std::string& roomInstanceId,
    const std::string& deviceName) {
    X509Ptr cert(X509_new(), X509_free);
    if (!cert) throw std::runtime_error("failed to allocate room Intermediate certificate");
    X509_set_version(cert.get(), 2);
    ASN1_INTEGER_set(X509_get_serialNumber(cert.get()), 2);
    X509_gmtime_adj(X509_get_notBefore(cert.get()), 0);
    X509_gmtime_adj(X509_get_notAfter(cert.get()), 5L * 365L * 24L * 60L * 60L);
    if (X509_set_pubkey(cert.get(), key) != 1) throw std::runtime_error("failed to set Intermediate public key");
    auto* subject = X509_get_subject_name(cert.get());
    addNameEntry(subject, "CN", commonName);
    addSecureChatSubjectFields(subject, roomInstanceTokenDigest, "room-intermediate-ca", deviceName);
    if (X509_set_issuer_name(cert.get(), X509_get_subject_name(rootCert)) != 1) {
        throw std::runtime_error("failed to set Intermediate issuer");
    }
    addExtension(cert.get(), rootCert, NID_basic_constraints, "critical,CA:TRUE,pathlen:0");
    addExtension(cert.get(), rootCert, NID_key_usage, "critical,keyCertSign,cRLSign");
    addExtension(cert.get(), rootCert, NID_subject_key_identifier, "hash");
    addExtension(cert.get(), rootCert, NID_authority_key_identifier, "keyid,issuer");
    addExtension(cert.get(), rootCert, NID_netscape_comment, roomCertificateComment(roomInstanceTokenDigest, roomInstanceId, "room-intermediate-ca"));
    if (X509_sign(cert.get(), rootKey, EVP_sha256()) <= 0) throw std::runtime_error("failed to sign Intermediate certificate");
    return cert;
}

X509Ptr createMemberCertificate(
    EVP_PKEY* publicKey,
    X509* issuerCert,
    EVP_PKEY* issuerKey,
    const std::string& commonName,
    int serial,
    const std::string& roomInstanceTokenDigest,
    const std::string& roomInstanceId,
    const std::string& deviceName,
    const std::string& role) {
    X509Ptr cert(X509_new(), X509_free);
    if (!cert) throw std::runtime_error("failed to allocate member certificate");
    X509_set_version(cert.get(), 2);
    ASN1_INTEGER_set(X509_get_serialNumber(cert.get()), serial);
    X509_gmtime_adj(X509_get_notBefore(cert.get()), 0);
    X509_gmtime_adj(X509_get_notAfter(cert.get()), 825L * 24L * 60L * 60L);
    if (X509_set_pubkey(cert.get(), publicKey) != 1) throw std::runtime_error("failed to set member public key");
    auto* subject = X509_get_subject_name(cert.get());
    addNameEntry(subject, "CN", commonName);
    addSecureChatSubjectFields(subject, roomInstanceTokenDigest, role, deviceName);
    if (X509_set_issuer_name(cert.get(), X509_get_subject_name(issuerCert)) != 1) {
        throw std::runtime_error("failed to set member issuer");
    }
    addExtension(cert.get(), issuerCert, NID_basic_constraints, "CA:FALSE");
    addExtension(cert.get(), issuerCert, NID_key_usage, "critical,digitalSignature");
    addExtension(cert.get(), issuerCert, NID_ext_key_usage, "clientAuth");
    addExtension(cert.get(), issuerCert, NID_subject_key_identifier, "hash");
    addExtension(cert.get(), issuerCert, NID_authority_key_identifier, "keyid,issuer");
    addExtension(cert.get(), issuerCert, NID_netscape_comment, roomCertificateComment(roomInstanceTokenDigest, roomInstanceId, role));
    if (X509_sign(cert.get(), issuerKey, EVP_sha256()) <= 0) throw std::runtime_error("failed to sign member certificate");
    return cert;
}

X509ReqPtr createMemberCsr(
    EVP_PKEY* key,
    const std::string& commonName,
    const std::string& roomInstanceTokenDigest,
    const std::string& deviceName) {
    X509ReqPtr req(X509_REQ_new(), X509_REQ_free);
    if (!req) throw std::runtime_error("failed to allocate CSR");
    X509_REQ_set_version(req.get(), 0);
    if (X509_REQ_set_pubkey(req.get(), key) != 1) throw std::runtime_error("failed to set CSR public key");
    auto* subject = X509_REQ_get_subject_name(req.get());
    addNameEntry(subject, "CN", commonName);
    addSecureChatSubjectFields(subject, roomInstanceTokenDigest, "pending-member", deviceName);
    if (X509_REQ_sign(req.get(), key, EVP_sha256()) <= 0) throw std::runtime_error("failed to sign CSR");
    return req;
}

std::vector<unsigned char> deriveEntranceKey(const std::string& phrase, const std::vector<unsigned char>& salt, std::uint32_t memoryKiB, std::uint32_t iterations, std::uint32_t parallelism) {
    std::vector<unsigned char> key(32);
    const int rc = argon2id_hash_raw(
        iterations,
        memoryKiB,
        parallelism,
        phrase.data(),
        phrase.size(),
        salt.data(),
        salt.size(),
        key.data(),
        key.size());
    if (rc != ARGON2_OK) {
        throw std::runtime_error(std::string("Argon2id failed: ") + argon2_error_message(rc));
    }
    return key;
}

json encryptEntrancePayload(const json& payload, const std::string& phrase) {
    const std::uint32_t memoryKiB = 64 * 1024;
    const std::uint32_t iterations = 3;
    const std::uint32_t parallelism = 1;
    auto salt = randomBytes(16);
    auto nonce = randomBytes(12);
    auto key = deriveEntranceKey(phrase, salt, memoryKiB, iterations, parallelism);
    const auto plaintext = payload.dump();
    std::vector<unsigned char> ciphertext(plaintext.size());
    std::vector<unsigned char> tag(16);
    EvpCipherCtxPtr ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    int len = 0;
    int outLen = 0;
    const std::string aad = std::string(entranceMagic) + "|v1|argon2id|aes-256-gcm";
    if (!ctx ||
        EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(nonce.size()), nullptr) != 1 ||
        EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), nonce.data()) != 1 ||
        EVP_EncryptUpdate(ctx.get(), nullptr, &len, reinterpret_cast<const unsigned char*>(aad.data()), static_cast<int>(aad.size())) != 1 ||
        EVP_EncryptUpdate(ctx.get(), ciphertext.data(), &len, reinterpret_cast<const unsigned char*>(plaintext.data()), static_cast<int>(plaintext.size())) != 1) {
        throw std::runtime_error("entrance encryption failed");
    }
    outLen = len;
    if (EVP_EncryptFinal_ex(ctx.get(), ciphertext.data() + outLen, &len) != 1) {
        throw std::runtime_error("entrance encryption final failed");
    }
    outLen += len;
    ciphertext.resize(static_cast<std::size_t>(outLen));
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, static_cast<int>(tag.size()), tag.data()) != 1) {
        throw std::runtime_error("entrance tag generation failed");
    }

    return {
        {"magic", entranceMagic},
        {"version", 1},
        {"kdf", "argon2id"},
        {"kdfParams", {{"memoryKiB", memoryKiB}, {"iterations", iterations}, {"parallelism", parallelism}}},
        {"aead", "aes-256-gcm"},
        {"salt", base64Encode(salt.data(), salt.size())},
        {"nonce", base64Encode(nonce.data(), nonce.size())},
        {"ciphertext", base64Encode(ciphertext.data(), ciphertext.size())},
        {"tag", base64Encode(tag.data(), tag.size())}
    };
}

json decryptEntrancePayload(const std::filesystem::path& entranceFile, const std::string& phrase) {
    const auto envelope = json::parse(readTextFile(entranceFile));
    if (envelope.value("magic", "") != entranceMagic || envelope.value("version", 0) != 1) {
        throw std::runtime_error("unsupported entrance.scp format");
    }
    if (envelope.value("kdf", "") != "argon2id" || envelope.value("aead", "") != "aes-256-gcm") {
        throw std::runtime_error("unsupported entrance.scp crypto suite");
    }
    const auto params = envelope.at("kdfParams");
    const auto salt = base64Decode(envelope.value("salt", ""));
    const auto nonce = base64Decode(envelope.value("nonce", ""));
    auto ciphertext = base64Decode(envelope.value("ciphertext", ""));
    const auto tag = base64Decode(envelope.value("tag", ""));
    auto key = deriveEntranceKey(
        phrase,
        salt,
        params.value("memoryKiB", 0U),
        params.value("iterations", 0U),
        params.value("parallelism", 0U));

    std::vector<unsigned char> plaintext(ciphertext.size() + 16);
    EvpCipherCtxPtr ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    int len = 0;
    int outLen = 0;
    const std::string aad = std::string(entranceMagic) + "|v1|argon2id|aes-256-gcm";
    if (!ctx ||
        EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(nonce.size()), nullptr) != 1 ||
        EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), nonce.data()) != 1 ||
        EVP_DecryptUpdate(ctx.get(), nullptr, &len, reinterpret_cast<const unsigned char*>(aad.data()), static_cast<int>(aad.size())) != 1 ||
        EVP_DecryptUpdate(ctx.get(), plaintext.data(), &len, ciphertext.data(), static_cast<int>(ciphertext.size())) != 1) {
        throw std::runtime_error("entrance decryption failed");
    }
    outLen = len;
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, static_cast<int>(tag.size()), const_cast<unsigned char*>(tag.data())) != 1 ||
        EVP_DecryptFinal_ex(ctx.get(), plaintext.data() + outLen, &len) != 1) {
        throw std::runtime_error("entrance phrase or authentication tag is invalid");
    }
    outLen += len;
    return json::parse(std::string(reinterpret_cast<char*>(plaintext.data()), static_cast<std::size_t>(outLen)));
}

std::array<unsigned char, admissionKeyBytes> deriveAdmissionKey(
    const std::string& admissionSecret,
    const std::string& roomInstanceTokenDigest,
    const std::string& purpose) {
    // admissionSecret 来自 entrance.scp，Server 不知道。
    // HKDF 的 salt 绑定 room instance，info 绑定具体用途，避免不同准入信令共用同一把 AES key。
    auto secretBytes = base64Decode(admissionSecret);
    if (secretBytes.empty()) {
        throw std::runtime_error("room runtime admissionSecret is empty or invalid");
    }
    const auto salt = std::string(admissionMagic) + "|v1|" + roomInstanceTokenDigest;
    const auto info = std::string("securechat-admission|") + purpose;

    std::array<unsigned char, admissionKeyBytes> out{};
    EvpPkeyCtxPtr ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr), EVP_PKEY_CTX_free);
    if (!ctx ||
        EVP_PKEY_derive_init(ctx.get()) != 1 ||
        EVP_PKEY_CTX_set_hkdf_md(ctx.get(), EVP_sha256()) != 1 ||
        EVP_PKEY_CTX_set1_hkdf_salt(
            ctx.get(),
            reinterpret_cast<const unsigned char*>(salt.data()),
            static_cast<int>(salt.size())) != 1 ||
        EVP_PKEY_CTX_set1_hkdf_key(ctx.get(), secretBytes.data(), static_cast<int>(secretBytes.size())) != 1 ||
        EVP_PKEY_CTX_add1_hkdf_info(
            ctx.get(),
            reinterpret_cast<const unsigned char*>(info.data()),
            static_cast<int>(info.size())) != 1) {
        throw std::runtime_error("admission HKDF setup failed");
    }

    std::size_t outLen = out.size();
    if (EVP_PKEY_derive(ctx.get(), out.data(), &outLen) != 1 || outLen != out.size()) {
        throw std::runtime_error("admission HKDF derive failed");
    }
    return out;
}

std::string admissionAad(const std::string& purpose, const std::string& roomInstanceTokenDigest) {
    return std::string(admissionMagic) + "|v1|" + purpose + "|" + roomInstanceTokenDigest;
}

json encryptAdmissionJson(
    const json& payload,
    const std::string& admissionSecret,
    const std::string& roomInstanceTokenDigest,
    const std::string& purpose) {
    if (!payload.is_object()) throw std::runtime_error("admission payload must be a JSON object");
    if (purpose.empty()) throw std::runtime_error("admission payload purpose is required");
    if (roomInstanceTokenDigest.empty()) throw std::runtime_error("room runtime missing roomInstanceTokenDigest");

    const auto key = deriveAdmissionKey(admissionSecret, roomInstanceTokenDigest, purpose);
    const auto nonce = randomBytes(admissionNonceBytes);
    const auto plaintext = payload.dump();
    std::vector<unsigned char> ciphertext(plaintext.size());
    std::vector<unsigned char> tag(admissionTagBytes);
    const auto aad = admissionAad(purpose, roomInstanceTokenDigest);
    EvpCipherCtxPtr ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    int len = 0;
    int outLen = 0;
    if (!ctx ||
        EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(nonce.size()), nullptr) != 1 ||
        EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), nonce.data()) != 1 ||
        EVP_EncryptUpdate(ctx.get(), nullptr, &len, reinterpret_cast<const unsigned char*>(aad.data()), static_cast<int>(aad.size())) != 1 ||
        EVP_EncryptUpdate(ctx.get(), ciphertext.data(), &len, reinterpret_cast<const unsigned char*>(plaintext.data()), static_cast<int>(plaintext.size())) != 1) {
        throw std::runtime_error("admission payload encryption failed");
    }
    outLen = len;
    if (EVP_EncryptFinal_ex(ctx.get(), ciphertext.data() + outLen, &len) != 1) {
        throw std::runtime_error("admission payload encryption final failed");
    }
    outLen += len;
    ciphertext.resize(static_cast<std::size_t>(outLen));
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, static_cast<int>(tag.size()), tag.data()) != 1) {
        throw std::runtime_error("admission payload tag generation failed");
    }

    return {
        {"magic", admissionMagic},
        {"version", 1},
        {"purpose", purpose},
        {"kdf", "HKDF-SHA256"},
        {"aead", "AES-256-GCM"},
        {"nonce", base64Encode(nonce.data(), nonce.size())},
        {"ciphertext", base64Encode(ciphertext.data(), ciphertext.size())},
        {"tag", base64Encode(tag.data(), tag.size())}
    };
}

json decryptAdmissionJson(
    const json& envelope,
    const std::string& admissionSecret,
    const std::string& roomInstanceTokenDigest,
    const std::string& purpose) {
    if (!envelope.is_object() ||
        envelope.value("magic", "") != admissionMagic ||
        envelope.value("version", 0) != 1 ||
        envelope.value("purpose", "") != purpose ||
        envelope.value("kdf", "") != "HKDF-SHA256" ||
        envelope.value("aead", "") != "AES-256-GCM") {
        throw std::runtime_error("unsupported admission payload format");
    }
    const auto key = deriveAdmissionKey(admissionSecret, roomInstanceTokenDigest, purpose);
    const auto nonce = base64Decode(envelope.value("nonce", ""));
    const auto ciphertext = base64Decode(envelope.value("ciphertext", ""));
    const auto tag = base64Decode(envelope.value("tag", ""));
    if (nonce.size() != admissionNonceBytes || tag.size() != admissionTagBytes) {
        throw std::runtime_error("admission payload nonce or tag has invalid size");
    }

    std::vector<unsigned char> plaintext(ciphertext.size() + admissionTagBytes);
    const auto aad = admissionAad(purpose, roomInstanceTokenDigest);
    EvpCipherCtxPtr ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    int len = 0;
    int outLen = 0;
    if (!ctx ||
        EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(nonce.size()), nullptr) != 1 ||
        EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), nonce.data()) != 1 ||
        EVP_DecryptUpdate(ctx.get(), nullptr, &len, reinterpret_cast<const unsigned char*>(aad.data()), static_cast<int>(aad.size())) != 1 ||
        EVP_DecryptUpdate(ctx.get(), plaintext.data(), &len, ciphertext.data(), static_cast<int>(ciphertext.size())) != 1) {
        throw std::runtime_error("admission payload decryption failed");
    }
    outLen = len;
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, static_cast<int>(tag.size()), const_cast<unsigned char*>(tag.data())) != 1 ||
        EVP_DecryptFinal_ex(ctx.get(), plaintext.data() + outLen, &len) != 1) {
        throw std::runtime_error("admission payload authentication failed");
    }
    outLen += len;
    auto payload = json::parse(std::string(reinterpret_cast<char*>(plaintext.data()), static_cast<std::size_t>(outLen)));
    if (!payload.is_object()) throw std::runtime_error("admission plaintext must be a JSON object");
    return payload;
}

json validateEntrancePayload(json payload) {
    if (payload.value("kind", "") != "securechat-room-entrance") {
        throw std::runtime_error("entrance payload is not a SecureChat room entrance");
    }
    const auto roomName = payload.value("roomName", "");
    const auto canonicalName = canonicalRoomName(roomName);
    if (canonicalName.empty() || payload.value("canonicalRoomName", "") != canonicalName) {
        throw std::runtime_error("entrance canonical room name mismatch");
    }

    auto rootCert = certificateFromPem(payload.value("rootCaPem", ""), "Root CA");
    auto intermediateCert = certificateFromPem(payload.value("intermediateCaPem", ""), "Intermediate CA");
    auto hostCert = certificateFromPem(payload.value("hostCertPem", ""), "Host member");
    verifyIssuedBy(rootCert.get(), rootCert.get(), "Root CA");
    verifyIssuedBy(intermediateCert.get(), rootCert.get(), "Intermediate");
    verifyIssuedBy(hostCert.get(), intermediateCert.get(), "Host member");

    const auto rootFp = certFingerprint(rootCert.get());
    const auto intermediateFp = certFingerprint(intermediateCert.get());
    const auto hostFp = certFingerprint(hostCert.get());
    EvpPkeyPtr rootPublicKey(X509_get_pubkey(rootCert.get()), EVP_PKEY_free);
    EvpPkeyPtr intermediatePublicKey(X509_get_pubkey(intermediateCert.get()), EVP_PKEY_free);
    EvpPkeyPtr hostPublicKey(X509_get_pubkey(hostCert.get()), EVP_PKEY_free);
    if (!rootPublicKey || !intermediatePublicKey || !hostPublicKey) {
        throw std::runtime_error("entrance certificate public key missing");
    }
    const auto rootPublicKeyFp = publicKeyFingerprint(rootPublicKey.get());
    const auto intermediatePublicKeyFp = publicKeyFingerprint(intermediatePublicKey.get());
    const auto hostPublicKeyFp = publicKeyFingerprint(hostPublicKey.get());
    if (payload.value("rootFingerprint", "") != rootFp ||
        payload.value("intermediateFingerprint", "") != intermediateFp ||
        payload.value("hostFingerprint", "") != hostFp ||
        payload.value("rootPublicKeyFingerprint", "") != rootPublicKeyFp ||
        payload.value("intermediatePublicKeyFingerprint", "") != intermediatePublicKeyFp ||
        payload.value("hostPublicKeyFingerprint", "") != hostPublicKeyFp) {
        throw std::runtime_error("entrance certificate fingerprint mismatch");
    }

    const auto roomInstanceId = payload.value("roomInstanceId", "");
    const auto admissionSecret = payload.value("admissionSecret", "");
    const auto expectedToken = deriveRoomInstanceToken(
        canonicalName,
        roomInstanceId,
        admissionSecret,
        rootPublicKeyFp,
        intermediatePublicKeyFp,
        hostPublicKeyFp);
    const auto expectedDigest = sha256Hex(expectedToken);
    if (payload.value("roomInstanceToken", "") != expectedToken ||
        payload.value("roomInstanceTokenDigest", "") != expectedDigest) {
        throw std::runtime_error("entrance room instance token mismatch");
    }

    auto descriptor = payload.value("descriptor", json::object());
    if (!descriptor.is_object()) throw std::runtime_error("entrance descriptor is missing");
    if (descriptor.value("roomName", "") != roomName ||
        descriptor.value("canonicalRoomName", "") != canonicalName ||
        descriptor.value("roomInstanceId", "") != roomInstanceId ||
        descriptor.value("roomInstanceTokenDigest", "") != expectedDigest ||
        descriptor.value("rootFingerprint", "") != rootFp ||
        descriptor.value("intermediateFingerprint", "") != intermediateFp ||
        descriptor.value("hostFingerprint", "") != hostFp ||
        descriptor.value("rootPublicKeyFingerprint", "") != rootPublicKeyFp ||
        descriptor.value("intermediatePublicKeyFingerprint", "") != intermediatePublicKeyFp ||
        descriptor.value("hostPublicKeyFingerprint", "") != hostPublicKeyFp) {
        throw std::runtime_error("entrance descriptor does not match payload");
    }
    const auto sigObject = descriptor.value("signature", json::object());
    if (!sigObject.is_object() || sigObject.value("alg", "") != "RSA-SHA256") {
        throw std::runtime_error("entrance descriptor signature is missing");
    }
    const auto signature = base64Decode(sigObject.value("value", ""));
    if (!verifyBytes(hostPublicKey.get(), canonicalRoomDescriptor(descriptor), signature)) {
        throw std::runtime_error("entrance descriptor signature verification failed");
    }

    payload["canonicalRoomName"] = canonicalName;
    payload["rootFingerprint"] = rootFp;
    payload["intermediateFingerprint"] = intermediateFp;
    payload["hostFingerprint"] = hostFp;
    payload["rootPublicKeyFingerprint"] = rootPublicKeyFp;
    payload["intermediatePublicKeyFingerprint"] = intermediatePublicKeyFp;
    payload["hostPublicKeyFingerprint"] = hostPublicKeyFp;
    payload["roomInstanceToken"] = expectedToken;
    payload["roomInstanceTokenDigest"] = expectedDigest;
    return payload;
}

std::filesystem::path roomDirFromDigest(const std::string& outputRoot, const std::string& digest) {
    return pathFromUtf8(outputRoot) / digest;
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

json encryptAdmissionPayload(
    const std::string& roomDirValue,
    const std::string& purpose,
    const json& payload) {
    const auto roomDir = pathFromUtf8(roomDirValue);
    const auto runtime = readRuntimeFile(roomDir);
    const auto admissionSecret = runtime.value("admissionSecret", "");
    const auto digest = runtime.value("roomInstanceTokenDigest", "");
    if (admissionSecret.empty()) throw std::runtime_error("room runtime missing admissionSecret");
    return encryptAdmissionJson(payload, admissionSecret, digest, purpose);
}

json decryptAdmissionPayload(
    const std::string& roomDirValue,
    const std::string& purpose,
    const json& envelope) {
    const auto roomDir = pathFromUtf8(roomDirValue);
    const auto runtime = readRuntimeFile(roomDir);
    const auto admissionSecret = runtime.value("admissionSecret", "");
    const auto digest = runtime.value("roomInstanceTokenDigest", "");
    if (admissionSecret.empty()) throw std::runtime_error("room runtime missing admissionSecret");
    return decryptAdmissionJson(envelope, admissionSecret, digest, purpose);
}

RoomEntranceCreateResult createRoomEntrance(const RoomEntranceCreateOptions& options) {
    const auto roomName = trimAscii(options.roomName);
    const auto roomPhrase = trimAscii(options.roomPhrase);
    const auto hostName = trimAscii(options.hostName.empty() ? "host" : options.hostName);
    if (roomName.empty()) throw std::runtime_error("room name is required");
    if (roomPhrase.size() < 16) throw std::runtime_error("room phrase is too short for entrance.scp");

    const auto roomInstanceId = base64Encode(randomBytes(32).data(), 32);
    const auto admissionSecret = base64Encode(randomBytes(32).data(), 32);
    const auto canonicalName = canonicalRoomName(roomName);
    const auto hostDevice = localHostname();

    auto rootKey = generateRsaKey(3072);
    auto intermediateKey = generateRsaKey(3072);
    auto hostKey = generateRsaKey(3072);
    const auto rootPublicKeyFp = publicKeyFingerprint(rootKey.get());
    const auto intermediatePublicKeyFp = publicKeyFingerprint(intermediateKey.get());
    const auto hostPublicKeyFp = publicKeyFingerprint(hostKey.get());
    const auto roomInstanceToken = deriveRoomInstanceToken(
        canonicalName,
        roomInstanceId,
        admissionSecret,
        rootPublicKeyFp,
        intermediatePublicKeyFp,
        hostPublicKeyFp);
    const auto digest = sha256Hex(roomInstanceToken);

    auto rootCert = createRoomCaCertificate(
        rootKey.get(),
        "SecureChat Room Root CA - " + canonicalName,
        1,
        10L * 365L,
        digest,
        roomInstanceId,
        "room-root-ca",
        hostDevice);
    auto intermediateCert = createIntermediateCertificate(
        intermediateKey.get(),
        rootCert.get(),
        rootKey.get(),
        "SecureChat Room Intermediate CA - " + canonicalName,
        digest,
        roomInstanceId,
        hostDevice);
    auto hostCert = createMemberCertificate(
        hostKey.get(),
        intermediateCert.get(),
        intermediateKey.get(),
        hostName,
        1001,
        digest,
        roomInstanceId,
        hostDevice,
        "host");

    const auto rootFp = certFingerprint(rootCert.get());
    const auto intermediateFp = certFingerprint(intermediateCert.get());
    const auto hostFp = certFingerprint(hostCert.get());
    const auto roomDir = roomDirFromDigest(options.outputRoot.empty() ? "logs/certs" : options.outputRoot, digest);
    ensureDirectory(roomDir);

    const auto rootKeyPath = roomDir / "root-ca-key.pem";
    const auto rootCertPath = roomDir / "root-ca.pem";
    const auto intermediateKeyPath = roomDir / "intermediate-ca-key.pem";
    const auto intermediateCertPath = roomDir / "intermediate-ca.pem";
    const auto hostKeyPath = roomDir / "host-key.pem";
    const auto hostCertPath = roomDir / "host-cert.pem";
    const auto hostChainPath = roomDir / "host-chain.pem";
    const auto entrancePath = roomDir / "entrance.scp";
    const auto descriptorPath = roomDir / "room-descriptor.json";
    const auto runtimePath = roomDir / "room-runtime.json";

    writePrivateKey(rootKeyPath, rootKey.get());
    writeCertificate(rootCertPath, rootCert.get());
    writePrivateKey(intermediateKeyPath, intermediateKey.get());
    writeCertificate(intermediateCertPath, intermediateCert.get());
    writePrivateKeyMaybeEncrypted(hostKeyPath, hostKey.get(), options.memberKeyPassword);
    writeCertificate(hostCertPath, hostCert.get());
    writeCertificateChain(hostChainPath, hostCert.get(), intermediateCert.get());

    json descriptor = {
        {"version", 1},
        {"roomName", roomName},
        {"canonicalRoomName", canonicalName},
        {"roomInstanceId", roomInstanceId},
        {"roomInstanceTokenDigest", digest},
        {"rootFingerprint", rootFp},
        {"intermediateFingerprint", intermediateFp},
        {"hostFingerprint", hostFp},
        {"rootPublicKeyFingerprint", rootPublicKeyFp},
        {"intermediatePublicKeyFingerprint", intermediatePublicKeyFp},
        {"hostPublicKeyFingerprint", hostPublicKeyFp},
        {"hostName", hostName},
        {"hostDevice", hostDevice}
    };
    const auto descriptorSig = signBytes(hostKey.get(), canonicalRoomDescriptor(descriptor));
    descriptor["signature"] = {
        {"alg", "RSA-SHA256"},
        {"value", base64Encode(descriptorSig.data(), descriptorSig.size())}
    };
    writeTextFile(descriptorPath, descriptor.dump(2));

    json runtime = {
        {"version", 1},
        {"roomName", roomName},
        {"canonicalRoomName", canonicalName},
        {"roomInstanceToken", roomInstanceToken},
        {"roomInstanceTokenDigest", digest},
        {"admissionSecret", admissionSecret},
        {"role", "host"},
        {"username", hostName}
    };
    writeTextFile(runtimePath, runtime.dump(2));
    restrictPrivateFile(runtimePath);

    json payload = {
        {"version", 1},
        {"kind", "securechat-room-entrance"},
        {"roomName", roomName},
        {"canonicalRoomName", canonicalName},
        {"roomInstanceId", roomInstanceId},
        {"admissionSecret", admissionSecret},
        {"roomInstanceToken", roomInstanceToken},
        {"roomInstanceTokenDigest", digest},
        {"rootCaPem", pemFromCertificate(rootCert.get())},
        {"intermediateCaPem", pemFromCertificate(intermediateCert.get())},
        {"hostCertPem", pemFromCertificate(hostCert.get())},
        {"rootFingerprint", rootFp},
        {"intermediateFingerprint", intermediateFp},
        {"hostFingerprint", hostFp},
        {"rootPublicKeyFingerprint", rootPublicKeyFp},
        {"intermediatePublicKeyFingerprint", intermediatePublicKeyFp},
        {"hostPublicKeyFingerprint", hostPublicKeyFp},
        {"descriptor", descriptor}
    };
    const auto envelope = encryptEntrancePayload(payload, roomPhrase);
    writeTextFile(entrancePath, envelope.dump(2));

    return {
        pathToUtf8(roomDir),
        pathToUtf8(entrancePath),
        pathToUtf8(rootCertPath),
        pathToUtf8(intermediateCertPath),
        pathToUtf8(hostChainPath),
        pathToUtf8(hostKeyPath),
        digest,
        rootFp,
        intermediateFp,
        hostFp};
}

std::string inspectRoomEntrance(const std::string& entranceFile, const std::string& roomPhrase) {
    auto payload = validateEntrancePayload(decryptEntrancePayload(pathFromUtf8(entranceFile), trimAscii(roomPhrase)));
    // 不把 admissionSecret 和 roomInstanceToken 打印给普通检查输出。
    payload.erase("admissionSecret");
    payload.erase("roomInstanceToken");
    return payload.dump(2);
}

std::string roomDirForEntrance(
    const std::string& entranceFile,
    const std::string& roomPhrase,
    const std::string& outputRoot) {
    auto payload = validateEntrancePayload(decryptEntrancePayload(pathFromUtf8(entranceFile), trimAscii(roomPhrase)));
    const auto digest = payload.value("roomInstanceTokenDigest", "");
    if (digest.empty()) throw std::runtime_error("entrance payload missing roomInstanceTokenDigest");
    return pathToUtf8(roomDirFromDigest(outputRoot.empty() ? "logs/certs" : outputRoot, digest));
}

std::string findLocalRoomDir(
    const std::string& roomNameValue,
    const std::string& usernameValue,
    const std::string& roleValue,
    const std::string& outputRoot) {
    const auto canonicalName = canonicalRoomName(roomNameValue);
    const auto username = trimAscii(usernameValue);
    const auto role = trimAscii(roleValue);
    if (canonicalName.empty()) throw std::runtime_error("room name is required");
    if (username.empty()) throw std::runtime_error("user name is required");
    if (role.empty()) throw std::runtime_error("room role is required");

    const auto root = pathFromUtf8(outputRoot.empty() ? "logs/certs" : outputRoot);
    std::error_code ec;
    if (!std::filesystem::is_directory(root, ec)) {
        throw std::runtime_error("no local room certificates found; import or create the room first");
    }

    std::filesystem::path bestDir;
    std::filesystem::file_time_type bestTime{};
    bool found = false;
    for (const auto& entry : std::filesystem::directory_iterator(root, ec)) {
        if (ec) break;
        if (!entry.is_directory(ec)) continue;
        const auto runtimePath = entry.path() / "room-runtime.json";
        if (!fileExists(runtimePath)) continue;
        try {
            const auto runtime = json::parse(readTextFile(runtimePath));
            if (runtime.value("canonicalRoomName", "") != canonicalName) continue;
            if (runtime.value("username", "") != username) continue;
            if (runtime.value("role", "") != role) continue;

            std::error_code timeEc;
            const auto modified = std::filesystem::last_write_time(runtimePath, timeEc);
            if (!found || (!timeEc && modified > bestTime)) {
                bestDir = entry.path();
                bestTime = timeEc ? std::filesystem::file_time_type{} : modified;
                found = true;
            }
        }
        catch (...) {
            // 损坏或半写入的 room-runtime 不参与自动选择。
            continue;
        }
    }
    if (!found) {
        throw std::runtime_error("no matching local room certificate directory found; import or create the room first");
    }
    return pathToUtf8(bestDir);
}

RoomEntranceImportResult importRoomEntrance(const RoomEntranceImportOptions& options) {
    const auto username = trimAscii(options.username);
    if (username.empty()) throw std::runtime_error("username is required");
    auto payload = validateEntrancePayload(decryptEntrancePayload(pathFromUtf8(options.entranceFile), trimAscii(options.roomPhrase)));
    const auto digest = payload.value("roomInstanceTokenDigest", "");
    if (digest.empty()) throw std::runtime_error("entrance payload missing roomInstanceTokenDigest");
    const auto roomDir = roomDirFromDigest(options.outputRoot.empty() ? "logs/certs" : options.outputRoot, digest);
    ensureDirectory(roomDir);

    const auto rootPath = roomDir / "root-ca.pem";
    const auto intermediatePath = roomDir / "intermediate-ca.pem";
    const auto hostCertPath = roomDir / "host-cert.pem";
    const auto descriptorPath = roomDir / "room-descriptor.json";
    const auto runtimePath = roomDir / "room-runtime.json";
    const auto keyPath = roomDir / (username + "-key.pem");
    const auto csrPath = roomDir / (username + ".csr");
    const auto csrBundlePath = roomDir / (username + ".csr.json");
    writeTextFile(rootPath, payload.value("rootCaPem", ""));
    writeTextFile(intermediatePath, payload.value("intermediateCaPem", ""));
    writeTextFile(hostCertPath, payload.value("hostCertPem", ""));
    writeTextFile(descriptorPath, payload["descriptor"].dump(2));

    json runtime = {
        {"version", 1},
        {"roomName", payload.value("roomName", "")},
        {"canonicalRoomName", payload.value("canonicalRoomName", "")},
        {"roomInstanceToken", payload.value("roomInstanceToken", "")},
        {"roomInstanceTokenDigest", digest},
        {"admissionSecret", payload.value("admissionSecret", "")},
        {"role", "client"},
        {"username", username}
    };
    writeTextFile(runtimePath, runtime.dump(2));
    restrictPrivateFile(runtimePath);

    auto memberKey = generateRsaKey(3072);
    const auto deviceName = localHostname();
    auto csr = createMemberCsr(memberKey.get(), username, digest, deviceName);
    writePrivateKeyMaybeEncrypted(keyPath, memberKey.get(), options.memberKeyPassword);
    const auto csrPem = pemFromCsr(csr.get());
    writeTextFile(csrPath, csrPem);

    EvpPkeyPtr csrPublicKey(X509_REQ_get_pubkey(csr.get()), EVP_PKEY_free);
    if (!csrPublicKey) throw std::runtime_error("CSR public key missing after generation");
    json csrBundle = {
        {"version", 1},
        {"kind", "securechat-room-csr"},
        {"roomInstanceTokenDigest", digest},
        {"username", username},
        {"deviceName", deviceName},
        {"csrPem", csrPem},
        {"csrSha256", sha256Hex(csrPem)},
        {"publicKeyFingerprint", publicKeyFingerprint(csrPublicKey.get())},
        {"nonce", base64Encode(randomBytes(16).data(), 16)}
    };
    const auto proof = signBytes(memberKey.get(), canonicalCsrBundle(csrBundle));
    csrBundle["proof"] = {
        {"alg", "RSA-SHA256"},
        {"value", base64Encode(proof.data(), proof.size())}
    };
    writeTextFile(csrBundlePath, csrBundle.dump(2));

    return {
        pathToUtf8(roomDir),
        pathToUtf8(rootPath),
        pathToUtf8(intermediatePath),
        pathToUtf8(keyPath),
        pathToUtf8(csrPath),
        pathToUtf8(csrBundlePath),
        digest,
        payload.value("rootFingerprint", ""),
        payload.value("intermediateFingerprint", "")};
}

json makePendingJoinProof(
    const std::string& roomDirValue,
    const std::string& usernameValue,
    const std::string& publicKey,
    const std::string& keyPassword) {
    const auto roomDir = pathFromUtf8(roomDirValue);
    const auto runtime = json::parse(readTextFile(roomDir / "room-runtime.json"));
    const auto username = trimAscii(usernameValue.empty() ? runtime.value("username", "") : usernameValue);
    const auto digest = runtime.value("roomInstanceTokenDigest", "");
    if (username.empty()) throw std::runtime_error("username is required");
    if (digest.empty()) throw std::runtime_error("room runtime missing roomInstanceTokenDigest");
    if (publicKey.empty()) throw std::runtime_error("pending join public key is required");

    const auto keyPath = roomDir / (username + "-key.pem");
    auto memberKey = readPrivateKey(keyPath, keyPassword);
    json proof = {
        {"version", 1},
        {"kind", "securechat-room-pending-join"},
        {"roomInstanceTokenDigest", digest},
        {"username", username},
        {"publicKey", publicKey},
        {"nonce", base64Encode(randomBytes(16).data(), 16)},
        {"alg", "RSA-SHA256"}
    };
    const auto signature = signBytes(memberKey.get(), canonicalPendingJoinProof(proof));
    proof["signature"] = base64Encode(signature.data(), signature.size());
    return proof;
}

std::string verifyPendingJoinRequest(
    const std::string& roomDirValue,
    const json& csrBundle,
    const json& joinProof,
    const std::string& usernameValue,
    const std::string& publicKey) {
    const auto roomDir = pathFromUtf8(roomDirValue);
    const auto username = trimAscii(usernameValue);
    if (username.empty()) throw std::runtime_error("username is required");
    auto verified = verifyRoomCsrBundle(roomDir, csrBundle, username);
    verifyPendingJoinProofObject(
        verified.publicKey.get(),
        verified.expectedDigest,
        joinProof,
        username,
        publicKey);
    return verified.publicKeyFingerprintValue;
}

RoomMemberSignResult signPendingRoomMemberCertificate(
    const std::string& roomDirValue,
    const json& csrBundle,
    const json& joinProof,
    const std::string& usernameValue,
    const std::string& publicKey) {
    const auto roomDir = pathFromUtf8(roomDirValue);
    const auto username = trimAscii(usernameValue);
    if (username.empty()) throw std::runtime_error("member name is required");
    auto verified = verifyRoomCsrBundle(roomDir, csrBundle, username);
    verifyPendingJoinProofObject(
        verified.publicKey.get(),
        verified.expectedDigest,
        joinProof,
        username,
        publicKey);
    return signVerifiedRoomCsr(roomDir, verified, username);
}

RoomMemberSignResult signRoomMemberCertificate(const RoomMemberSignOptions& options) {
    const auto roomDir = pathFromUtf8(options.roomDir);
    const auto csrPath = pathFromUtf8(options.csrFile);
    const auto memberName = trimAscii(options.memberName);
    if (memberName.empty()) throw std::runtime_error("member name is required");

    json csrBundle;
    std::string csrPem;
    if (csrPath.extension() == ".json") {
        csrBundle = json::parse(readTextFile(csrPath));
        auto verified = verifyRoomCsrBundle(roomDir, csrBundle, memberName);
        return signVerifiedRoomCsr(roomDir, verified, memberName);
    }

    csrPem = readTextFile(csrPath);
    auto csr = csrFromPem(csrPem);
    EvpPkeyPtr publicKey(X509_REQ_get_pubkey(csr.get()), EVP_PKEY_free);
    if (!publicKey) throw std::runtime_error("CSR public key missing");
    if (X509_REQ_verify(csr.get(), publicKey.get()) != 1) throw std::runtime_error("CSR signature verification failed");
    const auto descriptor = json::parse(readTextFile(roomDir / "room-descriptor.json"));
    const auto expectedDigest = descriptor.value("roomInstanceTokenDigest", "");
    if (expectedDigest.empty()) throw std::runtime_error("room descriptor missing roomInstanceTokenDigest");
    VerifiedRoomCsr verified{
        expectedDigest,
        csrPem,
        publicKeyFingerprint(publicKey.get()),
        "manual-csr",
        std::move(publicKey)};
    return signVerifiedRoomCsr(roomDir, verified, memberName);
}

RoomMemberInstallResult installRoomMemberCertificate(const RoomMemberInstallOptions& options) {
    const auto roomDir = pathFromUtf8(options.roomDir);
    const auto responsePath = pathFromUtf8(options.signResponseFile);
    auto response = json::parse(readTextFile(responsePath));
    return installRoomMemberCertificateJson(options.roomDir, response, options.memberName);
}

RoomMemberInstallResult installRoomMemberCertificateJson(
    const std::string& roomDirValue,
    const json& signResponse,
    const std::string& memberNameValue) {
    const auto roomDir = pathFromUtf8(roomDirValue);
    const auto runtime = json::parse(readTextFile(roomDir / "room-runtime.json"));
    const auto memberName = trimAscii(memberNameValue.empty()
        ? runtime.value("username", "")
        : memberNameValue);
    if (memberName.empty()) throw std::runtime_error("member name is required");

    const auto expectedDigest = runtime.value("roomInstanceTokenDigest", "");
    if (expectedDigest.empty()) throw std::runtime_error("room runtime missing roomInstanceTokenDigest");
    const auto csrPath = roomDir / (memberName + ".csr");
    if (!fileExists(csrPath)) throw std::runtime_error("local CSR missing: " + pathToUtf8(csrPath));

    auto response = signResponse;
    if (response.value("kind", "") != "securechat-room-sign-response" ||
        response.value("roomInstanceTokenDigest", "") != expectedDigest ||
        response.value("username", "") != memberName) {
        throw std::runtime_error("sign response does not match this room/member");
    }
    const auto csrPem = readTextFile(csrPath);
    if (sha256Hex(csrPem) != response.value("csrSha256", "")) {
        throw std::runtime_error("sign response does not match local CSR");
    }

    auto intermediateCert = readCertificate(roomDir / "intermediate-ca.pem");
    EvpPkeyPtr intermediatePublicKey(X509_get_pubkey(intermediateCert.get()), EVP_PKEY_free);
    if (!intermediatePublicKey) throw std::runtime_error("intermediate public key missing");
    const auto signatureObject = response.value("signature", json::object());
    if (!signatureObject.is_object() || signatureObject.value("alg", "") != "RSA-SHA256") {
        throw std::runtime_error("sign response signature is missing");
    }
    const auto signature = base64Decode(signatureObject.value("value", ""));
    if (!verifyBytes(intermediatePublicKey.get(), canonicalSignResponse(response), signature)) {
        throw std::runtime_error("sign response signature verification failed");
    }

    const auto memberCertPem = response.value("memberCertPem", "");
    const auto memberChainPem = response.value("memberChainPem", "");
    auto memberCert = certificateFromPem(memberCertPem, "member");
    verifyIssuedBy(memberCert.get(), intermediateCert.get(), "member");
    const auto memberFp = certFingerprint(memberCert.get());
    if (memberFp != response.value("memberFingerprint", "")) {
        throw std::runtime_error("member certificate fingerprint mismatch");
    }
    if (memberChainPem.find(memberCertPem) == std::string::npos) {
        throw std::runtime_error("member chain does not contain member certificate");
    }

    const auto certPath = roomDir / (memberName + "-cert.pem");
    const auto chainPath = roomDir / (memberName + "-chain.pem");
    writeTextFile(certPath, memberCertPem);
    writeTextFile(chainPath, memberChainPem);
    return {
        pathToUtf8(certPath),
        pathToUtf8(chainPath),
        memberFp};
}

RoomRuntimeMaterial loadRoomRuntimeMaterial(
    const std::string& roomDirValue,
    const std::string& usernameValue,
    bool host,
    bool requireIdentityCert) {
    const auto roomDir = pathFromUtf8(roomDirValue);
    const auto runtime = json::parse(readTextFile(roomDir / "room-runtime.json"));
    const auto username = trimAscii(usernameValue.empty()
        ? runtime.value("username", host ? "host" : "")
        : usernameValue);
    if (username.empty()) throw std::runtime_error("room runtime username is required");

    const auto trustStore = roomDir / "root-ca.pem";
    const auto certChain = host ? (roomDir / "host-chain.pem") : (roomDir / (username + "-chain.pem"));
    const auto keyFile = host ? (roomDir / "host-key.pem") : (roomDir / (username + "-key.pem"));
    const auto csrBundle = roomDir / (username + ".csr.json");
    if (!fileExists(trustStore)) throw std::runtime_error("room trust store missing: " + pathToUtf8(trustStore));
    const bool certReady = fileExists(certChain);
    if (requireIdentityCert && !certReady) {
        throw std::runtime_error("room identity chain missing: " + pathToUtf8(certChain));
    }
    if (!fileExists(keyFile)) throw std::runtime_error("room identity key missing: " + pathToUtf8(keyFile));

    return {
        runtime.value("roomName", ""),
        runtime.value("canonicalRoomName", ""),
        username,
        runtime.value("roomInstanceToken", ""),
        runtime.value("roomInstanceTokenDigest", ""),
        runtime.value("admissionSecret", ""),
        pathToUtf8(trustStore),
        pathToUtf8(certChain),
        pathToUtf8(keyFile),
        pathToUtf8(csrBundle),
        certReady
    };
}

}
