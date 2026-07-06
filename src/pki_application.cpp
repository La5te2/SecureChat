// 应用层 PKI 实现。它加载证书和私钥，
// 验证证书链，并签名/验签 GKA 身份绑定。
#include "pki_application.hpp"
#include "cert_utils.hpp"

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>

#include <algorithm>
#include <fstream>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace chat::pki_application {
namespace {
constexpr int identityNonceBytes = 16;
constexpr std::size_t sealedTextKeyBytes = 32;
constexpr std::size_t sealedTextNonceBytes = 12;
constexpr std::size_t sealedTextTagBytes = 16;
using chat::cert_utils::appendCanonicalField;
using chat::cert_utils::base64Decode;
using chat::cert_utils::base64Encode;
using chat::cert_utils::hexEncode;
using chat::cert_utils::randomBytes;
using chat::cert_utils::signBytes;
using chat::cert_utils::verifyBytes;

using BioPtr = std::unique_ptr<BIO, decltype(&BIO_free)>;
using EvpPkeyPtr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using X509Ptr = std::unique_ptr<X509, decltype(&X509_free)>;
using X509StorePtr = std::unique_ptr<X509_STORE, decltype(&X509_STORE_free)>;
using X509StoreCtxPtr = std::unique_ptr<X509_STORE_CTX, decltype(&X509_STORE_CTX_free)>;

std::string readTextFile(const std::string& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file) throw std::runtime_error("failed to open file: " + path);
    std::ostringstream buffer;
    buffer << file.rdbuf();
    return buffer.str();
}

std::string randomNonce() {
    return base64Encode(randomBytes(identityNonceBytes));
}

std::string canonicalJoinMessage(
    const std::string& roomId,
    const std::string& username,
    const std::string& publicKey,
    const std::string& nonce) {
    // 字段长度前缀让签名字节串保持唯一，即使 room id 或用户名包含 ':'、
    // 换行等分隔字符也不会产生歧义。
    std::string out = "securechat-pki-v1\njoin_room\n";
    appendCanonicalField(out, "roomId", roomId);
    appendCanonicalField(out, "username", username);
    appendCanonicalField(out, "publicKey", publicKey);
    appendCanonicalField(out, "nonce", nonce);
    return out;
}

std::string canonicalGkaContributionMessage(
    const std::string& roomId,
    std::uint64_t epoch,
    const std::string& memberId,
    const std::string& username,
    const std::string& publicKey,
    const std::string& contribution,
    const std::string& nonce) {
    // contribution 只对某个房间 epoch 和某个成员密钥有意义。
    // 长度前缀用于避免签名字节串歧义。
    std::string out = "securechat-pki-v1\ngka_contribution\n";
    appendCanonicalField(out, "roomId", roomId);
    appendCanonicalField(out, "epoch", std::to_string(epoch));
    appendCanonicalField(out, "memberId", memberId);
    appendCanonicalField(out, "username", username);
    appendCanonicalField(out, "publicKey", publicKey);
    appendCanonicalField(out, "contribution", contribution);
    appendCanonicalField(out, "nonce", nonce);
    return out;
}

std::string canonicalGroupKeyMessage(const json& envelope, const std::string& identityNonce) {
    // 把 Host 身份绑定到 Client 将要解封装的精确 group_key envelope。
    // 如果 Server 修改路由或密文字段，验签会在 X25519/AES-GCM 解封装前失败。
    std::string out = "securechat-pki-v1\ngroup_key\n";
    appendCanonicalField(out, "version", std::to_string(envelope.value("version", 0)));
    appendCanonicalField(out, "roomId", envelope.value("roomId", ""));
    appendCanonicalField(out, "epoch", std::to_string(envelope.value("epoch", 0ULL)));
    appendCanonicalField(out, "targetId", envelope.value("targetId", ""));
    appendCanonicalField(out, "senderId", envelope.value("senderId", ""));
    appendCanonicalField(out, "alg", envelope.value("alg", ""));
    appendCanonicalField(out, "kdf", envelope.value("kdf", ""));
    appendCanonicalField(out, "ephemeralPublicKey", envelope.value("ephemeralPublicKey", ""));
    appendCanonicalField(out, "nonce", envelope.value("nonce", ""));
    appendCanonicalField(out, "ciphertext", envelope.value("ciphertext", ""));
    appendCanonicalField(out, "tag", envelope.value("tag", ""));
    appendCanonicalField(out, "identityNonce", identityNonce);
    return out;
}

std::string canonicalRoomControlMessage(
    const std::string& roomId,
    const std::string& roomToken,
    const std::string& action,
    std::uint64_t epoch,
    const std::string& payloadDigest,
    const std::string& nonce) {
    // 房间控制动作必须绑定具体 room instance 和 payload 摘要。
    // Server 修改 action、epoch、reason、target 或 roomToken 后，成员验签会失败。
    std::string out = "securechat-pki-v1\nroom_control\n";
    appendCanonicalField(out, "roomId", roomId);
    appendCanonicalField(out, "roomToken", roomToken);
    appendCanonicalField(out, "action", action);
    appendCanonicalField(out, "epoch", std::to_string(epoch));
    appendCanonicalField(out, "payloadDigest", payloadDigest);
    appendCanonicalField(out, "nonce", nonce);
    return out;
}

BioPtr bioFromString(const std::string& value) {
    // OpenSSL PEM 读取器基于 BIO 流工作；这里把内存字符串包装成 BIO。
    return BioPtr(BIO_new_mem_buf(value.data(), static_cast<int>(value.size())), BIO_free);
}

int pemPasswordCallback(char* buffer, int size, int, void* userData) {
    // 加密私钥需要密码时，OpenSSL 会调用该回调。
    if (!userData) return 0;
    const auto* password = static_cast<const std::string*>(userData);
    if (password->empty()) return 0;
    const auto copied = (std::min)(static_cast<int>(password->size()), size);
    std::copy(password->begin(), password->begin() + copied, buffer);
    return copied;
}

std::vector<X509Ptr> parseCertificateChain(const std::string& pem) {
    // 第一张证书视为成员叶子证书；后续证书作为 X509_verify_cert 使用的非信任中间证书。
    auto bio = bioFromString(pem);
    if (!bio) throw std::runtime_error("certificate chain allocation failed");

    std::vector<X509Ptr> certs;
    while (true) {
        X509* cert = PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr);
        if (!cert) break;
        certs.emplace_back(cert, X509_free);
    }
    if (certs.empty()) throw std::runtime_error("certificate chain is empty");
    return certs;
}

EvpPkeyPtr loadPrivateKey(const std::string& path, const std::string& password) {
    auto pem = readTextFile(path);
    auto bio = bioFromString(pem);
    if (!bio) throw std::runtime_error("identity key allocation failed");
    EVP_PKEY* raw = PEM_read_bio_PrivateKey(
        bio.get(),
        nullptr,
        pemPasswordCallback,
        const_cast<std::string*>(&password));
    if (!raw) throw std::runtime_error("failed to read identity private key");
    return EvpPkeyPtr(raw, EVP_PKEY_free);
}

X509StorePtr loadTrustStore(const std::string& path) {
    X509StorePtr store(X509_STORE_new(), X509_STORE_free);
    if (!store) throw std::runtime_error("trust store allocation failed");
    if (X509_STORE_load_locations(store.get(), path.c_str(), nullptr) != 1) {
        throw std::runtime_error("failed to load PKI trust store: " + path);
    }
    return store;
}

std::string certificateSubject(X509* cert) {
    char buffer[512] = {};
    X509_NAME_oneline(X509_get_subject_name(cert), buffer, sizeof(buffer));
    return buffer;
}

std::string certificateFingerprint(X509* cert) {
    unsigned char digest[SHA256_DIGEST_LENGTH] = {};
    unsigned int digestSize = 0;
    if (X509_digest(cert, EVP_sha256(), digest, &digestSize) != 1) {
        throw std::runtime_error("certificate fingerprint failed");
    }
    return hexEncode(digest, digestSize);
}

void requireDigitalSignatureUsage(X509* cert) {
    // 身份证书必须允许签名协议绑定数据。
    ASN1_BIT_STRING* usage = static_cast<ASN1_BIT_STRING*>(
        X509_get_ext_d2i(cert, NID_key_usage, nullptr, nullptr));
    if (!usage) return;
    const int allowsDigitalSignature = ASN1_BIT_STRING_get_bit(usage, 0);
    ASN1_BIT_STRING_free(usage);
    if (allowsDigitalSignature != 1) {
        throw std::runtime_error("identity certificate does not allow digitalSignature");
    }
}

STACK_OF(X509)* buildUntrustedStack(const std::vector<X509Ptr>& certs) {
    auto* stack = sk_X509_new_null();
    if (!stack) throw std::runtime_error("certificate chain stack allocation failed");
    for (std::size_t i = 1; i < certs.size(); ++i) {
        if (sk_X509_push(stack, certs[i].get()) != 1) {
            sk_X509_free(stack);
            throw std::runtime_error("certificate chain stack push failed");
        }
    }
    return stack;
}

void verifyCertificateChain(
    X509_STORE* trustStore,
    const std::vector<X509Ptr>& certs) {
    if (!trustStore) throw std::runtime_error("PKI trust store is not loaded");
    if (certs.empty()) throw std::runtime_error("identity certificate is missing");

    requireDigitalSignatureUsage(certs.front().get());

    auto* untrusted = buildUntrustedStack(certs);
    X509StoreCtxPtr ctx(X509_STORE_CTX_new(), X509_STORE_CTX_free);
    if (!ctx ||
        X509_STORE_CTX_init(ctx.get(), trustStore, certs.front().get(), untrusted) != 1) {
        sk_X509_free(untrusted);
        throw std::runtime_error("certificate verification context failed");
    }

    const int verified = X509_verify_cert(ctx.get());
    const int error = X509_STORE_CTX_get_error(ctx.get());
    sk_X509_free(untrusted);
    if (verified != 1) {
        throw std::runtime_error(
            std::string("identity certificate verification failed: ") +
            X509_verify_cert_error_string(error));
    }
}

void requireKeyMatchesCertificate(EVP_PKEY* privateKey, X509* cert) {
    // 本地启动检查：配置的私钥必须与配置的身份证书对应。
    EvpPkeyPtr publicKey(X509_get_pubkey(cert), EVP_PKEY_free);
    if (!publicKey) throw std::runtime_error("identity certificate public key missing");
    if (EVP_PKEY_eq(privateKey, publicKey.get()) != 1) {
        throw std::runtime_error("identity private key does not match certificate");
    }
}

std::string signatureAlgorithm(EVP_PKEY* key) {
    // 显式记录声明的算法，使不匹配或被降级的签名格式在验签阶段被拒绝。
    const int id = EVP_PKEY_base_id(key);
    if (id == EVP_PKEY_ED25519) return "Ed25519";
    if (id == EVP_PKEY_EC) return "ECDSA-SHA256";
    if (id == EVP_PKEY_RSA || id == EVP_PKEY_RSA_PSS) return "RSA-SHA256";
    throw std::runtime_error("unsupported identity signing key type");
}

json makeIdentityObject(
    EVP_PKEY* privateKey,
    const std::string& certChainPem,
    const std::string& canonicalMessage,
    const std::string& identityNonce) {
    const auto signature = signBytes(privateKey, canonicalMessage);
    return {
        {"version", 1},
        {"certChainPem", certChainPem},
        {"nonce", identityNonce},
        {"signatureAlg", signatureAlgorithm(privateKey)},
        {"signature", base64Encode(signature.data(), signature.size())}
    };
}

std::vector<X509Ptr> verifiedIdentityCerts(
    X509_STORE* trustStore,
    const json& identity) {
    if (!identity.is_object()) throw std::runtime_error("identity must be an object");
    if (identity.value("version", 0) != 1) throw std::runtime_error("unsupported identity version");
    const auto certChainPem = identity.value("certChainPem", "");
    if (certChainPem.empty()) throw std::runtime_error("identity certificate chain is missing");
    auto certs = parseCertificateChain(certChainPem);
    verifyCertificateChain(trustStore, certs);
    return certs;
}

json sealWithCertificatePublicKey(
    X509* cert,
    const std::string& purpose,
    const std::string& recipientFingerprint,
    const std::vector<unsigned char>& plaintext) {
    EvpPkeyPtr publicKey(X509_get_pubkey(cert), EVP_PKEY_free);
    if (!publicKey) throw std::runtime_error("recipient certificate public key missing");
    const int keyType = EVP_PKEY_base_id(publicKey.get());
    if (keyType != EVP_PKEY_RSA && keyType != EVP_PKEY_RSA_PSS) {
        throw std::runtime_error("recipient certificate key is not RSA");
    }

    std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> ctx(
        EVP_PKEY_CTX_new(publicKey.get(), nullptr),
        EVP_PKEY_CTX_free);
    if (!ctx ||
        EVP_PKEY_encrypt_init(ctx.get()) != 1 ||
        EVP_PKEY_CTX_set_rsa_padding(ctx.get(), RSA_PKCS1_OAEP_PADDING) != 1 ||
        EVP_PKEY_CTX_set_rsa_oaep_md(ctx.get(), EVP_sha256()) != 1 ||
        EVP_PKEY_CTX_set_rsa_mgf1_md(ctx.get(), EVP_sha256()) != 1) {
        throw std::runtime_error("RSA-OAEP seal setup failed");
    }

    std::size_t outSize = 0;
    if (EVP_PKEY_encrypt(ctx.get(), nullptr, &outSize, plaintext.data(), plaintext.size()) != 1) {
        throw std::runtime_error("RSA-OAEP seal size failed");
    }
    std::vector<unsigned char> ciphertext(outSize);
    if (EVP_PKEY_encrypt(ctx.get(), ciphertext.data(), &outSize, plaintext.data(), plaintext.size()) != 1) {
        throw std::runtime_error("RSA-OAEP seal failed");
    }
    ciphertext.resize(outSize);

    return {
        {"version", 1},
        {"purpose", purpose},
        {"recipientFingerprint", recipientFingerprint},
        {"alg", "RSA-OAEP-SHA256"},
        {"ciphertext", base64Encode(ciphertext.data(), ciphertext.size())}
    };
}

std::vector<unsigned char> openWithPrivateKey(EVP_PKEY* privateKey, const json& envelope) {
    if (!envelope.is_object() ||
        envelope.value("version", 0) != 1 ||
        envelope.value("alg", "") != "RSA-OAEP-SHA256") {
        throw std::runtime_error("unsupported sealed key envelope");
    }
    const int keyType = EVP_PKEY_base_id(privateKey);
    if (keyType != EVP_PKEY_RSA && keyType != EVP_PKEY_RSA_PSS) {
        throw std::runtime_error("local identity key is not RSA");
    }
    const auto ciphertext = base64Decode(envelope.value("ciphertext", ""));

    std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> ctx(
        EVP_PKEY_CTX_new(privateKey, nullptr),
        EVP_PKEY_CTX_free);
    if (!ctx ||
        EVP_PKEY_decrypt_init(ctx.get()) != 1 ||
        EVP_PKEY_CTX_set_rsa_padding(ctx.get(), RSA_PKCS1_OAEP_PADDING) != 1 ||
        EVP_PKEY_CTX_set_rsa_oaep_md(ctx.get(), EVP_sha256()) != 1 ||
        EVP_PKEY_CTX_set_rsa_mgf1_md(ctx.get(), EVP_sha256()) != 1) {
        throw std::runtime_error("RSA-OAEP open setup failed");
    }

    std::size_t outSize = 0;
    if (EVP_PKEY_decrypt(ctx.get(), nullptr, &outSize, ciphertext.data(), ciphertext.size()) != 1) {
        throw std::runtime_error("RSA-OAEP open size failed");
    }
    std::vector<unsigned char> plaintext(outSize);
    if (EVP_PKEY_decrypt(ctx.get(), plaintext.data(), &outSize, ciphertext.data(), ciphertext.size()) != 1) {
        throw std::runtime_error("RSA-OAEP open failed");
    }
    plaintext.resize(outSize);
    return plaintext;
}

json encryptSealedTextBody(
    const std::string& purpose,
    const std::string& recipientFingerprint,
    const std::string& plaintext,
    const std::vector<unsigned char>& key) {
    if (key.size() != sealedTextKeyBytes) throw std::runtime_error("sealed text key size is invalid");
    const auto nonce = randomBytes(sealedTextNonceBytes);
    const auto aad = std::string("securechat-sealed-text-v1|") + purpose + "|" + recipientFingerprint;

    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> ctx(
        EVP_CIPHER_CTX_new(),
        EVP_CIPHER_CTX_free);
    if (!ctx ||
        EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(nonce.size()), nullptr) != 1 ||
        EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), nonce.data()) != 1) {
        throw std::runtime_error("sealed text encryption setup failed");
    }

    int outLength = 0;
    if (EVP_EncryptUpdate(
            ctx.get(),
            nullptr,
            &outLength,
            reinterpret_cast<const unsigned char*>(aad.data()),
            static_cast<int>(aad.size())) != 1) {
        throw std::runtime_error("sealed text AAD failed");
    }

    std::vector<unsigned char> ciphertext(plaintext.size() + sealedTextTagBytes);
    if (EVP_EncryptUpdate(
            ctx.get(),
            ciphertext.data(),
            &outLength,
            reinterpret_cast<const unsigned char*>(plaintext.data()),
            static_cast<int>(plaintext.size())) != 1) {
        throw std::runtime_error("sealed text encryption failed");
    }
    int total = outLength;
    if (EVP_EncryptFinal_ex(ctx.get(), ciphertext.data() + total, &outLength) != 1) {
        throw std::runtime_error("sealed text encryption final failed");
    }
    total += outLength;
    ciphertext.resize(static_cast<std::size_t>(total));

    std::vector<unsigned char> tag(sealedTextTagBytes);
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, static_cast<int>(tag.size()), tag.data()) != 1) {
        throw std::runtime_error("sealed text tag failed");
    }

    return {
        {"nonce", base64Encode(nonce)},
        {"ciphertext", base64Encode(ciphertext)},
        {"tag", base64Encode(tag)}
    };
}

std::string decryptSealedTextBody(
    const std::string& purpose,
    const std::string& recipientFingerprint,
    const json& envelope,
    const std::vector<unsigned char>& key) {
    if (key.size() != sealedTextKeyBytes) throw std::runtime_error("sealed text key size is invalid");
    const auto body = envelope.find("body");
    if (body == envelope.end() || !body->is_object()) throw std::runtime_error("sealed text body is missing");
    const auto nonce = base64Decode(body->value("nonce", ""));
    const auto ciphertext = base64Decode(body->value("ciphertext", ""));
    const auto tag = base64Decode(body->value("tag", ""));
    if (nonce.size() != sealedTextNonceBytes || tag.size() != sealedTextTagBytes) {
        throw std::runtime_error("sealed text nonce or tag is invalid");
    }
    const auto aad = std::string("securechat-sealed-text-v1|") + purpose + "|" + recipientFingerprint;

    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> ctx(
        EVP_CIPHER_CTX_new(),
        EVP_CIPHER_CTX_free);
    if (!ctx ||
        EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(nonce.size()), nullptr) != 1 ||
        EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), nonce.data()) != 1) {
        throw std::runtime_error("sealed text decryption setup failed");
    }

    int outLength = 0;
    if (EVP_DecryptUpdate(
            ctx.get(),
            nullptr,
            &outLength,
            reinterpret_cast<const unsigned char*>(aad.data()),
            static_cast<int>(aad.size())) != 1) {
        throw std::runtime_error("sealed text AAD failed");
    }

    std::vector<unsigned char> plaintext(ciphertext.size());
    if (EVP_DecryptUpdate(
            ctx.get(),
            plaintext.data(),
            &outLength,
            ciphertext.data(),
            static_cast<int>(ciphertext.size())) != 1) {
        throw std::runtime_error("sealed text decryption failed");
    }
    int total = outLength;
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, static_cast<int>(tag.size()), const_cast<unsigned char*>(tag.data())) != 1 ||
        EVP_DecryptFinal_ex(ctx.get(), plaintext.data() + total, &outLength) != 1) {
        throw std::runtime_error("sealed text authentication failed");
    }
    total += outLength;
    plaintext.resize(static_cast<std::size_t>(total));
    return std::string(reinterpret_cast<const char*>(plaintext.data()), plaintext.size());
}

std::string requiredIdentityString(const json& identity, const char* key) {
    const auto it = identity.find(key);
    if (it == identity.end() || !it->is_string() || it->get<std::string>().empty()) {
        throw std::runtime_error(std::string("identity field is missing: ") + key);
    }
    return it->get<std::string>();
}

void requireSignatureAlgorithmMatches(EVP_PKEY* key, const json& identity) {
    const auto advertised = requiredIdentityString(identity, "signatureAlg");
    const auto expected = signatureAlgorithm(key);
    if (advertised != expected) {
        throw std::runtime_error("identity signature algorithm mismatch");
    }
}
}

struct IdentityContext::Data {
    X509StorePtr trustStore{nullptr, X509_STORE_free};
    EvpPkeyPtr privateKey{nullptr, EVP_PKEY_free};
    std::string certChainPem;
    std::vector<X509Ptr> localCerts;
    std::string localSubject;
    std::string localFingerprint;
};

IdentityContext::IdentityContext() = default;

IdentityContext::IdentityContext(std::shared_ptr<Data> data)
    : mData(std::move(data)) {
}

bool IdentityContext::enabled() const {
    return static_cast<bool>(mData);
}

std::string IdentityContext::subject() const {
    return mData ? mData->localSubject : "";
}

std::string IdentityContext::fingerprint() const {
    return mData ? mData->localFingerprint : "";
}

json IdentityContext::publicIdentity() const {
    if (!mData) throw std::runtime_error("PKI identity is not configured");
    return {
        {"version", 1},
        {"certChainPem", mData->certChainPem}
    };
}

json IdentityContext::signJoinRoom(
    const std::string& roomId,
    const std::string& username,
    const std::string& publicKey) const {
    if (!mData) throw std::runtime_error("PKI identity is not configured");
    const auto nonce = randomNonce();
    return makeIdentityObject(
        mData->privateKey.get(),
        mData->certChainPem,
        canonicalJoinMessage(roomId, username, publicKey, nonce),
        nonce);
}

VerifiedIdentity IdentityContext::verifyJoinRoom(
    const std::string& roomId,
    const std::string& username,
    const std::string& publicKey,
    const json& identity) const {
    if (!mData) throw std::runtime_error("PKI identity is not configured");
    const auto nonce = requiredIdentityString(identity, "nonce");
    const auto signature = base64Decode(requiredIdentityString(identity, "signature"));
    const auto certs = verifiedIdentityCerts(mData->trustStore.get(), identity);
    EvpPkeyPtr publicSigningKey(X509_get_pubkey(certs.front().get()), EVP_PKEY_free);
    if (!publicSigningKey) throw std::runtime_error("identity certificate public key missing");
    requireSignatureAlgorithmMatches(publicSigningKey.get(), identity);

    if (!verifyBytes(publicSigningKey.get(), canonicalJoinMessage(roomId, username, publicKey, nonce), signature)) {
        throw std::runtime_error("join_room identity signature verification failed");
    }
    return {
        certificateSubject(certs.front().get()),
        certificateFingerprint(certs.front().get())
    };
}

json IdentityContext::signGkaContribution(
    const std::string& roomId,
    std::uint64_t epoch,
    const std::string& memberId,
    const std::string& username,
    const std::string& publicKey,
    const std::string& contribution) const {
    if (!mData) throw std::runtime_error("PKI identity is not configured");
    const auto nonce = randomNonce();
    return makeIdentityObject(
        mData->privateKey.get(),
        mData->certChainPem,
        canonicalGkaContributionMessage(roomId, epoch, memberId, username, publicKey, contribution, nonce),
        nonce);
}

VerifiedIdentity IdentityContext::verifyGkaContribution(
    const std::string& roomId,
    std::uint64_t epoch,
    const std::string& memberId,
    const std::string& username,
    const std::string& publicKey,
    const std::string& contribution,
    const json& identity) const {
    if (!mData) throw std::runtime_error("PKI identity is not configured");
    const auto nonce = requiredIdentityString(identity, "nonce");
    const auto signature = base64Decode(requiredIdentityString(identity, "signature"));
    const auto certs = verifiedIdentityCerts(mData->trustStore.get(), identity);
    EvpPkeyPtr publicSigningKey(X509_get_pubkey(certs.front().get()), EVP_PKEY_free);
    if (!publicSigningKey) throw std::runtime_error("identity certificate public key missing");
    requireSignatureAlgorithmMatches(publicSigningKey.get(), identity);

    if (!verifyBytes(
            publicSigningKey.get(),
            canonicalGkaContributionMessage(roomId, epoch, memberId, username, publicKey, contribution, nonce),
            signature)) {
        throw std::runtime_error("GKA contribution signature verification failed");
    }
    return {
        certificateSubject(certs.front().get()),
        certificateFingerprint(certs.front().get())
    };
}

void IdentityContext::signGroupKeyEnvelope(json& envelope) const {
    if (!mData) throw std::runtime_error("PKI identity is not configured");
    const auto nonce = randomNonce();
    envelope["identity"] = makeIdentityObject(
        mData->privateKey.get(),
        mData->certChainPem,
        canonicalGroupKeyMessage(envelope, nonce),
        nonce);
}

VerifiedIdentity IdentityContext::verifyGroupKeyEnvelope(const json& envelope) const {
    if (!mData) throw std::runtime_error("PKI identity is not configured");
    const auto it = envelope.find("identity");
    if (it == envelope.end()) throw std::runtime_error("group_key identity is missing");
    const auto& identity = *it;
    const auto nonce = requiredIdentityString(identity, "nonce");
    const auto signature = base64Decode(requiredIdentityString(identity, "signature"));
    const auto certs = verifiedIdentityCerts(mData->trustStore.get(), identity);
    EvpPkeyPtr publicSigningKey(X509_get_pubkey(certs.front().get()), EVP_PKEY_free);
    if (!publicSigningKey) throw std::runtime_error("host identity certificate public key missing");
    requireSignatureAlgorithmMatches(publicSigningKey.get(), identity);

    if (!verifyBytes(publicSigningKey.get(), canonicalGroupKeyMessage(envelope, nonce), signature)) {
        throw std::runtime_error("group_key identity signature verification failed");
    }
    return {
        certificateSubject(certs.front().get()),
        certificateFingerprint(certs.front().get())
    };
}

json IdentityContext::signRoomControl(
    const std::string& roomId,
    const std::string& roomToken,
    const std::string& action,
    std::uint64_t epoch,
    const std::string& payloadDigest) const {
    if (!mData) throw std::runtime_error("PKI identity is not configured");
    const auto nonce = randomNonce();
    return makeIdentityObject(
        mData->privateKey.get(),
        mData->certChainPem,
        canonicalRoomControlMessage(roomId, roomToken, action, epoch, payloadDigest, nonce),
        nonce);
}

VerifiedIdentity IdentityContext::verifyRoomControl(
    const std::string& roomId,
    const std::string& roomToken,
    const std::string& action,
    std::uint64_t epoch,
    const std::string& payloadDigest,
    const json& control) const {
    if (!mData) throw std::runtime_error("PKI identity is not configured");
    const auto nonce = requiredIdentityString(control, "nonce");
    const auto signature = base64Decode(requiredIdentityString(control, "signature"));
    const auto certs = verifiedIdentityCerts(mData->trustStore.get(), control);
    EvpPkeyPtr publicSigningKey(X509_get_pubkey(certs.front().get()), EVP_PKEY_free);
    if (!publicSigningKey) throw std::runtime_error("control identity certificate public key missing");
    requireSignatureAlgorithmMatches(publicSigningKey.get(), control);

    if (!verifyBytes(
            publicSigningKey.get(),
            canonicalRoomControlMessage(roomId, roomToken, action, epoch, payloadDigest, nonce),
            signature)) {
        throw std::runtime_error("room control signature verification failed");
    }
    return {
        certificateSubject(certs.front().get()),
        certificateFingerprint(certs.front().get())
    };
}

json IdentityContext::sealBytesForIdentity(
    const std::string& purpose,
    const std::string& recipientFingerprint,
    const std::vector<unsigned char>& plaintext,
    const json& identity) const {
    if (!mData) throw std::runtime_error("PKI identity is not configured");
    if (purpose.empty()) throw std::runtime_error("sealed key purpose is missing");
    if (recipientFingerprint.empty()) throw std::runtime_error("recipient fingerprint is missing");
    if (plaintext.empty()) throw std::runtime_error("sealed plaintext is empty");

    const auto certs = verifiedIdentityCerts(mData->trustStore.get(), identity);
    const auto actualFingerprint = certificateFingerprint(certs.front().get());
    if (actualFingerprint != recipientFingerprint) {
        throw std::runtime_error("recipient fingerprint does not match certificate");
    }
    return sealWithCertificatePublicKey(certs.front().get(), purpose, recipientFingerprint, plaintext);
}

std::vector<unsigned char> IdentityContext::openSealedBytes(
    const std::string& purpose,
    const json& envelope) const {
    if (!mData) throw std::runtime_error("PKI identity is not configured");
    if (!envelope.is_object()) throw std::runtime_error("sealed key envelope must be an object");
    if (envelope.value("purpose", "") != purpose) {
        throw std::runtime_error("sealed key purpose mismatch");
    }
    if (envelope.value("recipientFingerprint", "") != mData->localFingerprint) {
        throw std::runtime_error("sealed key is not for this member");
    }
    return openWithPrivateKey(mData->privateKey.get(), envelope);
}

json IdentityContext::sealTextForIdentity(
    const std::string& purpose,
    const std::string& recipientFingerprint,
    const std::string& plaintext,
    const json& identity) const {
    if (!mData) throw std::runtime_error("PKI identity is not configured");
    if (purpose.empty()) throw std::runtime_error("sealed text purpose is missing");
    if (recipientFingerprint.empty()) throw std::runtime_error("recipient fingerprint is missing");
    if (plaintext.empty()) throw std::runtime_error("sealed text plaintext is empty");

    const auto contentKey = randomBytes(sealedTextKeyBytes);
    return {
        {"version", 1},
        {"purpose", purpose},
        {"recipientFingerprint", recipientFingerprint},
        {"alg", "AES-256-GCM+RSA-OAEP-SHA256"},
        {"sealedKey", sealBytesForIdentity(purpose + ":content_key", recipientFingerprint, contentKey, identity)},
        {"body", encryptSealedTextBody(purpose, recipientFingerprint, plaintext, contentKey)}
    };
}

std::string IdentityContext::openSealedText(
    const std::string& purpose,
    const json& envelope) const {
    if (!mData) throw std::runtime_error("PKI identity is not configured");
    if (!envelope.is_object()) throw std::runtime_error("sealed text envelope must be an object");
    if (envelope.value("version", 0) != 1 ||
        envelope.value("purpose", "") != purpose ||
        envelope.value("alg", "") != "AES-256-GCM+RSA-OAEP-SHA256" ||
        envelope.value("recipientFingerprint", "") != mData->localFingerprint) {
        throw std::runtime_error("unsupported sealed text envelope");
    }
    const auto sealedKey = envelope.find("sealedKey");
    if (sealedKey == envelope.end() || !sealedKey->is_object()) {
        throw std::runtime_error("sealed text content key is missing");
    }
    const auto contentKey = openSealedBytes(purpose + ":content_key", *sealedKey);
    return decryptSealedTextBody(purpose, mData->localFingerprint, envelope, contentKey);
}

IdentityContext loadFromFiles(
    const std::string& trustStorePath,
    const std::string& certPath,
    const std::string& keyPath,
    const std::string& keyPassword) {
    if (trustStorePath.empty() || certPath.empty() || keyPath.empty()) {
        throw std::runtime_error("PKI file paths must not be empty");
    }

    auto data = std::make_shared<IdentityContext::Data>();
    data->trustStore = loadTrustStore(trustStorePath);
    data->certChainPem = readTextFile(certPath);
    data->localCerts = parseCertificateChain(data->certChainPem);
    data->privateKey = loadPrivateKey(keyPath, keyPassword);
    verifyCertificateChain(data->trustStore.get(), data->localCerts);
    requireKeyMatchesCertificate(data->privateKey.get(), data->localCerts.front().get());
    data->localSubject = certificateSubject(data->localCerts.front().get());
    data->localFingerprint = certificateFingerprint(data->localCerts.front().get());
    return IdentityContext(std::move(data));
}

}
