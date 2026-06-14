// Application-layer PKI implementation. It loads certificates and private keys,
// verifies certificate chains and signs/verifies GKA identity bindings.
#include "identity_pki.hpp"

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>

#include <algorithm>
#include <cstdlib>
#include <fstream>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace chat::identity_pki {
namespace {
constexpr int identityNonceBytes = 16;

using BioPtr = std::unique_ptr<BIO, decltype(&BIO_free)>;
using EvpMdCtxPtr = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;
using EvpPkeyPtr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using X509Ptr = std::unique_ptr<X509, decltype(&X509_free)>;
using X509StorePtr = std::unique_ptr<X509_STORE, decltype(&X509_STORE_free)>;
using X509StoreCtxPtr = std::unique_ptr<X509_STORE_CTX, decltype(&X509_STORE_CTX_free)>;

std::string envValue(const char* name) {
    const char* value = std::getenv(name);
    return value == nullptr ? std::string() : std::string(value);
}

std::string readTextFile(const std::string& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file) throw std::runtime_error("failed to open file: " + path);
    std::ostringstream buffer;
    buffer << file.rdbuf();
    return buffer.str();
}

std::string base64Encode(const unsigned char* data, std::size_t size) {
    if (size == 0) return "";
    std::string out(static_cast<std::size_t>(4 * ((size + 2) / 3)), '\0');
    const int written = EVP_EncodeBlock(
        reinterpret_cast<unsigned char*>(out.data()),
        data,
        static_cast<int>(size));
    if (written < 0) throw std::runtime_error("base64 encode failed");
    out.resize(static_cast<std::size_t>(written));
    return out;
}

std::vector<unsigned char> base64Decode(const std::string& value) {
    if (value.empty()) return {};
    std::vector<unsigned char> out(static_cast<std::size_t>(3 * value.size() / 4 + 3));
    const int written = EVP_DecodeBlock(
        out.data(),
        reinterpret_cast<const unsigned char*>(value.data()),
        static_cast<int>(value.size()));
    if (written < 0) throw std::runtime_error("base64 decode failed");

    std::size_t padding = 0;
    if (!value.empty() && value[value.size() - 1] == '=') ++padding;
    if (value.size() > 1 && value[value.size() - 2] == '=') ++padding;
    out.resize(static_cast<std::size_t>(written) - padding);
    return out;
}

std::string randomNonce() {
    std::vector<unsigned char> bytes(identityNonceBytes);
    if (RAND_bytes(bytes.data(), static_cast<int>(bytes.size())) != 1) {
        throw std::runtime_error("identity nonce generation failed");
    }
    return base64Encode(bytes.data(), bytes.size());
}

std::string hexEncode(const unsigned char* data, std::size_t size) {
    static constexpr char digits[] = "0123456789ABCDEF";
    std::string out;
    out.reserve(size * 2);
    for (std::size_t i = 0; i < size; ++i) {
        out.push_back(digits[(data[i] >> 4) & 0x0f]);
        out.push_back(digits[data[i] & 0x0f]);
    }
    return out;
}

void appendCanonicalField(std::string& out, const std::string& name, const std::string& value) {
    // Length-prefixing avoids ambiguous signed strings when values contain
    // separators or newline characters.
    out += name;
    out += ":";
    out += std::to_string(value.size());
    out += ":";
    out += value;
    out += "\n";
}

std::string canonicalJoinMessage(
    const std::string& roomId,
    const std::string& username,
    const std::string& publicKey,
    const std::string& nonce) {
    // Length-prefixed fields make the signed byte string unambiguous even if a
    // room id or username contains separators such as ':' or newlines.
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
    // A contribution is meaningful only for one room epoch and one member key.
    // Length prefixes prevent ambiguous signed strings.
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
    // Bind the Host identity to the exact group_key envelope the Client will
    // unwrap. If a Server changes routing or ciphertext fields, verification
    // fails before the X25519/AES-GCM unwrapping step.
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

BioPtr bioFromString(const std::string& value) {
    // OpenSSL PEM readers operate on BIO streams; this wraps an in-memory string.
    return BioPtr(BIO_new_mem_buf(value.data(), static_cast<int>(value.size())), BIO_free);
}

int pemPasswordCallback(char* buffer, int size, int, void* userData) {
    // OpenSSL calls this when an encrypted private key needs its password.
    if (!userData) return 0;
    const auto* password = static_cast<const std::string*>(userData);
    if (password->empty()) return 0;
    const auto copied = (std::min)(static_cast<int>(password->size()), size);
    std::copy(password->begin(), password->begin() + copied, buffer);
    return copied;
}

std::vector<X509Ptr> parseCertificateChain(const std::string& pem) {
    // The first certificate is treated as the member leaf certificate; following
    // certificates are untrusted intermediates for X509_verify_cert.
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
    // Identity certificates must be allowed to sign protocol bindings.
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
    // Local startup check: the configured private key must correspond to the
    // configured identity certificate.
    EvpPkeyPtr publicKey(X509_get_pubkey(cert), EVP_PKEY_free);
    if (!publicKey) throw std::runtime_error("identity certificate public key missing");
    if (EVP_PKEY_eq(privateKey, publicKey.get()) != 1) {
        throw std::runtime_error("identity private key does not match certificate");
    }
}

std::string signatureAlgorithm(EVP_PKEY* key) {
    // Keep the advertised algorithm explicit so a mismatched or downgraded
    // signature format is rejected during verification.
    const int id = EVP_PKEY_base_id(key);
    if (id == EVP_PKEY_ED25519) return "Ed25519";
    if (id == EVP_PKEY_EC) return "ECDSA-SHA256";
    if (id == EVP_PKEY_RSA || id == EVP_PKEY_RSA_PSS) return "RSA-SHA256";
    throw std::runtime_error("unsupported identity signing key type");
}

std::vector<unsigned char> signBytes(EVP_PKEY* key, const std::string& message) {
    EvpMdCtxPtr ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    if (!ctx) throw std::runtime_error("signature context allocation failed");

    const int id = EVP_PKEY_base_id(key);
    const EVP_MD* digest = id == EVP_PKEY_ED25519 ? nullptr : EVP_sha256();
    if (EVP_DigestSignInit(ctx.get(), nullptr, digest, nullptr, key) != 1) {
        throw std::runtime_error("signature init failed");
    }

    std::size_t signatureSize = 0;
    if (id == EVP_PKEY_ED25519) {
        if (EVP_DigestSign(
                ctx.get(),
                nullptr,
                &signatureSize,
                reinterpret_cast<const unsigned char*>(message.data()),
                message.size()) != 1) {
            throw std::runtime_error("signature size failed");
        }
        std::vector<unsigned char> signature(signatureSize);
        if (EVP_DigestSign(
                ctx.get(),
                signature.data(),
                &signatureSize,
                reinterpret_cast<const unsigned char*>(message.data()),
                message.size()) != 1) {
            throw std::runtime_error("signature failed");
        }
        signature.resize(signatureSize);
        return signature;
    }

    if (EVP_DigestSignUpdate(ctx.get(), message.data(), message.size()) != 1 ||
        EVP_DigestSignFinal(ctx.get(), nullptr, &signatureSize) != 1) {
        throw std::runtime_error("signature size failed");
    }
    std::vector<unsigned char> signature(signatureSize);
    if (EVP_DigestSignFinal(ctx.get(), signature.data(), &signatureSize) != 1) {
        throw std::runtime_error("signature failed");
    }
    signature.resize(signatureSize);
    return signature;
}

bool verifyBytes(EVP_PKEY* key, const std::string& message, const std::vector<unsigned char>& signature) {
    EvpMdCtxPtr ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    if (!ctx) throw std::runtime_error("signature verify context allocation failed");

    const int id = EVP_PKEY_base_id(key);
    const EVP_MD* digest = id == EVP_PKEY_ED25519 ? nullptr : EVP_sha256();
    if (EVP_DigestVerifyInit(ctx.get(), nullptr, digest, nullptr, key) != 1) {
        throw std::runtime_error("signature verify init failed");
    }

    if (id == EVP_PKEY_ED25519) {
        return EVP_DigestVerify(
            ctx.get(),
            signature.data(),
            signature.size(),
            reinterpret_cast<const unsigned char*>(message.data()),
            message.size()) == 1;
    }

    if (EVP_DigestVerifyUpdate(ctx.get(), message.data(), message.size()) != 1) {
        throw std::runtime_error("signature verify update failed");
    }
    return EVP_DigestVerifyFinal(ctx.get(), signature.data(), signature.size()) == 1;
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

IdentityContext loadFromEnvironment() {
    const auto trustStorePath = envValue("SECURECHAT_PKI_TRUST_STORE");
    const auto certPath = envValue("SECURECHAT_IDENTITY_CERT_FILE");
    const auto keyPath = envValue("SECURECHAT_IDENTITY_KEY_FILE");
    const auto keyPassword = envValue("SECURECHAT_IDENTITY_KEY_PASS");

    if (trustStorePath.empty() || certPath.empty() || keyPath.empty()) {
        throw std::runtime_error(
            "SecureChat requires PKI: set SECURECHAT_PKI_TRUST_STORE, SECURECHAT_IDENTITY_CERT_FILE, and SECURECHAT_IDENTITY_KEY_FILE");
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
