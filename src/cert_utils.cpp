// 证书和 PKI 共用工具实现。
#include "cert_utils.hpp"

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include <memory>
#include <stdexcept>

namespace chat::cert_utils {
namespace {
using EvpMdCtxPtr = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;
}

std::vector<unsigned char> randomBytes(std::size_t size) {
    std::vector<unsigned char> bytes(size);
    if (!bytes.empty() && RAND_bytes(bytes.data(), static_cast<int>(bytes.size())) != 1) {
        throw std::runtime_error("secure random generation failed");
    }
    return bytes;
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

std::string base64Encode(const std::vector<unsigned char>& data) {
    return base64Encode(data.data(), data.size());
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

std::string sha256Hex(const std::string& value) {
    return sha256Hex(reinterpret_cast<const unsigned char*>(value.data()), value.size());
}

std::string sha256Hex(const unsigned char* data, std::size_t size) {
    unsigned char digest[SHA256_DIGEST_LENGTH] = {};
    SHA256(data, size, digest);
    return hexEncode(digest, sizeof(digest));
}

void appendCanonicalField(std::string& out, const std::string& name, const std::string& value) {
    out += name;
    out += ":";
    out += std::to_string(value.size());
    out += ":";
    out += value;
    out += "\n";
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

}
