#include "secure_relay.hpp"

#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>

#include <algorithm>
#include <array>
#include <memory>
#include <stdexcept>
#include <vector>

namespace chat::secure_relay {
namespace {
constexpr int keyBytes = 32;
constexpr int x25519Bytes = 32;
constexpr int nonceBytes = 12;
constexpr int tagBytes = 16;

using CipherCtx = std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>;
using PkeyPtr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using PkeyCtxPtr = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>;

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

std::vector<unsigned char> randomBytes(std::size_t size) {
    std::vector<unsigned char> bytes(size);
    if (RAND_bytes(bytes.data(), static_cast<int>(bytes.size())) != 1) {
        throw std::runtime_error("secure random generation failed");
    }
    return bytes;
}

std::array<unsigned char, keyBytes> keyArrayFromVector(const std::vector<unsigned char>& key) {
    if (key.size() != keyBytes) throw std::runtime_error("invalid group key size");
    std::array<unsigned char, keyBytes> out{};
    std::copy(key.begin(), key.end(), out.begin());
    return out;
}

std::vector<unsigned char> aadForEnvelope(
    const std::string& roomId,
    const std::string& senderId,
    const std::string& senderKind,
    const std::string& targetId) {
    const std::string aad = std::string("securechat-relay|") + roomId + "|" + senderId + "|" + senderKind + "|" + targetId;
    return {aad.begin(), aad.end()};
}

std::vector<unsigned char> aadForGroupKey(
    const std::string& roomId,
    const std::string& targetId) {
    const std::string aad = std::string("securechat-gka-v2|") + roomId + "|" + targetId;
    return {aad.begin(), aad.end()};
}

PkeyPtr rawX25519PrivateKey(const std::vector<unsigned char>& privateKey) {
    if (privateKey.size() != x25519Bytes) throw std::runtime_error("invalid X25519 private key");
    return PkeyPtr(
        EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, privateKey.data(), privateKey.size()),
        EVP_PKEY_free);
}

PkeyPtr rawX25519PublicKey(const std::vector<unsigned char>& publicKey) {
    if (publicKey.size() != x25519Bytes) throw std::runtime_error("invalid X25519 public key");
    return PkeyPtr(
        EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr, publicKey.data(), publicKey.size()),
        EVP_PKEY_free);
}

std::vector<unsigned char> deriveX25519Secret(
    const std::vector<unsigned char>& privateKey,
    const std::vector<unsigned char>& peerPublicKey) {
    auto local = rawX25519PrivateKey(privateKey);
    auto peer = rawX25519PublicKey(peerPublicKey);
    if (!local || !peer) throw std::runtime_error("X25519 key allocation failed");

    PkeyCtxPtr ctx(EVP_PKEY_CTX_new(local.get(), nullptr), EVP_PKEY_CTX_free);
    if (!ctx ||
        EVP_PKEY_derive_init(ctx.get()) != 1 ||
        EVP_PKEY_derive_set_peer(ctx.get(), peer.get()) != 1) {
        throw std::runtime_error("X25519 derive init failed");
    }

    std::size_t len = 0;
    if (EVP_PKEY_derive(ctx.get(), nullptr, &len) != 1) {
        throw std::runtime_error("X25519 derive size failed");
    }
    std::vector<unsigned char> secret(len);
    if (EVP_PKEY_derive(ctx.get(), secret.data(), &len) != 1) {
        throw std::runtime_error("X25519 derive failed");
    }
    secret.resize(len);
    return secret;
}

std::array<unsigned char, keyBytes> hkdfSha256(
    const std::vector<unsigned char>& secret,
    const std::string& salt,
    const std::string& info) {
    std::array<unsigned char, keyBytes> out{};
    PkeyCtxPtr ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr), EVP_PKEY_CTX_free);
    if (!ctx ||
        EVP_PKEY_derive_init(ctx.get()) != 1 ||
        EVP_PKEY_CTX_set_hkdf_md(ctx.get(), EVP_sha256()) != 1 ||
        EVP_PKEY_CTX_set1_hkdf_salt(
            ctx.get(),
            reinterpret_cast<const unsigned char*>(salt.data()),
            static_cast<int>(salt.size())) != 1 ||
        EVP_PKEY_CTX_set1_hkdf_key(ctx.get(), secret.data(), static_cast<int>(secret.size())) != 1 ||
        EVP_PKEY_CTX_add1_hkdf_info(
            ctx.get(),
            reinterpret_cast<const unsigned char*>(info.data()),
            static_cast<int>(info.size())) != 1) {
        throw std::runtime_error("HKDF setup failed");
    }

    std::size_t outLen = out.size();
    if (EVP_PKEY_derive(ctx.get(), out.data(), &outLen) != 1 || outLen != out.size()) {
        throw std::runtime_error("HKDF derive failed");
    }
    return out;
}

json encryptWithAesGcm(
    const std::string& plaintext,
    const std::array<unsigned char, keyBytes>& key,
    const std::vector<unsigned char>& aad,
    json envelope) {
    const auto nonce = randomBytes(nonceBytes);
    CipherCtx ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    if (!ctx) throw std::runtime_error("AES-GCM context allocation failed");
    if (EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, nonceBytes, nullptr) != 1 ||
        EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), nonce.data()) != 1) {
        throw std::runtime_error("AES-GCM encryption init failed");
    }

    int outLen = 0;
    if (EVP_EncryptUpdate(ctx.get(), nullptr, &outLen, aad.data(), static_cast<int>(aad.size())) != 1) {
        throw std::runtime_error("AES-GCM AAD failed");
    }

    std::vector<unsigned char> ciphertext(plaintext.size() + tagBytes);
    if (EVP_EncryptUpdate(
            ctx.get(),
            ciphertext.data(),
            &outLen,
            reinterpret_cast<const unsigned char*>(plaintext.data()),
            static_cast<int>(plaintext.size())) != 1) {
        throw std::runtime_error("AES-GCM encryption failed");
    }
    int ciphertextLen = outLen;

    if (EVP_EncryptFinal_ex(ctx.get(), ciphertext.data() + ciphertextLen, &outLen) != 1) {
        throw std::runtime_error("AES-GCM final failed");
    }
    ciphertextLen += outLen;
    ciphertext.resize(static_cast<std::size_t>(ciphertextLen));

    std::array<unsigned char, tagBytes> tag{};
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, tagBytes, tag.data()) != 1) {
        throw std::runtime_error("AES-GCM tag failed");
    }

    envelope["nonce"] = base64Encode(nonce.data(), nonce.size());
    envelope["ciphertext"] = base64Encode(ciphertext.data(), ciphertext.size());
    envelope["tag"] = base64Encode(tag.data(), tag.size());
    return envelope;
}

std::string decryptWithAesGcm(
    const json& envelope,
    const std::array<unsigned char, keyBytes>& key,
    const std::vector<unsigned char>& aad) {
    const auto nonce = base64Decode(envelope.value("nonce", ""));
    const auto ciphertext = base64Decode(envelope.value("ciphertext", ""));
    const auto tag = base64Decode(envelope.value("tag", ""));
    if (nonce.size() != nonceBytes || tag.size() != tagBytes) {
        throw std::runtime_error("invalid AES-GCM nonce or tag");
    }

    CipherCtx ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    if (!ctx) throw std::runtime_error("AES-GCM context allocation failed");
    if (EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, nonceBytes, nullptr) != 1 ||
        EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), nonce.data()) != 1) {
        throw std::runtime_error("AES-GCM decryption init failed");
    }

    int outLen = 0;
    if (EVP_DecryptUpdate(ctx.get(), nullptr, &outLen, aad.data(), static_cast<int>(aad.size())) != 1) {
        throw std::runtime_error("AES-GCM AAD failed");
    }

    std::vector<unsigned char> plaintext(ciphertext.size());
    if (EVP_DecryptUpdate(ctx.get(), plaintext.data(), &outLen, ciphertext.data(), static_cast<int>(ciphertext.size())) != 1) {
        throw std::runtime_error("AES-GCM decryption failed");
    }
    int plaintextLen = outLen;

    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, tagBytes, const_cast<unsigned char*>(tag.data())) != 1 ||
        EVP_DecryptFinal_ex(ctx.get(), plaintext.data() + plaintextLen, &outLen) != 1) {
        throw std::runtime_error("AES-GCM authentication failed");
    }
    plaintextLen += outLen;
    plaintext.resize(static_cast<std::size_t>(plaintextLen));
    return std::string(plaintext.begin(), plaintext.end());
}
}

MemberKeyPair generateMemberKeyPair() {
    PkeyCtxPtr ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr), EVP_PKEY_CTX_free);
    EVP_PKEY* raw = nullptr;
    if (!ctx || EVP_PKEY_keygen_init(ctx.get()) != 1 || EVP_PKEY_keygen(ctx.get(), &raw) != 1) {
        throw std::runtime_error("X25519 key generation failed");
    }
    PkeyPtr key(raw, EVP_PKEY_free);

    std::vector<unsigned char> privateKey(x25519Bytes);
    std::vector<unsigned char> publicKey(x25519Bytes);
    std::size_t privateLen = privateKey.size();
    std::size_t publicLen = publicKey.size();
    if (EVP_PKEY_get_raw_private_key(key.get(), privateKey.data(), &privateLen) != 1 ||
        EVP_PKEY_get_raw_public_key(key.get(), publicKey.data(), &publicLen) != 1 ||
        privateLen != privateKey.size() ||
        publicLen != publicKey.size()) {
        throw std::runtime_error("X25519 raw key export failed");
    }

    return {std::move(privateKey), base64Encode(publicKey.data(), publicKey.size())};
}

std::array<unsigned char, GroupKeyBytes> generateGroupKey() {
    std::array<unsigned char, GroupKeyBytes> key{};
    if (RAND_bytes(key.data(), static_cast<int>(key.size())) != 1) {
        throw std::runtime_error("group key generation failed");
    }
    return key;
}

bool hasUsableGroupKey(const std::vector<unsigned char>& key) {
    return key.size() == GroupKeyBytes;
}

json encryptMessageWithGroupKey(
    const Message& message,
    const std::string& roomId,
    const std::string& senderId,
    const std::string& senderName,
    const std::string& senderKind,
    const std::string& targetId,
    const std::vector<unsigned char>& groupKey) {
    // targetId is clear routing metadata, so bind it into AAD. A malicious
    // relay cannot silently retarget a private envelope without breaking GCM.
    const auto key = keyArrayFromVector(groupKey);
    const auto aad = aadForEnvelope(roomId, senderId, senderKind, targetId);
    return encryptWithAesGcm(message.toJson(), key, aad, {
        {"type", EnvelopeType},
        {"version", 2},
        {"roomId", roomId},
        {"senderId", senderId},
        {"senderName", senderName},
        {"senderKind", senderKind},
        {"targetId", targetId},
        {"alg", "AES-256-GCM"},
        {"kdf", "GKA-X25519-HKDF-SHA256"}
    });
}

Message decryptMessageWithGroupKey(
    const json& envelope,
    const std::string& roomId,
    const std::vector<unsigned char>& groupKey) {
    // Rebuild the same AAD from envelope metadata before decrypting. This
    // authenticates room, sender role, and private target routing fields.
    if (envelope.value("type", "") != EnvelopeType) {
        throw std::runtime_error("not an encrypted relay envelope");
    }
    if (envelope.value("roomId", "") != roomId) {
        throw std::runtime_error("encrypted relay room mismatch");
    }
    if (envelope.value("version", 0) != 2 || envelope.value("alg", "") != "AES-256-GCM") {
        throw std::runtime_error("unsupported encrypted relay envelope");
    }
    const auto key = keyArrayFromVector(groupKey);
    const auto senderId = envelope.value("senderId", "");
    const auto senderKind = envelope.value("senderKind", "");
    const auto targetId = envelope.value("targetId", "");
    const auto plaintext = decryptWithAesGcm(envelope, key, aadForEnvelope(roomId, senderId, senderKind, targetId));
    return Message::fromJson(plaintext);
}

json encryptGroupKeyForMember(
    const std::vector<unsigned char>& groupKey,
    const std::string& roomId,
    const std::string& targetId,
    const std::string& targetPublicKey) {
    // Wraps the room group key to one Client using an ephemeral X25519 ECDH.
    // The Server forwards this envelope but cannot derive the wrapping key.
    const auto groupKeyArray = keyArrayFromVector(groupKey);
    const auto recipientPublic = base64Decode(targetPublicKey);
    auto ephemeral = generateMemberKeyPair();
    const auto secret = deriveX25519Secret(ephemeral.privateKey, recipientPublic);
    const auto wrapKey = hkdfSha256(secret, "securechat-gka-v2:" + roomId, "group-key|" + targetId);
    const std::string plaintext(groupKeyArray.begin(), groupKeyArray.end());
    return encryptWithAesGcm(plaintext, wrapKey, aadForGroupKey(roomId, targetId), {
        {"type", GroupKeyType},
        {"version", 2},
        {"roomId", roomId},
        {"targetId", targetId},
        {"senderId", chat::protocol::HostActorId},
        {"alg", "AES-256-GCM"},
        {"kdf", "X25519-HKDF-SHA256"},
        {"ephemeralPublicKey", ephemeral.publicKey}
    });
}

std::vector<unsigned char> decryptGroupKeyForMember(
    const json& envelope,
    const std::string& roomId,
    const std::string& clientId,
    const std::vector<unsigned char>& privateKey) {
    // A Client only accepts group keys addressed to its own server-assigned id.
    // This prevents replaying another member's key envelope into this session.
    if (envelope.value("type", "") != GroupKeyType ||
        envelope.value("version", 0) != 2 ||
        envelope.value("roomId", "") != roomId ||
        envelope.value("targetId", "") != clientId) {
        throw std::runtime_error("group key envelope is not for this member");
    }
    const auto ephemeralPublic = base64Decode(envelope.value("ephemeralPublicKey", ""));
    const auto secret = deriveX25519Secret(privateKey, ephemeralPublic);
    const auto wrapKey = hkdfSha256(secret, "securechat-gka-v2:" + roomId, "group-key|" + clientId);
    const auto plaintext = decryptWithAesGcm(envelope, wrapKey, aadForGroupKey(roomId, clientId));
    std::vector<unsigned char> groupKey(plaintext.begin(), plaintext.end());
    if (!hasUsableGroupKey(groupKey)) throw std::runtime_error("invalid unwrapped group key");
    return groupKey;
}

}
