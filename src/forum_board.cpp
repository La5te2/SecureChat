// 房间留言板密文记录实现。
#include "forum_board.hpp"
#include "cert_utils.hpp"

#include <openssl/evp.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

namespace chat::forum_board {
namespace {
constexpr int keyBytes = 32;
constexpr int nonceBytes = 12;
constexpr int tagBytes = 16;

using CipherCtx = std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>;

std::uint64_t unixMillis() {
    const auto now = std::chrono::system_clock::now().time_since_epoch();
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(now).count());
}

std::array<unsigned char, keyBytes> keyArray(const std::vector<unsigned char>& key) {
    if (key.size() != keyBytes) throw std::runtime_error("forum post key size is invalid");
    std::array<unsigned char, keyBytes> out{};
    std::copy(key.begin(), key.end(), out.begin());
    return out;
}

std::vector<unsigned char> aadForRecord(
    const std::string& roomToken,
    const std::string& boardMessageId,
    const std::string& authorFingerprint) {
    const std::string aad = "securechat-forum-v1|" + roomToken + "|" + boardMessageId + "|" + authorFingerprint;
    return {aad.begin(), aad.end()};
}

json encryptText(
    const std::string& text,
    const std::vector<unsigned char>& postKey,
    const std::vector<unsigned char>& aad,
    json record) {
    const auto key = keyArray(postKey);
    const auto nonce = chat::cert_utils::randomBytes(nonceBytes);
    CipherCtx ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    if (!ctx ||
        EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, nonceBytes, nullptr) != 1 ||
        EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), nonce.data()) != 1) {
        throw std::runtime_error("forum AES-GCM encryption setup failed");
    }

    int outLen = 0;
    if (EVP_EncryptUpdate(ctx.get(), nullptr, &outLen, aad.data(), static_cast<int>(aad.size())) != 1) {
        throw std::runtime_error("forum AES-GCM AAD failed");
    }

    std::vector<unsigned char> ciphertext(text.size() + tagBytes);
    if (EVP_EncryptUpdate(
            ctx.get(),
            ciphertext.data(),
            &outLen,
            reinterpret_cast<const unsigned char*>(text.data()),
            static_cast<int>(text.size())) != 1) {
        throw std::runtime_error("forum AES-GCM encryption failed");
    }
    int ciphertextLen = outLen;
    if (EVP_EncryptFinal_ex(ctx.get(), ciphertext.data() + ciphertextLen, &outLen) != 1) {
        throw std::runtime_error("forum AES-GCM encryption final failed");
    }
    ciphertextLen += outLen;
    ciphertext.resize(static_cast<std::size_t>(ciphertextLen));

    std::array<unsigned char, tagBytes> tag{};
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, tagBytes, tag.data()) != 1) {
        throw std::runtime_error("forum AES-GCM tag failed");
    }

    record["nonce"] = chat::cert_utils::base64Encode(nonce);
    record["ciphertext"] = chat::cert_utils::base64Encode(ciphertext);
    record["tag"] = chat::cert_utils::base64Encode(tag.data(), tag.size());
    return record;
}

std::string decryptText(
    const json& record,
    const std::vector<unsigned char>& postKey,
    const std::vector<unsigned char>& aad) {
    const auto key = keyArray(postKey);
    const auto nonce = chat::cert_utils::base64Decode(record.value("nonce", ""));
    const auto ciphertext = chat::cert_utils::base64Decode(record.value("ciphertext", ""));
    const auto tag = chat::cert_utils::base64Decode(record.value("tag", ""));
    if (nonce.size() != nonceBytes || tag.size() != tagBytes) {
        throw std::runtime_error("forum AES-GCM nonce or tag is invalid");
    }

    CipherCtx ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    if (!ctx ||
        EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, nonceBytes, nullptr) != 1 ||
        EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), nonce.data()) != 1) {
        throw std::runtime_error("forum AES-GCM decryption setup failed");
    }

    int outLen = 0;
    if (EVP_DecryptUpdate(ctx.get(), nullptr, &outLen, aad.data(), static_cast<int>(aad.size())) != 1) {
        throw std::runtime_error("forum AES-GCM AAD failed");
    }

    std::vector<unsigned char> plaintext(ciphertext.size());
    if (EVP_DecryptUpdate(ctx.get(), plaintext.data(), &outLen, ciphertext.data(), static_cast<int>(ciphertext.size())) != 1) {
        throw std::runtime_error("forum AES-GCM decryption failed");
    }
    int plaintextLen = outLen;
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, tagBytes, const_cast<unsigned char*>(tag.data())) != 1 ||
        EVP_DecryptFinal_ex(ctx.get(), plaintext.data() + plaintextLen, &outLen) != 1) {
        throw std::runtime_error("forum AES-GCM authentication failed");
    }
    plaintextLen += outLen;
    plaintext.resize(static_cast<std::size_t>(plaintextLen));
    return std::string(plaintext.begin(), plaintext.end());
}

json stablePayload(const json& record) {
    json copy = record;
    copy.erase("payloadDigest");
    copy.erase("control");
    return copy;
}

}

std::string payloadDigest(const json& record) {
    return chat::cert_utils::sha256Hex(stablePayload(record).dump());
}

json makeRecord(
    const std::string& roomId,
    const std::string& roomToken,
    std::uint64_t epoch,
    const std::string& authorMemberId,
    const std::string& authorDisplayName,
    const chat::pki_application::IdentityContext& identity,
    const std::vector<Recipient>& recipients,
    const std::string& text) {
    if (roomToken.empty()) throw std::runtime_error("forum room token is missing");
    if (text.empty()) throw std::runtime_error("forum post text is empty");
    if (text.size() > MaxPostTextBytes) throw std::runtime_error("forum post text is too large");
    if (recipients.empty()) throw std::runtime_error("forum has no approved recipients");
    const auto authorFingerprint = identity.fingerprint();
    if (authorFingerprint.empty()) throw std::runtime_error("forum author fingerprint is missing");

    auto postKey = chat::cert_utils::randomBytes(keyBytes);
    const auto createdAt = unixMillis();
    const auto randomPart = chat::cert_utils::base64Encode(chat::cert_utils::randomBytes(16));
    const auto boardMessageId = chat::cert_utils::sha256Hex(
        roomToken + "|" + authorFingerprint + "|" + std::to_string(createdAt) + "|" + randomPart);

    std::vector<Recipient> ordered = recipients;
    std::sort(ordered.begin(), ordered.end(), [](const Recipient& left, const Recipient& right) {
        return left.fingerprint < right.fingerprint;
    });

    json keyEnvelopes = json::array();
    for (const auto& recipient : ordered) {
        if (recipient.memberId.empty() || recipient.fingerprint.empty() || !recipient.identity.is_object()) continue;
        keyEnvelopes.push_back({
            {"memberId", recipient.memberId},
            {"displayName", recipient.displayName},
            {"fingerprint", recipient.fingerprint},
            {"key", identity.sealBytesForIdentity("forum_post_key", recipient.fingerprint, postKey, recipient.identity)}
        });
    }
    if (keyEnvelopes.empty()) throw std::runtime_error("forum has no usable recipient identities");

    json record = {
        {"type", RecordType},
        {"version", 1},
        {"roomId", roomToken},
        {"epoch", epoch},
        {"boardMessageId", boardMessageId},
        {"authorMemberId", authorMemberId},
        {"authorDisplayName", authorDisplayName},
        {"authorFingerprint", authorFingerprint},
        {"createdAtUnixMs", createdAt},
        {"alg", "AES-256-GCM"},
        {"keyAlg", "RSA-OAEP-SHA256"},
        {"keyEnvelopes", keyEnvelopes}
    };
    record = encryptText(text, postKey, aadForRecord(roomToken, boardMessageId, authorFingerprint), std::move(record));
    const auto digest = payloadDigest(record);
    record["payloadDigest"] = digest;
    record["control"] = identity.signRoomControl(roomId, roomToken, "forum_record", epoch, digest);
    return record;
}

DisplayRecord openRecord(
    const std::string& roomId,
    const std::string& roomToken,
    const chat::pki_application::IdentityContext& identity,
    const json& record) {
    if (!record.is_object() ||
        record.value("type", "") != RecordType ||
        record.value("version", 0) != 1 ||
        record.value("roomId", "") != roomToken ||
        record.value("alg", "") != "AES-256-GCM" ||
        record.value("keyAlg", "") != "RSA-OAEP-SHA256") {
        throw std::runtime_error("unsupported forum record");
    }
    const auto digest = record.value("payloadDigest", "");
    if (digest.empty() || digest != payloadDigest(record)) {
        throw std::runtime_error("forum record digest mismatch");
    }
    const auto control = record.find("control");
    if (control == record.end() || !control->is_object()) {
        throw std::runtime_error("forum record signature is missing");
    }
    const auto epoch = record.value("epoch", 0ULL);
    const auto signer = identity.verifyRoomControl(roomId, roomToken, "forum_record", epoch, digest, *control);
    const auto authorFingerprint = record.value("authorFingerprint", "");
    if (signer.fingerprint != authorFingerprint) {
        throw std::runtime_error("forum record signer does not match author");
    }

    json selectedKey;
    for (const auto& item : record.value("keyEnvelopes", json::array())) {
        if (!item.is_object()) continue;
        if (item.value("fingerprint", "") == identity.fingerprint()) {
            selectedKey = item.value("key", json::object());
            break;
        }
    }
    if (!selectedKey.is_object() || selectedKey.empty()) {
        throw std::runtime_error("forum record has no key envelope for this member");
    }
    const auto postKey = identity.openSealedBytes("forum_post_key", selectedKey);
    const auto boardMessageId = record.value("boardMessageId", "");
    const auto text = decryptText(record, postKey, aadForRecord(roomToken, boardMessageId, authorFingerprint));
    return {
        boardMessageId,
        record.value("authorDisplayName", record.value("authorMemberId", "")),
        authorFingerprint,
        text,
        record.value("createdAtUnixMs", 0ULL),
        authorFingerprint == identity.fingerprint()
    };
}

}
