// Cryptographic relay implementation. It encrypts chat payloads with AES-GCM
// and wraps room group keys with X25519 plus HKDF.
#include "secure_relay.hpp"

#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <memory>
#include <sstream>
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
    (void)senderKind;
    (void)targetId;
    // Phase 12 keeps only the room token and sender connection id in clear AAD.
    // Application sender name, role, and private target live inside ciphertext.
    const std::string aad = std::string("securechat-relay-v3|") + roomId + "|" + senderId;
    return {aad.begin(), aad.end()};
}

std::vector<unsigned char> aadForGroupKey(
    const std::string& roomId,
    const std::string& targetId,
    std::uint64_t epoch) {
    // The group key envelope is also bound to room and target id. Replaying a
    // wrapped key to another member fails before the group key is accepted.
    const std::string aad = std::string("securechat-gka-v3|") +
        roomId + "|" +
        targetId + "|" +
        std::to_string(epoch);
    return {aad.begin(), aad.end()};
}

std::vector<unsigned char> aadForGkaContribution(
    const std::string& roomId,
    const std::string& senderId,
    std::uint64_t epoch,
    const std::string& ephemeralPublicKey) {
    // Contributions are sent from a member to Host before the next K_G exists.
    // AAD binds the opaque room token, sender connection id, epoch, and sender
    // one-time X25519 public key to the ciphertext.
    const std::string aad = std::string("securechat-gka-contribution-v1|") +
        roomId + "|" +
        senderId + "|" +
        std::to_string(epoch) + "|" +
        ephemeralPublicKey;
    return {aad.begin(), aad.end()};
}

std::vector<unsigned char> aadForPairwise(
    const std::string& roomId,
    const std::string& senderId,
    const std::string& targetId,
    const std::string& senderFingerprint,
    const std::string& targetFingerprint,
    const std::string& ephemeralPublicKey) {
    // Pairwise AAD binds the inner ciphertext to both member identities and the
    // sender's one-time X25519 public key. If Host/Server swaps a public key or
    // member identity, AES-GCM authentication fails at the target.
    const std::string aad = std::string("securechat-pairwise-v1|") +
        roomId + "|" +
        senderId + "|" +
        targetId + "|" +
        senderFingerprint + "|" +
        targetFingerprint + "|" +
        ephemeralPublicKey;
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
    // X25519 derives a shared secret from one local private key and one peer
    // public key. The raw secret is never used directly as an AES key.
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
    // HKDF turns the X25519 shared secret into a uniformly shaped AES-256 key
    // and domain-separates this use from any future protocol use of X25519.
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
    // AES-GCM provides confidentiality plus integrity. nonce/ciphertext/tag are
    // stored in JSON as base64 so they can pass through WebSocket text frames.
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
    // Decryption succeeds only if the tag matches the ciphertext and the exact
    // same AAD. Tag failure means tampering, wrong key, or wrong routing metadata.
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
    // Each Host/Client session creates a fresh temporary X25519 pair. The public
    // half is signed by PKI before Host trusts it for GKA.
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

bool hasUsableGroupKey(const std::vector<unsigned char>& key) {
    return key.size() == GroupKeyBytes;
}

std::string generateGroupContribution() {
    const auto contribution = randomBytes(GroupKeyBytes);
    return base64Encode(contribution.data(), contribution.size());
}

std::string deriveRoomToken(const std::string& roomId, const std::string& roomPassword) {
    // The Server only needs a stable room routing token. Hashing room id with the
    // room password hides the human-readable room name from Server logs/state.
    const std::string input = "securechat-room-token-v1|" + roomId + "|" + roomPassword;
    unsigned char digest[SHA256_DIGEST_LENGTH] = {};
    SHA256(
        reinterpret_cast<const unsigned char*>(input.data()),
        input.size(),
        digest);
    return base64Encode(digest, sizeof(digest));
}

std::vector<unsigned char> deriveGroupKeyFromContributions(
    const std::string& roomId,
    std::uint64_t epoch,
    const json& contributions) {
    if (!contributions.is_array() || contributions.empty()) {
        throw std::runtime_error("GKA contribution set is empty");
    }

    std::vector<json> ordered;
    ordered.reserve(contributions.size());
    for (const auto& item : contributions) {
        if (!item.is_object()) throw std::runtime_error("GKA contribution must be an object");
        const auto memberId = item.value("memberId", "");
        const auto publicKey = item.value("publicKey", "");
        const auto fingerprint = item.value("fingerprint", "");
        const auto contribution = item.value("contribution", "");
        if (memberId.empty() || publicKey.empty() || fingerprint.empty() || contribution.empty()) {
            throw std::runtime_error("GKA contribution is missing required fields");
        }
        const auto contributionBytes = base64Decode(contribution);
        if (contributionBytes.size() != GroupKeyBytes) {
            throw std::runtime_error("GKA contribution has invalid size");
        }
        ordered.push_back(item);
    }

    std::sort(ordered.begin(), ordered.end(), [](const json& left, const json& right) {
        return left.value("memberId", "") < right.value("memberId", "");
    });

    std::string canonical = "securechat-gka-v3\n";
    canonical += "roomId:" + std::to_string(roomId.size()) + ":" + roomId + "\n";
    canonical += "epoch:" + std::to_string(std::to_string(epoch).size()) + ":" + std::to_string(epoch) + "\n";
    std::string memberInfo;
    for (const auto& item : ordered) {
        const auto memberId = item.value("memberId", "");
        if (!memberInfo.empty()) memberInfo += ",";
        memberInfo += memberId;
        const auto username = item.value("username", "");
        const auto publicKey = item.value("publicKey", "");
        const auto fingerprint = item.value("fingerprint", "");
        const auto contribution = item.value("contribution", "");
        canonical += "memberId:" + std::to_string(memberId.size()) + ":" + memberId + "\n";
        canonical += "username:" + std::to_string(username.size()) + ":" + username + "\n";
        canonical += "publicKey:" + std::to_string(publicKey.size()) + ":" + publicKey + "\n";
        canonical += "fingerprint:" + std::to_string(fingerprint.size()) + ":" + fingerprint + "\n";
        canonical += "contribution:" + std::to_string(contribution.size()) + ":" + contribution + "\n";
    }

    const std::vector<unsigned char> secret(canonical.begin(), canonical.end());
    const auto key = hkdfSha256(
        secret,
        "securechat-gka-v3:" + roomId + "|" + std::to_string(epoch),
        "room-group-key|" + memberInfo);
    return {key.begin(), key.end()};
}

json encryptGkaContributionForHost(
    const json& contribution,
    const std::string& roomId,
    const std::string& senderId,
    const std::string& hostPublicKey,
    std::uint64_t epoch) {
    if (!contribution.is_object()) throw std::runtime_error("GKA contribution payload must be an object");
    if (senderId.empty()) throw std::runtime_error("GKA contribution sender is missing");
    const auto recipientPublic = base64Decode(hostPublicKey);
    auto ephemeral = generateMemberKeyPair();
    const auto secret = deriveX25519Secret(ephemeral.privateKey, recipientPublic);
    const auto wrapKey = hkdfSha256(
        secret,
        "securechat-gka-contribution-v1:" + roomId,
        "member-contribution|" + senderId + "|" + std::to_string(epoch));
    return encryptWithAesGcm(
        contribution.dump(),
        wrapKey,
        aadForGkaContribution(roomId, senderId, epoch, ephemeral.publicKey),
        {
            {"type", GkaContributionType},
            {"version", 1},
            {"epoch", epoch},
            {"roomId", roomId},
            {"senderId", senderId},
            {"alg", "AES-256-GCM"},
            {"kdf", "X25519-HKDF-SHA256"},
            {"ephemeralPublicKey", ephemeral.publicKey}
        });
}

json decryptGkaContributionForHost(
    const json& envelope,
    const std::string& roomId,
    const std::string& expectedSenderId,
    const std::vector<unsigned char>& hostPrivateKey) {
    if (envelope.value("type", "") != GkaContributionType ||
        envelope.value("version", 0) != 1 ||
        envelope.value("roomId", "") != roomId ||
        envelope.value("senderId", "") != expectedSenderId) {
        throw std::runtime_error("GKA contribution envelope metadata mismatch");
    }
    const auto epoch = envelope.value("epoch", 0ULL);
    const auto ephemeralPublic = envelope.value("ephemeralPublicKey", "");
    const auto secret = deriveX25519Secret(hostPrivateKey, base64Decode(ephemeralPublic));
    const auto wrapKey = hkdfSha256(
        secret,
        "securechat-gka-contribution-v1:" + roomId,
        "member-contribution|" + expectedSenderId + "|" + std::to_string(epoch));
    const auto plaintext = decryptWithAesGcm(
        envelope,
        wrapKey,
        aadForGkaContribution(roomId, expectedSenderId, epoch, ephemeralPublic));
    return chat::protocol::parseJsonObjectWithBudget(
        plaintext,
        chat::protocol::MaxSignalingMessageBytes,
        "GKA contribution");
}

json encryptMessageWithGroupKey(
    const Message& message,
    const std::string& roomId,
    const std::string& senderId,
    const std::string& senderName,
    const std::string& senderKind,
    const std::string& targetId,
    const std::vector<unsigned char>& groupKey) {
    // senderName/senderKind/targetId are intentionally not emitted in clear
    // anymore. The Server sees only a room token and sender connection id; the
    // encrypted Message payload carries application identity and private target.
    const auto key = keyArrayFromVector(groupKey);
    const auto aad = aadForEnvelope(roomId, senderId, senderKind, targetId);
    return encryptWithAesGcm(message.toJson(), key, aad, {
        {"type", EnvelopeType},
        {"version", 3},
        {"roomId", roomId},
        {"senderId", senderId},
        {"alg", "AES-256-GCM"},
        {"kdf", "GKA-Contrib-v3-HKDF-SHA256"}
    });
}

Message decryptMessageWithGroupKey(
    const json& envelope,
    const std::string& roomId,
    const std::vector<unsigned char>& groupKey) {
    // Rebuild the same AAD from envelope metadata before decrypting. In v3 this
    // authenticates only the opaque room token and sender connection id; sender
    // display name, role, and target live inside the encrypted Message payload.
    if (envelope.value("type", "") != EnvelopeType) {
        throw std::runtime_error("not an encrypted relay envelope");
    }
    if (envelope.value("roomId", "") != roomId) {
        throw std::runtime_error("encrypted relay room mismatch");
    }
    if (envelope.value("version", 0) != 3 || envelope.value("alg", "") != "AES-256-GCM") {
        throw std::runtime_error("unsupported encrypted relay envelope");
    }
    const auto key = keyArrayFromVector(groupKey);
    const auto senderId = envelope.value("senderId", "");
    const auto senderKind = envelope.value("senderKind", "");
    const auto targetId = envelope.value("targetId", "");
    const auto plaintext = decryptWithAesGcm(envelope, key, aadForEnvelope(roomId, senderId, senderKind, targetId));
    auto message = Message::fromJson(plaintext);
    // Only senderId remains clear and authenticated by the relay envelope.
    // Private target stays encrypted in message.payload["targetId"] so Server
    // does not learn who a private message is for.
    message.payload["relaySenderId"] = senderId;
    message.payload["relaySenderKind"] = message.payload.value("actorKind", "");
    message.payload["relaySenderName"] = message.payload.value("displayName", "");
    message.payload["relayTargetId"] = message.payload.value("targetId", "");
    return message;
}

Message encryptMessageForPairwise(
    const Message& message,
    const std::string& roomId,
    const std::string& senderId,
    const std::string& targetId,
    const std::string& targetPublicKey,
    const std::string& senderFingerprint,
    const std::string& targetFingerprint) {
    if (senderId.empty() || targetId.empty()) throw std::runtime_error("pairwise sender or target is missing");
    if (senderFingerprint.empty() || targetFingerprint.empty()) {
        throw std::runtime_error("pairwise identity fingerprint is missing");
    }

    const auto recipientPublic = base64Decode(targetPublicKey);
    auto ephemeral = generateMemberKeyPair();
    const auto secret = deriveX25519Secret(ephemeral.privateKey, recipientPublic);
    // Do not derive pairwise keys from K_G: every room member has K_G. Use a new
    // sender ephemeral X25519 secret with the target's PKI-bound public key.
    const auto pairwiseKey = hkdfSha256(
        secret,
        "securechat-pairwise-v1:" + roomId + "|" + senderId + "|" + targetId,
        "private-message|" + senderFingerprint + "|" + targetFingerprint + "|" + ephemeral.publicKey);
    const auto inner = encryptWithAesGcm(
        message.toJson(),
        pairwiseKey,
        aadForPairwise(roomId, senderId, targetId, senderFingerprint, targetFingerprint, ephemeral.publicKey),
        {
            {"version", 1},
            {"roomId", roomId},
            {"senderId", senderId},
            {"targetId", targetId},
            {"alg", "AES-256-GCM"},
            {"kdf", "X25519-HKDF-SHA256"},
            {"ephemeralPublicKey", ephemeral.publicKey},
            {"senderFingerprint", senderFingerprint},
            {"targetFingerprint", targetFingerprint}
        });

    Message wrapper;
    wrapper.type = PairwisePrivateType;
    wrapper.from = message.from;
    wrapper.payload["pairwise"] = inner;
    wrapper.payload["private"] = true;
    wrapper.payload["targetId"] = targetId;
    return wrapper;
}

Message decryptMessageFromPairwise(
    const Message& wrapper,
    const std::string& roomId,
    const std::string& expectedSenderId,
    const std::string& expectedTargetId,
    const std::vector<unsigned char>& localPrivateKey,
    const std::string& expectedSenderFingerprint,
    const std::string& expectedTargetFingerprint) {
    if (wrapper.type != PairwisePrivateType) throw std::runtime_error("not a pairwise private message");
    const auto it = wrapper.payload.find("pairwise");
    if (it == wrapper.payload.end() || !it->is_object()) {
        throw std::runtime_error("pairwise envelope is missing");
    }
    const auto& inner = *it;
    if (inner.value("version", 0) != 1 ||
        inner.value("roomId", "") != roomId ||
        inner.value("senderId", "") != expectedSenderId ||
        inner.value("targetId", "") != expectedTargetId ||
        inner.value("alg", "") != "AES-256-GCM" ||
        inner.value("kdf", "") != "X25519-HKDF-SHA256") {
        throw std::runtime_error("pairwise envelope metadata mismatch");
    }
    const auto senderFingerprint = inner.value("senderFingerprint", "");
    const auto targetFingerprint = inner.value("targetFingerprint", "");
    if (senderFingerprint != expectedSenderFingerprint || targetFingerprint != expectedTargetFingerprint) {
        throw std::runtime_error("pairwise identity fingerprint mismatch");
    }

    const auto ephemeralPublic = inner.value("ephemeralPublicKey", "");
    const auto secret = deriveX25519Secret(localPrivateKey, base64Decode(ephemeralPublic));
    const auto pairwiseKey = hkdfSha256(
        secret,
        "securechat-pairwise-v1:" + roomId + "|" + expectedSenderId + "|" + expectedTargetId,
        "private-message|" + senderFingerprint + "|" + targetFingerprint + "|" + ephemeralPublic);
    const auto plaintext = decryptWithAesGcm(
        inner,
        pairwiseKey,
        aadForPairwise(roomId, expectedSenderId, expectedTargetId, senderFingerprint, targetFingerprint, ephemeralPublic));
    auto message = Message::fromJson(plaintext);
    message.payload["pairwisePrivate"] = true;
    return message;
}

std::string replayIdForEnvelope(const json& envelope) {
    return envelope.value("type", "") + "|" +
        envelope.value("roomId", "") + "|" +
        envelope.value("senderId", "") + "|" +
        envelope.value("nonce", "") + "|" +
        envelope.value("tag", "");
}

json encryptGroupStateForMember(
    const json& groupState,
    const std::string& roomId,
    const std::string& targetId,
    const std::string& targetPublicKey,
    std::uint64_t epoch) {
    // Wraps the verified GKA contribution set to one Client using ephemeral
    // X25519. The target derives K_G locally from this state after verification.
    if (!groupState.is_object()) throw std::runtime_error("GKA group state must be an object");
    const auto recipientPublic = base64Decode(targetPublicKey);
    auto ephemeral = generateMemberKeyPair();
    const auto secret = deriveX25519Secret(ephemeral.privateKey, recipientPublic);
    const auto wrapKey = hkdfSha256(secret, "securechat-gka-state-v3:" + roomId, "group-state|" + targetId + "|" + std::to_string(epoch));
    return encryptWithAesGcm(groupState.dump(), wrapKey, aadForGroupKey(roomId, targetId, epoch), {
        {"type", GroupKeyType},
        {"version", 3},
        {"epoch", epoch},
        {"roomId", roomId},
        {"targetId", targetId},
        {"senderId", chat::protocol::HostActorId},
        {"alg", "AES-256-GCM"},
        {"kdf", "X25519-HKDF-SHA256+GKA-Contrib-v3"},
        {"ephemeralPublicKey", ephemeral.publicKey}
    });
}

json decryptGroupStateForMember(
    const json& envelope,
    const std::string& roomId,
    const std::string& clientId,
    const std::vector<unsigned char>& privateKey) {
    // A Client only accepts GKA state addressed to its own server-assigned id.
    // It still verifies contribution signatures before deriving K_G.
    if (envelope.value("type", "") != GroupKeyType ||
        envelope.value("version", 0) != 3 ||
        envelope.value("roomId", "") != roomId ||
        envelope.value("targetId", "") != clientId) {
        throw std::runtime_error("GKA group state envelope is not for this member");
    }
    const auto epoch = envelope.value("epoch", 0ULL);
    const auto ephemeralPublic = base64Decode(envelope.value("ephemeralPublicKey", ""));
    const auto secret = deriveX25519Secret(privateKey, ephemeralPublic);
    const auto wrapKey = hkdfSha256(secret, "securechat-gka-state-v3:" + roomId, "group-state|" + clientId + "|" + std::to_string(epoch));
    const auto plaintext = decryptWithAesGcm(envelope, wrapKey, aadForGroupKey(roomId, clientId, epoch));
    return chat::protocol::parseJsonObjectWithBudget(
        plaintext,
        chat::protocol::MaxSignalingMessageBytes,
        "GKA group state");
}

}
