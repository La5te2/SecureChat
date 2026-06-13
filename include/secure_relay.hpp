// Encrypted relay declarations: room-token routing, contributory GKA,
// room-message encryption, and pairwise private message encryption.
#pragma once

#include "common.hpp"

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace chat::secure_relay {

// v3 relay cryptography:
// - Each member signs a fresh random contribution for a GKA epoch.
// - Members derive the room group key from the signed contribution set.
// - Each member has a temporary X25519 key pair for receiving GKA state and
//   pairwise-private messages.
// - Server only forwards JSON envelopes and never sees plaintext keys.
inline constexpr const char* EnvelopeType = "encrypted_relay";
inline constexpr const char* GroupKeyType = "group_key";
inline constexpr const char* PairwisePrivateType = "pairwise_private";
inline constexpr const char* GkaContributionType = "gka_contribution";
inline constexpr const char* GkaRequestType = "gka_request";
inline constexpr std::size_t GroupKeyBytes = 32;

struct MemberKeyPair {
    // Raw X25519 private key bytes remain local; publicKey is base64 for JSON.
    std::vector<unsigned char> privateKey;
    std::string publicKey;
};

// Generates a member X25519 key pair. The public key is sent through signaling;
// the private key stays in the local Host/Client process.
MemberKeyPair generateMemberKeyPair();

// Generates one base64-encoded 32-byte member contribution for a GKA epoch.
std::string generateGroupContribution();

// Returns whether a group key has the expected size for relay encryption.
bool hasUsableGroupKey(const std::vector<unsigned char>& key);

// Derives the opaque room token sent to Server. The human room id stays local;
// Server uses only this token for registration/routing.
std::string deriveRoomToken(const std::string& roomId, const std::string& roomPassword);

// Derives K_G from a verified contribution array. Each contribution object must
// contain memberId, publicKey, fingerprint, and contribution.
std::vector<unsigned char> deriveGroupKeyFromContributions(
    const std::string& roomId,
    std::uint64_t epoch,
    const json& contributions);

// Encrypts one signed contribution to Host's X25519 public key. Server routes
// by connection state and cannot read the contribution secret.
json encryptGkaContributionForHost(
    const json& contribution,
    const std::string& roomId,
    const std::string& senderId,
    const std::string& hostPublicKey,
    std::uint64_t epoch);

// Opens a Client contribution encrypted to Host.
json decryptGkaContributionForHost(
    const json& envelope,
    const std::string& roomId,
    const std::string& expectedSenderId,
    const std::vector<unsigned char>& hostPrivateKey);

// Encrypts one application protocol Message with the negotiated room group key.
json encryptMessageWithGroupKey(
    const Message& message,
    const std::string& roomId,
    const std::string& senderId,
    const std::string& senderName,
    const std::string& senderKind,
    const std::string& targetId,
    const std::vector<unsigned char>& groupKey);

// Decrypts one relay envelope with the negotiated room group key.
Message decryptMessageWithGroupKey(
    const json& envelope,
    const std::string& roomId,
    const std::vector<unsigned char>& groupKey);

// Builds an inner pairwise-private message. The result is still sent through the
// outer room encrypted_relay, but only the target member can decrypt this body.
Message encryptMessageForPairwise(
    const Message& message,
    const std::string& roomId,
    const std::string& senderId,
    const std::string& targetId,
    const std::string& targetPublicKey,
    const std::string& senderFingerprint,
    const std::string& targetFingerprint);

// Decrypts a pairwise-private message using the local X25519 private key and
// previously verified sender/target certificate fingerprints.
Message decryptMessageFromPairwise(
    const Message& wrapper,
    const std::string& roomId,
    const std::string& expectedSenderId,
    const std::string& expectedTargetId,
    const std::vector<unsigned char>& localPrivateKey,
    const std::string& expectedSenderFingerprint,
    const std::string& expectedTargetFingerprint);

// Returns a compact key for local replay caches. It is not secret; it combines
// authenticated envelope metadata and AEAD nonce/tag.
std::string replayIdForEnvelope(const json& envelope);

// Wraps the verified GKA contribution set to one member public key. Server only
// sees this opaque envelope and forwards it to the target member.
json encryptGroupStateForMember(
    const json& groupState,
    const std::string& roomId,
    const std::string& targetId,
    const std::string& targetPublicKey,
    std::uint64_t epoch);

// Unwraps a Host-distributed GKA contribution set using this member's X25519
// private key. The caller verifies contribution signatures before deriving K_G.
json decryptGroupStateForMember(
    const json& envelope,
    const std::string& roomId,
    const std::string& clientId,
    const std::vector<unsigned char>& privateKey);

}
