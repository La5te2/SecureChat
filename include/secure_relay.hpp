#pragma once

#include "common.hpp"

#include <array>
#include <string>
#include <vector>

namespace chat::secure_relay {

inline constexpr const char* EnvelopeType = "encrypted_relay";
inline constexpr const char* GroupKeyType = "group_key";
inline constexpr std::size_t GroupKeyBytes = 32;

struct MemberKeyPair {
    std::vector<unsigned char> privateKey;
    std::string publicKey;
};

// Generates a member X25519 key pair. The public key is sent through signaling;
// the private key stays in the local Host/Client process.
MemberKeyPair generateMemberKeyPair();

// Generates the room group key used for AES-GCM message and attachment E2EE.
std::array<unsigned char, GroupKeyBytes> generateGroupKey();

// Returns whether a group key has the expected size for v2 relay encryption.
bool hasUsableGroupKey(const std::vector<unsigned char>& key);

// Encrypts one application protocol Message with the negotiated room group key.
json encryptMessageWithGroupKey(
    const Message& message,
    const std::string& roomId,
    const std::string& senderId,
    const std::string& senderName,
    const std::string& senderKind,
    const std::vector<unsigned char>& groupKey);

// Decrypts one relay envelope with the negotiated room group key.
Message decryptMessageWithGroupKey(
    const json& envelope,
    const std::string& roomId,
    const std::vector<unsigned char>& groupKey);

// Wraps the current room group key to one member public key. Server only sees
// this opaque key envelope and forwards it to the target member.
json encryptGroupKeyForMember(
    const std::vector<unsigned char>& groupKey,
    const std::string& roomId,
    const std::string& targetId,
    const std::string& targetPublicKey);

// Unwraps a Host-distributed group key using this member's X25519 private key.
std::vector<unsigned char> decryptGroupKeyForMember(
    const json& envelope,
    const std::string& roomId,
    const std::string& clientId,
    const std::vector<unsigned char>& privateKey);

}
