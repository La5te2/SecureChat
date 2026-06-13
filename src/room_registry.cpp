// Room registry implementation. It stores only process-local room membership
// and a hash of the room password used for equality checks.
#include "room_registry.hpp"

#include <openssl/crypto.h>
#include <openssl/evp.h>

#include <array>
#include <memory>
#include <stdexcept>
#include <utility>

namespace {
std::array<unsigned char, 32> hashRoomPassword(const std::string& roomId, const std::string& password) {
    // The registry only needs equality checks. Store a domain-separated digest
    // instead of retaining the room password as a long-lived plaintext string.
    std::array<unsigned char, 32> digest{};
    using CtxPtr = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;
    CtxPtr ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    if (!ctx) throw std::runtime_error("could not create password hash context");

    const unsigned char separator = 0;
    unsigned int digestLength = 0;
    if (EVP_DigestInit_ex(ctx.get(), EVP_sha256(), nullptr) != 1 ||
        EVP_DigestUpdate(ctx.get(), "securechat-room-v1", 18) != 1 ||
        EVP_DigestUpdate(ctx.get(), &separator, 1) != 1 ||
        EVP_DigestUpdate(ctx.get(), roomId.data(), roomId.size()) != 1 ||
        EVP_DigestUpdate(ctx.get(), &separator, 1) != 1 ||
        EVP_DigestUpdate(ctx.get(), password.data(), password.size()) != 1 ||
        EVP_DigestFinal_ex(ctx.get(), digest.data(), &digestLength) != 1 ||
        digestLength != digest.size()) {
        throw std::runtime_error("could not hash room password");
    }
    return digest;
}
}

void RoomRegistry::createRoom(const std::string& roomId, const UserAccount& host, const std::string& password) {
    // Called only after SignalingServer has confirmed the room id is not already
    // active on this Server instance.
    if (roomId.empty()) throw std::runtime_error("missing roomId");
    if (mRooms.find(roomId) != mRooms.end()) throw std::runtime_error("room already exists");

    RoomState room;
    room.roomId = roomId;
    room.passwordHash = hashRoomPassword(roomId, password);
    room.host = RoomMember{host, RoomRole::Host};
    mRooms[roomId] = std::move(room);
}

bool RoomRegistry::passwordMatches(const std::string& roomId, const std::string& password) const {
    auto it = mRooms.find(roomId);
    if (it == mRooms.end()) return false;

    const auto suppliedHash = hashRoomPassword(roomId, password);
    // Use constant-time comparison so wrong guesses do not leak prefix matches.
    return CRYPTO_memcmp(
        it->second.passwordHash.data(),
        suppliedHash.data(),
        it->second.passwordHash.size()) == 0;
}

RoomMember RoomRegistry::joinClient(const std::string& roomId, const UserAccount& client) {
    // Rejoining the same user id refreshes process-local membership state.
    auto& room = requireRoom(roomId);
    auto& member = room.clients[client.userId];
    member = RoomMember{client, RoomRole::Client};
    return member;
}

void RoomRegistry::closeRoom(const std::string& roomId) {
    // Closing a room drops all process-local membership state.
    mRooms.erase(roomId);
}

RoomRegistry::RoomState& RoomRegistry::requireRoom(const std::string& roomId) {
    // Internal helper for operations that require an active room with a Host.
    auto it = mRooms.find(roomId);
    if (it == mRooms.end() || !it->second.host) throw std::runtime_error("room not found");
    return it->second;
}
