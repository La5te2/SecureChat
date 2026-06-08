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
    if (roomId.empty()) throw std::runtime_error("missing roomId");

    RoomState room;
    room.roomId = roomId;
    room.passwordHash = hashRoomPassword(roomId, password);
    room.host = RoomMember{host, RoomRole::Host, true};
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
    auto& room = requireRoom(roomId);
    auto& member = room.clients[client.userId];
    member = RoomMember{client, RoomRole::Client, true};
    return member;
}

void RoomRegistry::markOffline(const std::string& roomId, const std::string& userId) {
    auto it = mRooms.find(roomId);
    if (it == mRooms.end()) return;

    if (it->second.host && it->second.host->account.userId == userId) {
        it->second.host->online = false;
        return;
    }

    auto client = it->second.clients.find(userId);
    if (client != it->second.clients.end()) client->second.online = false;
}

void RoomRegistry::closeRoom(const std::string& roomId) {
    mRooms.erase(roomId);
}

RoomRegistry::RoomState& RoomRegistry::requireRoom(const std::string& roomId) {
    auto it = mRooms.find(roomId);
    if (it == mRooms.end() || !it->second.host) throw std::runtime_error("room not found");
    return it->second;
}
