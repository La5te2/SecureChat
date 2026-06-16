// 房间注册表实现。它只保存进程本地房间成员关系，以及用于等值检查的房间密码哈希。
#include "room_registry.hpp"

#include <openssl/crypto.h>
#include <openssl/evp.h>

#include <array>
#include <memory>
#include <stdexcept>
#include <utility>

namespace {
std::array<unsigned char, 32> hashRoomPassword(const std::string& roomId, const std::string& password) {
    // 注册表只需要等值检查。保存带域分离的摘要，而不是长期保留房间密码明文字符串。
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
    // 仅在 SignalingServer 确认该 room id 尚未在当前 Server 实例上活动后调用。
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
    // 使用常量时间比较，避免错误猜测泄露前缀匹配信息。
    return CRYPTO_memcmp(
        it->second.passwordHash.data(),
        suppliedHash.data(),
        it->second.passwordHash.size()) == 0;
}

RoomMember RoomRegistry::joinClient(const std::string& roomId, const UserAccount& client) {
    // 同一 user id 重新加入时刷新进程本地成员状态。
    auto& room = requireRoom(roomId);
    auto& member = room.clients[client.userId];
    member = RoomMember{client, RoomRole::Client};
    return member;
}

void RoomRegistry::closeRoom(const std::string& roomId) {
    // 关闭房间会丢弃所有进程本地成员状态。
    mRooms.erase(roomId);
}

RoomRegistry::RoomState& RoomRegistry::requireRoom(const std::string& roomId) {
    // 需要存在带 Host 的活动房间时使用的内部辅助函数。
    auto it = mRooms.find(roomId);
    if (it == mRooms.end() || !it->second.host) throw std::runtime_error("room not found");
    return it->second;
}
