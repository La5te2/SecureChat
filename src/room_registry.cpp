// 房间注册表实现。它只保存进程本地房间成员关系，不保存房间密码或群密钥。
#include "room_registry.hpp"

#include <stdexcept>
#include <utility>

void RoomRegistry::createRoom(const std::string& roomId, const UserAccount& host) {
    // roomId 在 Server 侧是不透明 room instance token，不是人类可读房间名。
    if (roomId.empty()) throw std::runtime_error("missing roomId");
    if (mRooms.find(roomId) != mRooms.end()) throw std::runtime_error("room already exists");

    RoomState room;
    room.roomId = roomId;
    room.host = RoomMember{host, RoomRole::Host};
    mRooms[roomId] = std::move(room);
}

void RoomRegistry::restoreRoom(const std::string& roomId, const UserAccount& host) {
    if (roomId.empty()) throw std::runtime_error("missing roomId");
    auto& room = mRooms[roomId];
    room.roomId = roomId;
    room.host = RoomMember{host, RoomRole::Host};
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
    auto it = mRooms.find(roomId);
    if (it == mRooms.end() || !it->second.host) throw std::runtime_error("room not found");
    return it->second;
}
