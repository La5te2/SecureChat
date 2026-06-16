// SignalingServer 使用的内存房间注册表。它记录当前进程内的房间密码和
// Host/Client 成员关系。
#pragma once

#include "auth_service.hpp"

#include <array>
#include <optional>
#include <string>
#include <unordered_map>

enum class RoomRole {
    // 存储的 role 仅用于成员关系记账。聊天权限由 Host/Client 协议逻辑
    // 和 Server 连接状态共同执行。
    Host,
    Client
};

struct RoomMember {
    // account id 在当前进程内稳定存在，并且只在房间活动期间有效。
    UserAccount account;
    RoomRole role = RoomRole::Client;
};

class RoomRegistry {
public:
    // 使用给定 Host 和房间密码创建房间。
    void createRoom(const std::string& roomId, const UserAccount& host, const std::string& password);
    // 检查传入房间密码是否匹配已保存的房间密码。
    bool passwordMatches(const std::string& roomId, const std::string& password) const;
    // 在已有房间中添加或刷新 Client 成员关系。
    RoomMember joinClient(const std::string& roomId, const UserAccount& client);
    // 移除房间及其所有内存成员关系。
    void closeRoom(const std::string& roomId);

private:
    struct RoomState {
        // RoomState 从不保存房间密码本身，只保存其摘要。
        std::string roomId;
        std::array<unsigned char, 32> passwordHash{};
        std::optional<RoomMember> host;
        std::unordered_map<std::string, RoomMember> clients;
    };

    RoomState& requireRoom(const std::string& roomId);

    std::unordered_map<std::string, RoomState> mRooms;
};
