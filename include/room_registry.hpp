// SignalingServer 使用的内存房间注册表。它记录当前进程内的 Host/Client
// 成员关系；房间准入由 room instance token 和应用层 PKI 共同完成。
#pragma once

#include "auth_service.hpp"

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
    // 使用给定 Host 创建房间。roomId 对 Server 来说是不透明 room instance token。
    void createRoom(const std::string& roomId, const UserAccount& host);
    // Server 重启恢复 open room 时先建立无 Host 的占位房间。
    // Host 可稍后重接管，已批准成员也可先恢复连接。
    void restoreOpenRoom(const std::string& roomId);
    // 持久化恢复或 Host 重接管时恢复 room registry 状态。
    void restoreRoom(const std::string& roomId, const UserAccount& host);
    // 在已有房间中添加或刷新 Client 成员关系。
    RoomMember joinClient(const std::string& roomId, const UserAccount& client);
    // 移除房间及其所有内存成员关系。
    void closeRoom(const std::string& roomId);

private:
    struct RoomState {
        std::string roomId;
        std::optional<RoomMember> host;
        std::unordered_map<std::string, RoomMember> clients;
    };

    RoomState& requireRoom(const std::string& roomId);

    std::unordered_map<std::string, RoomState> mRooms;
};
