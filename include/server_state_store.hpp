// Server 侧持久化状态存储。
// 当前只保存 opaque room token、open/closed 状态和待 Host 审批的
// pending join 原始 JSON；后续非房间专属的 Server 状态也可以放入这里。
// 该模块不保存聊天明文、群密钥或任何成员私钥。
#pragma once

#include <nlohmann/json.hpp>

#include <string>
#include <vector>

class ServerStateStore {
public:
    struct PendingJoin {
        std::string requestId;
        nlohmann::json payload;
    };

    ServerStateStore();
    ~ServerStateStore();

    std::vector<std::string> loadOpenRooms();
    std::vector<PendingJoin> loadPendingJoins(const std::string& roomId);
    // 返回 open/closed；不存在时返回空字符串。
    std::string roomState(const std::string& roomId);

    void markRoomOpen(const std::string& roomId);
    void markRoomClosed(const std::string& roomId);
    void addPendingJoin(const std::string& roomId, const std::string& requestId, const nlohmann::json& payload);
    void removePendingJoin(const std::string& roomId, const std::string& requestId);
    void clearPendingJoins(const std::string& roomId);

private:
    void open();
    void migrate();

    void* mDb = nullptr;
    std::string mPath;
};
