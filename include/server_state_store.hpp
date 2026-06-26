// Server 侧持久化状态存储。
// 当前只保存 opaque room token、open/closed 状态和待 Host 审批的
// pending join 原始 JSON；后续非房间专属的 Server 状态也可以放入这里。
// 该模块不保存聊天明文、群密钥或任何成员私钥。
#pragma once

#include <nlohmann/json.hpp>

#include <cstddef>
#include <string>
#include <vector>

class ServerStateStore {
public:
    struct PendingJoin {
        std::string requestId;
        nlohmann::json payload;
    };

    struct MembershipEvent {
        std::string eventId;
        nlohmann::json payload;
    };

    struct ForumRecord {
        std::string boardMessageId;
        std::string recordHash;
        nlohmann::json payload;
    };

    ServerStateStore();
    ~ServerStateStore();

    std::vector<std::string> loadOpenRooms();
    std::vector<PendingJoin> loadPendingJoins(const std::string& roomId);
    std::vector<MembershipEvent> loadMembershipEvents(const std::string& roomId);
    std::vector<ForumRecord> loadForumRecords(const std::string& roomId, std::size_t limit = 500);
    nlohmann::json loadGroupStateEnvelope(const std::string& roomId, const std::string& memberFingerprint);
    // 返回 open/closed；不存在时返回空字符串。
    std::string roomState(const std::string& roomId);

    void markRoomOpen(const std::string& roomId);
    void markRoomClosed(const std::string& roomId);
    void addPendingJoin(const std::string& roomId, const std::string& requestId, const nlohmann::json& payload);
    void removePendingJoin(const std::string& roomId, const std::string& requestId);
    void clearPendingJoins(const std::string& roomId);
    void addMembershipEvent(const std::string& roomId, const std::string& eventId, const nlohmann::json& payload);
    void upsertGroupStateEnvelope(const std::string& roomId, const std::string& memberFingerprint, const nlohmann::json& payload);
    void addForumRecord(const std::string& roomId, const std::string& boardMessageId, const std::string& recordHash, const nlohmann::json& payload);

private:
    void open();
    void migrate();

    void* mDb = nullptr;
    std::string mPath;
};
