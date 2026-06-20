// SignalingServer 声明。Server 监听 WebSocket Client，注册房间、跟踪成员，
// 并中继不透明加密封装。
#pragma once

#include "auth_service.hpp"
#include "common.hpp"
#include "room_registry.hpp"
#include "server_room_store.hpp"

#include <rtc/rtc.hpp>

#include <atomic>
#include <condition_variable>
#include <cstddef>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

// 拥有网络监听器、房间注册表、成员状态和不透明中继。
// 它刻意不解密聊天数据，也不解释应用层成员证书；Host/Client 在本地验证 PKI 身份。
class SignalingServer {
public:
    // 启动 WebSocket 信令服务器和不透明加密中继。
    explicit SignalingServer(uint16_t port);
    // Server 对象离开作用域时停止信令。
    ~SignalingServer();

    // 返回已绑定的信令端口，包括自动选择的端口。
    uint16_t port() const;
    // 返回 Client 连接该 Server 时使用的 "wss"。
    std::string urlScheme() const;
    // 关闭所有已发布房间，并向已连接 Client 告知原因。
    void closeAllRooms(const std::string& reason = "host disconnected");
    // 停止接受信令连接。
    void stop();

private:
    struct Room {
        // 一个房间由一个 Host socket 锚定。该 socket 离开时，
        // 当前设计会关闭房间并通知所有 Client。
        std::shared_ptr<rtc::WebSocket> host;
        std::unordered_map<std::string, std::shared_ptr<rtc::WebSocket>> clients;
        // Host 离线期间收到的新成员申请。Server 只保存和转发原始 JSON，
        // 不解释 CSR 或成员证书语义。
        std::unordered_map<std::string, json> pendingJoins;
        // Host 请求的房间内发送限制。被禁言 Client 仍保持连接并可接收重密钥流量，
        // 但 Server 会拒绝它们发送中继消息。
        std::unordered_set<std::string> silencedClients;
    };

    struct RoomSnapshot {
        std::vector<std::shared_ptr<rtc::WebSocket>> recipients;
        json members = json::array();
        json memberInfos = json::array();
    };

    struct ClientState {
        // Server 侧连接元数据。clientId 用于路由；
        // 加密聊天载荷内的 actorId 由 secure_relay 认证。
        std::string roomId;
        std::string clientId;
        std::string userId;
        // username 是房间级 PKI 绑定的不可变身份名；displayName 是成员列表显示昵称。
        std::string username;
        std::string displayName;
        std::string publicKey;
        std::string pendingRequestId;
        // 来自 join_room 的不透明 PKI identity 对象。Server 只保存它，
        // 以便其他 Client 独立验证广播中的成员 key。
        json identity;
        std::string role;
        std::shared_ptr<rtc::WebSocket> ws;
        // 多个信令回调同时写入同一个 TLS socket 时，libdatachannel WebSocket 发送
        // 不保证安全。Server 对每个连接的出站帧做串行化。
        std::shared_ptr<std::mutex> sendMutex = std::make_shared<std::mutex>();
        std::size_t badMessageCount = 0;
    };

    // 在新接受的 socket 完成入房认证前先注册它。
    void addClient(std::shared_ptr<rtc::WebSocket> ws);
    // 校验一个 JSON 信令帧，并按协议类型分发。
    void handleMessage(rtc::WebSocket* key, const std::string& payload);
    // 允许 Host 成员在该 Server 上注册唯一房间。
    void handleCreateRoom(rtc::WebSocket* key, const json& data);
    // 允许 Client 成员加入已有房间并发布其 GKA 公钥。
    void handleJoinRoom(rtc::WebSocket* key, const json& data);
    // 允许 Host 移除未通过本地身份验证的 Client。
    void handleRejectClient(rtc::WebSocket* key, const json& data);
    // 允许 Host 为某个 Client 启用或禁用房间内发送限制。
    void handleClientSilence(rtc::WebSocket* key, const json& data, bool silenced);
    // Host 显式批准一个 pending join 后，Server 才把申请者变成 active Client。
    void handleApproveJoin(rtc::WebSocket* key, const json& data);
    // Host 显式拒绝一个 pending join，并把签名拒绝原因转发给申请者。
    void handleRejectPendingJoin(rtc::WebSocket* key, const json& data);
    // 只有当前 Host 发送显式 close_room 时才销毁 room instance。
    void handleCloseRoom(rtc::WebSocket* key, const json& data);
    // 向当前 Client 广播 Host 发起的 GKA epoch 请求。
    void relayGkaRequest(rtc::WebSocket* key, const json& data);
    // 向 Host 转发一个加密成员 contribution。
    void relayGkaContribution(rtc::WebSocket* key, const json& data);
    // 将 Host 的加密 group-key envelope 精确转发给一个 Client。
    void relayGroupKey(rtc::WebSocket* key, const json& data);
    // 将已认证聊天密文中继给房间或某个目标成员。
    void relayEncrypted(rtc::WebSocket* key, const json& data);
    // 从成员和房间索引中移除已断连 socket。
    void cleanup(rtc::WebSocket* key);
    // 向房间内所有成员广播结构化成员 name/id 状态。
    void broadcastRoomMembers(const std::string& roomId);
    // 向准入失败的 socket 发送终止错误。
    void rejectClient(const std::shared_ptr<rtc::WebSocket>& ws, const std::string& message);
    // 统计畸形帧，并断开滥用连接的 Client。
    void recordBadMessage(rtc::WebSocket* key, const std::string& message);
    // 周期性清理过期房间和相关认证状态。
    void maintenanceLoop();
    // 为成员广播构造一个加锁后的房间视图。
    RoomSnapshot roomSnapshotLocked(const std::string& roomId);
    // 强制房间内显示名唯一。
    bool clientNameInRoomLocked(const std::string& roomId, const std::string& username) const;
    // 查找已连接 socket 的可变状态记录。
    ClientState* findClient(rtc::WebSocket* key);
    // 根据显式 id 或 socket 当前状态解析房间。
    Room* findRoom(const std::string& explicitRoomId, ClientState* client);
    // 如果 socket 仍打开，则向其发送 JSON。
    void sendToClient(rtc::WebSocket* key, const json& data);
    // 接收者快照离开 mutex 后使用的共享受保护发送工具。
    void safeSend(const std::shared_ptr<rtc::WebSocket>& ws, const json& data);
    // Host 上线或重连后，把积压的 pending join 转交给 Host。
    void flushPendingJoinsToHost(const std::string& roomId);

    std::unique_ptr<rtc::WebSocketServer> mServer;
    std::string mUrlScheme = "wss";
    std::atomic_bool mStopping = false;
    std::thread mMaintenanceThread;
    std::condition_variable mMaintenanceCv;
    std::mutex mMaintenanceMutex;
    std::mutex mMutex;
    AuthService mAuth;
    RoomRegistry mRegistry;
    ServerRoomStore mRoomStore;
    std::unordered_map<std::string, Room> mRooms;
    std::unordered_map<rtc::WebSocket*, ClientState> mClients;
};
