// CLI 和 WinUI 包装层使用的 Host 会话接口。
// Host 作为聊天成员创建房间并协调群密钥分发。
#pragma once

#include "attachment_transfer.hpp"
#include "common.hpp"
#include "events.hpp"
#include "pki_application.hpp"
#include "secure_relay.hpp"
#include "websocket_config.hpp"

#include <rtc/rtc.hpp>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

// 创建房间并协调群密钥分发的聊天成员。
// Host 不是监听服务器；它和其他成员一样连接 SignalingServer，
// 然后执行 PKI 签名/验签并管理房间群密钥。
class HostSessionCore {
public:
    // 创建绑定到一个信令 URL、房间显示名和 opaque room instance token 的 Host 会话。
    HostSessionCore(
        std::string wsUrl,
        std::string roomId,
        std::string username,
        chat::pki_application::IdentityContext identity,
        std::string roomToken,
        std::string roomDir = {},
        rtc::WebSocket::Configuration wsConfig = {});
    ~HostSessionCore();

    // 安装用于事件和日志的 UI 或控制台回调。
    void setCallbacks(ChatCallbacks callbacks);
    // 连接 Server 并创建已配置房间。
    void start();
    // 停止信令连接和活动房间状态。
    void stop();
    // 显式关闭当前 room instance。普通 stop 只表示 Host 本地离线。
    void closeRoom();
    // 返回该 Host 会话是否已经被请求停止。
    bool shouldStop() const;
    // 从 Host 向房间发送文本或附件命令。
    void sendLine(const std::string& line);
    // 通过加密 Server 中继发送图片文件。
    bool sendImage(const std::string& filePath);
    // 通过加密 Server 中继发送文本文件。
    bool sendTextFile(const std::string& filePath);
    // 通过加密 Server 中继发送录音语音片段。
    bool sendVoice(const std::string& filePath);
    // 向一个成员发送文本或附件命令；目标为空表示房间广播。
    void sendLineTo(const std::string& target, const std::string& line);
    // 向一个成员发送附件；目标为空表示房间广播。
    bool sendImageTo(const std::string& target, const std::string& filePath);
    bool sendTextFileTo(const std::string& target, const std::string& filePath);
    bool sendVoiceTo(const std::string& target, const std::string& filePath);
private:
    // 处理普通输入框中输入的 Host 专用房间管理命令。
    bool handleHostCommand(const std::string& line);
    // 批准一个已验证的 pending join，使 Server 将其提升为 active Client。
    void approvePendingJoin(const std::string& token);
    // 拒绝一个 pending join，并把签名原因返回给申请者。
    void rejectPendingJoin(const std::string& token, const std::string& reason);
    // 将原始 WebSocket 帧移出 libdatachannel 回调线程。
    void enqueueSignalingMessage(std::string payload);
    // 串行协议 worker，负责 JSON 解析、PKI 验证和 GKA 工作。
    void signalingWorkerLoop();
    // 停止并 join 协议 worker，不直接操作 WebSocket。
    void stopSignalingWorker();
    // 分发房间创建、成员关系、加密中继和错误事件。
    void handleSignalingMessage(const std::string& s);
    // 将一个 Client 标记为当前连接离线，但保留它的房间成员资格。
    void markClientDisconnected(const std::string& id);
    // 永久移除一个 Client 成员并更新本地房间状态。
    void removeClient(const std::string& id);
    // 切换当前某个 Client 在房间内的发送权限。
    void setClientSilenced(const std::string& target, bool silenced);
    // 踢出一个 Client，并在当前房间封禁其已验证证书指纹。
    void evictClient(const std::string& target);
    // 向 Server 发送一个经 Host 授权的管理帧。
    void sendClientModeration(const std::string& type, const std::string& clientId);
    // 通过不可信 Server 发送一条加密中继消息。
    bool sendRelayMessage(const Message& msg, const std::string& senderId, const std::string& senderName, const std::string& senderKind, const std::string& targetId);
    // 为 targetId 把私发 Message 包装进双方私发内层加密。
    Message wrapPairwiseForTarget(const Message& msg, const std::string& targetId);
    // 打开一个发给 Host 的双方私发包装。
    Message decryptPairwiseFromClient(const Message& msg);
    // 记录中继 nonce/tag 对，使 Server 重放帧被忽略。
    bool rememberRelayEnvelope(const json& envelope);
    // 为某个成员封装已提交的 GKA 状态，并请求 Server 中继。
    bool sendGroupStateToClient(
        const std::string& clientId,
        const std::string& clientPublicKey,
        const json& groupState,
        std::uint64_t epoch);
    // 成员关系变化后启动新的贡献式 GKA epoch。
    void rotateGroupKey(const std::string& reason);
    // 请求 Client 为当前待处理 epoch 提交 contribution。
    void sendGkaRequestToClients();
    // 启动/停止 Host 侧看门狗，用于处理拖延 GKA epoch 的成员。
    void startGkaTimeoutWorker();
    void stopGkaTimeoutWorker();
    // 等待待处理 GKA 截止时间，并驱逐一直未贡献的成员。
    void gkaTimeoutLoop();
    // 移除该 epoch 中仍缺失的所有贡献者，并重新启动一次 GKA。
    void evictGkaTimeoutMembers(std::uint64_t epoch);
    // 为一个 epoch 构造并签名本 Host 成员的 contribution。
    json makeLocalGkaContribution(std::uint64_t epoch) const;
    // 验证一个 contribution，并存入待处理 epoch 映射。
    bool rememberGkaContribution(const json& contribution, const std::string& expectedMemberId);
    // 当所有当前成员都提交已验证 contribution 后提交 \(K_G\)。
    void tryCommitGkaEpoch();
    // 以加密元数据加后续加密分片的形式发送一个本地附件。
    bool sendAttachmentRelay(const std::string& filePath, chat::attachment::Kind kind, const std::string& metaType, const std::string& binaryType, const std::string& mime, const std::string& targetId);
    // 处理一条已解密的 encrypted_relay 应用消息。
    void handleRelayMessage(const Message& msg);
    // 将一个加密附件分片重组成本地缓存文件。
    void handleRelayBinaryChunk(const std::string& senderKey, const Message& msg);
    // 返回当前活动 Host 聊天 actor 标签。
    std::string currentHostActorName();
    // 添加稳定 actor 身份元数据，同时保持 from/displayName 可读。
    void setActorMetadata(Message& msg, const std::string& actorId, const std::string& actorKind, const std::string& displayName);
    // 为 Host 发出的聊天/媒体消息标记 actor 元数据。
    void setCurrentHostActorMetadata(Message& msg);
    // 返回 Client 显示名；缺失时回退到 id。
    std::string displayNameForClient(const std::string& id);
    // 将可见 Client 名解析为 client id。
    std::string resolveClientId(const std::string& token);
    // 将 requestId 或成员名解析为 pending join requestId。
    std::string resolvePendingJoinId(const std::string& token);
    // 请求 Server 移除未通过 Host 侧身份检查的 Client。
    void rejectClient(const std::string& clientId, const std::string& reason);
    // 通过加密中继广播 Host 已验证的成员证书指纹。
    void announceVerifiedMember(
        const std::string& memberId,
        const std::string& displayName,
        const std::string& fingerprint,
        const std::string& subject,
        const std::string& publicKey,
        const json& identity);
    void announceVerifiedMembers();

private:
    std::string mWsUrl;
    std::string mRoomId;
    // Server 把该 token 当作 roomId；人类可读 room id 只留在本地 UI 和 PKI 语义中。
    std::string mRoomToken;
    std::string mRoomDir;
    std::string mUsername;
    rtc::WebSocket::Configuration mWsConfig;
    ChatCallbacks mCallbacks;
    std::shared_ptr<rtc::WebSocket> mWs;
    std::atomic_bool mStopped = false;
    // 在 Server 接受 room_created 后置位。WinUI 把此前的 close 事件视为
    // 连接/准入失败，而不是活动会话中断。
    std::atomic_bool mRoomCreated = false;
    std::mutex mClientsMutex;
    std::unordered_map<std::string, std::string> mClientNames;
    std::unordered_map<std::string, std::string> mClientPublicKeys;
    std::unordered_map<std::string, std::string> mClientIdentityFingerprints;
    std::unordered_map<std::string, std::string> mClientIdentitySubjects;
    std::unordered_map<std::string, json> mClientIdentityObjects;
    // 当前仍连接到 Server 的 Client。成员资格保存在上面的证书/公钥表中；
    // 断网或关闭进程只会从这个集合移除，不会自动吊销成员证书。
    std::unordered_set<std::string> mConnectedClientIds;
    std::unordered_map<std::string, json> mPendingJoinRequests;
    std::unordered_set<std::string> mSilencedClientIds;
    std::unordered_set<std::string> mBannedIdentityFingerprints;
    std::unordered_set<std::string> mRecentRelayIds;
    std::deque<std::string> mRecentRelayOrder;
    std::mutex mSignalingQueueMutex;
    std::condition_variable mSignalingQueueCv;
    std::deque<std::string> mSignalingQueue;
    std::thread mSignalingThread;
    std::atomic_bool mSignalingWorkerStopping = false;
    chat::secure_relay::MemberKeyPair mMemberKeys;
    chat::pki_application::IdentityContext mIdentity;
    std::vector<unsigned char> mGroupKey;
    // 待处理 GKA 状态会被 WebSocket 回调和 watchdog 线程共同访问。
    // 该 mutex 保证 epoch 变更、contribution 存储和超时决策一致。
    std::mutex mGkaMutex;
    std::condition_variable mGkaCv;
    std::thread mGkaTimeoutThread;
    bool mGkaTimeoutStop = false;
    std::uint64_t mGroupKeyEpoch = 0;
    std::uint64_t mPendingGkaEpoch = 0;
    std::chrono::steady_clock::time_point mPendingGkaDeadline{};
    std::unordered_set<std::string> mPendingGkaMembers;
    std::unordered_map<std::string, json> mPendingGkaContributions;
    // 核心附件接收状态，以加密中继发送者 actor id 为键。
    chat::attachment::ReceiveStore mPendingTransfers;
};
