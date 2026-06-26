// CLI 和 WinUI 包装层使用的 Client 会话接口。
// 它加入已有房间，并通过 Server 发送加密中继消息。
#pragma once

#include "attachment_transfer.hpp"
#include "common.hpp"
#include "events.hpp"
#include "forum_board.hpp"
#include "local_message_store.hpp"
#include "pki_application.hpp"
#include "secure_relay.hpp"
#include "websocket_config.hpp"

#include <rtc/rtc.hpp>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

// 普通房间成员。它加入已有房间，签名自己的临时 X25519 公钥，
// 接收 Host 封装的房间群密钥，然后通过 SignalingServer 发送加密中继封装。
class ClientSessionCore {
public:
    // 创建绑定到一个信令 URL、房间显示名和 opaque room instance token 的 Client 会话。
    ClientSessionCore(
        std::string url,
        std::string room,
        std::string username,
        std::string baseUsername,
        std::string nickname,
        chat::pki_application::IdentityContext identity,
        std::string roomToken,
        std::string admissionSecret,
        std::string roomDir = {},
        std::string keyPassword = {},
        rtc::WebSocket::Configuration wsConfig = {});
    ~ClientSessionCore();

    // 安装用于事件和日志的 UI 或控制台回调。
    void setCallbacks(ChatCallbacks callbacks);
    // 连接 Server 并加入已配置房间。
    void start();
    // 停止信令连接和活动传输状态。
    void stop();
    // 请求停止但不等待 worker 线程退出。WinUI 进程关闭时使用它避免 UI 被 native join 拖住。
    void requestStopNoJoin();
    // 返回该 Client 会话是否已经被请求停止。
    bool shouldStop() const;
    // 向 Host 发送文本或附件命令。
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
    // 返回当前 room instance 的本机文本历史 JSON。WinUI 重进房间时用它重放气泡。
    std::string messageHistoryJson(std::size_t limit = 500) const;
    // 返回当前会话已解密的留言板文本 JSON，供 WinUI 渲染。
    std::string forumHistoryJson(std::size_t limit = 500) const;

private:
    // 排队一次本地关闭，并携带用户可见原因。
    void requestShutdown(const std::string& reason);
    struct SignalingFrame {
        std::string payload;
        std::string relayUrl;
    };

    // 将原始 WebSocket 帧移出 libdatachannel 回调线程，并保留来源 relay。
    void enqueueSignalingMessage(std::string payload, std::string relayUrl);
    // 串行协议 worker，负责 JSON 解析、PKI 验证和 GKA 工作。
    void signalingWorkerLoop();
    // 停止并 join 协议 worker，不直接操作 WebSocket。
    void stopSignalingWorker();
    // 分发 joined、房间成员、加密中继和错误事件。
    void handleSignalingMessage(const SignalingFrame& frame);
    // 当前是否仍有至少一个 relay 可用于发送。
    bool hasOpenRelay() const;
    // 发送前尝试恢复已经关闭的 relay，使重启后的 relay 能重新进入可用集合。
    void reconnectClosedRelays();
    // 发出当前 relay pool 健康摘要给 CLI/WinUI。
    void emitRelayStatus();
    // 判断指定 relay 是否已经过了本机沉默期。
    bool relayRetryAllowed(std::size_t relayIndex) const;
    // relay 成功连接后清除沉默期和失败计数。
    void markRelayHealthy(std::size_t relayIndex, const std::string& url);
    // relay 失败后进入沉默期，避免坏 relay 持续刷屏。
    bool markRelayFailure(std::size_t relayIndex, const std::string& url, const std::string& status);
    // 查找 WebSocket 指针对应的 relay URL。
    std::string relayUrlFor(const std::shared_ptr<rtc::WebSocket>& relay) const;
    // 从 room relay pool 中按房间群密钥派生的调度摘要选择 relay。
    std::shared_ptr<rtc::WebSocket> chooseRelayForSend(const Message& msg, const std::string& targetId);
    // 首次准入流程按 admission secret 排序，连接第一个未处于沉默期的 relay。
    void connectAdmissionRelay();
    // 连接指定 relay 并发送 join_room。首次申请和后续静默绑定共用该路径。
    void connectRelay(std::size_t relayIndex);
    // 打开尚未连接的 relay。首次 entrance 入房只打开一个 relay，获批后再绑定剩余 relay。
    void connectRemainingRelays();
    // 通过不可信 Server 发送一条加密中继消息。
    bool sendRelayMessage(const Message& msg, const std::string& senderId, const std::string& senderName, const std::string& senderKind, const std::string& targetId);
    struct ReliableOutbound {
        Message message;
        std::string senderId;
        std::string senderName;
        std::string senderKind;
        std::string targetId;
        std::string messageId;
        std::string payloadHash;
        int retryCount = 0;
    };
    // 发送已经完成 pairwise 包装和可靠元数据标记的应用载荷。
    bool sendPreparedRelayMessage(ReliableOutbound outbound, bool emitNotice);
    // 为可恢复 payload 写入 messageId/payloadHash，并保存本机重传副本。
    void ensureReliableFields(Message& msg);
    void rememberReliableOutbound(const ReliableOutbound& outbound);
    // 记录入站 payload，拒绝重复消息和同 id 异 hash 的异常 payload。
    bool rememberReliableInbound(const Message& msg);
    // notice/missing 都走加密中继；notice 只声明有 payload，missing 请求发送方重发。
    void sendReliableNotice(const ReliableOutbound& outbound);
    void handleReliableNotice(const Message& msg);
    void handleMissingMessage(const Message& msg);
    // 为 targetId 把私发 Message 包装进双方私发内层加密。
    Message wrapPairwiseForTarget(const Message& msg, const std::string& targetId);
    // 打开一个发给本 Client 的双方私发包装。
    Message decryptPairwiseFromMember(const Message& msg);
    // 记录中继 nonce/tag 对，使 Server 重放帧被忽略。
    bool rememberRelayEnvelope(const json& envelope);
    // 验证并保存一个成员 identity/publicKey 映射，用于双方私发。
    bool rememberVerifiedMemberIdentity(
        const std::string& memberId,
        const std::string& identityName,
        const std::string& displayName,
        const std::string& publicKey,
        const json& identity,
        const std::string& advertisedFingerprint,
        const std::string& source,
        bool allowSessionKeyRotation = false);
    // 发送本 Client 针对一个 GKA epoch 的签名随机 contribution。
    void sendGkaContribution(std::uint64_t epoch);
    // 验证已解密的 GKA 状态，并安装派生出的房间群密钥。
    bool installGroupState(const json& groupState, std::uint64_t epoch, bool allowStoredSelfSessionKey);
    // 以加密元数据加后续加密分片的形式发送一个本地附件。
    bool sendAttachmentRelay(const std::string& filePath, chat::attachment::Kind kind, const std::string& metaType, const std::string& binaryType, const std::string& mime, const std::string& targetId);
    // 处理一条已解密的 encrypted_relay 应用消息。
    void handleRelayMessage(const Message& msg);
    // 将一个加密附件分片重组成本地缓存文件。
    void handleRelayBinaryChunk(const std::string& senderKey, const Message& msg);
    // 将已显示的文本消息写入本机历史；失败只报告状态，不影响收发。
    void rememberTextHistory(const Message& msg, bool isOwn);
    // 处理本机附件预览信任命令。该状态只影响当前 UI/CLI，不进入网络协议。
    bool handleAttachmentTrustCommand(const std::string& line);
    bool handleForumCommand(const std::string& line);
    // 将原始控制台/UI 输入转换为协议消息。
    Message parseInput(const std::string& line);
    void sendForumPost(const std::string& text);
    void requestForumSync();
    void handleForumRecords(const json& records);
    void rememberForumRecord(const json& record);
    // 根据至少 8 位证书指纹前缀解析成员 id。
    std::string resolveMemberId(const std::string& token);

private:
    std::string mWsUrl;
    std::string mRoomId;
    // Server 把该 token 当作 roomId；人类可读 room id 只留在本地 UI 和 PKI 语义中。
    std::string mRoomToken;
    // entrance.scp 派生出的房间准入 secret，用于 pending join 的加密和 relay 选择。
    std::string mAdmissionSecret;
    std::string mRoomDir;
    std::string mKeyPassword;
    std::string mBaseUsername;
    std::string mUsername;
    std::string mDisplayName;
    std::string mClientId;
    std::mutex mMembersMutex;
    std::unordered_map<std::string, std::string> mMemberNamesById;
    std::unordered_map<std::string, std::string> mMemberUsernamesById;
    std::unordered_map<std::string, std::string> mMemberPublicKeysById;
    std::unordered_map<std::string, std::string> mMemberFingerprintsById;
    std::unordered_map<std::string, json> mMemberIdentityObjectsById;
    std::unordered_set<std::string> mRecentRelayIds;
    std::deque<std::string> mRecentRelayOrder;
    std::mutex mReliableMutex;
    std::unordered_map<std::string, ReliableOutbound> mReliableOutbound;
    std::unordered_map<std::string, std::unordered_map<std::size_t, std::string>> mReliableChunkMessagesByTransfer;
    std::unordered_map<std::string, std::string> mReliableSeen;
    std::deque<std::string> mReliableSeenOrder;
    ChatCallbacks mCallbacks;
    std::shared_ptr<rtc::WebSocket> mWs;
    rtc::WebSocket::Configuration mWsConfig;
    chat::secure_relay::MemberKeyPair mMemberKeys;
    chat::pki_application::IdentityContext mIdentity;
    std::vector<unsigned char> mGroupKey;
    std::uint64_t mGroupKeyEpoch = 0;
    std::mutex mSignalingQueueMutex;
    std::condition_variable mSignalingQueueCv;
    std::deque<SignalingFrame> mSignalingQueue;
    std::thread mSignalingThread;
    std::atomic_bool mSignalingWorkerStopping = false;
    std::vector<std::string> mRelayUrls;
    std::vector<std::shared_ptr<rtc::WebSocket>> mRelays;
    std::vector<bool> mRelayOpen;
    mutable std::mutex mRelayMutex;
    std::vector<std::chrono::steady_clock::time_point> mRelayNextRetryAt;
    std::vector<int> mRelayFailureStreak;
    std::vector<bool> mRelayFailureReported;
    std::size_t mRelaySendCursor = 0;
    std::uint64_t mLastGkaContributionEpoch = 0;
    // 仅在 Server 接受 join_room 并分配 clientId 后为 true。
    // 此前关闭表示准入/连接失败，而不是聊天中断。
    std::atomic_bool mJoinedRoom = false;
    // 收到明确的 Server/Host error 帧后置位。若传输关闭时没有该标记，
    // UI 可以报告对端静默关闭。
    std::atomic_bool mSawErrorFrame = false;
    std::atomic_bool mShutdownRequested = false;
    std::atomic_bool mStopped = false;
    // 核心附件接收状态，以发送者 actor id 为键。
    chat::attachment::ReceiveStore mPendingTransfers;
    std::unique_ptr<chat::local_message::Store> mMessageHistory;
    mutable std::mutex mForumMutex;
    std::vector<chat::forum_board::DisplayRecord> mForumRecords;
    std::unordered_map<std::string, std::string> mForumRecordHashes;
};
