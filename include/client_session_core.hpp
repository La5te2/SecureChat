// CLI 和 WinUI 包装层使用的 Client 会话接口。
// 它加入已有房间，并通过 Server 发送加密中继消息。
#pragma once

#include "attachment_transfer.hpp"
#include "common.hpp"
#include "events.hpp"
#include "local_message_store.hpp"
#include "pki_application.hpp"
#include "secure_relay.hpp"
#include "websocket_config.hpp"

#include <rtc/rtc.hpp>

#include <atomic>
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

private:
    // 排队一次本地关闭，并携带用户可见原因。
    void requestShutdown(const std::string& reason);
    // 将原始 WebSocket 帧移出 libdatachannel 回调线程。
    void enqueueSignalingMessage(std::string payload);
    // 串行协议 worker，负责 JSON 解析、PKI 验证和 GKA 工作。
    void signalingWorkerLoop();
    // 停止并 join 协议 worker，不直接操作 WebSocket。
    void stopSignalingWorker();
    // 分发 joined、房间成员、加密中继和错误事件。
    void handleSignalingMessage(const std::string& s);
    // 通过不可信 Server 发送一条加密中继消息。
    bool sendRelayMessage(const Message& msg, const std::string& senderId, const std::string& senderName, const std::string& senderKind, const std::string& targetId);
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
    bool installGroupState(const json& groupState, std::uint64_t epoch);
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
    // 将原始控制台/UI 输入转换为协议消息。
    Message parseInput(const std::string& line);
    // 根据至少 8 位证书指纹前缀解析成员 id。
    std::string resolveMemberId(const std::string& token);

private:
    std::string mWsUrl;
    std::string mRoomId;
    // Server 把该 token 当作 roomId；人类可读 room id 只留在本地 UI 和 PKI 语义中。
    std::string mRoomToken;
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
    std::unordered_set<std::string> mRecentRelayIds;
    std::deque<std::string> mRecentRelayOrder;
    ChatCallbacks mCallbacks;
    std::shared_ptr<rtc::WebSocket> mWs;
    rtc::WebSocket::Configuration mWsConfig;
    chat::secure_relay::MemberKeyPair mMemberKeys;
    chat::pki_application::IdentityContext mIdentity;
    std::vector<unsigned char> mGroupKey;
    std::uint64_t mGroupKeyEpoch = 0;
    std::mutex mSignalingQueueMutex;
    std::condition_variable mSignalingQueueCv;
    std::deque<std::string> mSignalingQueue;
    std::thread mSignalingThread;
    std::atomic_bool mSignalingWorkerStopping = false;
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
};
