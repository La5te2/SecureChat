// Host 会话实现。它创建房间、验证 Client 的 PKI 身份，
// 分发房间群密钥，并处理加密中继消息。
#include "host_session_core.hpp"

#include "attachment_transfer.hpp"
#include "secure_relay.hpp"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstddef>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <tuple>
#include <utility>
#include <vector>

namespace {
namespace attachment = chat::attachment;

constexpr auto GkaContributionTimeout = std::chrono::seconds(10);

bool startsWithIgnoreCase(const std::string& value, const std::string& prefix) {
    if (value.size() < prefix.size()) return false;
    for (std::size_t i = 0; i < prefix.size(); ++i) {
        const auto a = static_cast<unsigned char>(value[i]);
        const auto b = static_cast<unsigned char>(prefix[i]);
        if (std::tolower(a) != std::tolower(b)) return false;
    }
    return true;
}

void requireWssServerUrl(const std::string& url) {
    // WSS 是唯一支持的对外信令入口。应用层 E2EE 仍保护消息内容，
    // 但明文 WS 会暴露握手、信令 metadata 和流量形态，因此产品入口禁用。
    if (!startsWithIgnoreCase(url, "wss://")) {
        throw std::runtime_error("Server URL must start with wss://; ws:// signaling is disabled");
    }
}

// 返回去除首尾 ASCII 空白后的副本。
std::string trimCopy(std::string value) {
    const auto first = value.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) return "";
    const auto last = value.find_last_not_of(" \t\r\n");
    return value.substr(first, last - first + 1);
}

bool parseDirectPrefix(const std::string& line, std::string& target, std::string& body) {
    // 在普通命令解析前拆分 "/to bob ..."，
    // 使私发文本和私发附件复用与房间广播相同的发送函数。
    if (line.rfind("/to ", 0) != 0) return false;
    const auto rest = trimCopy(line.substr(4));
    const auto split = rest.find_first_of(" \t\r\n");
    if (split == std::string::npos) {
        target = rest;
        body.clear();
        return true;
    }
    target = rest.substr(0, split);
    body = trimCopy(rest.substr(split + 1));
    return true;
}

void markPrivateTarget(Message& msg, const std::string& targetId, const std::string& targetName) {
    if (targetId.empty()) return;
    // 加密载荷携带 UI 意图；
    // 明文 envelope 只携带 Server 进行不透明私发投递所需的路由 id。
    msg.payload["private"] = true;
    msg.payload["targetId"] = targetId;
    msg.payload["targetName"] = targetName.empty() ? targetId : targetName;
}

bool attachmentKindForMeta(const std::string& type, attachment::Kind& kind) {
    // 将已解密附件元数据消息类型转换为 Host 和 Client 共用的 receive-store 枚举。
    if (type == "image_meta") {
        kind = attachment::Kind::Image;
        return true;
    }
    if (type == "file_meta") {
        kind = attachment::Kind::Text;
        return true;
    }
    if (type == "voice_meta") {
        kind = attachment::Kind::Voice;
        return true;
    }
    return false;
}

bool isAttachmentBinaryType(const std::string& type) {
    // 二进制分片仍是 JSON 中继消息；
    // 该辅助函数识别应追加到暂存传输中的加密载荷分片。
    return type == "image_binary" || type == "file_binary" || type == "voice_binary";
}

std::string actorIdFromMessage(const Message& msg) {
    // 对同一发送者的附件分片分组时，优先使用稳定 actor id，
    // 而不是显示名。
    if (msg.payload.is_object() && msg.payload.contains("actorId") && msg.payload["actorId"].is_string()) {
        const auto id = msg.payload["actorId"].get<std::string>();
        if (!id.empty()) return id;
    }
    return msg.from;
}

}

// 保存普通 SecureChat Host 会话的信令端点。
HostSessionCore::HostSessionCore(
    std::string wsUrl,
    std::string roomId,
    std::string username,
    std::string password,
    rtc::WebSocket::Configuration wsConfig)
    : mWsUrl(std::move(wsUrl)),
      mRoomId(std::move(roomId)),
      mUsername(std::move(username)),
      mPassword(std::move(password)),
      mWsConfig(std::move(wsConfig)) {
    requireWssServerUrl(mWsUrl);
    // Server 只注册该不透明 token。没有房间密码时无法恢复房间名，
    // 同时本地 PKI 签名仍绑定 mRoomId。
    mRoomToken = chat::secure_relay::deriveRoomToken(mRoomId, mPassword);
    // K_G 不再由 Host 直接生成。
    // 第一把可用房间密钥在 room_created 后由 epoch-1 contribution 集合派生。
    chat::websocket_config::applyClientTlsFromEnvironment(mWsConfig);
    // Host 身份用于签名 group_key envelope，并验证 Client 入房身份。
    mIdentity = chat::identity_pki::loadFromEnvironment();
    // Host 同样拥有成员 X25519 密钥对，使 Client 能向 Host 发送真正的 pairwise 私信，
    // 而不把房间群密钥作为唯一密钥。
    mMemberKeys = chat::secure_relay::generateMemberKeyPair();
}

HostSessionCore::~HostSessionCore() {
    // 析构可能发生在 UI 关闭期间。
    // 关闭传输并 join watchdog，但不再发送面向用户的 "Session stopped" 事件。
    mStopped.store(true);
    stopSignalingWorker();
    stopGkaTimeoutWorker();
    if (mWs && !mWs->isClosed()) {
        mWs->close();
    }
}

// 替换该会话使用的 UI/CLI 事件回调。
void HostSessionCore::setCallbacks(ChatCallbacks callbacks) {
    mCallbacks = std::move(callbacks);
}

// 打开信令 WebSocket 并创建聊天房间。
void HostSessionCore::start() {
    mStopped.store(false);
    mSignalingWorkerStopping.store(false);
    if (!mSignalingThread.joinable()) {
        mSignalingThread = std::thread([this]() {
            signalingWorkerLoop();
        });
    }
    startGkaTimeoutWorker();
    mWs = std::make_shared<rtc::WebSocket>(mWsConfig);

    mWs->onOpen([this]() {
        chatEmit(mCallbacks.onStatus, "Signaling connected");
        chatEmit(mCallbacks.onStatus, "PKI identity ready: " + mIdentity.fingerprint());
        json msg = {
            {"type", "create_room"},
            {"roomId", mRoomToken},
            {"username", mUsername},
            {"password", mRoomToken},
            {"publicKey", mMemberKeys.publicKey}
        };
        msg["identity"] = mIdentity.signJoinRoom(mRoomId, mUsername, mMemberKeys.publicKey);
        mWs->send(msg.dump());
        // 房间密码只保留到完成房间创建为止。
        std::fill(mPassword.begin(), mPassword.end(), '\0');
        mPassword.clear();
    });

    mWs->onMessage([this](rtc::message_variant data) {
        enqueueSignalingMessage(rtcMessageToString(data));
    });

    mWs->onClosed([this]() {
        chatEmit(mCallbacks.onStatus, "Signaling closed");
        // Host 连接尝试可能在 UI 进入 "hosting" 状态后异步失败。
        // 与 Client 关闭事件保持一致，使前端能在信令通道消失时恢复控件。
        if (!mStopped.exchange(true)) {
            if (!mRoomCreated.load()) {
                chatEmit(
                    mCallbacks.onError,
                    "Signaling closed before room creation completed; check Server URL, room name/password, PKI files, and rebuild all components if one executable was updated");
            }
            chatEmit(mCallbacks.onStatus, "Signaling connection ended");
        }
    });

    mWs->onError([this](std::string error) {
        chatEmit(mCallbacks.onError, "Signaling error: " + error);
        if (!mStopped.exchange(true)) {
            chatEmit(mCallbacks.onStatus, "Signaling failed");
        }
    });

    mWs->open(mWsUrl);
}

// 关闭所有 Host 持有的传输，并标记会话已停止。
void HostSessionCore::stop() {
    if (mStopped.exchange(true)) return;
    stopSignalingWorker();
    stopGkaTimeoutWorker();
    if (mWs && !mWs->isClosed()) {
        mWs->close();
    }

    chatEmit(mCallbacks.onStatus, "Session stopped");
}

// 返回外层 CLI/API 循环是否应停止轮询该会话。
bool HostSessionCore::shouldStop() const {
    return mStopped.load() || (mWs && mWs->isClosed());
}

void HostSessionCore::enqueueSignalingMessage(std::string payload) {
    {
        std::lock_guard<std::mutex> lock(mSignalingQueueMutex);
        if (mSignalingWorkerStopping.load()) return;
        mSignalingQueue.push_back(std::move(payload));
    }
    mSignalingQueueCv.notify_one();
}

void HostSessionCore::signalingWorkerLoop() {
    while (true) {
        std::string payload;
        {
            std::unique_lock<std::mutex> lock(mSignalingQueueMutex);
            mSignalingQueueCv.wait(lock, [this]() {
                return mSignalingWorkerStopping.load() || !mSignalingQueue.empty();
            });
            if (mSignalingWorkerStopping.load() && mSignalingQueue.empty()) {
                break;
            }
            payload = std::move(mSignalingQueue.front());
            mSignalingQueue.pop_front();
        }

        // Host 侧消息处理会验证成员 PKI、解密 GKA contribution，
        // 并可能提交新的群密钥。将这些工作移出 libdatachannel WSS 回调线程，
        // 避免连续 contribution 帧被证书验证阻塞。
        handleSignalingMessage(payload);
    }
}

void HostSessionCore::stopSignalingWorker() {
    mSignalingWorkerStopping.store(true);
    mSignalingQueueCv.notify_all();
    if (mSignalingThread.joinable() &&
        mSignalingThread.get_id() != std::this_thread::get_id()) {
        mSignalingThread.join();
    }
}

// 解析一行 Host 输入，并发送聊天、命令或附件。
void HostSessionCore::sendLine(const std::string& line) {
    if (handleHostCommand(line)) return;

    std::string directTarget;
    std::string directBody;
    if (parseDirectPrefix(line, directTarget, directBody)) {
        sendLineTo(directTarget, directBody);
        return;
    }

    if (line.empty()) return;
    if (line.rfind("/image ", 0) == 0 || line.rfind("/img ", 0) == 0) {
        sendImage(trimCopy(line.substr(line.find(' ') + 1)));
        return;
    }
    if (line.rfind("/file ", 0) == 0) {
        sendTextFile(trimCopy(line.substr(line.find(' ') + 1)));
        return;
    }
    if (line.rfind("/voice ", 0) == 0) {
        sendVoice(trimCopy(line.substr(line.find(' ') + 1)));
        return;
    }
    const auto actor = currentHostActorName();
    Message msg = makeTextMessage(actor, line);
    setCurrentHostActorMetadata(msg);
    if (!chat::secure_relay::hasUsableGroupKey(mGroupKey)) {
        chatEmit(mCallbacks.onError, "Room group key is not ready");
        return;
    }
    if (!mWs || mWs->isClosed()) {
        chatEmit(mCallbacks.onStatus, "Signaling channel is not open yet");
        return;
    }

    const auto envelope = chat::secure_relay::encryptMessageWithGroupKey(
        msg,
        mRoomToken,
        chat::protocol::HostActorId,
        mUsername,
        chat::protocol::HostActorKind,
        "",
        mGroupKey);
    mWs->send(envelope.dump());
    chatEmit(mCallbacks.onMessage, msg.toJson());
}

void HostSessionCore::sendLineTo(const std::string& target, const std::string& line) {
    // Host 对当前 Client 私发时只使用显示名寻址。
    // 解析出的协议 id 保留在加密载荷中，因此 Server 只进行广播。
    const auto targetNameInput = trimCopy(target);
    const auto targetId = resolveClientId(targetNameInput);
    if (targetNameInput.empty()) {
        sendLine(line);
        return;
    }
    if (targetId.empty()) {
        chatEmit(mCallbacks.onError, "Target member name not found: " + targetNameInput);
        return;
    }
    if (line.empty()) {
        chatEmit(mCallbacks.onError, "Private message body is empty");
        return;
    }
    if (line.rfind("/image ", 0) == 0 || line.rfind("/img ", 0) == 0) {
        sendImageTo(targetNameInput, trimCopy(line.substr(line.find(' ') + 1)));
        return;
    }
    if (line.rfind("/file ", 0) == 0) {
        sendTextFileTo(targetNameInput, trimCopy(line.substr(line.find(' ') + 1)));
        return;
    }
    if (line.rfind("/voice ", 0) == 0) {
        sendVoiceTo(targetNameInput, trimCopy(line.substr(line.find(' ') + 1)));
        return;
    }

    const auto targetName = displayNameForClient(targetId);
    const auto actor = currentHostActorName();
    Message msg = makeTextMessage(actor, line);
    setCurrentHostActorMetadata(msg);
    markPrivateTarget(msg, targetId, targetName);
    if (sendRelayMessage(msg, chat::protocol::HostActorId, mUsername, chat::protocol::HostActorKind, targetId)) {
        chatEmit(mCallbacks.onMessage, msg.toJson());
    }
}

bool HostSessionCore::handleHostCommand(const std::string& line) {
    // 管理命令是本地 Host 控制，不是聊天消息。
    // 它们复用普通输入框，使 CLI 和 WinUI 行为一致。
    std::istringstream input(trimCopy(line));
    std::string command;
    input >> command;
    if (command != "/silence" && command != "/unsilence" && command != "/evict" && command != "/ban") {
        return false;
    }

    std::string target;
    input >> target;
    if (target.empty()) {
        chatEmit(mCallbacks.onError, "Usage: " + command + " <member-name>");
        return true;
    }

    if (command == "/silence") {
        setClientSilenced(target, true);
    }
    else if (command == "/unsilence") {
        setClientSilenced(target, false);
    }
    else {
        evictClient(target);
    }
    return true;
}

// 通过加密 Server 中继向所有房间成员发送图片。
bool HostSessionCore::sendImage(const std::string& filePath) {
    return sendImageTo("", filePath);
}

bool HostSessionCore::sendImageTo(const std::string& target, const std::string& filePath) {
    const auto targetName = trimCopy(target);
    const auto targetId = resolveClientId(targetName);
    if (!targetName.empty() && targetId.empty()) {
        chatEmit(mCallbacks.onError, "Target member name not found: " + targetName);
        return false;
    }
    return sendAttachmentRelay(
        filePath,
        attachment::Kind::Image,
        "image_meta",
        "image_binary",
        "application/octet-stream",
        targetId);
}

// 通过加密 Server 中继向所有房间成员发送文本资料。
bool HostSessionCore::sendTextFile(const std::string& filePath) {
    return sendTextFileTo("", filePath);
}

bool HostSessionCore::sendTextFileTo(const std::string& target, const std::string& filePath) {
    const auto targetName = trimCopy(target);
    const auto targetId = resolveClientId(targetName);
    if (!targetName.empty() && targetId.empty()) {
        chatEmit(mCallbacks.onError, "Target member name not found: " + targetName);
        return false;
    }
    return sendAttachmentRelay(
        filePath,
        attachment::Kind::Text,
        "file_meta",
        "file_binary",
        "text/plain; charset=utf-8",
        targetId);
}

// 通过加密 Server 中继向所有房间成员发送短 WAV 语音。
bool HostSessionCore::sendVoice(const std::string& filePath) {
    return sendVoiceTo("", filePath);
}

bool HostSessionCore::sendVoiceTo(const std::string& target, const std::string& filePath) {
    const auto targetName = trimCopy(target);
    const auto targetId = resolveClientId(targetName);
    if (!targetName.empty() && targetId.empty()) {
        chatEmit(mCallbacks.onError, "Target member name not found: " + targetName);
        return false;
    }
    return sendAttachmentRelay(
        filePath,
        attachment::Kind::Voice,
        "voice_meta",
        "voice_binary",
        "audio/wav",
        targetId);
}

bool HostSessionCore::sendRelayMessage(
    const Message& msg,
    const std::string& senderId,
    const std::string& senderName,
    const std::string& senderKind,
    const std::string& targetId) {
    if (!chat::secure_relay::hasUsableGroupKey(mGroupKey)) {
        chatEmit(mCallbacks.onError, "Room group key is not ready");
        return false;
    }
    if (!mWs || mWs->isClosed()) {
        chatEmit(mCallbacks.onStatus, "Signaling channel is not open yet");
        return false;
    }

    Message outbound = msg;
    if (!targetId.empty()) {
        if (targetId == chat::protocol::HostActorId) {
            chatEmit(mCallbacks.onError, "Cannot send a private message to yourself");
            return false;
        }
        try {
            outbound = wrapPairwiseForTarget(msg, targetId);
        }
        catch (const std::exception& e) {
            chatEmit(mCallbacks.onError, std::string("Pairwise private send failed: ") + e.what());
            return false;
        }
    }

    const auto envelope = chat::secure_relay::encryptMessageWithGroupKey(
        outbound,
        mRoomToken,
        senderId,
        senderName,
        senderKind,
        targetId,
        mGroupKey);
    mWs->send(envelope.dump());
    return true;
}

Message HostSessionCore::wrapPairwiseForTarget(const Message& msg, const std::string& targetId) {
    // Host 使用目标经过 PKI 验证的 X25519 公钥构造内层私发加密。
    // 这让私发保持失败即关闭，而不是静默降级为只用房间群密钥投递。
    std::string targetPublicKey;
    std::string targetFingerprint;
    {
        std::lock_guard<std::mutex> lock(mClientsMutex);
        const auto publicKey = mClientPublicKeys.find(targetId);
        const auto fingerprint = mClientIdentityFingerprints.find(targetId);
        if (publicKey != mClientPublicKeys.end()) targetPublicKey = publicKey->second;
        if (fingerprint != mClientIdentityFingerprints.end()) targetFingerprint = fingerprint->second;
    }
    if (targetPublicKey.empty() || targetFingerprint.empty()) {
        throw std::runtime_error("target pairwise identity is not verified");
    }
    return chat::secure_relay::encryptMessageForPairwise(
        msg,
        mRoomToken,
        chat::protocol::HostActorId,
        targetId,
        targetPublicKey,
        mIdentity.fingerprint(),
        targetFingerprint);
}

Message HostSessionCore::decryptPairwiseFromClient(const Message& msg) {
    // Client 使用 Host 的成员公钥加密发给 Host 的私信。
    // 只有发送者 id 已有从 join_room 记录的已验证证书指纹时，
    // Host 才接受内层载荷。
    const auto senderId = msg.payload.value("relaySenderId", "");
    if (senderId.empty() || senderId == chat::protocol::HostActorId) {
        throw std::runtime_error("invalid pairwise sender");
    }
    std::string senderFingerprint;
    {
        std::lock_guard<std::mutex> lock(mClientsMutex);
        const auto it = mClientIdentityFingerprints.find(senderId);
        if (it != mClientIdentityFingerprints.end()) senderFingerprint = it->second;
    }
    if (senderFingerprint.empty()) {
        throw std::runtime_error("sender pairwise identity is not verified");
    }
    auto inner = chat::secure_relay::decryptMessageFromPairwise(
        msg,
        mRoomToken,
        senderId,
        chat::protocol::HostActorId,
        mMemberKeys.privateKey,
        senderFingerprint,
        mIdentity.fingerprint());
    inner.payload["relaySenderId"] = senderId;
    inner.payload["relaySenderKind"] = chat::protocol::ClientActorKind;
    inner.payload["relaySenderName"] = msg.payload.value("relaySenderName", "");
    inner.payload["relayTargetId"] = chat::protocol::HostActorId;
    return inner;
}

bool HostSessionCore::rememberRelayEnvelope(const json& envelope) {
    // 重放不同于解密失败：被重放的密文在 AES-GCM 下可能仍有效。
    // 跟踪近期 nonce/tag 对，使 Server 无法在本会话中重放旧命令、文本或附件分片。
    constexpr std::size_t maxRememberedRelayIds = 4096;
    const auto replayId = chat::secure_relay::replayIdForEnvelope(envelope);
    if (replayId.empty()) return true;
    if (mRecentRelayIds.find(replayId) != mRecentRelayIds.end()) {
        chatEmit(mCallbacks.onError, "Dropped replayed encrypted relay");
        return false;
    }
    mRecentRelayIds.insert(replayId);
    mRecentRelayOrder.push_back(replayId);
    while (mRecentRelayOrder.size() > maxRememberedRelayIds) {
        mRecentRelayIds.erase(mRecentRelayOrder.front());
        mRecentRelayOrder.pop_front();
    }
    return true;
}

bool HostSessionCore::sendGroupStateToClient(
    const std::string& clientId,
    const std::string& clientPublicKey,
    const json& groupState,
    std::uint64_t epoch) {
    // Host 转发的是已验证 contribution 集合，而不是 Host 自选的原始密钥。
    // Client 解密该状态、验证签名，并自行派生 K_G。
    if (!mWs || mWs->isClosed()) {
        chatEmit(mCallbacks.onStatus, "Signaling channel is not open yet");
        return false;
    }

    auto envelope = chat::secure_relay::encryptGroupStateForMember(
        groupState,
        mRoomToken,
        clientId,
        clientPublicKey,
        epoch);
    // Host 对最终 envelope 签名，使 Client 在接受房间群密钥前能拒绝任何被修改字段。
    mIdentity.signGroupKeyEnvelope(envelope);
    mWs->send(envelope.dump());
    chatEmit(mCallbacks.onStatus, "GKA state sent to " + displayNameForClient(clientId));
    return true;
}

void HostSessionCore::rotateGroupKey(const std::string& reason) {
    // 轮换现在会启动贡献式 GKA epoch。
    // Host 像其他成员一样贡献随机性，不再单独选择 K_G。
    std::unordered_set<std::string> currentMembers;
    {
        std::lock_guard<std::mutex> lock(mClientsMutex);
        for (const auto& [clientId, publicKey] : mClientPublicKeys) {
            if (!publicKey.empty()) currentMembers.insert(clientId);
        }
    }

    {
        std::lock_guard<std::mutex> lock(mGkaMutex);
        ++mGroupKeyEpoch;
        mPendingGkaEpoch = mGroupKeyEpoch;
        mPendingGkaMembers = std::move(currentMembers);
        mPendingGkaContributions.clear();
        mPendingGkaContributions[chat::protocol::HostActorId] = makeLocalGkaContribution(mPendingGkaEpoch);
        // 恶意或故障成员不能无限期拖住房间。
        // 看门狗会驱逐在该截止时间后仍未提交的 Client。
        mPendingGkaDeadline = std::chrono::steady_clock::now() + GkaContributionTimeout;
    }
    mGkaCv.notify_all();
    chatEmit(mCallbacks.onStatus, "GKA epoch started: " + reason);
    sendGkaRequestToClients();
    tryCommitGkaEpoch();
}

void HostSessionCore::sendGkaRequestToClients() {
    if (!mWs || mWs->isClosed()) {
        chatEmit(mCallbacks.onStatus, "Signaling channel is not open yet");
        return;
    }
    std::uint64_t epoch = 0;
    {
        std::lock_guard<std::mutex> lock(mGkaMutex);
        epoch = mPendingGkaEpoch;
    }
    if (epoch == 0) return;
    json msg = {
        {"type", chat::secure_relay::GkaRequestType},
        {"roomId", mRoomToken},
        {"epoch", epoch}
    };
    mWs->send(msg.dump());
    // 诊断状态：如果 Client 入房后从未打印 "GKA request received"，
    // 则 Server/proxy 路径没有投递该控制帧。
    chatEmit(mCallbacks.onStatus, "GKA request sent: epoch " + std::to_string(epoch));
}

void HostSessionCore::startGkaTimeoutWorker() {
    // 为该 Host 会话启动一个轻量看门狗。
    // 在 rotateGroupKey() 发布待处理 epoch 和截止时间前，它不做网络工作。
    {
        std::lock_guard<std::mutex> lock(mGkaMutex);
        mGkaTimeoutStop = false;
    }
    if (!mGkaTimeoutThread.joinable()) {
        mGkaTimeoutThread = std::thread(&HostSessionCore::gkaTimeoutLoop, this);
    }
}

void HostSessionCore::stopGkaTimeoutWorker() {
    // 取消所有待处理 epoch 并 join 看门狗，
    // 避免关闭后留下持有回调或 WebSocket 状态的后台线程。
    {
        std::lock_guard<std::mutex> lock(mGkaMutex);
        mGkaTimeoutStop = true;
        mPendingGkaEpoch = 0;
        mPendingGkaMembers.clear();
        mPendingGkaContributions.clear();
    }
    mGkaCv.notify_all();
    if (mGkaTimeoutThread.joinable() &&
        mGkaTimeoutThread.get_id() != std::this_thread::get_id()) {
        mGkaTimeoutThread.join();
    }
}

void HostSessionCore::gkaTimeoutLoop() {
    // 等待当前 GKA 截止时间。新 epoch 或成功提交会通过 mGkaCv 唤醒该循环，
    // 因此它只会针对真正超时的精确 epoch 驱逐成员。
    std::unique_lock<std::mutex> lock(mGkaMutex);
    while (!mGkaTimeoutStop) {
        if (mPendingGkaEpoch == 0) {
            mGkaCv.wait(lock, [this]() {
                return mGkaTimeoutStop || mPendingGkaEpoch != 0;
            });
            continue;
        }

        const auto epoch = mPendingGkaEpoch;
        const auto deadline = mPendingGkaDeadline;
        const bool changed = mGkaCv.wait_until(lock, deadline, [this, epoch]() {
            return mGkaTimeoutStop || mPendingGkaEpoch == 0 || mPendingGkaEpoch != epoch;
        });
        if (changed) continue;

        lock.unlock();
        evictGkaTimeoutMembers(epoch);
        lock.lock();
    }
}

void HostSessionCore::evictGkaTimeoutMembers(std::uint64_t epoch) {
    // 将停滞的 GKA epoch 转换为显式成员关系变化。
    // 缺失贡献者会被移除，其当前房间证书指纹会被封禁，
    // 随后剩余成员启动新的 epoch。
    std::vector<std::string> missingMembers;
    {
        std::lock_guard<std::mutex> lock(mGkaMutex);
        if (mPendingGkaEpoch != epoch) return;
        for (const auto& memberId : mPendingGkaMembers) {
            if (mPendingGkaContributions.find(memberId) == mPendingGkaContributions.end()) {
                missingMembers.push_back(memberId);
            }
        }
        if (missingMembers.empty()) return;
        // 该 epoch 因至少一个成员停滞而无法提交。
        // 移除成员前先清空它；rotateGroupKey() 会用剩余当前成员构造新 epoch。
        mPendingGkaEpoch = 0;
        mPendingGkaMembers.clear();
        mPendingGkaContributions.clear();
    }

    std::vector<std::string> removedNames;
    std::vector<std::string> removedIds;
    {
        std::lock_guard<std::mutex> lock(mClientsMutex);
        for (const auto& clientId : missingMembers) {
            auto name = mClientNames.find(clientId);
            if (name == mClientNames.end()) continue;

            const auto displayName = name->second;
            auto fingerprint = mClientIdentityFingerprints.find(clientId);
            if (fingerprint != mClientIdentityFingerprints.end() && !fingerprint->second.empty()) {
                mBannedIdentityFingerprints.insert(fingerprint->second);
            }
            mClientNames.erase(clientId);
            mClientPublicKeys.erase(clientId);
            mClientIdentityFingerprints.erase(clientId);
            mClientIdentitySubjects.erase(clientId);
            mClientIdentityObjects.erase(clientId);
            mSilencedClientIds.erase(clientId);
            removedNames.push_back(displayName.empty() ? clientId : displayName);
            removedIds.push_back(clientId);
        }
    }

    for (const auto& clientId : removedIds) {
        rejectClient(clientId, "GKA contribution timeout");
        mPendingTransfers.clear(clientId);
    }

    if (removedNames.empty()) return;
    std::ostringstream names;
    for (std::size_t i = 0; i < removedNames.size(); ++i) {
        if (i != 0) names << ", ";
        names << removedNames[i];
    }
    chatEmit(mCallbacks.onStatus, "GKA contribution timeout; evicted: " + names.str());
    rotateGroupKey("GKA contribution timeout");
}

json HostSessionCore::makeLocalGkaContribution(std::uint64_t epoch) const {
    const auto contribution = chat::secure_relay::generateGroupContribution();
    json item = {
        {"memberId", chat::protocol::HostActorId},
        {"username", mUsername},
        {"publicKey", mMemberKeys.publicKey},
        {"contribution", contribution}
    };
    item["identity"] = mIdentity.signGkaContribution(
        mRoomId,
        epoch,
        chat::protocol::HostActorId,
        mUsername,
        mMemberKeys.publicKey,
        contribution);
    item["fingerprint"] = mIdentity.fingerprint();
    return item;
}

bool HostSessionCore::rememberGkaContribution(const json& contribution, const std::string& expectedMemberId) {
    if (!contribution.is_object()) return false;
    const auto memberId = contribution.value("memberId", "");
    const auto username = contribution.value("username", memberId);
    const auto publicKey = contribution.value("publicKey", "");
    const auto secret = contribution.value("contribution", "");
    const auto identity = contribution.find("identity");
    if (memberId.empty() || memberId != expectedMemberId || publicKey.empty() || secret.empty() ||
        identity == contribution.end() || !identity->is_object()) {
        chatEmit(mCallbacks.onError, "Invalid GKA contribution from " + expectedMemberId);
        return false;
    }

    std::uint64_t pendingEpoch = 0;
    {
        std::lock_guard<std::mutex> lock(mGkaMutex);
        pendingEpoch = mPendingGkaEpoch;
        if (pendingEpoch == 0 || mPendingGkaMembers.find(memberId) == mPendingGkaMembers.end()) {
            chatEmit(mCallbacks.onError, "Dropped unexpected GKA contribution from " + memberId);
            return false;
        }
    }

    std::string knownPublicKey;
    std::string knownName;
    std::string knownFingerprint;
    {
        std::lock_guard<std::mutex> lock(mClientsMutex);
        auto key = mClientPublicKeys.find(memberId);
        auto name = mClientNames.find(memberId);
        auto fp = mClientIdentityFingerprints.find(memberId);
        if (key != mClientPublicKeys.end()) knownPublicKey = key->second;
        if (name != mClientNames.end()) knownName = name->second;
        if (fp != mClientIdentityFingerprints.end()) knownFingerprint = fp->second;
    }
    if (knownPublicKey != publicKey || (!knownName.empty() && knownName != username)) {
        chatEmit(mCallbacks.onError, "GKA contribution identity does not match member state: " + memberId);
        return false;
    }

    try {
        const auto verified = mIdentity.verifyGkaContribution(
            mRoomId,
            pendingEpoch,
            memberId,
            username,
            publicKey,
            secret,
            *identity);
        if (!knownFingerprint.empty() && verified.fingerprint != knownFingerprint) {
            throw std::runtime_error("contribution fingerprint does not match joined identity");
        }
        json stored = contribution;
        stored["fingerprint"] = verified.fingerprint;
        {
            std::lock_guard<std::mutex> lock(mGkaMutex);
            if (mPendingGkaEpoch != pendingEpoch ||
                mPendingGkaMembers.find(memberId) == mPendingGkaMembers.end()) {
                chatEmit(mCallbacks.onError, "Dropped stale GKA contribution from " + memberId);
                return false;
            }
            mPendingGkaContributions[memberId] = stored;
        }
        mGkaCv.notify_all();
        chatEmit(mCallbacks.onStatus, "GKA contribution verified: " + username + " / " + memberId);
        return true;
    }
    catch (const std::exception& e) {
        chatEmit(mCallbacks.onError, "GKA contribution rejected: " + memberId + ": " + e.what());
        return false;
    }
}

void HostSessionCore::tryCommitGkaEpoch() {
    std::uint64_t epoch = 0;
    json contributions = json::array();
    {
        std::lock_guard<std::mutex> lock(mGkaMutex);
        if (mPendingGkaEpoch == 0 || mPendingGkaEpoch != mGroupKeyEpoch) return;
        for (const auto& memberId : mPendingGkaMembers) {
            if (mPendingGkaContributions.find(memberId) == mPendingGkaContributions.end()) {
                return;
            }
        }
        epoch = mPendingGkaEpoch;
        for (const auto& [_, contribution] : mPendingGkaContributions) {
            contributions.push_back(contribution);
        }
    }

    json groupState = {
        {"version", 3},
        {"roomId", mRoomToken},
        {"epoch", epoch},
        {"contributions", contributions}
    };

    auto groupKey = chat::secure_relay::deriveGroupKeyFromContributions(
        mRoomToken,
        epoch,
        contributions);

    std::vector<std::pair<std::string, std::string>> clients;
    {
        std::lock_guard<std::mutex> lock(mClientsMutex);
        clients.reserve(mClientPublicKeys.size());
        for (const auto& [clientId, publicKey] : mClientPublicKeys) {
            clients.push_back({clientId, publicKey});
        }
    }

    {
        std::lock_guard<std::mutex> lock(mGkaMutex);
        if (mPendingGkaEpoch != epoch) return;
        mGroupKey = std::move(groupKey);
        mPendingGkaEpoch = 0;
        mPendingGkaMembers.clear();
        mPendingGkaContributions.clear();
    }
    mGkaCv.notify_all();

    for (const auto& [clientId, publicKey] : clients) {
        sendGroupStateToClient(clientId, publicKey, groupState, epoch);
    }
    chatEmit(mCallbacks.onStatus, "Room group key ready");
    announceVerifiedMembers();
}

bool HostSessionCore::sendAttachmentRelay(
    const std::string& filePath,
    attachment::Kind kind,
    const std::string& metaType,
    const std::string& binaryType,
    const std::string& mime,
    const std::string& targetId) {
    // 附件会被加密为元数据加分片消息。
    // targetId 保留在加密载荷中；Server 广播每个中继帧，
    // 预期接收者打开内层双方私发加密。
    const auto bytes = attachment::readFileBytes(filePath, kind);
    const auto actor = currentHostActorName();
    const auto targetName = targetId.empty() ? std::string() : displayNameForClient(targetId);
    Message meta = attachment::makeBinaryMeta(metaType, actor, filePath, mime, bytes.size());
    setCurrentHostActorMetadata(meta);
    markPrivateTarget(meta, targetId, targetName);
    if (!sendRelayMessage(meta, chat::protocol::HostActorId, mUsername, chat::protocol::HostActorKind, targetId)) {
        return false;
    }

    const auto transferId = attachment::transferIdFromMessage(meta);
    for (std::size_t offset = 0; offset < bytes.size(); offset += attachment::RelayChunkBytes) {
        const auto chunkSize = (std::min)(attachment::RelayChunkBytes, bytes.size() - offset);
        Message chunk;
        chunk.type = binaryType;
        chunk.from = actor;
        chunk.name = meta.name;
        chunk.mime = meta.mime;
        chunk.data = attachment::base64Encode(bytes, offset, chunkSize);
        chunk.payload = {
            {"transferId", transferId},
            {"name", meta.name},
            {"mime", meta.mime},
            {"size", static_cast<int>(bytes.size())},
            {"offset", static_cast<int>(offset)},
            {"chunkSize", static_cast<int>(chunkSize)}
        };
        setCurrentHostActorMetadata(chunk);
        markPrivateTarget(chunk, targetId, targetName);
        if (!sendRelayMessage(chunk, chat::protocol::HostActorId, mUsername, chat::protocol::HostActorKind, targetId)) {
            return false;
        }
    }

    chatEmit(mCallbacks.onMessage, meta.toJson());
    const auto uiKind = attachment::eventKind(kind);
    if (uiKind == "image") {
        chatEmit(mCallbacks.onImage, filePath);
    }
    else if (uiKind == "voice") {
        chatEmit(mCallbacks.onVoice, filePath);
    }
    else {
        chatEmit(mCallbacks.onFile, filePath);
    }
    return true;
}

// 处理发给 Host 房主的信令 WebSocket 消息。
void HostSessionCore::handleSignalingMessage(const std::string& s) {
    if (mStopped.load()) return;

    try {
        // 信令和中继消息都是不可信网络输入。
        // 从 JSON 对象读取类型字段前，先应用相同的大小/深度预算。
        auto j = chat::protocol::parseJsonObjectWithBudget(
            s,
            chat::protocol::MaxSignalingMessageBytes,
            "signaling message");
        std::string type = j.value("type", "");

        if (type == "room_created") {
            mRoomCreated.store(true);
            chatEmit(mCallbacks.onStatus, "Room created: " + mRoomId);
            rotateGroupKey("room created");
        }
        else if (type == "room_members") {
            std::ostringstream members;
            bool first = true;
            for (const auto& member : j.value("memberInfos", json::array())) {
                if (!member.is_object()) continue;
                if (!first) members << "; ";
                const auto id = member.value("id", "");
                // 发出 name/id，使 UI Client 不暴露原始信令 JSON
                // 也能保留内部 PKI 映射。
                members << member.value("username", id) << " / " << id;
                first = false;
            }
            if (first) {
                for (const auto& member : j.value("members", json::array())) {
                    if (!first) members << "; ";
                    members << member.get<std::string>();
                    first = false;
                }
            }
            chatEmit(mCallbacks.onStatus, "Room members: " + members.str());
        }
        else if (type == "new_client") {
            std::string clientId = j.value("clientId", "");
            std::string username = j.value("username", clientId);
            std::string publicKey = j.value("publicKey", "");
            json identityObject;
            std::string identityFingerprint;
            std::string identitySubject;
            if (!clientId.empty() && publicKey.empty()) {
                chatEmit(mCallbacks.onError, "Client public key is missing: " + username);
                rejectClient(clientId, "client public key is missing");
                return;
            }
            if (!clientId.empty()) {
                try {
                    // Host 是 Client 入房的信任决策点。
                    // Server 只转发该 identity 对象，并未验证它。
                    auto identity = j.find("identity");
                    if (identity == j.end()) throw std::runtime_error("client identity is missing");
                    identityObject = *identity;
                    const auto verified = mIdentity.verifyJoinRoom(mRoomId, username, publicKey, *identity);
                    identityFingerprint = verified.fingerprint;
                    identitySubject = verified.subject;
                    chatEmit(mCallbacks.onStatus, "PKI member verified: " + username + " / " + clientId + " / " + identityFingerprint);
                }
                catch (const std::exception& e) {
                    chatEmit(mCallbacks.onError, "Client identity rejected: " + username + ": " + e.what());
                    rejectClient(clientId, "client identity verification failed");
                    return;
                }
            }
            bool bannedCertificate = false;
            {
                std::lock_guard<std::mutex> lock(mClientsMutex);
                bannedCertificate = !identityFingerprint.empty() &&
                    mBannedIdentityFingerprints.find(identityFingerprint) != mBannedIdentityFingerprints.end();
            }
            if (bannedCertificate) {
                chatEmit(mCallbacks.onStatus, "Rejected banned member certificate: " + username + " / " + identityFingerprint);
                rejectClient(clientId, "member certificate is banned");
                return;
            }
            {
                std::lock_guard<std::mutex> lock(mClientsMutex);
                mClientNames[clientId] = username;
                if (!publicKey.empty()) mClientPublicKeys[clientId] = publicKey;
                if (!identityFingerprint.empty()) {
                    mClientIdentityFingerprints[clientId] = identityFingerprint;
                    mClientIdentitySubjects[clientId] = identitySubject;
                    mClientIdentityObjects[clientId] = identityObject;
                }
            }
            if (!clientId.empty()) {
                chatEmit(mCallbacks.onStatus, "Client joined: " + username);
                // 新成员加入意味着需要新的房间群密钥，
                // 该成员只能通过已验证公钥收到当前密钥版本。
                rotateGroupKey("member joined");
            }
        }
        else if (type == "client_left") {
            const std::string clientId = j.value("clientId", "");
            removeClient(clientId);
        }
        else if (type == chat::secure_relay::GkaContributionType) {
            const auto epoch = j.value("epoch", 0ULL);
            const auto senderId = j.value("senderId", "");
            std::uint64_t pendingEpoch = 0;
            {
                std::lock_guard<std::mutex> lock(mGkaMutex);
                pendingEpoch = mPendingGkaEpoch;
            }
            if (pendingEpoch == 0 || epoch != pendingEpoch) {
                chatEmit(mCallbacks.onError, "Dropped stale GKA contribution from " + senderId);
                return;
            }
            auto contribution = chat::secure_relay::decryptGkaContributionForHost(
                j,
                mRoomToken,
                senderId,
                mMemberKeys.privateKey);
            if (rememberGkaContribution(contribution, senderId)) {
                tryCommitGkaEpoch();
            }
        }
        else if (type == chat::secure_relay::EnvelopeType) {
            // Host 像普通成员一样解密应用中继。
            if (!chat::secure_relay::hasUsableGroupKey(mGroupKey)) {
                chatEmit(mCallbacks.onError, "Room group key is not ready");
                return;
            }
            if (!rememberRelayEnvelope(j)) return;
            auto msg = chat::secure_relay::decryptMessageWithGroupKey(j, mRoomToken, mGroupKey);
            const auto relayTargetId = msg.payload.value("relayTargetId", "");
            if (!relayTargetId.empty() && relayTargetId != chat::protocol::HostActorId) {
                // 私发中继在外层以广播方式发送。
                // 非目标成员会静默丢弃它，避免暴露私发事件。
                return;
            }
            if (msg.type == chat::secure_relay::PairwisePrivateType) {
                try {
                    msg = decryptPairwiseFromClient(msg);
                }
                catch (const std::exception& e) {
                    chatEmit(mCallbacks.onError, std::string("Pairwise private receive failed: ") + e.what());
                    return;
                }
            }
            handleRelayMessage(msg);
        }
        else if (type == "error") {
            const std::string message = j.value("message", "unknown");
            chatEmit(mCallbacks.onError, "Signaling server error: " + message);
            if (message == "room already exists") {
                mStopped.store(true);
                if (mWs && !mWs->isClosed()) mWs->close();
                chatEmit(mCallbacks.onStatus, "Session stopped");
            }
        }
    }
    catch (const std::exception& e) {
        chatEmit(mCallbacks.onError, std::string("Bad signaling message: ") + e.what());
    }
}

// 移除一个 Client 成员，并清除来自它的所有暂存附件传输。
void HostSessionCore::removeClient(const std::string& id) {
    if (id.empty()) return;
    if (mStopped.load()) return;

    std::string displayName = id;
    bool knownClient = false;
    {
        std::lock_guard<std::mutex> lock(mClientsMutex);
        auto name = mClientNames.find(id);
        if (name != mClientNames.end()) {
            displayName = name->second;
            knownClient = true;
        }
        knownClient = mClientNames.erase(id) > 0 || knownClient;
        knownClient = mClientPublicKeys.erase(id) > 0 || knownClient;
        knownClient = mClientIdentityFingerprints.erase(id) > 0 || knownClient;
        knownClient = mClientIdentitySubjects.erase(id) > 0 || knownClient;
        knownClient = mClientIdentityObjects.erase(id) > 0 || knownClient;
        mSilencedClientIds.erase(id);
    }
    if (!knownClient) {
        // 恶意或混乱的 Server 可能报告过期/未知 client_left。
        // 忽略它可避免不必要的群密钥轮换和 UI 抖动。
        chatEmit(mCallbacks.onStatus, "Ignored unknown client_left: " + id);
        return;
    }
    mPendingTransfers.clear(id);
    chatEmit(mCallbacks.onStatus, "Client left: " + displayName);
    // 离开成员不应读取未来消息，因此 Host 会轮换 K_G。
    rotateGroupKey("member left");
}

void HostSessionCore::setClientSilenced(const std::string& target, bool silenced) {
    if (!mWs || mWs->isClosed()) {
        chatEmit(mCallbacks.onStatus, "Signaling channel is not open yet");
        return;
    }

    const auto clientId = resolveClientId(trimCopy(target));
    if (clientId.empty() || clientId == chat::protocol::HostActorId) {
        chatEmit(mCallbacks.onError, "Target member is not a client");
        return;
    }

    std::string displayName;
    bool foundClient = false;
    {
        std::lock_guard<std::mutex> lock(mClientsMutex);
        auto name = mClientNames.find(clientId);
        if (name != mClientNames.end()) {
            foundClient = true;
            displayName = name->second;
        }
        if (foundClient) {
            if (silenced) {
                mSilencedClientIds.insert(clientId);
            }
            else {
                mSilencedClientIds.erase(clientId);
            }
        }
    }
    if (!foundClient) {
        chatEmit(mCallbacks.onError, "Target client not found: " + target);
        return;
    }

    sendClientModeration(silenced ? "silence_client" : "unsilence_client", clientId);
    chatEmit(mCallbacks.onStatus, std::string(silenced ? "Client silenced: " : "Client unsilenced: ") + displayName);
}

void HostSessionCore::evictClient(const std::string& target) {
    if (!mWs || mWs->isClosed()) {
        chatEmit(mCallbacks.onStatus, "Signaling channel is not open yet");
        return;
    }

    const auto clientId = resolveClientId(trimCopy(target));
    if (clientId.empty() || clientId == chat::protocol::HostActorId) {
        chatEmit(mCallbacks.onError, "Target member is not a client");
        return;
    }

    std::string displayName;
    std::string fingerprint;
    bool foundClient = false;
    {
        std::lock_guard<std::mutex> lock(mClientsMutex);
        auto name = mClientNames.find(clientId);
        if (name != mClientNames.end()) {
            foundClient = true;
            displayName = name->second;
        }
        if (foundClient) {
            auto identity = mClientIdentityFingerprints.find(clientId);
            if (identity != mClientIdentityFingerprints.end()) {
                fingerprint = identity->second;
                mBannedIdentityFingerprints.insert(fingerprint);
            }
        }
    }
    if (!foundClient) {
        chatEmit(mCallbacks.onError, "Target client not found: " + target);
        return;
    }

    rejectClient(clientId, "member evicted by host");
    chatEmit(mCallbacks.onStatus, "Client evicted: " + displayName);
    if (!fingerprint.empty()) {
        chatEmit(mCallbacks.onStatus, "Banned member certificate for this room: " + fingerprint);
    }
    removeClient(clientId);
}

void HostSessionCore::sendClientModeration(const std::string& type, const std::string& clientId) {
    if (clientId.empty() || !mWs || mWs->isClosed()) {
        chatEmit(mCallbacks.onStatus, "Signaling channel is not open yet");
        return;
    }
    json msg = {
        {"type", type},
        {"roomId", mRoomToken},
        {"targetId", clientId}
    };
    mWs->send(msg.dump());
}

void HostSessionCore::handleRelayMessage(const Message& msg) {
    // member_identity 是 Host 发起且只发给 Client 的控制消息；
    // 如果它回环到 Host，Host 会忽略。
    if (msg.type == "member_identity") {
        return;
    }

    if (msg.type == "text") {
        chatEmit(mCallbacks.onMessage, msg.toJson());
        return;
    }

    attachment::Kind kind = attachment::Kind::Text;
    const auto senderKey = actorIdFromMessage(msg);
    if (attachmentKindForMeta(msg.type, kind)) {
        // 元数据会打开接收槽位。后续二进制分片必须携带相同 transferId，
        // 否则会被拒绝。
        const auto transferId = attachment::transferIdFromMessage(msg);
        const auto pending = mPendingTransfers.stage(
            senderKey,
            kind,
            transferId,
            msg.name,
            attachment::expectedSizeFromMeta(msg, kind));
        Message out = msg;
        out.name = pending.name;
        out.payload["transferId"] = pending.transferId;
        out.payload["name"] = pending.name;
        chatEmit(mCallbacks.onMessage, out.toJson());
        chatEmit(mCallbacks.onStatus, "Encrypted attachment meta received: " + pending.name);
        return;
    }

    if (isAttachmentBinaryType(msg.type)) {
        handleRelayBinaryChunk(senderKey, msg);
        return;
    }

    if (msg.type == "attachment_cancel") {
        mPendingTransfers.clear(senderKey);
        chatEmit(mCallbacks.onStatus, "Encrypted attachment transfer canceled: " + msg.content);
        return;
    }

    chatEmit(mCallbacks.onMessage, msg.toJson());
}

void HostSessionCore::handleRelayBinaryChunk(const std::string& senderKey, const Message& msg) {
    // 这里的二进制分片已经是解密后的应用 Message。
    // 该函数检查传输连续性，并把字节追加到本地缓存文件。
    std::string transferId;
    try {
        transferId = attachment::transferIdFromMessage(msg);
        if (transferId != mPendingTransfers.activeTransferId(senderKey)) {
            throw std::runtime_error("attachment chunk transfer id does not match pending meta");
        }
        const auto result = mPendingTransfers.appendChunk(senderKey, attachment::base64DecodeToRtcBytes(msg.data));
        if (!result.found) {
            chatEmit(mCallbacks.onError, "Unexpected encrypted attachment chunk from " + senderKey);
            return;
        }
        if (!result.complete) return;

        const auto uiKind = attachment::eventKind(result.slot.kind);
        if (uiKind == "image") {
            chatEmit(mCallbacks.onImage, result.slot.path);
        }
        else if (uiKind == "voice") {
            chatEmit(mCallbacks.onVoice, result.slot.path);
        }
        else {
            chatEmit(mCallbacks.onFile, result.slot.path);
        }
    }
    catch (const std::exception& e) {
        mPendingTransfers.clear(senderKey);
        chatEmit(mCallbacks.onError, std::string("Encrypted attachment receive failed from ") + senderKey + ": " + e.what());
    }
}

std::string HostSessionCore::currentHostActorName() {
    return chat::protocol::HostActorId;
}

void HostSessionCore::setCurrentHostActorMetadata(Message& msg) {
    setActorMetadata(
        msg,
        chat::protocol::HostActorId,
        chat::protocol::HostActorKind,
        msg.from.empty() ? chat::protocol::HostActorId : msg.from);
}

// 将稳定 actor 身份与人类可读发送者标签分开保存。
void HostSessionCore::setActorMetadata(
    Message& msg,
    const std::string& actorId,
    const std::string& actorKind,
    const std::string& displayName) {
    msg.payload["actorId"] = actorId;
    msg.payload["actorKind"] = actorKind;
    msg.payload["displayName"] = displayName;
}

// 从信令用户名中选择可见参与者名称。
std::string HostSessionCore::displayNameForClient(const std::string& id) {
    std::lock_guard<std::mutex> lock(mClientsMutex);
    auto name = mClientNames.find(id);
    return name == mClientNames.end() ? id : name->second;
}

// 尽可能将可见成员名解析为底层 client id。
std::string HostSessionCore::resolveClientId(const std::string& token) {
    if (token.empty()) return "";
    std::lock_guard<std::mutex> lock(mClientsMutex);
    for (const auto& [id, name] : mClientNames) {
        if (name == token) return id;
    }
    return "";
}

void HostSessionCore::rejectClient(const std::string& clientId, const std::string& reason) {
    if (clientId.empty() || !mWs || mWs->isClosed()) return;
    json msg = {
        {"type", "reject_client"},
        {"roomId", mRoomToken},
        {"targetId", clientId},
        {"reason", reason}
    };
    mWs->send(msg.dump());
}

void HostSessionCore::announceVerifiedMember(
    const std::string& memberId,
    const std::string& displayName,
    const std::string& fingerprint,
    const std::string& subject,
    const std::string& publicKey,
    const json& identity) {
    if (memberId.empty() || fingerprint.empty() || publicKey.empty() || !identity.is_object()) return;

    Message msg;
    msg.type = "member_identity";
    msg.from = currentHostActorName();
    setCurrentHostActorMetadata(msg);
    msg.payload["memberId"] = memberId;
    msg.payload["displayName"] = displayName.empty() ? memberId : displayName;
    msg.payload["fingerprint"] = fingerprint;
    msg.payload["subject"] = subject;
    msg.payload["publicKey"] = publicKey;
    msg.payload["identity"] = identity;
    msg.payload["state"] = "verified";
    msg.payload["verifiedBy"] = chat::protocol::HostActorId;

    // 该公告是加密控制消息。Server 可以中继，但无法读取。
    // Client 仍会验证其中的身份签名，使不可信 Host 无法静默替换其他成员公钥。
    sendRelayMessage(msg, chat::protocol::HostActorId, mUsername, chat::protocol::HostActorKind, "");
}

void HostSessionCore::announceVerifiedMembers() {
    std::vector<std::tuple<std::string, std::string, std::string, std::string, std::string, json>> members;
    members.emplace_back(
        chat::protocol::HostActorId,
        mUsername,
        mIdentity.fingerprint(),
        mIdentity.subject(),
        mMemberKeys.publicKey,
        mIdentity.signJoinRoom(mRoomId, mUsername, mMemberKeys.publicKey));
    {
        std::lock_guard<std::mutex> lock(mClientsMutex);
        members.reserve(members.size() + mClientIdentityFingerprints.size());
        for (const auto& [memberId, fingerprint] : mClientIdentityFingerprints) {
            const auto name = mClientNames.find(memberId);
            const auto subject = mClientIdentitySubjects.find(memberId);
            const auto publicKey = mClientPublicKeys.find(memberId);
            const auto identity = mClientIdentityObjects.find(memberId);
            if (publicKey == mClientPublicKeys.end() || identity == mClientIdentityObjects.end()) continue;
            members.emplace_back(
                memberId,
                name == mClientNames.end() ? memberId : name->second,
                fingerprint,
                subject == mClientIdentitySubjects.end() ? std::string() : subject->second,
                publicKey->second,
                identity->second);
        }
    }

    for (const auto& [memberId, displayName, fingerprint, subject, publicKey, identity] : members) {
        announceVerifiedMember(memberId, displayName, fingerprint, subject, publicKey, identity);
    }
}
