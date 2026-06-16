// Client 会话实现。它签名 join_room，接收 Host 分发的群密钥，
// 解密中继 envelope，并发送加密聊天/附件消息。
#include "client_session_core.hpp"

#include "attachment_transfer.hpp"
#include "secure_relay.hpp"

#include <algorithm>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace {
namespace attachment = chat::attachment;

// 返回去除首尾 ASCII 空白后的副本。
std::string trimCopy(std::string value) {
    const auto first = value.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) return "";
    const auto last = value.find_last_not_of(" \t\r\n");
    return value.substr(first, last - first + 1);
}

bool parseDirectPrefix(const std::string& line, std::string& target, std::string& body) {
    // 将 "/to alice hello" 拆成路由 token 和剩余命令正文。
    // 正文本身也可以是 "/image p.png" 这类附件命令。
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
    // 明文 envelope 只暴露路由 id。
    // 加密载荷保留 UI 标签，并把该项标记为私发。
    msg.payload["private"] = true;
    msg.payload["targetId"] = targetId;
    msg.payload["targetName"] = targetName.empty() ? targetId : targetName;
}

bool attachmentKindForMeta(const std::string& type, attachment::Kind& kind) {
    // 将已解密附件元数据消息映射回 receive-store 类型，
    // 使文本、图片和语音共用同一条加密中继路径。
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
    // 二进制分片是携带 base64 载荷的加密 JSON 消息；
    // 该判断用于把分片消息同普通文本或元数据消息区分开。
    return type == "image_binary" || type == "file_binary" || type == "voice_binary";
}

std::string actorIdFromMessage(const Message& msg) {
    // 附件重组以稳定 actor id 为键，而不使用显示名；
    // 用户名在重连或未来 UI 变化时可能出现冲突。
    if (msg.payload.is_object() && msg.payload.contains("actorId") && msg.payload["actorId"].is_string()) {
        const auto id = msg.payload["actorId"].get<std::string>();
        if (!id.empty()) return id;
    }
    return msg.from;
}
}

// 保存信令目标和 Client 凭据。
// Client 输入会直接映射为普通 SecureChat 协议消息。
ClientSessionCore::ClientSessionCore(
    std::string url,
    std::string room,
    std::string username,
    std::string password,
    rtc::WebSocket::Configuration wsConfig)
    : mWsUrl(std::move(url)),
      mRoomId(std::move(room)),
      mUsername(std::move(username)),
      mPassword(std::move(password)),
      mWsConfig(std::move(wsConfig)) {
    // Server 使用该不透明 token 注册和路由。
    // 用户输入的 room id 保留在本地，并作为 PKI 签名绑定对象。
    mRoomToken = chat::secure_relay::deriveRoomToken(mRoomId, mPassword);
    // X25519 密钥对按会话生成。公钥会在 join_room 中被签名；
    // 私钥留在本地，用于解封装 Host 分发的群密钥。
    mMemberKeys = chat::secure_relay::generateMemberKeyPair();
    chat::websocket_config::applyClientTlsFromEnvironment(mWsConfig);
    // Host/Client 启动必须具备 PKI 配置。
    // 环境变量缺失会在这里失败，且不会发送任何入房消息。
    mIdentity = chat::identity_pki::loadFromEnvironment();
}

ClientSessionCore::~ClientSessionCore() {
    stopSignalingWorker();
}

// 替换该会话使用的 UI/CLI 事件回调。
void ClientSessionCore::setCallbacks(ChatCallbacks callbacks) {
    mCallbacks = std::move(callbacks);
}

// 打开信令 WebSocket，并请求加入已配置房间。
void ClientSessionCore::start() {
    mSignalingWorkerStopping.store(false);
    if (!mSignalingThread.joinable()) {
        mSignalingThread = std::thread([this]() {
            signalingWorkerLoop();
        });
    }

    mWs = std::make_shared<rtc::WebSocket>(mWsConfig);

    mWs->onOpen([this]() {
        chatEmit(mCallbacks.onStatus, "Signaling connected");
        json msg = {
            {"type", "join_room"},
            {"roomId", mRoomToken},
            {"username", mUsername},
            {"password", mRoomToken},
            {"publicKey", mMemberKeys.publicKey}
        };
        chatEmit(mCallbacks.onStatus, "PKI identity ready: " + mIdentity.fingerprint());
        // 对 roomId、username 和临时 X25519 公钥签名，
        // 使 Host 在给该 Client 发送房间群密钥前能检测替换攻击。
        msg["identity"] = mIdentity.signJoinRoom(mRoomId, mUsername, mMemberKeys.publicKey);
        mWs->send(msg.dump());
        // 房间密码只保留到完成入房认证为止。
        std::fill(mPassword.begin(), mPassword.end(), '\0');
        mPassword.clear();
    });

    mWs->onMessage([this](rtc::message_variant data) {
        enqueueSignalingMessage(rtcMessageToString(data));
    });

    mWs->onClosed([this]() {
        chatEmit(mCallbacks.onStatus, "Signaling closed");
        if (!mSawErrorFrame.load() && !mStopped.load() && !mShutdownRequested.load()) {
            // WebSocket close 可能先于对端试图发送的 error JSON 帧到达。
            // 报告当前准入阶段，避免 WinUI 把所有静默关闭都误判为构建版本不匹配。
            const auto message = mJoinedRoom.load()
                ? "Signaling connection ended unexpectedly; the Server or Host may have stopped, or the network closed the socket"
                : "Signaling closed before room join completed; check Server URL, room/password, Host status, PKI files, and rebuild all components if one executable was updated";
            chatEmit(mCallbacks.onError, message);
        }
        requestShutdown("Signaling connection ended");
    });

    mWs->onError([this](std::string error) {
        chatEmit(mCallbacks.onError, "Signaling error: " + error);
        requestShutdown("Signaling failed");
    });

    mWs->open(mWsUrl);
}

// 关闭信令 WebSocket 和本地传输状态。
void ClientSessionCore::stop() {
    mStopped.store(true);
    if (mWs && !mWs->isClosed()) {
        mWs->close();
    }
    stopSignalingWorker();
    requestShutdown("Stopped");
}

// 返回外层 CLI/API 循环是否应停止轮询该会话。
bool ClientSessionCore::shouldStop() const {
    if (mStopped.load()) return true;
    if (mShutdownRequested.load()) return true;
    return mWs && mWs->isClosed();
}

// 解析一行 Client 输入，并发送对应的聊天、命令或附件。
void ClientSessionCore::sendLine(const std::string& line) {
    std::string directTarget;
    std::string directBody;
    if (parseDirectPrefix(line, directTarget, directBody)) {
        sendLineTo(directTarget, directBody);
        return;
    }

    if (line.empty()) return;
    if (mClientId.empty()) {
        chatEmit(mCallbacks.onStatus, "Client identity is not ready yet");
        return;
    }

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

    try {
        Message msg = parseInput(line);
        msg.payload["actorId"] = mClientId;
        msg.payload["actorKind"] = chat::protocol::ClientActorKind;
        msg.payload["displayName"] = mUsername;
        if (!chat::secure_relay::hasUsableGroupKey(mGroupKey)) {
            chatEmit(mCallbacks.onStatus, "Waiting for room group key");
            return;
        }
        if (!mWs || mWs->isClosed()) {
            chatEmit(mCallbacks.onStatus, "Signaling channel is not open yet");
            return;
        }
        const auto envelope = chat::secure_relay::encryptMessageWithGroupKey(
            msg,
            mRoomToken,
            mClientId,
            mUsername,
            chat::protocol::ClientActorKind,
            "",
            mGroupKey);
        mWs->send(envelope.dump());
        chatEmit(mCallbacks.onMessage, msg.toJson());
    }
    catch (const std::exception& e) {
        chatEmit(mCallbacks.onError, std::string("Input failed: ") + e.what());
    }
}

void ClientSessionCore::sendLineTo(const std::string& target, const std::string& line) {
    const auto targetName = trimCopy(target);
    const auto targetId = resolveMemberId(targetName);
    if (targetName.empty()) {
        sendLine(line);
        return;
    }
    if (targetId.empty()) {
        chatEmit(mCallbacks.onError, "Target member name not found: " + targetName);
        return;
    }
    if (targetId == mClientId) {
        chatEmit(mCallbacks.onError, "Cannot send a private message to yourself");
        return;
    }
    if (line.empty()) {
        chatEmit(mCallbacks.onError, "Private message body is empty");
        return;
    }
    if (line.rfind("/image ", 0) == 0 || line.rfind("/img ", 0) == 0) {
        sendImageTo(targetName, trimCopy(line.substr(line.find(' ') + 1)));
        return;
    }
    if (line.rfind("/file ", 0) == 0) {
        sendTextFileTo(targetName, trimCopy(line.substr(line.find(' ') + 1)));
        return;
    }
    if (line.rfind("/voice ", 0) == 0) {
        sendVoiceTo(targetName, trimCopy(line.substr(line.find(' ') + 1)));
        return;
    }

    try {
        Message msg = parseInput(line);
        msg.payload["actorId"] = mClientId;
        msg.payload["actorKind"] = chat::protocol::ClientActorKind;
        msg.payload["displayName"] = mUsername;
        std::string targetName = targetId;
        {
            std::lock_guard<std::mutex> lock(mMembersMutex);
            auto it = mMemberNamesById.find(targetId);
            if (it != mMemberNamesById.end()) targetName = it->second;
        }
        markPrivateTarget(msg, targetId, targetName);
        if (sendRelayMessage(msg, mClientId, mUsername, chat::protocol::ClientActorKind, targetId)) {
            chatEmit(mCallbacks.onMessage, msg.toJson());
        }
    }
    catch (const std::exception& e) {
        chatEmit(mCallbacks.onError, std::string("Input failed: ") + e.what());
    }
}

Message ClientSessionCore::parseInput(const std::string& line) {
    // Client 文本消息使用 Server 分配的 client id 作为协议发送者，
    // 并把人类可读显示名保存在载荷元数据中。
    return makeTextMessage(mClientId, line);
}

std::string ClientSessionCore::resolveMemberId(const std::string& token) {
    // 私发中继需要具体成员 id，但 UI/CLI 目标只使用显示名。
    // 这样可以避免与 "host" 等固定协议 id 冲突。
    if (token.empty()) return "";

    std::lock_guard<std::mutex> lock(mMembersMutex);
    for (const auto& [id, name] : mMemberNamesById) {
        if (name == token) return id;
    }
    return "";
}

bool ClientSessionCore::rememberVerifiedMemberIdentity(
    const std::string& memberId,
    const std::string& displayName,
    const std::string& publicKey,
    const json& identity,
    const std::string& advertisedFingerprint,
    const std::string& source) {
    // Server/Host 可以报告成员列表，但二者都不被视为密钥权威。
    // 成员证书签名必须绑定 roomId、displayName 和 X25519 公钥后，
    // 双方私发才能使用该成员信息。
    if (memberId.empty() || publicKey.empty() || !identity.is_object()) return false;
    try {
        const auto verified = mIdentity.verifyJoinRoom(mRoomId, displayName, publicKey, identity);
        if (!advertisedFingerprint.empty() && advertisedFingerprint != verified.fingerprint) {
            throw std::runtime_error("member identity fingerprint mismatch");
        }

        {
            std::lock_guard<std::mutex> lock(mMembersMutex);
            const auto existingPublicKey = mMemberPublicKeysById.find(memberId);
            if (existingPublicKey != mMemberPublicKeysById.end() && existingPublicKey->second != publicKey) {
                throw std::runtime_error("member public key changed for existing id");
            }
            const auto existingFingerprint = mMemberFingerprintsById.find(memberId);
            if (existingFingerprint != mMemberFingerprintsById.end() &&
                existingFingerprint->second != verified.fingerprint) {
                throw std::runtime_error("member fingerprint changed for existing id");
            }
            mMemberNamesById[memberId] = displayName.empty() ? memberId : displayName;
            mMemberPublicKeysById[memberId] = publicKey;
            mMemberFingerprintsById[memberId] = verified.fingerprint;
        }

        chatEmit(
            mCallbacks.onStatus,
            "PKI member verified: " + (displayName.empty() ? memberId : displayName) +
                " / " + memberId + " / " + verified.fingerprint);
        return true;
    }
    catch (const std::exception& e) {
        chatEmit(
            mCallbacks.onError,
            "Member identity rejected from " + source + ": " +
                (displayName.empty() ? memberId : displayName) + ": " + e.what());
        return false;
    }
}

void ClientSessionCore::sendGkaContribution(std::uint64_t epoch) {
    if (mClientId.empty()) {
        chatEmit(mCallbacks.onStatus, "Client identity is not ready yet");
        return;
    }
    if (!mWs || mWs->isClosed()) {
        chatEmit(mCallbacks.onStatus, "Signaling channel is not open yet");
        return;
    }

    std::string hostPublicKey;
    {
        std::lock_guard<std::mutex> lock(mMembersMutex);
        const auto it = mMemberPublicKeysById.find(chat::protocol::HostActorId);
        if (it != mMemberPublicKeysById.end()) hostPublicKey = it->second;
    }
    if (hostPublicKey.empty()) {
        chatEmit(
            mCallbacks.onError,
            "Cannot send GKA contribution before Host identity is verified; check Client trust store and Host certificate chain");
        requestShutdown("Host identity verification failed");
        return;
    }

    const auto contribution = chat::secure_relay::generateGroupContribution();
    json item = {
        {"memberId", mClientId},
        {"username", mUsername},
        {"publicKey", mMemberKeys.publicKey},
        {"contribution", contribution},
        {"fingerprint", mIdentity.fingerprint()}
    };
    item["identity"] = mIdentity.signGkaContribution(
        mRoomId,
        epoch,
        mClientId,
        mUsername,
        mMemberKeys.publicKey,
        contribution);

    auto envelope = chat::secure_relay::encryptGkaContributionForHost(
        item,
        mRoomToken,
        mClientId,
        hostPublicKey,
        epoch);
    const auto serialized = envelope.dump();
    const auto queued = mWs->send(serialized);
    chatEmit(
        mCallbacks.onStatus,
        std::string("GKA contribution ") + (queued ? "sent" : "send failed") +
            ": epoch " + std::to_string(epoch) +
            ", bytes " + std::to_string(serialized.size()));
}

bool ClientSessionCore::installGroupState(const json& groupState, std::uint64_t epoch) {
    if (groupState.value("version", 0) != 3 ||
        groupState.value("roomId", "") != mRoomToken ||
        groupState.value("epoch", 0ULL) != epoch ||
        !groupState.contains("contributions") ||
        !groupState["contributions"].is_array()) {
        chatEmit(mCallbacks.onError, "Invalid GKA group state");
        return false;
    }

    bool sawSelf = false;
    bool sawHost = false;
    for (const auto& item : groupState["contributions"]) {
        if (!item.is_object()) {
            chatEmit(mCallbacks.onError, "Invalid GKA contribution object");
            return false;
        }
        const auto memberId = item.value("memberId", "");
        const auto username = item.value("username", memberId);
        const auto publicKey = item.value("publicKey", "");
        const auto contribution = item.value("contribution", "");
        const auto advertisedFingerprint = item.value("fingerprint", "");
        const auto identity = item.find("identity");
        if (memberId.empty() || publicKey.empty() || contribution.empty() ||
            identity == item.end() || !identity->is_object()) {
            chatEmit(mCallbacks.onError, "GKA contribution is missing required fields");
            return false;
        }

        try {
            const auto verified = mIdentity.verifyGkaContribution(
                mRoomId,
                epoch,
                memberId,
                username,
                publicKey,
                contribution,
                *identity);
            if (!advertisedFingerprint.empty() && advertisedFingerprint != verified.fingerprint) {
                throw std::runtime_error("GKA contribution fingerprint mismatch");
            }
            if (memberId == mClientId) {
                sawSelf = true;
                if (publicKey != mMemberKeys.publicKey || verified.fingerprint != mIdentity.fingerprint()) {
                    throw std::runtime_error("GKA state does not include this Client identity");
                }
            }
            if (memberId == chat::protocol::HostActorId) {
                sawHost = true;
            }
            {
                std::lock_guard<std::mutex> lock(mMembersMutex);
                const auto existingPublicKey = mMemberPublicKeysById.find(memberId);
                if (existingPublicKey != mMemberPublicKeysById.end() && existingPublicKey->second != publicKey) {
                    throw std::runtime_error("member public key changed inside GKA state");
                }
                const auto existingFingerprint = mMemberFingerprintsById.find(memberId);
                if (existingFingerprint != mMemberFingerprintsById.end() &&
                    existingFingerprint->second != verified.fingerprint) {
                    throw std::runtime_error("member fingerprint changed inside GKA state");
                }
                mMemberNamesById[memberId] = username.empty() ? memberId : username;
                mMemberPublicKeysById[memberId] = publicKey;
                mMemberFingerprintsById[memberId] = verified.fingerprint;
            }
        }
        catch (const std::exception& e) {
            chatEmit(mCallbacks.onError, "GKA contribution rejected: " + memberId + ": " + e.what());
            return false;
        }
    }

    if (!sawSelf || !sawHost) {
        chatEmit(mCallbacks.onError, "GKA state is missing self or Host contribution");
        return false;
    }

    auto groupKey = chat::secure_relay::deriveGroupKeyFromContributions(
        mRoomToken,
        epoch,
        groupState["contributions"]);
    if (!chat::secure_relay::hasUsableGroupKey(groupKey)) {
        chatEmit(mCallbacks.onError, "Derived GKA group key has invalid size");
        return false;
    }
    mGroupKey = std::move(groupKey);
    return true;
}

void ClientSessionCore::handleRelayMessage(const Message& msg) {
    // 所有应用数据都在 AES-GCM 解密后到达。
    // 文本直接渲染；附件元数据创建接收槽位；分片追加字节。
    if (msg.type == "member_identity") {
        const auto relaySenderId = msg.payload.value("relaySenderId", "");
        const auto relaySenderKind = msg.payload.value("relaySenderKind", "");
        if (relaySenderId == chat::protocol::HostActorId &&
            relaySenderKind == chat::protocol::HostActorKind) {
            const auto memberId = msg.payload.value("memberId", "");
            const auto displayName = msg.payload.value("displayName", memberId);
            const auto fingerprint = msg.payload.value("fingerprint", "");
            const auto publicKey = msg.payload.value("publicKey", "");
            const auto identity = msg.payload.find("identity");
            if (!memberId.empty() && !publicKey.empty() && identity != msg.payload.end() && identity->is_object()) {
                // Host 公告是加密控制消息，但 Client 仍会重新验证其中的成员签名，
                // 并拒绝与此前已验证 Server 成员列表冲突的内容。
                rememberVerifiedMemberIdentity(memberId, displayName, publicKey, *identity, fingerprint, "member_identity");
            }
        }
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

void ClientSessionCore::handleRelayBinaryChunk(const std::string& senderKey, const Message& msg) {
    // 二进制分片到达该函数前仍位于加密中继 envelope 内。
    // 该函数只重组已经解密的分片。
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

// 以加密元数据加后续加密中继分片的形式发送图片。
bool ClientSessionCore::sendImage(const std::string& filePath) {
    return sendImageTo("", filePath);
}

bool ClientSessionCore::sendImageTo(const std::string& target, const std::string& filePath) {
    const auto targetName = trimCopy(target);
    const auto targetId = resolveMemberId(targetName);
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

// 以加密元数据加后续加密中继分片的形式发送文本资料。
bool ClientSessionCore::sendTextFile(const std::string& filePath) {
    return sendTextFileTo("", filePath);
}

bool ClientSessionCore::sendTextFileTo(const std::string& target, const std::string& filePath) {
    const auto targetName = trimCopy(target);
    const auto targetId = resolveMemberId(targetName);
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

// 以加密元数据加后续加密中继分片的形式发送短 WAV 语音。
bool ClientSessionCore::sendVoice(const std::string& filePath) {
    return sendVoiceTo("", filePath);
}

bool ClientSessionCore::sendVoiceTo(const std::string& target, const std::string& filePath) {
    const auto targetName = trimCopy(target);
    const auto targetId = resolveMemberId(targetName);
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

bool ClientSessionCore::sendRelayMessage(
    const Message& msg,
    const std::string& senderId,
    const std::string& senderName,
    const std::string& senderKind,
    const std::string& targetId) {
    // 房间群密钥安装后，所有文本和附件消息都走该路径。
    // targetId 保留在密文中；Server 只负责广播。
    if (!chat::secure_relay::hasUsableGroupKey(mGroupKey)) {
        chatEmit(mCallbacks.onStatus, "Waiting for room group key");
        return false;
    }
    if (!mWs || mWs->isClosed()) {
        chatEmit(mCallbacks.onStatus, "Signaling channel is not open yet");
        return false;
    }

    Message outbound = msg;
    if (!targetId.empty()) {
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

Message ClientSessionCore::wrapPairwiseForTarget(const Message& msg, const std::string& targetId) {
    // 私发消息采用失败即关闭策略：如果尚未通过已验证 member_identity
    // 获得目标的 PKI 绑定 X25519 公钥，就不回退到仅依赖房间群密钥的私发。
    if (targetId == mClientId) throw std::runtime_error("cannot send a private message to yourself");

    std::string targetPublicKey;
    std::string targetFingerprint;
    {
        std::lock_guard<std::mutex> lock(mMembersMutex);
        const auto publicKey = mMemberPublicKeysById.find(targetId);
        const auto fingerprint = mMemberFingerprintsById.find(targetId);
        if (publicKey != mMemberPublicKeysById.end()) targetPublicKey = publicKey->second;
        if (fingerprint != mMemberFingerprintsById.end()) targetFingerprint = fingerprint->second;
    }
    if (targetPublicKey.empty() || targetFingerprint.empty()) {
        throw std::runtime_error("target pairwise identity is not verified yet");
    }

    return chat::secure_relay::encryptMessageForPairwise(
        msg,
        mRoomToken,
        mClientId,
        targetId,
        targetPublicKey,
        mIdentity.fingerprint(),
        targetFingerprint);
}

Message ClientSessionCore::decryptPairwiseFromMember(const Message& msg) {
    // 外层 encrypted_relay 证明房间成员资格和投递目标。
    // 内层双方私发加密保证只有预期目标能读取私发载荷，
    // 即使其他成员也拥有房间群密钥。
    const auto senderId = msg.payload.value("relaySenderId", "");
    if (senderId.empty() || senderId == mClientId) {
        throw std::runtime_error("invalid pairwise sender");
    }

    std::string senderFingerprint;
    {
        std::lock_guard<std::mutex> lock(mMembersMutex);
        const auto it = mMemberFingerprintsById.find(senderId);
        if (it != mMemberFingerprintsById.end()) senderFingerprint = it->second;
    }
    if (senderFingerprint.empty()) {
        throw std::runtime_error("sender pairwise identity is not verified");
    }

    auto inner = chat::secure_relay::decryptMessageFromPairwise(
        msg,
        mRoomToken,
        senderId,
        mClientId,
        mMemberKeys.privateKey,
        senderFingerprint,
        mIdentity.fingerprint());
    inner.payload["relaySenderId"] = senderId;
    inner.payload["relaySenderKind"] = msg.payload.value("relaySenderKind", "");
    inner.payload["relaySenderName"] = msg.payload.value("relaySenderName", "");
    inner.payload["relayTargetId"] = mClientId;
    return inner;
}

bool ClientSessionCore::rememberRelayEnvelope(const json& envelope) {
    // 恶意 Server 可以重放旧的外层 envelope。
    // AES-GCM 能认证密文，但新鲜性由接收端负责，因此每个会话维护有限 nonce/tag 缓存。
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

bool ClientSessionCore::sendAttachmentRelay(
    const std::string& filePath,
    attachment::Kind kind,
    const std::string& metaType,
    const std::string& binaryType,
    const std::string& mime,
    const std::string& targetId) {
    // 附件以一条加密元数据消息加后续加密分片发送。
    // 房间广播时 targetId 为空；私发时通过同一 Server 中继设置目标。
    if (mClientId.empty()) {
        chatEmit(mCallbacks.onStatus, "Client identity is not ready yet");
        return false;
    }
    if (targetId == mClientId) {
        chatEmit(mCallbacks.onError, "Cannot send a private attachment to yourself");
        return false;
    }

    const auto bytes = attachment::readFileBytes(filePath, kind);
    std::string targetName = targetId;
    {
        std::lock_guard<std::mutex> lock(mMembersMutex);
        auto it = mMemberNamesById.find(targetId);
        if (it != mMemberNamesById.end()) targetName = it->second;
    }
    Message meta = attachment::makeBinaryMeta(metaType, mUsername, filePath, mime, bytes.size());
    // actor 元数据让 UI 在解密后区分发送者身份，
    // 同时中继元数据仍绑定到 Server 侧连接状态。
    meta.payload["actorId"] = mClientId;
    meta.payload["actorKind"] = chat::protocol::ClientActorKind;
    meta.payload["displayName"] = mUsername;
    markPrivateTarget(meta, targetId, targetName);
    if (!sendRelayMessage(meta, mClientId, mUsername, chat::protocol::ClientActorKind, targetId)) {
        return false;
    }

    const auto transferId = attachment::transferIdFromMessage(meta);
    for (std::size_t offset = 0; offset < bytes.size(); offset += attachment::RelayChunkBytes) {
        const auto chunkSize = (std::min)(attachment::RelayChunkBytes, bytes.size() - offset);
        Message chunk;
        // 每个分片都是独立的应用 Message，并由 sendRelayMessage 分别加密，
        // 因此大附件不会以明文传输。
        chunk.type = binaryType;
        chunk.from = mUsername;
        chunk.name = meta.name;
        chunk.mime = meta.mime;
        chunk.data = attachment::base64Encode(bytes, offset, chunkSize);
        chunk.payload = {
            {"transferId", transferId},
            {"name", meta.name},
            {"mime", meta.mime},
            {"size", static_cast<int>(bytes.size())},
            {"offset", static_cast<int>(offset)},
            {"chunkSize", static_cast<int>(chunkSize)},
            {"actorId", mClientId},
            {"actorKind", chat::protocol::ClientActorKind},
            {"displayName", mUsername}
        };
        markPrivateTarget(chunk, targetId, targetName);
        if (!sendRelayMessage(chunk, mClientId, mUsername, chat::protocol::ClientActorKind, targetId)) {
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

// 幂等地标记 Client 会话已关闭，并释放传输对象。
void ClientSessionCore::requestShutdown(const std::string& reason) {
    if (!mShutdownRequested.exchange(true)) {
        if (mWs && !mWs->isClosed()) {
            mWs->close();
        }
        mSignalingWorkerStopping.store(true);
        mSignalingQueueCv.notify_all();
        chatEmit(mCallbacks.onStatus, reason);
    }
}

void ClientSessionCore::enqueueSignalingMessage(std::string payload) {
    {
        std::lock_guard<std::mutex> lock(mSignalingQueueMutex);
        if (mSignalingWorkerStopping.load()) return;
        mSignalingQueue.push_back(std::move(payload));
    }
    mSignalingQueueCv.notify_one();
}

void ClientSessionCore::signalingWorkerLoop() {
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

        // JSON 解析、PKI 证书验证和 GKA contribution 生成可能相对耗时。
        // 将这些工作移出 WSS 回调线程，可避免应用仍在认证上一帧时
        // libdatachannel 关闭 TLS socket。
        handleSignalingMessage(payload);
    }
}

void ClientSessionCore::stopSignalingWorker() {
    mSignalingWorkerStopping.store(true);
    mSignalingQueueCv.notify_all();
    if (mSignalingThread.joinable() &&
        mSignalingThread.get_id() != std::this_thread::get_id()) {
        mSignalingThread.join();
    }
}

// 处理来自 Server WebSocket 的房间控制消息和加密中继消息。
void ClientSessionCore::handleSignalingMessage(const std::string& s) {
    if (mStopped.load() || mShutdownRequested.load()) return;

    try {
        // 信令和中继消息都是不可信网络输入。
        // 读取字段前，先按显式预算和对象要求解析。
        auto j = chat::protocol::parseJsonObjectWithBudget(
            s,
            chat::protocol::MaxSignalingMessageBytes,
            "signaling message");
        std::string type = j.value("type", "");

        if (type == "joined") {
            // Server 分配的 clientId 会成为后续私发中继和 group-key envelope 的路由 id。
            mClientId = j.value("clientId", "");
            mJoinedRoom.store(true);
            // 后续签名 GKA contribution 使用 Server 接受的显示名。
            // Host 会用成员表验证该字段，本地副本保持同步可避免不必要的 GKA 拒绝。
            const auto acceptedUsername = j.value("username", mUsername);
            if (!acceptedUsername.empty()) {
                mUsername = acceptedUsername;
            }
            const auto hostPublicKey = j.value("hostPublicKey", "");
            const auto hostUsername = j.value("hostUsername", chat::protocol::HostActorId);
            const auto hostIdentity = j.find("hostIdentity");
            if (hostPublicKey.empty() || hostIdentity == j.end() || !hostIdentity->is_object()) {
                // Client 只有认证 Host 签名的 identity/publicKey 绑定后才能参与 GKA。
                // 此处字段缺失通常表示仍在运行旧 Server 构建。
                chatEmit(
                    mCallbacks.onError,
                    "Host identity is missing from join response; check that Server, Host, and Client are the same build");
                requestShutdown("Host identity verification failed");
                return;
            }
            if (!rememberVerifiedMemberIdentity(
                    chat::protocol::HostActorId,
                    hostUsername,
                    hostPublicKey,
                    *hostIdentity,
                    "",
                    "joined")) {
                // 验证失败是终止性错误。继续保持连接只会导致 GKA 超时，
                // 并掩盖真正的 PKI 根因。
                chatEmit(
                    mCallbacks.onError,
                    "Host identity verification failed; check Client trust store, Host certificate chain, room name, and rebuild all components if one executable was updated");
                requestShutdown("Host identity verification failed");
                return;
            }
            chatEmit(mCallbacks.onLog, "own_actor_id " + mClientId);
            chatEmit(
                mCallbacks.onStatus,
                "Joined room " + mRoomId + " as " + mUsername + " (" + mClientId + ")");
            chatEmit(mCallbacks.onStatus, "Waiting for room group key");
        }
        else if (type == "room_members") {
            // 保存最新成员 name/id 映射，用于解析 To: name 输入。
            // 如果 Server 包含已签名成员 identity，离开 mutex 后再验证，
            // 避免 OpenSSL 工作阻塞 UI/成员表读取。
            std::ostringstream members;
            bool first = true;
            std::vector<json> identityCandidates;
            std::unordered_set<std::string> currentMemberIds;
            {
                std::lock_guard<std::mutex> lock(mMembersMutex);
                mMemberNamesById.clear();
                for (const auto& member : j.value("memberInfos", json::array())) {
                    if (!member.is_object()) continue;
                    const auto id = member.value("id", "");
                    const auto username = member.value("username", id);
                    if (!id.empty()) {
                        mMemberNamesById[id] = username;
                        currentMemberIds.insert(id);
                        if (member.contains("publicKey") && member.contains("identity")) {
                            identityCandidates.push_back(member);
                        }
                    }
                    // 发出 name/id，使 UI Client 不解析原始信令 JSON
                    // 也能保留内部 PKI 映射。
                    if (!first) members << "; ";
                    members << username << " / " << id;
                    first = false;
                }
                for (auto it = mMemberPublicKeysById.begin(); it != mMemberPublicKeysById.end();) {
                    if (it->first != chat::protocol::HostActorId && currentMemberIds.find(it->first) == currentMemberIds.end()) {
                        it = mMemberPublicKeysById.erase(it);
                    }
                    else {
                        ++it;
                    }
                }
                for (auto it = mMemberFingerprintsById.begin(); it != mMemberFingerprintsById.end();) {
                    if (it->first != chat::protocol::HostActorId && currentMemberIds.find(it->first) == currentMemberIds.end()) {
                        it = mMemberFingerprintsById.erase(it);
                    }
                    else {
                        ++it;
                    }
                }
            }
            for (const auto& member : identityCandidates) {
                const auto id = member.value("id", "");
                if (id != chat::protocol::HostActorId) {
                    // 非 Host 成员身份会在 GKA epoch 提交后，
                    // 通过加密 member_identity 控制消息再次公告。
                    // 延后处理可让 room_members 保持轻量，
                    // 使新加入 Client 能在 Host 侧 contribution 截止前响应 gka_request。
                    continue;
                }
                {
                    std::lock_guard<std::mutex> lock(mMembersMutex);
                    if (mMemberPublicKeysById.find(id) != mMemberPublicKeysById.end()) {
                        continue;
                    }
                }
                const auto username = member.value("username", id);
                const auto publicKey = member.value("publicKey", "");
                const auto identity = member.find("identity");
                if (identity != member.end() && identity->is_object()) {
                    rememberVerifiedMemberIdentity(id, username, publicKey, *identity, "", "room_members");
                }
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
        else if (type == chat::secure_relay::GroupKeyType) {
            const auto verified = mIdentity.verifyGroupKeyEnvelope(j);
            std::string hostName = "Host";
            {
                std::lock_guard<std::mutex> lock(mMembersMutex);
                const auto host = mMemberNamesById.find(chat::protocol::HostActorId);
                if (host != mMemberNamesById.end() && !host->second.empty()) {
                    hostName = host->second;
                }
                // group_key 上的 Host 签名会在 member_identity 广播到达前认证 Host 身份。
                // 立即保存指纹，使来自 Host 的 pairwise 私发消息可以被打开。
                mMemberFingerprintsById[chat::protocol::HostActorId] = verified.fingerprint;
                if (host == mMemberNamesById.end()) {
                    mMemberNamesById[chat::protocol::HostActorId] = hostName;
                }
            }
            chatEmit(
                mCallbacks.onStatus,
                std::string("PKI member verified: ") + hostName + " / " +
                    chat::protocol::HostActorId + " / " + verified.fingerprint);
            const auto epoch = j.value("epoch", 0ULL);
            if (epoch <= mGroupKeyEpoch) {
                chatEmit(mCallbacks.onError, "Dropped replayed or stale room group key");
                return;
            }
            // 安装密钥前会检查 epoch，因此重放旧 group_key 无法让 Client 回滚到旧 K_G。
            // 解密后的 group state 会先被验证，再在本地派生 K_G。
            const auto groupState = chat::secure_relay::decryptGroupStateForMember(
                j,
                mRoomToken,
                mClientId,
                mMemberKeys.privateKey);
            if (!installGroupState(groupState, epoch)) return;
            mGroupKeyEpoch = epoch;
            chatEmit(mCallbacks.onStatus, "Room group key ready");
        }
        else if (type == chat::secure_relay::GkaRequestType) {
            const auto epoch = j.value("epoch", 0ULL);
            const auto requestRoom = j.value("roomId", "");
            chatEmit(
                mCallbacks.onStatus,
                "GKA request received: epoch " + std::to_string(epoch) +
                    (requestRoom == mRoomToken ? " (room matched)" : " (room mismatch)"));
            if (requestRoom != mRoomToken) {
                chatEmit(mCallbacks.onError, "Dropped GKA request for another room");
                return;
            }
            if (epoch <= mGroupKeyEpoch) {
                chatEmit(mCallbacks.onError, "Dropped stale GKA request");
                return;
            }
            sendGkaContribution(epoch);
        }
        else if (type == chat::secure_relay::EnvelopeType) {
            if (!chat::secure_relay::hasUsableGroupKey(mGroupKey)) {
                chatEmit(mCallbacks.onError, "Encrypted relay received before room group key");
                return;
            }
            if (!rememberRelayEnvelope(j)) return;
            auto msg = chat::secure_relay::decryptMessageWithGroupKey(j, mRoomToken, mGroupKey);
            const auto relayTargetId = msg.payload.value("relayTargetId", "");
            if (!relayTargetId.empty() && relayTargetId != mClientId) {
                // 投递错误的私发中继会在打开内层双方私发加密前被忽略。
                // 该路径保持静默，使非目标成员无法得知刚刚发生过私发消息。
                return;
            }
            if (msg.type == chat::secure_relay::PairwisePrivateType) {
                try {
                    msg = decryptPairwiseFromMember(msg);
                }
                catch (const std::exception& e) {
                    chatEmit(mCallbacks.onError, std::string("Pairwise private receive failed: ") + e.what());
                    return;
                }
            }
            handleRelayMessage(msg);
        }
        else if (type == "moderation") {
            // Server 转发的管理通知。它不是终止性错误；
            // Host 仍是请求状态变化的权威。
            chatEmit(mCallbacks.onStatus, j.value("message", "moderation state changed"));
        }
        else if (type == "error") {
            mSawErrorFrame.store(true);
            const std::string message = j.value("message", "unknown");
            if (message == "host disconnected") {
                requestShutdown("Session stopped");
            }
            else if (message == "invalid username or password" ||
                     message == "invalid room password" ||
                     message == "invalid room or username" ||
                     message == "room is full" ||
                     message == "room not found" ||
                     message == "missing roomId" ||
                     message == "missing room password") {
                chatEmit(mCallbacks.onError, "Signaling server error: " + message);
                requestShutdown(message);
            }
            else if (message == "username already in room") {
                chatEmit(mCallbacks.onError, "Signaling server error: " + message);
                requestShutdown("Username already in room");
            }
            else if (message == "member is silenced") {
                chatEmit(mCallbacks.onError, "Signaling server error: " + message);
            }
            else if (message == "client public key is missing" ||
                     message == "client identity verification failed" ||
                     message == "member certificate is banned" ||
                     message == "GKA contribution timeout" ||
                     message == "member evicted by host") {
                // 这些错误是 Host 决策，由 Server 在关闭该 Client socket 前转发。
                // 将其视为终止性错误，使 UI 显示真实原因，
                // 而不是只显示 "Signaling connection ended"。
                chatEmit(mCallbacks.onError, "Host rejected client: " + message);
                requestShutdown("Host rejected client: " + message);
            }
            else {
                // 非准入阶段的中继错误不被信任为终止性错误。
                // 恶意 Server 仍可关闭 WebSocket，但伪造的普通错误不应让 Client 主动离开房间。
                chatEmit(mCallbacks.onError, "Signaling server error: " + message);
            }
        }
    }
    catch (const std::exception& e) {
        chatEmit(mCallbacks.onError, std::string("Bad signaling message: ") + e.what());
    }
}
