// Host 会话实现。它创建房间、验证 Client 的 PKI 身份，
// 分发房间群密钥，并处理加密中继消息。
#include "host_session_core.hpp"

#include "attachment_transfer.hpp"
#include "cert_generation.hpp"
#include "cert_utils.hpp"
#include "forum_board.hpp"
#include "relay_pool.hpp"
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
constexpr std::size_t RelayRouteNonceBytes = 16;
constexpr std::size_t ReliableMessageIdBytes = 16;
constexpr std::size_t ReliableCacheLimit = 4096;
constexpr std::size_t EarlyAttachmentChunkLimit = 512;
constexpr int ReliableRetryLimit = 3;
constexpr int RelayRetryBaseSeconds = 5;
constexpr int RelayRetryMaxSeconds = 60;

std::uint64_t unixMillis() {
    const auto now = std::chrono::system_clock::now().time_since_epoch();
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(now).count());
}

bool startsWithIgnoreCase(const std::string& value, const std::string& prefix) {
    if (value.size() < prefix.size()) return false;
    for (std::size_t i = 0; i < prefix.size(); ++i) {
        const auto a = static_cast<unsigned char>(value[i]);
        const auto b = static_cast<unsigned char>(prefix[i]);
        if (std::tolower(a) != std::tolower(b)) return false;
    }
    return true;
}

// 返回去除首尾 ASCII 空白后的副本。
std::string trimCopy(std::string value) {
    const auto first = value.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) return "";
    const auto last = value.find_last_not_of(" \t\r\n");
    return value.substr(first, last - first + 1);
}

std::string earlyAttachmentKey(const std::string& senderKey, const std::string& transferId) {
    return senderKey + "\n" + transferId;
}

std::string membershipEventDigest(json event) {
    event.erase("payloadDigest");
    event.erase("control");
    return chat::cert_utils::sha256Hex(event.dump());
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

std::string pendingJoinDigest(
    const std::string& requestId,
    const std::string& username,
    const std::string& publicKey) {
    // approve_join 签名只绑定固定长度 digest，避免把可变长申请 JSON 直接塞进控制签名。
    return chat::cert_utils::sha256Hex(
        "approve_join\nrequestId=" + requestId +
        "\nusername=" + username +
        "\npublicKey=" + publicKey);
}

std::string pendingRejectDigest(const std::string& requestId, const std::string& reason) {
    return chat::cert_utils::sha256Hex(
        "reject_pending_join\nrequestId=" + requestId +
        "\nreason=" + reason);
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

bool isReliablePayloadType(const std::string& type) {
    attachment::Kind ignored = attachment::Kind::Text;
    return type == "text" ||
        type == chat::secure_relay::PairwisePrivateType ||
        attachmentKindForMeta(type, ignored) ||
        isAttachmentBinaryType(type);
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

std::string normalizeNickname(const std::string& nickname, const std::string& fallbackName) {
    // nickname 只影响显示。非法或为空时回退到用户输入的 base username，
    // 避免普通 UI 暴露内部唯一 username。
    const auto trimmed = trimCopy(nickname);
    if (trimmed.empty() || trimmed.size() > 64) return fallbackName;
    for (const auto ch : trimmed) {
        const auto c = static_cast<unsigned char>(ch);
        if (c < 0x20 || c == 0x7f) return fallbackName;
    }
    return trimmed;
}

std::string relayLabel(const std::string& url) {
    const auto scheme = url.find("://");
    const auto start = scheme == std::string::npos ? 0 : scheme + 3;
    return url.substr(start);
}

std::chrono::seconds relayRetryDelay(int failureStreak) {
    const auto shift = (std::min)(failureStreak, 4);
    return std::chrono::seconds((std::min)(RelayRetryMaxSeconds, RelayRetryBaseSeconds * (1 << shift)));
}

std::string jsonStringField(const json& value, const std::string& name) {
    auto it = value.find(name);
    if (it == value.end()) return "";
    if (it->is_string()) return it->get<std::string>();
    if (it->is_number_integer()) return std::to_string(it->get<long long>());
    if (it->is_number_unsigned()) return std::to_string(it->get<unsigned long long>());
    return "";
}

std::string relayRouteLabelForMessage(const Message& msg) {
    attachment::Kind ignored = attachment::Kind::Text;
    if (isAttachmentBinaryType(msg.type)) return "route:chunk";
    if (attachmentKindForMeta(msg.type, ignored)) return "route:manifest";
    if (msg.type == "text" || msg.type == chat::secure_relay::PairwisePrivateType) return "route:text";
    return "route:notice";
}

std::string relayRouteMaterialForMessage(const Message& msg, const std::string& targetId) {
    std::string material = "securechat-relay-route\n";
    chat::cert_utils::appendCanonicalField(material, "label", relayRouteLabelForMessage(msg));
    chat::cert_utils::appendCanonicalField(material, "type", msg.type);
    chat::cert_utils::appendCanonicalField(material, "from", msg.from);
    chat::cert_utils::appendCanonicalField(material, "targetId", targetId);
    chat::cert_utils::appendCanonicalField(material, "contentHash", chat::cert_utils::sha256Hex(msg.content));
    if (msg.payload.is_object()) {
        chat::cert_utils::appendCanonicalField(material, "routeNonce", jsonStringField(msg.payload, "routeNonce"));
        chat::cert_utils::appendCanonicalField(material, "transferId", jsonStringField(msg.payload, "transferId"));
        chat::cert_utils::appendCanonicalField(material, "chunkIndex", jsonStringField(msg.payload, "chunkIndex"));
        chat::cert_utils::appendCanonicalField(material, "offset", jsonStringField(msg.payload, "offset"));
        chat::cert_utils::appendCanonicalField(material, "fileSize", jsonStringField(msg.payload, "size"));
        chat::cert_utils::appendCanonicalField(material, "actorId", jsonStringField(msg.payload, "actorId"));
        chat::cert_utils::appendCanonicalField(material, "messageId", jsonStringField(msg.payload, "messageId"));
        chat::cert_utils::appendCanonicalField(material, "attempt", jsonStringField(msg.payload, "attempt"));
    }
    return material;
}

void ensureRelayRouteNonce(Message& msg) {
    if (!msg.payload.is_object()) msg.payload = json::object();
    const auto it = msg.payload.find("routeNonce");
    if (it != msg.payload.end() && it->is_string() && !it->get<std::string>().empty()) {
        return;
    }
    const auto nonce = chat::cert_utils::randomBytes(RelayRouteNonceBytes);
    msg.payload["routeNonce"] = chat::cert_utils::base64Encode(nonce);
}

std::string makeReliableMessageId() {
    return chat::cert_utils::base64Encode(chat::cert_utils::randomBytes(ReliableMessageIdBytes));
}

std::string payloadStringField(const Message& msg, const std::string& name) {
    if (!msg.payload.is_object()) return "";
    const auto value = jsonStringField(msg.payload, name);
    return value;
}

std::string reliablePayloadHashFor(Message msg) {
    if (!msg.payload.is_object()) msg.payload = json::object();
    // routeNonce 和 attempt 只影响本次 relay 调度；payloadHash 绑定真正的应用载荷。
    msg.payload.erase("routeNonce");
    msg.payload.erase("payloadHash");
    msg.payload.erase("attempt");
    return chat::cert_utils::sha256Hex(msg.toJson());
}

std::string reliableMissingBitmapFor(const Message& msg) {
    if (!isAttachmentBinaryType(msg.type) || !msg.payload.is_object()) return "";
    const auto chunkIndex = jsonStringField(msg.payload, "chunkIndex");
    const auto chunkCount = jsonStringField(msg.payload, "chunkCount");
    if (chunkIndex.empty() || chunkCount.empty()) return "";
    try {
        const auto index = static_cast<std::size_t>(std::stoull(chunkIndex));
        const auto count = static_cast<std::size_t>(std::stoull(chunkCount));
        if (count == 0 || index >= count || count > 8192) return "";
        std::string bitmap(count, '0');
        bitmap[index] = '1';
        return bitmap;
    }
    catch (...) {
        return "";
    }
}

bool bitmapHasMissing(const std::string& bitmap) {
    return bitmap.find('1') != std::string::npos;
}

std::vector<std::size_t> missingIndicesFromBitmap(const std::string& bitmap) {
    if (bitmap.empty() || bitmap.size() > 8192) return {};
    std::vector<std::size_t> indices;
    for (std::size_t i = 0; i < bitmap.size(); ++i) {
        if (bitmap[i] == '1') {
            indices.push_back(i);
        }
        else if (bitmap[i] != '0') {
            return {};
        }
    }
    return indices;
}

}

HostSessionCore::HostSessionCore(
    std::string wsUrl,
    std::string roomId,
    std::string username,
    std::string baseUsername,
    std::string nickname,
    chat::pki_application::IdentityContext identity,
    std::string roomToken,
    std::string roomDir,
    rtc::WebSocket::Configuration wsConfig)
    : mWsUrl(std::move(wsUrl)),
      mRoomId(std::move(roomId)),
      mBaseUsername(std::move(baseUsername)),
      mUsername(std::move(username)),
      mDisplayName(normalizeNickname(nickname, mBaseUsername.empty() ? mUsername : mBaseUsername)),
      mRoomToken(std::move(roomToken)),
      mRoomDir(std::move(roomDir)),
      mWsConfig(std::move(wsConfig)) {
    // Server 只注册该不透明 token。房间显示名留在本地 PKI 签名语义里。
    if (mRoomToken.empty()) throw std::runtime_error("room instance token is required");
    mRelayUrls = chat::relay_pool::relayUrlsFromRoomDir(mRoomDir);
    if (mRelayUrls.empty()) throw std::runtime_error("relay pool has no usable relay");
    mWsUrl = mRelayUrls.front();
    // K_G 不再由 Host 直接生成。
    // 第一把可用房间密钥在 room_created 后由 epoch-1 contribution 集合派生。
    chat::websocket_config::applyClientTlsFromEnvironment(mWsConfig);
    // Host 身份用于签名 group_key envelope，并验证 Client 入房身份。
    mIdentity = std::move(identity);
    // Host 同样拥有成员 X25519 密钥对，使 Client 能向 Host 发送真正的 pairwise 私信，
    // 而不把房间群密钥作为唯一密钥。
    mMemberKeys = chat::secure_relay::generateMemberKeyPair();
    mPendingTransfers.setRoomContext("host", mUsername, mRoomId, mRoomToken);
    mMessageHistory = std::make_unique<chat::local_message::Store>(
        "host",
        mRoomId,
        mRoomToken,
        mUsername);
}

HostSessionCore::~HostSessionCore() {
    // 析构可能发生在 UI 关闭期间。
    // 关闭传输并 join watchdog，但不再发送面向用户的 "Session stopped" 事件。
    requestStopNoJoin();
    stopSignalingWorker();
    stopGkaTimeoutWorker();
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

    {
        std::lock_guard<std::mutex> lock(mRelayMutex);
        mRelays.assign(mRelayUrls.size(), nullptr);
        mRelayOpen.assign(mRelayUrls.size(), false);
        mRelayRoomReady.assign(mRelayUrls.size(), false);
        mRelayNextRetryAt.assign(mRelayUrls.size(), {});
        mRelayFailureStreak.assign(mRelayUrls.size(), 0);
        mRelayFailureReported.assign(mRelayUrls.size(), false);
    }

    for (std::size_t i = 0; i < mRelayUrls.size(); ++i) {
        connectRelay(i);
    }
}

void HostSessionCore::connectRelay(std::size_t relayIndex) {
    if (relayIndex >= mRelayUrls.size()) return;
    const auto url = mRelayUrls[relayIndex];
    {
        std::lock_guard<std::mutex> lock(mRelayMutex);
        if (relayIndex < mRelays.size() && mRelays[relayIndex] && !mRelays[relayIndex]->isClosed()) return;
    }
    if (!relayRetryAllowed(relayIndex)) return;

    try {
        chat::relay_pool::markRelayStatus(mRoomDir, url, "connecting");
    }
    catch (...) {
    }

    auto ws = std::make_shared<rtc::WebSocket>(mWsConfig);
    {
        std::lock_guard<std::mutex> lock(mRelayMutex);
        if (mRelays.size() < mRelayUrls.size()) mRelays.resize(mRelayUrls.size());
        if (mRelayOpen.size() < mRelayUrls.size()) mRelayOpen.resize(mRelayUrls.size(), false);
        if (mRelayRoomReady.size() < mRelayUrls.size()) mRelayRoomReady.resize(mRelayUrls.size(), false);
        if (mRelayFailureReported.size() < mRelayUrls.size()) mRelayFailureReported.resize(mRelayUrls.size(), false);
        mRelayFailureReported[relayIndex] = false;
        mRelayOpen[relayIndex] = false;
        mRelayRoomReady[relayIndex] = false;
        mRelays[relayIndex] = ws;
        if (!mWs) {
            mWs = ws;
            mWsUrl = url;
        }
    }

    ws->onOpen([this, ws, url, relayIndex]() {
        markRelayHealthy(relayIndex, url);
        chatEmit(mCallbacks.onStatus, "Relay connected: " + relayLabel(url));
        emitRelayStatus();
        if (url == mWsUrl) {
            chatEmit(mCallbacks.onStatus, "PKI identity ready: " + mIdentity.fingerprint());
        }
        json msg = {
            {"type", "create_room"},
            {"roomId", mRoomToken},
            {"username", mUsername},
            {"nickname", mDisplayName},
            {"publicKey", mMemberKeys.publicKey}
        };
        msg["identity"] = mIdentity.signJoinRoom(mRoomId, mUsername, mMemberKeys.publicKey);
        ws->send(msg.dump());
    });

    ws->onMessage([this, url](rtc::message_variant data) {
        enqueueSignalingMessage(rtcMessageToString(data), url);
    });

    ws->onClosed([this, url, relayIndex]() {
        const auto report = markRelayFailure(relayIndex, url, "offline");
        if (report) {
            chatEmit(mCallbacks.onStatus, "Relay closed: " + relayLabel(url));
            emitRelayStatus();
        }
        if (!mStopped.load() && !hasOpenRelay() && !mRoomCreated.load()) {
            chatEmit(
                mCallbacks.onError,
                "All relays closed before room creation completed; check relay pool, room directory, PKI files, and rebuild all components if one executable was updated");
        }
    });

    ws->onError([this, url, relayIndex](std::string error) {
        const auto report = markRelayFailure(relayIndex, url, "offline");
        if (report) {
            chatEmit(mCallbacks.onError, "Relay error: " + relayLabel(url) + ": " + error);
            emitRelayStatus();
        }
    });

    ws->open(url);
}

void HostSessionCore::reconnectClosedRelays() {
    for (std::size_t i = 0; i < mRelayUrls.size(); ++i) {
        bool needsConnect = false;
        {
            std::lock_guard<std::mutex> lock(mRelayMutex);
            needsConnect = i >= mRelays.size() || !mRelays[i] || mRelays[i]->isClosed();
        }
        if (needsConnect && relayRetryAllowed(i)) connectRelay(i);
    }
}

void HostSessionCore::emitRelayStatus() {
    try {
        chatEmit(mCallbacks.onRelayStatus, chat::relay_pool::relayStatusSummaryText(mRoomDir));
    }
    catch (...) {
    }
}

std::string HostSessionCore::relayUrlFor(const std::shared_ptr<rtc::WebSocket>& relay) const {
    std::lock_guard<std::mutex> lock(mRelayMutex);
    for (std::size_t i = 0; i < mRelays.size(); ++i) {
        if (mRelays[i] == relay && i < mRelayUrls.size()) return mRelayUrls[i];
    }
    return {};
}

bool HostSessionCore::relayRetryAllowed(std::size_t relayIndex) const {
    std::lock_guard<std::mutex> lock(mRelayMutex);
    if (relayIndex >= mRelayNextRetryAt.size()) return true;
    return std::chrono::steady_clock::now() >= mRelayNextRetryAt[relayIndex];
}

void HostSessionCore::markRelayHealthy(std::size_t relayIndex, const std::string& url) {
    {
        std::lock_guard<std::mutex> lock(mRelayMutex);
        if (relayIndex >= mRelayFailureStreak.size()) mRelayFailureStreak.resize(mRelayUrls.size(), 0);
        if (relayIndex >= mRelayNextRetryAt.size()) mRelayNextRetryAt.resize(mRelayUrls.size());
        if (relayIndex >= mRelayFailureReported.size()) mRelayFailureReported.resize(mRelayUrls.size(), false);
        if (relayIndex >= mRelayOpen.size()) mRelayOpen.resize(mRelayUrls.size(), false);
        if (relayIndex >= mRelayRoomReady.size()) mRelayRoomReady.resize(mRelayUrls.size(), false);
        mRelayOpen[relayIndex] = true;
        mRelayFailureStreak[relayIndex] = 0;
        mRelayNextRetryAt[relayIndex] = {};
        mRelayFailureReported[relayIndex] = false;
    }
    try {
        chat::relay_pool::markRelayStatus(mRoomDir, url, "healthy");
    }
    catch (...) {
    }
}

bool HostSessionCore::markRelayFailure(std::size_t relayIndex, const std::string& url, const std::string& status) {
    int failures = 1;
    std::chrono::seconds delay = relayRetryDelay(0);
    bool shouldReport = true;
    {
        std::lock_guard<std::mutex> lock(mRelayMutex);
        if (relayIndex >= mRelayFailureStreak.size()) mRelayFailureStreak.resize(mRelayUrls.size(), 0);
        if (relayIndex >= mRelayNextRetryAt.size()) mRelayNextRetryAt.resize(mRelayUrls.size());
        if (relayIndex >= mRelayFailureReported.size()) mRelayFailureReported.resize(mRelayUrls.size(), false);
        if (relayIndex >= mRelayOpen.size()) mRelayOpen.resize(mRelayUrls.size(), false);
        mRelayOpen[relayIndex] = false;
        if (relayIndex >= mRelayRoomReady.size()) mRelayRoomReady.resize(mRelayUrls.size(), false);
        mRelayRoomReady[relayIndex] = false;
        shouldReport = !mRelayFailureReported[relayIndex];
        mRelayFailureReported[relayIndex] = true;
        if (!shouldReport) {
            return false;
        }
        failures = ++mRelayFailureStreak[relayIndex];
        delay = relayRetryDelay(failures - 1);
        mRelayNextRetryAt[relayIndex] = std::chrono::steady_clock::now() + delay;
    }
    try {
        chat::relay_pool::markRelayStatus(mRoomDir, url, status);
    }
    catch (...) {
    }
    chatEmit(
        mCallbacks.onRelayStatus,
        "paused " + relayLabel(url) + " for " + std::to_string(delay.count()) + "s after " + std::to_string(failures) + " failure(s)");
    return true;
}

void HostSessionCore::requestStopNoJoin() {
    mStopped.store(true);
    std::vector<std::shared_ptr<rtc::WebSocket>> relays;
    {
        std::lock_guard<std::mutex> lock(mRelayMutex);
        relays = mRelays;
        if (mWs) relays.push_back(mWs);
    }
    for (const auto& relay : relays) {
        if (relay && !relay->isClosed()) relay->close();
    }
    {
        std::lock_guard<std::mutex> lock(mSignalingQueueMutex);
        mSignalingWorkerStopping.store(true);
        mSignalingQueue.clear();
    }
    mSignalingQueueCv.notify_all();
    requestGkaTimeoutStop();
}

// 关闭所有 Host 持有的传输，并标记会话已停止。
void HostSessionCore::stop() {
    requestStopNoJoin();
    stopSignalingWorker();
    stopGkaTimeoutWorker();
    chatEmit(mCallbacks.onStatus, "Session stopped");
}

void HostSessionCore::closeRoom() {
    // 普通 stop 只表示 Host 本地离线。显式 closeRoom 才请求 Server
    // 销毁当前 room instance，并让所有成员收到 room_closed。
    if (!hasOpenRelay()) {
        chatEmit(mCallbacks.onStatus, "Signaling channel is not open yet");
        return;
    }
    json msg = {
        {"type", "close_room"},
        {"roomId", mRoomToken},
        {"reason", "host closed room"},
        {"epoch", mGroupKeyEpoch}
    };
    const auto payloadDigest = chat::cert_utils::sha256Hex(msg.value("reason", ""));
    msg["payloadDigest"] = payloadDigest;
    msg["control"] = mIdentity.signRoomControl(
        mRoomId,
        mRoomToken,
        "close_room",
        mGroupKeyEpoch,
        payloadDigest);
    const auto sent = sendToAllRelays(msg);
    chatEmit(mCallbacks.onStatus, "Close room requested on relays: " + std::to_string(sent));
}

// 返回外层 CLI/API 循环是否应停止轮询该会话。
bool HostSessionCore::shouldStop() const {
    return mStopped.load();
}

bool HostSessionCore::hasOpenRelay() const {
    std::lock_guard<std::mutex> lock(mRelayMutex);
    for (std::size_t i = 0; i < mRelays.size(); ++i) {
        if (i < mRelayOpen.size() && i < mRelayRoomReady.size() &&
            mRelayOpen[i] && mRelayRoomReady[i] && mRelays[i] && !mRelays[i]->isClosed()) return true;
    }
    return false;
}

std::shared_ptr<rtc::WebSocket> HostSessionCore::chooseRelayForSend(const Message& msg, const std::string& targetId) {
    reconnectClosedRelays();
    std::lock_guard<std::mutex> lock(mRelayMutex);
    struct Candidate {
        std::shared_ptr<rtc::WebSocket> relay;
        std::string url;
    };
    std::vector<Candidate> openRelays;
    openRelays.reserve(mRelays.size());
    for (std::size_t i = 0; i < mRelays.size(); ++i) {
        const auto& relay = mRelays[i];
        if (i < mRelayOpen.size() && i < mRelayRoomReady.size() &&
            mRelayOpen[i] && mRelayRoomReady[i] && relay && !relay->isClosed()) {
            openRelays.push_back({relay, i < mRelayUrls.size() ? mRelayUrls[i] : ""});
        }
    }
    if (openRelays.empty()) return {};
    if (!chat::secure_relay::hasUsableGroupKey(mGroupKey)) {
        const auto index = mRelaySendCursor++ % openRelays.size();
        return openRelays[index].relay;
    }

    std::string material = relayRouteMaterialForMessage(msg, targetId);
    chat::cert_utils::appendCanonicalField(material, "roomToken", mRoomToken);
    chat::cert_utils::appendCanonicalField(material, "epoch", std::to_string(mGroupKeyEpoch));

    std::string bestScore;
    std::shared_ptr<rtc::WebSocket> bestRelay;
    for (const auto& candidate : openRelays) {
        std::string item = material;
        chat::cert_utils::appendCanonicalField(item, "relayUrl", candidate.url);
        const auto score = chat::cert_utils::hmacSha256Hex(mGroupKey, item);
        if (!bestRelay || score < bestScore) {
            bestScore = score;
            bestRelay = candidate.relay;
        }
    }
    return bestRelay;
}

std::size_t HostSessionCore::sendToAllRelays(const json& msg) {
    reconnectClosedRelays();
    std::vector<std::shared_ptr<rtc::WebSocket>> relays;
    std::vector<std::string> urls;
    std::vector<bool> open;
    std::vector<bool> ready;
    {
        std::lock_guard<std::mutex> lock(mRelayMutex);
        relays = mRelays;
        urls = mRelayUrls;
        open = mRelayOpen;
        ready = mRelayRoomReady;
    }

    const auto payload = msg.dump();
    std::size_t sent = 0;
    for (std::size_t i = 0; i < relays.size(); ++i) {
        const auto& relay = relays[i];
        const auto url = i < urls.size() ? urls[i] : std::string();
        const bool usable = i < open.size() && i < ready.size() && open[i] && ready[i];
        if (!usable) continue;
        const auto ok = relay && !relay->isClosed() && relay->send(payload);
        if (!url.empty()) {
            try {
                chat::relay_pool::recordRelaySend(mRoomDir, url, false, ok);
            }
            catch (...) {
            }
        }
        if (ok) {
            ++sent;
        }
    }
    emitRelayStatus();
    return sent;
}

bool HostSessionCore::sendToRelayUrl(const std::string& relayUrl, const json& msg) {
    std::shared_ptr<rtc::WebSocket> target;
    std::shared_ptr<rtc::WebSocket> fallback;
    {
        std::lock_guard<std::mutex> lock(mRelayMutex);
        for (std::size_t i = 0; i < mRelays.size(); ++i) {
            const auto& relay = mRelays[i];
            const bool usable = i < mRelayOpen.size() && i < mRelayRoomReady.size() &&
                mRelayOpen[i] && mRelayRoomReady[i] && relay && !relay->isClosed();
            if (!usable) continue;
            if (i < mRelayUrls.size() && mRelayUrls[i] == relayUrl) {
                target = relay;
                break;
            }
            if (!fallback) fallback = relay;
        }
    }
    if (!target) target = fallback;
    const auto targetUrl = relayUrlFor(target);
    const auto ok = target && target->send(msg.dump());
    if (!targetUrl.empty()) {
        try {
            chat::relay_pool::recordRelaySend(mRoomDir, targetUrl, false, ok);
            emitRelayStatus();
        }
        catch (...) {
        }
    }
    return ok;
}

void HostSessionCore::enqueueSignalingMessage(std::string payload, std::string relayUrl) {
    {
        std::lock_guard<std::mutex> lock(mSignalingQueueMutex);
        if (mSignalingWorkerStopping.load()) return;
        mSignalingQueue.push_back({std::move(payload), std::move(relayUrl)});
    }
    mSignalingQueueCv.notify_one();
}

void HostSessionCore::signalingWorkerLoop() {
    while (true) {
        SignalingFrame frame;
        {
            std::unique_lock<std::mutex> lock(mSignalingQueueMutex);
            mSignalingQueueCv.wait(lock, [this]() {
                return mSignalingWorkerStopping.load() || !mSignalingQueue.empty();
            });
            if (mSignalingWorkerStopping.load() && mSignalingQueue.empty()) {
                break;
            }
            frame = std::move(mSignalingQueue.front());
            mSignalingQueue.pop_front();
        }

        // Host 侧消息处理会验证成员 PKI、解密 GKA contribution，
        // 并可能提交新的群密钥。将这些工作移出 libdatachannel WSS 回调线程，
        // 避免连续 contribution 帧被证书验证阻塞。
        handleSignalingMessage(frame);
    }
}

void HostSessionCore::stopSignalingWorker() {
    {
        std::lock_guard<std::mutex> lock(mSignalingQueueMutex);
        mSignalingWorkerStopping.store(true);
        mSignalingQueue.clear();
    }
    mSignalingQueueCv.notify_all();
    if (mSignalingThread.joinable() &&
        mSignalingThread.get_id() != std::this_thread::get_id()) {
        mSignalingThread.join();
    }
}

// 解析一行 Host 输入，并发送聊天、命令或附件。
void HostSessionCore::sendLine(const std::string& line) {
    if (handleAttachmentTrustCommand(line)) return;
    if (handleForumCommand(line)) return;
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
        chatEmit(mCallbacks.onError, "CLI /voice is disabled; send audio files with /file or use WinUI hold-to-talk");
        return;
    }
    const auto actor = currentHostActorName();
    Message msg = makeTextMessage(actor, line);
    setCurrentHostActorMetadata(msg);
    if (sendRelayMessage(msg, chat::protocol::HostActorId, mDisplayName, chat::protocol::HostActorKind, "")) {
        rememberTextHistory(msg, true);
        chatEmit(mCallbacks.onMessage, msg.toJson());
    }
}

void HostSessionCore::sendLineTo(const std::string& target, const std::string& line) {
    // Host 私发只接受证书指纹前缀。
    // nickname/displayName 只用于展示，不能作为路由依据。
    const auto targetNameInput = trimCopy(target);
    const auto targetId = resolveClientId(targetNameInput);
    if (targetNameInput.empty()) {
        sendLine(line);
        return;
    }
    if (targetId.empty()) {
        chatEmit(mCallbacks.onError, "Target fingerprint prefix not found: " + targetNameInput);
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
        chatEmit(mCallbacks.onError, "CLI /voice is disabled; send audio files with /file or use WinUI hold-to-talk");
        return;
    }

    const auto targetName = displayNameForClient(targetId);
    const auto actor = currentHostActorName();
    Message msg = makeTextMessage(actor, line);
    setCurrentHostActorMetadata(msg);
    markPrivateTarget(msg, targetId, targetName);
    if (sendRelayMessage(msg, chat::protocol::HostActorId, mDisplayName, chat::protocol::HostActorKind, targetId)) {
        rememberTextHistory(msg, true);
        chatEmit(mCallbacks.onMessage, msg.toJson());
    }
}

bool HostSessionCore::handleHostCommand(const std::string& line) {
    // 管理命令是本地 Host 控制，不是聊天消息。
    // 它们复用普通输入框，使 CLI 和 WinUI 行为一致。
    std::istringstream input(trimCopy(line));
    std::string command;
    input >> command;
    if (command == "/stop_session") {
        closeRoom();
        return true;
    }
    if (command == "/approve") {
        std::string target;
        input >> target;
        if (target.empty()) {
            chatEmit(mCallbacks.onError, "Usage: /approve <request-id>");
            return true;
        }
        approvePendingJoin(target);
        return true;
    }
    if (command == "/reject") {
        std::string target;
        input >> target;
        auto reason = trimCopy(line.substr(line.find(target) + target.size()));
        if (reason.empty()) reason = "join request rejected by host";
        if (target.empty()) {
            chatEmit(mCallbacks.onError, "Usage: /reject <request-id> [reason]");
            return true;
        }
        rejectPendingJoin(target, reason);
        return true;
    }
    if (command == "/list") {
        std::vector<std::string> rows;
        {
            std::lock_guard<std::mutex> lock(mClientsMutex);
            rows.emplace_back("host display=" + mDisplayName + " username=" + mUsername +
                " fingerprint=" + mIdentity.fingerprint());
            for (const auto& [id, username] : mClientUsernames) {
                const auto display = mClientNames.find(id);
                const auto fingerprint = mClientIdentityFingerprints.find(id);
                rows.emplace_back(
                    "client id=" + id +
                    " display=" + (display == mClientNames.end() ? username : display->second) +
                    " username=" + username +
                    " fingerprint=" + (fingerprint == mClientIdentityFingerprints.end() ? std::string() : fingerprint->second));
            }
            for (const auto& [requestId, pending] : mPendingJoinRequests) {
                rows.emplace_back(
                    "pending request=" + requestId +
                    " display=" + pending.value("displayName", pending.value("username", "")) +
                    " username=" + pending.value("username", "") +
                    " fingerprint=" + pending.value("fingerprint", ""));
            }
        }
        if (rows.empty()) rows.emplace_back("no members");
        for (const auto& row : rows) chatEmit(mCallbacks.onStatus, "Member: " + row);
        return true;
    }
    if (command != "/silence" && command != "/unsilence" && command != "/evict") {
        return false;
    }

    std::string target;
    input >> target;
    if (target.empty()) {
        chatEmit(mCallbacks.onError, "Usage: " + command + " <fingerprint-prefix>");
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

bool HostSessionCore::handleAttachmentTrustCommand(const std::string& line) {
    // 附件信任是本机预览策略。Host 输入该命令时只更新本地 UI 状态，
    // 不会把“信任/不信任”广播给 Server 或其他成员。
    std::istringstream input(trimCopy(line));
    std::string command;
    input >> command;
    if (command != "/trust" && command != "/untrust") return false;

    std::string target;
    input >> target;
    if (target.empty()) {
        chatEmit(mCallbacks.onError, "Usage: " + command + " <fingerprint-prefix>");
        return true;
    }

    const auto clientId = resolveClientId(target);
    if (clientId.empty()) {
        chatEmit(mCallbacks.onError, "Target fingerprint prefix not found: " + target);
        return true;
    }

    std::string displayName = clientId;
    std::string fingerprint;
    {
        std::lock_guard<std::mutex> lock(mClientsMutex);
        if (auto it = mClientNames.find(clientId); it != mClientNames.end() && !it->second.empty()) {
            displayName = it->second;
        }
        if (auto it = mClientIdentityFingerprints.find(clientId); it != mClientIdentityFingerprints.end()) {
            fingerprint = it->second;
        }
    }
    if (fingerprint.empty()) {
        chatEmit(mCallbacks.onError, "Target member fingerprint is not available: " + target);
        return true;
    }

    const auto action = command == "/trust" ? "trust" : "untrust";
    chatEmit(mCallbacks.onStatus, "Attachment trust: " + std::string(action) +
        " / " + displayName + " / " + clientId + " / " + fingerprint);
    return true;
}

bool HostSessionCore::handleForumCommand(const std::string& line) {
    const auto trimmed = trimCopy(line);
    if (trimmed != "/forum" &&
        trimmed != "/forum sync" &&
        trimmed.rfind("/forum post ", 0) != 0) {
        return false;
    }

    if (trimmed == "/forum") {
        std::vector<chat::forum_board::DisplayRecord> records;
        {
            std::lock_guard<std::mutex> lock(mForumMutex);
            records = mForumRecords;
        }
        if (records.empty()) {
            chatEmit(mCallbacks.onStatus, "Forum is empty");
            return true;
        }
        for (const auto& record : records) {
            chatEmit(mCallbacks.onStatus, "Forum: " + record.authorName + ": " + record.text);
        }
        return true;
    }

    if (trimmed == "/forum sync") {
        requestForumSync();
        return true;
    }

    const auto text = trimCopy(trimmed.substr(std::string("/forum post ").size()));
    if (text.empty()) {
        chatEmit(mCallbacks.onError, "Usage: /forum post <text>");
        return true;
    }
    sendForumPost(text);
    return true;
}

json HostSessionCore::makeMembershipEvent(
    const std::string& eventType,
    const std::string& clientId,
    const std::string& username,
    const std::string& displayName,
    const std::string& fingerprint,
    const json& identity) {
    if (eventType.empty()) throw std::runtime_error("membership event type is missing");
    if (fingerprint.empty()) throw std::runtime_error("membership event fingerprint is missing");
    const auto eventSeed = chat::cert_utils::randomBytes(32);
    json event = {
        {"version", 1},
        {"eventId", chat::cert_utils::sha256Hex(eventSeed.data(), eventSeed.size())},
        {"eventType", eventType},
        {"roomId", mRoomToken},
        {"epoch", mGroupKeyEpoch},
        {"clientId", clientId},
        {"username", username},
        {"displayName", displayName.empty() ? username : displayName},
        {"memberFingerprint", fingerprint},
        {"createdAtUnixMs", unixMillis()}
    };
    if (identity.is_object() && !identity.empty()) {
        event["identity"] = identity;
    }
    const auto digest = chat::cert_utils::sha256Hex(event.dump());
    event["payloadDigest"] = digest;
    event["control"] = mIdentity.signRoomControl(
        mRoomId,
        mRoomToken,
        "membership_" + eventType,
        mGroupKeyEpoch,
        digest);
    return event;
}

void HostSessionCore::approvePendingJoin(const std::string& token) {
    if (!hasOpenRelay()) {
        chatEmit(mCallbacks.onStatus, "Signaling channel is not open yet");
        return;
    }

    const auto requestId = resolvePendingJoinId(trimCopy(token));
    if (requestId.empty()) {
        chatEmit(mCallbacks.onError, "Pending join not found: " + token);
        return;
    }

    json pending;
    {
        std::lock_guard<std::mutex> lock(mClientsMutex);
        auto it = mPendingJoinRequests.find(requestId);
        if (it == mPendingJoinRequests.end()) {
            chatEmit(mCallbacks.onError, "Pending join not found: " + token);
            return;
        }
        pending = it->second;
    }

    const auto username = pending.value("username", requestId);
    const auto displayName = pending.value("displayName", username);
    const auto publicKey = pending.value("publicKey", "");
    const auto relayUrl = pending.value("relayUrl", "");
    if (!pending.contains("fingerprint") || publicKey.empty()) {
        chatEmit(mCallbacks.onError, "Pending join is not verified and cannot be approved: " + username);
        return;
    }
    json signResponse;
    if (pending.contains("csrBundle") && pending.contains("joinProof")) {
        try {
            const auto result = chat::certs::signPendingRoomMemberCertificate(
                mRoomDir,
                pending["csrBundle"],
                pending["joinProof"],
                username,
                publicKey);
            signResponse = result.signResponse;
        }
        catch (const std::exception& e) {
            chatEmit(mCallbacks.onError, "Pending certificate signing failed: " + username + ": " + e.what());
            rejectPendingJoin(requestId, "client certificate signing failed");
            return;
        }
    }
    const auto approvedFingerprint = signResponse.is_object()
        ? signResponse.value("memberFingerprint", pending.value("fingerprint", ""))
        : pending.value("fingerprint", "");
    const auto payloadDigest = pendingJoinDigest(requestId, username, publicKey);
    json msg = {
        {"type", "approve_join"},
        {"roomId", mRoomToken},
        {"requestId", requestId},
        {"epoch", mGroupKeyEpoch},
        {"payloadDigest", payloadDigest}
    };
    msg["control"] = mIdentity.signRoomControl(
        mRoomId,
        mRoomToken,
        "approve_join",
        mGroupKeyEpoch,
        payloadDigest);
    if (!signResponse.is_null()) {
        msg["admissionSignResponse"] = chat::certs::encryptAdmissionPayload(
            mRoomDir,
            "sign_response",
            {{"signResponse", signResponse}});
    }
    try {
        msg["membershipEvent"] = makeMembershipEvent(
            "approve",
            "",
            username,
            displayName,
            approvedFingerprint,
            pending.value("identity", json::object()));
    }
    catch (const std::exception& e) {
        chatEmit(mCallbacks.onError, std::string("Membership event signing failed: ") + e.what());
        return;
    }
    sendToAllRelays({
        {"type", "membership_event"},
        {"roomId", mRoomToken},
        {"event", msg["membershipEvent"]}
    });
    sendToRelayUrl(relayUrl, msg);
    chatEmit(mCallbacks.onStatus, "Pending join approved: " + username + " / " + requestId);
}

void HostSessionCore::rejectPendingJoin(const std::string& token, const std::string& reason) {
    if (!hasOpenRelay()) {
        chatEmit(mCallbacks.onStatus, "Signaling channel is not open yet");
        return;
    }

    const auto requestId = resolvePendingJoinId(trimCopy(token));
    if (requestId.empty()) {
        chatEmit(mCallbacks.onError, "Pending join not found: " + token);
        return;
    }
    std::string relayUrl;
    {
        std::lock_guard<std::mutex> lock(mClientsMutex);
        auto it = mPendingJoinRequests.find(requestId);
        if (it != mPendingJoinRequests.end()) {
            relayUrl = it->second.value("relayUrl", "");
            const auto fingerprint = it->second.value("fingerprint", "");
            if (!fingerprint.empty()) {
                // Host 显式拒绝 pending join 才写入当前房间的临时封禁集。
                // 申请者断线只会触发 pending_join_cancelled，不会走这条封禁路径。
                mBannedIdentityFingerprints.insert(fingerprint);
            }
        }
    }
    const auto finalReason = reason.empty() ? std::string("join request rejected by host") : reason;
    const auto payloadDigest = pendingRejectDigest(requestId, finalReason);
    json msg = {
        {"type", "reject_pending_join"},
        {"roomId", mRoomToken},
        {"requestId", requestId},
        {"reason", finalReason},
        {"epoch", mGroupKeyEpoch},
        {"payloadDigest", payloadDigest}
    };
    msg["control"] = mIdentity.signRoomControl(
        mRoomId,
        mRoomToken,
        "reject_pending_join",
        mGroupKeyEpoch,
        payloadDigest);
    sendToRelayUrl(relayUrl, msg);
    {
        std::lock_guard<std::mutex> lock(mClientsMutex);
        mPendingJoinRequests.erase(requestId);
    }
    chatEmit(mCallbacks.onStatus, "Pending join rejected: " + requestId.substr(0, 12));
}

// 通过加密 Server 中继向所有房间成员发送图片。
bool HostSessionCore::sendImage(const std::string& filePath) {
    return sendImageTo("", filePath);
}

bool HostSessionCore::sendImageTo(const std::string& target, const std::string& filePath) {
    const auto targetName = trimCopy(target);
    const auto targetId = resolveClientId(targetName);
    if (!targetName.empty() && targetId.empty()) {
        chatEmit(mCallbacks.onError, "Target fingerprint prefix not found: " + targetName);
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
        chatEmit(mCallbacks.onError, "Target fingerprint prefix not found: " + targetName);
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
        chatEmit(mCallbacks.onError, "Target fingerprint prefix not found: " + targetName);
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
    const bool reliable = isReliablePayloadType(msg.type);
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
    if (reliable) {
        ensureReliableFields(outbound);
    }

    ReliableOutbound prepared;
    prepared.message = std::move(outbound);
    prepared.senderId = senderId;
    prepared.senderName = senderName;
    prepared.senderKind = senderKind;
    prepared.targetId = targetId;
    prepared.messageId = payloadStringField(prepared.message, "messageId");
    prepared.payloadHash = payloadStringField(prepared.message, "payloadHash");
    return sendPreparedRelayMessage(std::move(prepared), reliable);
}

bool HostSessionCore::sendPreparedRelayMessage(ReliableOutbound outbound, bool emitNotice) {
    if (!chat::secure_relay::hasUsableGroupKey(mGroupKey)) {
        chatEmit(mCallbacks.onError, "Room group key is not ready");
        return false;
    }

    // 每条发送尝试都带独立路由 nonce，重传时会重新进入 relay selector。
    ensureRelayRouteNonce(outbound.message);

    auto relay = chooseRelayForSend(outbound.message, outbound.targetId);
    if (!relay) {
        chatEmit(mCallbacks.onStatus, "Signaling channel is not open yet");
        return false;
    }

    const auto envelope = chat::secure_relay::encryptMessageWithGroupKey(
        outbound.message,
        mRoomToken,
        outbound.senderId,
        outbound.senderName,
        outbound.senderKind,
        outbound.targetId,
        mGroupKey);
    const auto relayUrl = relayUrlFor(relay);
    const auto ok = relay->send(envelope.dump());
    if (!relayUrl.empty()) {
        try {
            chat::relay_pool::recordRelaySend(mRoomDir, relayUrl, isAttachmentBinaryType(outbound.message.type), ok);
            emitRelayStatus();
        }
        catch (...) {
        }
    }
    if (ok && emitNotice && !outbound.messageId.empty() && !outbound.payloadHash.empty()) {
        rememberReliableOutbound(outbound);
        sendReliableNotice(outbound);
    }
    return ok;
}

void HostSessionCore::ensureReliableFields(Message& msg) {
    if (!msg.payload.is_object()) msg.payload = json::object();
    if (payloadStringField(msg, "messageId").empty()) {
        msg.payload["messageId"] = makeReliableMessageId();
    }
    if (!msg.payload.contains("attempt")) {
        msg.payload["attempt"] = 0;
    }
    msg.payload.erase("payloadHash");
    msg.payload["payloadHash"] = reliablePayloadHashFor(msg);
}

void HostSessionCore::rememberReliableOutbound(const ReliableOutbound& outbound) {
    if (outbound.messageId.empty()) return;
    std::lock_guard<std::mutex> lock(mReliableMutex);
    mReliableOutbound[outbound.messageId] = outbound;
    if (isAttachmentBinaryType(outbound.message.type) && outbound.message.payload.is_object()) {
        const auto transferId = payloadStringField(outbound.message, "transferId");
        const auto chunkIndex = payloadStringField(outbound.message, "chunkIndex");
        if (!transferId.empty() && !chunkIndex.empty()) {
            try {
                mReliableChunkMessagesByTransfer[transferId][static_cast<std::size_t>(std::stoull(chunkIndex))] =
                    outbound.messageId;
            }
            catch (...) {
            }
        }
    }
    while (mReliableOutbound.size() > ReliableCacheLimit && !mReliableOutbound.empty()) {
        mReliableOutbound.erase(mReliableOutbound.begin());
    }
}

bool HostSessionCore::rememberReliableInbound(const Message& msg) {
    const auto messageId = payloadStringField(msg, "messageId");
    const auto payloadHash = payloadStringField(msg, "payloadHash");
    if (messageId.empty() || payloadHash.empty()) return true;

    std::lock_guard<std::mutex> lock(mReliableMutex);
    const auto existing = mReliableSeen.find(messageId);
    if (existing != mReliableSeen.end()) {
        if (existing->second == payloadHash) return false;
        chatEmit(mCallbacks.onError, "Rejected conflicting reliable relay payload: " + messageId);
        return false;
    }

    mReliableSeen[messageId] = payloadHash;
    mReliableSeenOrder.push_back(messageId);
    while (mReliableSeenOrder.size() > ReliableCacheLimit) {
        mReliableSeen.erase(mReliableSeenOrder.front());
        mReliableSeenOrder.pop_front();
    }
    return true;
}

void HostSessionCore::sendReliableNotice(const ReliableOutbound& outbound) {
    Message notice;
    notice.type = "relay_notice";
    notice.from = currentHostActorName();
    notice.payload = {
        {"messageId", outbound.messageId},
        {"payloadHash", outbound.payloadHash},
        {"epoch", mGroupKeyEpoch},
        {"senderId", outbound.senderId},
        {"senderFingerprint", mIdentity.fingerprint()},
        {"targetId", outbound.targetId},
        {"payloadType", outbound.message.type}
    };
    if (outbound.message.payload.is_object()) {
        for (const auto& field : {"transferId", "chunkIndex", "chunkCount", "fileHash"}) {
            auto it = outbound.message.payload.find(field);
            if (it != outbound.message.payload.end()) notice.payload[field] = *it;
        }
    }
    sendRelayMessage(notice, outbound.senderId, outbound.senderName, outbound.senderKind, outbound.targetId);
}

void HostSessionCore::handleReliableNotice(const Message& msg) {
    if (!msg.payload.is_object()) return;
    const auto messageId = payloadStringField(msg, "messageId");
    const auto payloadHash = payloadStringField(msg, "payloadHash");
    const auto senderId = payloadStringField(msg, "senderId");
    const auto targetId = payloadStringField(msg, "targetId");
    if (messageId.empty() || payloadHash.empty() || senderId.empty()) return;
    if (senderId == chat::protocol::HostActorId) return;
    if (!targetId.empty() && targetId != chat::protocol::HostActorId) return;

    {
        std::lock_guard<std::mutex> lock(mReliableMutex);
        const auto existing = mReliableSeen.find(messageId);
        if (existing != mReliableSeen.end() && existing->second == payloadHash) return;
    }

    Message missing;
    missing.type = "missing_message";
    missing.from = currentHostActorName();
    missing.payload = {
        {"messageId", messageId},
        {"payloadHash", payloadHash},
        {"epoch", mGroupKeyEpoch},
        {"targetSenderId", senderId},
        {"requesterId", chat::protocol::HostActorId}
    };
    const auto transferId = payloadStringField(msg, "transferId");
    if (!transferId.empty()) {
        missing.payload["transferId"] = transferId;
    }
    auto bitmap = transferId.empty() ? std::string() : mPendingTransfers.missingBitmapFor(senderId, transferId);
    if (bitmap.empty()) {
        Message noticePayload;
        noticePayload.type = payloadStringField(msg, "payloadType");
        noticePayload.payload = msg.payload;
        bitmap = reliableMissingBitmapFor(noticePayload);
    }
    if (!bitmap.empty() && bitmapHasMissing(bitmap)) {
        missing.payload["missingBitmap"] = bitmap;
    }

    const auto recordKey = bitmap.empty() ? messageId : bitmap;
    const auto requestId = chat::cert_utils::sha256Hex(messageId + "\n" + payloadHash + "\n" + bitmap);
    try {
        chat::relay_pool::recordRelayMissing(mRoomDir, requestId, transferId.empty() ? messageId : transferId, recordKey, 0);
    }
    catch (...) {
    }
    sendRelayMessage(missing, chat::protocol::HostActorId, mDisplayName, chat::protocol::HostActorKind, senderId);
}

void HostSessionCore::handleMissingMessage(const Message& msg) {
    if (!msg.payload.is_object()) return;
    const auto targetSenderId = payloadStringField(msg, "targetSenderId");
    if (!targetSenderId.empty() && targetSenderId != chat::protocol::HostActorId) return;
    const auto messageId = payloadStringField(msg, "messageId");
    const auto payloadHash = payloadStringField(msg, "payloadHash");
    const auto transferId = payloadStringField(msg, "transferId");
    const auto missingBitmap = payloadStringField(msg, "missingBitmap");
    if (!transferId.empty() && !missingBitmap.empty()) {
        const auto missingIndices = missingIndicesFromBitmap(missingBitmap);
        if (missingIndices.empty()) return;

        std::vector<ReliableOutbound> outbounds;
        {
            std::lock_guard<std::mutex> lock(mReliableMutex);
            auto byTransfer = mReliableChunkMessagesByTransfer.find(transferId);
            if (byTransfer == mReliableChunkMessagesByTransfer.end()) return;
            for (const auto chunkIndex : missingIndices) {
                auto mapped = byTransfer->second.find(chunkIndex);
                if (mapped == byTransfer->second.end()) continue;
                auto it = mReliableOutbound.find(mapped->second);
                if (it == mReliableOutbound.end() || it->second.retryCount >= ReliableRetryLimit) continue;
                ++it->second.retryCount;
                if (!it->second.message.payload.is_object()) it->second.message.payload = json::object();
                it->second.message.payload["attempt"] = it->second.retryCount;
                it->second.message.payload.erase("routeNonce");
                outbounds.push_back(it->second);
            }
        }

        const auto requestId = chat::cert_utils::sha256Hex(transferId + "\n" + missingBitmap);
        try {
            chat::relay_pool::recordRelayMissing(
                mRoomDir,
                requestId,
                transferId,
                missingBitmap,
                outbounds.empty() ? 0 : outbounds.front().retryCount);
        }
        catch (...) {
        }
        for (auto& outbound : outbounds) {
            sendPreparedRelayMessage(std::move(outbound), true);
        }
        return;
    }
    if (messageId.empty() || payloadHash.empty()) return;

    ReliableOutbound outbound;
    {
        std::lock_guard<std::mutex> lock(mReliableMutex);
        auto it = mReliableOutbound.find(messageId);
        if (it == mReliableOutbound.end() || it->second.payloadHash != payloadHash) return;
        if (it->second.retryCount >= ReliableRetryLimit) return;
        ++it->second.retryCount;
        if (!it->second.message.payload.is_object()) it->second.message.payload = json::object();
        it->second.message.payload["attempt"] = it->second.retryCount;
        it->second.message.payload.erase("routeNonce");
        outbound = it->second;
    }

    const auto bitmap = reliableMissingBitmapFor(outbound.message);
    const auto requestId = chat::cert_utils::sha256Hex(messageId + "\n" + payloadHash + "\n" + bitmap);
    try {
        chat::relay_pool::recordRelayMissing(mRoomDir, requestId, messageId, bitmap.empty() ? messageId : bitmap, outbound.retryCount);
    }
    catch (...) {
    }
    sendPreparedRelayMessage(outbound, true);
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
    if (!hasOpenRelay()) {
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
    std::string relayUrl;
    {
        std::lock_guard<std::mutex> lock(mClientsMutex);
        const auto it = mClientRelayUrls.find(clientId);
        if (it != mClientRelayUrls.end() && !it->second.empty()) {
            relayUrl = *it->second.begin();
        }
    }
    sendToRelayUrl(relayUrl, envelope);
    chatEmit(mCallbacks.onStatus, "GKA state sent to " + displayNameForClient(clientId));
    return true;
}

void HostSessionCore::storeGroupStateForClient(
    const std::string& clientId,
    const std::string& fingerprint,
    const json& identity,
    const json& groupState,
    std::uint64_t epoch) {
    if (fingerprint.empty() || !identity.is_object() || identity.empty()) return;
    try {
        const auto envelope = mIdentity.sealTextForIdentity(
            "group_state",
            fingerprint,
            groupState.dump(),
            identity);
        json msg = {
            {"type", "group_state_store"},
            {"roomId", mRoomToken},
            {"memberFingerprint", fingerprint},
            {"epoch", epoch},
            {"envelope", envelope}
        };
        sendToAllRelays(msg);
    }
    catch (const std::exception& e) {
        chatEmit(mCallbacks.onStatus, "Group state store warning for " + clientId + ": " + e.what());
    }
}

bool HostSessionCore::resendCurrentGroupStateToClient(const std::string& clientId) {
    std::string publicKey;
    json groupState;
    std::uint64_t epoch = 0;
    {
        std::lock_guard<std::mutex> lock(mClientsMutex);
        const auto publicKeyIt = mClientPublicKeys.find(clientId);
        if (publicKeyIt == mClientPublicKeys.end() || publicKeyIt->second.empty()) return false;
        publicKey = publicKeyIt->second;
    }
    {
        std::lock_guard<std::mutex> lock(mGkaMutex);
        if (mCurrentGroupState.empty() || !chat::secure_relay::hasUsableGroupKey(mGroupKey)) return false;
        groupState = mCurrentGroupState;
        epoch = mGroupKeyEpoch;
    }
    return sendGroupStateToClient(clientId, publicKey, groupState, epoch);
}

void HostSessionCore::rotateGroupKey(const std::string& reason) {
    // 轮换现在会启动贡献式 GKA epoch。
    // Host 像其他成员一样贡献随机性，不再单独选择 K_G。
    std::unordered_set<std::string> currentMembers;
    {
        std::lock_guard<std::mutex> lock(mClientsMutex);
        for (const auto& clientId : mConnectedClientIds) {
            auto publicKey = mClientPublicKeys.find(clientId);
            if (publicKey != mClientPublicKeys.end() && !publicKey->second.empty()) {
                currentMembers.insert(clientId);
            }
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
    if (!hasOpenRelay()) {
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
    sendToAllRelays(msg);
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

void HostSessionCore::requestGkaTimeoutStop() {
    // 取消所有待处理 epoch 并唤醒看门狗。该函数不 join 线程，
    // WinUI shutdown 可以先快速返回，把等待工作留给后台清理。
    {
        std::lock_guard<std::mutex> lock(mGkaMutex);
        mGkaTimeoutStop = true;
        mPendingGkaEpoch = 0;
        mPendingGkaMembers.clear();
        mPendingGkaContributions.clear();
    }
    mGkaCv.notify_all();
}

void HostSessionCore::stopGkaTimeoutWorker() {
    // 取消所有待处理 epoch 并 join 看门狗，
    // 避免关闭后留下持有回调或 WebSocket 状态的后台线程。
    requestGkaTimeoutStop();
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
            mClientSealIdentityObjects.erase(clientId);
            mClientUsernames.erase(clientId);
            mConnectedClientIds.erase(clientId);
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
    std::string knownUsername;
    std::string knownFingerprint;
    {
        std::lock_guard<std::mutex> lock(mClientsMutex);
        auto key = mClientPublicKeys.find(memberId);
        auto name = mClientUsernames.find(memberId);
        auto fp = mClientIdentityFingerprints.find(memberId);
        if (key != mClientPublicKeys.end()) knownPublicKey = key->second;
        if (name != mClientUsernames.end()) knownUsername = name->second;
        if (fp != mClientIdentityFingerprints.end()) knownFingerprint = fp->second;
    }
    if (knownPublicKey != publicKey || (!knownUsername.empty() && knownUsername != username)) {
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
        {
            std::lock_guard<std::mutex> lock(mClientsMutex);
            mClientIdentityFingerprints[memberId] = verified.fingerprint;
            mClientIdentitySubjects[memberId] = verified.subject;
            // GKA contribution 的 identity 签名绑定 epoch 和 contribution，
            // 不能复用为 member_identity 中的 join_room 公钥公告签名。
            // 其他成员会在 group state 中重新验证该 GKA identity。
            mClientSealIdentityObjects[memberId] = *identity;
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

    struct ClientStateForGroup {
        std::string clientId;
        std::string publicKey;
        std::string fingerprint;
        json identity;
        bool connected = false;
    };
    std::vector<ClientStateForGroup> clients;
    {
        std::lock_guard<std::mutex> lock(mClientsMutex);
        clients.reserve(mConnectedClientIds.size());
        for (const auto& [clientId, publicKeyValue] : mClientPublicKeys) {
            if (!publicKeyValue.empty()) {
                const auto fingerprint = mClientIdentityFingerprints.find(clientId);
                json identityObject = json::object();
                if (const auto identity = mClientIdentityObjects.find(clientId);
                    identity != mClientIdentityObjects.end()) {
                    identityObject = identity->second;
                }
                else if (const auto identity = mClientSealIdentityObjects.find(clientId);
                         identity != mClientSealIdentityObjects.end()) {
                    identityObject = identity->second;
                }
                clients.push_back({
                    clientId,
                    publicKeyValue,
                    fingerprint == mClientIdentityFingerprints.end() ? std::string() : fingerprint->second,
                    identityObject,
                    mConnectedClientIds.find(clientId) != mConnectedClientIds.end()
                });
            }
        }
    }

    {
        std::lock_guard<std::mutex> lock(mGkaMutex);
        if (mPendingGkaEpoch != epoch) return;
        mGroupKey = std::move(groupKey);
        mCurrentGroupState = groupState;
        mPendingGkaEpoch = 0;
        mPendingGkaMembers.clear();
        mPendingGkaContributions.clear();
    }
    mGkaCv.notify_all();

    for (const auto& client : clients) {
        storeGroupStateForClient(client.clientId, client.fingerprint, client.identity, groupState, epoch);
        if (client.connected) {
            sendGroupStateToClient(client.clientId, client.publicKey, groupState, epoch);
        }
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
    const auto fileHash = attachment::sha256Hex(bytes);
    const auto chunkHashes = attachment::chunkSha256Hexes(bytes, attachment::RelayChunkBytes);
    const auto merkleRoot = attachment::merkleRootForChunkHashes(chunkHashes);
    setCurrentHostActorMetadata(meta);
    meta.payload["fileHash"] = fileHash;
    meta.payload["chunkSize"] = static_cast<std::uint64_t>(attachment::RelayChunkBytes);
    meta.payload["chunkCount"] = static_cast<std::uint64_t>(chunkHashes.size());
    meta.payload["chunkHashes"] = chunkHashes;
    meta.payload["merkleRoot"] = merkleRoot;
    markPrivateTarget(meta, targetId, targetName);
    if (!sendRelayMessage(meta, chat::protocol::HostActorId, mDisplayName, chat::protocol::HostActorKind, targetId)) {
        return false;
    }

    const auto transferId = attachment::transferIdFromMessage(meta);
    for (std::size_t offset = 0; offset < bytes.size(); offset += attachment::RelayChunkBytes) {
        const auto chunkSize = (std::min)(attachment::RelayChunkBytes, bytes.size() - offset);
        const auto chunkIndex = offset / attachment::RelayChunkBytes;
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
            {"chunkSize", static_cast<int>(chunkSize)},
            {"chunkCount", static_cast<int>(chunkHashes.size())},
            {"chunkIndex", static_cast<int>(chunkIndex)},
            {"chunkHash", chunkHashes[chunkIndex]},
            {"merkleProof", attachment::merkleProofForChunk(chunkHashes, chunkIndex)},
            {"fileHash", fileHash}
        };
        setCurrentHostActorMetadata(chunk);
        markPrivateTarget(chunk, targetId, targetName);
        if (!sendRelayMessage(chunk, chat::protocol::HostActorId, mDisplayName, chat::protocol::HostActorKind, targetId)) {
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
void HostSessionCore::handleSignalingMessage(const SignalingFrame& frame) {
    if (mStopped.load()) return;
    const auto& s = frame.payload;
    const auto& relayUrl = frame.relayUrl;

    try {
        // 信令和中继消息都是不可信网络输入。
        // 从 JSON 对象读取类型字段前，先应用相同的大小/深度预算。
        auto j = chat::protocol::parseJsonObjectWithBudget(
            s,
            chat::protocol::MaxSignalingMessageBytes,
            "signaling message");
        std::string type = j.value("type", "");

        if (type == "room_created") {
            const bool reattached = j.value("reattached", false);
            {
                std::lock_guard<std::mutex> lock(mRelayMutex);
                if (mRelayRoomReady.size() < mRelayUrls.size()) mRelayRoomReady.resize(mRelayUrls.size(), false);
                for (std::size_t i = 0; i < mRelayUrls.size(); ++i) {
                    if (mRelayUrls[i] == relayUrl) {
                        mRelayRoomReady[i] = true;
                        break;
                    }
                }
            }
            if (!mRoomCreated.exchange(true)) {
                chatEmit(mCallbacks.onStatus, std::string(reattached ? "Room reattached: " : "Room created: ") + mRoomId);
                rotateGroupKey(reattached ? "host reattached" : "room created");
            }
            else {
                chatEmit(mCallbacks.onStatus, "Relay room ready: " + relayLabel(relayUrl));
            }
        }
        else if (type == "room_members") {
            std::ostringstream members;
            bool first = true;
            std::vector<json> clientIdentityCandidates;
            std::unordered_set<std::string> onlineClientIds;
            for (const auto& member : j.value("memberInfos", json::array())) {
                if (!member.is_object()) continue;
                if (!first) members << "; ";
                const auto id = member.value("id", "");
                const auto username = member.value("username", id);
                const auto displayName = member.value("displayName", username);
                // 发出 name/id，使 UI Client 不暴露原始信令 JSON
                // 也能保留内部 PKI 映射。
                members << displayName << " / " << id;
                if (member.value("role", "") == "client") {
                    if (!id.empty()) onlineClientIds.insert(id);
                    clientIdentityCandidates.push_back(member);
                }
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
            bool addedClient = false;
            bool onlineChanged = false;
            std::vector<std::string> stateResendIds;
            for (const auto& member : clientIdentityCandidates) {
                const auto id = member.value("id", "");
                const auto username = member.value("username", id);
                const auto displayName = member.value("displayName", username);
                const auto publicKey = member.value("publicKey", "");
                const auto identity = member.find("identity");
                if (id.empty() || publicKey.empty() || identity == member.end() || !identity->is_object()) continue;

                bool alreadyKnown = false;
                {
                    std::lock_guard<std::mutex> lock(mClientsMutex);
                    alreadyKnown = mClientNames.find(id) != mClientNames.end();
                    if (alreadyKnown) {
                        mClientRelayUrls[id].insert(relayUrl);
                    }
                    if (alreadyKnown && mConnectedClientIds.insert(id).second) {
                        onlineChanged = true;
                        stateResendIds.push_back(id);
                    }
                }
                if (alreadyKnown) continue;

                try {
                    // Host 重新接管持久房间时，Server 会通过 room_members
                    // 提供现有 Client 的候选 identity。Host 必须重新验签，
                    // 不能信任 Server 的成员列表。
                    const auto verified = mIdentity.verifyJoinRoom(mRoomId, username, publicKey, *identity);
                    {
                        std::lock_guard<std::mutex> lock(mClientsMutex);
                        mClientUsernames[id] = username;
                        mClientNames[id] = displayName.empty() ? username : displayName;
                        mClientPublicKeys[id] = publicKey;
                        mClientIdentityFingerprints[id] = verified.fingerprint;
                        mClientIdentitySubjects[id] = verified.subject;
                        mClientIdentityObjects[id] = *identity;
                        mClientSealIdentityObjects[id] = *identity;
                        mConnectedClientIds.insert(id);
                        mClientRelayUrls[id].insert(relayUrl);
                    }
                    chatEmit(mCallbacks.onStatus, "PKI member verified: " + (displayName.empty() ? username : displayName) + " / " + id + " / " + verified.fingerprint);
                    addedClient = true;
                    stateResendIds.push_back(id);
                }
                catch (const std::exception& e) {
                    chatEmit(mCallbacks.onError, "Existing client identity rejected: " + username + ": " + e.what());
                    rejectClient(id, "client identity verification failed");
                }
            }
            if (addedClient) {
                chatEmit(mCallbacks.onStatus, "Room member state synchronized");
            }
            if (onlineChanged) {
                chatEmit(mCallbacks.onStatus, "Member reconnected");
            }
            for (const auto& id : stateResendIds) {
                resendCurrentGroupStateToClient(id);
            }
        }
        else if (type == "pending_join") {
            const auto requestId = j.value("requestId", "");
            const auto username = j.value("username", requestId);
            const auto displayName = j.value("displayName", username);
            const auto publicKey = j.value("publicKey", "");
            const auto identity = j.find("identity");
            const auto admissionPayload = j.find("admissionPayload");
            if (requestId.empty() || publicKey.empty()) {
                chatEmit(mCallbacks.onError, "Malformed pending join request");
                return;
            }

            std::string identityFingerprint;
            std::string identitySubject;
            bool bannedCertificate = false;
            bool knownMemberRejoin = false;
            try {
                if (identity != j.end() && identity->is_object()) {
                    const auto verified = mIdentity.verifyJoinRoom(mRoomId, username, publicKey, *identity);
                    identityFingerprint = verified.fingerprint;
                    identitySubject = verified.subject;
                }
                else if (admissionPayload != j.end() && admissionPayload->is_object()) {
                    const auto decryptedAdmission = chat::certs::decryptAdmissionPayload(
                        mRoomDir,
                        "pending_join",
                        *admissionPayload);
                    const auto csrBundle = decryptedAdmission.find("csrBundle");
                    const auto joinProof = decryptedAdmission.find("joinProof");
                    if (csrBundle == decryptedAdmission.end() || !csrBundle->is_object() ||
                        joinProof == decryptedAdmission.end() || !joinProof->is_object()) {
                        throw std::runtime_error("admission payload is missing CSR proof");
                    }
                    identityFingerprint = chat::certs::verifyPendingJoinRequest(
                        mRoomDir,
                        *csrBundle,
                        *joinProof,
                        username,
                        publicKey);
                    identitySubject = "pending CSR";
                    j["csrBundle"] = *csrBundle;
                    j["joinProof"] = *joinProof;
                }
                else {
                    throw std::runtime_error("pending join has no identity or CSR proof");
                }
                {
                    std::lock_guard<std::mutex> lock(mClientsMutex);
                    bannedCertificate = mBannedIdentityFingerprints.find(identityFingerprint) != mBannedIdentityFingerprints.end();
                    for (const auto& [knownId, knownFingerprint] : mClientIdentityFingerprints) {
                        if (knownFingerprint == identityFingerprint) {
                            knownMemberRejoin = true;
                            break;
                        }
                    }
                }
                if (bannedCertificate) {
                    throw std::runtime_error("member certificate is banned in this room");
                }
            }
            catch (const std::exception& e) {
                {
                    std::lock_guard<std::mutex> lock(mClientsMutex);
                    mPendingJoinRequests[requestId] = j;
                }
                chatEmit(mCallbacks.onError, "Pending join rejected: " + username + ": " + e.what());
                rejectPendingJoin(requestId, "client identity verification failed");
                return;
            }

            json pending = j;
            pending["fingerprint"] = identityFingerprint;
            pending["subject"] = identitySubject;
            pending["relayUrl"] = relayUrl;
            {
                std::lock_guard<std::mutex> lock(mClientsMutex);
                mPendingJoinRequests[requestId] = pending;
            }
            if (knownMemberRejoin) {
                approvePendingJoin(requestId);
                return;
            }
            chatEmit(
                mCallbacks.onStatus,
                "Pending join verified: " + (displayName.empty() ? username : displayName) +
                    " / " + requestId +
                    " / " + identityFingerprint);
        }
        else if (type == "pending_join_cancelled") {
            const auto requestId = j.value("requestId", "");
            if (!requestId.empty()) {
                std::lock_guard<std::mutex> lock(mClientsMutex);
                mPendingJoinRequests.erase(requestId);
            }
            chatEmit(mCallbacks.onStatus, "Pending join cancelled: " + requestId);
        }
        else if (type == "new_client") {
            std::string clientId = j.value("clientId", "");
            std::string username = j.value("username", clientId);
            std::string displayName = j.value("displayName", username);
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
                    auto admissionSignResponse = j.find("admissionSignResponse");
                    if (identity != j.end() && identity->is_object()) {
                        identityObject = *identity;
                        const auto verified = mIdentity.verifyJoinRoom(mRoomId, username, publicKey, *identity);
                        identityFingerprint = verified.fingerprint;
                        identitySubject = verified.subject;
                    }
                    else if (admissionSignResponse != j.end() && admissionSignResponse->is_object()) {
                        // 首次 entrance 入房时，Client 在收到 joined 后才安装成员证书。
                        // Server 回送的是 admission-encrypted sign response；Host 解开后
                        // 只取证书指纹建立成员映射，后续 GKA contribution 会补齐正式 identity。
                        json signResponseObject = chat::certs::decryptAdmissionPayload(
                            mRoomDir,
                            "sign_response",
                            *admissionSignResponse).value("signResponse", json::object());
                        identityFingerprint = signResponseObject.value("memberFingerprint", "");
                        identitySubject = "pending signed member certificate";
                        if (identityFingerprint.empty()) {
                            throw std::runtime_error("signed member certificate response is missing fingerprint");
                        }
                    }
                    else {
                        throw std::runtime_error("client identity is missing");
                    }
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
            bool wasKnownClient = false;
            {
                std::lock_guard<std::mutex> lock(mClientsMutex);
                wasKnownClient = mClientNames.find(clientId) != mClientNames.end();
                mClientUsernames[clientId] = username;
                mClientNames[clientId] = displayName.empty() ? username : displayName;
                if (!publicKey.empty()) mClientPublicKeys[clientId] = publicKey;
                if (!clientId.empty()) mConnectedClientIds.insert(clientId);
                if (!clientId.empty()) mClientRelayUrls[clientId].insert(relayUrl);
                if (!identityFingerprint.empty()) {
                    mClientIdentityFingerprints[clientId] = identityFingerprint;
                    mClientIdentitySubjects[clientId] = identitySubject;
                    if (identityObject.is_object()) {
                        mClientIdentityObjects[clientId] = identityObject;
                        mClientSealIdentityObjects[clientId] = identityObject;
                    }
                }
                for (auto it = mPendingJoinRequests.begin(); it != mPendingJoinRequests.end();) {
                    if (it->second.value("username", "") == username &&
                        it->second.value("publicKey", "") == publicKey) {
                        it = mPendingJoinRequests.erase(it);
                    }
                    else {
                        ++it;
                    }
                }
            }
            if (!clientId.empty() && !wasKnownClient) {
                chatEmit(mCallbacks.onStatus, "Client joined: " +
                    (displayName.empty() ? username : displayName) + " / " + clientId);
                // 新成员加入意味着需要新的房间群密钥，
                // 该成员只能通过已验证公钥收到当前密钥版本。
                rotateGroupKey("member joined");
            }
        }
        else if (type == "client_left") {
            const std::string clientId = j.value("clientId", "");
            bool stillConnectedOnRelay = false;
            {
                std::lock_guard<std::mutex> lock(mClientsMutex);
                auto it = mClientRelayUrls.find(clientId);
                if (it != mClientRelayUrls.end()) {
                    it->second.erase(relayUrl);
                    stillConnectedOnRelay = !it->second.empty();
                    if (it->second.empty()) mClientRelayUrls.erase(it);
                }
            }
            if (stillConnectedOnRelay) return;
            markClientDisconnected(clientId);
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
        else if (type == chat::forum_board::RecordsType) {
            handleForumRecords(
                j.value("records", json::array()),
                j.value("membershipEvents", json::array()));
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
            if (isReliablePayloadType(msg.type) && !rememberReliableInbound(msg)) {
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
        else if (type == "room_closed") {
            const auto reason = j.value("reason", "room closed");
            chatEmit(mCallbacks.onStatus, "Room is no longer available: " + reason);
            mStopped.store(true);
            stopGkaTimeoutWorker();
            requestStopNoJoin();
        }
        else if (type == "error") {
            const std::string message = j.value("message", "unknown");
            chatEmit(mCallbacks.onError, "Signaling server error: " + message);
            if (message == "room already exists") {
                mStopped.store(true);
                requestStopNoJoin();
                chatEmit(mCallbacks.onStatus, "Session stopped");
            }
        }
    }
    catch (const std::exception& e) {
        chatEmit(mCallbacks.onError, std::string("Bad signaling message: ") + e.what());
    }
}

// 将 Client 标记为当前连接离线，但保留它的房间成员资格。
void HostSessionCore::markClientDisconnected(const std::string& id) {
    if (id.empty()) return;
    if (mStopped.load()) return;

    std::string displayName = id;
    bool knownClient = false;
    bool wasConnected = false;
    bool removedFromPendingGka = false;
    {
        std::lock_guard<std::mutex> lock(mClientsMutex);
        auto name = mClientNames.find(id);
        if (name != mClientNames.end()) {
            displayName = name->second;
            knownClient = true;
        }
        wasConnected = mConnectedClientIds.erase(id) > 0;
        mSilencedClientIds.erase(id);
    }
    if (!knownClient) {
        // 恶意或混乱的 Server 可能报告过期/未知 client_left。
        // 忽略它可避免不必要的群密钥轮换和 UI 抖动。
        chatEmit(mCallbacks.onStatus, "Ignored unknown client_left: " + id);
        return;
    }
    mPendingTransfers.clear(id);
    {
        std::lock_guard<std::mutex> lock(mGkaMutex);
        removedFromPendingGka = mPendingGkaMembers.erase(id) > 0;
        mPendingGkaContributions.erase(id);
    }
    if (wasConnected) {
        chatEmit(mCallbacks.onStatus, "Client disconnected: " + displayName);
    }
    // 断线不是成员资格撤销。若断线发生在 GKA 进行中，
    // 当前 epoch 只等待仍在线成员，避免网络波动拖住房间。
    if (removedFromPendingGka) {
        mGkaCv.notify_all();
        tryCommitGkaEpoch();
    }
}

// 永久移除一个 Client 成员，并清除来自它的所有暂存附件传输。
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
        knownClient = mClientUsernames.erase(id) > 0 || knownClient;
        knownClient = mClientPublicKeys.erase(id) > 0 || knownClient;
        knownClient = mClientIdentityFingerprints.erase(id) > 0 || knownClient;
        knownClient = mClientIdentitySubjects.erase(id) > 0 || knownClient;
        knownClient = mClientIdentityObjects.erase(id) > 0 || knownClient;
        knownClient = mClientSealIdentityObjects.erase(id) > 0 || knownClient;
        mClientRelayUrls.erase(id);
        mConnectedClientIds.erase(id);
        mSilencedClientIds.erase(id);
    }
    if (!knownClient) {
        chatEmit(mCallbacks.onStatus, "Ignored unknown member removal: " + id);
        return;
    }
    mPendingTransfers.clear(id);
    chatEmit(mCallbacks.onStatus, "Client removed: " + displayName);
    // Host 显式驱逐或 GKA 超时驱逐才改变成员资格；
    // 这类事件会轮换 K_G，防止被移除成员继续读取后续消息。
    rotateGroupKey("member removed");
}

void HostSessionCore::setClientSilenced(const std::string& target, bool silenced) {
    if (!hasOpenRelay()) {
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
    if (!hasOpenRelay()) {
        chatEmit(mCallbacks.onStatus, "Signaling channel is not open yet");
        return;
    }

    const auto clientId = resolveClientId(trimCopy(target));
    if (clientId.empty() || clientId == chat::protocol::HostActorId) {
        chatEmit(mCallbacks.onError, "Target member is not a client");
        return;
    }

    std::string displayName;
    std::string username;
    std::string fingerprint;
    json identityObject;
    bool foundClient = false;
    {
        std::lock_guard<std::mutex> lock(mClientsMutex);
        auto name = mClientNames.find(clientId);
        if (name != mClientNames.end()) {
            foundClient = true;
            displayName = name->second;
        }
        if (auto it = mClientUsernames.find(clientId); it != mClientUsernames.end()) {
            username = it->second;
        }
        if (auto it = mClientIdentityObjects.find(clientId); it != mClientIdentityObjects.end()) {
            identityObject = it->second;
        }
        else if (auto it = mClientSealIdentityObjects.find(clientId); it != mClientSealIdentityObjects.end()) {
            identityObject = it->second;
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

    json membershipEvent;
    try {
        membershipEvent = makeMembershipEvent(
            "evict",
            clientId,
            username.empty() ? clientId : username,
            displayName,
            fingerprint,
            identityObject);
    }
    catch (const std::exception& e) {
        chatEmit(mCallbacks.onError, std::string("Eviction event signing failed: ") + e.what());
        return;
    }

    sendToAllRelays({
        {"type", "membership_event"},
        {"roomId", mRoomToken},
        {"event", membershipEvent}
    });
    rejectClient(clientId, "member evicted by host", membershipEvent);
    chatEmit(mCallbacks.onStatus, "Client evicted: " + displayName);
    if (!fingerprint.empty()) {
        chatEmit(mCallbacks.onStatus, "Banned member certificate for this room: " + fingerprint);
    }
    removeClient(clientId);
}

void HostSessionCore::sendClientModeration(const std::string& type, const std::string& clientId) {
    if (clientId.empty() || !hasOpenRelay()) {
        chatEmit(mCallbacks.onStatus, "Signaling channel is not open yet");
        return;
    }
    json msg = {
        {"type", type},
        {"roomId", mRoomToken},
        {"targetId", clientId}
    };
    sendToAllRelays(msg);
}

void HostSessionCore::handleRelayMessage(const Message& msg) {
    if (msg.type == "relay_notice") {
        handleReliableNotice(msg);
        return;
    }
    if (msg.type == "missing_message") {
        handleMissingMessage(msg);
        return;
    }

    // member_identity 是 Host 发起且只发给 Client 的控制消息；
    // 如果它回环到 Host，Host 会忽略。
    if (msg.type == "member_identity") {
        return;
    }

    if (msg.type == "text") {
        rememberTextHistory(msg, false);
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
            attachment::expectedSizeFromMeta(msg, kind),
            attachment::chunkSizeFromMeta(msg),
            attachment::fileHashFromMeta(msg),
            attachment::merkleRootFromMeta(msg),
            attachment::chunkHashesFromMeta(msg));
        Message out = msg;
        out.name = pending.name;
        out.payload["transferId"] = pending.transferId;
        out.payload["name"] = pending.name;
        chatEmit(mCallbacks.onMessage, out.toJson());
        chatEmit(mCallbacks.onStatus, "Encrypted attachment meta received: " + pending.name);
        drainEarlyAttachmentChunks(senderKey, pending.transferId);
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
        const auto activeTransferId = mPendingTransfers.activeTransferId(senderKey);
        if (activeTransferId.empty()) {
            if (bufferEarlyAttachmentChunk(senderKey, transferId, msg)) return;
            throw std::runtime_error("attachment chunk arrived before meta and early buffer is full");
        }
        if (transferId != activeTransferId) {
            throw std::runtime_error("attachment chunk transfer id does not match pending meta");
        }
        const auto result = mPendingTransfers.appendChunk(
            senderKey,
            attachment::chunkOffsetFromMessage(msg),
            attachment::base64DecodeToRtcBytes(msg.data),
            attachment::chunkHashFromMessage(msg),
            attachment::merkleProofFromMessage(msg));
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

bool HostSessionCore::bufferEarlyAttachmentChunk(
    const std::string& senderKey,
    const std::string& transferId,
    const Message& msg) {
    if (transferId.empty()) return false;
    auto& chunks = mEarlyAttachmentChunks[earlyAttachmentKey(senderKey, transferId)];
    if (chunks.size() >= EarlyAttachmentChunkLimit) return false;
    chunks.push_back(msg);
    return true;
}

void HostSessionCore::drainEarlyAttachmentChunks(const std::string& senderKey, const std::string& transferId) {
    const auto key = earlyAttachmentKey(senderKey, transferId);
    auto found = mEarlyAttachmentChunks.find(key);
    if (found == mEarlyAttachmentChunks.end()) return;

    auto chunks = std::move(found->second);
    mEarlyAttachmentChunks.erase(found);
    for (const auto& chunk : chunks) {
        handleRelayBinaryChunk(senderKey, chunk);
    }
}

void HostSessionCore::rememberTextHistory(const Message& msg, bool isOwn) {
    if (!mMessageHistory || msg.type != "text") return;
    try {
        mMessageHistory->appendText(chat::local_message::makeTextRecord(msg, isOwn));
    }
    catch (const std::exception& e) {
        chatEmit(mCallbacks.onStatus, std::string("Local message history warning: ") + e.what());
    }
}

std::string HostSessionCore::messageHistoryJson(std::size_t limit) const {
    if (!mMessageHistory) return "[]";
    return mMessageHistory->historyJson(limit);
}

std::string HostSessionCore::currentHostActorName() {
    return mDisplayName.empty() ? mUsername : mDisplayName;
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

// 将证书指纹前缀解析为底层 client id。至少要求 8 个十六进制字符。
std::string HostSessionCore::resolveClientId(const std::string& token) {
    if (token.empty()) return "";
    if (token.size() < 8) return "";
    for (const auto ch : token) {
        if (!std::isxdigit(static_cast<unsigned char>(ch))) return "";
    }

    std::lock_guard<std::mutex> lock(mClientsMutex);
    std::string match;
    for (const auto& [id, fingerprint] : mClientIdentityFingerprints) {
        if (startsWithIgnoreCase(fingerprint, token)) {
            if (!match.empty() && match != id) return "";
            match = id;
        }
    }
    return match;
}

std::string HostSessionCore::resolvePendingJoinId(const std::string& token) {
    if (token.empty()) return "";
    std::lock_guard<std::mutex> lock(mClientsMutex);
    if (mPendingJoinRequests.find(token) != mPendingJoinRequests.end()) {
        return token;
    }
    return "";
}

void HostSessionCore::rejectClient(const std::string& clientId, const std::string& reason, const json& membershipEvent) {
    if (clientId.empty() || !hasOpenRelay()) return;
    json msg = {
        {"type", "reject_client"},
        {"roomId", mRoomToken},
        {"targetId", clientId},
        {"reason", reason}
    };
    if (membershipEvent.is_object() && !membershipEvent.empty()) {
        msg["membershipEvent"] = membershipEvent;
    }
    std::unordered_set<std::string> relayUrls;
    {
        std::lock_guard<std::mutex> lock(mClientsMutex);
        if (auto it = mClientRelayUrls.find(clientId); it != mClientRelayUrls.end()) {
            relayUrls = it->second;
        }
    }
    if (relayUrls.empty()) {
        chatEmit(mCallbacks.onStatus, "No active relay for client: " + clientId);
        return;
    }
    for (const auto& relayUrl : relayUrls) {
        sendToRelayUrl(relayUrl, msg);
    }
}

void HostSessionCore::announceVerifiedMember(
    const std::string& memberId,
    const std::string& username,
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
    msg.payload["username"] = username.empty() ? memberId : username;
    msg.payload["displayName"] = displayName.empty() ? memberId : displayName;
    msg.payload["fingerprint"] = fingerprint;
    msg.payload["subject"] = subject;
    msg.payload["publicKey"] = publicKey;
    msg.payload["identity"] = identity;
    msg.payload["state"] = "verified";
    msg.payload["verifiedBy"] = chat::protocol::HostActorId;

    // 该公告是加密控制消息。Server 可以中继，但无法读取。
    // Client 仍会验证其中的身份签名，使不可信 Host 无法静默替换其他成员公钥。
    sendRelayMessage(msg, chat::protocol::HostActorId, mDisplayName, chat::protocol::HostActorKind, "");
}

void HostSessionCore::announceVerifiedMembers() {
    std::vector<std::tuple<std::string, std::string, std::string, std::string, std::string, std::string, json>> members;
    members.emplace_back(
        chat::protocol::HostActorId,
        mUsername,
        mDisplayName,
        mIdentity.fingerprint(),
        mIdentity.subject(),
        mMemberKeys.publicKey,
        mIdentity.signJoinRoom(mRoomId, mUsername, mMemberKeys.publicKey));
    {
        std::lock_guard<std::mutex> lock(mClientsMutex);
        members.reserve(members.size() + mClientIdentityFingerprints.size());
        for (const auto& [memberId, fingerprint] : mClientIdentityFingerprints) {
            const auto username = mClientUsernames.find(memberId);
            const auto name = mClientNames.find(memberId);
            const auto subject = mClientIdentitySubjects.find(memberId);
            const auto publicKey = mClientPublicKeys.find(memberId);
            const auto identity = mClientIdentityObjects.find(memberId);
            if (publicKey == mClientPublicKeys.end() || identity == mClientIdentityObjects.end()) continue;
            members.emplace_back(
                memberId,
                username == mClientUsernames.end() ? memberId : username->second,
                name == mClientNames.end() ? memberId : name->second,
                fingerprint,
                subject == mClientIdentitySubjects.end() ? std::string() : subject->second,
                publicKey->second,
                identity->second);
        }
    }

    for (const auto& [memberId, username, displayName, fingerprint, subject, publicKey, identity] : members) {
        announceVerifiedMember(memberId, username, displayName, fingerprint, subject, publicKey, identity);
    }
}

void HostSessionCore::sendForumPost(const std::string& text) {
    std::vector<chat::forum_board::Recipient> recipients;
    std::unordered_set<std::string> recipientFingerprints;
    recipients.push_back({
        chat::protocol::HostActorId,
        mDisplayName.empty() ? mUsername : mDisplayName,
        mIdentity.fingerprint(),
        mIdentity.signJoinRoom(mRoomId, mUsername, mMemberKeys.publicKey)
    });
    recipientFingerprints.insert(mIdentity.fingerprint());
    {
        std::lock_guard<std::mutex> lock(mClientsMutex);
        for (const auto& [memberId, fingerprint] : mClientIdentityFingerprints) {
            if (fingerprint.empty() || recipientFingerprints.find(fingerprint) != recipientFingerprints.end()) continue;
            json identityObject = json::object();
            if (const auto identity = mClientIdentityObjects.find(memberId);
                identity != mClientIdentityObjects.end()) {
                identityObject = identity->second;
            }
            else if (const auto identity = mClientSealIdentityObjects.find(memberId);
                     identity != mClientSealIdentityObjects.end()) {
                identityObject = identity->second;
            }
            if (!identityObject.is_object() || identityObject.empty()) continue;
            const auto displayName = mClientNames.find(memberId);
            recipients.push_back({
                memberId,
                displayName == mClientNames.end() ? memberId : displayName->second,
                fingerprint,
                identityObject
            });
            recipientFingerprints.insert(fingerprint);
        }
        for (const auto& [fingerprint, recipient] : mForumRecipientsByFingerprint) {
            if (fingerprint.empty() || recipientFingerprints.find(fingerprint) != recipientFingerprints.end()) continue;
            recipients.push_back(recipient);
            recipientFingerprints.insert(fingerprint);
        }
    }

    try {
        const auto record = chat::forum_board::makeRecord(
            mRoomId,
            mRoomToken,
            mGroupKeyEpoch,
            chat::protocol::HostActorId,
            mDisplayName.empty() ? mUsername : mDisplayName,
            mIdentity,
            recipients,
            text);
        json msg = {
            {"type", chat::forum_board::RecordType},
            {"roomId", mRoomToken},
            {"boardMessageId", record.value("boardMessageId", "")},
            {"recordHash", chat::forum_board::payloadDigest(record)},
            {"record", record}
        };
        const auto sent = sendToAllRelays(msg);
        rememberForumRecord(record);
        chatEmit(mCallbacks.onStatus, "Forum post sent to relays: " + std::to_string(sent));
    }
    catch (const std::exception& e) {
        chatEmit(mCallbacks.onError, std::string("Forum post failed: ") + e.what());
    }
}

void HostSessionCore::requestForumSync() {
    json msg = {
        {"type", chat::forum_board::SyncType},
        {"roomId", mRoomToken}
    };
    const auto sent = sendToAllRelays(msg);
    chatEmit(mCallbacks.onStatus, "Forum sync requested on relays: " + std::to_string(sent));
}

void HostSessionCore::handleForumRecords(const json& records, const json& membershipEvents) {
    if (membershipEvents.is_array()) {
        for (const auto& event : membershipEvents) {
            rememberForumMembershipEvent(event);
        }
    }

    if (!records.is_array()) return;
    std::size_t opened = 0;
    for (const auto& record : records) {
        const auto before = mForumRecords.size();
        rememberForumRecord(record);
        if (mForumRecords.size() > before) ++opened;
    }
    if (opened > 0) {
        chatEmit(mCallbacks.onStatus, "Forum records synced: " + std::to_string(opened));
    }
}

bool HostSessionCore::rememberForumMembershipEvent(const json& event) {
    if (!event.is_object()) return false;
    const auto eventType = event.value("eventType", "");
    const auto fingerprint = event.value("memberFingerprint", "");
    const auto digest = event.value("payloadDigest", "");
    const auto control = event.find("control");
    if ((eventType != "approve" && eventType != "evict") ||
        fingerprint.empty() ||
        digest.empty() ||
        control == event.end() ||
        !control->is_object() ||
        event.value("roomId", "") != mRoomToken) {
        return false;
    }
    if (digest != membershipEventDigest(event)) {
        chatEmit(mCallbacks.onStatus, "Forum membership event skipped: digest mismatch");
        return false;
    }

    try {
        const auto signer = mIdentity.verifyRoomControl(
            mRoomId,
            mRoomToken,
            "membership_" + eventType,
            event.value("epoch", 0ULL),
            digest,
            *control);
        if (signer.fingerprint != mIdentity.fingerprint()) return false;

        std::lock_guard<std::mutex> lock(mClientsMutex);
        if (eventType == "evict") {
            mForumRecipientsByFingerprint.erase(fingerprint);
            return true;
        }

        const auto identity = event.find("identity");
        if (identity == event.end() || !identity->is_object()) return false;
        mForumRecipientsByFingerprint[fingerprint] = {
            event.value("clientId", fingerprint),
            event.value("displayName", event.value("username", fingerprint)),
            fingerprint,
            *identity
        };
        return true;
    }
    catch (const std::exception& e) {
        chatEmit(mCallbacks.onStatus, std::string("Forum membership event skipped: ") + e.what());
        return false;
    }
}

void HostSessionCore::rememberForumRecord(const json& record) {
    try {
        const auto messageId = record.value("boardMessageId", "");
        const auto digest = chat::forum_board::payloadDigest(record);
        if (messageId.empty() || digest.empty()) return;
        {
            std::lock_guard<std::mutex> lock(mForumMutex);
            const auto existing = mForumRecordHashes.find(messageId);
            if (existing != mForumRecordHashes.end()) {
                if (existing->second != digest) {
                    chatEmit(mCallbacks.onError, "Rejected conflicting forum record: " + messageId);
                }
                return;
            }
        }

        auto opened = chat::forum_board::openRecord(mRoomId, mRoomToken, mIdentity, record);
        {
            std::lock_guard<std::mutex> lock(mForumMutex);
            mForumRecordHashes[messageId] = digest;
            mForumRecords.push_back(std::move(opened));
            std::sort(mForumRecords.begin(), mForumRecords.end(), [](const auto& left, const auto& right) {
                return left.createdAtUnixMs < right.createdAtUnixMs;
            });
        }
    }
    catch (const std::exception& e) {
        chatEmit(mCallbacks.onStatus, std::string("Forum record skipped: ") + e.what());
    }
}

std::string HostSessionCore::forumHistoryJson(std::size_t limit) const {
    json out = json::array();
    std::lock_guard<std::mutex> lock(mForumMutex);
    const auto start = mForumRecords.size() > limit ? mForumRecords.size() - limit : 0;
    for (std::size_t i = start; i < mForumRecords.size(); ++i) {
        const auto& record = mForumRecords[i];
        out.push_back({
            {"boardMessageId", record.boardMessageId},
            {"authorDisplayName", record.authorName},
            {"authorFingerprint", record.authorFingerprint},
            {"text", record.text},
            {"createdAtUnixMs", record.createdAtUnixMs},
            {"own", record.own}
        });
    }
    return out.dump();
}
