// Client 会话实现。它签名 join_room，接收 Host 分发的群密钥，
// 解密中继 envelope，并发送加密聊天/附件消息。
#include "client_session_core.hpp"

#include "attachment_transfer.hpp"
#include "cert_generation.hpp"
#include "cert_utils.hpp"
#include "forum_board.hpp"
#include "relay_pool.hpp"
#include "secure_relay.hpp"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace {
namespace attachment = chat::attachment;
constexpr std::size_t RelayRouteNonceBytes = 16;
constexpr std::size_t ReliableMessageIdBytes = 16;
constexpr std::size_t ReliableCacheLimit = 4096;
constexpr std::size_t EarlyAttachmentChunkLimit = 512;
constexpr int ReliableRetryLimit = 3;
constexpr int RelayRetryBaseSeconds = 5;
constexpr int RelayRetryMaxSeconds = 60;

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

std::string pendingJoinDigest(
    const std::string& requestId,
    const std::string& username,
    const std::string& publicKey) {
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

bool isReliablePayloadType(const std::string& type) {
    attachment::Kind ignored = attachment::Kind::Text;
    return type == "text" ||
        type == chat::secure_relay::PairwisePrivateType ||
        attachmentKindForMeta(type, ignored) ||
        isAttachmentBinaryType(type);
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

std::string normalizeNickname(const std::string& nickname, const std::string& fallbackName) {
    // nickname 是运行时显示名。非法或为空时回退到用户输入的 base username，
    // 避免把内部唯一 username 暴露到普通聊天界面。
    const auto trimmed = trimCopy(nickname);
    if (trimmed.empty() || trimmed.size() > 64) return fallbackName;
    for (const auto ch : trimmed) {
        const auto c = static_cast<unsigned char>(ch);
        if (c < 0x20 || c == 0x7f) return fallbackName;
    }
    return trimmed;
}

bool validNicknameCommandValue(const std::string& nickname) {
    const auto trimmed = trimCopy(nickname);
    if (trimmed.empty() || trimmed.size() > 64) return false;
    for (const auto ch : trimmed) {
        const auto c = static_cast<unsigned char>(ch);
        if (c < 0x20 || c == 0x7f) return false;
    }
    return true;
}

std::string relayLabel(const std::string& url) {
    const auto scheme = url.find("://");
    const auto start = scheme == std::string::npos ? 0 : scheme + 3;
    return url.substr(start);
}

bool isLocalOrLanRelayUrl(const std::string& url) {
    auto lower = url;
    std::transform(lower.begin(), lower.end(), lower.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    if (lower.rfind("wss://", 0) != 0) return false;
    auto pos = std::string("wss://").size();
    if (pos < lower.size() && lower[pos] == '[') {
        const auto end = lower.find(']', pos + 1);
        if (end == std::string::npos) return false;
        const auto host = lower.substr(pos + 1, end - pos - 1);
        return host == "::1" || host.rfind("fc", 0) == 0 || host.rfind("fd", 0) == 0 || host.rfind("fe80", 0) == 0;
    }
    const auto end = lower.find_first_of(":/?#", pos);
    const auto host = lower.substr(pos, end == std::string::npos ? std::string::npos : end - pos);
    if (host == "localhost") return true;
    std::istringstream parts(host);
    std::string item;
    int ip[4] = {};
    for (int i = 0; i < 4; ++i) {
        if (!std::getline(parts, item, '.')) return false;
        if (item.empty() || item.size() > 3) return false;
        int value = 0;
        for (const auto ch : item) {
            if (!std::isdigit(static_cast<unsigned char>(ch))) return false;
            value = value * 10 + (ch - '0');
        }
        if (value > 255) return false;
        ip[i] = value;
    }
    if (!parts.eof()) return false;
    return ip[0] == 10 ||
        ip[0] == 127 ||
        (ip[0] == 169 && ip[1] == 254) ||
        (ip[0] == 172 && ip[1] >= 16 && ip[1] <= 31) ||
        (ip[0] == 192 && ip[1] == 168);
}

bool looksLikeTlsTrustError(std::string error) {
    std::transform(error.begin(), error.end(), error.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    return error.find("tls") != std::string::npos ||
        error.find("ssl") != std::string::npos ||
        error.find("cert") != std::string::npos ||
        error.find("x509") != std::string::npos ||
        error.find("verify") != std::string::npos ||
        error.find("handshake") != std::string::npos;
}

std::string relayErrorMessage(const std::string& url, const std::string& error) {
    if (isLocalOrLanRelayUrl(url) && looksLikeTlsTrustError(error)) {
        return "local/LAN WSS relay requires a matching local TLS-CA";
    }
    return "Relay error: " + relayLabel(url) + ": " + error;
}

std::string earlyAttachmentKey(const std::string& senderKey, const std::string& transferId) {
    return senderKey + "\n" + transferId;
}

std::string membershipEventDigest(json event) {
    event.erase("payloadDigest");
    event.erase("control");
    return chat::cert_utils::sha256Hex(event.dump());
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
    return jsonStringField(msg.payload, name);
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

std::vector<std::size_t> admissionRelayOrder(
    const std::vector<std::string>& urls,
    const std::string& roomToken,
    const std::string& admissionSecret,
    const std::string& username,
    const std::string& publicKey) {
    if (urls.empty()) return {};
    const auto key = chat::cert_utils::base64Decode(admissionSecret);
    if (key.empty()) {
        throw std::runtime_error("room admission secret is missing");
    }

    std::vector<std::pair<std::string, std::size_t>> scored;
    scored.reserve(urls.size());
    for (std::size_t i = 0; i < urls.size(); ++i) {
        std::string material = "securechat-relay-admission-route\n";
        chat::cert_utils::appendCanonicalField(material, "label", "route:pending-join");
        chat::cert_utils::appendCanonicalField(material, "roomToken", roomToken);
        chat::cert_utils::appendCanonicalField(material, "username", username);
        chat::cert_utils::appendCanonicalField(material, "sessionPublicKey", publicKey);
        chat::cert_utils::appendCanonicalField(material, "relayUrl", urls[i]);
        scored.emplace_back(chat::cert_utils::hmacSha256Hex(key, material), i);
    }
    std::sort(scored.begin(), scored.end(), [](const auto& lhs, const auto& rhs) {
        return lhs.first == rhs.first ? lhs.second < rhs.second : lhs.first < rhs.first;
    });

    std::vector<std::size_t> order;
    order.reserve(scored.size());
    for (const auto& item : scored) {
        order.push_back(item.second);
    }
    return order;
}
}

ClientSessionCore::ClientSessionCore(
    std::string url,
    std::string room,
    std::string username,
    std::string baseUsername,
    std::string nickname,
    chat::pki_application::IdentityContext identity,
    std::string roomToken,
    std::string admissionSecret,
    std::string roomDir,
    std::string keyPassword,
    rtc::WebSocket::Configuration wsConfig)
    : mWsUrl(std::move(url)),
      mRoomId(std::move(room)),
      mBaseUsername(std::move(baseUsername)),
      mUsername(std::move(username)),
      mDisplayName(normalizeNickname(nickname, mBaseUsername.empty() ? mUsername : mBaseUsername)),
      mRoomToken(std::move(roomToken)),
      mAdmissionSecret(std::move(admissionSecret)),
      mRoomDir(std::move(roomDir)),
      mKeyPassword(std::move(keyPassword)),
      mWsConfig(std::move(wsConfig)) {
    // Server 使用该不透明 token 注册和路由；显示房间名只留在本地 PKI 语义中。
    if (mRoomToken.empty()) throw std::runtime_error("room instance token is required");
    mRelayUrls = chat::relay_pool::relayUrlsFromRoomDir(mRoomDir);
    if (mRelayUrls.empty()) throw std::runtime_error("relay pool has no usable relay");
    mWsUrl = mRelayUrls.front();
    // X25519 密钥对按会话生成。公钥会在 join_room 中被签名；
    // 私钥留在本地，用于解封装 Host 分发的群密钥。
    mMemberKeys = chat::secure_relay::generateMemberKeyPair();
    chat::websocket_config::applyClientTlsFromEnvironment(mWsConfig);
    // Host/Client 启动必须具备 PKI 配置。
    // 环境变量缺失会在这里失败，且不会发送任何入房消息。
    mIdentity = std::move(identity);
    mPendingTransfers.setRoomContext("client", mUsername, mRoomId, mRoomToken);
    mMessageHistory = std::make_unique<chat::local_message::Store>(
        "client",
        mRoomId,
        mRoomToken,
        mUsername);
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
    mAllRelaysUnavailableReported.store(false);
    if (!mSignalingThread.joinable()) {
        mSignalingThread = std::thread([this]() {
            signalingWorkerLoop();
        });
    }

    {
        std::lock_guard<std::mutex> lock(mRelayMutex);
        mRelays.assign(mRelayUrls.size(), nullptr);
        mRelayOpen.assign(mRelayUrls.size(), false);
        mRelayNextRetryAt.assign(mRelayUrls.size(), {});
        mRelayFailureStreak.assign(mRelayUrls.size(), 0);
        mRelayFailureReported.assign(mRelayUrls.size(), false);
    }

    if (mIdentity.enabled()) {
        connectRemainingRelays();
    }
    else {
        connectAdmissionRelay();
    }
}

void ClientSessionCore::connectAdmissionRelay() {
    const auto order = admissionRelayOrder(
        mRelayUrls,
        mRoomToken,
        mAdmissionSecret,
        mUsername,
        mMemberKeys.publicKey);
    for (const auto relayIndex : order) {
        if (relayRetryAllowed(relayIndex)) {
            connectRelay(relayIndex);
            return;
        }
    }
    chatEmit(mCallbacks.onRelayStatus, "relay unavailable");
    handleAllRelaysUnavailable("All relays are unavailable; join aborted");
}

void ClientSessionCore::connectRelay(std::size_t relayIndex) {
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

    rtc::WebSocket::Configuration relayConfig;
    try {
        relayConfig = chat::websocket_config::clientConfigForUrl(mWsConfig, url);
    }
    catch (const std::exception& e) {
        markRelayFailure(relayIndex, url, "offline");
        chatEmit(mCallbacks.onError, e.what());
        emitRelayStatus();
        if (!mIdentity.enabled() && !mJoinedRoom.load() && !mStopped.load() && !mShutdownRequested.load()) {
            connectAdmissionRelay();
            return;
        }
        if (!mJoinedRoom.load() && !hasOpenRelay() && allRelaysFailed()) {
            handleAllRelaysUnavailable("All relays are unavailable; join aborted");
        }
        else if (mJoinedRoom.load() && !hasOpenRelay() && allRelaysFailed()) {
            handleAllRelaysUnavailable("All relays are unavailable; left current room");
        }
        return;
    }
    auto ws = std::make_shared<rtc::WebSocket>(relayConfig);
    {
        std::lock_guard<std::mutex> lock(mRelayMutex);
        if (mRelays.size() < mRelayUrls.size()) mRelays.resize(mRelayUrls.size());
        if (mRelayOpen.size() < mRelayUrls.size()) mRelayOpen.resize(mRelayUrls.size(), false);
        if (mRelayFailureReported.size() < mRelayUrls.size()) mRelayFailureReported.resize(mRelayUrls.size(), false);
        mRelayFailureReported[relayIndex] = false;
        mRelayOpen[relayIndex] = false;
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
        json msg = {
            {"type", mIdentity.enabled() ? "member_rejoin" : "join_room"},
            {"roomId", mRoomToken},
            {"username", mUsername},
            {"displayName", mDisplayName},
            {"publicKey", mMemberKeys.publicKey}
        };
        if (mIdentity.enabled()) {
            chatEmit(mCallbacks.onStatus, "PKI identity ready: " + mIdentity.fingerprint());
            // 对 roomId、username 和临时 X25519 公钥签名，
            // 使 Host 在给该 Client 发送房间群密钥前能检测替换攻击。
            msg["memberFingerprint"] = mIdentity.fingerprint();
            msg["identity"] = mIdentity.signJoinRoom(mRoomId, mUsername, mMemberKeys.publicKey);
        }
        else {
            // 首次导入 entrance.scp 时还没有 Host 签发的成员证书。
            // 这时用 CSR 私钥签名 pending join proof，再用 admission secret
            // 加密 CSR/proof；Server 只能转发密文，看不到 CSR PEM 或设备声明。
            const auto material = chat::certs::loadRoomRuntimeMaterial(mRoomDir, mUsername, false, false);
            json admissionPlaintext = {
                {"csrBundle", material.memberCsrBundle},
                {"joinProof", chat::certs::makePendingJoinProof(
                    mRoomDir,
                    mUsername,
                    mMemberKeys.publicKey,
                    mKeyPassword)}
            };
            msg["admissionPayload"] = chat::certs::encryptAdmissionPayload(
                mRoomDir,
                "pending_join",
                admissionPlaintext);
        }
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
        if (report && !mIdentity.enabled() && !mJoinedRoom.load() && !mStopped.load() && !mShutdownRequested.load()) {
            connectAdmissionRelay();
            return;
        }
        if (report && !hasOpenRelay() && allRelaysFailed() && !mSawErrorFrame.load() && !mStopped.load() && !mShutdownRequested.load()) {
            // WebSocket close 可能先于对端试图发送的 error JSON 帧到达。
            // 报告当前准入流程，避免 WinUI 把所有静默关闭都误判为构建版本不匹配。
            if (!mJoinedRoom.load()) {
                const auto message =
                    "Signaling closed before room join completed; check relay pool, room directory, Host status, PKI files, and rebuild all components if one executable was updated";
                chatEmit(mCallbacks.onError, message);
                handleAllRelaysUnavailable("All relays are unavailable; join aborted");
            }
        }
        if (report && !hasOpenRelay()) {
            chatEmit(mCallbacks.onRelayStatus, "relay unavailable");
            if (!mJoinedRoom.load() && allRelaysFailed()) {
                handleAllRelaysUnavailable("All relays are unavailable; join aborted");
            }
            else if (mJoinedRoom.load() && allRelaysFailed()) {
                handleAllRelaysUnavailable("All relays are unavailable; left current room");
            }
        }
    });

    ws->onError([this, url, relayIndex](std::string error) {
        const auto report = markRelayFailure(relayIndex, url, "offline");
        if (report) {
            chatEmit(mCallbacks.onError, relayErrorMessage(url, error));
            emitRelayStatus();
        }
        if (report && !mIdentity.enabled() && !mJoinedRoom.load() && !mStopped.load() && !mShutdownRequested.load()) {
            connectAdmissionRelay();
            return;
        }
        if (report && !hasOpenRelay()) {
            chatEmit(mCallbacks.onRelayStatus, "relay unavailable");
            if (!mJoinedRoom.load() && allRelaysFailed()) {
                handleAllRelaysUnavailable("All relays are unavailable; join aborted");
            }
            else if (mJoinedRoom.load() && allRelaysFailed()) {
                handleAllRelaysUnavailable("All relays are unavailable; left current room");
            }
        }
    });

    ws->open(url);
}

void ClientSessionCore::connectRemainingRelays() {
    for (std::size_t i = 0; i < mRelayUrls.size(); ++i) {
        if (relayRetryAllowed(i)) connectRelay(i);
    }
}

void ClientSessionCore::reconnectClosedRelays() {
    for (std::size_t i = 0; i < mRelayUrls.size(); ++i) {
        bool needsConnect = false;
        {
            std::lock_guard<std::mutex> lock(mRelayMutex);
            needsConnect = i >= mRelays.size() || !mRelays[i] || mRelays[i]->isClosed();
        }
        if (needsConnect && relayRetryAllowed(i)) connectRelay(i);
    }
}

void ClientSessionCore::emitRelayStatus() {
    try {
        chatEmit(mCallbacks.onRelayStatus, chat::relay_pool::relayStatusSummaryText(mRoomDir));
    }
    catch (...) {
    }
}

std::string ClientSessionCore::relayUrlFor(const std::shared_ptr<rtc::WebSocket>& relay) const {
    std::lock_guard<std::mutex> lock(mRelayMutex);
    for (std::size_t i = 0; i < mRelays.size(); ++i) {
        if (mRelays[i] == relay && i < mRelayUrls.size()) return mRelayUrls[i];
    }
    return {};
}

bool ClientSessionCore::relayRetryAllowed(std::size_t relayIndex) const {
    std::lock_guard<std::mutex> lock(mRelayMutex);
    if (relayIndex >= mRelayNextRetryAt.size()) return true;
    return std::chrono::steady_clock::now() >= mRelayNextRetryAt[relayIndex];
}

void ClientSessionCore::markRelayHealthy(std::size_t relayIndex, const std::string& url) {
    {
        std::lock_guard<std::mutex> lock(mRelayMutex);
        if (relayIndex >= mRelayFailureStreak.size()) mRelayFailureStreak.resize(mRelayUrls.size(), 0);
        if (relayIndex >= mRelayNextRetryAt.size()) mRelayNextRetryAt.resize(mRelayUrls.size());
        if (relayIndex >= mRelayFailureReported.size()) mRelayFailureReported.resize(mRelayUrls.size(), false);
        if (relayIndex >= mRelayOpen.size()) mRelayOpen.resize(mRelayUrls.size(), false);
        mRelayOpen[relayIndex] = true;
        mRelayFailureStreak[relayIndex] = 0;
        mRelayNextRetryAt[relayIndex] = {};
        mRelayFailureReported[relayIndex] = false;
    }
    mAllRelaysUnavailableReported.store(false);
    try {
        chat::relay_pool::markRelayStatus(mRoomDir, url, "healthy");
    }
    catch (...) {
    }
}

bool ClientSessionCore::markRelayFailure(std::size_t relayIndex, const std::string& url, const std::string& status) {
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

void ClientSessionCore::handleAllRelaysUnavailable(const std::string& reason) {
    if (mStopped.load() || mShutdownRequested.load()) return;
    if (mAllRelaysUnavailableReported.exchange(true)) return;
    requestShutdown(reason);
}

void ClientSessionCore::requestStopNoJoin() {
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
}

// 关闭信令 WebSocket 和本地传输状态。
void ClientSessionCore::stop() {
    requestStopNoJoin();
    stopSignalingWorker();
    requestShutdown("Stopped");
}

// 返回外层 CLI/API 循环是否应停止轮询该会话。
bool ClientSessionCore::shouldStop() const {
    if (mStopped.load()) return true;
    if (mShutdownRequested.load()) return true;
    return false;
}

bool ClientSessionCore::hasOpenRelay() const {
    std::lock_guard<std::mutex> lock(mRelayMutex);
    for (std::size_t i = 0; i < mRelays.size(); ++i) {
        if (i < mRelayOpen.size() && mRelayOpen[i] && mRelays[i] && !mRelays[i]->isClosed()) return true;
    }
    return false;
}

bool ClientSessionCore::allRelaysFailed() const {
    std::lock_guard<std::mutex> lock(mRelayMutex);
    if (mRelayUrls.empty()) return true;
    for (std::size_t i = 0; i < mRelayUrls.size(); ++i) {
        if (i >= mRelayFailureReported.size() || !mRelayFailureReported[i]) return false;
    }
    return true;
}

std::shared_ptr<rtc::WebSocket> ClientSessionCore::chooseRelayForSend(const Message& msg, const std::string& targetId) {
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
        if (i < mRelayOpen.size() && mRelayOpen[i] && relay && !relay->isClosed()) {
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

// 解析一行 Client 输入，并发送对应的聊天、命令或附件。
void ClientSessionCore::sendLine(const std::string& line) {
    std::string directTarget;
    std::string directBody;
    if (parseDirectPrefix(line, directTarget, directBody)) {
        sendLineTo(directTarget, directBody);
        return;
    }

    if (line.empty()) return;
    if (handleNicknameCommand(line)) return;
    if (handleAttachmentTrustCommand(line)) return;
    if (handleForumCommand(line)) return;
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
        chatEmit(mCallbacks.onError, "CLI /voice is disabled; send audio files with /file or use WinUI hold-to-talk");
        return;
    }

    try {
        Message msg = parseInput(line);
        msg.payload["actorId"] = mClientId;
        msg.payload["actorKind"] = chat::protocol::ClientActorKind;
        msg.payload["displayName"] = mDisplayName;
        if (sendRelayMessage(msg, mClientId, mDisplayName, chat::protocol::ClientActorKind, "")) {
            rememberTextHistory(msg, true);
            chatEmit(mCallbacks.onMessage, msg.toJson());
        }
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
        chatEmit(mCallbacks.onError, "Target fingerprint prefix not found: " + targetName);
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
        chatEmit(mCallbacks.onError, "CLI /voice is disabled; send audio files with /file or use WinUI hold-to-talk");
        return;
    }

    try {
        Message msg = parseInput(line);
        msg.payload["actorId"] = mClientId;
        msg.payload["actorKind"] = chat::protocol::ClientActorKind;
        msg.payload["displayName"] = mDisplayName;
        std::string targetName = targetId;
        {
            std::lock_guard<std::mutex> lock(mMembersMutex);
            auto it = mMemberNamesById.find(targetId);
            if (it != mMemberNamesById.end()) targetName = it->second;
        }
        markPrivateTarget(msg, targetId, targetName);
        if (sendRelayMessage(msg, mClientId, mDisplayName, chat::protocol::ClientActorKind, targetId)) {
            rememberTextHistory(msg, true);
            chatEmit(mCallbacks.onMessage, msg.toJson());
        }
    }
    catch (const std::exception& e) {
        chatEmit(mCallbacks.onError, std::string("Input failed: ") + e.what());
    }
}

bool ClientSessionCore::handleAttachmentTrustCommand(const std::string& line) {
    // /trust 和 /untrust 是本机 UI 策略，不会改变房间成员资格或发送任何网络帧。
    // 目标只接受证书指纹前缀，保持与私发 To: Member 相同的安全路由规则。
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

    const auto memberId = resolveMemberId(target);
    if (memberId.empty()) {
        chatEmit(mCallbacks.onError, "Target fingerprint prefix not found: " + target);
        return true;
    }

    std::string displayName = memberId;
    std::string fingerprint;
    {
        std::lock_guard<std::mutex> lock(mMembersMutex);
        if (auto it = mMemberNamesById.find(memberId); it != mMemberNamesById.end() && !it->second.empty()) {
            displayName = it->second;
        }
        if (auto it = mMemberFingerprintsById.find(memberId); it != mMemberFingerprintsById.end()) {
            fingerprint = it->second;
        }
    }
    if (fingerprint.empty()) {
        chatEmit(mCallbacks.onError, "Target member fingerprint is not available: " + target);
        return true;
    }

    const auto action = command == "/trust" ? "trust" : "untrust";
    chatEmit(mCallbacks.onStatus, "Attachment trust: " + std::string(action) +
        " / " + displayName + " / " + memberId + " / " + fingerprint);
    return true;
}

bool ClientSessionCore::handleNicknameCommand(const std::string& line) {
    const auto trimmedLine = trimCopy(line);
    if (trimmedLine != "/nickname" && trimmedLine.rfind("/nickname ", 0) != 0) {
        return false;
    }

    auto nickname = trimCopy(trimmedLine.size() > std::string("/nickname").size()
        ? trimmedLine.substr(std::string("/nickname").size())
        : std::string());
    if (nickname.empty()) {
        nickname = mBaseUsername.empty() ? mUsername : mBaseUsername;
    }
    if (!validNicknameCommandValue(nickname)) {
        chatEmit(mCallbacks.onError, "Usage: /nickname <1-64 visible characters>");
        return true;
    }
    if (!mJoinedRoom.load()) {
        chatEmit(mCallbacks.onError, "Cannot change nickname before joining the room");
        return true;
    }
    if (!chat::secure_relay::hasUsableGroupKey(mGroupKey)) {
        chatEmit(mCallbacks.onStatus, "Waiting for room group key");
        return true;
    }

    const auto oldNickname = mDisplayName;
    mDisplayName = nickname;
    mPublishedNickname.clear();
    mNicknamePublishedEpoch = 0;
    if (!publishNickname()) {
        mDisplayName = oldNickname;
        chatEmit(mCallbacks.onError, "Nickname update failed: no relay is available");
        return true;
    }

    chatEmit(mCallbacks.onStatus, "Nickname changed: " + nickname);
    return true;
}

bool ClientSessionCore::publishNickname() {
    if (!mJoinedRoom.load() || mClientId.empty() ||
        !chat::secure_relay::hasUsableGroupKey(mGroupKey)) {
        return false;
    }
    const auto nickname = normalizeNickname(mDisplayName, mBaseUsername.empty() ? mUsername : mBaseUsername);
    if (mNicknamePublishedEpoch == mGroupKeyEpoch && mPublishedNickname == nickname) {
        return true;
    }

    Message msg;
    msg.type = "nickname_update";
    msg.from = nickname;
    msg.payload["actorId"] = mClientId;
    msg.payload["actorKind"] = chat::protocol::ClientActorKind;
    msg.payload["displayName"] = nickname;
    if (!sendRelayMessage(msg, mClientId, nickname, chat::protocol::ClientActorKind, "")) {
        return false;
    }

    mDisplayName = nickname;
    mPublishedNickname = nickname;
    mNicknamePublishedEpoch = mGroupKeyEpoch;
    {
        std::lock_guard<std::mutex> lock(mMembersMutex);
        mMemberNamesById[mClientId] = nickname;
        mMemberUsernamesById[mClientId] = mUsername;
        mMemberFingerprintsById[mClientId] = mIdentity.fingerprint();
    }
    chatEmit(
        mCallbacks.onStatus,
        "PKI member verified: " + nickname + " / " + mClientId + " / " + mIdentity.fingerprint());
    return true;
}

bool ClientSessionCore::handleForumCommand(const std::string& line) {
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

Message ClientSessionCore::parseInput(const std::string& line) {
    // Client 文本消息使用 Server 分配的 client id 作为协议发送者，
    // 并把人类可读显示名保存在载荷元数据中。
    return makeTextMessage(mClientId, line);
}

std::string ClientSessionCore::resolveMemberId(const std::string& token) {
    // 私发中继最终需要具体成员 id。输入端只接受证书指纹前缀，
    // 且至少 8 个十六进制字符，避免同名昵称或 username 被误用为路由目标。
    if (token.empty()) return "";
    if (token.size() < 8) return "";
    for (const auto ch : token) {
        if (!std::isxdigit(static_cast<unsigned char>(ch))) return "";
    }

    std::lock_guard<std::mutex> lock(mMembersMutex);
    std::string match;
    for (const auto& [id, fingerprint] : mMemberFingerprintsById) {
        if (startsWithIgnoreCase(fingerprint, token)) {
            if (!match.empty() && match != id) return "";
            match = id;
        }
    }
    return match;
}

bool ClientSessionCore::rememberVerifiedMemberIdentity(
    const std::string& memberId,
    const std::string& identityName,
    const std::string& displayName,
    const std::string& publicKey,
    const json& identity,
    const std::string& advertisedFingerprint,
    const std::string& source,
    bool allowSessionKeyRotation) {
    // Server/Host 可以报告成员列表，但二者都不被视为密钥权威。
    // 成员证书签名绑定 roomId、username 和 X25519 公钥；
    // nickname/displayName 只用于成员列表和消息气泡显示。
    if (memberId.empty() || publicKey.empty() || !identity.is_object()) return false;
    try {
        const auto verified = mIdentity.verifyJoinRoom(mRoomId, identityName, publicKey, identity);
        if (!advertisedFingerprint.empty() && advertisedFingerprint != verified.fingerprint) {
            throw std::runtime_error("member identity fingerprint mismatch");
        }

        {
            std::lock_guard<std::mutex> lock(mMembersMutex);
            const auto existingFingerprint = mMemberFingerprintsById.find(memberId);
            if (existingFingerprint != mMemberFingerprintsById.end() &&
                existingFingerprint->second != verified.fingerprint) {
                throw std::runtime_error("member fingerprint changed for existing id");
            }
            const auto existingPublicKey = mMemberPublicKeysById.find(memberId);
            if (existingPublicKey != mMemberPublicKeysById.end() && existingPublicKey->second != publicKey &&
                !allowSessionKeyRotation) {
                throw std::runtime_error("member public key changed for existing id");
            }
            mMemberNamesById[memberId] = displayName.empty()
                ? (identityName.empty() ? memberId : identityName)
                : displayName;
            mMemberUsernamesById[memberId] = identityName.empty() ? memberId : identityName;
            mMemberPublicKeysById[memberId] = publicKey;
            mMemberFingerprintsById[memberId] = verified.fingerprint;
            mMemberIdentityObjectsById[memberId] = identity;
        }

        chatEmit(
            mCallbacks.onStatus,
            "PKI member verified: " + (displayName.empty() ? (identityName.empty() ? memberId : identityName) : displayName) +
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
    if (epoch == mLastGkaContributionEpoch) return;
    Message routeHint;
    routeHint.type = chat::secure_relay::GkaContributionType;
    routeHint.from = mClientId;
    routeHint.payload["epoch"] = epoch;
    ensureRelayRouteNonce(routeHint);
    auto relay = chooseRelayForSend(routeHint, chat::protocol::HostActorId);
    if (!relay) {
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
    const auto queued = relay->send(serialized);
    const auto relayUrl = relayUrlFor(relay);
    if (!relayUrl.empty()) {
        try {
            chat::relay_pool::recordRelaySend(mRoomDir, relayUrl, false, queued);
            emitRelayStatus();
        }
        catch (...) {
        }
    }
    if (queued) mLastGkaContributionEpoch = epoch;
    chatEmit(
        mCallbacks.onStatus,
        std::string("GKA contribution ") + (queued ? "sent" : "send failed") +
            ": epoch " + std::to_string(epoch) +
            ", bytes " + std::to_string(serialized.size()));
}

bool ClientSessionCore::installGroupState(const json& groupState, std::uint64_t epoch, bool allowStoredSelfSessionKey) {
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
                const bool sameIdentity = verified.fingerprint == mIdentity.fingerprint();
                const bool sameSessionKey = publicKey == mMemberKeys.publicKey;
                if (!sameIdentity || (!sameSessionKey && !allowStoredSelfSessionKey)) {
                    throw std::runtime_error("GKA state does not include this Client identity");
                }
            }
            if (memberId == chat::protocol::HostActorId) {
                sawHost = true;
            }
            {
                std::lock_guard<std::mutex> lock(mMembersMutex);
                const auto existingFingerprint = mMemberFingerprintsById.find(memberId);
                if (existingFingerprint != mMemberFingerprintsById.end() &&
                    existingFingerprint->second != verified.fingerprint) {
                    throw std::runtime_error("member fingerprint changed inside GKA state");
                }
                const auto existingPublicKey = mMemberPublicKeysById.find(memberId);
                const bool sameStableIdentity = existingFingerprint != mMemberFingerprintsById.end() &&
                    existingFingerprint->second == verified.fingerprint;
                const bool allowSessionKeyRotation = memberId == chat::protocol::HostActorId && sameStableIdentity;
                if (existingPublicKey != mMemberPublicKeysById.end() && existingPublicKey->second != publicKey &&
                    !allowSessionKeyRotation) {
                    throw std::runtime_error("member public key changed inside GKA state");
                }
                mMemberUsernamesById[memberId] = username.empty() ? memberId : username;
                if (mMemberNamesById.find(memberId) == mMemberNamesById.end()) {
                    mMemberNamesById[memberId] = username.empty() ? memberId : username;
                }
                mMemberPublicKeysById[memberId] = publicKey;
                mMemberFingerprintsById[memberId] = verified.fingerprint;
                mMemberIdentityObjectsById[memberId] = *identity;
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
    if (msg.type == "relay_notice") {
        handleReliableNotice(msg);
        return;
    }
    if (msg.type == "missing_message") {
        handleMissingMessage(msg);
        return;
    }

    if (msg.type == "member_identity") {
        const auto relaySenderId = msg.payload.value("relaySenderId", "");
        const auto relaySenderKind = msg.payload.value("relaySenderKind", "");
        if (relaySenderId == chat::protocol::HostActorId &&
            relaySenderKind == chat::protocol::HostActorKind) {
            const auto memberId = msg.payload.value("memberId", "");
            const auto username = msg.payload.value("username", memberId);
            const auto displayName = msg.payload.value("displayName", memberId);
            const auto fingerprint = msg.payload.value("fingerprint", "");
            const auto publicKey = msg.payload.value("publicKey", "");
            const auto identity = msg.payload.find("identity");
            if (!memberId.empty() && !publicKey.empty() && identity != msg.payload.end() && identity->is_object()) {
                // Host 公告是加密控制消息，但 Client 仍会重新验证其中的成员签名，
                // 并拒绝与此前已验证 Server 成员列表冲突的内容。
                rememberVerifiedMemberIdentity(memberId, username, displayName, publicKey, *identity, fingerprint, "member_identity");
            }
        }
        return;
    }

    if (msg.type == "nickname_update") {
        const auto relaySenderId = msg.payload.value("relaySenderId", "");
        const auto actorId = msg.payload.value("actorId", "");
        const auto actorKind = msg.payload.value("actorKind", "");
        const auto displayName = msg.payload.value("displayName", "");
        if (relaySenderId.empty() || actorId != relaySenderId ||
            (actorId == chat::protocol::HostActorId && actorKind != chat::protocol::HostActorKind) ||
            (actorId != chat::protocol::HostActorId && actorKind != chat::protocol::ClientActorKind) ||
            !validNicknameCommandValue(displayName)) {
            chatEmit(mCallbacks.onError, "Dropped invalid encrypted nickname update");
            return;
        }

        std::string fingerprint;
        {
            std::lock_guard<std::mutex> lock(mMembersMutex);
            mMemberNamesById[actorId] = displayName;
            const auto fp = mMemberFingerprintsById.find(actorId);
            if (fp != mMemberFingerprintsById.end()) fingerprint = fp->second;
        }
        if (!fingerprint.empty()) {
            chatEmit(mCallbacks.onStatus, "PKI member verified: " + displayName + " / " + actorId + " / " + fingerprint);
        }
        chatEmit(mCallbacks.onStatus, "Nickname updated: " + displayName);
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

void ClientSessionCore::handleRelayBinaryChunk(const std::string& senderKey, const Message& msg) {
    // 二进制分片到达该函数前仍位于加密中继 envelope 内。
    // 该函数只重组已经解密的分片。
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

bool ClientSessionCore::bufferEarlyAttachmentChunk(
    const std::string& senderKey,
    const std::string& transferId,
    const Message& msg) {
    if (transferId.empty()) return false;
    auto& chunks = mEarlyAttachmentChunks[earlyAttachmentKey(senderKey, transferId)];
    if (chunks.size() >= EarlyAttachmentChunkLimit) return false;
    chunks.push_back(msg);
    return true;
}

void ClientSessionCore::drainEarlyAttachmentChunks(const std::string& senderKey, const std::string& transferId) {
    const auto key = earlyAttachmentKey(senderKey, transferId);
    auto found = mEarlyAttachmentChunks.find(key);
    if (found == mEarlyAttachmentChunks.end()) return;

    auto chunks = std::move(found->second);
    mEarlyAttachmentChunks.erase(found);
    for (const auto& chunk : chunks) {
        handleRelayBinaryChunk(senderKey, chunk);
    }
}

void ClientSessionCore::rememberTextHistory(const Message& msg, bool isOwn) {
    if (!mMessageHistory || msg.type != "text") return;
    try {
        mMessageHistory->appendText(chat::local_message::makeTextRecord(msg, isOwn));
    }
    catch (const std::exception& e) {
        chatEmit(mCallbacks.onStatus, std::string("Local message history warning: ") + e.what());
    }
}

std::string ClientSessionCore::messageHistoryJson(std::size_t limit) const {
    if (!mMessageHistory) return "[]";
    return mMessageHistory->historyJson(limit);
}

// 以加密元数据加后续加密中继分片的形式发送图片。
bool ClientSessionCore::sendImage(const std::string& filePath) {
    return sendImageTo("", filePath);
}

bool ClientSessionCore::sendImageTo(const std::string& target, const std::string& filePath) {
    const auto targetName = trimCopy(target);
    const auto targetId = resolveMemberId(targetName);
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

// 以加密元数据加后续加密中继分片的形式发送文本资料。
bool ClientSessionCore::sendTextFile(const std::string& filePath) {
    return sendTextFileTo("", filePath);
}

bool ClientSessionCore::sendTextFileTo(const std::string& target, const std::string& filePath) {
    const auto targetName = trimCopy(target);
    const auto targetId = resolveMemberId(targetName);
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

// 以加密元数据加后续加密中继分片的形式发送短 WAV 语音。
bool ClientSessionCore::sendVoice(const std::string& filePath) {
    return sendVoiceTo("", filePath);
}

bool ClientSessionCore::sendVoiceTo(const std::string& target, const std::string& filePath) {
    const auto targetName = trimCopy(target);
    const auto targetId = resolveMemberId(targetName);
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
    const bool reliable = isReliablePayloadType(msg.type);
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

bool ClientSessionCore::sendPreparedRelayMessage(ReliableOutbound outbound, bool emitNotice) {
    if (!chat::secure_relay::hasUsableGroupKey(mGroupKey)) {
        chatEmit(mCallbacks.onStatus, "Waiting for room group key");
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
        mGroupKeyEpoch,
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

void ClientSessionCore::ensureReliableFields(Message& msg) {
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

void ClientSessionCore::rememberReliableOutbound(const ReliableOutbound& outbound) {
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

bool ClientSessionCore::rememberReliableInbound(const Message& msg) {
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

void ClientSessionCore::sendReliableNotice(const ReliableOutbound& outbound) {
    Message notice;
    notice.type = "relay_notice";
    notice.from = mDisplayName;
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

void ClientSessionCore::handleReliableNotice(const Message& msg) {
    if (!msg.payload.is_object()) return;
    const auto messageId = payloadStringField(msg, "messageId");
    const auto payloadHash = payloadStringField(msg, "payloadHash");
    const auto senderId = payloadStringField(msg, "senderId");
    const auto targetId = payloadStringField(msg, "targetId");
    if (messageId.empty() || payloadHash.empty() || senderId.empty()) return;
    if (senderId == mClientId) return;
    if (!targetId.empty() && targetId != mClientId) return;

    {
        std::lock_guard<std::mutex> lock(mReliableMutex);
        const auto existing = mReliableSeen.find(messageId);
        if (existing != mReliableSeen.end() && existing->second == payloadHash) return;
    }

    Message missing;
    missing.type = "missing_message";
    missing.from = mDisplayName;
    missing.payload = {
        {"messageId", messageId},
        {"payloadHash", payloadHash},
        {"epoch", mGroupKeyEpoch},
        {"targetSenderId", senderId},
        {"requesterId", mClientId}
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
    sendRelayMessage(missing, mClientId, mDisplayName, chat::protocol::ClientActorKind, senderId);
}

void ClientSessionCore::handleMissingMessage(const Message& msg) {
    if (!msg.payload.is_object()) return;
    const auto targetSenderId = payloadStringField(msg, "targetSenderId");
    if (!targetSenderId.empty() && targetSenderId != mClientId) return;
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
    Message meta = attachment::makeBinaryMeta(metaType, mDisplayName, filePath, mime, bytes.size());
    const auto fileHash = attachment::sha256Hex(bytes);
    const auto chunkHashes = attachment::chunkSha256Hexes(bytes, attachment::RelayChunkBytes);
    const auto merkleRoot = attachment::merkleRootForChunkHashes(chunkHashes);
    // actor 元数据让 UI 在解密后区分发送者身份，
    // 同时中继元数据仍绑定到 Server 侧连接状态。
    meta.payload["actorId"] = mClientId;
    meta.payload["actorKind"] = chat::protocol::ClientActorKind;
    meta.payload["displayName"] = mDisplayName;
    meta.payload["fileHash"] = fileHash;
    meta.payload["chunkSize"] = static_cast<std::uint64_t>(attachment::RelayChunkBytes);
    meta.payload["chunkCount"] = static_cast<std::uint64_t>(chunkHashes.size());
    meta.payload["chunkHashes"] = chunkHashes;
    meta.payload["merkleRoot"] = merkleRoot;
    markPrivateTarget(meta, targetId, targetName);
    if (!sendRelayMessage(meta, mClientId, mDisplayName, chat::protocol::ClientActorKind, targetId)) {
        return false;
    }

    const auto transferId = attachment::transferIdFromMessage(meta);
    for (std::size_t offset = 0; offset < bytes.size(); offset += attachment::RelayChunkBytes) {
        const auto chunkSize = (std::min)(attachment::RelayChunkBytes, bytes.size() - offset);
        const auto chunkIndex = offset / attachment::RelayChunkBytes;
        Message chunk;
        // 每个分片都是独立的应用 Message，并由 sendRelayMessage 分别加密，
        // 因此大附件不会以明文传输。
        chunk.type = binaryType;
        chunk.from = mDisplayName;
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
            {"fileHash", fileHash},
            {"actorId", mClientId},
            {"actorKind", chat::protocol::ClientActorKind},
            {"displayName", mDisplayName}
        };
        markPrivateTarget(chunk, targetId, targetName);
        if (!sendRelayMessage(chunk, mClientId, mDisplayName, chat::protocol::ClientActorKind, targetId)) {
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
        chatEmit(mCallbacks.onStatus, reason);
    }
}

void ClientSessionCore::enqueueSignalingMessage(std::string payload, std::string relayUrl) {
    {
        std::lock_guard<std::mutex> lock(mSignalingQueueMutex);
        if (mSignalingWorkerStopping.load()) return;
        mSignalingQueue.push_back({std::move(payload), std::move(relayUrl)});
    }
    mSignalingQueueCv.notify_one();
}

void ClientSessionCore::signalingWorkerLoop() {
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

        // JSON 解析、PKI 证书验证和 GKA contribution 生成可能相对耗时。
        // 将这些工作移出 WSS 回调线程，可避免应用仍在认证上一帧时
        // libdatachannel 关闭 TLS socket。
        handleSignalingMessage(frame);
    }
}

void ClientSessionCore::stopSignalingWorker() {
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

// 处理来自 Server WebSocket 的房间控制消息和加密中继消息。
void ClientSessionCore::handleSignalingMessage(const SignalingFrame& frame) {
    if (mStopped.load() || mShutdownRequested.load()) return;
    const auto& s = frame.payload;
    const auto& relayUrl = frame.relayUrl;

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
            // 后续签名 GKA contribution 使用 Server 接受的显示名。
            // Host 会用成员表验证该字段，本地副本保持同步可避免不必要的 GKA 拒绝。
            const auto acceptedUsername = j.value("username", mUsername);
            if (!acceptedUsername.empty()) {
                mUsername = acceptedUsername;
            }
            const auto acceptedPublicKey = j.value("publicKey", "");
            if (acceptedPublicKey != mMemberKeys.publicKey) {
                chatEmit(mCallbacks.onError, "Join response public key does not match this Client session");
                requestShutdown("Host approval verification failed");
                return;
            }
            const bool rejoin = j.value("rejoin", false);
            const auto hostPublicKey = j.value("hostPublicKey", "");
            const auto hostUsername = j.value("hostUsername", chat::protocol::HostActorId);
            const auto hostIdentity = j.find("hostIdentity");
            const auto admissionSignResponse = j.find("admissionSignResponse");
            if (!mIdentity.enabled()) {
                if (admissionSignResponse == j.end() || !admissionSignResponse->is_object()) {
                    chatEmit(mCallbacks.onError, "Join approval is missing signed member certificate response");
                    requestShutdown("Member certificate signing response missing");
                    return;
                }
                try {
                    const auto responsePlaintext = chat::certs::decryptAdmissionPayload(
                        mRoomDir,
                        "sign_response",
                        *admissionSignResponse);
                    const auto signResponse = responsePlaintext.find("signResponse");
                    if (signResponse == responsePlaintext.end() || !signResponse->is_object()) {
                        throw std::runtime_error("admission sign response is missing signResponse");
                    }
                    const auto installed = chat::certs::installRoomMemberCertificateJson(
                        mRoomDir,
                        *signResponse,
                        mUsername);
                    const auto material = chat::certs::loadRoomRuntimeMaterial(mRoomDir, mUsername, false, true);
                    mIdentity = chat::pki_application::loadFromFiles(
                        material.trustStoreFile,
                        material.identityCertFile,
                        material.identityKeyFile,
                        mKeyPassword);
                    chatEmit(mCallbacks.onStatus, "PKI identity ready: " + mIdentity.fingerprint());
                    chatEmit(mCallbacks.onStatus, "Room member certificate installed: " + installed.memberFingerprint);
                }
                catch (const std::exception& e) {
                    chatEmit(mCallbacks.onError, std::string("Member certificate install failed: ") + e.what());
                    requestShutdown("Member certificate install failed");
                    return;
                }
            }
            if (hostPublicKey.empty() || hostIdentity == j.end() || !hostIdentity->is_object()) {
                // Client 只有认证 Host 签名的 identity/publicKey 绑定后才能参与 GKA。
                // 此处字段缺失通常表示仍在运行旧 Server 构建。
                if (!rejoin) {
                    chatEmit(
                        mCallbacks.onError,
                        "Host identity is missing from join response; check that Server, Host, and Client are the same build");
                    requestShutdown("Host identity verification failed");
                    return;
                }
            }
            if (hostIdentity != j.end() && hostIdentity->is_object() && !hostPublicKey.empty()) {
                const auto hostDisplayName = j.value("hostDisplayName", hostUsername);
                if (!rememberVerifiedMemberIdentity(
                        chat::protocol::HostActorId,
                        hostUsername,
                        hostDisplayName,
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
            }
            const auto approvalRequestId = j.value("approvalRequestId", "");
            const auto approvalDigest = j.value("approvalPayloadDigest", "");
            const auto approvalEpoch = j.value("approvalEpoch", 0ULL);
            const auto approvalControl = j.find("approvalControl");
            if (!rejoin) {
                if (approvalRequestId.empty() || approvalDigest.empty() ||
                    approvalControl == j.end() || !approvalControl->is_object() ||
                    approvalDigest != pendingJoinDigest(approvalRequestId, mUsername, mMemberKeys.publicKey)) {
                    chatEmit(mCallbacks.onError, "Join response is missing a valid Host approval signature");
                    requestShutdown("Host approval verification failed");
                    return;
                }
                try {
                    const auto approvalSigner = mIdentity.verifyRoomControl(
                        mRoomId,
                        mRoomToken,
                        "approve_join",
                        approvalEpoch,
                        approvalDigest,
                        *approvalControl);
                    std::lock_guard<std::mutex> lock(mMembersMutex);
                    const auto hostFp = mMemberFingerprintsById.find(chat::protocol::HostActorId);
                    if (hostFp != mMemberFingerprintsById.end() && hostFp->second != approvalSigner.fingerprint) {
                        throw std::runtime_error("approval signer is not the verified Host");
                    }
                }
                catch (const std::exception& e) {
                    chatEmit(mCallbacks.onError, std::string("Host approval rejected: ") + e.what());
                    requestShutdown("Host approval verification failed");
                    return;
                }
            }
            if (const auto membershipEvent = j.find("membershipEvent");
                membershipEvent != j.end() && membershipEvent->is_object()) {
                // approve_join 附带 Host 签名的成员资格事件。
                // 立即记住它，避免等下一轮 forum sync 才能打开留言板记录。
                rememberForumMembershipEvent(*membershipEvent);
            }
            const bool alreadyJoined = mJoinedRoom.exchange(true);
            if (!alreadyJoined) {
                chatEmit(mCallbacks.onLog, "own_actor_id " + mClientId);
                chatEmit(
                    mCallbacks.onStatus,
                    std::string(rejoin ? "Rejoined room " : "Joined room ") + mRoomId +
                        " as " + mUsername + " (" + mClientId + ")");
                if (!chat::secure_relay::hasUsableGroupKey(mGroupKey)) {
                    chatEmit(mCallbacks.onStatus, "Waiting for room group key");
                }
                requestForumSync();
            }
        }
        else if (type == "join_pending") {
            if (mJoinedRoom.load()) return;
            const auto requestId = j.value("requestId", "");
            chatEmit(
                mCallbacks.onStatus,
                "Join request is waiting for Host approval");
        }
        else if (type == "room_members") {
            // 保存最新成员显示名、username 和 id 映射。
            // 私信解析只使用证书指纹前缀，显示名仅供 UI 展示。
            // 如果 Server 包含已签名成员 identity，离开 mutex 后再验证，
            // 避免 OpenSSL 工作阻塞 UI/成员表读取。
            std::ostringstream members;
            bool first = true;
            std::vector<json> identityCandidates;
            {
                std::lock_guard<std::mutex> lock(mMembersMutex);
                for (const auto& member : j.value("memberInfos", json::array())) {
                    if (!member.is_object()) continue;
                    const auto id = member.value("id", "");
                    const auto username = member.value("username", id);
                    const auto displayName = member.value("displayName", username);
                    auto shownName = displayName.empty() ? username : displayName;
                    if (!id.empty()) {
                        const auto knownName = mMemberNamesById.find(id);
                        if (knownName == mMemberNamesById.end() || knownName->second.empty()) {
                            mMemberNamesById[id] = shownName;
                        }
                        else {
                            shownName = knownName->second;
                        }
                        mMemberUsernamesById[id] = username.empty() ? id : username;
                        if (member.contains("publicKey") && member.contains("identity")) {
                            identityCandidates.push_back(member);
                        }
                    }
                    // 发出显示名/id，使 UI Client 不解析原始信令 JSON。
                    if (!first) members << "; ";
                    members << shownName << " / " << id;
                    first = false;
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
                const auto username = member.value("username", id);
                const auto displayName = member.value("displayName", username);
                const auto publicKey = member.value("publicKey", "");
                const auto identity = member.find("identity");
                if (identity != member.end() && identity->is_object()) {
                    try {
                        // Host 重连时 Server 会重新广播 Host identity。
                        // Client 必须重新验证它，而不是相信“同一个 room token”
                        // 就仍然是同一个 Host。
                        const auto verified = mIdentity.verifyJoinRoom(mRoomId, username, publicKey, *identity);
                        {
                            std::lock_guard<std::mutex> lock(mMembersMutex);
                            const auto oldFp = mMemberFingerprintsById.find(id);
                            if (oldFp != mMemberFingerprintsById.end() && oldFp->second != verified.fingerprint) {
                                chatEmit(mCallbacks.onError, "Rejected changed Host identity in room member list");
                                requestShutdown("Host identity changed");
                                return;
                            }
                        }
                        // Host 重连会生成新的 X25519 session public key。
                        // 只要新公钥由同一 Host 证书签名绑定，且证书 fingerprint 未变，
                        // 就更新 session key；这不是 Host 身份被替换。
                        rememberVerifiedMemberIdentity(
                            id,
                            username,
                            displayName,
                            publicKey,
                            *identity,
                            verified.fingerprint,
                            "room_members",
                            true);
                    }
                    catch (const std::exception& e) {
                        chatEmit(mCallbacks.onError, std::string("Rejected Host identity in room member list: ") + e.what());
                        requestShutdown("Host identity verification failed");
                        return;
                    }
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
        else if (type == "stored_group_state") {
            const auto envelope = j.find("envelope");
            if (envelope == j.end() || !envelope->is_object()) {
                chatEmit(mCallbacks.onError, "Stored group state is missing");
                return;
            }
            try {
                const auto plaintext = mIdentity.openSealedText("group_state", *envelope);
                const auto groupState = chat::protocol::parseJsonObjectWithBudget(
                    plaintext,
                    chat::protocol::MaxSignalingMessageBytes,
                    "stored group state");
                const auto epoch = groupState.value("epoch", 0ULL);
                if (epoch <= mGroupKeyEpoch) {
                    chatEmit(mCallbacks.onStatus, "Stored group state is current or stale");
                    return;
                }
                chatEmit(mCallbacks.onStatus, "Stored group state received");
                if (!installGroupState(groupState, epoch, true)) return;
                mGroupKeyEpoch = epoch;
                chatEmit(mCallbacks.onStatus, "Room group key restored");
                connectRemainingRelays();
                publishNickname();
                requestForumSync();
            }
            catch (const std::exception& e) {
                chatEmit(mCallbacks.onError, std::string("Stored group state rejected: ") + e.what());
            }
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
                const auto knownHostFingerprint = mMemberFingerprintsById.find(chat::protocol::HostActorId);
                if (knownHostFingerprint != mMemberFingerprintsById.end() &&
                    !knownHostFingerprint->second.empty() &&
                    knownHostFingerprint->second != verified.fingerprint) {
                    chatEmit(mCallbacks.onError, "Rejected group key from changed Host identity");
                    requestShutdown("Host identity changed");
                    return;
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
                chatEmit(mCallbacks.onStatus, "Dropped replayed or stale room group key");
                return;
            }
            // 安装密钥前会检查 epoch，因此重放旧 group_key 无法让 Client 回滚到旧 K_G。
            // 解密后的 group state 会先被验证，再在本地派生 K_G。
            const auto groupState = chat::secure_relay::decryptGroupStateForMember(
                j,
                mRoomToken,
                mClientId,
                mMemberKeys.privateKey);
            if (!installGroupState(groupState, epoch, false)) return;
            mGroupKeyEpoch = epoch;
            chatEmit(mCallbacks.onStatus, "Room group key ready");
            connectRemainingRelays();
            publishNickname();
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
            const auto envelopeEpoch = j.value("epoch", 0ULL);
            if (envelopeEpoch != mGroupKeyEpoch) {
                chatEmit(
                    mCallbacks.onStatus,
                    "Dropped encrypted relay for epoch " + std::to_string(envelopeEpoch) +
                        "; current epoch is " + std::to_string(mGroupKeyEpoch));
                return;
            }
            if (!rememberRelayEnvelope(j)) return;
            Message msg;
            try {
                msg = chat::secure_relay::decryptMessageWithGroupKey(j, mRoomToken, mGroupKey);
            }
            catch (const std::exception& e) {
                chatEmit(
                    mCallbacks.onError,
                    "Dropped encrypted relay that cannot be opened with current room group key: " + std::string(e.what()));
                return;
            }
            const auto relayTargetId = msg.payload.value("relayTargetId", "");
            if (!relayTargetId.empty() && relayTargetId != mClientId) {
                // 投递错误的私发中继会在打开内层双方私发加密前被忽略。
                // 该路径保持静默，使非目标成员无法得知刚刚发生过私发消息。
                return;
            }
            if (isReliablePayloadType(msg.type) && !rememberReliableInbound(msg)) {
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
        else if (type == chat::forum_board::RecordsType) {
            handleForumRecords(
                j.value("records", json::array()),
                j.value("membershipEvents", json::array()));
        }
        else if (type == "moderation") {
            // Server 转发的管理通知。它不是终止性错误；
            // Host 仍是请求状态变化的权威。
            chatEmit(mCallbacks.onStatus, j.value("message", "moderation state changed"));
        }
        else if (type == "host_disconnected") {
            // Host 暂离时，Client 保留当前连接和当前 epoch，
            // 等待 Host 重新接管后轮换密钥。
            chatEmit(mCallbacks.onStatus, "Host disconnected");
        }
        else if (type == "join_rejected") {
            const auto requestId = j.value("requestId", "");
            const auto reason = j.value("reason", "join request rejected by host");
            const auto epoch = j.value("epoch", 0ULL);
            const auto payloadDigest = j.value("payloadDigest", "");
            const auto control = j.find("control");
            if (requestId.empty() || payloadDigest != pendingRejectDigest(requestId, reason) ||
                control == j.end() || !control->is_object()) {
                chatEmit(mCallbacks.onError, "Rejected malformed join rejection");
                return;
            }
            try {
                mIdentity.verifyRoomControl(
                    mRoomId,
                    mRoomToken,
                    "reject_pending_join",
                    epoch,
                    payloadDigest,
                    *control);
            }
            catch (const std::exception& e) {
                chatEmit(mCallbacks.onError, std::string("Rejected unsigned join rejection: ") + e.what());
                return;
            }
            mSawErrorFrame.store(true);
            chatEmit(mCallbacks.onError, "Host rejected join request: " + reason);
            requestShutdown("Host rejected join request");
        }
        else if (type == "room_closed") {
            const auto reason = j.value("reason", "room closed");
            const auto epoch = j.value("epoch", 0ULL);
            const auto payloadDigest = j.value("payloadDigest", "");
            const auto control = j.find("control");
            if (control == j.end() || !control->is_object() ||
                payloadDigest != chat::cert_utils::sha256Hex(reason)) {
                chatEmit(mCallbacks.onError, "Rejected unsigned or malformed room close event");
                return;
            }
            try {
                const auto verified = mIdentity.verifyRoomControl(
                    mRoomId,
                    mRoomToken,
                    "close_room",
                    epoch,
                    payloadDigest,
                    *control);
                std::lock_guard<std::mutex> lock(mMembersMutex);
                const auto hostFp = mMemberFingerprintsById.find(chat::protocol::HostActorId);
                if (hostFp != mMemberFingerprintsById.end() && hostFp->second != verified.fingerprint) {
                    throw std::runtime_error("room close signer is not the verified Host");
                }
            }
            catch (const std::exception& e) {
                chatEmit(mCallbacks.onError, std::string("Rejected room close event: ") + e.what());
                return;
            }
            mSawErrorFrame.store(true);
            requestShutdown("Room is no longer available: " + reason);
        }
        else if (type == "error") {
            mSawErrorFrame.store(true);
            const std::string message = j.value("message", "unknown");
            if (message == "host disconnected") {
                chatEmit(mCallbacks.onStatus, "Host disconnected");
            }
            else if (message == "room not found" && mRelayUrls.size() > 1) {
                for (std::size_t i = 0; i < mRelayUrls.size(); ++i) {
                    if (mRelayUrls[i] == relayUrl) {
                        markRelayFailure(i, relayUrl, "offline");
                        break;
                    }
                }
                chatEmit(mCallbacks.onStatus, "Relay has not opened this room yet: " + relayLabel(relayUrl));
                if (!mIdentity.enabled() && !mJoinedRoom.load()) {
                    connectAdmissionRelay();
                }
            }
            else if (message == "invalid username or password" ||
                     message == "invalid room or username" ||
                     message == "room is full" ||
                     message == "room closed" ||
                     message == "room not found" ||
                     message == "missing roomId") {
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
                // 非准入流程的中继错误不被信任为终止性错误。
                // 恶意 Server 仍可关闭 WebSocket，但伪造的普通错误不应让 Client 主动离开房间。
                chatEmit(mCallbacks.onError, "Signaling server error: " + message);
            }
        }
    }
    catch (const std::exception& e) {
        chatEmit(mCallbacks.onError, std::string("Bad signaling message: ") + e.what());
    }
}

void ClientSessionCore::sendForumPost(const std::string& text) {
    if (!mIdentity.enabled()) {
        chatEmit(mCallbacks.onError, "Forum post requires room member certificate");
        return;
    }
    if (mClientId.empty()) {
        chatEmit(mCallbacks.onStatus, "Client identity is not ready yet");
        return;
    }

    std::vector<chat::forum_board::Recipient> recipients;
    std::unordered_set<std::string> recipientFingerprints;
    recipients.push_back({
        mClientId,
        mDisplayName.empty() ? mUsername : mDisplayName,
        mIdentity.fingerprint(),
        mIdentity.signJoinRoom(mRoomId, mUsername, mMemberKeys.publicKey)
    });
    recipientFingerprints.insert(mIdentity.fingerprint());
    {
        std::lock_guard<std::mutex> lock(mMembersMutex);
        for (const auto& [memberId, fingerprint] : mMemberFingerprintsById) {
            if (fingerprint.empty() || recipientFingerprints.find(fingerprint) != recipientFingerprints.end()) continue;
            const auto identity = mMemberIdentityObjectsById.find(memberId);
            if (identity == mMemberIdentityObjectsById.end()) continue;
            const auto displayName = mMemberNamesById.find(memberId);
            recipients.push_back({
                memberId,
                displayName == mMemberNamesById.end() ? memberId : displayName->second,
                fingerprint,
                identity->second
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
            mClientId,
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

        std::vector<std::shared_ptr<rtc::WebSocket>> relays;
        std::vector<std::string> urls;
        std::vector<bool> open;
        {
            std::lock_guard<std::mutex> lock(mRelayMutex);
            relays = mRelays;
            urls = mRelayUrls;
            open = mRelayOpen;
        }
        const auto payload = msg.dump();
        std::size_t sent = 0;
        for (std::size_t i = 0; i < relays.size(); ++i) {
            const auto& relay = relays[i];
            const bool usable = i < open.size() && open[i] && relay && !relay->isClosed();
            if (!usable) continue;
            const auto ok = relay->send(payload);
            if (i < urls.size()) {
                try {
                    chat::relay_pool::recordRelaySend(mRoomDir, urls[i], false, ok);
                }
                catch (...) {
                }
            }
            if (ok) ++sent;
        }
        rememberForumRecord(record);
        emitRelayStatus();
        chatEmit(mCallbacks.onStatus, "Forum post sent to relays: " + std::to_string(sent));
    }
    catch (const std::exception& e) {
        chatEmit(mCallbacks.onError, std::string("Forum post failed: ") + e.what());
    }
}

void ClientSessionCore::requestForumSync() {
    if (mRoomToken.empty()) return;
    json msg = {
        {"type", chat::forum_board::SyncType},
        {"roomId", mRoomToken}
    };
    std::vector<std::shared_ptr<rtc::WebSocket>> relays;
    std::vector<std::string> urls;
    std::vector<bool> open;
    {
        std::lock_guard<std::mutex> lock(mRelayMutex);
        relays = mRelays;
        urls = mRelayUrls;
        open = mRelayOpen;
    }
    const auto payload = msg.dump();
    std::size_t sent = 0;
    for (std::size_t i = 0; i < relays.size(); ++i) {
        const auto& relay = relays[i];
        const bool usable = i < open.size() && open[i] && relay && !relay->isClosed();
        if (!usable) continue;
        const auto ok = relay->send(payload);
        if (i < urls.size()) {
            try {
                chat::relay_pool::recordRelaySend(mRoomDir, urls[i], false, ok);
            }
            catch (...) {
            }
        }
        if (ok) ++sent;
    }
    emitRelayStatus();
    chatEmit(mCallbacks.onStatus, "Forum sync requested on relays: " + std::to_string(sent));
}

void ClientSessionCore::handleForumRecords(const json& records, const json& membershipEvents) {
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

bool ClientSessionCore::rememberForumMembershipEvent(const json& event) {
    if (!event.is_object() || !mIdentity.enabled()) return false;
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
        std::string hostFingerprint;
        {
            std::lock_guard<std::mutex> lock(mMembersMutex);
            const auto host = mMemberFingerprintsById.find(chat::protocol::HostActorId);
            if (host != mMemberFingerprintsById.end()) hostFingerprint = host->second;
        }
        if (hostFingerprint.empty() || signer.fingerprint != hostFingerprint) {
            return false;
        }

        std::lock_guard<std::mutex> lock(mMembersMutex);
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

void ClientSessionCore::rememberForumRecord(const json& record) {
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

std::string ClientSessionCore::forumHistoryJson(std::size_t limit) const {
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
