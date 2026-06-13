#include "host_session_core.hpp"

#include "attachment_transfer.hpp"
#include "secure_relay.hpp"

#include <algorithm>
#include <cstddef>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace {
namespace attachment = chat::attachment;

// Returns a copy without surrounding ASCII whitespace.
std::string trimCopy(std::string value) {
    const auto first = value.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) return "";
    const auto last = value.find_last_not_of(" \t\r\n");
    return value.substr(first, last - first + 1);
}

bool parseDirectPrefix(const std::string& line, std::string& target, std::string& body) {
    // Splits "/to bob ..." before normal command parsing so private text and
    // private attachments reuse the same send functions as room broadcast.
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
    // The encrypted payload carries UI intent; the clear envelope carries only
    // the routing id that Server needs for opaque private delivery.
    msg.payload["private"] = true;
    msg.payload["targetId"] = targetId;
    msg.payload["targetName"] = targetName.empty() ? targetId : targetName;
}

bool attachmentKindForMeta(const std::string& type, attachment::Kind& kind) {
    // Converts decrypted attachment metadata message types into the shared
    // receive-store enum used by Host and Client.
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
    // Binary chunks are still JSON relay messages; this helper identifies the
    // encrypted payload chunks that should be appended to a staged transfer.
    return type == "image_binary" || type == "file_binary" || type == "voice_binary";
}

std::string actorIdFromMessage(const Message& msg) {
    // Prefer stable actor ids over display names when grouping attachment
    // chunks from the same sender.
    if (msg.payload.is_object() && msg.payload.contains("actorId") && msg.payload["actorId"].is_string()) {
        const auto id = msg.payload["actorId"].get<std::string>();
        if (!id.empty()) return id;
    }
    return msg.from;
}

}

// Stores signaling endpoint for a plain SecureChat host session.
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
    const auto groupKey = chat::secure_relay::generateGroupKey();
    mGroupKey.assign(groupKey.begin(), groupKey.end());
    chat::websocket_config::applyClientTlsFromEnvironment(mWsConfig);
    mIdentity = chat::identity_pki::loadFromEnvironment();
}

HostSessionCore::~HostSessionCore() = default;

// Replaces UI/CLI event callbacks used by the session.
void HostSessionCore::setCallbacks(ChatCallbacks callbacks) {
    mCallbacks = std::move(callbacks);
}

// Opens the signaling WebSocket and creates the chat room.
void HostSessionCore::start() {
    mStopped.store(false);
    mWs = std::make_shared<rtc::WebSocket>(mWsConfig);

    mWs->onOpen([this]() {
        chatEmit(mCallbacks.onStatus, "Signaling connected");
        if (chat::websocket_config::hasClientCertificate(mWsConfig)) {
            chatEmit(mCallbacks.onStatus, "mTLS client certificate ready");
        }
        if (mIdentity.enabled()) {
            chatEmit(mCallbacks.onStatus, "PKI identity ready: " + mIdentity.fingerprint());
        }
        json msg = {
            {"type", "create_room"},
            {"roomId", mRoomId},
            {"username", mUsername},
            {"password", mPassword}
        };
        mWs->send(msg.dump());
        std::fill(mPassword.begin(), mPassword.end(), '\0');
        mPassword.clear();
    });

    mWs->onMessage([this](rtc::message_variant data) {
        handleSignalingMessage(rtcMessageToString(data));
    });

    mWs->onClosed([this]() {
        chatEmit(mCallbacks.onStatus, "Signaling closed");
    });

    mWs->onError([this](std::string error) {
        chatEmit(mCallbacks.onError, "Signaling error: " + error);
    });

    mWs->open(mWsUrl);
}

// Closes all host-owned transports and marks the session stopped.
void HostSessionCore::stop() {
    if (mStopped.exchange(true)) return;
    if (mWs && !mWs->isClosed()) {
        mWs->close();
    }

    chatEmit(mCallbacks.onStatus, "Session stopped");
}

// Reports whether the outer CLI/API loop should stop polling this session.
bool HostSessionCore::shouldStop() const {
    return mStopped.load() || (mWs && mWs->isClosed());
}

// Parses one host input line and sends chat, commands, or attachments.
void HostSessionCore::sendLine(const std::string& line) {
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
        mRoomId,
        chat::protocol::HostActorId,
        mUsername,
        chat::protocol::HostActorKind,
        "",
        mGroupKey);
    mWs->send(envelope.dump());
    chatEmit(mCallbacks.onMessage, msg.toJson());
}

void HostSessionCore::sendLineTo(const std::string& target, const std::string& line) {
    // Host can privately address any current Client by name or id. The Server
    // still only sees targetId and ciphertext, not the plaintext body.
    const auto targetId = resolveClientId(trimCopy(target));
    if (targetId.empty()) {
        sendLine(line);
        return;
    }
    if (line.empty()) {
        chatEmit(mCallbacks.onError, "Private message body is empty");
        return;
    }
    if (line.rfind("/image ", 0) == 0 || line.rfind("/img ", 0) == 0) {
        sendImageTo(targetId, trimCopy(line.substr(line.find(' ') + 1)));
        return;
    }
    if (line.rfind("/file ", 0) == 0) {
        sendTextFileTo(targetId, trimCopy(line.substr(line.find(' ') + 1)));
        return;
    }
    if (line.rfind("/voice ", 0) == 0) {
        sendVoiceTo(targetId, trimCopy(line.substr(line.find(' ') + 1)));
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

// Sends an image to all room members through encrypted Server relay.
bool HostSessionCore::sendImage(const std::string& filePath) {
    return sendImageTo("", filePath);
}

bool HostSessionCore::sendImageTo(const std::string& target, const std::string& filePath) {
    const auto targetId = resolveClientId(trimCopy(target));
    return sendAttachmentRelay(
        filePath,
        attachment::Kind::Image,
        "image_meta",
        "image_binary",
        "application/octet-stream",
        targetId);
}

// Sends a text handout to all room members through encrypted Server relay.
bool HostSessionCore::sendTextFile(const std::string& filePath) {
    return sendTextFileTo("", filePath);
}

bool HostSessionCore::sendTextFileTo(const std::string& target, const std::string& filePath) {
    const auto targetId = resolveClientId(trimCopy(target));
    return sendAttachmentRelay(
        filePath,
        attachment::Kind::Text,
        "file_meta",
        "file_binary",
        "text/plain; charset=utf-8",
        targetId);
}

// Sends a short WAV voice clip to all room members through encrypted Server relay.
bool HostSessionCore::sendVoice(const std::string& filePath) {
    return sendVoiceTo("", filePath);
}

bool HostSessionCore::sendVoiceTo(const std::string& target, const std::string& filePath) {
    const auto targetId = resolveClientId(trimCopy(target));
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

    const auto envelope = chat::secure_relay::encryptMessageWithGroupKey(
        msg,
        mRoomId,
        senderId,
        senderName,
        senderKind,
        targetId,
        mGroupKey);
    mWs->send(envelope.dump());
    return true;
}

bool HostSessionCore::sendGroupKeyToClient(const std::string& clientId, const std::string& clientPublicKey) {
    // Host is the GKA coordinator: it wraps the current room group key to a
    // single Client public key and asks the Server to forward the opaque result.
    if (!chat::secure_relay::hasUsableGroupKey(mGroupKey)) {
        chatEmit(mCallbacks.onError, "Room group key is not ready");
        return false;
    }
    if (!mWs || mWs->isClosed()) {
        chatEmit(mCallbacks.onStatus, "Signaling channel is not open yet");
        return false;
    }

    auto envelope = chat::secure_relay::encryptGroupKeyForMember(
        mGroupKey,
        mRoomId,
        clientId,
        clientPublicKey);
    if (mIdentity.enabled()) {
        mIdentity.signGroupKeyEnvelope(envelope);
    }
    mWs->send(envelope.dump());
    chatEmit(mCallbacks.onStatus, "Group key sent to " + displayNameForClient(clientId));
    return true;
}

void HostSessionCore::rotateGroupKey(const std::string& reason) {
    const auto groupKey = chat::secure_relay::generateGroupKey();
    mGroupKey.assign(groupKey.begin(), groupKey.end());
    chatEmit(mCallbacks.onStatus, "Room group key rotated: " + reason);
    sendGroupKeyToAllClients();
}

void HostSessionCore::sendGroupKeyToAllClients() {
    std::vector<std::pair<std::string, std::string>> clients;
    {
        std::lock_guard<std::mutex> lock(mClientsMutex);
        clients.reserve(mClientPublicKeys.size());
        for (const auto& [clientId, publicKey] : mClientPublicKeys) {
            clients.push_back({clientId, publicKey});
        }
    }

    // Server relays one opaque key envelope per member. It never receives the
    // raw group key or participates in the GKA semantics.
    for (const auto& [clientId, publicKey] : clients) {
        sendGroupKeyToClient(clientId, publicKey);
    }
}

bool HostSessionCore::sendAttachmentRelay(
    const std::string& filePath,
    attachment::Kind kind,
    const std::string& metaType,
    const std::string& binaryType,
    const std::string& mime,
    const std::string& targetId) {
    // Attachments are encrypted as metadata plus chunk messages. Passing a
    // targetId switches the Server from broadcast relay to private relay.
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

// Handles signaling WebSocket messages addressed to the host room owner.
void HostSessionCore::handleSignalingMessage(const std::string& s) {
    if (mStopped.load()) return;

    try {
        // Signaling and relay messages are untrusted network input. Apply the
        // same size/depth budget before reading typed fields from the JSON object.
        auto j = chat::protocol::parseJsonObjectWithBudget(
            s,
            chat::protocol::MaxSignalingMessageBytes,
            "signaling message");
        std::string type = j.value("type", "");

        if (type == "room_created") {
            chatEmit(mCallbacks.onStatus, "Room created: " + mRoomId);
            chatEmit(mCallbacks.onStatus, "Group key ready");
        }
        else if (type == "room_members") {
            std::ostringstream members;
            bool first = true;
            for (const auto& member : j.value("memberInfos", json::array())) {
                if (!member.is_object()) continue;
                if (!first) members << "; ";
                const auto id = member.value("id", "");
                // Emit "name / id" for UI display and manual private-message
                // targeting without exposing raw signaling JSON to the UI.
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
            if (!clientId.empty() && publicKey.empty()) {
                chatEmit(mCallbacks.onError, "Client public key is missing: " + username);
                rejectClient(clientId, "client public key is missing");
                return;
            }
            if (!clientId.empty() && mIdentity.enabled()) {
                try {
                    auto identity = j.find("identity");
                    if (identity == j.end()) throw std::runtime_error("client identity is missing");
                    mIdentity.verifyJoinRoom(mRoomId, username, publicKey, *identity);
                    chatEmit(mCallbacks.onStatus, "Client identity verified: " + username);
                }
                catch (const std::exception& e) {
                    chatEmit(mCallbacks.onError, "Client identity rejected: " + username + ": " + e.what());
                    rejectClient(clientId, "client identity verification failed");
                    return;
                }
            }
            {
                std::lock_guard<std::mutex> lock(mClientsMutex);
                mClientNames[clientId] = username;
                if (!publicKey.empty()) mClientPublicKeys[clientId] = publicKey;
            }
            if (!clientId.empty()) {
                chatEmit(mCallbacks.onStatus, "Client joined: " + username);
                rotateGroupKey("member joined");
            }
        }
        else if (type == "client_left") {
            const std::string clientId = j.value("clientId", "");
            removePeer(clientId);
        }
        else if (type == chat::secure_relay::EnvelopeType) {
            if (!chat::secure_relay::hasUsableGroupKey(mGroupKey)) {
                chatEmit(mCallbacks.onError, "Room group key is not ready");
                return;
            }
            const auto msg = chat::secure_relay::decryptMessageWithGroupKey(j, mRoomId, mGroupKey);
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

// Removes a client member and clears any staged attachment transfer from it.
void HostSessionCore::removePeer(const std::string& id) {
    if (id.empty()) return;
    if (mStopped.load()) return;

    std::string displayName = id;
    {
        std::lock_guard<std::mutex> lock(mClientsMutex);
        auto name = mClientNames.find(id);
        if (name != mClientNames.end()) displayName = name->second;
        mClientNames.erase(id);
        mClientPublicKeys.erase(id);
    }
    mPendingTransfers.clear(id);
    chatEmit(mCallbacks.onStatus, "Client left: " + displayName);
    rotateGroupKey("member left");
}

void HostSessionCore::handleRelayMessage(const Message& msg) {
    if (msg.type == "text") {
        chatEmit(mCallbacks.onMessage, msg.toJson());
        return;
    }

    attachment::Kind kind = attachment::Kind::Text;
    const auto senderKey = actorIdFromMessage(msg);
    if (attachmentKindForMeta(msg.type, kind)) {
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

// Stores stable actor identity separately from the human-readable sender label.
void HostSessionCore::setActorMetadata(
    Message& msg,
    const std::string& actorId,
    const std::string& actorKind,
    const std::string& displayName) {
    msg.payload["actorId"] = actorId;
    msg.payload["actorKind"] = actorKind;
    msg.payload["displayName"] = displayName;
}

// Chooses the visible participant name from the signaling username.
std::string HostSessionCore::displayNameForClient(const std::string& id) {
    std::lock_guard<std::mutex> lock(mClientsMutex);
    auto name = mClientNames.find(id);
    return name == mClientNames.end() ? id : name->second;
}

// Resolves a username or user id token into the underlying client id when possible.
std::string HostSessionCore::resolveClientId(const std::string& token) {
    std::lock_guard<std::mutex> lock(mClientsMutex);
    if (mClientNames.find(token) != mClientNames.end()) return token;
    for (const auto& [id, name] : mClientNames) {
        if (name == token) return id;
    }
    return token;
}

void HostSessionCore::rejectClient(const std::string& clientId, const std::string& reason) {
    if (clientId.empty() || !mWs || mWs->isClosed()) return;
    json msg = {
        {"type", "reject_client"},
        {"roomId", mRoomId},
        {"targetId", clientId},
        {"reason", reason}
    };
    mWs->send(msg.dump());
}
