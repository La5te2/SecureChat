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

// Returns a copy without surrounding ASCII whitespace.
std::string trimCopy(std::string value) {
    const auto first = value.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) return "";
    const auto last = value.find_last_not_of(" \t\r\n");
    return value.substr(first, last - first + 1);
}

bool parseDirectPrefix(const std::string& line, std::string& target, std::string& body) {
    // Splits "/to alice hello" into a routing token and the remaining command
    // body. The body may itself be an attachment command such as "/image p.png".
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
    // The clear envelope exposes only the routing id. The encrypted payload
    // keeps the UI label and marks this item as private.
    msg.payload["private"] = true;
    msg.payload["targetId"] = targetId;
    msg.payload["targetName"] = targetName.empty() ? targetId : targetName;
}

bool attachmentKindForMeta(const std::string& type, attachment::Kind& kind) {
    // Maps decrypted attachment metadata messages back to the receive-store
    // kind so text, image, and voice share the same encrypted relay path.
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
    // Binary chunks are encrypted JSON messages carrying base64 payloads; this
    // distinguishes chunk messages from ordinary text or metadata messages.
    return type == "image_binary" || type == "file_binary" || type == "voice_binary";
}

std::string actorIdFromMessage(const Message& msg) {
    // Attachment reassembly is keyed by stable actor id, not display name,
    // because usernames can collide across reconnects or future UI changes.
    if (msg.payload.is_object() && msg.payload.contains("actorId") && msg.payload["actorId"].is_string()) {
        const auto id = msg.payload["actorId"].get<std::string>();
        if (!id.empty()) return id;
    }
    return msg.from;
}
}

// Stores the signaling target and client credentials.
// Client input maps directly to plain SecureChat protocol messages.
ClientSessionCore::ClientSessionCore(
    std::string url,
    std::string room,
    std::string username,
    std::string password)
    : mWsUrl(std::move(url)),
      mRoomId(std::move(room)),
      mUsername(std::move(username)),
      mPassword(std::move(password)) {
    mMemberKeys = chat::secure_relay::generateMemberKeyPair();
}

ClientSessionCore::~ClientSessionCore() = default;

// Replaces UI/CLI event callbacks used by the session.
void ClientSessionCore::setCallbacks(ChatCallbacks callbacks) {
    mCallbacks = std::move(callbacks);
}

// Opens the signaling WebSocket and requests to join the configured room.
void ClientSessionCore::start() {
    mWs = std::make_shared<rtc::WebSocket>();

    mWs->onOpen([this]() {
        chatEmit(mCallbacks.onStatus, "Signaling connected");
        json msg = {
            {"type", "join_room"},
            {"roomId", mRoomId},
            {"username", mUsername},
            {"password", mPassword},
            {"publicKey", mMemberKeys.publicKey}
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
        requestShutdown("Signaling connection ended");
    });

    mWs->onError([this](std::string error) {
        chatEmit(mCallbacks.onError, "Signaling error: " + error);
        requestShutdown("Signaling failed");
    });

    mWs->open(mWsUrl);
}

// Closes the signaling WebSocket and local transfer state.
void ClientSessionCore::stop() {
    mStopped.store(true);
    if (mWs && !mWs->isClosed()) {
        mWs->close();
    }
    requestShutdown("Stopped");
}

// Reports whether the outer CLI/API loop should stop polling this session.
bool ClientSessionCore::shouldStop() const {
    if (mStopped.load()) return true;
    if (mShutdownRequested.load()) return true;
    return mWs && mWs->isClosed();
}

// Parses one Client input line and sends the corresponding chat/command/attachment.
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
            mRoomId,
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
    const auto targetId = resolveMemberId(trimCopy(target));
    if (targetId.empty()) {
        sendLine(line);
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
    // Client text messages use the server-assigned client id as the protocol
    // sender and keep the human display name in payload metadata.
    return makeTextMessage(mClientId, line);
}

std::string ClientSessionCore::resolveMemberId(const std::string& token) {
    // Private relay needs a concrete member id. Users may type either "host",
    // a client id, or the display name from the latest room_members update.
    if (token.empty()) return "";
    if (token == chat::protocol::HostActorId) return token;

    std::lock_guard<std::mutex> lock(mMembersMutex);
    if (mMemberNamesById.find(token) != mMemberNamesById.end()) return token;
    for (const auto& [id, name] : mMemberNamesById) {
        if (name == token) return id;
    }
    return token;
}

void ClientSessionCore::handleRelayMessage(const Message& msg) {
    // All application data arrives after AES-GCM decryption. Text is rendered
    // directly; attachment metadata stages a receive slot; chunks append bytes.
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

void ClientSessionCore::handleRelayBinaryChunk(const std::string& senderKey, const Message& msg) {
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

// Sends an image as encrypted metadata followed by encrypted relay chunks.
bool ClientSessionCore::sendImage(const std::string& filePath) {
    return sendImageTo("", filePath);
}

bool ClientSessionCore::sendImageTo(const std::string& target, const std::string& filePath) {
    const auto targetId = resolveMemberId(trimCopy(target));
    return sendAttachmentRelay(
        filePath,
        attachment::Kind::Image,
        "image_meta",
        "image_binary",
        "application/octet-stream",
        targetId);
}

// Sends a text handout as encrypted metadata followed by encrypted relay chunks.
bool ClientSessionCore::sendTextFile(const std::string& filePath) {
    return sendTextFileTo("", filePath);
}

bool ClientSessionCore::sendTextFileTo(const std::string& target, const std::string& filePath) {
    const auto targetId = resolveMemberId(trimCopy(target));
    return sendAttachmentRelay(
        filePath,
        attachment::Kind::Text,
        "file_meta",
        "file_binary",
        "text/plain; charset=utf-8",
        targetId);
}

// Sends a short WAV voice clip as encrypted metadata followed by encrypted relay chunks.
bool ClientSessionCore::sendVoice(const std::string& filePath) {
    return sendVoiceTo("", filePath);
}

bool ClientSessionCore::sendVoiceTo(const std::string& target, const std::string& filePath) {
    const auto targetId = resolveMemberId(trimCopy(target));
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
    if (!chat::secure_relay::hasUsableGroupKey(mGroupKey)) {
        chatEmit(mCallbacks.onStatus, "Waiting for room group key");
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

bool ClientSessionCore::sendAttachmentRelay(
    const std::string& filePath,
    attachment::Kind kind,
    const std::string& metaType,
    const std::string& binaryType,
    const std::string& mime,
    const std::string& targetId) {
    // Attachments are sent as one encrypted metadata message followed by
    // encrypted chunks. targetId is empty for room broadcast and set for private
    // delivery through the same Server relay.
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

// Idempotently marks the Client session closed and releases transport objects.
void ClientSessionCore::requestShutdown(const std::string& reason) {
    if (!mShutdownRequested.exchange(true)) {
        if (mWs && !mWs->isClosed()) {
            mWs->close();
        }
        chatEmit(mCallbacks.onStatus, reason);
    }
}

// Handles room control and encrypted relay messages from the Server WebSocket.
void ClientSessionCore::handleSignalingMessage(const std::string& s) {
    if (mStopped.load() || mShutdownRequested.load()) return;

    try {
        // Signaling and relay messages are untrusted network input. Parse with
        // an explicit budget and object requirement before reading fields.
        auto j = chat::protocol::parseJsonObjectWithBudget(
            s,
            chat::protocol::MaxSignalingMessageBytes,
            "signaling message");
        std::string type = j.value("type", "");

        if (type == "joined") {
            mClientId = j.value("clientId", "");
            chatEmit(mCallbacks.onLog, "own_actor_id " + mClientId);
            chatEmit(
                mCallbacks.onStatus,
                "Joined room " + mRoomId + " as " + j.value("username", mClientId) +
                    " (" + mClientId + ")");
            chatEmit(mCallbacks.onStatus, "Waiting for room group key");
        }
        else if (type == "room_members") {
            std::ostringstream members;
            bool first = true;
            {
                std::lock_guard<std::mutex> lock(mMembersMutex);
                mMemberNamesById.clear();
                for (const auto& member : j.value("memberInfos", json::array())) {
                    if (!member.is_object()) continue;
                    const auto id = member.value("id", "");
                    const auto username = member.value("username", id);
                    if (!id.empty()) mMemberNamesById[id] = username;
                    // Emit "name / id" so UI clients can show a copyable target
                    // id without parsing the raw signaling JSON.
                    if (!first) members << "; ";
                    members << username << " / " << id;
                    first = false;
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
            mGroupKey = chat::secure_relay::decryptGroupKeyForMember(j, mRoomId, mClientId, mMemberKeys.privateKey);
            chatEmit(mCallbacks.onStatus, "Room group key ready");
        }
        else if (type == chat::secure_relay::EnvelopeType) {
            if (!chat::secure_relay::hasUsableGroupKey(mGroupKey)) {
                chatEmit(mCallbacks.onError, "Encrypted relay received before room group key");
                return;
            }
            const auto msg = chat::secure_relay::decryptMessageWithGroupKey(j, mRoomId, mGroupKey);
            handleRelayMessage(msg);
        }
        else if (type == "error") {
            const std::string message = j.value("message", "unknown");
            if (message == "host disconnected") {
                requestShutdown("Session stopped");
            }
            else if (message == "invalid username or password" || message == "invalid room password") {
                chatEmit(mCallbacks.onError, "Signaling server error: " + message);
                requestShutdown(message == "invalid room password" ? "Invalid room password" : "Invalid username or password");
            }
            else if (message == "username already in room") {
                chatEmit(mCallbacks.onError, "Signaling server error: " + message);
                requestShutdown("Username already in room");
            }
            else {
                chatEmit(mCallbacks.onError, "Signaling server error: " + message);
                requestShutdown("Session stopped");
            }
        }
    }
    catch (const std::exception& e) {
        chatEmit(mCallbacks.onError, std::string("Bad signaling message: ") + e.what());
    }
}
