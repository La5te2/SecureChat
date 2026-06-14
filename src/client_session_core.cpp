// Client session implementation. It signs join_room, receives Host group keys,
// decrypts relay envelopes, and sends encrypted chat/attachment messages.
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
    std::string password,
    rtc::WebSocket::Configuration wsConfig)
    : mWsUrl(std::move(url)),
      mRoomId(std::move(room)),
      mUsername(std::move(username)),
      mPassword(std::move(password)),
      mWsConfig(std::move(wsConfig)) {
    // Server registers and routes with this opaque token. The typed room id
    // remains local and is what PKI signatures bind to.
    mRoomToken = chat::secure_relay::deriveRoomToken(mRoomId, mPassword);
    // The X25519 pair is per session. Its public key is signed in join_room;
    // its private key stays local and unwraps the Host-distributed group key.
    mMemberKeys = chat::secure_relay::generateMemberKeyPair();
    chat::websocket_config::applyClientTlsFromEnvironment(mWsConfig);
    // PKI is mandatory for Host/Client startup. Missing environment variables
    // fail here before any room join message is sent.
    mIdentity = chat::identity_pki::loadFromEnvironment();
}

ClientSessionCore::~ClientSessionCore() = default;

// Replaces UI/CLI event callbacks used by the session.
void ClientSessionCore::setCallbacks(ChatCallbacks callbacks) {
    mCallbacks = std::move(callbacks);
}

// Opens the signaling WebSocket and requests to join the configured room.
void ClientSessionCore::start() {
    mWs = std::make_shared<rtc::WebSocket>(mWsConfig);

    mWs->onOpen([this]() {
        chatEmit(mCallbacks.onStatus, "Signaling connected");
        if (chat::websocket_config::hasClientCertificate(mWsConfig)) {
            chatEmit(mCallbacks.onStatus, "mTLS client certificate ready");
        }
        json msg = {
            {"type", "join_room"},
            {"roomId", mRoomToken},
            {"username", mUsername},
            {"password", mRoomToken},
            {"publicKey", mMemberKeys.publicKey}
        };
        chatEmit(mCallbacks.onStatus, "PKI identity ready: " + mIdentity.fingerprint());
        // Sign roomId, username, and temporary X25519 public key so Host can
        // detect replacement before sending this Client a room group key.
        msg["identity"] = mIdentity.signJoinRoom(mRoomId, mUsername, mMemberKeys.publicKey);
        mWs->send(msg.dump());
        // Keep the room password only long enough to authenticate the join.
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

bool ClientSessionCore::rememberVerifiedMemberIdentity(
    const std::string& memberId,
    const std::string& displayName,
    const std::string& publicKey,
    const json& identity,
    const std::string& advertisedFingerprint,
    const std::string& source) {
    // Server/Host may report member lists, but neither statement is trusted as a
    // key authority. The member's certificate signature must bind roomId,
    // displayName, and X25519 publicKey before pairwise sends can use it.
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
        chatEmit(mCallbacks.onError, "Cannot send GKA contribution before Host identity is verified");
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
    mWs->send(envelope.dump());
    chatEmit(mCallbacks.onStatus, "GKA contribution sent");
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
    // All application data arrives after AES-GCM decryption. Text is rendered
    // directly; attachment metadata stages a receive slot; chunks append bytes.
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
                // Host announcements are encrypted control messages, but Clients
                // still re-verify the embedded member signature and reject any
                // conflict with a previously verified Server member listing.
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
        // Metadata opens a receive slot. The following binary chunks must carry
        // the same transferId or they are rejected.
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
    // Binary chunks are still inside encrypted relay envelopes when received by
    // this function. This function only reassembles already-decrypted chunks.
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
    // All text and attachment messages take this path after the room group key
    // is installed. targetId stays inside ciphertext; Server only broadcasts.
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
    // Private messages fail closed: if the target's PKI-bound X25519 public key
    // has not arrived through verified member_identity, do not fall back to room
    // group-key-only private delivery.
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
    // The outer encrypted_relay proves room membership and delivery target. This
    // inner pairwise layer proves only the intended target can read the private
    // payload, even if another member also has the room group key.
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
    // A malicious Server can replay an old outer envelope. AES-GCM authenticates
    // the ciphertext, but freshness is a receiver responsibility, so keep a
    // bounded nonce/tag cache per session.
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
    // Actor metadata lets UI distinguish sender identity after decrypting, while
    // relay metadata is still bound to Server-side connection state.
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
        // Each chunk is its own application Message and is encrypted separately
        // by sendRelayMessage, so large attachments never travel as plaintext.
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
            // Server-assigned clientId becomes the routing id for future private
            // relay and group-key envelopes.
            mClientId = j.value("clientId", "");
            // Use the Server-accepted display name for all later signed GKA
            // contributions. Host verifies this field against its member table,
            // so keeping the local copy in sync prevents avoidable GKA rejection.
            const auto acceptedUsername = j.value("username", mUsername);
            if (!acceptedUsername.empty()) {
                mUsername = acceptedUsername;
            }
            const auto hostPublicKey = j.value("hostPublicKey", "");
            const auto hostUsername = j.value("hostUsername", chat::protocol::HostActorId);
            const auto hostIdentity = j.find("hostIdentity");
            if (!hostPublicKey.empty() && hostIdentity != j.end() && hostIdentity->is_object()) {
                rememberVerifiedMemberIdentity(
                    chat::protocol::HostActorId,
                    hostUsername,
                    hostPublicKey,
                    *hostIdentity,
                    "",
                    "joined");
            }
            chatEmit(mCallbacks.onLog, "own_actor_id " + mClientId);
            chatEmit(
                mCallbacks.onStatus,
                "Joined room " + mRoomId + " as " + mUsername + " (" + mClientId + ")");
            chatEmit(mCallbacks.onStatus, "Waiting for room group key");
        }
        else if (type == "room_members") {
            // Keep latest member name/id map for resolving To: member input. If
            // Server includes signed member identities, verify them after leaving
            // the mutex so OpenSSL work does not block UI/member map reads.
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
                    // Emit "name / id" so UI clients can show a copyable target
                    // id without parsing the raw signaling JSON.
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
                // The Host signature on group_key authenticates the Host identity
                // before member_identity broadcasts arrive. Store the fingerprint
                // immediately so pairwise private messages from Host can be opened.
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
            // Epoch is checked before installing the key, so a replayed old
            // group_key cannot roll the Client back to a previous K_G. The
            // decrypted group state is verified before K_G is derived locally.
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
            if (j.value("roomId", "") != mRoomToken) {
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
                // Wrong-delivered private relay is rejected before the inner
                // pairwise layer is opened. A malicious Server can copy frames,
                // but it cannot make this Client accept another member's targetId.
                chatEmit(mCallbacks.onError, "Dropped encrypted relay for another member");
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
            // Server-originated moderation notice. It is not a terminal error;
            // Host remains the authority that requested the state change.
            chatEmit(mCallbacks.onStatus, j.value("message", "moderation state changed"));
        }
        else if (type == "error") {
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
                // These errors are Host decisions that the Server forwards before
                // closing this Client's socket. Treat them as terminal so the UI
                // shows the real reason instead of only "Signaling connection ended".
                chatEmit(mCallbacks.onError, "Host rejected client: " + message);
                requestShutdown("Host rejected client: " + message);
            }
            else {
                // Non-admission relay errors are not trusted as terminal. A malicious
                // Server can still close the WebSocket, but a forged ordinary error
                // should not make the Client voluntarily leave the room.
                chatEmit(mCallbacks.onError, "Signaling server error: " + message);
            }
        }
    }
    catch (const std::exception& e) {
        chatEmit(mCallbacks.onError, std::string("Bad signaling message: ") + e.what());
    }
}
