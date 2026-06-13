// Host session implementation. It creates rooms, verifies Client PKI identities,
// distributes room group keys, and handles encrypted relay messages.
#include "host_session_core.hpp"

#include "attachment_transfer.hpp"
#include "secure_relay.hpp"

#include <algorithm>
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
    // The Server registers only this opaque token. It cannot recover the room
    // name without the password, while local PKI signatures still bind mRoomId.
    mRoomToken = chat::secure_relay::deriveRoomToken(mRoomId, mPassword);
    // K_G is not generated directly by Host anymore. The first usable room key
    // is derived from the epoch-1 contribution set after room_created.
    chat::websocket_config::applyClientTlsFromEnvironment(mWsConfig);
    // Host identity signs group_key envelopes and verifies Client join identities.
    mIdentity = chat::identity_pki::loadFromEnvironment();
    // Host also owns a member X25519 pair so Clients can send true pairwise
    // private messages to Host without reusing the room group key as the only key.
    mMemberKeys = chat::secure_relay::generateMemberKeyPair();
}

HostSessionCore::~HostSessionCore() {
    // Destruction may happen during UI shutdown. Close transports and join the
    // watchdog without emitting another user-facing "Session stopped" event.
    mStopped.store(true);
    stopGkaTimeoutWorker();
    if (mWs && !mWs->isClosed()) {
        mWs->close();
    }
}

// Replaces UI/CLI event callbacks used by the session.
void HostSessionCore::setCallbacks(ChatCallbacks callbacks) {
    mCallbacks = std::move(callbacks);
}

// Opens the signaling WebSocket and creates the chat room.
void HostSessionCore::start() {
    mStopped.store(false);
    startGkaTimeoutWorker();
    mWs = std::make_shared<rtc::WebSocket>(mWsConfig);

    mWs->onOpen([this]() {
        chatEmit(mCallbacks.onStatus, "Signaling connected");
        if (chat::websocket_config::hasClientCertificate(mWsConfig)) {
            chatEmit(mCallbacks.onStatus, "mTLS client certificate ready");
        }
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
        // Keep the room password only long enough to create the room.
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
    stopGkaTimeoutWorker();
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
    // Host can privately address any current Client by name or id. The private
    // target is stored inside the encrypted payload, so Server only broadcasts.
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

bool HostSessionCore::handleHostCommand(const std::string& line) {
    // Moderation commands are local Host controls, not chat messages. They reuse
    // the normal input box so CLI, WinUI, and Web wrappers get the same behavior.
    std::istringstream input(trimCopy(line));
    std::string command;
    input >> command;
    if (command != "/silence" && command != "/unsilence" && command != "/evict" && command != "/ban") {
        return false;
    }

    std::string target;
    input >> target;
    if (target.empty()) {
        chatEmit(mCallbacks.onError, "Usage: " + command + " <member-name-or-id>");
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
    // Host uses the target's PKI-verified X25519 public key for the inner private
    // layer. This keeps private sends fail-closed instead of silently downgrading
    // to room-group-key-only delivery.
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
    // Clients encrypt private messages to Host's member public key. Host accepts
    // the inner payload only when the sender id has a verified certificate
    // fingerprint recorded from join_room.
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
    // Replay is different from decryption failure: a replayed ciphertext can be
    // valid under AES-GCM. Track recent nonce/tag pairs so a Server cannot replay
    // an old command, text, or attachment chunk in this session.
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
    // Host forwards the verified contribution set, not a Host-chosen raw key.
    // The Client decrypts this state, verifies signatures, and derives K_G itself.
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
    // Host signs the final envelope so Client can reject any modified fields
    // before accepting a room group key.
    mIdentity.signGroupKeyEnvelope(envelope);
    mWs->send(envelope.dump());
    chatEmit(mCallbacks.onStatus, "GKA state sent to " + displayNameForClient(clientId));
    return true;
}

void HostSessionCore::rotateGroupKey(const std::string& reason) {
    // Rotation now starts a contributory GKA epoch. Host contributes randomness
    // like every other member; it no longer selects K_G alone.
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
        // A malicious or broken member must not hold the room forever. The
        // watchdog will evict any Client still missing at this deadline.
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
}

void HostSessionCore::startGkaTimeoutWorker() {
    // Starts one lightweight watchdog for this Host session. It does no network
    // work until rotateGroupKey() publishes a pending epoch and deadline.
    {
        std::lock_guard<std::mutex> lock(mGkaMutex);
        mGkaTimeoutStop = false;
    }
    if (!mGkaTimeoutThread.joinable()) {
        mGkaTimeoutThread = std::thread(&HostSessionCore::gkaTimeoutLoop, this);
    }
}

void HostSessionCore::stopGkaTimeoutWorker() {
    // Cancels any pending epoch and joins the watchdog so shutdown cannot leave a
    // background thread holding callbacks or WebSocket state.
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
    // Waits for the current GKA deadline. A new epoch or a successful commit
    // wakes this loop through mGkaCv, so it only evicts members for the exact
    // epoch that actually timed out.
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
    // Converts a stalled GKA epoch into an explicit membership change. Missing
    // contributors are removed and their current-room certificate fingerprints
    // are banned, then a new epoch starts with the remaining members.
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
        // This epoch cannot commit because at least one member stalled. Clear it
        // before removing members; rotateGroupKey() will build a fresh epoch with
        // the remaining current membership.
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
    // Attachments are encrypted as metadata plus chunk messages. Passing a
    // targetId remains inside encrypted payloads. Server broadcasts every relay
    // frame, and the intended recipient opens the inner pairwise layer.
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
            rotateGroupKey("room created");
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
                    // Host is the trust decision point for joining Clients. Server
                    // forwarded this identity object but did not verify it.
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
                // A new member means a new room group key so the member receives
                // only the current key version through its verified public key.
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
            // Host decrypts application relay exactly like a normal member.
            if (!chat::secure_relay::hasUsableGroupKey(mGroupKey)) {
                chatEmit(mCallbacks.onError, "Room group key is not ready");
                return;
            }
            if (!rememberRelayEnvelope(j)) return;
            auto msg = chat::secure_relay::decryptMessageWithGroupKey(j, mRoomToken, mGroupKey);
            const auto relayTargetId = msg.payload.value("relayTargetId", "");
            if (!relayTargetId.empty() && relayTargetId != chat::protocol::HostActorId) {
                chatEmit(mCallbacks.onError, "Dropped encrypted relay for another member");
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

// Removes a client member and clears any staged attachment transfer from it.
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
        // A malicious or confused Server may report stale/unknown client_left.
        // Ignoring it avoids unnecessary group-key rotation and UI churn.
        chatEmit(mCallbacks.onStatus, "Ignored unknown client_left: " + id);
        return;
    }
    mPendingTransfers.clear(id);
    chatEmit(mCallbacks.onStatus, "Client left: " + displayName);
    // Leaving members must not read future messages, so Host rotates K_G.
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
    // member_identity is a Host-originated control message sent to Clients only;
    // if it loops back, the Host ignores it.
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

void HostSessionCore::handleRelayBinaryChunk(const std::string& senderKey, const Message& msg) {
    // Binary chunks are already decrypted application Messages here. This function
    // checks transfer continuity and appends bytes to the local cache file.
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

    // The announcement is an encrypted control message. Server can relay it but
    // cannot read it. Clients still verify the embedded identity signature so an
    // untrusted Host cannot silently substitute another member's public key.
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
