#include "client_session_core.hpp"

#include "attachment_transfer.hpp"
#include "ice_config.hpp"

#include <algorithm>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace {
namespace attachment = chat::attachment;
constexpr const char* hostTransferKey = chat::protocol::HostActorId;

// Returns a copy without surrounding ASCII whitespace.
std::string trimCopy(std::string value) {
    const auto first = value.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) return "";
    const auto last = value.find_last_not_of(" \t\r\n");
    return value.substr(first, last - first + 1);
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
        requestShutdown("Signaling connection ended");
    });

    mWs->onError([this](std::string error) {
        chatEmit(mCallbacks.onError, "Signaling error: " + error);
        requestShutdown("Signaling failed");
    });

    mWs->open(mWsUrl);
}

// Closes the DataChannel, PeerConnection, and signaling WebSocket.
void ClientSessionCore::stop() {
    mStopped.store(true);
    mRemoteDescriptionReady.store(false);
    mDataChannelOpen.store(false);
    mPendingRemoteCandidates.clear();
    if (mDc && mDc->isOpen()) {
        mDc->close();
    }
    if (mPc) {
        mPc->close();
    }
    if (mWs && !mWs->isClosed()) {
        mWs->close();
    }
    requestShutdown("Stopped");
}

// Reports whether the outer CLI/API loop should stop polling this session.
bool ClientSessionCore::shouldStop() const {
    if (mStopped.load()) return true;
    if (mShutdownRequested.load()) return true;
    if (mWs && mWs->isClosed() && !mDataChannelEverOpened.load()) return true;
    return mDataChannelEverOpened.load() && !mDataChannelOpen.load();
}

// Returns whether the WebRTC DataChannel is currently ready for sends.
bool ClientSessionCore::isDataChannelOpen() const {
    return mDc && mDc->isOpen();
}

// Parses one Client input line and sends the corresponding chat/command/attachment.
void ClientSessionCore::sendLine(const std::string& line) {
    if (line.empty()) return;
    if (!isDataChannelOpen()) {
        chatEmit(mCallbacks.onStatus, "Data channel is not open yet");
        return;
    }
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
        mDc->send(msg.toJson());
    }
    catch (const std::exception& e) {
            chatEmit(mCallbacks.onError, std::string("Input failed: ") + e.what());
    }
}

Message ClientSessionCore::parseInput(const std::string& line) {
    return makeTextMessage(mClientId, line);
}

// Handles host-originated JSON/text payloads. Transport-neutral chat and
// attachment messages stay in session core.
void ClientSessionCore::printDataMessage(const std::string& s) {
    if (mStopped.load() || mShutdownRequested.load()) return;

    bool parsedProtocolMessage = false;
    try {
        const Message msg = Message::fromJson(s);
        parsedProtocolMessage = true;

        if (msg.type == "text") {
            chatEmit(mCallbacks.onMessage, msg.toJson());
        }
        else if (msg.type == "image_meta") {
            const auto transferId = attachment::transferIdFromMessage(msg);
            const auto pending = mPendingTransfers.stage(
                hostTransferKey,
                attachment::Kind::Image,
                transferId,
                msg.name,
                attachment::expectedSizeFromMeta(msg, attachment::Kind::Image));
            Message out = msg;
            out.name = pending.name;
            out.payload["transferId"] = pending.transferId;
            out.payload["name"] = pending.name;
            chatEmit(mCallbacks.onMessage, out.toJson());
            chatEmit(mCallbacks.onStatus, "Image meta received: " + pending.name);
        }
        else if (msg.type == "file_meta") {
            const auto transferId = attachment::transferIdFromMessage(msg);
            const auto pending = mPendingTransfers.stage(
                hostTransferKey,
                attachment::Kind::Text,
                transferId,
                msg.name,
                attachment::expectedSizeFromMeta(msg, attachment::Kind::Text));
            Message out = msg;
            out.name = pending.name;
            out.payload["transferId"] = pending.transferId;
            out.payload["name"] = pending.name;
            chatEmit(mCallbacks.onMessage, out.toJson());
            chatEmit(mCallbacks.onStatus, "File meta received: " + pending.name);
        }
        else if (msg.type == "voice_meta") {
            const auto transferId = attachment::transferIdFromMessage(msg);
            const auto pending = mPendingTransfers.stage(
                hostTransferKey,
                attachment::Kind::Voice,
                transferId,
                msg.name,
                attachment::expectedSizeFromMeta(msg, attachment::Kind::Voice));
            Message out = msg;
            out.name = pending.name;
            out.payload["transferId"] = pending.transferId;
            out.payload["name"] = pending.name;
            chatEmit(mCallbacks.onMessage, out.toJson());
            chatEmit(mCallbacks.onStatus, "Voice meta received: " + pending.name);
        }
        else if (msg.type == "image_binary" || msg.type == "file_binary" || msg.type == "voice_binary") {
            if (msg.payload.contains("transferId") &&
                attachment::transferIdFromMessage(msg) != mPendingTransfers.activeTransferId(hostTransferKey)) {
                throw std::runtime_error("attachment binary marker transfer id does not match pending meta");
            }
            chatEmit(mCallbacks.onStatus, "File binary received");
        }
        else if (msg.type == "attachment_cancel") {
            mPendingTransfers.clear(hostTransferKey);
            chatEmit(mCallbacks.onStatus, "Attachment transfer canceled: " + msg.content);
        }
        else {
            chatEmit(mCallbacks.onMessage, s);
        }
    }
    catch (const std::exception& e) {
        if (!parsedProtocolMessage && mPendingTransfers.has(hostTransferKey)) {
            rtc::binary bytes;
            bytes.reserve(s.size());
            for (unsigned char ch : s) {
                bytes.push_back(static_cast<rtc::byte>(ch));
            }
            printDataBinary(bytes);
            return;
        }

        chatEmit(mCallbacks.onError, std::string("Bad data message: ") + e.what());
    }
}

// Sends an image as metadata followed by a binary DataChannel payload.
bool ClientSessionCore::sendImage(const std::string& filePath) {
    if (!isDataChannelOpen()) {
        chatEmit(mCallbacks.onStatus, "Data channel is not open yet");
        return false;
    }
    if (mClientId.empty()) {
        chatEmit(mCallbacks.onStatus, "Client identity is not ready yet");
        return false;
    }

    const auto bytes = attachment::readFileBytes(filePath, attachment::Kind::Image);
    const auto raw = attachment::toRtcBytes(bytes);
    Message meta = attachment::makeBinaryMeta("image_meta", mClientId, filePath, "application/octet-stream", bytes.size());

    mDc->send(meta.toJson());
    attachment::sendTransferChunks(*mDc, raw, meta, "image_binary", mClientId);
    meta.from = mUsername;
    meta.payload["actorId"] = mClientId;
    meta.payload["actorKind"] = chat::protocol::ClientActorKind;
    meta.payload["displayName"] = mUsername;
    chatEmit(mCallbacks.onMessage, meta.toJson());
    chatEmit(mCallbacks.onImage, filePath);
    return true;
}

// Sends a small text handout as metadata followed by binary file contents.
bool ClientSessionCore::sendTextFile(const std::string& filePath) {
    if (!isDataChannelOpen()) {
        chatEmit(mCallbacks.onStatus, "Data channel is not open yet");
        return false;
    }
    if (mClientId.empty()) {
        chatEmit(mCallbacks.onStatus, "Client identity is not ready yet");
        return false;
    }

    const auto bytes = attachment::readFileBytes(filePath, attachment::Kind::Text);
    const auto raw = attachment::toRtcBytes(bytes);
    Message meta = attachment::makeBinaryMeta("file_meta", mClientId, filePath, "text/plain; charset=utf-8", bytes.size());

    mDc->send(meta.toJson());
    attachment::sendTransferChunks(*mDc, raw, meta, "file_binary", mClientId);
    meta.from = mUsername;
    meta.payload["actorId"] = mClientId;
    meta.payload["actorKind"] = chat::protocol::ClientActorKind;
    meta.payload["displayName"] = mUsername;
    chatEmit(mCallbacks.onMessage, meta.toJson());
    chatEmit(mCallbacks.onFile, filePath);
    return true;
}

// Sends a short WAV voice clip as metadata followed by binary audio contents.
bool ClientSessionCore::sendVoice(const std::string& filePath) {
    if (!isDataChannelOpen()) {
        chatEmit(mCallbacks.onStatus, "Data channel is not open yet");
        return false;
    }
    if (mClientId.empty()) {
        chatEmit(mCallbacks.onStatus, "Client identity is not ready yet");
        return false;
    }

    const auto bytes = attachment::readFileBytes(filePath, attachment::Kind::Voice);
    const auto raw = attachment::toRtcBytes(bytes);
    // Voice is still a DataChannel binary transfer, but uses a distinct
    // meta type so GUI clients can show a client instead of a file row.
    Message meta = attachment::makeBinaryMeta("voice_meta", mClientId, filePath, "audio/wav", bytes.size());

    mDc->send(meta.toJson());
    attachment::sendTransferChunks(*mDc, raw, meta, "voice_binary", mClientId);
    meta.from = mUsername;
    meta.payload["actorId"] = mClientId;
    meta.payload["actorKind"] = chat::protocol::ClientActorKind;
    meta.payload["displayName"] = mUsername;
    chatEmit(mCallbacks.onMessage, meta.toJson());
    chatEmit(mCallbacks.onVoice, filePath);
    return true;
}

// Idempotently marks the Client session closed and releases transport objects.
void ClientSessionCore::requestShutdown(const std::string& reason) {
    if (!mShutdownRequested.exchange(true)) {
        mDataChannelOpen.store(false);
        if (mDc && mDc->isOpen()) {
            mDc->close();
        }
        if (mPc) {
            mPc->close();
        }
        if (mWs && !mWs->isClosed()) {
            mWs->close();
        }
        chatEmit(mCallbacks.onStatus, reason);
    }
}

// Handles signaling messages from the WebSocket bootstrap channel.
void ClientSessionCore::handleSignalingMessage(const std::string& s) {
    if (mStopped.load() || mShutdownRequested.load()) return;

    try {
        // Signaling is untrusted network input before the DataChannel exists,
        // so parse it with an explicit budget and object requirement first.
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
        }
        else if (type == "room_members") {
            std::ostringstream members;
            bool first = true;
            for (const auto& member : j.value("members", json::array())) {
                if (!first) members << "; ";
                members << member.get<std::string>();
                first = false;
            }
            chatEmit(mCallbacks.onStatus, "Room members: " + members.str());
        }
        else if (type == "offer") {
            createPeer(j.at("sdp").get<std::string>());
        }
        else if (type == "ice") {
            const auto candidate = j.at("candidate").get<std::string>();
            if (mPc && mRemoteDescriptionReady.load()) {
                mPc->addRemoteCandidate(rtc::Candidate(candidate));
            }
            else {
                mPendingRemoteCandidates.push_back(candidate);
                chatEmit(mCallbacks.onLog, "Queued remote ICE candidate until offer is applied");
            }
        }
        else if (type == "error") {
            const std::string message = j.value("message", "unknown");
            if (message == "host disconnected" || message == "host disconnected") {
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

// Creates the Client-side PeerConnection from the Host SDP offer.
void ClientSessionCore::createPeer(const std::string& sdp) {
    if (mStopped.load() || mShutdownRequested.load()) return;

    // The Host side is the offerer and creates the DataChannel. The Client side waits
    // for onDataChannel after applying that offer, then answers with its SDP.
    auto config = makePeerConfiguration();
    if (mPc) {
        mPendingRemoteCandidates.clear();
    }
    mRemoteDescriptionReady.store(false);
    mPc = std::make_shared<rtc::PeerConnection>(config);

    mPc->onDataChannel([this](std::shared_ptr<rtc::DataChannel> dc) {
        if (mStopped.load() || mShutdownRequested.load()) return;
        mDc = dc;

        dc->onOpen([this]() {
            if (mStopped.load() || mShutdownRequested.load()) return;
            mDataChannelEverOpened.store(true);
            mDataChannelOpen.store(true);
            chatEmit(mCallbacks.onStatus, "Data channel open");
        });

        dc->onClosed([this]() {
            if (mStopped.load()) return;
            mDataChannelOpen.store(false);
            chatEmit(mCallbacks.onStatus, "Data channel closed");
            requestShutdown("Data channel closed");
        });

        dc->onMessage([this](rtc::message_variant data) {
            if (mStopped.load() || mShutdownRequested.load()) return;
            if (auto bin = std::get_if<rtc::binary>(&data)) {
                printDataBinary(*bin);
                return;
            }
            printDataMessage(rtcMessageToString(data));
        });
    });

    mPc->onStateChange([this](rtc::PeerConnection::State state) {
        if (mStopped.load()) return;
        chatEmit(mCallbacks.onLog, "Peer state: " + std::to_string(static_cast<int>(state)));
        if (state == rtc::PeerConnection::State::Failed ||
            state == rtc::PeerConnection::State::Closed) {
            requestShutdown("Peer connection ended");
        }
        else if (state == rtc::PeerConnection::State::Disconnected &&
                 mDataChannelEverOpened.load()) {
            mDataChannelOpen.store(false);
            requestShutdown("Peer disconnected");
        }
    });

    mPc->onLocalDescription([this](rtc::Description description) {
        if (mStopped.load() || mShutdownRequested.load() || !mWs || mWs->isClosed()) return;
        // This is the answer generated from the Host offer. The signaling server
        // just forwards it; libdatachannel consumes the SDP on the Host side.
        json msg = {
            {"type", "answer"},
            {"roomId", mRoomId},
            {"from", mClientId},
            {"sdp", static_cast<std::string>(description)}
        };
        mWs->send(msg.dump());
    });

    mPc->onLocalCandidate([this](rtc::Candidate candidate) {
        if (mStopped.load() || mShutdownRequested.load() || !mWs || mWs->isClosed()) return;
        // Keep sending ICE candidates as they are discovered. The WebSocket
        // signaling channel exists only to bootstrap the later peer connection.
        json msg = {
            {"type", "ice"},
            {"roomId", mRoomId},
            {"from", mClientId},
            {"target", chat::protocol::HostActorId},
            {"candidate", static_cast<std::string>(candidate)}
        };
        mWs->send(msg.dump());
    });

    mPc->setRemoteDescription(rtc::Description(sdp, "offer"));
    mRemoteDescriptionReady.store(true);
    // WebSocket signaling and libdatachannel callbacks may interleave on busy
    // LANs, so remote ICE received before the offer is applied must be replayed.
    const auto queuedCandidates = std::move(mPendingRemoteCandidates);
    mPendingRemoteCandidates.clear();
    for (const auto& candidate : queuedCandidates) {
        mPc->addRemoteCandidate(rtc::Candidate(candidate));
    }
    if (!queuedCandidates.empty()) {
        chatEmit(mCallbacks.onLog, "Applied queued remote ICE candidates: " + std::to_string(queuedCandidates.size()));
    }
    // Generates the local SDP answer and starts local ICE candidate callbacks.
    mPc->setLocalDescription();
}

// Persists a received binary attachment and emits the matching UI event.
void ClientSessionCore::printDataBinary(const rtc::binary& data) {
    if (mStopped.load() || mShutdownRequested.load()) return;

    std::string transferId;
    try {
        transferId = mPendingTransfers.activeTransferId(hostTransferKey);
        const auto result = mPendingTransfers.appendChunk(hostTransferKey, data);
        if (!result.found) {
            chatEmit(mCallbacks.onError, "Unexpected binary file data");
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
        mPendingTransfers.clear(hostTransferKey);
        if (mDc && mDc->isOpen() && !transferId.empty()) {
            mDc->send(attachment::makeTransferCancel(mClientId, transferId, e.what()).toJson());
        }
        chatEmit(mCallbacks.onError, std::string("File receive failed: ") + e.what());
    }
}
