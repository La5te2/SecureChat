#include "host_session_core.hpp"

#include "attachment_transfer.hpp"
#include "ice_config.hpp"

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
    srand(static_cast<unsigned>(time(nullptr)));
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

    std::vector<std::shared_ptr<rtc::DataChannel>> dataChannels;
    std::vector<std::shared_ptr<rtc::PeerConnection>> peers;
    {
        std::lock_guard<std::mutex> lock(mPeersMutex);
        for (auto& [_, dc] : mDataChannels) dataChannels.push_back(dc);
        for (auto& [_, peer] : mPeers) peers.push_back(peer);
        mPendingRemoteCandidates.clear();
        mRemoteDescriptionReadyPeers.clear();
    }

    for (auto& dc : dataChannels) {
        if (dc && dc->isOpen()) dc->close();
    }
    for (auto& peer : peers) {
        if (peer) peer->close();
    }
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
    broadcast(msg);
    chatEmit(mCallbacks.onMessage, msg.toJson());
}

// Sends an image to all open client DataChannels.
bool HostSessionCore::sendImage(const std::string& filePath) {
    const auto bytes = attachment::readFileBytes(filePath, attachment::Kind::Image);
    const auto raw = attachment::toRtcBytes(bytes);
    const auto actor = currentHostActorName();
    Message meta = attachment::makeBinaryMeta("image_meta", actor, filePath, "application/octet-stream", bytes.size());
    setCurrentHostActorMetadata(meta);

    broadcast(meta);
    std::vector<std::shared_ptr<rtc::DataChannel>> channels;
    {
        std::lock_guard<std::mutex> lock(mPeersMutex);
        for (auto& [_, dc] : mDataChannels) channels.push_back(dc);
    }
    for (auto& dc : channels) {
        if (dc && dc->isOpen()) attachment::sendTransferChunks(*dc, raw, meta, "image_binary", actor);
    }
    chatEmit(mCallbacks.onMessage, meta.toJson());
    chatEmit(mCallbacks.onImage, filePath);
    return true;
}

// Sends a text handout to all open client DataChannels.
bool HostSessionCore::sendTextFile(const std::string& filePath) {
    const auto bytes = attachment::readFileBytes(filePath, attachment::Kind::Text);
    const auto raw = attachment::toRtcBytes(bytes);
    const auto actor = currentHostActorName();
    Message meta = attachment::makeBinaryMeta("file_meta", actor, filePath, "text/plain; charset=utf-8", bytes.size());
    setCurrentHostActorMetadata(meta);

    broadcast(meta);
    std::vector<std::shared_ptr<rtc::DataChannel>> channels;
    {
        std::lock_guard<std::mutex> lock(mPeersMutex);
        for (auto& [_, dc] : mDataChannels) channels.push_back(dc);
    }
    for (auto& dc : channels) {
        if (dc && dc->isOpen()) attachment::sendTransferChunks(*dc, raw, meta, "file_binary", actor);
    }
    chatEmit(mCallbacks.onMessage, meta.toJson());
    chatEmit(mCallbacks.onFile, filePath);
    return true;
}

// Sends a short WAV voice clip to all open client DataChannels.
bool HostSessionCore::sendVoice(const std::string& filePath) {
    const auto bytes = attachment::readFileBytes(filePath, attachment::Kind::Voice);
    const auto raw = attachment::toRtcBytes(bytes);
    // Voice clips use their own meta type so the GUI can render an inline client.
    const auto actor = currentHostActorName();
    Message meta = attachment::makeBinaryMeta("voice_meta", actor, filePath, "audio/wav", bytes.size());
    setCurrentHostActorMetadata(meta);

    broadcast(meta);
    std::vector<std::shared_ptr<rtc::DataChannel>> channels;
    {
        std::lock_guard<std::mutex> lock(mPeersMutex);
        for (auto& [_, dc] : mDataChannels) channels.push_back(dc);
    }
    for (auto& dc : channels) {
        if (dc && dc->isOpen()) attachment::sendTransferChunks(*dc, raw, meta, "voice_binary", actor);
    }
    chatEmit(mCallbacks.onMessage, meta.toJson());
    chatEmit(mCallbacks.onVoice, filePath);
    return true;
}

// Handles signaling WebSocket messages addressed to the host room owner.
void HostSessionCore::handleSignalingMessage(const std::string& s) {
    if (mStopped.load()) return;

    try {
        // Signaling is still untrusted network input even though it is only
        // used for room setup and ICE exchange. Apply the same size/depth
        // budget before reading typed fields from the JSON object.
        auto j = chat::protocol::parseJsonObjectWithBudget(
            s,
            chat::protocol::MaxSignalingMessageBytes,
            "signaling message");
        std::string type = j.value("type", "");

        if (type == "room_created") {
            chatEmit(mCallbacks.onStatus, "Room created: " + mRoomId);
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
        else if (type == "new_client") {
            std::string clientId = j.value("clientId", "");
            std::string username = j.value("username", clientId);
            {
                std::lock_guard<std::mutex> lock(mPeersMutex);
                mClientNames[clientId] = username;
            }
            if (!clientId.empty()) createPeer(clientId);
        }
        else if (type == "answer") {
            std::string clientId = j.value("clientId", "");
            std::shared_ptr<rtc::PeerConnection> peer;
            {
                std::lock_guard<std::mutex> lock(mPeersMutex);
                auto it = mPeers.find(clientId);
                if (it != mPeers.end()) peer = it->second;
            }
            if (peer) {
                peer->setRemoteDescription(rtc::Description(j.at("sdp").get<std::string>(), "answer"));
                std::vector<std::string> queuedCandidates;
                {
                    std::lock_guard<std::mutex> lock(mPeersMutex);
                    mRemoteDescriptionReadyPeers.insert(clientId);
                    auto queued = mPendingRemoteCandidates.find(clientId);
                    if (queued != mPendingRemoteCandidates.end()) {
                        queuedCandidates = std::move(queued->second);
                        mPendingRemoteCandidates.erase(queued);
                    }
                }
                for (const auto& candidate : queuedCandidates) {
                    peer->addRemoteCandidate(rtc::Candidate(candidate));
                }
                if (!queuedCandidates.empty()) {
                    chatEmit(mCallbacks.onLog, "Applied queued remote ICE candidates for " + clientId + ": " + std::to_string(queuedCandidates.size()));
                }
            }
        }
        else if (type == "ice") {
            std::string clientId = j.value("clientId", "");
            const auto candidate = j.at("candidate").get<std::string>();
            std::shared_ptr<rtc::PeerConnection> peer;
            bool remoteDescriptionReady = false;
            {
                std::lock_guard<std::mutex> lock(mPeersMutex);
                auto it = mPeers.find(clientId);
                if (it != mPeers.end()) peer = it->second;
                remoteDescriptionReady = mRemoteDescriptionReadyPeers.find(clientId) != mRemoteDescriptionReadyPeers.end();
                // Queue only candidates for the current active peer. ICE from a
                // closed WebSocket/DataChannel can arrive late after reconnects;
                // keeping those stale candidates can poison the next attempt.
                if (peer && !remoteDescriptionReady) {
                    mPendingRemoteCandidates[clientId].push_back(candidate);
                }
            }
            if (peer && remoteDescriptionReady) {
                peer->addRemoteCandidate(rtc::Candidate(candidate));
            }
            else if (!peer) {
                chatEmit(mCallbacks.onLog, "Dropped remote ICE candidate for inactive peer " + clientId);
            }
            else {
                chatEmit(mCallbacks.onLog, "Queued remote ICE candidate for " + clientId + " until answer is applied");
            }
        }
        else if (type == "client_left") {
            const std::string clientId = j.value("clientId", "");
            // A left notification means this signaling identity is no longer
            // valid. Retire the PeerConnection immediately so late ICE is
            // treated as stale instead of being queued for a future reconnect.
            removePeer(clientId);
        }
        else if (type == "error") {
            const std::string message = j.value("message", "unknown");
            chatEmit(mCallbacks.onError, "Signaling server error: " + message);
            if (message == "signaling server already hosts a room") {
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

// Creates a host-side PeerConnection and DataChannel for one client.
void HostSessionCore::createPeer(const std::string& id) {
    if (mStopped.load()) return;

    std::string displayName = id;
    {
        std::lock_guard<std::mutex> lock(mPeersMutex);
        auto name = mClientNames.find(id);
        if (name != mClientNames.end()) displayName = name->second;
    }
    chatEmit(mCallbacks.onStatus, "Client joined: " + displayName);

    // We create the single "chat" DataChannel before generating the offer.
    // With auto negotiation disabled, setLocalDescription() below is the point
    // that asks libdatachannel to gather ICE and emit an SDP offer.
    auto config = makePeerConfiguration();
    auto pc = std::make_shared<rtc::PeerConnection>(config);
    {
        std::lock_guard<std::mutex> lock(mPeersMutex);
        mPendingRemoteCandidates.erase(id);
        mRemoteDescriptionReadyPeers.erase(id);
        mPeers[id] = pc;
    }

    pc->onStateChange([this, id](rtc::PeerConnection::State state) {
        if (mStopped.load()) return;
        chatEmit(mCallbacks.onLog, "Peer " + id + " state: " + std::to_string(static_cast<int>(state)));
        if (state == rtc::PeerConnection::State::Failed ||
            state == rtc::PeerConnection::State::Closed) {
            removePeer(id);
        }
        else if (state == rtc::PeerConnection::State::Disconnected) {
            retireDataChannel(id);
        }
    });

    pc->onLocalDescription([this, id](rtc::Description desc) {
        if (mStopped.load() || !mWs || mWs->isClosed()) return;
        // SDP is opaque to our signaling layer; it only needs to be relayed to
        // the matching Client so both libdatachannel peers can agree on transport.
        json msg = {
            {"type", "offer"},
            {"roomId", mRoomId},
            {"target", id},
            {"sdp", static_cast<std::string>(desc)}
        };
        mWs->send(msg.dump());
    });

    pc->onLocalCandidate([this, id](rtc::Candidate candidate) {
        if (mStopped.load() || !mWs || mWs->isClosed()) return;
        // ICE candidates may arrive after the offer. Keep relaying them over
        // WebSocket until libdatachannel has enough network paths to connect.
        json msg = {
            {"type", "ice"},
            {"roomId", mRoomId},
            {"target", id},
            {"candidate", static_cast<std::string>(candidate)}
        };
        mWs->send(msg.dump());
    });

    auto dc = pc->createDataChannel("chat");

    dc->onOpen([this, id, dc]() {
        if (mStopped.load()) return;
        {
            std::lock_guard<std::mutex> lock(mPeersMutex);
            mDataChannels[id] = dc;
        }
        chatEmit(mCallbacks.onStatus, "Data channel open: " + id);

        Message welcome = makeTextMessage(currentHostActorName(), "Welcome " + displayNameForClient(id));
        setCurrentHostActorMetadata(welcome);
        dc->send(welcome.toJson());
    });

    dc->onClosed([this, id]() {
        if (mStopped.load()) return;
        retireDataChannel(id);
        chatEmit(mCallbacks.onStatus, "Data channel closed: " + id);
    });

    dc->onMessage([this, id](rtc::message_variant data) {
        if (mStopped.load()) return;
        if (auto bin = std::get_if<rtc::binary>(&data)) {
            handleBinaryData(id, *bin);
            return;
        }
        handleData(id, rtcMessageToString(data));
    });

    pc->setLocalDescription();
}

// Removes a client peer and retains it briefly for callback safety.
void HostSessionCore::removePeer(const std::string& id) {
    if (id.empty()) return;
    if (mStopped.load()) return;

    retireDataChannel(id);

    std::string displayName = id;
    {
        std::lock_guard<std::mutex> lock(mPeersMutex);
        auto name = mClientNames.find(id);
        if (name != mClientNames.end()) displayName = name->second;
        auto peer = mPeers.find(id);
        if (peer != mPeers.end()) {
            mRetiredPeers.push_back(peer->second);
            mPeers.erase(peer);
        }
        mPendingRemoteCandidates.erase(id);
        mRemoteDescriptionReadyPeers.erase(id);
    }
    chatEmit(mCallbacks.onStatus, "Client left: " + displayName);
}

// Removes a DataChannel from the active map while keeping its shared_ptr alive.
void HostSessionCore::retireDataChannel(const std::string& id) {
    {
        std::lock_guard<std::mutex> lock(mPeersMutex);
        auto channel = mDataChannels.find(id);
        if (channel != mDataChannels.end()) {
            mRetiredDataChannels.push_back(channel->second);
            mDataChannels.erase(channel);
        }
    }
    mPendingTransfers.clear(id);
}

// Handles one JSON/text DataChannel message from a client.
void HostSessionCore::handleData(const std::string& id, const std::string& s) {
    if (mStopped.load()) return;

    bool parsedProtocolMessage = false;
    try {
        Message msg = Message::fromJson(s);
        parsedProtocolMessage = true;
        if (msg.from.empty()) msg.from = id;

        if (msg.type == "text") {
            Message out = msg;
            out.from = displayNameForClient(id);
            setActorMetadata(out, id, chat::protocol::ClientActorKind, out.from);
            broadcast(out);
            chatEmit(mCallbacks.onMessage, out.toJson());
        }
        else if (msg.type == "image_meta") {
            Message out = msg;
            out.from = displayNameForClient(id);
            setActorMetadata(out, id, chat::protocol::ClientActorKind, out.from);
            const auto transferId = attachment::transferIdFromMessage(out);
            const auto pending = mPendingTransfers.stage(
                id,
                attachment::Kind::Image,
                transferId,
                out.name,
                attachment::expectedSizeFromMeta(out, attachment::Kind::Image));
            out.name = pending.name;
            out.payload["transferId"] = pending.transferId;
            out.payload["name"] = pending.name;
            broadcastExcept(out, id);
            chatEmit(mCallbacks.onMessage, out.toJson());
            chatEmit(mCallbacks.onStatus, "Image meta received: " + pending.name);
        }
        else if (msg.type == "image_binary") {
            if (msg.payload.contains("transferId") &&
                attachment::transferIdFromMessage(msg) != mPendingTransfers.activeTransferId(id)) {
                throw std::runtime_error("image binary marker transfer id does not match pending meta");
            }
            broadcastExcept(msg, id);
            chatEmit(mCallbacks.onStatus, "Image binary received");
        }
        else if (msg.type == "file_meta") {
            Message out = msg;
            out.from = displayNameForClient(id);
            setActorMetadata(out, id, chat::protocol::ClientActorKind, out.from);
            const auto transferId = attachment::transferIdFromMessage(out);
            const auto pending = mPendingTransfers.stage(
                id,
                attachment::Kind::Text,
                transferId,
                out.name,
                attachment::expectedSizeFromMeta(out, attachment::Kind::Text));
            out.name = pending.name;
            out.payload["transferId"] = pending.transferId;
            out.payload["name"] = pending.name;
            broadcastExcept(out, id);
            chatEmit(mCallbacks.onMessage, out.toJson());
            chatEmit(mCallbacks.onStatus, "File meta received: " + pending.name);
        }
        else if (msg.type == "file_binary") {
            if (msg.payload.contains("transferId") &&
                attachment::transferIdFromMessage(msg) != mPendingTransfers.activeTransferId(id)) {
                throw std::runtime_error("file binary marker transfer id does not match pending meta");
            }
            broadcastExcept(msg, id);
            chatEmit(mCallbacks.onStatus, "File binary received");
        }
        else if (msg.type == "voice_meta") {
            Message out = msg;
            out.from = displayNameForClient(id);
            setActorMetadata(out, id, chat::protocol::ClientActorKind, out.from);
            const auto transferId = attachment::transferIdFromMessage(out);
            const auto pending = mPendingTransfers.stage(
                id,
                attachment::Kind::Voice,
                transferId,
                out.name,
                attachment::expectedSizeFromMeta(out, attachment::Kind::Voice));
            out.name = pending.name;
            out.payload["transferId"] = pending.transferId;
            out.payload["name"] = pending.name;
            broadcastExcept(out, id);
            chatEmit(mCallbacks.onMessage, out.toJson());
            chatEmit(mCallbacks.onStatus, "Voice meta received: " + pending.name);
        }
        else if (msg.type == "voice_binary") {
            if (msg.payload.contains("transferId") &&
                attachment::transferIdFromMessage(msg) != mPendingTransfers.activeTransferId(id)) {
                throw std::runtime_error("voice binary marker transfer id does not match pending meta");
            }
            broadcastExcept(msg, id);
            chatEmit(mCallbacks.onStatus, "Voice binary received");
        }
        else if (msg.type == "attachment_cancel") {
            mPendingTransfers.clear(id);
            broadcastExcept(msg, id);
            chatEmit(mCallbacks.onStatus, "Attachment transfer canceled by " + id);
        }
    }
    catch (const std::exception& e) {
        if (!parsedProtocolMessage && mPendingTransfers.has(id)) {
            rtc::binary bytes;
            bytes.reserve(s.size());
            for (unsigned char ch : s) {
                bytes.push_back(static_cast<rtc::byte>(ch));
            }
            handleBinaryData(id, bytes);
            return;
        }

        chatEmit(mCallbacks.onError, std::string("Bad data message from ") + id + ": " + e.what());
    }
}

// Persists one binary attachment payload and relays it to other clients.
void HostSessionCore::handleBinaryData(const std::string& id, const rtc::binary& data) {
    if (mStopped.load()) return;

    std::string transferId;
    try {
        transferId = mPendingTransfers.activeTransferId(id);
        const auto result = mPendingTransfers.appendChunk(id, data);
        if (!result.found) {
            chatEmit(mCallbacks.onError, "Unexpected binary file data from " + id);
            return;
        }

        broadcastBinary(data, id);
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
        mPendingTransfers.clear(id);
        if (!transferId.empty()) {
            broadcastExcept(
                attachment::makeTransferCancel(displayNameForClient(id), transferId, e.what()),
                id);
        }
        chatEmit(mCallbacks.onError, std::string("File receive failed from ") + id + ": " + e.what());
    }
}

// Broadcasts a JSON message to every open client DataChannel.
void HostSessionCore::broadcast(const Message& msg) {
    broadcastExcept(msg, "");
}

// Broadcasts a JSON message to every open client DataChannel except one sender.
void HostSessionCore::broadcastExcept(const Message& msg, const std::string& exceptId) {
    std::string payload = msg.toJson();
    bool sent = false;
    std::vector<std::shared_ptr<rtc::DataChannel>> channels;
    {
        std::lock_guard<std::mutex> lock(mPeersMutex);
        for (auto& [id, dc] : mDataChannels) {
            if (!exceptId.empty() && id == exceptId) continue;
            channels.push_back(dc);
        }
    }

    // Snapshot channels before send: libdatachannel callbacks can close or
    // retire a channel while another thread is broadcasting.
    for (auto& dc : channels) {
        if (dc && dc->isOpen()) {
            dc->send(payload);
            sent = true;
        }
    }

    if (!sent && exceptId.empty()) {
        chatEmit(mCallbacks.onStatus, "No open client data channels");
    }
}

// Broadcasts a binary payload to every open client DataChannel except one sender.
void HostSessionCore::broadcastBinary(const rtc::binary& data, const std::string& exceptId) {
    std::vector<std::pair<std::string, std::shared_ptr<rtc::DataChannel>>> channels;
    {
        std::lock_guard<std::mutex> lock(mPeersMutex);
        for (auto& [id, dc] : mDataChannels) channels.emplace_back(id, dc);
    }

    for (auto& [id, dc] : channels) {
        if (!exceptId.empty() && id == exceptId) continue;
        if (dc && dc->isOpen()) {
            dc->send(data);
        }
    }
}

// Sends one JSON message to a specific client DataChannel.
bool HostSessionCore::sendToClient(const std::string& id, const Message& msg) {
    std::shared_ptr<rtc::DataChannel> dc;
    {
        std::lock_guard<std::mutex> lock(mPeersMutex);
        auto it = mDataChannels.find(id);
        if (it != mDataChannels.end()) dc = it->second;
    }

    if (!dc || !dc->isOpen()) return false;
    dc->send(msg.toJson());
    return true;
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

// Sends a non-chat room notice to one client.
void HostSessionCore::sendNoticeToClient(const std::string& id, const std::string& content) {
    Message notice;
    notice.type = "room_notice";
    notice.from = currentHostActorName();
    notice.to = id;
    notice.content = content;
    setCurrentHostActorMetadata(notice);
    sendToClient(id, notice);
}

// Chooses the visible participant name from the signaling username.
std::string HostSessionCore::displayNameForClient(const std::string& id) {
    std::lock_guard<std::mutex> lock(mPeersMutex);
    auto name = mClientNames.find(id);
    return name == mClientNames.end() ? id : name->second;
}

// Resolves a username or user id token into the underlying client id when possible.
std::string HostSessionCore::resolveClientId(const std::string& token) {
    std::lock_guard<std::mutex> lock(mPeersMutex);
    if (mDataChannels.find(token) != mDataChannels.end()) return token;
    if (mClientNames.find(token) != mClientNames.end()) return token;
    for (const auto& [id, name] : mClientNames) {
        if (name == token) return id;
    }
    return token;
}
