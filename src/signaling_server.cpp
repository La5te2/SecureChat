#include "signaling_server.hpp"

#include <chrono>
#include <cstdlib>
#include <initializer_list>
#include <iostream>
#include <stdexcept>
#include <utility>

namespace {
constexpr std::size_t maxSignalingClients = 32;
constexpr std::size_t maxRoomClients = 16;
constexpr std::size_t maxBadMessagesPerClient = 4;
constexpr std::size_t maxPasswordBytes = 256;
constexpr std::size_t maxSdpBytes = 128 * 1024;
constexpr std::size_t maxIceCandidateBytes = 4096;
constexpr auto maintenanceInterval = std::chrono::seconds(15);
constexpr auto healthLogInterval = std::chrono::minutes(1);

std::string envValue(const char* name) {
    const char* value = std::getenv(name);
    return value == nullptr ? std::string() : std::string(value);
}

bool envEnabled(const char* name) {
    const auto value = envValue(name);
    return value == "1" || value == "true" || value == "TRUE" || value == "yes" || value == "on";
}

bool validName(const std::string& value, std::size_t maxLength) {
    if (value.empty() || value.size() > maxLength) return false;
    for (const auto ch : value) {
        const auto c = static_cast<unsigned char>(ch);
        if (c < 0x20 || c == 0x7f) return false;
    }
    return true;
}

bool hasOnlyFields(const json& data, std::initializer_list<const char*> allowed) {
    for (const auto& item : data.items()) {
        bool found = false;
        for (const auto* key : allowed) {
            if (item.key() == key) {
                found = true;
                break;
            }
        }
        if (!found) return false;
    }
    return true;
}

std::string stringField(const json& data, const char* key, std::size_t maxLength, bool required) {
    auto it = data.find(key);
    if (it == data.end()) {
        if (required) throw std::runtime_error(std::string("missing ") + key);
        return "";
    }
    if (!it->is_string()) {
        throw std::runtime_error(std::string("signaling field must be a string: ") + key);
    }
    auto value = it->get<std::string>();
    if (value.size() > maxLength) {
        throw std::runtime_error(std::string("signaling field is too large: ") + key);
    }
    return value;
}

void requireFieldsForType(const json& data, const std::string& type) {
    // Signaling is public network input. Keep a per-type schema so unknown
    // fields cannot become accidental protocol extensions or spoofing channels.
    if (type == "create_room") {
        if (!hasOnlyFields(data, {"type", "roomId", "username", "password"})) {
            throw std::runtime_error("create_room has unknown field");
        }
        stringField(data, "roomId", 64, true);
        stringField(data, "username", 64, true);
        stringField(data, "password", maxPasswordBytes, true);
    }
    else if (type == "join_room") {
        if (!hasOnlyFields(data, {"type", "roomId", "username", "password"})) {
            throw std::runtime_error("join_room has unknown field");
        }
        stringField(data, "roomId", 64, true);
        stringField(data, "username", 64, true);
        stringField(data, "password", maxPasswordBytes, true);
    }
    else if (type == "offer") {
        if (!hasOnlyFields(data, {"type", "roomId", "target", "sdp"})) {
            throw std::runtime_error("offer has unknown field");
        }
        stringField(data, "roomId", 64, true);
        stringField(data, "target", 64, true);
        stringField(data, "sdp", maxSdpBytes, true);
    }
    else if (type == "answer") {
        if (!hasOnlyFields(data, {"type", "roomId", "from", "sdp"})) {
            throw std::runtime_error("answer has unknown field");
        }
        stringField(data, "roomId", 64, true);
        stringField(data, "from", 64, true);
        stringField(data, "sdp", maxSdpBytes, true);
    }
    else if (type == "ice") {
        if (!hasOnlyFields(data, {"type", "roomId", "from", "target", "candidate"})) {
            throw std::runtime_error("ice has unknown field");
        }
        stringField(data, "roomId", 64, true);
        stringField(data, "from", 64, false);
        stringField(data, "target", 64, true);
        stringField(data, "candidate", maxIceCandidateBytes, true);
    }
    else {
        throw std::runtime_error("unknown signaling type");
    }
}

void validateIncomingSignaling(const json& data) {
    const auto type = stringField(data, "type", 32, true);
    requireFieldsForType(data, type);
}
}

SignalingServer::SignalingServer(uint16_t port) {
    rtc::WebSocketServer::Configuration config;
    config.port = port;
    config.bindAddress = "0.0.0.0";
    // Do not let half-open or abandoned WebSocket handshakes keep the public
    // signaling port alive but unable to accept fresh clients.
    config.connectionTimeout = std::chrono::seconds(15);

    if (envEnabled("SECURECHAT_SIGNALING_TLS")) {
        const auto certFile = envValue("SECURECHAT_TLS_CERT_FILE");
        const auto keyFile = envValue("SECURECHAT_TLS_KEY_FILE");
        const auto keyPass = envValue("SECURECHAT_TLS_KEY_PASS");
        if (certFile.empty() || keyFile.empty()) {
            throw std::runtime_error("SECURECHAT_TLS_CERT_FILE and SECURECHAT_TLS_KEY_FILE are required when SECURECHAT_SIGNALING_TLS=1");
        }
        // WSS protects room password, SDP, and ICE metadata in transit. It does
        // not make the host unable to see application-layer chat content.
        config.enableTls = true;
        config.certificatePemFile = certFile;
        config.keyPemFile = keyFile;
        if (!keyPass.empty()) config.keyPemPass = keyPass;
        mUrlScheme = "wss";
    }

    mServer = std::make_unique<rtc::WebSocketServer>(config);
    mServer->onClient([this](std::shared_ptr<rtc::WebSocket> ws) {
        addClient(std::move(ws));
    });

    std::cout << "[signal] server running on " << mUrlScheme << "://0.0.0.0:" << mServer->port() << std::endl;
    mMaintenanceThread = std::thread([this]() {
        maintenanceLoop();
    });
}

SignalingServer::~SignalingServer() {
    stop();
}

uint16_t SignalingServer::port() const {
    return mServer ? mServer->port() : 0;
}

std::string SignalingServer::urlScheme() const {
    return mUrlScheme;
}

void SignalingServer::closeAllRooms(const std::string& reason) {
    std::vector<std::shared_ptr<rtc::WebSocket>> notifyClients;
    {
        std::lock_guard<std::mutex> lock(mMutex);
        for (auto& [roomId, room] : mRooms) {
            for (auto& item : room.clients) notifyClients.push_back(item.second);
            mRegistry.closeRoom(roomId);
        }
        mRooms.clear();
    }

    for (auto& ws : notifyClients) {
        safeSend(ws, {{"type", "error"}, {"message", reason}});
    }
}

void SignalingServer::stop() {
    mStopping.store(true);
    mMaintenanceCv.notify_all();
    if (mServer) mServer->stop();
    if (mMaintenanceThread.joinable()) {
        mMaintenanceThread.join();
    }
}

void SignalingServer::addClient(std::shared_ptr<rtc::WebSocket> ws) {
    const auto key = ws.get();
    bool serverFull = false;
    {
        std::lock_guard<std::mutex> lock(mMutex);
        if (mClients.size() >= maxSignalingClients) {
            serverFull = true;
        }
        else {
            mClients[key] = ClientState{"", "", "", "", "", ws};
        }
    }
    if (serverFull) {
        rejectClient(ws, "signaling server is full");
        return;
    }

    ws->onMessage([this, key](rtc::message_variant data) {
        handleMessage(key, rtcMessageToString(data));
    });

    ws->onClosed([this, key]() {
        cleanup(key);
    });

    ws->onError([this, key](std::string error) {
        std::cerr << "[signal] websocket error: " << error << std::endl;
        cleanup(key);
    });
}

void SignalingServer::handleMessage(rtc::WebSocket* key, const std::string& payload) {
    try {
        // The signaling server accepts messages from every room participant.
        // Reject oversized, deeply nested, or non-object JSON before routing.
        auto data = chat::protocol::parseJsonObjectWithBudget(
            payload,
            chat::protocol::MaxSignalingMessageBytes,
            "signaling message");
        // Size/depth checks protect the parser; schema checks protect routing.
        validateIncomingSignaling(data);
        const std::string type = data.value("type", "");

        if (type == "create_room") {
            handleCreateRoom(key, data);
        }
        else if (type == "join_room") {
            handleJoinRoom(key, data);
        }
        else if (type == "offer") {
            relayOffer(key, data);
        }
        else if (type == "answer") {
            relayAnswer(key, data);
        }
        else if (type == "ice") {
            relayIce(key, data);
        }
        else {
            sendToClient(key, {{"type", "error"}, {"message", "unknown type: " + type}});
        }
    }
    catch (const json::parse_error&) {
        recordBadMessage(key, "invalid json");
    }
    catch (const std::exception& e) {
        recordBadMessage(key, e.what());
    }
}

void SignalingServer::handleCreateRoom(rtc::WebSocket* key, const json& data) {
    const std::string roomId = data.value("roomId", "");
    const std::string username = data.value("username", "host");
    const std::string password = data.value("password", "");
    if (roomId.empty()) {
        sendToClient(key, {{"type", "error"}, {"message", "missing roomId"}});
        return;
    }
    if (password.empty()) {
        sendToClient(key, {{"type", "error"}, {"message", "missing room password"}});
        return;
    }
    if (!validName(roomId, 64) || !validName(username, 64)) {
        sendToClient(key, {{"type", "error"}, {"message", "invalid room or username"}});
        return;
    }

    std::shared_ptr<rtc::WebSocket> ws;
    UserAccount account;
    bool alreadyHosting = false;
    {
        std::lock_guard<std::mutex> lock(mMutex);
        auto client = findClient(key);
        if (!client) return;

        if (!mRooms.empty()) {
            ws = client->ws;
            alreadyHosting = true;
        }
        else {
            account = mAuth.registerOrLogin(username, "local-account");
            mRegistry.createRoom(roomId, account, password);
            ws = client->ws;
            mRooms[roomId] = Room{};
            mRooms[roomId].host = ws;
            client->roomId = roomId;
            client->role = "host";
            client->clientId = "host";
            client->userId = account.userId;
            client->username = account.username;
        }
    }

    if (alreadyHosting) {
        // Send outside mMutex. libdatachannel callbacks can be re-entrant, and
        // a slow/broken peer must not block the signaling server's client map.
        safeSend(ws, {{"type", "error"}, {"message", "signaling server already hosts a room"}});
        return;
    }

    std::cout << "[signal] room created: " << roomId << std::endl;
    safeSend(ws, {
        {"type", "room_created"},
        {"roomId", roomId},
        {"userId", account.userId},
        {"username", account.username}
    });
    broadcastRoomMembers(roomId);
}

void SignalingServer::handleJoinRoom(rtc::WebSocket* key, const json& data) {
    const std::string roomId = data.value("roomId", "");
    const std::string username = data.value("username", "");
    const std::string password = data.value("password", "");
    std::shared_ptr<rtc::WebSocket> clientWs;
    std::shared_ptr<rtc::WebSocket> hostWs;
    std::string clientId;
    UserAccount account;

    if (!validName(roomId, 64) || !validName(username, 64)) {
        sendToClient(key, {{"type", "error"}, {"message", "invalid room or username"}});
        return;
    }

    {
        std::lock_guard<std::mutex> lock(mMutex);
        auto client = findClient(key);
        auto roomIt = mRooms.find(roomId);
        if (!client || roomIt == mRooms.end() || !roomIt->second.host) {
            clientWs = client ? client->ws : nullptr;
        }
        else {
            auto& room = roomIt->second;
            if (clientNameInRoomLocked(roomId, username)) {
                clientWs = client->ws;
                clientId = "__duplicate_username__";
            }
            else if (!mRegistry.passwordMatches(roomId, password)) {
                clientWs = client->ws;
                clientId = "__invalid_room_password__";
            }
            else if (room.clients.size() >= maxRoomClients) {
                clientWs = client->ws;
                clientId = "__room_full__";
            }
            else {
                account = mAuth.registerOrLogin(username, "local-account");
                mRegistry.joinClient(roomId, account);
                clientId = account.userId;
                clientWs = client->ws;
                hostWs = room.host;
                room.clients[clientId] = clientWs;

                client->roomId = roomId;
                client->clientId = clientId;
                client->userId = account.userId;
                client->username = account.username;
                client->role = "client";
            }
        }
    }

    if (clientId == "__duplicate_username__") {
        safeSend(clientWs, {{"type", "error"}, {"message", "username already in room"}});
        return;
    }

    if (clientId == "__invalid_room_password__") {
        safeSend(clientWs, {{"type", "error"}, {"message", "invalid room password"}});
        return;
    }

    if (clientId == "__room_full__") {
        safeSend(clientWs, {{"type", "error"}, {"message", "room is full"}});
        return;
    }

    if (clientId.empty()) {
        safeSend(clientWs, {{"type", "error"}, {"message", "room not found"}});
        return;
    }

    std::cout << "[signal] " << account.username << " joined " << roomId << " as " << clientId << std::endl;
    safeSend(clientWs, {
        {"type", "joined"},
        {"roomId", roomId},
        {"clientId", clientId},
        {"userId", account.userId},
        {"username", account.username}
    });
    safeSend(hostWs, {
        {"type", "new_client"},
        {"clientId", clientId},
        {"userId", account.userId},
        {"username", account.username}
    });
    broadcastRoomMembers(roomId);
}

void SignalingServer::relayOffer(rtc::WebSocket* key, const json& data) {
    const std::string target = data.value("target", "");
    std::shared_ptr<rtc::WebSocket> sender;
    std::shared_ptr<rtc::WebSocket> targetWs;
    bool senderIsHost = false;

    {
        std::lock_guard<std::mutex> lock(mMutex);
        auto state = findClient(key);
        sender = state ? state->ws : nullptr;
        senderIsHost = state && state->role == "host";
        auto room = findRoom(data.value("roomId", ""), state);
        if (room) {
            auto targetClient = room->clients.find(target);
            if (targetClient != room->clients.end()) targetWs = targetClient->second;
        }
    }

    if (!senderIsHost) {
        // Clients must not be able to inject offers to other clients.
        safeSend(sender, {{"type", "error"}, {"message", "offer is host-only"}});
        return;
    }

    if (!targetWs) {
        safeSend(sender, {{"type", "error"}, {"message", "target client not found"}});
        return;
    }

    safeSend(targetWs, {{"type", "offer"}, {"sdp", data.value("sdp", "")}});
    std::cout << "[signal] offer host -> " << target << std::endl;
}

void SignalingServer::relayAnswer(rtc::WebSocket* key, const json& data) {
    std::shared_ptr<rtc::WebSocket> senderWs;
    std::shared_ptr<rtc::WebSocket> hostWs;
    std::string senderId;
    bool senderIsClient = false;
    bool senderMatchesClaim = false;

    {
        std::lock_guard<std::mutex> lock(mMutex);
        auto client = findClient(key);
        senderWs = client ? client->ws : nullptr;
        senderId = data.value("from", client ? client->clientId : "");
        senderIsClient = client && client->role == "client";
        senderMatchesClaim = client && senderId == client->clientId;
        auto room = findRoom(data.value("roomId", ""), client);
        if (room) hostWs = room->host;
    }

    if (!senderIsClient || !senderMatchesClaim) {
        // Do not trust the JSON "from" field unless it matches the WebSocket state.
        safeSend(senderWs, {{"type", "error"}, {"message", "invalid answer sender"}});
        return;
    }

    if (!hostWs || senderId.empty()) {
        safeSend(senderWs, {{"type", "error"}, {"message", "host or sender not found"}});
        return;
    }

    safeSend(hostWs, {{"type", "answer"}, {"clientId", senderId}, {"sdp", data.value("sdp", "")}});
    std::cout << "[signal] answer " << senderId << " -> host" << std::endl;
}

void SignalingServer::relayIce(rtc::WebSocket* key, const json& data) {
    std::shared_ptr<rtc::WebSocket> senderWs;
    std::shared_ptr<rtc::WebSocket> targetWs;
    std::string logLine;
    bool authorized = false;

    {
        std::lock_guard<std::mutex> lock(mMutex);
        auto client = findClient(key);
        senderWs = client ? client->ws : nullptr;
        auto room = findRoom(data.value("roomId", ""), client);
        if (!room) {
            targetWs = nullptr;
        }
        else {
            const std::string target = data.value("target", "");
            if (client && client->role == "client" && target == chat::protocol::HostActorId) {
                const std::string senderId = data.value("from", "");
                authorized = senderId == client->clientId;
                targetWs = room->host;
                logLine = "[signal] ice " + senderId + " -> host";
            }
            else if (client && client->role == "host") {
                authorized = true;
                auto targetClient = room->clients.find(target);
                if (targetClient != room->clients.end()) {
                    targetWs = targetClient->second;
                    logLine = "[signal] ice host -> " + target;
                }
            }
        }
    }

    if (!authorized) {
        // ICE candidates affect connection routing, so enforce direction by role.
        safeSend(senderWs, {{"type", "error"}, {"message", "invalid ice sender"}});
        return;
    }

    if (!targetWs) {
        // Keep network I/O outside the mutex so bad ICE traffic from one peer
        // cannot stall new WebSocket accepts or room membership cleanup.
        safeSend(senderWs, {{"type", "error"}, {"message", "room not found"}});
        return;
    }

    if (data.value("target", "") == chat::protocol::HostActorId) {
        std::string senderId;
        {
            std::lock_guard<std::mutex> lock(mMutex);
            auto client = findClient(key);
            senderId = data.value("from", client ? client->clientId : "");
        }
        safeSend(targetWs, {
            {"type", "ice"},
            {"clientId", senderId},
            {"candidate", data.value("candidate", "")}
        });
    }
    else {
        safeSend(targetWs, {{"type", "ice"}, {"candidate", data.value("candidate", "")}});
    }
    std::cout << logLine << std::endl;
}

void SignalingServer::cleanup(rtc::WebSocket* key) {
    std::string roomId;
    std::string role;
    std::string clientId;
    std::string userId;
    std::vector<std::shared_ptr<rtc::WebSocket>> notifyClients;
    std::shared_ptr<rtc::WebSocket> notifyHost;
    bool shouldBroadcastMembers = false;

    {
        std::lock_guard<std::mutex> lock(mMutex);
        auto clientIt = mClients.find(key);
        if (clientIt == mClients.end()) return;

        roomId = clientIt->second.roomId;
        role = clientIt->second.role;
        clientId = clientIt->second.clientId;
        userId = clientIt->second.userId;

        auto roomIt = mRooms.find(roomId);
        if (roomIt != mRooms.end()) {
            auto& room = roomIt->second;
            if (role == "host" && room.host.get() == key) {
                for (auto& item : room.clients) notifyClients.push_back(item.second);
                mRooms.erase(roomIt);
                mRegistry.closeRoom(roomId);
            }
            else if (role == "client" && !clientId.empty()) {
                auto clientIt = room.clients.find(clientId);
                if (clientIt != room.clients.end() && clientIt->second.get() == key) {
                    room.clients.erase(clientIt);
                    notifyHost = room.host;
                    shouldBroadcastMembers = true;
                }
                mRegistry.markOffline(roomId, userId);
            }
        }

        mClients.erase(clientIt);
    }

    if (role == "host" && !roomId.empty()) {
        std::cout << "[signal] host left, closing room " << roomId << std::endl;
        for (auto& ws : notifyClients) {
            safeSend(ws, {{"type", "error"}, {"message", "host disconnected"}});
        }
        return;
    }

    if (role == "client" && !clientId.empty()) {
        std::cout << "[signal] " << clientId << " left " << roomId << std::endl;
        safeSend(notifyHost, {{"type", "client_left"}, {"clientId", clientId}});
        if (shouldBroadcastMembers) broadcastRoomMembers(roomId);
    }
}

void SignalingServer::broadcastRoomMembers(const std::string& roomId) {
    RoomSnapshot snapshot;
    {
        std::lock_guard<std::mutex> lock(mMutex);
        snapshot = roomSnapshotLocked(roomId);
    }

    json msg = {
        {"type", "room_members"},
        {"roomId", roomId},
        {"members", snapshot.members}
    };
    for (auto& ws : snapshot.recipients) {
        safeSend(ws, msg);
    }
}

void SignalingServer::rejectClient(const std::shared_ptr<rtc::WebSocket>& ws, const std::string& message) {
    safeSend(ws, {{"type", "error"}, {"message", message}});
    if (ws && !ws->isClosed()) {
        try {
            ws->close();
        }
        catch (const std::exception&) {
        }
    }
}

void SignalingServer::recordBadMessage(rtc::WebSocket* key, const std::string& message) {
    std::shared_ptr<rtc::WebSocket> ws;
    bool closeClient = false;
    {
        std::lock_guard<std::mutex> lock(mMutex);
        auto client = findClient(key);
        if (!client) return;

        ws = client->ws;
        client->badMessageCount++;
        closeClient = client->badMessageCount >= maxBadMessagesPerClient;
    }

    safeSend(ws, {{"type", "error"}, {"message", message}});
    if (closeClient) {
        std::cout << "[signal] closing client after repeated bad signaling messages" << std::endl;
        if (ws && !ws->isClosed()) {
            try {
                ws->close();
            }
            catch (const std::exception&) {
            }
        }
    }
}

void SignalingServer::maintenanceLoop() {
    auto nextHealthLog = std::chrono::steady_clock::now() + healthLogInterval;
    while (!mStopping.load()) {
        {
            std::unique_lock<std::mutex> lock(mMaintenanceMutex);
            mMaintenanceCv.wait_for(lock, maintenanceInterval, [this]() {
                return mStopping.load();
            });
        }
        if (mStopping.load()) break;

        std::vector<rtc::WebSocket*> closedClients;
        std::size_t clientCount = 0;
        std::size_t roomCount = 0;
        std::size_t roomClientCount = 0;
        {
            std::lock_guard<std::mutex> lock(mMutex);
            clientCount = mClients.size();
            roomCount = mRooms.size();
            for (const auto& [_, room] : mRooms) {
                roomClientCount += room.clients.size();
            }
            for (const auto& [key, client] : mClients) {
                if (!client.ws || client.ws->isClosed()) {
                    closedClients.push_back(key);
                }
            }
        }

        // Close callbacks should normally remove these entries. The periodic
        // sweep is a fallback for missed callbacks or peers that disappear in
        // ways libdatachannel reports only as a closed socket state.
        for (auto* key : closedClients) {
            cleanup(key);
        }

        const auto now = std::chrono::steady_clock::now();
        if (now >= nextHealthLog) {
            std::cout << "[signal] health clients=" << clientCount
                      << " rooms=" << roomCount
                      << " roomClients=" << roomClientCount
                      << " sweptClosed=" << closedClients.size()
                      << std::endl;
            nextHealthLog = now + healthLogInterval;
        }
    }
}

SignalingServer::RoomSnapshot SignalingServer::roomSnapshotLocked(const std::string& roomId) {
    RoomSnapshot snapshot;
    auto roomIt = mRooms.find(roomId);
    if (roomIt == mRooms.end()) return snapshot;

    for (auto& [_, client] : mClients) {
        if (client.roomId != roomId) continue;

        if (client.role == "host") {
            snapshot.members.push_back(client.username + " (Host)");
            snapshot.recipients.push_back(client.ws);
        }
    }

    for (auto& [_, client] : mClients) {
        if (client.roomId != roomId || client.role != "client") continue;

        snapshot.members.push_back(client.username);
        snapshot.recipients.push_back(client.ws);
    }

    return snapshot;
}

bool SignalingServer::clientNameInRoomLocked(const std::string& roomId, const std::string& username) const {
    for (const auto& [_, client] : mClients) {
        if (client.roomId == roomId && client.role == "client" && client.username == username) {
            return true;
        }
    }
    return false;
}

SignalingServer::ClientState* SignalingServer::findClient(rtc::WebSocket* key) {
    auto it = mClients.find(key);
    return it == mClients.end() ? nullptr : &it->second;
}

SignalingServer::Room* SignalingServer::findRoom(const std::string& explicitRoomId, ClientState* client) {
    const std::string roomId = !explicitRoomId.empty()
        ? explicitRoomId
        : (client ? client->roomId : "");
    auto it = mRooms.find(roomId);
    return it == mRooms.end() ? nullptr : &it->second;
}

void SignalingServer::sendToClient(rtc::WebSocket* key, const json& data) {
    std::shared_ptr<rtc::WebSocket> ws;
    {
        std::lock_guard<std::mutex> lock(mMutex);
        auto client = findClient(key);
        if (client) ws = client->ws;
    }
    safeSend(ws, data);
}

void SignalingServer::safeSend(const std::shared_ptr<rtc::WebSocket>& ws, const json& data) {
    if (!ws || ws->isClosed()) return;

    try {
        ws->send(data.dump());
    }
    catch (const std::exception&) {
    }
}
