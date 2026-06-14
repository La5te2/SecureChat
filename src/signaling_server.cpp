// Signaling server implementation. It validates public signaling JSON, manages
// room membership, and forwards encrypted relay/group-key envelopes.
#include "signaling_server.hpp"

#include "secure_relay.hpp"

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
constexpr std::size_t maxRelayFieldBytes = 512 * 1024;
constexpr std::size_t maxPublicKeyBytes = 128;
constexpr std::size_t maxIdentityCertChainBytes = 128 * 1024;
constexpr std::size_t maxIdentitySignatureBytes = 4096;
constexpr auto maintenanceInterval = std::chrono::seconds(15);
constexpr auto healthLogInterval = std::chrono::minutes(1);
// Give terminal error frames enough time to leave the WebSocket before closing.
// Public WSS/reverse-proxy paths can otherwise show Clients only a bare close.
constexpr auto terminalErrorFlushDelay = std::chrono::milliseconds(600);
// Printed at startup so deployment logs can prove which Server binary is
// actually running after a git pull/rebuild/restart cycle.
constexpr const char* serverBuildMarker = "securechat-server-20260614-ws-frame-budget";

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

void closeAfterTerminalError(std::shared_ptr<rtc::WebSocket> ws) {
    // rtc::WebSocket::send is asynchronous. Closing immediately after sending a
    // terminal error can race the error frame and make Clients see only "closed".
    // The socket is already removed from room state before this helper is used.
    if (!ws) return;
    std::thread([socket = std::move(ws)]() {
        std::this_thread::sleep_for(terminalErrorFlushDelay);
        if (!socket->isClosed()) {
            try {
                socket->close();
            }
            catch (const std::exception&) {
            }
        }
    }).detach();
}

void identityField(const json& data, bool required) {
    // Server checks only the shape and size of application identity data. The
    // certificate chain, revocation list, and signature are verified by Host or
    // Client after the Server forwards this opaque field.
    auto it = data.find("identity");
    if (it == data.end()) {
        if (required) throw std::runtime_error("missing identity");
        return;
    }
    if (!it->is_object()) throw std::runtime_error("identity must be an object");
    const auto& identity = *it;
    if (!hasOnlyFields(identity, {"version", "certChainPem", "nonce", "signatureAlg", "signature"})) {
        throw std::runtime_error("identity has unknown field");
    }
    if (!identity.contains("version") || !identity["version"].is_number_integer()) {
        throw std::runtime_error("identity version must be an integer");
    }
    stringField(identity, "certChainPem", maxIdentityCertChainBytes, true);
    stringField(identity, "nonce", 64, true);
    stringField(identity, "signatureAlg", 32, true);
    stringField(identity, "signature", maxIdentitySignatureBytes, true);
}

void requireFieldsForType(const json& data, const std::string& type) {
    // Signaling is public network input. Keep a per-type schema so unknown
    // fields cannot become accidental protocol extensions or spoofing channels.
    if (type == "create_room") {
        if (!hasOnlyFields(data, {"type", "roomId", "username", "password", "publicKey", "identity"})) {
            throw std::runtime_error("create_room has unknown field");
        }
        stringField(data, "roomId", 64, true);
        stringField(data, "username", 64, true);
        stringField(data, "password", maxPasswordBytes, true);
        stringField(data, "publicKey", maxPublicKeyBytes, true);
        identityField(data, true);
    }
    else if (type == "join_room") {
        if (!hasOnlyFields(data, {"type", "roomId", "username", "password", "publicKey", "identity"})) {
            throw std::runtime_error("join_room has unknown field");
        }
        stringField(data, "roomId", 64, true);
        stringField(data, "username", 64, true);
        stringField(data, "password", maxPasswordBytes, true);
        stringField(data, "publicKey", maxPublicKeyBytes, true);
        identityField(data, true);
    }
    else if (type == "group_key") {
        if (!hasOnlyFields(data, {
                "type",
                "version",
                "epoch",
                "roomId",
                "targetId",
                "senderId",
                "alg",
                "kdf",
                "ephemeralPublicKey",
                "nonce",
                "ciphertext",
                "tag",
                "identity"})) {
            throw std::runtime_error("group_key has unknown field");
        }
        if (!data.contains("version") || !data["version"].is_number_integer()) {
            throw std::runtime_error("group_key version must be an integer");
        }
        if (!data.contains("epoch") || !data["epoch"].is_number_integer() ||
            (!data["epoch"].is_number_unsigned() && data["epoch"].get<long long>() < 0)) {
            throw std::runtime_error("group_key epoch must be a non-negative integer");
        }
        stringField(data, "roomId", 64, true);
        stringField(data, "targetId", 64, true);
        stringField(data, "senderId", 64, true);
        stringField(data, "alg", 32, true);
        stringField(data, "kdf", 64, true);
        stringField(data, "ephemeralPublicKey", maxPublicKeyBytes, true);
        stringField(data, "nonce", 64, true);
        stringField(data, "ciphertext", maxRelayFieldBytes, true);
        stringField(data, "tag", 64, true);
        identityField(data, true);
    }
    else if (type == chat::secure_relay::GkaRequestType) {
        if (!hasOnlyFields(data, {"type", "roomId", "epoch"})) {
            throw std::runtime_error("gka_request has unknown field");
        }
        stringField(data, "roomId", 64, true);
        if (!data.contains("epoch") || !data["epoch"].is_number_integer() ||
            (!data["epoch"].is_number_unsigned() && data["epoch"].get<long long>() < 0)) {
            throw std::runtime_error("gka_request epoch must be a non-negative integer");
        }
    }
    else if (type == chat::secure_relay::GkaContributionType) {
        if (!hasOnlyFields(data, {
                "type",
                "version",
                "epoch",
                "roomId",
                "senderId",
                "alg",
                "kdf",
                "ephemeralPublicKey",
                "nonce",
                "ciphertext",
                "tag"})) {
            throw std::runtime_error("gka_contribution has unknown field");
        }
        if (!data.contains("version") || !data["version"].is_number_integer()) {
            throw std::runtime_error("gka_contribution version must be an integer");
        }
        if (!data.contains("epoch") || !data["epoch"].is_number_integer() ||
            (!data["epoch"].is_number_unsigned() && data["epoch"].get<long long>() < 0)) {
            throw std::runtime_error("gka_contribution epoch must be a non-negative integer");
        }
        stringField(data, "roomId", 64, true);
        stringField(data, "senderId", 64, true);
        stringField(data, "alg", 32, true);
        stringField(data, "kdf", 64, true);
        stringField(data, "ephemeralPublicKey", maxPublicKeyBytes, true);
        stringField(data, "nonce", 64, true);
        stringField(data, "ciphertext", maxRelayFieldBytes, true);
        stringField(data, "tag", 64, true);
    }
    else if (type == "reject_client") {
        if (!hasOnlyFields(data, {"type", "roomId", "targetId", "reason"})) {
            throw std::runtime_error("reject_client has unknown field");
        }
        stringField(data, "roomId", 64, true);
        stringField(data, "targetId", 64, true);
        stringField(data, "reason", 256, true);
    }
    else if (type == "silence_client" || type == "unsilence_client") {
        if (!hasOnlyFields(data, {"type", "roomId", "targetId"})) {
            throw std::runtime_error(type + " has unknown field");
        }
        stringField(data, "roomId", 64, true);
        stringField(data, "targetId", 64, true);
    }
    else if (type == "encrypted_relay") {
        if (!hasOnlyFields(data, {
                "type",
                "version",
                "roomId",
                "senderId",
                "alg",
                "kdf",
                "nonce",
                "ciphertext",
                "tag"})) {
            throw std::runtime_error("encrypted_relay has unknown field");
        }
        if (!data.contains("version") || !data["version"].is_number_integer()) {
            throw std::runtime_error("encrypted_relay version must be an integer");
        }
        stringField(data, "roomId", 64, true);
        stringField(data, "senderId", 64, true);
        stringField(data, "alg", 32, true);
        stringField(data, "kdf", 64, true);
        stringField(data, "nonce", 64, true);
        stringField(data, "ciphertext", maxRelayFieldBytes, true);
        stringField(data, "tag", 64, true);
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
    // Normal standalone mode listens on all interfaces. Reverse-proxy TLS
    // deployments can set SECURECHAT_BIND_ADDRESS=127.0.0.1 so only Nginx/Caddy
    // can reach the plain backend WebSocket.
    const auto bindAddress = envValue("SECURECHAT_BIND_ADDRESS");
    config.bindAddress = bindAddress.empty() ? "0.0.0.0" : bindAddress;
    // Do not let half-open or abandoned WebSocket handshakes keep the public
    // signaling port alive but unable to accept fresh clients.
    config.connectionTimeout = std::chrono::seconds(15);
    // Match libdatachannel's WebSocket frame cap to our signaling JSON budget.
    // PKI cert chains make room_members/group_key frames larger than tiny
    // defaults on some builds, especially over public WSS.
    config.maxMessageSize = chat::protocol::MaxSignalingMessageBytes;

    if (envEnabled("SECURECHAT_SIGNALING_TLS")) {
        const auto certFile = envValue("SECURECHAT_TLS_CERT_FILE");
        const auto keyFile = envValue("SECURECHAT_TLS_KEY_FILE");
        const auto keyPass = envValue("SECURECHAT_TLS_KEY_PASS");
        if (certFile.empty() || keyFile.empty()) {
            throw std::runtime_error("SECURECHAT_TLS_CERT_FILE and SECURECHAT_TLS_KEY_FILE are required when SECURECHAT_SIGNALING_TLS=1");
        }
        // WSS protects room passwords and relay envelopes in transit. It does
        // not replace application-layer E2EE.
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

    std::cout << "[signal] server running on " << mUrlScheme << "://"
              << *config.bindAddress << ":" << mServer->port() << std::endl;
    std::cout << "[signal] build marker: " << serverBuildMarker
              << " maxMessageSize=" << chat::protocol::MaxSignalingMessageBytes
              << std::endl;
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
            mClients[key] = ClientState{"", "", "", "", "", json{}, "", ws};
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
        else if (type == "reject_client") {
            handleRejectClient(key, data);
        }
        else if (type == "silence_client") {
            handleClientSilence(key, data, true);
        }
        else if (type == "unsilence_client") {
            handleClientSilence(key, data, false);
        }
        else if (type == chat::secure_relay::GkaRequestType) {
            relayGkaRequest(key, data);
        }
        else if (type == chat::secure_relay::GkaContributionType) {
            relayGkaContribution(key, data);
        }
        else if (type == "encrypted_relay") {
            relayEncrypted(key, data);
        }
        else if (type == "group_key") {
            relayGroupKey(key, data);
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
    // Room creation is a registration operation: Server records one unique room
    // id and the Host socket. It does not create a group key or become a member.
    const std::string roomId = data.value("roomId", "");
    const std::string username = data.value("username", "host");
    const std::string password = data.value("password", "");
    const std::string publicKey = data.value("publicKey", "");
    if (roomId.empty()) {
        sendToClient(key, {{"type", "error"}, {"message", "missing roomId"}});
        return;
    }
    if (password.empty()) {
        sendToClient(key, {{"type", "error"}, {"message", "missing room password"}});
        return;
    }
    if (!validName(roomId, 64) || !validName(username, 64) || publicKey.empty()) {
        sendToClient(key, {{"type", "error"}, {"message", "invalid room or username"}});
        return;
    }

    std::shared_ptr<rtc::WebSocket> ws;
    UserAccount account;
    bool roomAlreadyExists = false;
    {
        std::lock_guard<std::mutex> lock(mMutex);
        auto client = findClient(key);
        if (!client) return;

        if (mRooms.find(roomId) != mRooms.end()) {
            ws = client->ws;
            roomAlreadyExists = true;
        }
        else {
            // The local AuthService/RoomRegistry give stable ids and password
            // checks for this process. They are not a chat plaintext database.
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
            client->publicKey = publicKey;
            client->identity = data["identity"];
        }
    }

    if (roomAlreadyExists) {
        // Send outside mMutex. WebSocket callbacks can be re-entrant, and a
        // slow/broken peer must not block the signaling server's client map.
        safeSend(ws, {{"type", "error"}, {"message", "room already exists"}});
        return;
    }

    std::cout << "[signal] room created: " << roomId << std::endl;
    safeSend(ws, {
        {"type", "room_created"},
        {"roomId", roomId},
        {"userId", account.userId},
        {"username", account.username},
        {"publicKey", publicKey}
    });
    broadcastRoomMembers(roomId);
}

void SignalingServer::handleJoinRoom(rtc::WebSocket* key, const json& data) {
    // A Client publishes a temporary X25519 public key and application identity.
    // Server stores the public key for routing, then forwards it to Host. Host
    // decides whether the PKI signature really binds this key to the member.
    const std::string roomId = data.value("roomId", "");
    const std::string username = data.value("username", "");
    const std::string password = data.value("password", "");
    const std::string publicKey = data.value("publicKey", "");
    std::shared_ptr<rtc::WebSocket> clientWs;
    std::shared_ptr<rtc::WebSocket> hostWs;
    std::string clientId;
    std::string hostUsername;
    std::string hostPublicKey;
    json hostIdentity;
    UserAccount account;

    if (!validName(roomId, 64) || !validName(username, 64) || publicKey.empty()) {
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
                // clientId is the Server-assigned stable routing id for this
                // room. It is exposed to members so private relay can target it.
                account = mAuth.registerOrLogin(username, "local-account");
                mRegistry.joinClient(roomId, account);
                clientId = account.userId;
                clientWs = client->ws;
                hostWs = room.host;
                for (const auto& [_, state] : mClients) {
                    if (state.ws == hostWs && state.role == "host") {
                        hostUsername = state.username;
                        hostPublicKey = state.publicKey;
                        hostIdentity = state.identity;
                        break;
                    }
                }
                room.clients[clientId] = clientWs;

                client->roomId = roomId;
                client->clientId = clientId;
                client->userId = account.userId;
                client->username = account.username;
                client->publicKey = publicKey;
                client->identity = data["identity"];
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

    std::cout << "[signal] member joined " << roomId << " as " << clientId << std::endl;
    json joined = {
        {"type", "joined"},
        {"roomId", roomId},
        {"clientId", clientId},
        {"userId", account.userId},
        {"username", account.username},
        {"publicKey", publicKey},
        {"hostUsername", hostUsername},
        {"hostPublicKey", hostPublicKey}
    };
    if (data.contains("identity")) joined["identity"] = data["identity"];
    if (hostIdentity.is_object()) joined["hostIdentity"] = hostIdentity;
    // Echo the Client's own identity back so the Client sees the exact fields
    // accepted by Server schema validation.
    safeSend(clientWs, joined);

    json newClient = {
        {"type", "new_client"},
        {"clientId", clientId},
        {"userId", account.userId},
        {"username", account.username},
        {"publicKey", publicKey}
    };
    if (data.contains("identity")) newClient["identity"] = data["identity"];
    // Host receives the identity object and public key, verifies the PKI binding,
    // then either sends group_key or rejects the Client.
    safeSend(hostWs, newClient);
    broadcastRoomMembers(roomId);
}

void SignalingServer::handleRejectClient(rtc::WebSocket* key, const json& data) {
    // Only Host may reject a Client. This keeps Server from inventing identity
    // failures while still letting Host enforce application-layer PKI.
    std::shared_ptr<rtc::WebSocket> senderWs;
    std::shared_ptr<rtc::WebSocket> targetWs;
    std::string roomId;
    std::string targetId;
    std::string reason = data.value("reason", "identity verification failed");
    std::string errorMessage;

    {
        std::lock_guard<std::mutex> lock(mMutex);
        auto sender = findClient(key);
        senderWs = sender ? sender->ws : nullptr;
        if (!sender || sender->role != "host" || sender->roomId.empty() || sender->roomId != data.value("roomId", "")) {
            errorMessage = "invalid reject sender";
        }
        else {
            auto room = findRoom(sender->roomId, sender);
            roomId = sender->roomId;
            targetId = data.value("targetId", "");
            if (!room) {
                errorMessage = "room not found";
            }
            else {
                auto target = room->clients.find(targetId);
                if (target == room->clients.end() || !target->second) {
                    errorMessage = "target client not found";
                }
                else {
                    targetWs = target->second;
                    room->clients.erase(target);
                    room->silencedClients.erase(targetId);
                    for (auto it = mClients.begin(); it != mClients.end(); ++it) {
                        if (it->second.ws == targetWs) {
                            mClients.erase(it);
                            break;
                        }
                    }
                }
            }
        }
    }

    if (!errorMessage.empty()) {
        safeSend(senderWs, {{"type", "error"}, {"message", errorMessage}});
        return;
    }

    safeSend(targetWs, {{"type", "error"}, {"message", reason}});
    closeAfterTerminalError(targetWs);
    if (!roomId.empty()) broadcastRoomMembers(roomId);
    std::cout << "[signal] host rejected " << targetId << " from " << roomId << ": " << reason << std::endl;
}

void SignalingServer::handleClientSilence(rtc::WebSocket* key, const json& data, bool silenced) {
    // Silence is room-local send control requested by Host. It does not decrypt
    // chat data and does not remove the member; it only blocks future encrypted
    // relay sends from that Client connection.
    std::shared_ptr<rtc::WebSocket> senderWs;
    std::shared_ptr<rtc::WebSocket> targetWs;
    std::string roomId;
    std::string targetId;
    std::string errorMessage;

    {
        std::lock_guard<std::mutex> lock(mMutex);
        auto sender = findClient(key);
        senderWs = sender ? sender->ws : nullptr;
        if (!sender || sender->role != "host" || sender->roomId.empty() || sender->roomId != data.value("roomId", "")) {
            errorMessage = "invalid silence sender";
        }
        else {
            auto room = findRoom(sender->roomId, sender);
            roomId = sender->roomId;
            targetId = data.value("targetId", "");
            if (!room) {
                errorMessage = "room not found";
            }
            else {
                auto target = room->clients.find(targetId);
                if (target == room->clients.end() || !target->second) {
                    errorMessage = "target client not found";
                }
                else {
                    targetWs = target->second;
                    if (silenced) {
                        room->silencedClients.insert(targetId);
                    }
                    else {
                        room->silencedClients.erase(targetId);
                    }
                }
            }
        }
    }

    if (!errorMessage.empty()) {
        safeSend(senderWs, {{"type", "error"}, {"message", errorMessage}});
        return;
    }

    const std::string state = silenced ? "silenced" : "unsilenced";
    const std::string message = silenced ? "member silenced" : "member unsilenced";
    safeSend(targetWs, {{"type", "moderation"}, {"state", state}, {"message", message}});
    std::cout << "[signal] host " << (silenced ? "silenced " : "unsilenced ")
              << targetId << " in " << roomId << std::endl;
}

void SignalingServer::relayGkaRequest(rtc::WebSocket* key, const json& data) {
    // GKA request contains only an epoch number. Server may see the epoch, but
    // it does not receive contribution secrets or derived group keys.
    std::shared_ptr<rtc::WebSocket> senderWs;
    std::vector<std::shared_ptr<rtc::WebSocket>> recipients;
    json envelope = data;
    std::string roomId;
    std::string errorMessage;

    {
        std::lock_guard<std::mutex> lock(mMutex);
        auto sender = findClient(key);
        senderWs = sender ? sender->ws : nullptr;
        if (!sender || sender->role != "host" || sender->roomId.empty() || sender->roomId != data.value("roomId", "")) {
            errorMessage = "invalid GKA request sender";
        }
        else {
            auto room = findRoom(sender->roomId, sender);
            if (!room) {
                errorMessage = "room not found";
            }
            else {
                roomId = sender->roomId;
                envelope["roomId"] = roomId;
                envelope["senderId"] = chat::protocol::HostActorId;
                for (const auto& [_, ws] : room->clients) {
                    if (ws) recipients.push_back(ws);
                }
            }
        }
    }

    if (!errorMessage.empty()) {
        safeSend(senderWs, {{"type", "error"}, {"message", errorMessage}});
        return;
    }

    for (const auto& recipient : recipients) safeSend(recipient, envelope);
    std::cout << "[signal] GKA request room " << roomId
              << " epoch=" << envelope.value("epoch", 0ULL)
              << " recipients=" << recipients.size() << std::endl;
}

void SignalingServer::relayGkaContribution(rtc::WebSocket* key, const json& data) {
    // Contributions are encrypted to Host. Server routes by the sender connection
    // and forwards one opaque envelope to Host.
    std::shared_ptr<rtc::WebSocket> senderWs;
    std::shared_ptr<rtc::WebSocket> hostWs;
    json envelope = data;
    std::string roomId;
    std::string senderId;
    std::string errorMessage;

    std::cout << "[signal] received gka_contribution frame epoch="
              << data.value("epoch", 0ULL)
              << " bytes=" << data.dump().size()
              << std::endl;

    {
        std::lock_guard<std::mutex> lock(mMutex);
        auto sender = findClient(key);
        senderWs = sender ? sender->ws : nullptr;
        if (!sender || sender->role != "client" || sender->roomId.empty() || sender->roomId != data.value("roomId", "")) {
            errorMessage = "invalid GKA contribution sender";
        }
        else {
            auto room = findRoom(sender->roomId, sender);
            if (!room || !room->host) {
                errorMessage = "room not found";
            }
            else {
                roomId = sender->roomId;
                senderId = sender->clientId;
                hostWs = room->host;
                envelope["roomId"] = roomId;
                envelope["senderId"] = senderId;
            }
        }
    }

    if (!errorMessage.empty()) {
        safeSend(senderWs, {{"type", "error"}, {"message", errorMessage}});
        return;
    }

    safeSend(hostWs, envelope);
    std::cout << "[signal] GKA contribution " << senderId
              << " -> host room " << roomId
              << " epoch=" << envelope.value("epoch", 0ULL) << std::endl;
}

void SignalingServer::relayGroupKey(rtc::WebSocket* key, const json& data) {
    // group_key envelopes are Host-to-one-Client only. Server rewrites routing
    // metadata from connection state and forwards the opaque envelope unchanged.
    std::shared_ptr<rtc::WebSocket> senderWs;
    std::shared_ptr<rtc::WebSocket> targetWs;
    json envelope = data;
    std::string roomId;
    std::string targetId;
    std::string errorMessage;

    {
        std::lock_guard<std::mutex> lock(mMutex);
        auto sender = findClient(key);
        senderWs = sender ? sender->ws : nullptr;
        if (!sender || sender->role != "host" || sender->roomId.empty() || sender->roomId != data.value("roomId", "")) {
            errorMessage = "invalid group key sender";
        }
        else {
            auto room = findRoom(sender->roomId, sender);
            targetId = data.value("targetId", "");
            if (!room) {
                errorMessage = "room not found";
            }
            else {
                auto target = room->clients.find(targetId);
                if (target == room->clients.end()) {
                    errorMessage = "target client not found";
                }
                else {
                    roomId = sender->roomId;
                    targetWs = target->second;
                    // Bind clear routing fields to the actual Host connection.
                    // Client later authenticates these fields through Host's
                    // PKI signature and the AES-GCM AAD in secure_relay.
                    envelope["roomId"] = roomId;
                    envelope["senderId"] = chat::protocol::HostActorId;
                    envelope["targetId"] = targetId;
                }
            }
        }
    }

    if (!errorMessage.empty()) {
        safeSend(senderWs, {{"type", "error"}, {"message", errorMessage}});
        return;
    }

    safeSend(targetWs, envelope);
    std::cout << "[signal] group key host -> " << targetId << " room " << roomId << std::endl;
}

void SignalingServer::relayEncrypted(rtc::WebSocket* key, const json& data) {
    // Relays opaque application ciphertext. The Server validates membership
    // and sender connection state, but never sees application sender names,
    // private targets, or the room group key needed to decrypt.
    std::shared_ptr<rtc::WebSocket> senderWs;
    std::vector<std::shared_ptr<rtc::WebSocket>> recipients;
    json envelope = data;
    std::string roomId;
    std::string senderId;
    std::string errorMessage;

    {
        std::lock_guard<std::mutex> lock(mMutex);
        auto sender = findClient(key);
        senderWs = sender ? sender->ws : nullptr;
        if (!sender || sender->roomId.empty() || sender->roomId != data.value("roomId", "")) {
            errorMessage = "invalid encrypted relay sender";
        }
        else {
            auto room = findRoom(sender->roomId, sender);
            if (!room) {
                errorMessage = "room not found";
            }
            else {
                roomId = sender->roomId;
                senderId = sender->clientId;

                if (sender->role == "client" && room->silencedClients.find(senderId) != room->silencedClients.end()) {
                    errorMessage = "member is silenced";
                }
                else {
                    // Phase 12 metadata minimization: bind only the opaque room
                    // token and sender connection id. Every encrypted relay is
                    // broadcast; private targets are filtered after decryption.
                    envelope["roomId"] = roomId;
                    envelope["senderId"] = senderId;
                    if (room->host && room->host.get() != key) recipients.push_back(room->host);
                    for (const auto& [_, ws] : room->clients) {
                        if (ws && ws.get() != key) recipients.push_back(ws);
                    }
                }
            }
        }
    }

    if (!errorMessage.empty()) {
        safeSend(senderWs, {{"type", "error"}, {"message", errorMessage}});
        return;
    }

    for (const auto& recipient : recipients) {
        safeSend(recipient, envelope);
    }

    std::cout << "[signal] encrypted relay " << senderId
              << " -> room " << roomId
              << " recipients=" << recipients.size() << std::endl;
}

void SignalingServer::cleanup(rtc::WebSocket* key) {
    // Cleanup runs for normal close and network errors. It removes only the
    // disconnected socket's room indexes, then sends notifications outside the
    // mutex to avoid blocking other clients.
    std::string roomId;
    std::string role;
    std::string clientId;
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

        auto roomIt = mRooms.find(roomId);
        if (roomIt != mRooms.end()) {
            auto& room = roomIt->second;
            if (role == "host" && room.host.get() == key) {
                // Current room lifetime policy: Host leaving closes the room.
                // Persistent rooms would need stored membership and key recovery.
                for (auto& item : room.clients) notifyClients.push_back(item.second);
                mRooms.erase(roomIt);
                mRegistry.closeRoom(roomId);
            }
            else if (role == "client" && !clientId.empty()) {
                auto clientIt = room.clients.find(clientId);
                if (clientIt != room.clients.end() && clientIt->second.get() == key) {
                    room.clients.erase(clientIt);
                    room.silencedClients.erase(clientId);
                    notifyHost = room.host;
                    shouldBroadcastMembers = true;
                }
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
    // Sends both human-readable member labels and structured ids. Existing UI
    // can display members, while private relay can resolve name/id targets.
    RoomSnapshot snapshot;
    {
        std::lock_guard<std::mutex> lock(mMutex);
        snapshot = roomSnapshotLocked(roomId);
    }

    json msg = {
        {"type", "room_members"},
        {"roomId", roomId},
        {"members", snapshot.members},
        {"memberInfos", snapshot.memberInfos}
    };
    for (auto& ws : snapshot.recipients) {
        safeSend(ws, msg);
    }
    std::cout << "[signal] room_members room " << roomId
              << " recipients=" << snapshot.recipients.size() << std::endl;
}

void SignalingServer::rejectClient(const std::shared_ptr<rtc::WebSocket>& ws, const std::string& message) {
    safeSend(ws, {{"type", "error"}, {"message", message}});
    closeAfterTerminalError(ws);
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
        closeAfterTerminalError(ws);
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
        // sweep is a fallback for missed callbacks or sockets that disappear
        // without a clean close notification.
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
            json info = {
                {"id", chat::protocol::HostActorId},
                {"username", client.username},
                {"role", "host"}
            };
            if (!client.publicKey.empty() && client.identity.is_object()) {
                info["publicKey"] = client.publicKey;
                info["identity"] = client.identity;
            }
            snapshot.memberInfos.push_back(info);
            snapshot.recipients.push_back(client.ws);
        }
    }

    for (auto& [_, client] : mClients) {
        if (client.roomId != roomId || client.role != "client") continue;

        snapshot.members.push_back(client.username);
        json info = {
            {"id", client.clientId},
            {"username", client.username},
            {"role", "client"}
        };
        // memberInfos is not trusted by receivers. It carries the Client's
        // original signed identity/publicKey so other Clients can verify the
        // binding themselves and avoid trusting Host for pairwise key mapping.
        if (!client.publicKey.empty() && client.identity.is_object()) {
            info["publicKey"] = client.publicKey;
            info["identity"] = client.identity;
        }
        snapshot.memberInfos.push_back(info);
        snapshot.recipients.push_back(client.ws);
    }

    return snapshot;
}

bool SignalingServer::clientNameInRoomLocked(const std::string& roomId, const std::string& username) const {
    for (const auto& [_, client] : mClients) {
        if (client.roomId == roomId && client.username == username) {
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
    const auto type = data.value("type", "");
    if (!ws) {
        std::cout << "[signal] skipped send type=" << type << " reason=null socket" << std::endl;
        return;
    }
    if (ws->isClosed()) {
        std::cout << "[signal] skipped send type=" << type << " reason=closed socket" << std::endl;
        return;
    }

    std::shared_ptr<std::mutex> sendMutex;
    {
        std::lock_guard<std::mutex> lock(mMutex);
        auto client = findClient(ws.get());
        if (client) sendMutex = client->sendMutex;
    }

    // Host actions and membership broadcasts can be produced by different
    // signaling callback threads. Serialize writes to one socket so TLS/WSS
    // frames are not interleaved under libdatachannel.
    std::unique_lock<std::mutex> sendLock;
    if (sendMutex) {
        sendLock = std::unique_lock<std::mutex>(*sendMutex);
    }

    try {
        const auto serialized = data.dump();
        if (type == "room_members" ||
            type == chat::secure_relay::GkaRequestType ||
            type == chat::secure_relay::GroupKeyType) {
            // These frames carry PKI/member/GKA material and are the first
            // messages likely to exceed tiny WebSocket defaults on stale builds.
            std::cout << "[signal] sending type=" << type
                      << " bytes=" << serialized.size()
                      << " limit=" << chat::protocol::MaxSignalingMessageBytes
                      << std::endl;
        }
        ws->send(serialized);
    }
    catch (const std::exception& e) {
        std::cout << "[signal] send failed type=" << type << " error=" << e.what() << std::endl;
    }
}
