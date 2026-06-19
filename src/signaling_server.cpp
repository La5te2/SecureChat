// 信令 Server 实现。它校验公开信令 JSON、管理房间成员关系，
// 并转发加密中继和 group-key 封装。
#include "signaling_server.hpp"

#include "cert_generation.hpp"
#include "secure_relay.hpp"

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <iomanip>
#include <initializer_list>
#include <iostream>
#include <memory>
#include <openssl/evp.h>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

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
// 关闭前给终止性 error 帧留出足够时间离开 WebSocket。
// 否则公网 WSS/反向代理路径可能让 Client 只看到裸 close。
constexpr auto terminalErrorFlushDelay = std::chrono::milliseconds(600);
// 启动时打印该标记，使部署日志能确认 git pull/rebuild/restart 后
// 实际运行的是哪个 Server 二进制。
constexpr const char* serverBuildMarker = "securechat-server-20260614-ws-frame-budget";

std::string envValue(const char* name) {
    const char* value = std::getenv(name);
    return value == nullptr ? std::string() : std::string(value);
}

std::string sha256HexForLog(const std::string& value) {
    unsigned char digest[EVP_MAX_MD_SIZE] = {};
    unsigned int digestLength = 0;
    using CtxPtr = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;
    CtxPtr ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    if (!ctx ||
        EVP_DigestInit_ex(ctx.get(), EVP_sha256(), nullptr) != 1 ||
        EVP_DigestUpdate(ctx.get(), value.data(), value.size()) != 1 ||
        EVP_DigestFinal_ex(ctx.get(), digest, &digestLength) != 1) {
        return "redacted";
    }

    std::ostringstream out;
    out << std::hex << std::setfill('0');
    for (unsigned int i = 0; i < digestLength; ++i) {
        out << std::setw(2) << static_cast<int>(digest[i]);
    }
    return out.str();
}

std::string logActorId(const std::string& actorId) {
    // Host/Client UI 内部仍可使用可读成员 id，
    // 但 Server 日志避免写入 "user_bob" 这类名称。
    if (actorId.empty()) return "<empty>";
    if (actorId == chat::protocol::HostActorId) return "host";
    return "id#" + sha256HexForLog("securechat-log-actor:" + actorId).substr(0, 12);
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
    // rtc::WebSocket::send 是异步的。发送终止性错误后立即关闭，
    // 可能与 error 帧竞态，导致 Client 只看到 "closed"。
    // 调用该辅助函数前，socket 已经从房间状态中移除。
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
    // Server 只检查应用身份数据的形状和大小。
    // 证书链和签名在 Server 转发该不透明字段后，由 Host 或 Client 验证。
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
    // 信令属于公开网络输入。按类型保持 schema，
    // 避免未知字段变成意外协议扩展或伪造通道。
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
    // 独立模式监听所有网卡。反向代理部署可设置
    // SECURECHAT_BIND_ADDRESS=127.0.0.1，使只有 Nginx/Caddy 能访问后端 WSS。
    const auto bindAddress = envValue("SECURECHAT_BIND_ADDRESS");
    config.bindAddress = bindAddress.empty() ? "0.0.0.0" : bindAddress;
    // 避免半开或被遗弃的 WebSocket 握手占住公网信令端口，
    // 导致端口仍存活却无法接收新 Client。
    config.connectionTimeout = std::chrono::seconds(15);
    // 将 libdatachannel 的 WebSocket 帧上限与信令 JSON 预算对齐。
    // PKI 证书链会让 room_members/group_key 帧大于某些构建中的较小默认值，
    // 公网 WSS 场景尤其明显。
    config.maxMessageSize = chat::protocol::MaxSignalingMessageBytes;

    const auto tlsMaterial = chat::certs::resolveServerTlsMaterial();
    const auto keyPass = envValue("SECURECHAT_TLS_KEY_PASS");
    // WSS 是唯一对外信令模式。环境变量存在时使用用户提供的正式证书；
    // 环境变量为空时生成本地/局域网开发证书，避免 Windows 手动启动还要先准备证书。
    config.enableTls = true;
    config.certificatePemFile = tlsMaterial.certFile;
    config.keyPemFile = tlsMaterial.keyFile;
    if (!keyPass.empty()) config.keyPemPass = keyPass;
    mUrlScheme = "wss";

    mServer = std::make_unique<rtc::WebSocketServer>(config);
    mServer->onClient([this](std::shared_ptr<rtc::WebSocket> ws) {
        addClient(std::move(ws));
    });

    std::cout << "[signal] server running on " << mUrlScheme << "://"
              << *config.bindAddress << ":" << mServer->port() << std::endl;
    if (tlsMaterial.generatedLocal) {
        std::cout << "[signal] generated local WSS certificate cert=" << tlsMaterial.certFile
                  << " key=" << tlsMaterial.keyFile
                  << " ca=" << tlsMaterial.caFile << std::endl;
    }
    else if (tlsMaterial.reusedLocal) {
        std::cout << "[signal] using local WSS certificate cert=" << tlsMaterial.certFile
                  << " key=" << tlsMaterial.keyFile
                  << " ca=" << tlsMaterial.caFile << std::endl;
    }
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
        // 信令 Server 接收来自每个房间参与者的消息。
        // 路由前拒绝超大、过深嵌套或非对象 JSON。
        auto data = chat::protocol::parseJsonObjectWithBudget(
            payload,
            chat::protocol::MaxSignalingMessageBytes,
            "signaling message");
        // 大小/深度检查保护解析器；schema 检查保护路由逻辑。
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
    // 房间创建是注册操作：Server 记录一个唯一 room id 和 Host socket。
    // Server 不创建群密钥，也不成为成员。
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
            // 本地 AuthService/RoomRegistry 为当前进程提供稳定 id 和密码检查。
            // 它们不是聊天明文数据库。
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
        // 在 mMutex 外发送。WebSocket 回调可能重入，
        // 慢速或故障对端不能阻塞信令 Server 的 Client 映射。
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
    // Client 发布临时 X25519 公钥和应用身份。
    // Server 保存公钥用于路由，然后转发给 Host。
    // Host 判断 PKI 签名是否真正把该密钥绑定到成员。
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
                // clientId 是 Server 为该房间分配的稳定路由 id。
                // 它会暴露给成员，使私发中继可以寻址。
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

    std::cout << "[signal] member joined " << roomId << " as " << logActorId(clientId) << std::endl;
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
    // 回显 Client 自己的 identity，使 Client 看到 Server schema 校验接受的精确字段。
    safeSend(clientWs, joined);

    json newClient = {
        {"type", "new_client"},
        {"clientId", clientId},
        {"userId", account.userId},
        {"username", account.username},
        {"publicKey", publicKey}
    };
    if (data.contains("identity")) newClient["identity"] = data["identity"];
    // Host 接收 identity 对象和公钥，验证 PKI 绑定，
    // 然后发送 group_key 或拒绝该 Client。
    safeSend(hostWs, newClient);
    broadcastRoomMembers(roomId);
}

void SignalingServer::handleRejectClient(rtc::WebSocket* key, const json& data) {
    // 只有 Host 可以拒绝 Client。这样 Server 无法编造身份失败，
    // 同时 Host 仍能执行应用层 PKI 策略。
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
    std::cout << "[signal] host rejected " << logActorId(targetId) << " from " << roomId << ": " << reason << std::endl;
}

void SignalingServer::handleClientSilence(rtc::WebSocket* key, const json& data, bool silenced) {
    // silence 是 Host 请求的房间本地发送控制。
    // 它不解密聊天数据，也不移除成员；
    // 只阻止该 Client 连接后续发送加密中继。
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
              << logActorId(targetId) << " in " << roomId << std::endl;
}

void SignalingServer::relayGkaRequest(rtc::WebSocket* key, const json& data) {
    // GKA request 只包含 epoch 编号。
    // Server 可以看到 epoch，但不会收到 contribution secret 或派生出的群密钥。
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
    // 贡献值加密给 Host。
    // Server 按发送者连接路由，并向 Host 转发一个不透明封装。
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
    std::cout << "[signal] GKA contribution " << logActorId(senderId)
              << " -> host room " << roomId
              << " epoch=" << envelope.value("epoch", 0ULL) << std::endl;
}

void SignalingServer::relayGroupKey(rtc::WebSocket* key, const json& data) {
    // group_key 封装仅用于 Host 到单个 Client。
    // Server 根据连接状态重写路由元数据，并原样转发不透明封装。
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
                    // 将明文路由字段绑定到真实 Host 连接。
                    // Client 随后通过 Host 的 PKI 签名和 secure_relay 中的
                    // AES-GCM AAD 认证这些字段。
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
    std::cout << "[signal] group key host -> " << logActorId(targetId) << " room " << roomId << std::endl;
}

void SignalingServer::relayEncrypted(rtc::WebSocket* key, const json& data) {
    // 中继不透明应用密文。Server 校验成员关系和发送者连接状态，
    // 但看不到应用层发送者名称、私发目标或解密所需的房间群密钥。
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
                    // 阶段 12 元数据最小化：只绑定不透明 room token 和发送者连接 id。
                    // 每个加密中继都会广播；私发目标在解密后过滤。
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

    std::cout << "[signal] encrypted relay " << logActorId(senderId)
              << " -> room " << roomId
              << " recipients=" << recipients.size() << std::endl;
}

void SignalingServer::cleanup(rtc::WebSocket* key) {
    // 普通关闭和网络错误都会执行清理。
    // 它只移除断连 socket 的房间索引，然后在 mutex 外发送通知，
    // 避免阻塞其他 Client。
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
                // 当前房间生命周期策略是 Host 离开即关闭房间。
                // 持久房间需要保存成员关系并支持密钥恢复。
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
        std::cout << "[signal] " << logActorId(clientId) << " left " << roomId << std::endl;
        safeSend(notifyHost, {{"type", "client_left"}, {"clientId", clientId}});
        if (shouldBroadcastMembers) broadcastRoomMembers(roomId);
    }
}

void SignalingServer::broadcastRoomMembers(const std::string& roomId) {
    // 同时发送人类可读成员标签和结构化 id。
    // UI 显示名称，Host/Client 在内部保留 id 用于 PKI 和中继路由。
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

        // close 回调通常应移除这些条目。
        // 周期性清扫用于处理漏掉回调或未干净发送 close 通知就消失的 socket。
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
        // memberInfos 不被接收者直接信任。
        // 它携带 Client 原始签名 identity/publicKey，
        // 使其他 Client 能自行验证绑定，避免在双方私发密钥映射上信任 Host。
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

    // Host 操作和成员关系广播可能由不同信令回调线程产生。
    // 对同一个 socket 序列化写入，避免 libdatachannel 下的 TLS/WSS 帧交错。
    std::unique_lock<std::mutex> sendLock;
    if (sendMutex) {
        sendLock = std::unique_lock<std::mutex>(*sendMutex);
    }

    try {
        const auto serialized = data.dump();
        if (type == "room_members" ||
            type == chat::secure_relay::GkaRequestType ||
            type == chat::secure_relay::GroupKeyType) {
            // 这些帧携带 PKI/member/GKA 材料，
            // 通常是旧构建中最先超过较小 WebSocket 默认上限的消息。
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
