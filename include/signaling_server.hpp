#pragma once

#include "auth_service.hpp"
#include "common.hpp"
#include "room_registry.hpp"

#include <rtc/rtc.hpp>

#include <atomic>
#include <condition_variable>
#include <cstddef>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

class SignalingServer {
public:
    // Starts the WebSocket signaling server and opaque encrypted relay.
    explicit SignalingServer(uint16_t port);
    // Stops signaling when the server object leaves scope.
    ~SignalingServer();

    // Returns the bound signaling port, including auto-selected ports.
    uint16_t port() const;
    // Returns "ws" or "wss" for clients that connect back to this server.
    std::string urlScheme() const;
    // Closes every advertised room and tells connected clients why.
    void closeAllRooms(const std::string& reason = "host disconnected");
    // Stops accepting signaling connections.
    void stop();

private:
    struct Room {
        std::shared_ptr<rtc::WebSocket> host;
        std::unordered_map<std::string, std::shared_ptr<rtc::WebSocket>> clients;
    };

    struct RoomSnapshot {
        std::vector<std::shared_ptr<rtc::WebSocket>> recipients;
        json members = json::array();
    };

    struct ClientState {
        std::string roomId;
        std::string clientId;
        std::string userId;
        std::string username;
        std::string publicKey;
        std::string role;
        std::shared_ptr<rtc::WebSocket> ws;
        std::size_t badMessageCount = 0;
    };

    void addClient(std::shared_ptr<rtc::WebSocket> ws);
    void handleMessage(rtc::WebSocket* key, const std::string& payload);
    void handleCreateRoom(rtc::WebSocket* key, const json& data);
    void handleJoinRoom(rtc::WebSocket* key, const json& data);
    void relayGroupKey(rtc::WebSocket* key, const json& data);
    void relayEncrypted(rtc::WebSocket* key, const json& data);
    void cleanup(rtc::WebSocket* key);
    void broadcastRoomMembers(const std::string& roomId);
    void rejectClient(const std::shared_ptr<rtc::WebSocket>& ws, const std::string& message);
    void recordBadMessage(rtc::WebSocket* key, const std::string& message);
    void maintenanceLoop();
    RoomSnapshot roomSnapshotLocked(const std::string& roomId);
    bool clientNameInRoomLocked(const std::string& roomId, const std::string& username) const;
    ClientState* findClient(rtc::WebSocket* key);
    Room* findRoom(const std::string& explicitRoomId, ClientState* client);
    void sendToClient(rtc::WebSocket* key, const json& data);
    static void safeSend(const std::shared_ptr<rtc::WebSocket>& ws, const json& data);

    std::unique_ptr<rtc::WebSocketServer> mServer;
    std::string mUrlScheme = "ws";
    std::atomic_bool mStopping = false;
    std::thread mMaintenanceThread;
    std::condition_variable mMaintenanceCv;
    std::mutex mMaintenanceMutex;
    std::mutex mMutex;
    AuthService mAuth;
    RoomRegistry mRegistry;
    std::unordered_map<std::string, Room> mRooms;
    std::unordered_map<rtc::WebSocket*, ClientState> mClients;
};
