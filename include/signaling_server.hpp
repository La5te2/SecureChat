// SignalingServer declaration. The Server listens for WebSocket clients,
// registers rooms, tracks members, and relays opaque encrypted envelopes.
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
#include <unordered_set>
#include <vector>

// Owns the network listener, room registry, membership state, and opaque relay.
// It deliberately does not decrypt chat data and does not interpret application
// member certificates; Host/Client verify PKI identities locally.
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
        // A room is anchored by one Host socket. When this socket leaves, the
        // current design closes the room and notifies all Clients.
        std::shared_ptr<rtc::WebSocket> host;
        std::unordered_map<std::string, std::shared_ptr<rtc::WebSocket>> clients;
        // Room-local send restrictions requested by Host. Silenced clients stay
        // connected and can receive rekey traffic, but Server rejects their relay sends.
        std::unordered_set<std::string> silencedClients;
    };

    struct RoomSnapshot {
        std::vector<std::shared_ptr<rtc::WebSocket>> recipients;
        json members = json::array();
        json memberInfos = json::array();
    };

    struct ClientState {
        // Server-side connection metadata. clientId is used for routing; actorId
        // inside encrypted chat payloads is authenticated by secure_relay.
        std::string roomId;
        std::string clientId;
        std::string userId;
        std::string username;
        std::string publicKey;
        // Opaque PKI identity object from join_room. Server stores it only so
        // other Clients can independently verify the member key it broadcasts.
        json identity;
        std::string role;
        std::shared_ptr<rtc::WebSocket> ws;
        // libdatachannel WebSocket sends are not guaranteed to be safe when
        // multiple signaling callbacks write the same TLS socket at once. The
        // Server serializes every outbound frame per connection.
        std::shared_ptr<std::mutex> sendMutex = std::make_shared<std::mutex>();
        std::size_t badMessageCount = 0;
    };

    // Registers a newly accepted socket before it has authenticated into a room.
    void addClient(std::shared_ptr<rtc::WebSocket> ws);
    // Validates one JSON signaling frame and dispatches it by protocol type.
    void handleMessage(rtc::WebSocket* key, const std::string& payload);
    // Lets a Host member register a unique room on this Server.
    void handleCreateRoom(rtc::WebSocket* key, const json& data);
    // Lets a Client member join an existing room and publish its GKA public key.
    void handleJoinRoom(rtc::WebSocket* key, const json& data);
    // Lets Host remove a Client that failed local identity verification.
    void handleRejectClient(rtc::WebSocket* key, const json& data);
    // Lets Host enable or disable a room-local send restriction for one Client.
    void handleClientSilence(rtc::WebSocket* key, const json& data, bool silenced);
    // Broadcasts a Host-started GKA epoch request to current Clients.
    void relayGkaRequest(rtc::WebSocket* key, const json& data);
    // Forwards one encrypted member contribution to Host.
    void relayGkaContribution(rtc::WebSocket* key, const json& data);
    // Forwards an encrypted group-key envelope from Host to exactly one Client.
    void relayGroupKey(rtc::WebSocket* key, const json& data);
    // Relays authenticated chat ciphertext to the room or to one target member.
    void relayEncrypted(rtc::WebSocket* key, const json& data);
    // Removes a disconnected socket from member and room indexes.
    void cleanup(rtc::WebSocket* key);
    // Broadcasts structured member name/id state to all members in a room.
    void broadcastRoomMembers(const std::string& roomId);
    // Sends a terminal error to a socket that failed admission.
    void rejectClient(const std::shared_ptr<rtc::WebSocket>& ws, const std::string& message);
    // Counts malformed frames and disconnects abusive clients.
    void recordBadMessage(rtc::WebSocket* key, const std::string& message);
    // Periodically expires stale rooms and related authentication state.
    void maintenanceLoop();
    // Builds a locked room view for membership broadcasts.
    RoomSnapshot roomSnapshotLocked(const std::string& roomId);
    // Enforces per-room display-name uniqueness.
    bool clientNameInRoomLocked(const std::string& roomId, const std::string& username) const;
    // Finds the mutable state record for a connected socket.
    ClientState* findClient(rtc::WebSocket* key);
    // Resolves a room from an explicit id or from the socket's current state.
    Room* findRoom(const std::string& explicitRoomId, ClientState* client);
    // Sends JSON to one connected socket if it is still open.
    void sendToClient(rtc::WebSocket* key, const json& data);
    // Shared guarded send helper used after recipient snapshots leave the mutex.
    void safeSend(const std::shared_ptr<rtc::WebSocket>& ws, const json& data);

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
