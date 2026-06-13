#pragma once

#include "attachment_transfer.hpp"
#include "common.hpp"
#include "events.hpp"
#include "identity_pki.hpp"
#include "secure_relay.hpp"
#include "websocket_config.hpp"

#include <rtc/rtc.hpp>

#include <atomic>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

class HostSessionCore {
public:
    // Creates a host session bound to one signaling URL and room identity.
    HostSessionCore(
        std::string wsUrl,
        std::string roomId,
        std::string username,
        std::string password,
        rtc::WebSocket::Configuration wsConfig = {});
    ~HostSessionCore();

    // Installs UI or console callbacks used for events and logs.
    void setCallbacks(ChatCallbacks callbacks);
    // Connects to the Server and creates the configured room.
    void start();
    // Stops signaling and active room state.
    void stop();
    // Reports whether the host session has been asked to stop.
    bool shouldStop() const;
    // Sends a text or attachment command from host to the room.
    void sendLine(const std::string& line);
    // Sends an image file through encrypted Server relay.
    bool sendImage(const std::string& filePath);
    // Sends a text file through encrypted Server relay.
    bool sendTextFile(const std::string& filePath);
    // Sends a recorded voice clip through encrypted Server relay.
    bool sendVoice(const std::string& filePath);
    // Sends a text or attachment command to one member. Empty target means room broadcast.
    void sendLineTo(const std::string& target, const std::string& line);
    // Sends one attachment to one member. Empty target means room broadcast.
    bool sendImageTo(const std::string& target, const std::string& filePath);
    bool sendTextFileTo(const std::string& target, const std::string& filePath);
    bool sendVoiceTo(const std::string& target, const std::string& filePath);
private:
    // Dispatches room creation, membership, encrypted relay, and error events.
    void handleSignalingMessage(const std::string& s);
    // Removes a client member and updates local room state.
    void removePeer(const std::string& id);
    // Sends one encrypted relay message through the untrusted Server.
    bool sendRelayMessage(const Message& msg, const std::string& senderId, const std::string& senderName, const std::string& senderKind, const std::string& targetId);
    // Wraps the room group key for one newly joined member and asks Server to relay it.
    bool sendGroupKeyToClient(const std::string& clientId, const std::string& clientPublicKey);
    // Generates a fresh room group key and sends it to every current client.
    void rotateGroupKey(const std::string& reason);
    // Re-sends the current room group key to every known client public key.
    void sendGroupKeyToAllClients();
    // Sends one local attachment as encrypted metadata followed by encrypted chunks.
    bool sendAttachmentRelay(const std::string& filePath, chat::attachment::Kind kind, const std::string& metaType, const std::string& binaryType, const std::string& mime, const std::string& targetId);
    // Handles one decrypted encrypted_relay application message.
    void handleRelayMessage(const Message& msg);
    // Reassembles one encrypted attachment chunk into the local cache.
    void handleRelayBinaryChunk(const std::string& senderKey, const Message& msg);
    // Returns the active host chat actor label.
    std::string currentHostActorName();
    // Adds stable actor identity metadata while keeping from/displayName human-readable.
    void setActorMetadata(Message& msg, const std::string& actorId, const std::string& actorKind, const std::string& displayName);
    // Marks a host-originated chat/media message with actor metadata.
    void setCurrentHostActorMetadata(Message& msg);
    // Returns a client's display name, falling back to id.
    std::string displayNameForClient(const std::string& id);
    // Resolves a command token to a client id.
    std::string resolveClientId(const std::string& token);
    // Asks Server to remove a Client that failed Host-side identity checks.
    void rejectClient(const std::string& clientId, const std::string& reason);
    // Announces Host-verified member certificate fingerprints through encrypted relay.
    void announceVerifiedMember(const std::string& memberId, const std::string& displayName, const std::string& fingerprint, const std::string& subject);
    void announceVerifiedMembers();

private:
    std::string mWsUrl;
    std::string mRoomId;
    std::string mUsername;
    std::string mPassword;
    rtc::WebSocket::Configuration mWsConfig;
    ChatCallbacks mCallbacks;
    std::shared_ptr<rtc::WebSocket> mWs;
    std::atomic_bool mStopped = false;
    std::mutex mClientsMutex;
    std::unordered_map<std::string, std::string> mClientNames;
    std::unordered_map<std::string, std::string> mClientPublicKeys;
    std::unordered_map<std::string, std::string> mClientIdentityFingerprints;
    std::unordered_map<std::string, std::string> mClientIdentitySubjects;
    chat::identity_pki::IdentityContext mIdentity;
    std::vector<unsigned char> mGroupKey;
    // Core attachment receive state, keyed by encrypted relay sender actor id.
    chat::attachment::ReceiveStore mPendingTransfers;
};
