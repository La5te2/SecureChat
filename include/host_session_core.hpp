// Host session interface used by CLI, WinUI, and Web wrappers.
// Host creates rooms and coordinates group-key distribution as a chat member.
#pragma once

#include "attachment_transfer.hpp"
#include "common.hpp"
#include "events.hpp"
#include "identity_pki.hpp"
#include "secure_relay.hpp"
#include "websocket_config.hpp"

#include <rtc/rtc.hpp>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

// Chat member that creates a room and coordinates group-key distribution.
// The Host is not the listening server; it connects to SignalingServer like
// every other member, then signs/verifies PKI and manages the room group key.
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
    // Handles Host-only room moderation commands typed into the normal input box.
    bool handleHostCommand(const std::string& line);
    // Dispatches room creation, membership, encrypted relay, and error events.
    void handleSignalingMessage(const std::string& s);
    // Removes a client member and updates local room state.
    void removeClient(const std::string& id);
    // Toggles room-local send permission for one current Client.
    void setClientSilenced(const std::string& target, bool silenced);
    // Kicks one Client and bans its verified certificate fingerprint for this room.
    void evictClient(const std::string& target);
    // Sends one Host-authorized moderation frame to the Server.
    void sendClientModeration(const std::string& type, const std::string& clientId);
    // Sends one encrypted relay message through the untrusted Server.
    bool sendRelayMessage(const Message& msg, const std::string& senderId, const std::string& senderName, const std::string& senderKind, const std::string& targetId);
    // Wraps a private Message in a pairwise inner encryption layer for targetId.
    Message wrapPairwiseForTarget(const Message& msg, const std::string& targetId);
    // Opens a pairwise-private wrapper addressed to Host.
    Message decryptPairwiseFromClient(const Message& msg);
    // Remembers relay nonce/tag pairs so replayed Server frames are ignored.
    bool rememberRelayEnvelope(const json& envelope);
    // Wraps one committed GKA state for a member and asks Server to relay it.
    bool sendGroupStateToClient(
        const std::string& clientId,
        const std::string& clientPublicKey,
        const json& groupState,
        std::uint64_t epoch);
    // Starts a fresh contributory GKA epoch after membership changes.
    void rotateGroupKey(const std::string& reason);
    // Requests Client contributions for the current pending epoch.
    void sendGkaRequestToClients();
    // Starts/stops the Host-side watchdog for members that stall a GKA epoch.
    void startGkaTimeoutWorker();
    void stopGkaTimeoutWorker();
    // Waits for pending GKA deadlines and evicts members that never contributed.
    void gkaTimeoutLoop();
    // Removes all still-missing contributors for epoch and restarts GKA once.
    void evictGkaTimeoutMembers(std::uint64_t epoch);
    // Builds and signs this Host member's contribution for one epoch.
    json makeLocalGkaContribution(std::uint64_t epoch) const;
    // Verifies one contribution and stores it in the pending epoch map.
    bool rememberGkaContribution(const json& contribution, const std::string& expectedMemberId);
    // Commits K_G once every current member has supplied a verified contribution.
    void tryCommitGkaEpoch();
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
    void announceVerifiedMember(
        const std::string& memberId,
        const std::string& displayName,
        const std::string& fingerprint,
        const std::string& subject,
        const std::string& publicKey,
        const json& identity);
    void announceVerifiedMembers();

private:
    std::string mWsUrl;
    std::string mRoomId;
    // Opaque routing token derived from roomId + room password. Server sees this
    // token as roomId; the human-readable room id stays local for UI and PKI.
    std::string mRoomToken;
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
    std::unordered_map<std::string, json> mClientIdentityObjects;
    std::unordered_set<std::string> mSilencedClientIds;
    std::unordered_set<std::string> mBannedIdentityFingerprints;
    std::unordered_set<std::string> mRecentRelayIds;
    std::deque<std::string> mRecentRelayOrder;
    chat::secure_relay::MemberKeyPair mMemberKeys;
    chat::identity_pki::IdentityContext mIdentity;
    std::vector<unsigned char> mGroupKey;
    // Pending GKA state is touched by both WebSocket callbacks and the watchdog
    // thread. This mutex keeps epoch changes, contribution storage, and timeout
    // decisions consistent.
    std::mutex mGkaMutex;
    std::condition_variable mGkaCv;
    std::thread mGkaTimeoutThread;
    bool mGkaTimeoutStop = false;
    std::uint64_t mGroupKeyEpoch = 0;
    std::uint64_t mPendingGkaEpoch = 0;
    std::chrono::steady_clock::time_point mPendingGkaDeadline{};
    std::unordered_set<std::string> mPendingGkaMembers;
    std::unordered_map<std::string, json> mPendingGkaContributions;
    // Core attachment receive state, keyed by encrypted relay sender actor id.
    chat::attachment::ReceiveStore mPendingTransfers;
};
