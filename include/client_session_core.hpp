// Client session interface used by CLI and WinUI wrappers.
// It joins an existing room and sends encrypted relay messages through Server.
#pragma once

#include "attachment_transfer.hpp"
#include "common.hpp"
#include "events.hpp"
#include "identity_pki.hpp"
#include "secure_relay.hpp"
#include "websocket_config.hpp"

#include <rtc/rtc.hpp>

#include <atomic>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

// Regular room member. It joins an existing room, signs its temporary X25519
// public key, receives the Host-wrapped room group key, and then sends encrypted
// relay envelopes through SignalingServer.
class ClientSessionCore {
public:
    // Creates a client session bound to one signaling URL and room identity.
    ClientSessionCore(
        std::string url,
        std::string room,
        std::string username,
        std::string password,
        rtc::WebSocket::Configuration wsConfig = {});
    ~ClientSessionCore();

    // Installs UI or console callbacks used for events and logs.
    void setCallbacks(ChatCallbacks callbacks);
    // Connects to the Server and joins the configured room.
    void start();
    // Stops signaling and active transfer state.
    void stop();
    // Reports whether the client session has been asked to stop.
    bool shouldStop() const;
    // Sends a text or attachment command to the host.
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
    // Queues a local shutdown with a user-visible reason.
    void requestShutdown(const std::string& reason);
    // Moves raw WebSocket frames off the libdatachannel callback thread.
    void enqueueSignalingMessage(std::string payload);
    // Serial protocol worker; does JSON parsing, PKI verification, and GKA work.
    void signalingWorkerLoop();
    // Stops and joins the protocol worker without touching the WebSocket.
    void stopSignalingWorker();
    // Dispatches joined, room membership, encrypted relay, and error events.
    void handleSignalingMessage(const std::string& s);
    // Sends one encrypted relay message through the untrusted Server.
    bool sendRelayMessage(const Message& msg, const std::string& senderId, const std::string& senderName, const std::string& senderKind, const std::string& targetId);
    // Wraps a private Message in a pairwise inner encryption layer for targetId.
    Message wrapPairwiseForTarget(const Message& msg, const std::string& targetId);
    // Opens a pairwise-private wrapper addressed to this Client.
    Message decryptPairwiseFromMember(const Message& msg);
    // Remembers relay nonce/tag pairs so replayed Server frames are ignored.
    bool rememberRelayEnvelope(const json& envelope);
    // Verifies and stores one member identity/publicKey mapping for pairwise sends.
    bool rememberVerifiedMemberIdentity(
        const std::string& memberId,
        const std::string& displayName,
        const std::string& publicKey,
        const json& identity,
        const std::string& advertisedFingerprint,
        const std::string& source);
    // Sends this Client's signed random contribution for one GKA epoch.
    void sendGkaContribution(std::uint64_t epoch);
    // Verifies a decrypted GKA state and installs the derived room group key.
    bool installGroupState(const json& groupState, std::uint64_t epoch);
    // Sends one local attachment as encrypted metadata followed by encrypted chunks.
    bool sendAttachmentRelay(const std::string& filePath, chat::attachment::Kind kind, const std::string& metaType, const std::string& binaryType, const std::string& mime, const std::string& targetId);
    // Handles one decrypted encrypted_relay application message.
    void handleRelayMessage(const Message& msg);
    // Reassembles one encrypted attachment chunk into the local cache.
    void handleRelayBinaryChunk(const std::string& senderKey, const Message& msg);
    // Converts raw console/UI input into a protocol message.
    Message parseInput(const std::string& line);
    // Resolves a visible member name from the latest room_members update.
    std::string resolveMemberId(const std::string& token);

private:
    std::string mWsUrl;
    std::string mRoomId;
    // Opaque routing token derived from roomId + room password. Server sees this
    // token as roomId; the human-readable room id stays local for UI and PKI.
    std::string mRoomToken;
    std::string mUsername;
    std::string mPassword;
    std::string mClientId;
    std::mutex mMembersMutex;
    std::unordered_map<std::string, std::string> mMemberNamesById;
    std::unordered_map<std::string, std::string> mMemberPublicKeysById;
    std::unordered_map<std::string, std::string> mMemberFingerprintsById;
    std::unordered_set<std::string> mRecentRelayIds;
    std::deque<std::string> mRecentRelayOrder;
    ChatCallbacks mCallbacks;
    std::shared_ptr<rtc::WebSocket> mWs;
    rtc::WebSocket::Configuration mWsConfig;
    chat::secure_relay::MemberKeyPair mMemberKeys;
    chat::identity_pki::IdentityContext mIdentity;
    std::vector<unsigned char> mGroupKey;
    std::uint64_t mGroupKeyEpoch = 0;
    std::mutex mSignalingQueueMutex;
    std::condition_variable mSignalingQueueCv;
    std::deque<std::string> mSignalingQueue;
    std::thread mSignalingThread;
    std::atomic_bool mSignalingWorkerStopping = false;
    // True only after the Server accepts join_room and assigns a clientId.
    // A close before this point is an admission/connect failure, not a chat drop.
    std::atomic_bool mJoinedRoom = false;
    // Set once an explicit Server/Host error frame is received. If the transport
    // closes without this flag, the UI can report that the peer closed silently.
    std::atomic_bool mSawErrorFrame = false;
    std::atomic_bool mShutdownRequested = false;
    std::atomic_bool mStopped = false;
    // Core attachment receive state, keyed by sender actor id.
    chat::attachment::ReceiveStore mPendingTransfers;
};
