#pragma once

#include "attachment_transfer.hpp"
#include "common.hpp"
#include "events.hpp"
#include "secure_relay.hpp"

#include <rtc/rtc.hpp>

#include <atomic>
#include <cstddef>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

class ClientSessionCore {
public:
    // Creates a client session bound to one signaling URL and room identity.
    ClientSessionCore(std::string url, std::string room, std::string username, std::string password);
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

private:
    // Queues a local shutdown with a user-visible reason.
    void requestShutdown(const std::string& reason);
    // Dispatches joined, room membership, encrypted relay, and error events.
    void handleSignalingMessage(const std::string& s);
    // Sends one encrypted relay message through the untrusted Server.
    bool sendRelayMessage(const Message& msg, const std::string& senderId, const std::string& senderName, const std::string& senderKind);
    // Sends one local attachment as encrypted metadata followed by encrypted chunks.
    bool sendAttachmentRelay(const std::string& filePath, chat::attachment::Kind kind, const std::string& metaType, const std::string& binaryType, const std::string& mime);
    // Handles one decrypted encrypted_relay application message.
    void handleRelayMessage(const Message& msg);
    // Reassembles one encrypted attachment chunk into the local cache.
    void handleRelayBinaryChunk(const std::string& senderKey, const Message& msg);
    // Converts raw console/UI input into a protocol message.
    Message parseInput(const std::string& line);

private:
    std::string mWsUrl;
    std::string mRoomId;
    std::string mUsername;
    std::string mPassword;
    std::string mClientId;
    ChatCallbacks mCallbacks;
    std::shared_ptr<rtc::WebSocket> mWs;
    chat::secure_relay::MemberKeyPair mMemberKeys;
    std::vector<unsigned char> mGroupKey;
    std::atomic_bool mShutdownRequested = false;
    std::atomic_bool mStopped = false;
    // Core attachment receive state, keyed by sender actor id.
    chat::attachment::ReceiveStore mPendingTransfers;
};
