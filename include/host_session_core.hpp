#pragma once

#include "attachment_transfer.hpp"
#include "common.hpp"
#include "events.hpp"

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
    // Connects to signaling, creates the room, and prepares client peers.
    void start();
    // Stops signaling, peers, and active room state.
    void stop();
    // Reports whether the host session has been asked to stop.
    bool shouldStop() const;
    // Sends a text or attachment command from host to the room.
    void sendLine(const std::string& line);
    // Sends an image file through the open DataChannels.
    bool sendImage(const std::string& filePath);
    // Sends a text file through the open DataChannels.
    bool sendTextFile(const std::string& filePath);
    // Sends a recorded voice clip through the open DataChannels.
    bool sendVoice(const std::string& filePath);
private:
    // Dispatches room creation, client join, SDP, and ICE signaling events.
    void handleSignalingMessage(const std::string& s);
    // Creates the host-side peer connection and DataChannel for one client.
    void createPeer(const std::string& id);
    // Removes a client peer and updates local room state.
    void removePeer(const std::string& id);
    // Moves a closing DataChannel into temporary retired storage.
    void retireDataChannel(const std::string& id);
    // Handles one JSON/text DataChannel payload from a client.
    void handleData(const std::string& id, const std::string& s);
    // Handles one binary DataChannel payload from a client.
    void handleBinaryData(const std::string& id, const rtc::binary& data);
    // Sends one structured message to every connected client and local host output.
    void broadcast(const Message& msg);
    // Sends one structured message to every client except the supplied id.
    void broadcastExcept(const Message& msg, const std::string& exceptId);
    // Sends one binary transfer payload to every client except the supplied id.
    void broadcastBinary(const rtc::binary& data, const std::string& exceptId = "");
    // Sends one structured message to a specific client.
    bool sendToClient(const std::string& id, const Message& msg);
    // Returns the active host chat actor label.
    std::string currentHostActorName();
    // Adds stable actor identity metadata while keeping from/displayName human-readable.
    void setActorMetadata(Message& msg, const std::string& actorId, const std::string& actorKind, const std::string& displayName);
    // Marks a host-originated chat/media message with actor metadata.
    void setCurrentHostActorMetadata(Message& msg);
    // Sends a private notice to one client.
    void sendNoticeToClient(const std::string& id, const std::string& content);
    // Returns a client's display name, falling back to id.
    std::string displayNameForClient(const std::string& id);
    // Resolves a command token to a client id.
    std::string resolveClientId(const std::string& token);

private:
    std::string mWsUrl;
    std::string mRoomId;
    std::string mUsername;
    std::string mPassword;
    rtc::WebSocket::Configuration mWsConfig;
    ChatCallbacks mCallbacks;
    std::shared_ptr<rtc::WebSocket> mWs;
    std::atomic_bool mStopped = false;
    std::mutex mPeersMutex;
    std::unordered_map<std::string, std::shared_ptr<rtc::PeerConnection>> mPeers;
    std::unordered_map<std::string, std::shared_ptr<rtc::DataChannel>> mDataChannels;
    std::unordered_map<std::string, std::string> mClientNames;
    // Remote ICE is only safe to apply after that client's SDP answer lands.
    // Candidates that race ahead of the answer are buffered by client id here.
    std::unordered_map<std::string, std::vector<std::string>> mPendingRemoteCandidates;
    std::unordered_set<std::string> mRemoteDescriptionReadyPeers;
    // Core attachment receive state, keyed by client id because Host can receive
    // binary payloads from multiple DataChannels at the same time.
    chat::attachment::ReceiveStore mPendingTransfers;
    // Closed objects are kept briefly so libdatachannel callbacks that are
    // already in flight do not outlive the shared_ptr they captured.
    std::vector<std::shared_ptr<rtc::PeerConnection>> mRetiredPeers;
    std::vector<std::shared_ptr<rtc::DataChannel>> mRetiredDataChannels;
};
