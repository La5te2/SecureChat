#pragma once

#include "attachment_transfer.hpp"
#include "common.hpp"
#include "events.hpp"

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
    // Connects to signaling and waits for the Host peer offer.
    void start();
    // Stops signaling, peer, and active transfer state.
    void stop();
    // Reports whether the client session has been asked to stop.
    bool shouldStop() const;
    // Reports whether the WebRTC DataChannel is currently open.
    bool isDataChannelOpen() const;
    // Sends a text or attachment command to the host.
    void sendLine(const std::string& line);
    // Sends an image file through the open DataChannel.
    bool sendImage(const std::string& filePath);
    // Sends a text file through the open DataChannel.
    bool sendTextFile(const std::string& filePath);
    // Sends a recorded voice clip through the open DataChannel.
    bool sendVoice(const std::string& filePath);

private:
    // Queues a local shutdown with a user-visible reason.
    void requestShutdown(const std::string& reason);
    // Dispatches joined, SDP, ICE, and error signaling events.
    void handleSignalingMessage(const std::string& s);
    // Creates the client-side peer connection from the Host offer.
    void createPeer(const std::string& sdp);
    // Handles a binary DataChannel payload from Host.
    void printDataBinary(const rtc::binary& data);
    // Handles a JSON/text DataChannel payload from Host.
    void printDataMessage(const std::string& s);
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
    std::shared_ptr<rtc::PeerConnection> mPc;
    std::shared_ptr<rtc::DataChannel> mDc;
    std::atomic_bool mRemoteDescriptionReady = false;
    std::atomic_bool mDataChannelEverOpened = false;
    std::atomic_bool mDataChannelOpen = false;
    std::atomic_bool mShutdownRequested = false;
    std::atomic_bool mStopped = false;
    // Core attachment receive state. Client has one Host DataChannel, so all incoming
    // transfers use the same store key.
    chat::attachment::ReceiveStore mPendingTransfers;
    // ICE candidates can be signaled before the SDP offer is fully applied.
    // Keep them here so transport setup is not lost to WebSocket message order.
    std::vector<std::string> mPendingRemoteCandidates;
};
