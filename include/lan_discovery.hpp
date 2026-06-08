#pragma once

#include <atomic>
#include <cstdint>
#include <string>
#include <thread>
#include <vector>

struct LanRoomInfo {
    std::string roomId;
    std::string url;
    std::string host;
    std::string hostName;
    uint16_t port = 0;
};

// Broadcasts a LAN discovery query and returns matching room advertisements.
// The current SecureChat protocol is room-only.
std::vector<LanRoomInfo> discoverLanRooms(const std::string& roomId, int timeoutMs);
// Checks whether a LAN room id is advertised within the timeout window.
bool lanRoomExists(const std::string& roomId, int timeoutMs);
// Serializes LAN discovery results for the native UI API.
std::string lanRoomsJson(const std::vector<LanRoomInfo>& rooms);

class LanRoomDiscoveryResponder {
public:
    // Creates a responder that advertises one locally hosted room.
    LanRoomDiscoveryResponder(std::string roomId, uint16_t port, std::string hostName);
    // Stops the responder thread before destruction.
    ~LanRoomDiscoveryResponder();

    LanRoomDiscoveryResponder(const LanRoomDiscoveryResponder&) = delete;
    LanRoomDiscoveryResponder& operator=(const LanRoomDiscoveryResponder&) = delete;

    // Starts the background UDP discovery responder.
    void start();
    // Stops the background UDP discovery responder.
    void stop();

private:
    // Runs the UDP request/response loop.
    void run();

private:
    std::string mRoomId;
    uint16_t mPort = 0;
    std::string mHostName;
    std::atomic_bool mRunning = false;
    std::thread mThread;
};
