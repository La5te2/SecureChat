#include "lan_discovery.hpp"

#include <nlohmann/json.hpp>

#include <chrono>
#include <set>
#include <sstream>
#include <utility>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <WinSock2.h>
#include <Ws2tcpip.h>
#include <iphlpapi.h>
#endif

using json = nlohmann::json;

namespace {
constexpr uint16_t discoveryPort = 25777;
constexpr const char* discoverPrefix = "CHAT_DISCOVER_V1|";
constexpr const char* roomPrefix = "CHAT_ROOM_V1|";

#ifdef _WIN32
class WinsockSession {
public:
    // Initializes Winsock for the lifetime of this helper object.
    WinsockSession() {
        WSADATA data{};
        mOk = WSAStartup(MAKEWORD(2, 2), &data) == 0;
    }

    // Releases Winsock resources if initialization succeeded.
    ~WinsockSession() {
        if (mOk) WSACleanup();
    }

    // Reports whether Winsock startup completed successfully.
    bool ok() const { return mOk; }

private:
    bool mOk = false;
};

// Splits a delimiter-separated LAN discovery payload.
std::vector<std::string> split(const std::string& value, char delimiter) {
    std::vector<std::string> parts;
    std::stringstream input(value);
    std::string part;
    while (std::getline(input, part, delimiter)) parts.push_back(part);
    return parts;
}

// Closes a Winsock socket when it is valid.
void closeSocket(SOCKET socket) {
    if (socket != INVALID_SOCKET) closesocket(socket);
}

// Builds broadcast targets for global broadcast and each active IPv4 subnet.
std::vector<sockaddr_in> discoveryTargets() {
    std::vector<sockaddr_in> targets;
    std::set<uint32_t> seen;

    auto addTarget = [&](uint32_t address) {
        if (!seen.insert(address).second) return;
        sockaddr_in target{};
        target.sin_family = AF_INET;
        target.sin_port = htons(discoveryPort);
        target.sin_addr.s_addr = address;
        targets.push_back(target);
    };

    addTarget(INADDR_BROADCAST);

    ULONG bufferSize = 15 * 1024;
    std::vector<unsigned char> buffer(bufferSize);
    IP_ADAPTER_ADDRESSES* adapters = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data());
    ULONG result = GetAdaptersAddresses(
        AF_INET,
        GAA_FLAG_INCLUDE_PREFIX,
        nullptr,
        adapters,
        &bufferSize);

    if (result == ERROR_BUFFER_OVERFLOW) {
        buffer.resize(bufferSize);
        adapters = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data());
        result = GetAdaptersAddresses(
            AF_INET,
            GAA_FLAG_INCLUDE_PREFIX,
            nullptr,
            adapters,
            &bufferSize);
    }

    if (result != NO_ERROR) return targets;

    for (auto adapter = adapters; adapter; adapter = adapter->Next) {
        if (adapter->OperStatus != IfOperStatusUp) continue;
        if (adapter->IfType == IF_TYPE_SOFTWARE_LOOPBACK) continue;

        for (auto unicast = adapter->FirstUnicastAddress; unicast; unicast = unicast->Next) {
            auto sockaddr = unicast->Address.lpSockaddr;
            if (!sockaddr || sockaddr->sa_family != AF_INET) continue;

            auto ipv4 = reinterpret_cast<sockaddr_in*>(sockaddr);
            const uint32_t address = ntohl(ipv4->sin_addr.s_addr);
            const ULONG prefixLength = unicast->OnLinkPrefixLength;
            if (prefixLength == 0 || prefixLength > 32) continue;

            const uint32_t mask = prefixLength == 32 ? 0xFFFFFFFFu : (0xFFFFFFFFu << (32 - prefixLength));
            const uint32_t broadcast = (address & mask) | ~mask;
            addTarget(htonl(broadcast));
        }
    }

    return targets;
}
#endif
}

// Broadcasts a LAN discovery request and collects matching room responses.
// SecureChat discovery is room-only; no extra protocol identity is accepted.
std::vector<LanRoomInfo> discoverLanRooms(const std::string& roomId, int timeoutMs) {
    std::vector<LanRoomInfo> rooms;
#ifdef _WIN32
    WinsockSession winsock;
    if (!winsock.ok()) return rooms;

    SOCKET socket = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (socket == INVALID_SOCKET) return rooms;

    BOOL broadcast = TRUE;
    setsockopt(socket, SOL_SOCKET, SO_BROADCAST, reinterpret_cast<const char*>(&broadcast), sizeof(broadcast));

    DWORD recvTimeout = static_cast<DWORD>(timeoutMs > 0 ? timeoutMs : 800);
    setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&recvTimeout), sizeof(recvTimeout));

    const std::string request = std::string(discoverPrefix) + roomId;
    for (auto& target : discoveryTargets()) {
        sendto(socket, request.c_str(), static_cast<int>(request.size()), 0, reinterpret_cast<sockaddr*>(&target), sizeof(target));
    }

    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeoutMs > 0 ? timeoutMs : 800);
    while (std::chrono::steady_clock::now() < deadline) {
        char buffer[1024] = {};
        sockaddr_in from{};
        int fromLen = sizeof(from);
        const int bytes = recvfrom(socket, buffer, sizeof(buffer) - 1, 0, reinterpret_cast<sockaddr*>(&from), &fromLen);
        if (bytes <= 0) break;

        std::string payload(buffer, buffer + bytes);
        if (payload.rfind(roomPrefix, 0) != 0) continue;

        const auto parts = split(payload, '|');
        if (parts.size() < 4) continue;
        if (!roomId.empty() && parts[1] != roomId) continue;

        const std::string portText = parts[2];
        const std::string hostName = parts[3];

        char address[INET_ADDRSTRLEN] = {};
        if (!InetNtopA(AF_INET, &from.sin_addr, address, sizeof(address))) continue;

        LanRoomInfo info;
        info.roomId = parts[1];
        info.port = static_cast<uint16_t>(std::stoi(portText));
        info.hostName = hostName;
        info.host = address;
        info.url = "ws://" + info.host + ":" + std::to_string(info.port);

        bool duplicate = false;
        for (const auto& existing : rooms) {
            if (existing.roomId == info.roomId && existing.url == info.url) {
                duplicate = true;
                break;
            }
        }
        if (!duplicate) rooms.push_back(std::move(info));
    }

    closeSocket(socket);
#else
    (void)roomId;
    (void)timeoutMs;
#endif
    return rooms;
}

// Checks whether at least one LAN responder advertises the requested room.
bool lanRoomExists(const std::string& roomId, int timeoutMs) {
    return !discoverLanRooms(roomId, timeoutMs).empty();
}

// Serializes discovered rooms for the WinUI native API.
std::string lanRoomsJson(const std::vector<LanRoomInfo>& rooms) {
    json out = json::array();
    for (const auto& room : rooms) {
        out.push_back({
            {"roomId", room.roomId},
            {"url", room.url},
            {"host", room.host},
            {"port", room.port},
            {"hostName", room.hostName}
        });
    }
    return out.dump(2);
}

// Stores the room advertisement data used by the UDP responder.
LanRoomDiscoveryResponder::LanRoomDiscoveryResponder(std::string roomId, uint16_t port, std::string hostName)
    : mRoomId(std::move(roomId)),
      mPort(port),
      mHostName(std::move(hostName)) {
}

// Stops the background responder before destruction.
LanRoomDiscoveryResponder::~LanRoomDiscoveryResponder() {
    stop();
}

// Starts the background UDP responder thread.
void LanRoomDiscoveryResponder::start() {
    if (mRunning.exchange(true)) return;
    mThread = std::thread([this]() { run(); });
}

// Stops and joins the background UDP responder thread.
void LanRoomDiscoveryResponder::stop() {
    if (!mRunning.exchange(false)) return;
    if (mThread.joinable()) mThread.join();
}

// Listens for discovery probes and replies with this Host room endpoint.
void LanRoomDiscoveryResponder::run() {
#ifdef _WIN32
    WinsockSession winsock;
    if (!winsock.ok()) return;

    SOCKET socket = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (socket == INVALID_SOCKET) return;

    BOOL reuse = TRUE;
    setsockopt(socket, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&reuse), sizeof(reuse));

    DWORD timeout = 250;
    setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout));

    sockaddr_in local{};
    local.sin_family = AF_INET;
    local.sin_port = htons(discoveryPort);
    local.sin_addr.s_addr = INADDR_ANY;
    if (bind(socket, reinterpret_cast<sockaddr*>(&local), sizeof(local)) == SOCKET_ERROR) {
        closeSocket(socket);
        return;
    }

    while (mRunning.load()) {
        char buffer[1024] = {};
        sockaddr_in from{};
        int fromLen = sizeof(from);
        const int bytes = recvfrom(socket, buffer, sizeof(buffer) - 1, 0, reinterpret_cast<sockaddr*>(&from), &fromLen);
        if (bytes <= 0) continue;

        std::string payload(buffer, buffer + bytes);
        if (payload.rfind(discoverPrefix, 0) != 0) continue;

        const auto query = payload.substr(std::string(discoverPrefix).size());
        const auto queryParts = split(query, '|');
        const std::string requestedRoom = queryParts.empty() ? "" : queryParts[0];
        if (!requestedRoom.empty() && requestedRoom != mRoomId) continue;

        const std::string response =
            std::string(roomPrefix) + mRoomId + "|" + std::to_string(mPort) + "|" + mHostName;
        sendto(socket, response.c_str(), static_cast<int>(response.size()), 0, reinterpret_cast<sockaddr*>(&from), fromLen);
    }

    closeSocket(socket);
#endif
}
