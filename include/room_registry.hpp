// In-memory room registry for SignalingServer. It records room passwords and
// Host/Client membership for the current process.
#pragma once

#include "auth_service.hpp"

#include <array>
#include <optional>
#include <string>
#include <unordered_map>

enum class RoomRole {
    // Stored role is used for membership bookkeeping only. Chat authority is
    // enforced by Host/Client protocol logic and Server connection state.
    Host,
    Client
};

struct RoomMember {
    // Account id is stable inside this process and exists only while room is active.
    UserAccount account;
    RoomRole role = RoomRole::Client;
};

class RoomRegistry {
public:
    // Creates a room with the given host and room password.
    void createRoom(const std::string& roomId, const UserAccount& host, const std::string& password);
    // Checks whether the supplied room password matches the stored room password.
    bool passwordMatches(const std::string& roomId, const std::string& password) const;
    // Adds or refreshes a client membership in an existing room.
    RoomMember joinClient(const std::string& roomId, const UserAccount& client);
    // Removes a room and all in-memory memberships.
    void closeRoom(const std::string& roomId);

private:
    struct RoomState {
        // RoomState never stores the room password itself, only its digest.
        std::string roomId;
        std::array<unsigned char, 32> passwordHash{};
        std::optional<RoomMember> host;
        std::unordered_map<std::string, RoomMember> clients;
    };

    RoomState& requireRoom(const std::string& roomId);

    std::unordered_map<std::string, RoomState> mRooms;
};
