#pragma once

#include "auth_service.hpp"

#include <array>
#include <optional>
#include <string>
#include <unordered_map>

enum class RoomRole {
    Host,
    Client
};

struct RoomMember {
    UserAccount account;
    RoomRole role = RoomRole::Client;
    bool online = true;
};

class RoomRegistry {
public:
    // Creates a room with the given host and room password.
    void createRoom(const std::string& roomId, const UserAccount& host, const std::string& password);
    // Checks whether the supplied room password matches the stored room password.
    bool passwordMatches(const std::string& roomId, const std::string& password) const;
    // Adds or refreshes a client membership in an existing room.
    RoomMember joinClient(const std::string& roomId, const UserAccount& client);
    // Marks the host or client account offline without deleting room history.
    void markOffline(const std::string& roomId, const std::string& userId);
    // Removes a room and all in-memory memberships.
    void closeRoom(const std::string& roomId);

private:
    struct RoomState {
        std::string roomId;
        std::array<unsigned char, 32> passwordHash{};
        std::optional<RoomMember> host;
        std::unordered_map<std::string, RoomMember> clients;
    };

    RoomState& requireRoom(const std::string& roomId);

    std::unordered_map<std::string, RoomState> mRooms;
};
