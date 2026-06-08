#pragma once

#include <cstddef>
#include <string>
#include <unordered_map>
#include <vector>

struct UserAccount {
    std::string userId;
    std::string username;
};

class AuthService {
public:
    // Creates a new in-memory account or validates an existing username/password.
    UserAccount registerOrLogin(const std::string& username, const std::string& password);

private:
    struct UserRecord {
        UserAccount account;
        std::size_t passwordHash = 0;
    };

    static void validateUsername(const std::string& username);
    static std::vector<char32_t> decodeUtf8(const std::string& text);
    static bool isChineseCodepoint(char32_t ch);
    static void validatePassword(const std::string& password);
    static std::size_t hashPassword(const std::string& username, const std::string& password);
    static std::string makeUserId(const std::string& username);

    std::unordered_map<std::string, UserRecord> mUsers;
};
