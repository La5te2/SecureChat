// SignalingServer 用来分配稳定 user id 的内存账户辅助模块。
// 这是进程本地状态，不是持久化用户数据库。
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
    // 创建新的内存账户，或验证已有用户名/密码。
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
