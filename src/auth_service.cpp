// Process-local user account implementation for SignalingServer membership ids.
#include "auth_service.hpp"

#include <functional>
#include <stdexcept>

UserAccount AuthService::registerOrLogin(const std::string& username, const std::string& password) {
    // This helper gives Server a stable userId for routing. It is intentionally
    // in-memory; restarting the Server clears these accounts and rooms.
    validateUsername(username);
    validatePassword(password);

    auto it = mUsers.find(username);
    if (it == mUsers.end()) {
        UserRecord record;
        record.account = UserAccount{makeUserId(username), username};
        record.passwordHash = hashPassword(username, password);
        auto inserted = mUsers.emplace(username, std::move(record));
        return inserted.first->second.account;
    }

    if (it->second.passwordHash != hashPassword(username, password)) {
        throw std::runtime_error("invalid username or password");
    }

    return it->second.account;
}

void AuthService::validateUsername(const std::string& username) {
    // Validate by Unicode codepoint count rather than byte count so Chinese
    // display names do not get rejected just because UTF-8 uses multiple bytes.
    const auto codepoints = decodeUtf8(username);
    if (codepoints.empty() || codepoints.size() > 32) {
        throw std::runtime_error("username must be 1-32 characters");
    }

    for (char32_t ch : codepoints) {
        const bool ok =
            (ch >= 'a' && ch <= 'z') ||
            (ch >= 'A' && ch <= 'Z') ||
            (ch >= '0' && ch <= '9') ||
            ch == '_' || ch == '-' ||
            isChineseCodepoint(ch);
        if (!ok) throw std::runtime_error("username contains unsupported characters");
    }
}

std::vector<char32_t> AuthService::decodeUtf8(const std::string& text) {
    // Minimal UTF-8 decoder used only for username validation. It rejects
    // malformed byte sequences instead of relying on platform code pages.
    std::vector<char32_t> result;
    for (std::size_t i = 0; i < text.size();) {
        const unsigned char first = static_cast<unsigned char>(text[i]);
        char32_t codepoint = 0;
        std::size_t extra = 0;

        if (first <= 0x7F) {
            codepoint = first;
        }
        else if ((first & 0xE0) == 0xC0) {
            codepoint = first & 0x1F;
            extra = 1;
        }
        else if ((first & 0xF0) == 0xE0) {
            codepoint = first & 0x0F;
            extra = 2;
        }
        else if ((first & 0xF8) == 0xF0) {
            codepoint = first & 0x07;
            extra = 3;
        }
        else {
            throw std::runtime_error("username must be valid UTF-8");
        }

        if (i + extra >= text.size()) throw std::runtime_error("username must be valid UTF-8");
        for (std::size_t offset = 1; offset <= extra; ++offset) {
            const unsigned char next = static_cast<unsigned char>(text[i + offset]);
            if ((next & 0xC0) != 0x80) throw std::runtime_error("username must be valid UTF-8");
            codepoint = (codepoint << 6) | (next & 0x3F);
        }

        result.push_back(codepoint);
        i += extra + 1;
    }
    return result;
}

bool AuthService::isChineseCodepoint(char32_t ch) {
    return (ch >= 0x3400 && ch <= 0x4DBF) ||
        (ch >= 0x4E00 && ch <= 0x9FFF) ||
        (ch >= 0xF900 && ch <= 0xFAFF) ||
        (ch >= 0x20000 && ch <= 0x2A6DF) ||
        (ch >= 0x2A700 && ch <= 0x2B73F) ||
        (ch >= 0x2B740 && ch <= 0x2B81F) ||
        (ch >= 0x2B820 && ch <= 0x2CEAF);
}

void AuthService::validatePassword(const std::string& password) {
    // Room password strength is handled by deployment policy and UI guidance;
    // this low minimum only prevents accidental empty or one-character values.
    if (password.size() < 4) {
        throw std::runtime_error("password must be at least 4 characters");
    }
}

std::size_t AuthService::hashPassword(const std::string& username, const std::string& password) {
    // Process-local helper for AuthService account reuse. Room password matching
    // uses RoomRegistry's SHA-256 digest and constant-time comparison.
    return std::hash<std::string>{}("chat-auth-v1:" + username + ":" + password);
}

std::string AuthService::makeUserId(const std::string& username) {
    // Server exposes this id for room membership and private-message targeting.
    return "user_" + username;
}
