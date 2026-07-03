// 本机文本消息历史。该模块只保存已经在本端解密并显示的 text message，
// 不保存附件内容、密钥材料、Server 状态或系统 status/error/log。
#pragma once

#include "common.hpp"

#include <cstddef>
#include <memory>
#include <mutex>
#include <string>

namespace chat::local_message {

struct TextRecord {
    bool isOwn = false;
    std::string sender;
    std::string actorId;
    std::string displayKind = "message";
    std::string body;
    std::string messageJson;
};

class Store {
public:
    Store(std::string role, std::string roomName, std::string roomToken, std::string systemUsername);
    ~Store();

    Store(const Store&) = delete;
    Store& operator=(const Store&) = delete;

    void appendText(const TextRecord& record);
    std::string historyJson(std::size_t limit = 500) const;
    std::string databasePath() const;

private:
    void open();

private:
    std::string mRole;
    std::string mRoomName;
    std::string mRoomToken;
    std::string mSystemUsername;
    std::string mPath;
    void* mDb = nullptr;
    mutable std::mutex mMutex;
};

TextRecord makeTextRecord(const Message& msg, bool isOwn);

} // namespace chat::local_message
