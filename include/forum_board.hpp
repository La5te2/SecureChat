// 房间留言板密文记录。留言板只处理文本，不承载附件。
// Server/Relay 保存 ForumRecord JSON，但正文和 post key 都由成员端加密。
#pragma once

#include "common.hpp"
#include "pki_application.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace chat::forum_board {

inline constexpr const char* RecordType = "forum_record";
inline constexpr const char* SyncType = "forum_sync";
inline constexpr const char* RecordsType = "forum_records";
inline constexpr std::size_t MaxPostTextBytes = 16 * 1024;
inline constexpr std::size_t MaxRecordsPerSync = 500;

struct Recipient {
    std::string memberId;
    std::string displayName;
    std::string fingerprint;
    json identity = json::object();
};

struct DisplayRecord {
    std::string boardMessageId;
    std::string authorName;
    std::string authorFingerprint;
    std::string text;
    std::uint64_t createdAtUnixMs = 0;
    bool own = false;
};

// 创建一条可交给 relay 保存的加密留言板记录。正文使用随机 post key
// AES-256-GCM 加密；post key 再分别封装给每个收件成员证书。
json makeRecord(
    const std::string& roomId,
    const std::string& roomToken,
    std::uint64_t epoch,
    const std::string& authorMemberId,
    const std::string& authorDisplayName,
    const chat::pki_application::IdentityContext& identity,
    const std::vector<Recipient>& recipients,
    const std::string& text);

// 校验记录签名、record hash 和本地收件 key envelope，并返回解密后的文本。
DisplayRecord openRecord(
    const std::string& roomId,
    const std::string& roomToken,
    const chat::pki_application::IdentityContext& identity,
    const json& record);

// 对 record 中除 payloadDigest/control 外的稳定字段计算摘要。
std::string payloadDigest(const json& record);

}
