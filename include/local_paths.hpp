// 本机持久化路径工具。只处理日志、附件缓存和本机 SQLite 的目录名，
// 不参与网络协议、密钥协商或 Server room token 语义。
#pragma once

#include <filesystem>
#include <string>

namespace chat::local_paths {

// 把用户可读名称压成适合 Windows/Linux 文件名的短标签。
std::string sanitizePathComponent(const std::string& value, const std::string& fallback);

// 返回 <room_base_name>_<SHA256(roomInstanceToken)前8位>，作为 room instance 目录名。
std::string roomInstanceLabel(const std::string& roomName, const std::string& roomToken);

// 返回 hosts 或 clients，作为本机身份角色目录。
std::string roleDirectoryName(const std::string& role);

// 返回安全的用户目录名。用于 logs/<hosts|clients>/<system-username>/。
std::string userDirectoryName(const std::string& systemUsername);

// 返回安全的用户文件名。用于 texts/<system-username>.sqlite3。
std::string userFileStem(const std::string& systemUsername);

std::filesystem::path logsRoot();
std::filesystem::path identityRoot(const std::string& role, const std::string& systemUsername);
std::filesystem::path roomRoot(
    const std::string& role,
    const std::string& systemUsername,
    const std::string& roomName,
    const std::string& roomToken);
std::filesystem::path attachmentDirectory(
    const std::string& kind,
    const std::string& role,
    const std::string& systemUsername,
    const std::string& roomName,
    const std::string& roomToken);
std::filesystem::path textHistoryDatabase(
    const std::string& role,
    const std::string& roomName,
    const std::string& roomToken,
    const std::string& systemUsername);

} // namespace chat::local_paths
