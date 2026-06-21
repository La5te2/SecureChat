// 房间级 relay pool 工具。
// 它负责解析 Host 本地的 pool 配置、生成 entrance 内的 manifest、
// 以及在 room-dir/relay/relay-pool.sqlite3 中保存房间级副本。
#pragma once

#include "common.hpp"

#include <filesystem>
#include <string>
#include <vector>

namespace chat::relay_pool {

struct RelayPoolLoadResult {
    json manifest = json::object();
    std::vector<std::string> urls;
};

struct RelayStatusSummary {
    int total = 0;
    int healthy = 0;
    int connecting = 0;
    int candidate = 0;
    int degraded = 0;
    int offline = 0;
    int banned = 0;
    std::string lastUsedRelay;
    std::string lastFailedRelay;
    int recentFailures = 0;
};

// 从 UTF-8 文本读取 relay URL。文件可以只包含 URL 行，也可以包含 [pool] 段。
std::vector<std::string> readRelayUrlsFromFile(const std::filesystem::path& path);

// 根据 URL 列表生成规范 manifest。调用方可以再追加签名字段。
json buildRelayManifest(const std::vector<std::string>& urls, const std::string& source);

// 用稳定 JSON 文本作为签名和 manifest id 输入。
std::string canonicalRelayManifest(const json& manifest);

// 读取 pool 文件并返回 manifest 与 URL 列表。
RelayPoolLoadResult loadRelayPoolFile(const std::filesystem::path& path, const std::string& source);

// 把房间级 manifest 写成 SQLite 副本。
void writeRelayPoolDatabase(const std::filesystem::path& roomDir, const json& manifest);

// 从 SQLite 副本读取当前首选 relay。
std::string primaryRelayUrlFromRoomDir(const std::filesystem::path& roomDir);

// 从 SQLite 副本读取当前 room instance 的完整 relay URL 列表。
std::vector<std::string> relayUrlsFromRoomDir(const std::filesystem::path& roomDir);

// 更新某个 relay 的本机连接状态。
void markRelayStatus(const std::filesystem::path& roomDir, const std::string& url, const std::string& status);

// 记录一次经某个 relay 发送的 payload，用于 UI 摘要和后续重传排障。
void recordRelaySend(
    const std::filesystem::path& roomDir,
    const std::string& url,
    bool chunk,
    bool success);

// 记录一次可靠投递缺失请求，便于排查 relay 丢帧和附件缺块。
void recordRelayMissing(
    const std::filesystem::path& roomDir,
    const std::string& requestId,
    const std::string& itemId,
    const std::string& missingBitmap,
    int retryCount);

// 读取当前 relay pool 健康摘要。
RelayStatusSummary relayStatusSummary(const std::filesystem::path& roomDir);

// 面向 CLI/WinUI 的短摘要，不包含聊天明文。
std::string relayStatusSummaryText(const std::filesystem::path& roomDir);

std::filesystem::path relayPoolDatabasePath(const std::filesystem::path& roomDir);

} // namespace chat::relay_pool
