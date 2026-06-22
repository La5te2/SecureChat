// 房间级 relay pool 的解析和本机 SQLite 副本实现。
// 该副本记录连接 relay 的方法。
#include "relay_pool.hpp"

#include "cert_utils.hpp"
#include "websocket_config.hpp"

#include <sqlite3.h>

#include <algorithm>
#include <cctype>
#include <chrono>
#include <condition_variable>
#include <cstdlib>
#include <fstream>
#include <memory>
#include <mutex>
#include <sstream>
#include <stdexcept>
#include <variant>

namespace chat::relay_pool {
namespace {

struct RelayProbeResult {
    std::string url;
    std::string relayInstanceId;
};

std::string trim(std::string value) {
    const auto first = value.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) return "";
    const auto last = value.find_last_not_of(" \t\r\n");
    return value.substr(first, last - first + 1);
}

bool startsWith(const std::string& value, const std::string& prefix) {
    return value.rfind(prefix, 0) == 0;
}

bool isRelayUrl(const std::string& value) {
    // 房间级 pool 面向成员可直接访问的 TLS relay 入口。
    return startsWith(value, "wss://");
}

int relayProbeTimeoutMs() {
    const char* raw = std::getenv("SECURECHAT_RELAY_PROBE_TIMEOUT_MS");
    if (raw == nullptr || *raw == '\0') return 600;
    try {
        const auto value = std::stoi(raw);
        return std::max(250, std::min(value, 10000));
    }
    catch (...) {
        return 600;
    }
}

RelayProbeResult probeRelayIdentity(const std::string& url, int timeoutMs) {
    struct ProbeState {
        std::mutex mutex;
        std::condition_variable ready;
        bool finished = false;
        std::string relayInstanceId;
    };

    rtc::WebSocket::Configuration config;
    chat::websocket_config::applyClientTlsFromEnvironment(config);
    auto state = std::make_shared<ProbeState>();
    auto ws = std::make_shared<rtc::WebSocket>(config);
    const auto nonce = chat::cert_utils::base64Encode(chat::cert_utils::randomBytes(16));

    ws->onOpen([ws, nonce]() {
        // relay_probe 不创建房间，也不进入成员状态；它只让 Host 区分
        // “两个 URL”是否实际指向同一个 Server 进程。
        ws->send(json{
            {"type", "relay_probe"},
            {"nonce", nonce}
        }.dump());
    });
    ws->onMessage([state, nonce](rtc::message_variant data) {
        const auto text = std::holds_alternative<std::string>(data)
            ? std::get<std::string>(data)
            : std::string(
                  reinterpret_cast<const char*>(std::get<rtc::binary>(data).data()),
                  std::get<rtc::binary>(data).size());
        try {
            auto response = chat::protocol::parseJsonObjectWithBudget(
                text,
                chat::protocol::MaxSignalingMessageBytes,
                "relay probe response");
            if (response.value("type", "") != "relay_probe_result" ||
                response.value("nonce", "") != nonce) {
                return;
            }
            const auto instanceId = response.value("relayInstanceId", "");
            if (instanceId.empty() || instanceId.size() > 128) return;
            std::lock_guard<std::mutex> lock(state->mutex);
            state->relayInstanceId = instanceId;
            state->finished = true;
            state->ready.notify_all();
        }
        catch (...) {
            std::lock_guard<std::mutex> lock(state->mutex);
            state->finished = true;
            state->ready.notify_all();
        }
    });
    ws->onError([state](std::string) {
        std::lock_guard<std::mutex> lock(state->mutex);
        state->finished = true;
        state->ready.notify_all();
    });
    ws->onClosed([state]() {
        std::lock_guard<std::mutex> lock(state->mutex);
        state->finished = true;
        state->ready.notify_all();
    });

    try {
        ws->open(url);
    }
    catch (...) {
        return {};
    }

    std::string relayInstanceId;
    {
        std::unique_lock<std::mutex> lock(state->mutex);
        state->ready.wait_for(lock, std::chrono::milliseconds(timeoutMs), [&]() {
            return state->finished;
        });
        relayInstanceId = state->relayInstanceId;
    }
    try {
        ws->close();
    }
    catch (...) {
    }
    if (relayInstanceId.empty()) return {};
    return {url, relayInstanceId};
}

std::vector<std::string> uniqueRelayUrls(const std::vector<std::string>& urls) {
    std::vector<std::string> unique;
    for (const auto& url : urls) {
        if (!isRelayUrl(url)) throw std::runtime_error("invalid relay URL in pool: " + url);
        if (std::find(unique.begin(), unique.end(), url) == unique.end()) {
            unique.push_back(url);
        }
    }
    if (unique.empty()) throw std::runtime_error("relay pool is empty");
    return unique;
}

std::vector<std::string> selectRoomRelays(const std::vector<std::string>& candidateUrls) {
    auto selected = uniqueRelayUrls(candidateUrls);
    if (selected.size() > MaxRoomRelayCount) {
        selected.resize(MaxRoomRelayCount);
    }
    return selected;
}

std::vector<RelayProbeResult> reachableRelayIdentities(const std::vector<std::string>& candidateUrls) {
    const auto timeoutMs = relayProbeTimeoutMs();
    std::vector<RelayProbeResult> reachable;
    for (const auto& url : candidateUrls) {
        auto probe = probeRelayIdentity(url, timeoutMs);
        if (!probe.url.empty() && !probe.relayInstanceId.empty()) {
            reachable.push_back(std::move(probe));
        }
    }
    if (reachable.empty()) {
        throw std::runtime_error("relay pool has no currently reachable relay");
    }
    return reachable;
}

std::vector<RelayProbeResult> uniqueRelayInstances(const std::vector<RelayProbeResult>& reachable) {
    std::vector<RelayProbeResult> selected;
    std::vector<std::string> seenInstanceIds;
    for (const auto& relay : reachable) {
        if (std::find(seenInstanceIds.begin(), seenInstanceIds.end(), relay.relayInstanceId) != seenInstanceIds.end()) {
            continue;
        }
        seenInstanceIds.push_back(relay.relayInstanceId);
        selected.push_back(relay);
    }
    if (selected.empty()) throw std::runtime_error("relay pool has no unique reachable relay");
    return selected;
}

std::vector<RelayProbeResult> selectRoomRelayInstances(const std::vector<RelayProbeResult>& uniqueRelays) {
    auto selected = uniqueRelays;
    if (selected.size() > MaxRoomRelayCount) selected.resize(MaxRoomRelayCount);
    return selected;
}

std::vector<std::string> relayUrlsFromProbeResults(const std::vector<RelayProbeResult>& relays) {
    std::vector<std::string> urls;
    urls.reserve(relays.size());
    for (const auto& relay : relays) urls.push_back(relay.url);
    return urls;
}

long long nowUnixMs() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

std::string readTextFile(const std::filesystem::path& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file) throw std::runtime_error("failed to open relay pool file: " + path.u8string());
    std::ostringstream buffer;
    buffer << file.rdbuf();
    return buffer.str();
}

void ensureDirectory(const std::filesystem::path& path) {
    std::error_code ec;
    std::filesystem::create_directories(path, ec);
    if (ec) throw std::runtime_error("failed to create relay directory: " + path.u8string() + ": " + ec.message());
}

void execSql(sqlite3* db, const char* sql) {
    char* error = nullptr;
    if (sqlite3_exec(db, sql, nullptr, nullptr, &error) != SQLITE_OK) {
        std::string message = error ? error : "unknown sqlite error";
        sqlite3_free(error);
        throw std::runtime_error("relay pool sqlite error: " + message);
    }
}

void bindText(sqlite3_stmt* stmt, int index, const std::string& value) {
    if (sqlite3_bind_text(stmt, index, value.c_str(), static_cast<int>(value.size()), SQLITE_TRANSIENT) != SQLITE_OK) {
        throw std::runtime_error("relay pool sqlite bind failed");
    }
}

struct Database {
    explicit Database(const std::filesystem::path& path) {
        sqlite3* raw = nullptr;
        if (sqlite3_open(path.u8string().c_str(), &raw) != SQLITE_OK) {
            std::string message = raw ? sqlite3_errmsg(raw) : "sqlite allocation failed";
            if (raw) sqlite3_close(raw);
            throw std::runtime_error("failed to open relay pool database: " + message);
        }
        db = raw;
    }

    ~Database() {
        if (db) sqlite3_close(db);
    }

    sqlite3* db = nullptr;
};

struct Statement {
    Statement(sqlite3* db, const char* sql) {
        if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
            throw std::runtime_error("relay pool sqlite prepare failed: " + std::string(sqlite3_errmsg(db)));
        }
    }

    ~Statement() {
        if (stmt) sqlite3_finalize(stmt);
    }

    sqlite3_stmt* stmt = nullptr;
};

void createSchema(sqlite3* db) {
    execSql(db,
        "CREATE TABLE IF NOT EXISTS relay_nodes ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "url TEXT NOT NULL UNIQUE,"
        "source TEXT NOT NULL,"
        "manifest_id TEXT NOT NULL,"
        "schema_version INTEGER NOT NULL,"
        "status TEXT NOT NULL DEFAULT 'candidate',"
        "weight INTEGER NOT NULL DEFAULT 100,"
        "rtt_ms INTEGER NOT NULL DEFAULT 0,"
        "success_count INTEGER NOT NULL DEFAULT 0,"
        "failure_count INTEGER NOT NULL DEFAULT 0,"
        "last_used_unix_ms INTEGER NOT NULL DEFAULT 0"
        ")");
    execSql(db,
        "CREATE TABLE IF NOT EXISTS relay_manifests ("
        "manifest_id TEXT PRIMARY KEY,"
        "schema_version INTEGER NOT NULL,"
        "source TEXT NOT NULL,"
        "raw_json TEXT NOT NULL"
        ")");
    execSql(db,
        "CREATE TABLE IF NOT EXISTS relay_room_states ("
        "room_instance_digest TEXT PRIMARY KEY,"
        "status TEXT NOT NULL,"
        "host_fingerprint TEXT NOT NULL,"
        "open_event_hash TEXT NOT NULL DEFAULT '',"
        "close_event_hash TEXT NOT NULL DEFAULT '',"
        "updated_unix_ms INTEGER NOT NULL DEFAULT 0,"
        "raw_signed_event TEXT NOT NULL DEFAULT ''"
        ")");
    execSql(db,
        "CREATE TABLE IF NOT EXISTS relay_send_stats ("
        "url TEXT PRIMARY KEY,"
        "message_count INTEGER NOT NULL DEFAULT 0,"
        "chunk_count INTEGER NOT NULL DEFAULT 0,"
        "failure_count INTEGER NOT NULL DEFAULT 0,"
        "last_used_unix_ms INTEGER NOT NULL DEFAULT 0"
        ")");
    execSql(db,
        "CREATE TABLE IF NOT EXISTS relay_schedule_events ("
        "event_id TEXT PRIMARY KEY,"
        "label TEXT NOT NULL,"
        "schema_version INTEGER NOT NULL DEFAULT 1,"
        "attempt INTEGER NOT NULL DEFAULT 0,"
        "relay_set_digest TEXT NOT NULL,"
        "created_unix_ms INTEGER NOT NULL DEFAULT 0"
        ")");
    execSql(db,
        "CREATE TABLE IF NOT EXISTS relay_missing_requests ("
        "request_id TEXT PRIMARY KEY,"
        "item_id TEXT NOT NULL,"
        "missing_bitmap TEXT NOT NULL,"
        "retry_count INTEGER NOT NULL DEFAULT 0,"
        "last_request_unix_ms INTEGER NOT NULL DEFAULT 0"
        ")");
}

} // namespace

std::vector<std::string> readRelayUrlsFromFile(const std::filesystem::path& path) {
    const auto text = readTextFile(path);
    std::istringstream input(text);
    std::vector<std::string> urls;
    bool sawSection = false;
    bool inPool = false;
    std::string raw;
    while (std::getline(input, raw)) {
        auto line = trim(raw);
        if (line.size() >= 3 &&
            static_cast<unsigned char>(line[0]) == 0xef &&
            static_cast<unsigned char>(line[1]) == 0xbb &&
            static_cast<unsigned char>(line[2]) == 0xbf) {
            line.erase(0, 3);
            line = trim(line);
        }
        if (line.empty() || startsWith(line, "#")) continue;

        if (line.size() > 2 && line.front() == '[' && line.back() == ']') {
            sawSection = true;
            auto section = trim(line.substr(1, line.size() - 2));
            std::transform(section.begin(), section.end(), section.begin(), [](unsigned char ch) {
                return static_cast<char>(std::tolower(ch));
            });
            inPool = section == "pool";
            continue;
        }

        if (sawSection && !inPool) continue;
        if (!isRelayUrl(line)) {
            if (inPool || !sawSection) {
                throw std::runtime_error("invalid relay URL in pool file: " + line);
            }
            continue;
        }
        urls.push_back(std::move(line));
    }

    return uniqueRelayUrls(urls);
}

json buildRelayManifest(const std::vector<std::string>& urls, const std::string& source) {
    const auto roomRelays = selectRoomRelays(urls);
    json relays = json::array();
    for (const auto& url : roomRelays) {
        relays.push_back({
            {"url", url},
            {"weight", 100},
            {"source", source.empty() ? "local" : source}
        });
    }

    json manifest = {
        {"version", 1},
        {"kind", "securechat-relay-pool"},
        {"source", source.empty() ? "local" : source},
        {"maxRelayCount", static_cast<int>(MaxRoomRelayCount)},
        {"selectedRelayCount", static_cast<int>(roomRelays.size())},
        {"relays", relays}
    };
    manifest["manifestId"] = chat::cert_utils::sha256Hex(canonicalRelayManifest(manifest));
    return manifest;
}

json buildRelayManifestFromProbeResults(const std::vector<RelayProbeResult>& selected, const std::string& source) {
    if (selected.empty()) throw std::runtime_error("relay pool is empty");
    json relays = json::array();
    for (const auto& relay : selected) {
        relays.push_back({
            {"url", relay.url},
            {"relayInstanceId", relay.relayInstanceId},
            {"weight", 100},
            {"source", source.empty() ? "local" : source}
        });
    }

    json manifest = {
        {"version", 1},
        {"kind", "securechat-relay-pool"},
        {"source", source.empty() ? "local" : source},
        {"maxRelayCount", static_cast<int>(MaxRoomRelayCount)},
        {"selectedRelayCount", static_cast<int>(selected.size())},
        {"relays", relays}
    };
    manifest["manifestId"] = chat::cert_utils::sha256Hex(canonicalRelayManifest(manifest));
    return manifest;
}

std::string canonicalRelayManifest(const json& manifest) {
    auto copy = manifest;
    copy.erase("signature");
    copy.erase("manifestId");
    return copy.dump();
}

RelayPoolLoadResult loadRelayPoolFile(const std::filesystem::path& path, const std::string& source) {
    auto candidates = readRelayUrlsFromFile(path);
    auto reachableUrls = reachableRelayIdentities(candidates);
    auto reachableRelays = uniqueRelayInstances(reachableUrls);
    auto selectedRelays = selectRoomRelayInstances(reachableRelays);
    auto selected = relayUrlsFromProbeResults(selectedRelays);
    auto manifest = buildRelayManifestFromProbeResults(selectedRelays, source);
    manifest["candidateRelayCount"] = static_cast<int>(candidates.size());
    manifest["reachableUrlCount"] = static_cast<int>(reachableUrls.size());
    manifest["reachableRelayCount"] = static_cast<int>(reachableRelays.size());
    manifest["selectedRelayCount"] = static_cast<int>(selected.size());
    manifest["manifestId"] = chat::cert_utils::sha256Hex(canonicalRelayManifest(manifest));
    return {std::move(manifest), std::move(selected), candidates.size(), reachableRelays.size()};
}

std::filesystem::path relayPoolDatabasePath(const std::filesystem::path& roomDir) {
    return roomDir / "relay" / "relay-pool.sqlite3";
}

void writeRelayPoolDatabase(const std::filesystem::path& roomDir, const json& manifest) {
    if (!manifest.is_object() || manifest.value("kind", "") != "securechat-relay-pool") {
        throw std::runtime_error("relay pool manifest is invalid");
    }
    const auto relays = manifest.value("relays", json::array());
    if (!relays.is_array() || relays.empty()) {
        throw std::runtime_error("relay pool manifest has no relay URL");
    }
    if (relays.size() > MaxRoomRelayCount) {
        throw std::runtime_error("relay pool manifest exceeds room relay limit");
    }
    std::vector<std::string> seenUrls;
    std::vector<std::string> seenInstanceIds;
    for (const auto& relay : relays) {
        const auto url = relay.value("url", "");
        if (!isRelayUrl(url)) throw std::runtime_error("relay pool manifest has invalid URL");
        if (std::find(seenUrls.begin(), seenUrls.end(), url) != seenUrls.end()) {
            throw std::runtime_error("relay pool manifest has duplicate URL");
        }
        seenUrls.push_back(url);
        const auto instanceId = relay.value("relayInstanceId", "");
        if (!instanceId.empty()) {
            if (instanceId.size() > 128) throw std::runtime_error("relay pool manifest has invalid instance id");
            if (std::find(seenInstanceIds.begin(), seenInstanceIds.end(), instanceId) != seenInstanceIds.end()) {
                throw std::runtime_error("relay pool manifest has duplicate instance id");
            }
            seenInstanceIds.push_back(instanceId);
        }
    }

    const auto dbPath = relayPoolDatabasePath(roomDir);
    ensureDirectory(dbPath.parent_path());
    Database database(dbPath);
    createSchema(database.db);
    execSql(database.db, "BEGIN IMMEDIATE");
    try {
        execSql(database.db, "DELETE FROM relay_nodes");
        const auto manifestId = manifest.value("manifestId", chat::cert_utils::sha256Hex(canonicalRelayManifest(manifest)));
        const auto schemaVersion = manifest.value("version", 1);
        const auto source = manifest.value("source", "local");

        {
            Statement stmt(database.db,
                "INSERT OR REPLACE INTO relay_manifests "
                "(manifest_id, schema_version, source, raw_json) VALUES (?, ?, ?, ?)");
            bindText(stmt.stmt, 1, manifestId);
            sqlite3_bind_int64(stmt.stmt, 2, schemaVersion);
            bindText(stmt.stmt, 3, source);
            const auto raw = manifest.dump();
            bindText(stmt.stmt, 4, raw);
            if (sqlite3_step(stmt.stmt) != SQLITE_DONE) {
                throw std::runtime_error("relay pool manifest insert failed");
            }
        }

        for (const auto& relay : relays) {
            const auto url = relay.value("url", "");
            Statement stmt(database.db,
                "INSERT OR REPLACE INTO relay_nodes "
                "(url, source, manifest_id, schema_version, status, weight) VALUES (?, ?, ?, ?, 'candidate', ?)");
            bindText(stmt.stmt, 1, url);
            bindText(stmt.stmt, 2, relay.value("source", source));
            bindText(stmt.stmt, 3, manifestId);
            sqlite3_bind_int64(stmt.stmt, 4, schemaVersion);
            sqlite3_bind_int64(stmt.stmt, 5, relay.value("weight", 100));
            if (sqlite3_step(stmt.stmt) != SQLITE_DONE) {
                throw std::runtime_error("relay pool node insert failed");
            }
        }
        execSql(database.db, "COMMIT");
    }
    catch (...) {
        execSql(database.db, "ROLLBACK");
        throw;
    }
}

std::string primaryRelayUrlFromRoomDir(const std::filesystem::path& roomDir) {
    const auto dbPath = relayPoolDatabasePath(roomDir);
    if (!std::filesystem::is_regular_file(dbPath)) {
        throw std::runtime_error("relay pool database is missing: " + dbPath.u8string());
    }
    Database database(dbPath);
    createSchema(database.db);
    Statement stmt(database.db,
        "SELECT url FROM relay_nodes "
        "WHERE status <> 'banned' "
        "ORDER BY CASE status WHEN 'healthy' THEN 0 WHEN 'candidate' THEN 1 ELSE 2 END, id "
        "LIMIT 1");
    if (sqlite3_step(stmt.stmt) != SQLITE_ROW) {
        throw std::runtime_error("relay pool has no usable relay");
    }
    const auto* text = reinterpret_cast<const char*>(sqlite3_column_text(stmt.stmt, 0));
    return text ? text : "";
}

std::vector<std::string> relayUrlsFromRoomDir(const std::filesystem::path& roomDir) {
    const auto dbPath = relayPoolDatabasePath(roomDir);
    if (!std::filesystem::is_regular_file(dbPath)) {
        throw std::runtime_error("relay pool database is missing: " + dbPath.u8string());
    }

    Database database(dbPath);
    createSchema(database.db);
    Statement stmt(database.db,
        "SELECT url FROM relay_nodes "
        "WHERE status <> 'banned' "
        "ORDER BY CASE status WHEN 'healthy' THEN 0 WHEN 'candidate' THEN 1 ELSE 2 END, id");

    std::vector<std::string> urls;
    while (sqlite3_step(stmt.stmt) == SQLITE_ROW) {
        const auto* text = reinterpret_cast<const char*>(sqlite3_column_text(stmt.stmt, 0));
        if (text && *text) urls.emplace_back(text);
    }
    if (urls.empty()) throw std::runtime_error("relay pool has no usable relay");
    return urls;
}

void markRelayStatus(const std::filesystem::path& roomDir, const std::string& url, const std::string& status) {
    if (roomDir.empty() || url.empty()) return;
    const auto dbPath = relayPoolDatabasePath(roomDir);
    if (!std::filesystem::is_regular_file(dbPath)) return;
    Database database(dbPath);
    createSchema(database.db);
    Statement stmt(database.db,
        "UPDATE relay_nodes SET status = ? WHERE url = ?");
    bindText(stmt.stmt, 1, status);
    bindText(stmt.stmt, 2, url);
    sqlite3_step(stmt.stmt);
}

void recordRelaySend(
    const std::filesystem::path& roomDir,
    const std::string& url,
    bool chunk,
    bool success) {
    if (roomDir.empty() || url.empty()) return;
    const auto dbPath = relayPoolDatabasePath(roomDir);
    if (!std::filesystem::is_regular_file(dbPath)) return;
    Database database(dbPath);
    createSchema(database.db);
    const auto now = nowUnixMs();
    {
        Statement stmt(database.db,
            "INSERT INTO relay_send_stats (url, message_count, chunk_count, failure_count, last_used_unix_ms) "
            "VALUES (?, ?, ?, ?, ?) "
            "ON CONFLICT(url) DO UPDATE SET "
            "message_count = message_count + excluded.message_count,"
            "chunk_count = chunk_count + excluded.chunk_count,"
            "failure_count = failure_count + excluded.failure_count,"
            "last_used_unix_ms = excluded.last_used_unix_ms");
        bindText(stmt.stmt, 1, url);
        sqlite3_bind_int64(stmt.stmt, 2, success && !chunk ? 1 : 0);
        sqlite3_bind_int64(stmt.stmt, 3, success && chunk ? 1 : 0);
        sqlite3_bind_int64(stmt.stmt, 4, success ? 0 : 1);
        sqlite3_bind_int64(stmt.stmt, 5, now);
        sqlite3_step(stmt.stmt);
    }

    {
        Statement stmt(database.db,
            "UPDATE relay_nodes SET "
            "status = ?,"
            "success_count = success_count + ?,"
            "failure_count = failure_count + ?,"
            "last_used_unix_ms = ? "
            "WHERE url = ?");
        bindText(stmt.stmt, 1, success ? "healthy" : "degraded");
        sqlite3_bind_int64(stmt.stmt, 2, success ? 1 : 0);
        sqlite3_bind_int64(stmt.stmt, 3, success ? 0 : 1);
        sqlite3_bind_int64(stmt.stmt, 4, now);
        bindText(stmt.stmt, 5, url);
        sqlite3_step(stmt.stmt);
    }
}

void recordRelayMissing(
    const std::filesystem::path& roomDir,
    const std::string& requestId,
    const std::string& itemId,
    const std::string& missingBitmap,
    int retryCount) {
    if (roomDir.empty() || requestId.empty() || itemId.empty()) return;
    const auto dbPath = relayPoolDatabasePath(roomDir);
    if (!std::filesystem::is_regular_file(dbPath)) return;
    Database database(dbPath);
    createSchema(database.db);
    Statement stmt(database.db,
        "INSERT INTO relay_missing_requests (request_id, item_id, missing_bitmap, retry_count, last_request_unix_ms) "
        "VALUES (?, ?, ?, ?, ?) "
        "ON CONFLICT(request_id) DO UPDATE SET "
        "missing_bitmap = excluded.missing_bitmap,"
        "retry_count = excluded.retry_count,"
        "last_request_unix_ms = excluded.last_request_unix_ms");
    bindText(stmt.stmt, 1, requestId);
    bindText(stmt.stmt, 2, itemId);
    bindText(stmt.stmt, 3, missingBitmap);
    sqlite3_bind_int64(stmt.stmt, 4, retryCount);
    sqlite3_bind_int64(stmt.stmt, 5, nowUnixMs());
    sqlite3_step(stmt.stmt);
}

RelayStatusSummary relayStatusSummary(const std::filesystem::path& roomDir) {
    RelayStatusSummary summary;
    const auto dbPath = relayPoolDatabasePath(roomDir);
    if (roomDir.empty() || !std::filesystem::is_regular_file(dbPath)) return summary;
    Database database(dbPath);
    createSchema(database.db);

    {
        Statement stmt(database.db,
            "SELECT status, COUNT(*) FROM relay_nodes GROUP BY status");
        while (sqlite3_step(stmt.stmt) == SQLITE_ROW) {
            const auto* text = reinterpret_cast<const char*>(sqlite3_column_text(stmt.stmt, 0));
            const auto count = static_cast<int>(sqlite3_column_int64(stmt.stmt, 1));
            const std::string status = text ? text : "";
            summary.total += count;
            if (status == "healthy") summary.healthy += count;
            else if (status == "connecting") summary.connecting += count;
            else if (status == "candidate") summary.candidate += count;
            else if (status == "degraded") summary.degraded += count;
            else if (status == "offline") summary.offline += count;
            else if (status == "banned") summary.banned += count;
        }
    }

    {
        Statement stmt(database.db,
            "SELECT url FROM relay_send_stats WHERE last_used_unix_ms > 0 "
            "ORDER BY last_used_unix_ms DESC LIMIT 1");
        if (sqlite3_step(stmt.stmt) == SQLITE_ROW) {
            const auto* text = reinterpret_cast<const char*>(sqlite3_column_text(stmt.stmt, 0));
            if (text) summary.lastUsedRelay = text;
        }
    }

    {
        Statement stmt(database.db,
            "SELECT url, failure_count FROM relay_send_stats WHERE failure_count > 0 "
            "ORDER BY last_used_unix_ms DESC LIMIT 1");
        if (sqlite3_step(stmt.stmt) == SQLITE_ROW) {
            const auto* text = reinterpret_cast<const char*>(sqlite3_column_text(stmt.stmt, 0));
            if (text) summary.lastFailedRelay = text;
            summary.recentFailures = static_cast<int>(sqlite3_column_int64(stmt.stmt, 1));
        }
    }

    return summary;
}

std::string relayStatusSummaryText(const std::filesystem::path& roomDir) {
    const auto summary = relayStatusSummary(roomDir);
    std::ostringstream out;
    out << "available " << summary.healthy << " / " << summary.total;
    if (summary.connecting > 0) out << "; connecting " << summary.connecting;
    if (summary.degraded > 0) out << "; degraded " << summary.degraded;
    if (summary.offline > 0) out << "; offline " << summary.offline;
    if (!summary.lastUsedRelay.empty()) out << "; current " << summary.lastUsedRelay;
    if (!summary.lastFailedRelay.empty()) {
        out << "; recent failure " << summary.lastFailedRelay << " x" << summary.recentFailures;
    }
    return out.str();
}

} // namespace chat::relay_pool
