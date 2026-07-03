// Server 状态 SQLite 存储实现。
#include "server_state_store.hpp"

#include <sqlite3.h>

#include <chrono>
#include <cstdlib>
#include <ctime>
#include <filesystem>
#include <iomanip>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

std::string envValue(const char* name) {
    const char* value = std::getenv(name);
    return value == nullptr ? std::string() : std::string(value);
}

std::filesystem::path pathFromUtf8(const std::string& value) {
    return std::filesystem::u8path(value);
}

std::string timestampForFile() {
    const auto now = std::chrono::system_clock::now();
    const auto seconds = std::chrono::time_point_cast<std::chrono::seconds>(now);
    const auto millis = std::chrono::duration_cast<std::chrono::milliseconds>(now - seconds).count();
    const auto timeValue = std::chrono::system_clock::to_time_t(now);

    std::tm local{};
#ifdef _WIN32
    localtime_s(&local, &timeValue);
#else
    localtime_r(&timeValue, &local);
#endif

    std::ostringstream out;
    out << std::put_time(&local, "%Y%m%d-%H%M%S")
        << '-' << std::setw(3) << std::setfill('0') << millis;
    return out.str();
}

bool envFlagEnabled(const char* name) {
    const auto value = envValue(name);
    return value == "1" || value == "true" || value == "TRUE" ||
        value == "yes" || value == "YES" || value == "on" || value == "ON";
}

bool isTimestampStateDb(const std::filesystem::directory_entry& entry) {
    if (!entry.is_regular_file()) return false;
    const auto path = entry.path();
    if (path.extension() != ".sqlite3") return false;

    const auto name = path.stem().string();
    if (name.size() != 19) return false;
    for (std::size_t i = 0; i < name.size(); ++i) {
        const char ch = name[i];
        if (i == 8 || i == 15) {
            if (ch != '-') return false;
            continue;
        }
        if (ch < '0' || ch > '9') return false;
    }
    return true;
}

std::optional<std::string> latestTimestampDbPath(const std::filesystem::path& directory) {
    std::error_code ec;
    if (!std::filesystem::exists(directory, ec)) return std::nullopt;

    std::string latestName;
    std::filesystem::path latestPath;
    for (const auto& entry : std::filesystem::directory_iterator(directory, ec)) {
        if (ec) break;
        if (!isTimestampStateDb(entry)) continue;
        if (entry.file_size(ec) == 0 || ec) {
            ec.clear();
            continue;
        }

        const auto name = entry.path().stem().string();
        if (latestName.empty() || name > latestName) {
            latestName = name;
            latestPath = entry.path();
        }
    }
    if (latestPath.empty()) return std::nullopt;
    return latestPath.generic_string();
}

std::string defaultDbPath() {
    const auto configured = envValue("SECURECHAT_SERVER_STATE_DB");
    if (!configured.empty()) return configured;

    const std::filesystem::path stateDir = "server/state";
    if (!envFlagEnabled("SECURECHAT_SERVER_STATE_FRESH")) {
        if (const auto latest = latestTimestampDbPath(stateDir)) {
            return *latest;
        }
    }
    return (stateDir / (timestampForFile() + ".sqlite3")).generic_string();
}

void execSql(sqlite3* db, const char* sql) {
    char* error = nullptr;
    if (sqlite3_exec(db, sql, nullptr, nullptr, &error) != SQLITE_OK) {
        std::string message = error ? error : "unknown sqlite error";
        sqlite3_free(error);
        throw std::runtime_error("server state store SQL failed: " + message);
    }
}

void bindText(sqlite3_stmt* stmt, int index, const std::string& value) {
    if (sqlite3_bind_text(stmt, index, value.c_str(), static_cast<int>(value.size()), SQLITE_TRANSIENT) != SQLITE_OK) {
        throw std::runtime_error("server state store bind failed");
    }
}

class Statement {
public:
    Statement(sqlite3* db, const char* sql) : mDb(db) {
        if (sqlite3_prepare_v2(db, sql, -1, &mStmt, nullptr) != SQLITE_OK) {
            throw std::runtime_error("server state store prepare failed: " + std::string(sqlite3_errmsg(db)));
        }
    }
    ~Statement() {
        if (mStmt) sqlite3_finalize(mStmt);
    }
    sqlite3_stmt* get() const { return mStmt; }

private:
    sqlite3* mDb = nullptr;
    sqlite3_stmt* mStmt = nullptr;
};

sqlite3* dbPtr(void* value) {
    return static_cast<sqlite3*>(value);
}

}

ServerStateStore::ServerStateStore() : mPath(defaultDbPath()) {
    open();
    migrate();
}

ServerStateStore::~ServerStateStore() {
    if (mDb) {
        sqlite3_close(dbPtr(mDb));
        mDb = nullptr;
    }
}

const std::string& ServerStateStore::path() const {
    return mPath;
}

void ServerStateStore::open() {
    const auto path = pathFromUtf8(mPath);
    std::error_code ec;
    if (path.has_parent_path()) {
        std::filesystem::create_directories(path.parent_path(), ec);
        if (ec) throw std::runtime_error("failed to create Server state directory: " + ec.message());
    }

    sqlite3* db = nullptr;
    if (sqlite3_open(mPath.c_str(), &db) != SQLITE_OK) {
        std::string message = db ? sqlite3_errmsg(db) : "sqlite allocation failed";
        if (db) sqlite3_close(db);
        throw std::runtime_error("failed to open Server state database: " + message);
    }
    mDb = db;
}

void ServerStateStore::migrate() {
    auto* db = dbPtr(mDb);
    execSql(db, "PRAGMA journal_mode=WAL;");
    execSql(db,
        "CREATE TABLE IF NOT EXISTS rooms ("
        "room_id TEXT PRIMARY KEY,"
        "state TEXT NOT NULL,"
        "updated_at INTEGER NOT NULL DEFAULT (unixepoch())"
        ");");
    execSql(db,
        "CREATE TABLE IF NOT EXISTS pending_joins ("
        "room_id TEXT NOT NULL,"
        "request_id TEXT NOT NULL,"
        "payload TEXT NOT NULL,"
        "created_at INTEGER NOT NULL DEFAULT (unixepoch()),"
        "PRIMARY KEY(room_id, request_id)"
        ");");
    execSql(db,
        "CREATE TABLE IF NOT EXISTS membership_events ("
        "room_id TEXT NOT NULL,"
        "event_id TEXT NOT NULL,"
        "payload TEXT NOT NULL,"
        "created_at INTEGER NOT NULL DEFAULT (unixepoch()),"
        "PRIMARY KEY(room_id, event_id)"
        ");");
    execSql(db,
        "CREATE TABLE IF NOT EXISTS group_state_envelopes ("
        "room_id TEXT NOT NULL,"
        "member_fingerprint TEXT NOT NULL,"
        "payload TEXT NOT NULL,"
        "updated_at INTEGER NOT NULL DEFAULT (unixepoch()),"
        "PRIMARY KEY(room_id, member_fingerprint)"
        ");");
    execSql(db,
        "CREATE TABLE IF NOT EXISTS forum_records ("
        "room_id TEXT NOT NULL,"
        "board_message_id TEXT NOT NULL,"
        "record_hash TEXT NOT NULL,"
        "payload TEXT NOT NULL,"
        "created_at INTEGER NOT NULL DEFAULT (unixepoch()),"
        "PRIMARY KEY(room_id, board_message_id, record_hash)"
        ");");
}

std::vector<std::string> ServerStateStore::loadOpenRooms() {
    Statement stmt(dbPtr(mDb), "SELECT room_id FROM rooms WHERE state='open';");
    std::vector<std::string> rooms;
    while (sqlite3_step(stmt.get()) == SQLITE_ROW) {
        const auto* text = reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 0));
        if (text) rooms.emplace_back(text);
    }
    return rooms;
}

std::vector<ServerStateStore::PendingJoin> ServerStateStore::loadPendingJoins(const std::string& roomId) {
    Statement stmt(dbPtr(mDb), "SELECT request_id, payload FROM pending_joins WHERE room_id=? ORDER BY created_at;");
    bindText(stmt.get(), 1, roomId);
    std::vector<PendingJoin> pending;
    while (sqlite3_step(stmt.get()) == SQLITE_ROW) {
        const auto* id = reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 0));
        const auto* payload = reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 1));
        if (id && payload) pending.push_back({id, nlohmann::json::parse(payload)});
    }
    return pending;
}

std::vector<ServerStateStore::MembershipEvent> ServerStateStore::loadMembershipEvents(const std::string& roomId) {
    Statement stmt(dbPtr(mDb), "SELECT event_id, payload FROM membership_events WHERE room_id=? ORDER BY created_at, event_id;");
    bindText(stmt.get(), 1, roomId);
    std::vector<MembershipEvent> events;
    while (sqlite3_step(stmt.get()) == SQLITE_ROW) {
        const auto* id = reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 0));
        const auto* payload = reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 1));
        if (id && payload) events.push_back({id, nlohmann::json::parse(payload)});
    }
    return events;
}

std::vector<ServerStateStore::ForumRecord> ServerStateStore::loadForumRecords(const std::string& roomId, std::size_t limit) {
    Statement stmt(dbPtr(mDb),
        "SELECT board_message_id, record_hash, payload "
        "FROM forum_records WHERE room_id=? ORDER BY created_at, board_message_id LIMIT ?;");
    bindText(stmt.get(), 1, roomId);
    sqlite3_bind_int64(stmt.get(), 2, static_cast<sqlite3_int64>(limit));
    std::vector<ForumRecord> records;
    while (sqlite3_step(stmt.get()) == SQLITE_ROW) {
        const auto* id = reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 0));
        const auto* hash = reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 1));
        const auto* payload = reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 2));
        if (id && hash && payload) records.push_back({id, hash, nlohmann::json::parse(payload)});
    }
    return records;
}

nlohmann::json ServerStateStore::loadGroupStateEnvelope(const std::string& roomId, const std::string& memberFingerprint) {
    Statement stmt(dbPtr(mDb), "SELECT payload FROM group_state_envelopes WHERE room_id=? AND member_fingerprint=?;");
    bindText(stmt.get(), 1, roomId);
    bindText(stmt.get(), 2, memberFingerprint);
    if (sqlite3_step(stmt.get()) != SQLITE_ROW) return nlohmann::json::object();
    const auto* payload = reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 0));
    return payload ? nlohmann::json::parse(payload) : nlohmann::json::object();
}

std::string ServerStateStore::roomState(const std::string& roomId) {
    Statement stmt(dbPtr(mDb), "SELECT state FROM rooms WHERE room_id=?;");
    bindText(stmt.get(), 1, roomId);
    if (sqlite3_step(stmt.get()) != SQLITE_ROW) return "";
    const auto* text = reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 0));
    return text ? std::string(text) : std::string();
}

void ServerStateStore::markRoomOpen(const std::string& roomId) {
    Statement stmt(dbPtr(mDb),
        "INSERT INTO rooms(room_id, state, updated_at) VALUES(?, 'open', unixepoch()) "
        "ON CONFLICT(room_id) DO UPDATE SET state='open', updated_at=unixepoch();");
    bindText(stmt.get(), 1, roomId);
    if (sqlite3_step(stmt.get()) != SQLITE_DONE) {
        throw std::runtime_error("failed to mark room open");
    }
}

void ServerStateStore::markRoomClosed(const std::string& roomId) {
    Statement stmt(dbPtr(mDb),
        "INSERT INTO rooms(room_id, state, updated_at) VALUES(?, 'closed', unixepoch()) "
        "ON CONFLICT(room_id) DO UPDATE SET state='closed', updated_at=unixepoch();");
    bindText(stmt.get(), 1, roomId);
    if (sqlite3_step(stmt.get()) != SQLITE_DONE) {
        throw std::runtime_error("failed to mark room closed");
    }
    clearPendingJoins(roomId);
}

void ServerStateStore::addPendingJoin(const std::string& roomId, const std::string& requestId, const nlohmann::json& payload) {
    Statement stmt(dbPtr(mDb),
        "INSERT OR REPLACE INTO pending_joins(room_id, request_id, payload, created_at) VALUES(?, ?, ?, unixepoch());");
    bindText(stmt.get(), 1, roomId);
    bindText(stmt.get(), 2, requestId);
    bindText(stmt.get(), 3, payload.dump());
    if (sqlite3_step(stmt.get()) != SQLITE_DONE) {
        throw std::runtime_error("failed to add pending join");
    }
}

void ServerStateStore::removePendingJoin(const std::string& roomId, const std::string& requestId) {
    Statement stmt(dbPtr(mDb), "DELETE FROM pending_joins WHERE room_id=? AND request_id=?;");
    bindText(stmt.get(), 1, roomId);
    bindText(stmt.get(), 2, requestId);
    if (sqlite3_step(stmt.get()) != SQLITE_DONE) {
        throw std::runtime_error("failed to remove pending join");
    }
}

void ServerStateStore::clearPendingJoins(const std::string& roomId) {
    Statement stmt(dbPtr(mDb), "DELETE FROM pending_joins WHERE room_id=?;");
    bindText(stmt.get(), 1, roomId);
    if (sqlite3_step(stmt.get()) != SQLITE_DONE) {
        throw std::runtime_error("failed to clear pending joins");
    }
}

void ServerStateStore::addMembershipEvent(
    const std::string& roomId,
    const std::string& eventId,
    const nlohmann::json& payload) {
    Statement stmt(dbPtr(mDb),
        "INSERT OR IGNORE INTO membership_events(room_id, event_id, payload, created_at) "
        "VALUES(?, ?, ?, unixepoch());");
    bindText(stmt.get(), 1, roomId);
    bindText(stmt.get(), 2, eventId);
    bindText(stmt.get(), 3, payload.dump());
    if (sqlite3_step(stmt.get()) != SQLITE_DONE) {
        throw std::runtime_error("failed to add membership event");
    }
}

void ServerStateStore::upsertGroupStateEnvelope(
    const std::string& roomId,
    const std::string& memberFingerprint,
    const nlohmann::json& payload) {
    Statement stmt(dbPtr(mDb),
        "INSERT INTO group_state_envelopes(room_id, member_fingerprint, payload, updated_at) "
        "VALUES(?, ?, ?, unixepoch()) "
        "ON CONFLICT(room_id, member_fingerprint) DO UPDATE SET payload=excluded.payload, updated_at=unixepoch();");
    bindText(stmt.get(), 1, roomId);
    bindText(stmt.get(), 2, memberFingerprint);
    bindText(stmt.get(), 3, payload.dump());
    if (sqlite3_step(stmt.get()) != SQLITE_DONE) {
        throw std::runtime_error("failed to store group state envelope");
    }
}

void ServerStateStore::addForumRecord(
    const std::string& roomId,
    const std::string& boardMessageId,
    const std::string& recordHash,
    const nlohmann::json& payload) {
    Statement stmt(dbPtr(mDb),
        "INSERT OR IGNORE INTO forum_records(room_id, board_message_id, record_hash, payload, created_at) "
        "VALUES(?, ?, ?, ?, unixepoch());");
    bindText(stmt.get(), 1, roomId);
    bindText(stmt.get(), 2, boardMessageId);
    bindText(stmt.get(), 3, recordHash);
    bindText(stmt.get(), 4, payload.dump());
    if (sqlite3_step(stmt.get()) != SQLITE_DONE) {
        throw std::runtime_error("failed to add forum record");
    }
}
