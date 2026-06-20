// 本机文本消息历史实现。SQLite 只做本机 UI 恢复用途，
// 不参与 E2EE、GKA、PKI 或 Server 房间状态。
#include "local_message_store.hpp"

#include "local_paths.hpp"

#include <nlohmann/json.hpp>
#include <sqlite3.h>

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <utility>

namespace chat::local_message {
namespace {
using json = nlohmann::json;

sqlite3* dbPtr(void* value) {
    return static_cast<sqlite3*>(value);
}

std::int64_t nowUnixMs() {
    using namespace std::chrono;
    return duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
}

void execSql(sqlite3* db, const char* sql) {
    char* error = nullptr;
    if (sqlite3_exec(db, sql, nullptr, nullptr, &error) != SQLITE_OK) {
        std::string message = error ? error : "unknown sqlite error";
        sqlite3_free(error);
        throw std::runtime_error("local message store SQL failed: " + message);
    }
}

void bindText(sqlite3_stmt* stmt, int index, const std::string& value) {
    sqlite3_bind_text(stmt, index, value.c_str(), static_cast<int>(value.size()), SQLITE_TRANSIENT);
}

void bindInt64(sqlite3_stmt* stmt, int index, std::int64_t value) {
    sqlite3_bind_int64(stmt, index, static_cast<sqlite3_int64>(value));
}

std::string columnText(sqlite3_stmt* stmt, int column) {
    const auto* value = reinterpret_cast<const char*>(sqlite3_column_text(stmt, column));
    return value ? std::string(value) : std::string();
}

std::string payloadString(const Message& msg, const char* key) {
    if (!msg.payload.is_object()) return "";
    const auto it = msg.payload.find(key);
    if (it == msg.payload.end() || !it->is_string()) return "";
    return it->get<std::string>();
}

bool payloadBool(const Message& msg, const char* key) {
    if (!msg.payload.is_object()) return false;
    const auto it = msg.payload.find(key);
    return it != msg.payload.end() && it->is_boolean() && it->get<bool>();
}

} // namespace

Store::Store(std::string roomName, std::string roomToken, std::string systemUsername)
    : mRoomName(std::move(roomName)),
      mRoomToken(std::move(roomToken)),
      mSystemUsername(std::move(systemUsername)) {
    const auto path = chat::local_paths::textHistoryDatabase(mRoomName, mRoomToken, mSystemUsername);
    mPath = path.u8string();
    open();
}

Store::~Store() {
    if (mDb) sqlite3_close(dbPtr(mDb));
}

void Store::open() {
    const auto path = std::filesystem::u8path(mPath);
    std::filesystem::create_directories(path.parent_path());

    sqlite3* db = nullptr;
    if (sqlite3_open(mPath.c_str(), &db) != SQLITE_OK) {
        std::string message = db ? sqlite3_errmsg(db) : "sqlite allocation failed";
        if (db) sqlite3_close(db);
        throw std::runtime_error("failed to open local message history: " + message);
    }
    mDb = db;
    execSql(dbPtr(mDb), "PRAGMA journal_mode=WAL;");
    execSql(dbPtr(mDb),
        "CREATE TABLE IF NOT EXISTS messages ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "created_at INTEGER NOT NULL,"
        "is_own INTEGER NOT NULL,"
        "sender TEXT NOT NULL,"
        "actor_id TEXT,"
        "display_kind TEXT NOT NULL,"
        "body TEXT NOT NULL,"
        "message_json TEXT NOT NULL"
        ");");
}

void Store::appendText(const TextRecord& record) {
    std::lock_guard<std::mutex> lock(mMutex);
    if (!mDb || record.body.empty()) return;

    sqlite3_stmt* raw = nullptr;
    const char* sql =
        "INSERT INTO messages(created_at, is_own, sender, actor_id, display_kind, body, message_json) "
        "VALUES(?, ?, ?, ?, ?, ?, ?);";
    if (sqlite3_prepare_v2(dbPtr(mDb), sql, -1, &raw, nullptr) != SQLITE_OK) {
        throw std::runtime_error("local message store prepare failed");
    }
    std::unique_ptr<sqlite3_stmt, decltype(&sqlite3_finalize)> stmt(raw, sqlite3_finalize);
    bindInt64(stmt.get(), 1, nowUnixMs());
    bindInt64(stmt.get(), 2, record.isOwn ? 1 : 0);
    bindText(stmt.get(), 3, record.sender);
    bindText(stmt.get(), 4, record.actorId);
    bindText(stmt.get(), 5, record.displayKind.empty() ? "message" : record.displayKind);
    bindText(stmt.get(), 6, record.body);
    bindText(stmt.get(), 7, record.messageJson);
    if (sqlite3_step(stmt.get()) != SQLITE_DONE) {
        throw std::runtime_error("failed to append local message history");
    }
}

std::string Store::historyJson(std::size_t limit) const {
    std::lock_guard<std::mutex> lock(mMutex);
    if (!mDb) return "[]";
    if (limit == 0) limit = 500;

    sqlite3_stmt* raw = nullptr;
    const char* sql =
        "SELECT id, created_at, is_own, sender, actor_id, display_kind, body, message_json "
        "FROM (SELECT id, created_at, is_own, sender, actor_id, display_kind, body, message_json "
        "FROM messages ORDER BY id DESC LIMIT ?) ORDER BY id ASC;";
    if (sqlite3_prepare_v2(dbPtr(mDb), sql, -1, &raw, nullptr) != SQLITE_OK) {
        throw std::runtime_error("local message history query failed");
    }
    std::unique_ptr<sqlite3_stmt, decltype(&sqlite3_finalize)> stmt(raw, sqlite3_finalize);
    bindInt64(stmt.get(), 1, static_cast<std::int64_t>(limit));

    json rows = json::array();
    while (sqlite3_step(stmt.get()) == SQLITE_ROW) {
        rows.push_back({
            {"id", static_cast<std::int64_t>(sqlite3_column_int64(stmt.get(), 0))},
            {"createdAt", static_cast<std::int64_t>(sqlite3_column_int64(stmt.get(), 1))},
            {"isOwn", sqlite3_column_int64(stmt.get(), 2) != 0},
            {"sender", columnText(stmt.get(), 3)},
            {"actorId", columnText(stmt.get(), 4)},
            {"kind", columnText(stmt.get(), 5)},
            {"body", columnText(stmt.get(), 6)},
            {"messageJson", columnText(stmt.get(), 7)}
        });
    }
    return rows.dump();
}

std::string Store::databasePath() const {
    std::lock_guard<std::mutex> lock(mMutex);
    return mPath;
}

TextRecord makeTextRecord(const Message& msg, bool isOwn) {
    TextRecord record;
    record.isOwn = isOwn;
    record.actorId = payloadString(msg, "actorId");
    record.sender = payloadString(msg, "displayName");
    if (record.sender.empty()) record.sender = msg.from;
    record.body = msg.content;
    record.messageJson = msg.toJson();
    record.displayKind = payloadBool(msg, "private") ? "message private" : "message";
    return record;
}

} // namespace chat::local_message
