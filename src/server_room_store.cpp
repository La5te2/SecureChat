// Server room 状态 SQLite 实现。
#include "server_room_store.hpp"

#include <sqlite3.h>

#include <cstdlib>
#include <filesystem>
#include <stdexcept>
#include <string>

namespace {

std::string envValue(const char* name) {
    const char* value = std::getenv(name);
    return value == nullptr ? std::string() : std::string(value);
}

std::filesystem::path pathFromUtf8(const std::string& value) {
    return std::filesystem::u8path(value);
}

std::string defaultDbPath() {
    const auto configured = envValue("SECURECHAT_SERVER_STATE_DB");
    return configured.empty() ? "logs/server-state.sqlite3" : configured;
}

void execSql(sqlite3* db, const char* sql) {
    char* error = nullptr;
    if (sqlite3_exec(db, sql, nullptr, nullptr, &error) != SQLITE_OK) {
        std::string message = error ? error : "unknown sqlite error";
        sqlite3_free(error);
        throw std::runtime_error("server room store SQL failed: " + message);
    }
}

void bindText(sqlite3_stmt* stmt, int index, const std::string& value) {
    if (sqlite3_bind_text(stmt, index, value.c_str(), static_cast<int>(value.size()), SQLITE_TRANSIENT) != SQLITE_OK) {
        throw std::runtime_error("server room store bind failed");
    }
}

class Statement {
public:
    Statement(sqlite3* db, const char* sql) : mDb(db) {
        if (sqlite3_prepare_v2(db, sql, -1, &mStmt, nullptr) != SQLITE_OK) {
            throw std::runtime_error("server room store prepare failed: " + std::string(sqlite3_errmsg(db)));
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

ServerRoomStore::ServerRoomStore() : mPath(defaultDbPath()) {
    open();
    migrate();
}

ServerRoomStore::~ServerRoomStore() {
    if (mDb) {
        sqlite3_close(dbPtr(mDb));
        mDb = nullptr;
    }
}

void ServerRoomStore::open() {
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

void ServerRoomStore::migrate() {
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
}

std::vector<std::string> ServerRoomStore::loadOpenRooms() {
    Statement stmt(dbPtr(mDb), "SELECT room_id FROM rooms WHERE state='open';");
    std::vector<std::string> rooms;
    while (sqlite3_step(stmt.get()) == SQLITE_ROW) {
        const auto* text = reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 0));
        if (text) rooms.emplace_back(text);
    }
    return rooms;
}

std::vector<ServerRoomStore::PendingJoin> ServerRoomStore::loadPendingJoins(const std::string& roomId) {
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

std::string ServerRoomStore::roomState(const std::string& roomId) {
    Statement stmt(dbPtr(mDb), "SELECT state FROM rooms WHERE room_id=?;");
    bindText(stmt.get(), 1, roomId);
    if (sqlite3_step(stmt.get()) != SQLITE_ROW) return "";
    const auto* text = reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 0));
    return text ? std::string(text) : std::string();
}

void ServerRoomStore::markRoomOpen(const std::string& roomId) {
    Statement stmt(dbPtr(mDb),
        "INSERT INTO rooms(room_id, state, updated_at) VALUES(?, 'open', unixepoch()) "
        "ON CONFLICT(room_id) DO UPDATE SET state='open', updated_at=unixepoch();");
    bindText(stmt.get(), 1, roomId);
    if (sqlite3_step(stmt.get()) != SQLITE_DONE) {
        throw std::runtime_error("failed to mark room open");
    }
}

void ServerRoomStore::markRoomClosed(const std::string& roomId) {
    Statement stmt(dbPtr(mDb),
        "INSERT INTO rooms(room_id, state, updated_at) VALUES(?, 'closed', unixepoch()) "
        "ON CONFLICT(room_id) DO UPDATE SET state='closed', updated_at=unixepoch();");
    bindText(stmt.get(), 1, roomId);
    if (sqlite3_step(stmt.get()) != SQLITE_DONE) {
        throw std::runtime_error("failed to mark room closed");
    }
    clearPendingJoins(roomId);
}

void ServerRoomStore::addPendingJoin(const std::string& roomId, const std::string& requestId, const nlohmann::json& payload) {
    Statement stmt(dbPtr(mDb),
        "INSERT OR REPLACE INTO pending_joins(room_id, request_id, payload, created_at) VALUES(?, ?, ?, unixepoch());");
    bindText(stmt.get(), 1, roomId);
    bindText(stmt.get(), 2, requestId);
    bindText(stmt.get(), 3, payload.dump());
    if (sqlite3_step(stmt.get()) != SQLITE_DONE) {
        throw std::runtime_error("failed to add pending join");
    }
}

void ServerRoomStore::removePendingJoin(const std::string& roomId, const std::string& requestId) {
    Statement stmt(dbPtr(mDb), "DELETE FROM pending_joins WHERE room_id=? AND request_id=?;");
    bindText(stmt.get(), 1, roomId);
    bindText(stmt.get(), 2, requestId);
    if (sqlite3_step(stmt.get()) != SQLITE_DONE) {
        throw std::runtime_error("failed to remove pending join");
    }
}

void ServerRoomStore::clearPendingJoins(const std::string& roomId) {
    Statement stmt(dbPtr(mDb), "DELETE FROM pending_joins WHERE room_id=?;");
    bindText(stmt.get(), 1, roomId);
    if (sqlite3_step(stmt.get()) != SQLITE_DONE) {
        throw std::runtime_error("failed to clear pending joins");
    }
}
