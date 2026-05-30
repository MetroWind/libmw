#include <chrono>
#include <expected>
#include <format>
#include <memory>
#include <stdint.h>
#include <string>
#include <string_view>
#include <thread>
#include <utility>

#include <sqlite3.h>

#include "database.hpp"
#include "error.hpp"
#include "utils.hpp"

namespace mw
{

namespace internal
{

void sqliteBusyBackoff(int attempt)
{
    // Linearly increasing backoff, capped so a pathological run can't
    // sleep unboundedly. Kept here (rather than in the header) so the
    // public header doesn't pull in <thread> / <chrono>.
    constexpr int MAX_BACKOFF_MS = 50;
    int ms = SQLITE_BUSY_BASE_BACKOFF_MS * (attempt + 1);
    if(ms > MAX_BACKOFF_MS)
    {
        ms = MAX_BACKOFF_MS;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(ms));
}

} // namespace internal

SQLiteStatement::SQLiteStatement(SQLiteStatement&& rhs)
{
    std::swap(sql, rhs.sql);
}

SQLiteStatement& SQLiteStatement::operator=(SQLiteStatement&& rhs)
{
    std::swap(sql, rhs.sql);
    return *this;
}

SQLiteStatement::~SQLiteStatement()
{
    if(sql != nullptr)
    {
        sqlite3_finalize(sql);
    }
}

E<SQLiteStatement> SQLiteStatement::fromStr(sqlite3* db, std::string_view expr)
{
    SQLiteStatement s;
    int code = sqlite3_prepare_v2(db, expr.data(), expr.size(), &s.sql, nullptr);
    if(code != SQLITE_OK)
    {
        return std::unexpected(runtimeError(std::format(
            "Invalid statement '{}': {}", expr, sqlite3_errstr(code))));
    }
    return E<SQLiteStatement>{std::in_place, std::move(s)};
}

void SQLite::clear()
{
    if(db != nullptr)
    {
        sqlite3_close(db);
        db = nullptr;
    }
}

E<std::unique_ptr<SQLite>>
SQLite::connectFile(const std::string& db_file, int busy_timeout_ms)
{
    auto data = std::make_unique<SQLite>();
    if(int code = sqlite3_open(db_file.c_str(), &data->db);
       code != SQLITE_OK)
    {
        data->clear();
        return std::unexpected(runtimeError(std::string(
            "Failed to create DB connection: ") + sqlite3_errstr(code)));
    }
    // Block-and-wait up to `busy_timeout_ms` on a locked database
    // before returning SQLITE_BUSY. This is what lets separate
    // connections to the same WAL database tolerate concurrent writers.
    if(int code = sqlite3_busy_timeout(data->db, busy_timeout_ms);
       code != SQLITE_OK)
    {
        data->clear();
        return std::unexpected(runtimeError(std::string(
            "Failed to set busy timeout: ") + sqlite3_errstr(code)));
    }
    // Enable WAL.
    DO_OR_RETURN(data->execute("PRAGMA journal_mode = WAL;"));
    // Enable foreign key support.
    DO_OR_RETURN(data->execute("PRAGMA foreign_keys = ON;"));
    return data;
}

E<std::unique_ptr<SQLite>> SQLite::connectMemory(int busy_timeout_ms)
{
    return connectFile(":memory:", busy_timeout_ms);
}

E<SQLiteStatement> SQLite::statementFromStr(std::string_view s)
{
    return SQLiteStatement::fromStr(db, s);
}

E<void> SQLite::execute(SQLiteStatement sql_code) const
{
    auto result = eval<int>(std::move(sql_code));
    if(result.has_value())
    {
        return {};
    }
    else
    {
        return std::unexpected(result.error());
    }
}

E<void> SQLite::execute(const char* sql_code) const
{
    ASSIGN_OR_RETURN(auto sql, SQLiteStatement::fromStr(db, sql_code));
    return execute(std::move(sql));
}

SQLite::~SQLite()
{
    clear();
}

int64_t SQLite::lastInsertRowID() const
{
    return sqlite3_last_insert_rowid(db);
}

int64_t SQLite::changedRowsCount() const
{
    return sqlite3_changes64(db);
}

} // namespace mw
