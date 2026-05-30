#pragma once

#include <exception>
#include <format>
#include <memory>
#include <optional>
#include <tuple>
#include <type_traits>
#include <vector>
#include <string>
#include <string_view>
#include <utility>
#include <iostream>

#include <sqlite3.h>

#include "error.hpp"
#include "utils.hpp"

namespace mw
{

/// \brief A simple RAII wrapper of `sqlite3_stmt*`.
///
/// A statement object can be constructed with the `fromStr()` static
/// member function. *Do not use the default constructor*. This class
/// is not copyable. This class is usually not constructed by itself.
/// The usual use case is to use `SQLite::statementFromStr()`.
class SQLiteStatement
{
public:
    SQLiteStatement(const SQLiteStatement&) = delete;
    SQLiteStatement& operator=(const SQLiteStatement&) = delete;
    SQLiteStatement(SQLiteStatement&& rhs);
    SQLiteStatement& operator=(SQLiteStatement&& rhs);
    ~SQLiteStatement();

    /// Construct a statement object from a SQL statement string.
    static E<SQLiteStatement> fromStr(sqlite3* db, std::string_view expr);

    /// Get the raw sqlite3_stmt pointer.
    sqlite3_stmt* data() const { return sql; }

    /// \brief Bind values to the placeholders in the SQL statement.
    ///
    /// In the case of parameterized statement, this function binds
    /// some values to the placeholders. As of now only the `?`
    /// placeholder is supported. Example:
    ///
    /// ```
    /// // statement is `SELECT * FROM table WHERE name = ? AND number > ?;`.
    /// statement.bind<std::string, uint64_t>("some name", 42);
    /// ```
    ///
    /// It is undefined behavior if the number/type of the arguments
    /// does not match the template arguments.
    template<typename... Types>
    E<void> bind(Types... args) const;

    /// Do not use.
    SQLiteStatement() = default;
private:
    sqlite3_stmt* sql = nullptr;
};

/// \brief An abstraction of a SQLite connection.
///
/// This should be thread-safe. Multiple threads should be able to use
/// the same SQLite object at the same time. This is because SQLite 3
/// uses serialized threading model by default. See
/// https://www.sqlite.org/threadsafe.html.
///
/// This class is not copyable.
class SQLite
{
public:
    /// Construct a null SQLite object.
    SQLite() = default;
    ~SQLite();
    SQLite(const SQLite&) = delete;
    SQLite& operator=(const SQLite&) = delete;

    /// \brief Open a SQLite database from a file.
    ///
    /// \param db_file The path to the database file.
    /// \param busy_timeout_ms How long, in milliseconds, SQLite should
    ///     block-and-wait on a locked database before returning
    ///     `SQLITE_BUSY`. This is the primary mechanism that lets
    ///     multiple connections to the same WAL database tolerate
    ///     concurrent writers. The default (5000 ms) suits typical
    ///     contention; pass 0 to disable waiting entirely.
    static E<std::unique_ptr<SQLite>>
    connectFile(const std::string& db_file, int busy_timeout_ms = 5000);

    /// Create a in-memory SQLite database. See `connectFile()` for the
    /// meaning of `busy_timeout_ms`.
    static E<std::unique_ptr<SQLite>> connectMemory(int busy_timeout_ms = 5000);

    /// \brief Construct a SQLiteStatement object from a SQLite
    /// statement string.
    ///
    /// Construct a SQLiteStatement object from a SQLite statement
    /// string. This is the recommended way to construct
    /// SQLiteStatement objects.
    E<SQLiteStatement> statementFromStr(std::string_view expr);

    /// \brief Evaluate a SQL statement, and retrieve the result.
    ///
    /// The `eval()` series of functions evaluate a SQL statement, and
    /// retrieve the result. In the return value, each element is a
    /// row, which is modeled as a tuple. The type of the tuple
    /// depends on the template arguments you pass when calling this
    /// function. Example:
    ///
    /// ```
    /// auto rows = db.eval<int, std::string>("SELECT id, name FROM table;");
    /// for(const std::tuple<int, std::string>& row: *rows)
    /// {
    ///     int id = std::get<0>(row);
    ///     std::string_view name = std::get<1>(row);
    ///     // ...
    /// }
    /// ```
    ///
    /// You are responsible to make sure that the template arguments
    /// match the expected result of the SQL statement. Otherwise it
    /// is undefined behavior.
    template<typename... Types>
    E<std::vector<std::tuple<Types...>>> eval(SQLiteStatement sql_code) const;
    template<typename... Types>
    E<std::vector<std::tuple<Types...>>> eval(const char* sql_code) const;
    template<typename... Types>
    E<std::vector<std::tuple<Types...>>> eval(const std::string& sql_code) const
    {
        return eval<Types...>(sql_code.c_str());
    }

    /// Evaluate a SQL statement that is not supposed to return data.
    E<void> execute(SQLiteStatement sql_code) const;
    E<void> execute(const char* sql_code) const;
    E<void> execute(const std::string& sql_code) const
    {
        return execute(sql_code.c_str());
    }

    /// \brief Evaluate a SQL statement that is supposed to return a
    /// single value, and return that value.
    ///
    /// The `evalToValue()` series of functions evaluate a SQL
    /// statement that is supposed to return a single value, and
    /// return that value. This is just a wrapper of `eval()`.
    template<typename T>
    E<T> evalToValue(SQLiteStatement sql_code) const;
    template<typename T>
    E<T> evalToValue(const char* sql_code) const;
    template<typename T>
    E<T> evalToValue(const std::string& sql_code) const
    {
        return evalToValue<T>(sql_code.c_str());
    }

    /// \brief Return the row ID of the last successful insert
    /// command. See
    /// https://www.sqlite.org/c3ref/last_insert_rowid.html.
    int64_t lastInsertRowID() const;

    /// \brief Count the number of affected rows in the most recently
    /// finished `INSERT`, `UPDATE` or `DELETE`.
    int64_t changedRowsCount() const;

private:
    sqlite3* db = nullptr;
    void clear();
};

// ========== Template implementations ==============================>

namespace internal
{

/// Maximum number of times `eval()` re-runs a statement that returns
/// `SQLITE_BUSY` / `SQLITE_LOCKED` before giving up. This retry loop is
/// only a backstop; the `busy_timeout` set on connect is the primary
/// wait mechanism, so a small bound is plenty.
inline constexpr int SQLITE_BUSY_MAX_RETRIES = 5;

/// Base backoff, in milliseconds, between busy retries. The actual wait
/// increases linearly with the attempt number (see `sqliteBusyBackoff`).
inline constexpr int SQLITE_BUSY_BASE_BACKOFF_MS = 5;

/// Sleep for a short, attempt-dependent backoff before retrying a busy
/// statement. `attempt` is the zero-based retry index. Defined in
/// `database.cpp` so that `<thread>` / `<chrono>` stay out of this
/// public header.
void sqliteBusyBackoff(int attempt);

template<typename T>
inline void getValue(SQLiteStatement&, int, T&)
{
    static_assert(false, "Invalid type of sqlite column");
}

template<>
inline void getValue(SQLiteStatement& sql, int i, int64_t& x)
{
    x = sqlite3_column_int64(sql.data(), i);
}

template<>
inline void getValue(SQLiteStatement& sql, int i, int& x)
{
    x = sqlite3_column_int(sql.data(), i);
}

template<>
inline void getValue(SQLiteStatement& sql, int i, double& x)
{
    x = sqlite3_column_double(sql.data(), i);
}

template<>
inline void getValue(SQLiteStatement& sql, int i, std::string& s)
{
    const unsigned char* raw = sqlite3_column_text(sql.data(), i);
    if(raw == nullptr)
    {
        // The column value is NULL. Do nothing.
        return;
    }
    s = reinterpret_cast<const char*>(raw);
}

template<typename T>
inline void getValue(SQLiteStatement& sql, int i, std::optional<T>& x)
{
    if(sqlite3_column_type(sql.data(), i) == SQLITE_NULL)
    {
        x = std::nullopt;
    }
    else
    {
        T val;
        getValue(sql, i, val);
        x = std::move(val);
    }
}

// template<typename T, typename T1, typename... Types>
// inline std::tuple<T, T1, Types...> getRowInternal(SQLiteStatement& sql, int i)
// {
//     std::tuple<T> result;
//     getValue(sql, i, std::get<0>(result));
//     return std::tuple_cat(result, getRowInternal<T1, Types...>(sql, i+1));
// }

template<typename T, typename... Types>
inline std::tuple<T, Types...> getRowInternal(SQLiteStatement& sql, int i)
{
    std::tuple<T> result;
    getValue(sql, i, std::get<0>(result));
    if constexpr(sizeof...(Types) == 0)
    {
        return result;
    }
    else
    {
        return std::tuple_cat(result, getRowInternal<Types...>(sql, i+1));
    }
}

template<typename T, typename... Types>
inline std::tuple<T, Types...> getRow(SQLiteStatement& sql)
{
    return getRowInternal<T, Types...>(sql, 0);
}

inline E<void> sqlMaybe(int code, const char* msg)
{
    if(code != SQLITE_OK)
    {
        return std::unexpected(runtimeError(std::format(
            "{}: {}", msg, sqlite3_errstr(code))));
    }
    return {};
}

inline E<void> bindOne(const SQLiteStatement& sql, int i, int x)
{
    return sqlMaybe(sqlite3_bind_int(sql.data(), i, x),
                    "Failed to bind parameter");
}

inline E<void> bindOne(const SQLiteStatement& sql, int i, int64_t x)
{
    return sqlMaybe(sqlite3_bind_int64(sql.data(), i, x),
                    "Failed to bind parameter");
}

inline E<void> bindOne(const SQLiteStatement& sql, int i, double x)
{
    return sqlMaybe(sqlite3_bind_double(sql.data(), i, x),
                    "Failed to bind parameter");
}

inline E<void> bindOne(const SQLiteStatement& sql, int i, const std::string& x)
{
    return sqlMaybe(sqlite3_bind_text(sql.data(), i, x.data(), x.size(),
                                      SQLITE_TRANSIENT),
                    "Failed to bind parameter");
}

inline E<void> bindOne(const SQLiteStatement& sql, int i, const char* x)
{
    return sqlMaybe(sqlite3_bind_text(sql.data(), i, x, -1,
                                      SQLITE_STATIC),
                    "Failed to bind parameter");
}

inline E<void> bindOne(const SQLiteStatement& sql, int i,
                       [[maybe_unused]] std::nullopt_t _)
{
    return sqlMaybe(sqlite3_bind_null(sql.data(), i),
                    "Failed to bind parameter");
}

template<typename T>
inline E<void> bindOne(const SQLiteStatement& sql, int i, const std::optional<T>& x)
{
    if(x.has_value())
    {
        return bindOne(sql, i, *x);
    }
    return bindOne(sql, i, std::nullopt);
}

template<typename T>
inline E<void> bindInternal(const SQLiteStatement& sql, int i, T x)
{
    return bindOne(sql, i, x);
}

template<typename T, typename...Types>
inline E<void> bindInternal(const SQLiteStatement& sql, int i, T x,
                            Types... args)
{
    auto e = bindOne(sql, i, x);
    if(!e.has_value())
    {
        return std::unexpected(e.error());
    }
    return bindInternal(sql, i+1, args...);
}

} // namespace internal

template<typename... Types>
E<void> SQLiteStatement::bind(Types... args) const
{
    return internal::bindInternal(*this, 1, args...);
}

template<typename... Types>
E<std::vector<std::tuple<Types...>>> SQLite::eval(SQLiteStatement sql) const
{
    std::vector<std::tuple<Types...>> result;
    int busy_retries = 0;
    while(true)
    {
        int code = sqlite3_step(sql.data());
        switch(code)
        {
        case SQLITE_DONE:
            return result;
        case SQLITE_ROW:
            result.push_back(internal::getRow<Types...>(sql));
            break;
        case SQLITE_BUSY:
        case SQLITE_LOCKED:
            // The `busy_timeout` set on connect is the primary wait
            // mechanism; this bounded retry-with-backoff is a backstop
            // for the cases the timeout does not cover (e.g.
            // `SQLITE_LOCKED` from a shared-cache conflict, or a
            // momentary collision after the timeout elapses).
            //
            // We deliberately do NOT roll back here. The caller may
            // have started an enclosing transaction, and silently
            // rolling it back inside eval() would be surprising; let
            // the caller decide what to do on a hard failure.
            //
            // Retry semantics: we reset the statement and re-run it
            // from the start. To keep this correct even if SQLITE_BUSY
            // surfaces mid-scan (after some SQLITE_ROWs), we discard
            // any rows accumulated during this execution before
            // retrying, so they cannot be duplicated. Re-executing the
            // statement reproduces the full result set.
            if(busy_retries >= internal::SQLITE_BUSY_MAX_RETRIES)
            {
                return std::unexpected(runtimeError(std::format(
                    "SQL still busy after {} retries: {}",
                    busy_retries, sqlite3_errstr(code))));
            }
            internal::sqliteBusyBackoff(busy_retries);
            ++busy_retries;
            result.clear();
            sqlite3_reset(sql.data());
            break;
        case SQLITE_ERROR:
        case SQLITE_MISUSE:
            return std::unexpected(runtimeError(std::string(
                "Failed to evaluate SQL: ") + sqlite3_errstr(code)));
        default:
            return std::unexpected(runtimeError(std::string(
                "Unexpected return code when evaluating SQL: ") +
                sqlite3_errstr(code)));
        }
    }
    return result;
}

template<typename... Types>
E<std::vector<std::tuple<Types...>>> SQLite::eval(const char* sql_code) const
{
    ASSIGN_OR_RETURN(auto sql, SQLiteStatement::fromStr(db, sql_code));
    return eval<Types...>(std::move(sql));
}

template<typename T>
E<T> SQLite::evalToValue(SQLiteStatement sql_code) const
{
    ASSIGN_OR_RETURN(std::vector<std::tuple<T>> result,
                     eval<T>(std::move(sql_code)));
    if(result.empty())
    {
        return std::unexpected(runtimeError(
            "evalToValue() expects a return value from SQL evaluation, "
            "but no value is returned"));
    }
    return std::get<0>(std::move(result)[0]);
}

template<typename T>
E<T> SQLite::evalToValue(const char* sql_code) const
{
    ASSIGN_OR_RETURN(auto sql, SQLiteStatement::fromStr(db, sql_code));
    return evalToValue<T>(std::move(sql));
}

} // namespace mw
