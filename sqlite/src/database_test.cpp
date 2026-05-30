#include <chrono>
#include <filesystem>
#include <memory>
#include <optional>
#include <stdint.h>
#include <string>
#include <thread>
#include <tuple>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

#include "database.hpp"
#include "test_utils.hpp"

using namespace mw;

TEST(Database, CanEvaluateAndExecute)
{
    ASSIGN_OR_FAIL(auto db, SQLite::connectMemory());
    ASSERT_TRUE(db->execute("CREATE TABLE test (a INTEGER, b TEXT);")
                .has_value());
    ASSERT_TRUE(db->execute("INSERT INTO test (a, b) VALUES "
                            "(1, \"aaa\"), (2, \"aaa\");")
                .has_value());

    ASSIGN_OR_FAIL(auto result0,
                   (db->eval<int64_t, std::string>("SELECT * FROM test;")));
    EXPECT_EQ(result0.size(), 2);

    ASSIGN_OR_FAIL(auto result1, (db->eval<int64_t, std::string>(
        "SELECT a, b FROM test WHERE a = 1;")));
    EXPECT_EQ(result1.size(), 1);
    EXPECT_EQ(result1[0], (std::make_tuple<int64_t, std::string>(1, "aaa")));

    ASSIGN_OR_FAIL(auto result2, (db->eval<int64_t, std::string>(
        "SELECT a, b FROM test WHERE a = 123;")));
    EXPECT_EQ(result2.size(), 0);

    ASSIGN_OR_FAIL(auto result3,
                   (db->eval<int64_t>("SELECT COUNT(*) FROM test;")));
    EXPECT_EQ(result3.size(), 1);
    EXPECT_EQ(std::get<0>(result3[0]), 2);
}

TEST(Database, ParametrizedStatement)
{
    ASSIGN_OR_FAIL(auto db, SQLite::connectMemory());
    ASSERT_TRUE(db->execute("CREATE TABLE test (a INTEGER, b TEXT);")
                .has_value());
    ASSIGN_OR_FAIL(auto sql, db->statementFromStr(
        "INSERT INTO test (a, b) VALUES (?, ?), (2, ?), (?, ?);"));
    auto result = sql.bind(1, "aaa", "bbb", std::nullopt, std::nullopt);
    ASSERT_TRUE(result.has_value());
    ASSERT_TRUE(db->execute(std::move(sql)).has_value());
    ASSIGN_OR_FAIL(auto result0, (db->eval<int64_t, std::string>(
        "SELECT * FROM test;")));
    EXPECT_EQ(result0.size(), 3);
    ASSIGN_OR_FAIL(auto result1, (db->eval<int64_t, std::string>(
        "SELECT * FROM test WHERE b = 'aaa';")));
    EXPECT_EQ(result1.size(), 1);
    ASSIGN_OR_FAIL(auto result2, (db->eval<int64_t, std::string>(
        "SELECT * FROM test WHERE b IS NULL;")));
    EXPECT_EQ(result2.size(), 1);
    EXPECT_EQ(std::get<0>(result2[0]), 0);
    EXPECT_TRUE(std::get<1>(result2[0]).empty());
}

TEST(Database, OptionalBinding)
{
    ASSIGN_OR_FAIL(auto db, SQLite::connectMemory());
    ASSERT_TRUE(db->execute("CREATE TABLE test (a INTEGER, b TEXT);")
                .has_value());
    ASSIGN_OR_FAIL(auto sql, db->statementFromStr(
        "INSERT INTO test (a, b) VALUES (?, ?);"));

    std::optional<int64_t> a1 = 42;
    std::optional<std::string> b1 = "hello";
    ASSERT_TRUE(sql.bind(a1, b1).has_value());
    ASSERT_TRUE(db->execute(std::move(sql)).has_value());

    ASSIGN_OR_FAIL(auto sql2, db->statementFromStr(
        "INSERT INTO test (a, b) VALUES (?, ?);"));
    std::optional<int64_t> a2 = std::nullopt;
    std::optional<std::string> b2 = std::nullopt;
    ASSERT_TRUE(sql2.bind(a2, b2).has_value());
    ASSERT_TRUE(db->execute(std::move(sql2)).has_value());

    ASSIGN_OR_FAIL(auto result, (db->eval<std::optional<int64_t>, std::optional<std::string>>(
        "SELECT * FROM test ORDER BY a DESC;")));
    ASSERT_EQ(result.size(), 2);
    EXPECT_EQ(std::get<0>(result[0]), 42);
    EXPECT_EQ(std::get<1>(result[0]), "hello");
    EXPECT_EQ(std::get<0>(result[1]), std::nullopt);
    EXPECT_EQ(std::get<1>(result[1]), std::nullopt);
}

// Two separate connections to the same on-disk WAL database, each
// running interleaved write transactions, must not surface spurious
// SQLITE_BUSY errors: the busy timeout / retry should make the
// contended writer wait and eventually succeed. With the old behavior
// (immediate ROLLBACK + error on SQLITE_BUSY) this test would fail.
TEST(Database, ConcurrentWritersDoNotSpuriouslyFail)
{
    namespace fs = std::filesystem;
    const auto stamp = std::chrono::steady_clock::now()
        .time_since_epoch().count();
    const fs::path db_path = fs::temp_directory_path() /
        ("libmw_busy_test_" + std::to_string(stamp) + ".sqlite");

    // Make sure we start from a clean slate and clean up afterwards,
    // including the WAL side files.
    auto cleanup = [&]()
    {
        std::error_code ec;
        fs::remove(db_path, ec);
        fs::remove(fs::path(db_path).concat("-wal"), ec);
        fs::remove(fs::path(db_path).concat("-shm"), ec);
    };
    cleanup();

    {
        ASSIGN_OR_FAIL(auto db, SQLite::connectFile(db_path.string()));
        ASSERT_TRUE(db->execute(
            "CREATE TABLE test (id INTEGER PRIMARY KEY, worker INTEGER);")
            .has_value());
    }

    constexpr int NUM_WORKERS = 8;
    constexpr int INSERTS_PER_WORKER = 200;

    // Each worker gets its own connection (the separate-connection
    // concurrency case) and runs many small write transactions. Using
    // BEGIN IMMEDIATE forces each transaction to grab the write lock up
    // front, maximizing contention between workers.
    auto worker = [&](int worker_id) -> bool
    {
        auto db_result = SQLite::connectFile(db_path.string());
        if(!db_result.has_value())
        {
            return false;
        }
        auto db = std::move(*db_result);
        for(int i = 0; i < INSERTS_PER_WORKER; ++i)
        {
            if(!db->execute("BEGIN IMMEDIATE;").has_value())
            {
                return false;
            }
            auto stmt = db->statementFromStr(
                "INSERT INTO test (worker) VALUES (?);");
            if(!stmt.has_value())
            {
                return false;
            }
            if(!stmt->bind(worker_id).has_value())
            {
                return false;
            }
            if(!db->execute(std::move(*stmt)).has_value())
            {
                return false;
            }
            if(!db->execute("COMMIT;").has_value())
            {
                return false;
            }
        }
        return true;
    };

    // Distinct indices into `results`, so no synchronization is needed.
    std::vector<int> results(NUM_WORKERS, 0);
    std::vector<std::thread> threads;
    for(int w = 0; w < NUM_WORKERS; ++w)
    {
        threads.emplace_back([&, w]() { results[w] = worker(w) ? 1 : 0; });
    }
    for(auto& t: threads)
    {
        t.join();
    }

    for(int w = 0; w < NUM_WORKERS; ++w)
    {
        EXPECT_EQ(results[w], 1) << "worker " << w << " hit a spurious error";
    }

    ASSIGN_OR_FAIL(auto db, SQLite::connectFile(db_path.string()));
    ASSIGN_OR_FAIL(auto count,
                   db->evalToValue<int64_t>("SELECT COUNT(*) FROM test;"));
    EXPECT_EQ(count, NUM_WORKERS * INSERTS_PER_WORKER);

    cleanup();
}
