#include <memory>
#include <optional>
#include <stdint.h>
#include <string>
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
