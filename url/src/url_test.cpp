#include "url.hpp"

#include <gtest/gtest.h>

namespace mw
{

TEST(URL, CanGetSetParts)
{
    auto url = URL::fromStr("http://example.com:1234/aaa/bbb");
    ASSERT_TRUE(url.has_value());
    EXPECT_EQ(url->path(), "/aaa/bbb");
    url->query("ccc=ddd");
    EXPECT_EQ(url->query(), "ccc=ddd");
    EXPECT_EQ(url->str(), "http://example.com:1234/aaa/bbb?ccc=ddd");
}

TEST(URL, CanAppendPath)
{
    {
        auto url = URL::fromStr("http://example.com/aaa/");
        ASSERT_TRUE(url.has_value());
        url->appendPath("/bbb/");
        EXPECT_EQ(url->str(), "http://example.com/aaa/bbb/");
        url->appendPath("///");
        EXPECT_EQ(url->str(), "http://example.com/aaa/bbb/");
    }
    {
        auto url = URL::fromStr("http://example.com");
        ASSERT_TRUE(url.has_value());
        url->appendPath("bbb");
        EXPECT_EQ(url->str(), "http://example.com/bbb");
    }
}

TEST(URL, ResolveAgainstBase)
{
    auto base = URL::fromStr("http://example.com/foo/bar");
    ASSERT_TRUE(base.has_value());

    // Absolute reference replaces everything.
    {
        auto r = base->resolve("https://other.com/x");
        ASSERT_TRUE(r.has_value());
        EXPECT_EQ(r->str(), "https://other.com/x");
    }
    // Absolute path.
    {
        auto r = base->resolve("/baz");
        ASSERT_TRUE(r.has_value());
        EXPECT_EQ(r->str(), "http://example.com/baz");
    }
    // Relative path.
    {
        auto r = base->resolve("baz");
        ASSERT_TRUE(r.has_value());
        EXPECT_EQ(r->str(), "http://example.com/foo/baz");
    }
    // Protocol-relative.
    {
        auto r = base->resolve("//cdn.example.com/x");
        ASSERT_TRUE(r.has_value());
        EXPECT_EQ(r->str(), "http://cdn.example.com/x");
    }
    // Empty reference resolves to the base.
    {
        auto r = base->resolve("");
        ASSERT_TRUE(r.has_value());
        EXPECT_EQ(r->str(), base->str());
    }
    // Query-only reference replaces the query.
    {
        auto r = base->resolve("?token=1");
        ASSERT_TRUE(r.has_value());
        EXPECT_EQ(r->str(), "http://example.com/foo/bar?token=1");
    }
}

} // namespace mw
