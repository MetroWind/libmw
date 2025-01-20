#include <string>
#include <span>
#include <vector>

#include <gtest/gtest.h>

#include "utils.hpp"
#include "test_utils.hpp"

namespace mw
{

TEST(Utils, CanStripStringFromLeft)
{
    EXPECT_EQ(lstrip(""), "");
    EXPECT_EQ(lstrip(" "), "");
    EXPECT_EQ(lstrip("  "), "");
    EXPECT_EQ(lstrip(" a "), "a ");
    EXPECT_EQ(lstrip("  a "), "a ");
    EXPECT_EQ(lstrip("a "), "a ");
}

TEST(Utils, CanStripStringFromRight)
{
    EXPECT_EQ(rstrip(""), "");
    EXPECT_EQ(rstrip(" "), "");
    EXPECT_EQ(rstrip("  "), "");
    EXPECT_EQ(rstrip(" a "), " a");
    EXPECT_EQ(rstrip(" a  "), " a");
    EXPECT_EQ(rstrip(" a"), " a");
}

TEST(Utils, CanStripStringFromBothSides)
{
    EXPECT_EQ(strip(""), "");
    EXPECT_EQ(strip(" "), "");
    EXPECT_EQ(strip("  "), "");
    EXPECT_EQ(strip(" a "), "a");
    EXPECT_EQ(strip(" a  "), "a");
    EXPECT_EQ(strip("a"), "a");
}

TEST(Utils, CanEncodeBase64)
{
    std::string data = "abcd";
    EXPECT_EQ(base64Encode(
                  {reinterpret_cast<unsigned char*>(data.data()), data.size()}),
              "YWJjZA");
    EXPECT_EQ(base64Encode(
                  {reinterpret_cast<unsigned char*>(data.data()), data.size()},
                  true, true), "YWJjZA==\n");
}

TEST(Utils, CanDecodeBase64)
{
    std::string expected = "abcd";
    {
        ASSIGN_OR_FAIL(auto result, base64Decode("YWJjZA"));
        EXPECT_EQ(result,
                  std::vector<unsigned char>(expected.begin(), expected.end()));
    }
    {
        ASSIGN_OR_FAIL(auto result, base64Decode("YWJjZA="));
        EXPECT_EQ(result,
                  std::vector<unsigned char>(expected.begin(), expected.end()));
    }
    {
        ASSIGN_OR_FAIL(auto result, base64Decode("YWJjZA=="));
        EXPECT_EQ(result,
                  std::vector<unsigned char>(expected.begin(), expected.end()));
    }
    {
        ASSIGN_OR_FAIL(auto result, base64Decode("YWJjZA==\n"));
        EXPECT_EQ(result,
                  std::vector<unsigned char>(expected.begin(), expected.end()));
    }
    {
        // This is technically invalid, but it’s just padding. We’ll allow it.
        ASSIGN_OR_FAIL(auto result, base64Decode("YWJjZA==="));
        EXPECT_EQ(result,
                  std::vector<unsigned char>(expected.begin(), expected.end()));
    }
    {
        // Base64 string with newlines and paddings.
        ASSIGN_OR_FAIL(auto result, base64Decode("QVNDSUkgc3RhbmRzIGZvciBBbWVyaWNhbiBTdGFuZGFyZCBDb2RlIGZvciBJbmZvcm1hdGlv\nbiBJbnRlcmNoYW5nZS4gQ29tcHV0ZXJzIGNhbiBvbmx5IHVuZGVyc3RhbmQgbnVtYmVycywg\nc28gYW4gQVNDSUkgY29kZSBpcyB0aGUgbnVtZXJpY2FsIHJlcHJlc2VudGF0aW9uIG9mIGEg\nY2hhcmFjdGVyIHN1Y2ggYXMgJ2EnIG9yICdAJyBvciBhbiBhY3Rpb24gb2Ygc29tZSBzb3J0\nLg==\n"));
        std::string expected = "ASCII stands for American Standard Code for Information Interchange. Computers can only understand numbers, so an ASCII code is the numerical representation of a character such as 'a' or '@' or an action of some sort.";
        EXPECT_EQ(result,
                  std::vector<unsigned char>(expected.begin(), expected.end()));
    }
}

} // namespace mw
