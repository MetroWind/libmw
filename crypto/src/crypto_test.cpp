#include <string>

#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include "crypto.hpp"
#include "test_utils.hpp"

using ::testing::ElementsAre;

TEST(Hash, CanHashSHA256)
{
    ASSIGN_OR_FAIL(auto hash, mw::SHA256Hasher().hashToBytes("aaa"));
    EXPECT_THAT(hash,
                ElementsAre(0x98, 0x34, 0x87, 0x6d, 0xcf, 0xb0, 0x5c, 0xb1,
                            0x67, 0xa5, 0xc2, 0x49, 0x53, 0xeb, 0xa5, 0x8c,
                            0x4a, 0xc8, 0x9b, 0x1a, 0xdf, 0x57, 0xf2, 0x8f,
                            0x2f, 0x9d, 0x09, 0xaf, 0x10, 0x7e, 0xe8, 0xf0));

    ASSIGN_OR_FAIL(std::string result, mw::SHA256Hasher().hashToHexStr("aaa"));
    EXPECT_EQ(result,
              "9834876dcfb05cb167a5c24953eba58c4ac89b1adf57f28f2f9d09af107ee8f0");
}

TEST(Hash, CanHashSHA256Half)
{
    ASSIGN_OR_FAIL(auto hash, mw::SHA256HalfHasher().hashToBytes("aaa"));
    EXPECT_THAT(hash,
                ElementsAre(0x98, 0x34, 0x87, 0x6d, 0xcf, 0xb0, 0x5c, 0xb1,
                            0x67, 0xa5, 0xc2, 0x49, 0x53, 0xeb, 0xa5, 0x8c));

    ASSIGN_OR_FAIL(std::string result,
                   mw::SHA256HalfHasher().hashToHexStr("aaa"));
    EXPECT_EQ(result,
              "9834876dcfb05cb167a5c24953eba58c");
}
