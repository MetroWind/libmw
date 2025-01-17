#include <gtest/gtest.h>

#include "crypto.hpp"

TEST(Hash, CanHashSHA256)
{
    EXPECT_EQ(mw::SHA256Hasher().hashToHexStr("aaa"),
              "9834876dcfb05cb167a5c24953eba58c4ac89b1adf57f28f2f9d09af107ee8f0");
}

TEST(Hash, CanHashSHA256Half)
{
    EXPECT_EQ(mw::SHA256HalfHasher().hashToHexStr("aaa"),
              "9834876dcfb05cb167a5c24953eba58c");
}
