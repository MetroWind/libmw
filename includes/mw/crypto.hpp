#pragma once

#include <string>

#include <openssl/evp.h>

#include "error.hpp"

namespace mw
{

class HasherInterface
{
public:
    virtual ~HasherInterface() = default;
    // Calculate the hash of the bytes, and return the hex string
    // representation of the hash in lowercase.
    virtual E<std::string> hashToHexStr(const std::string& bytes) const = 0;
};

// This hasher takes the first half of the SHA256 hash.
class SHA256Hasher : public HasherInterface
{
public:
    SHA256Hasher();
    ~SHA256Hasher() override;
    E<std::string> hashToHexStr(const std::string& bytes) const override;

private:
    EVP_MD_CTX* ctx;
};

// This hasher takes the first half of the SHA256 hash.
class SHA256HalfHasher : public HasherInterface
{
public:
    SHA256HalfHasher() = default;
    ~SHA256HalfHasher() override = default;
    E<std::string> hashToHexStr(const std::string& bytes) const override;

private:
    SHA256Hasher full_hasher;
};

} // namespace mw
