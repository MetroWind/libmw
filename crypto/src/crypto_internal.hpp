#pragma once

#include <cstddef>
#include <vector>

#include <openssl/crypto.h>

#include "error.hpp"

namespace mw::crypto_detail
{

/// A function used to cleanse an owned byte buffer.
using CleanseFunction = void (*)(void*, size_t);

/// A random-byte backend compatible with OpenSSL's private generator.
using RandomBytesFunction = int (*)(unsigned char*, size_t, unsigned int);

/// Generate random bytes through a supplied backend for deterministic tests.
E<std::vector<std::byte>> generateRandomBytes(
    size_t output_size, RandomBytesFunction random_bytes_function,
    CleanseFunction cleanse_function = OPENSSL_cleanse);

/// Owns temporary plaintext and cleanses its entire allocation on destruction.
class PlaintextBuffer
{
public:
    /// Allocate a buffer that will be cleansed on destruction.
    explicit PlaintextBuffer(
        size_t size, CleanseFunction cleanse_function = OPENSSL_cleanse)
            : bytes(size), cleanse_function(cleanse_function)
    {}

    /// Cleanse every byte in the original allocation.
    ~PlaintextBuffer() noexcept
    {
        if(!bytes.empty())
        {
            cleanse_function(bytes.data(), bytes.size());
        }
    }

    PlaintextBuffer(const PlaintextBuffer&) = delete;
    PlaintextBuffer& operator=(const PlaintextBuffer&) = delete;
    PlaintextBuffer(PlaintextBuffer&&) = delete;
    PlaintextBuffer& operator=(PlaintextBuffer&&) = delete;

    /// Return a pointer to the owned byte storage.
    unsigned char* data()
    {
        return bytes.data();
    }

    /// Return the number of bytes in the original allocation.
    size_t size() const
    {
        return bytes.size();
    }

private:
    std::vector<unsigned char> bytes;
    CleanseFunction cleanse_function;
};

} // namespace mw::crypto_detail
