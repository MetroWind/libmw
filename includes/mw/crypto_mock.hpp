#pragma once

#include <string>

#include <gmock/gmock.h>

#include "crypto.hpp"

namespace mw
{

class HasherMock : public HasherInterface
{
public:
    ~HasherMock() override = default;

    MOCK_METHOD(E<std::vector<unsigned char>>, hashToBytes,
                (const std::string& bytes), (const override));
};

class CryptoMock : public CryptoInterface
{
public:
    ~CryptoMock() override = default;

    MOCK_METHOD(E<bool>, verifySignature,
                (SignatureAlgorithm algo, const std::string& key,
                 const std::vector<unsigned char>& signature,
                 const std::string& data),
                (override));

    MOCK_METHOD(E<std::vector<unsigned char>>, sign,
                (SignatureAlgorithm algo, const std::string& key,
                 const std::string& data),
                (override));

    MOCK_METHOD(E<KeyPair>, generateKeyPair, (KeyType type), (override));

    MOCK_METHOD(E<std::string>, encrypt,
                (EncryptionAlgorithm algo, const std::string& key,
                 const std::string& clear_content),
                (override));

    MOCK_METHOD(E<std::string>, decrypt,
                (EncryptionAlgorithm algo, const std::string& key,
                 const std::string& encrypted_content),
                (override));
};

} // namespace mw
