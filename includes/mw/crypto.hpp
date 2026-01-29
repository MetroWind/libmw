#pragma once

#include <string>
#include <vector>

#include <openssl/evp.h>

#include "error.hpp"

namespace mw
{

/// An interface for crypto hashes.
class HasherInterface
{
public:
    virtual ~HasherInterface() = default;

    /// Hash the given bytes. The hash is returned as raw bytes.
    virtual E<std::vector<unsigned char>> hashToBytes(const std::string& bytes)
        const = 0;

    /// @brief Hash some bytes into hex strings.
    ///
    /// Calculate the hash of the bytes, and return the hex string
    /// representation of the hash in lowercase.
    virtual E<std::string> hashToHexStr(const std::string& bytes) const;
};

// This hasher takes the first half of the SHA256 hash.
class SHA256Hasher : public HasherInterface
{
public:
    SHA256Hasher();
    ~SHA256Hasher() override;
    E<std::vector<unsigned char>> hashToBytes(const std::string& bytes)
        const override;

private:
    EVP_MD_CTX* ctx;
};

// This hasher takes the first half of the SHA256 hash.
class SHA256HalfHasher : public HasherInterface
{
public:
    SHA256HalfHasher() = default;
    ~SHA256HalfHasher() override = default;
    E<std::vector<unsigned char>> hashToBytes(const std::string& bytes)
        const override;

private:
    SHA256Hasher full_hasher;
};

enum class SignatureAlgorithm
{
    RSA_PSS_SHA512,
    RSA_V1_5_SHA256,
    HMAC_SHA256,
    ECDSA_P256_SHA256,
    ECDSA_P384_SHA384,
    ED25519
};

enum class KeyType
{
    ED25519,
    RSA
};

struct KeyPair
{
    std::string public_key;
    std::string private_key;
};

class CryptoInterface
{
public:
    virtual ~CryptoInterface() = default;

    /// @brief Verifies the signature of the data using the provided key and
    /// algorithm.
    ///
    /// @param algo The signature algorithm to use.
    /// @param key The key to verify with. For asymmetric algorithms, this should
    /// be a PEM encoded public key. For HMAC, this is the raw key bytes.
    /// @param signature The signature to verify.
    /// @param data The data that was signed.
    /// @return True if the signature is valid, False if invalid. Returns an error
    /// if verification could not be performed (e.g. invalid key format).
    virtual E<bool> verifySignature(
        SignatureAlgorithm algo, const std::string& key,
        const std::vector<unsigned char>& signature,
        const std::string& data) = 0;

    /// @brief Signs the data using the provided key and algorithm.
    ///
    /// @param algo The signature algorithm to use.
    /// @param key The private key to sign with. For asymmetric algorithms, this
    /// should be a PEM encoded private key.
    /// @param data The data to sign.
    /// @return The signature bytes, or an error if signing failed.
    virtual E<std::vector<unsigned char>> sign(SignatureAlgorithm algo,
                                               const std::string& key,
                                               const std::string& data) = 0;

    /// @brief Generates a new key pair.
    ///
    /// @param type The type of key pair to generate.
    /// @return A KeyPair containing the PEM encoded public and private keys, or
    /// an error if generation fails.
    virtual E<KeyPair> generateKeyPair(KeyType type) = 0;
};

class Crypto : public CryptoInterface
{
public:
    E<bool> verifySignature(SignatureAlgorithm algo, const std::string& key,
                            const std::vector<unsigned char>& signature,
                            const std::string& data) override;

    E<std::vector<unsigned char>> sign(SignatureAlgorithm algo,
                                       const std::string& key,
                                       const std::string& data) override;

    E<KeyPair> generateKeyPair(KeyType type) override;
};

} // namespace mw
