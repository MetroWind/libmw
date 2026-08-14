#pragma once

#include <cstddef>
#include <string>
#include <vector>

#include "error.hpp"

namespace mw
{

/// Resource limits enforced by the concrete crypto implementation.
namespace crypto_limits
{

/// Maximum size of a PEM-encoded key accepted by asymmetric operations.
inline constexpr std::size_t MAX_PEM_INPUT_SIZE = std::size_t{64} * 1024;

/// Maximum plaintext size accepted by authenticated encryption.
inline constexpr std::size_t MAX_PLAINTEXT_SIZE =
    std::size_t{16} * 1024 * 1024;

/// Maximum size of the current AES-GCM ciphertext envelope.
inline constexpr std::size_t MAX_CIPHERTEXT_SIZE =
    MAX_PLAINTEXT_SIZE + 12 + 16;

/// Maximum number of bytes permitted for secure random output.
inline constexpr std::size_t MAX_RANDOM_OUTPUT_SIZE =
    std::size_t{1} * 1024 * 1024;

/// Maximum number of bytes returned by a key-derivation operation.
inline constexpr std::size_t MAX_DERIVED_KEY_SIZE = std::size_t{64} * 1024;

} // namespace crypto_limits

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

/// A stateless SHA-256 hasher.
///
/// Each hash operation owns a separate digest context. The same instance may
/// therefore be used concurrently from multiple threads.
class SHA256Hasher : public HasherInterface
{
public:
    /// Construct a SHA-256 hasher.
    SHA256Hasher() = default;

    /// Destroy a SHA-256 hasher.
    ~SHA256Hasher() override = default;

    /// Copy a SHA-256 hasher, which has no operation state.
    SHA256Hasher(const SHA256Hasher&) = default;

    /// Assign a SHA-256 hasher, which has no operation state.
    SHA256Hasher& operator=(const SHA256Hasher&) = default;

    /// Move a SHA-256 hasher, which has no operation state.
    SHA256Hasher(SHA256Hasher&&) noexcept = default;

    /// Move-assign a SHA-256 hasher, which has no operation state.
    SHA256Hasher& operator=(SHA256Hasher&&) noexcept = default;

    /// Hash the given bytes with SHA-256 and return the raw digest.
    E<std::vector<unsigned char>> hashToBytes(const std::string& bytes)
        const override;
};

/// A stateless SHA-512 hasher.
///
/// Each hash operation owns a separate digest context. The same instance may
/// therefore be used concurrently from multiple threads.
class SHA512Hasher : public HasherInterface
{
public:
    /// Construct a SHA-512 hasher.
    SHA512Hasher() = default;

    /// Destroy a SHA-512 hasher.
    ~SHA512Hasher() override = default;

    /// Copy a SHA-512 hasher, which has no operation state.
    SHA512Hasher(const SHA512Hasher&) = default;

    /// Assign a SHA-512 hasher, which has no operation state.
    SHA512Hasher& operator=(const SHA512Hasher&) = default;

    /// Move a SHA-512 hasher, which has no operation state.
    SHA512Hasher(SHA512Hasher&&) noexcept = default;

    /// Move-assign a SHA-512 hasher, which has no operation state.
    SHA512Hasher& operator=(SHA512Hasher&&) noexcept = default;

    /// Hash the given bytes with SHA-512 and return the raw digest.
    E<std::vector<unsigned char>> hashToBytes(const std::string& bytes)
        const override;
};

/// A stateless hasher returning the first half of a SHA-256 digest.
///
/// The same instance may be used concurrently from multiple threads.
class SHA256HalfHasher : public HasherInterface
{
public:
    /// Construct a half-SHA-256 hasher.
    SHA256HalfHasher() = default;

    /// Destroy a half-SHA-256 hasher.
    ~SHA256HalfHasher() override = default;

    /// Hash the bytes and return the first half of the SHA-256 digest.
    E<std::vector<unsigned char>> hashToBytes(const std::string& bytes)
        const override;

private:
    SHA256Hasher full_hasher;
};

enum class SignatureAlgorithm
{
    /// RSA-PSS with SHA-512, MGF1-SHA-512, and a digest-length salt.
    RSA_PSS_SHA512,

    /// RSA PKCS#1 v1.5 signatures with SHA-256.
    RSA_V1_5_SHA256,

    /// HMAC with SHA-256 over an opaque raw-byte key.
    HMAC_SHA256,

    /// ECDSA with SHA-256 on the NIST P-256 curve.
    ECDSA_P256_SHA256,

    /// ECDSA with SHA-384 on the NIST P-384 curve.
    ECDSA_P384_SHA384,

    /// Ed25519 signatures without an external digest.
    ED25519
};

enum class KeyType
{
    /// An Ed25519 signing key pair.
    ED25519,

    /// A general RSA-2048 signing key pair.
    RSA
};

enum class EncryptionAlgorithm
{
    /// AES-256-GCM authenticated encryption.
    AES_256_GCM
};

/// A PEM-encoded public and private asymmetric key pair.
struct KeyPair
{
    std::string public_key;
    std::string private_key;
};

/// The interface for hashing, signatures, key generation, and encryption.
class CryptoInterface
{
public:
    virtual ~CryptoInterface() = default;

    /// Verify data with a supported signature algorithm and key.
    ///
    /// @param algo The signature algorithm to use.
    /// @param key The verification key. Asymmetric algorithms require a PEM
    /// encoded public key. HMAC treats this as opaque raw key bytes.
    /// @param signature The signature to verify.
    /// @param data The data that was signed.
    /// @return True if the signature is valid, false when the cryptographic
    /// check reports a mismatch. Returns an error for an unsupported algorithm,
    /// malformed key, incompatible key, unusable key, or serious verification
    /// failure.
    ///
    /// RSA-PSS accepts general RSA or compatible RSA-PSS keys of at least 2,048
    /// bits. RSA v1.5 accepts general RSA keys of at least 2,048 bits. ECDSA
    /// requires P-256 or P-384 as named by the selected algorithm, and Ed25519
    /// requires an Ed25519 public key.
    /// Asymmetric PEM keys are limited to
    /// `crypto_limits::MAX_PEM_INPUT_SIZE` bytes.
    /// Public errors do not contain caller-supplied key, signature, or data
    /// bytes.
    virtual E<bool> verifySignature(
        SignatureAlgorithm algo, const std::string& key,
        const std::vector<unsigned char>& signature,
        const std::string& data) = 0;

    /// Sign data with a supported signature algorithm and key.
    ///
    /// @param algo The signature algorithm to use.
    /// @param key The signing key. Asymmetric algorithms require a PEM encoded
    /// private key. HMAC treats this as opaque raw key bytes.
    /// @param data The data to sign.
    /// @return The signature bytes, or an error for an unsupported algorithm,
    /// malformed key, incompatible key, or unusable key.
    ///
    /// RSA-PSS accepts general RSA or compatible RSA-PSS keys of at least 2,048
    /// bits. RSA v1.5 accepts general RSA keys of at least 2,048 bits. ECDSA
    /// requires P-256 or P-384 as named by the selected algorithm, and Ed25519
    /// requires an Ed25519 private key.
    /// Asymmetric PEM keys are limited to
    /// `crypto_limits::MAX_PEM_INPUT_SIZE` bytes.
    /// Public errors do not contain caller-supplied key or data bytes.
    virtual E<std::vector<unsigned char>> sign(SignatureAlgorithm algo,
                                               const std::string& key,
                                               const std::string& data) = 0;

    /// @brief Generates a new key pair.
    ///
    /// @param type The type of key pair to generate.
    /// @return A KeyPair containing the PEM encoded public and private keys, or
    /// an error if generation fails.
    virtual E<KeyPair> generateKeyPair(KeyType type) = 0;

    /// @brief Encrypts the provided content using symmetric encryption.
    ///
    /// The resulting ciphertext for AES_256_GCM is formatted as:
    /// [ 12-byte IV ] + [ Raw Ciphertext ] + [ 16-byte Auth Tag ]
    ///
    /// @param algo The symmetric encryption algorithm to use.
    /// @param key The symmetric key (must be 32 bytes for AES_256_GCM).
    /// @param clear_content The plaintext data to encrypt.
    /// The plaintext is limited to `crypto_limits::MAX_PLAINTEXT_SIZE` bytes.
    /// @return The encrypted ciphertext, or an error if encryption failed.
    /// Public errors do not contain the key or plaintext.
    virtual E<std::string> encrypt(EncryptionAlgorithm algo,
                                   const std::string& key,
                                   const std::string& clear_content) = 0;

    /// @brief Decrypts the provided ciphertext using symmetric encryption.
    ///
    /// The ciphertext for AES_256_GCM must be formatted as:
    /// [ 12-byte IV ] + [ Raw Ciphertext ] + [ 16-byte Auth Tag ]
    ///
    /// @param algo The symmetric encryption algorithm to use.
    /// @param key The symmetric key (must be 32 bytes for AES_256_GCM).
    /// @param encrypted_content The ciphertext data to decrypt.
    /// The ciphertext envelope is limited to
    /// `crypto_limits::MAX_CIPHERTEXT_SIZE` bytes.
    /// @return The decrypted plaintext data, or an error if decryption failed.
    /// Authentication failure returns an error and no plaintext. Candidate
    /// plaintext is cleared from libmw's temporary output buffer. Public
    /// errors do not contain the key or ciphertext.
    virtual E<std::string> decrypt(EncryptionAlgorithm algo,
                                   const std::string& key,
                                   const std::string& encrypted_content) = 0;

    /// @brief Derives a key using the Argon2id key derivation function.
    ///
    /// @param password The password to derive the key from.
    /// @param salt The salt for key derivation.
    /// @param iterations Time cost (number of iterations).
    /// @param memory_kb Memory cost in kilobytes.
    /// @param parallelism Number of threads/lanes.
    /// @param key_length The length of the derived key in bytes.
    /// `key_length` may not exceed `crypto_limits::MAX_DERIVED_KEY_SIZE`.
    /// @return The derived key as raw bytes, or an error if derivation failed.
    /// Public errors do not contain the password, salt, or derived key bytes.
    virtual E<std::vector<unsigned char>> deriveKeyArgon2id(
        const std::string& password, const std::string& salt,
        uint32_t iterations, uint32_t memory_kb, uint32_t parallelism,
        size_t key_length) = 0;
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

    E<std::string> encrypt(EncryptionAlgorithm algo, const std::string& key,
                           const std::string& clear_content) override;

    E<std::string> decrypt(EncryptionAlgorithm algo, const std::string& key,
                           const std::string& encrypted_content) override;

    E<std::vector<unsigned char>> deriveKeyArgon2id(
        const std::string& password, const std::string& salt,
        uint32_t iterations, uint32_t memory_kb, uint32_t parallelism,
        size_t key_length) override;
};

} // namespace mw
