# Technical Design: Argon2id Key Derivation Function

## 1. Overview
The goal is to implement the Argon2id Key Derivation Function (KDF) into `libmw`'s cryptographic module. Argon2id is an industry-standard, memory-hard KDF that is highly resistant to both GPU cracking and side-channel attacks, making it ideal for deriving cryptographic keys from user passwords.

## 2. Interface Changes
We will update `mw::CryptoInterface` in `includes/mw/crypto.hpp` to include a new pure virtual method for key derivation.

```cpp
class CryptoInterface
{
public:
    // ... existing methods ...

    /// @brief Derives a key using the Argon2id key derivation function.
    ///
    /// @param password The password to derive the key from.
    /// @param salt The salt for key derivation.
    /// @param iterations Time cost (number of iterations).
    /// @param memory_kb Memory cost in kilobytes.
    /// @param parallelism Number of threads/lanes.
    /// @param key_length The length of the derived key in bytes.
    /// @return The derived key as raw bytes, or an error if derivation failed.
    virtual E<std::vector<unsigned char>> deriveKeyArgon2id(
        const std::string& password, const std::string& salt,
        uint32_t iterations, uint32_t memory_kb, uint32_t parallelism,
        size_t key_length) = 0;
};
```

## 3. Implementation Details
The concrete implementation will be added to `mw::Crypto` in `crypto/src/crypto.cpp`. Since `libmw` relies on OpenSSL and the environment supports OpenSSL 3.x, we will use the `EVP_KDF` API.

### 3.1 OpenSSL API Usage
- **Fetching the Algorithm:** Use `EVP_KDF_fetch(nullptr, "ARGON2ID", nullptr)` to obtain the KDF handle.
- **Context Creation:** Create an `EVP_KDF_CTX` using `EVP_KDF_CTX_new`.
- **Parameter Configuration:** Construct an `OSSL_PARAM` array to feed the arguments:
  - `OSSL_KDF_PARAM_PASSWORD` -> maps to `password`
  - `OSSL_KDF_PARAM_SALT` -> maps to `salt`
  - `OSSL_KDF_PARAM_ITER` -> maps to `iterations`
  - `OSSL_KDF_PARAM_ARGON2_MEMCOST` -> maps to `memory_kb`
  - `OSSL_KDF_PARAM_ARGON2_LANES` -> maps to `parallelism`
- **Derivation:** Invoke `EVP_KDF_derive(ctx, out_buffer, key_length, params)`.

### 3.2 Resource Management & Error Handling
- Memory management of the OpenSSL structs will be handled securely via RAII (e.g., `std::unique_ptr` with `EVP_KDF_free` and `EVP_KDF_CTX_free` deleters).
- If any OpenSSL operation fails, the method will return an `std::unexpected(mw::runtimeError(...))` wrapping the OpenSSL error stack, accessed via `ERR_get_error()`.

## 4. Test Mocks
We will update `CryptoMock` in `includes/mw/crypto_mock.hpp` to include the new interface method so existing and future unit tests can mock key derivations.

```cpp
class CryptoMock : public CryptoInterface
{
    // ... existing mocks ...

    MOCK_METHOD(E<std::vector<unsigned char>>, deriveKeyArgon2id,
                (const std::string& password, const std::string& salt,
                 uint32_t iterations, uint32_t memory_kb, uint32_t parallelism,
                 size_t key_length),
                (override));
};
```

## 5. Testing Strategy
We will add test cases to `crypto/src/crypto_test.cpp`:
1. **Consistency Check:** Verify that invoking the method with identical parameters twice yields the exact same derived key.
2. **Distinct Configurations:** Verify that altering the salt, password, iterations, or memory cost produces entirely different derived keys.
3. **Correct Length:** Ensure the returned byte vector perfectly matches the requested `key_length`.
4. **Error Propagation:** Test invalid inputs if applicable, ensuring correct propagation of `E<std::vector<unsigned char>>` errors instead of crashing or silently failing.
