# Technical Design: Symmetric Encryption

## Objective
Add symmetric encryption capabilities to the `mw::Crypto` module, specifically supporting AES-256. This requires extending the `CryptoInterface`, providing a concrete implementation using OpenSSL in `Crypto`, and updating `CryptoMock` for testing.

## Interface Changes

### 1. `EncryptionAlgorithm` Enum
We will introduce a new enumeration to specify the symmetric encryption algorithm.

```cpp
namespace mw {
enum class EncryptionAlgorithm {
    AES_256_GCM
};
}
```

### 2. `CryptoInterface` Additions
We will add `encrypt` and `decrypt` virtual methods to the `CryptoInterface` in `includes/mw/crypto.hpp`.

```cpp
class CryptoInterface {
public:
    // ... existing methods ...

    /// @brief Encrypts the provided content using symmetric encryption.
    ///
    /// @param algo The symmetric encryption algorithm to use.
    /// @param key The symmetric key (must be exactly 32 bytes for AES_256_GCM).
    /// @param clear_content The plaintext data to encrypt.
    /// @return The encrypted ciphertext (which includes the IV/nonce and authentication tag if applicable), 
    ///         or an error if encryption failed.
    virtual E<std::string> encrypt(EncryptionAlgorithm algo, 
                                   const std::string& key, 
                                   const std::string& clear_content) = 0;

    /// @brief Decrypts the provided ciphertext using symmetric encryption.
    ///
    /// @param algo The symmetric encryption algorithm to use.
    /// @param key The symmetric key (must be exactly 32 bytes for AES_256_GCM).
    /// @param encrypted_content The ciphertext data (must include the IV/nonce and auth tag).
    /// @return The decrypted plaintext data, or an error if decryption failed 
    ///         (e.g., invalid key, corrupted data, or failed authentication).
    virtual E<std::string> decrypt(EncryptionAlgorithm algo, 
                                   const std::string& key, 
                                   const std::string& encrypted_content) = 0;
};
```

### 3. `CryptoMock` Updates
Add the corresponding mock methods to `CryptoMock` in `includes/mw/crypto_mock.hpp`.

```cpp
class CryptoMock : public CryptoInterface {
public:
    // ... existing mocks ...

    MOCK_METHOD(E<std::string>, encrypt, 
                (EncryptionAlgorithm algo, const std::string& key, const std::string& clear_content), 
                (override));

    MOCK_METHOD(E<std::string>, decrypt, 
                (EncryptionAlgorithm algo, const std::string& key, const std::string& encrypted_content), 
                (override));
};
```

## Implementation Details (in `crypto/src/crypto.cpp`)

### Algorithm specifics
For `AES_256_GCM`, we will use **AES-256-GCM** (Galois/Counter Mode). GCM provides Authenticated Encryption with Associated Data (AEAD), ensuring both confidentiality and data integrity. This prevents tampering with the ciphertext, which is highly recommended over CBC mode.

- **Key Size:** 32 bytes (256 bits).
- **IV/Nonce Size:** 12 bytes (96 bits), the standard for GCM.
- **Authentication Tag Size:** 16 bytes (128 bits).

### Ciphertext Structure
Since the `encrypt` and `decrypt` interfaces only pass around a single `std::string` for the content, the IV and the Authentication Tag must be bundled with the raw ciphertext. 
The output of `encrypt` will be formatted as:
`[ 12-byte IV ] + [ Raw Ciphertext ] + [ 16-byte Auth Tag ]`

### Encrypt Workflow
1. Validate `algo` is `AES_256_GCM`.
2. Validate `key` is exactly 32 bytes.
3. Generate a 12-byte random IV using `RAND_bytes`.
4. Initialize `EVP_CIPHER_CTX` with `EVP_aes_256_gcm()`.
5. Perform `EVP_EncryptInit_ex` passing the key and generated IV.
6. Perform `EVP_EncryptUpdate` to encrypt `clear_content`.
7. Perform `EVP_EncryptFinal_ex`.
8. Extract the 16-byte authentication tag using `EVP_CIPHER_CTX_ctrl` with `EVP_CTRL_GCM_GET_TAG`.
9. Construct the final output string: `IV + Ciphertext + Tag`.

### Decrypt Workflow
1. Validate `algo` is `AES_256_GCM`.
2. Validate `key` is exactly 32 bytes.
3. Validate `encrypted_content` is at least 28 bytes long (12-byte IV + 16-byte Tag).
4. Extract the IV, raw ciphertext, and tag from `encrypted_content`.
5. Initialize `EVP_CIPHER_CTX` with `EVP_aes_256_gcm()`.
6. Perform `EVP_DecryptInit_ex` passing the key and extracted IV.
7. Perform `EVP_DecryptUpdate` with the raw ciphertext.
8. Set the expected tag using `EVP_CIPHER_CTX_ctrl` with `EVP_CTRL_GCM_SET_TAG`.
9. Perform `EVP_DecryptFinal_ex`. If this fails, it indicates either the data was tampered with or the wrong key was used. Return an error.
10. Return the successfully decrypted plaintext.

## Testing Strategy
1. **Basic Roundtrip:** Encrypt a string and decrypt it with the same key. Verify the decrypted string matches the original.
2. **Invalid Key Length:** Provide keys longer or shorter than 32 bytes and ensure an error is returned.
3. **Invalid Ciphertext:** Attempt to decrypt a string shorter than 28 bytes. Ensure an error is returned.
4. **Tampering / Authentication Failure:** Encrypt a string, modify a byte in the ciphertext (or IV/Tag), and attempt to decrypt it. Ensure decryption fails gracefully returning an error.
5. **Wrong Key:** Encrypt a string, attempt to decrypt with a different 32-byte key. Ensure decryption fails.
6. **Empty Plaintext:** Encrypt an empty string and decrypt it, ensuring the behavior is correct.
