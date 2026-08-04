# `mw::crypto` TODO

## Goal

Provide the reusable cryptographic operations needed by `nsauth`, OIDC
clients, and other libmw consumers. Keep protocol encoding, protocol
validation, and consumer key-management policy in separate JOSE, OIDC, or
application modules.

Implement the work in the priority order below. Correctness and hardening of
the existing public API take precedence over adding new primitives.

## Compatibility Contract

- [ ] Preserve the signatures and valid behavior of all existing public
  functions.
- [ ] Keep existing call sites working without source changes, including
  current defaults and ciphertexts produced without associated data.
- [ ] Add new overloads and pure virtual functions where new capabilities are
  required, and update `Crypto`, `CryptoMock`, documentation, and downstream
  implementations together.
- [ ] Require users that implement `CryptoInterface` to implement newly added
  pure virtual functions, but do not require ordinary users of `Crypto` to
  change existing calls.
- [ ] Document intentional behavior changes where previously accepted input
  is rejected because it is invalid, unsafe, or exceeds a resource limit.
- [ ] Document when consumers must rebuild because a public class layout or
  virtual table changes, even if source compatibility is preserved.

## P0: Existing Implementation Corrections

### Hashers and OpenSSL Resource Ownership

- [x] Make `SHA256Hasher` and `SHA512Hasher` stateless by creating a fresh,
  RAII-owned `EVP_MD_CTX` for each hash operation.
- [x] Remove the raw `EVP_MD_CTX*` members from the public header.
- [x] Explicitly delete or correctly implement copy and move operations for
  every type that owns an OpenSSL resource.
- [x] Document and test that stateless hasher instances may be used
  concurrently.
- [x] Use a persistent digest context only if an intentional streaming API is
  added later.

`SHA256Hasher` and `SHA512Hasher` no longer contain an OpenSSL resource or any
other operation state. Their copy and move operations are value-like, and each
hash call owns its digest context. `SHA256HalfHasher` inherits these concurrency
properties. Because the public hasher class layouts changed, consumers must
rebuild before using this version, although existing source remains compatible.

### Algorithm and Key Validation

- [ ] Validate that every supplied key is compatible with the requested
  signature algorithm before signing or verification.
- [ ] Validate RSA versus EC versus Ed25519 key types, P-256 versus P-384
  curves, RSA-PSS restrictions, and minimum RSA modulus size.
- [ ] Reject unknown `SignatureAlgorithm`, `EncryptionAlgorithm`, and
  `KeyType` values instead of allowing a default or fallback algorithm.
- [ ] Add negative tests for incorrect key type, incorrect EC curve, malformed
  PEM, public keys passed to signing operations, weak RSA keys, and unknown
  enum values.

### Error Handling and Output Safety

- [x] Establish a clean OpenSSL error-queue boundary for every public crypto
  operation.
- [x] Clear stale errors on entry and consume the complete relevant error
  queue on infrastructure failures.
- [x] Return a stable, generic error for authentication failures instead of
  exposing provider-specific details or an empty OpenSSL error.
- [x] Check every OpenSSL return value, including BIO serialization and
  extraction operations.
- [x] Ensure failures never return partially initialized output.
- [x] Clear temporary plaintext after failed authenticated decryption.
- [x] Ensure public errors never contain keys, passwords, plaintext, or other
  secret material.

### Input and Resource Limits

- [ ] Define maximum accepted sizes for PEM input, plaintext, ciphertext,
  random output, and derived-key output.
- [ ] Validate every conversion from `size_t` to an OpenSSL `int` parameter.
- [ ] Reject excessive allocations and invalid parameter combinations before
  calling OpenSSL.
- [ ] Add boundary tests at, below, and above every public size limit.

## P1: Secure Random Generation

- [ ] Add a public operation that returns a requested number of
  cryptographically secure random bytes.
- [ ] Expose random generation through `CryptoInterface` so consumers can
  substitute deterministic output in their own tests.
- [ ] Use the OpenSSL private random generator for secret values where
  supported.
- [ ] Return an error whenever the operating system or cryptographic provider
  cannot provide secure randomness.
- [ ] Never return predictable or deterministic fallback output from the
  production implementation.
- [ ] Define zero-length behavior and enforce the public maximum output size.
- [ ] Add a narrow internal backend seam or injectable OpenSSL context so the
  concrete provider-failure path can be tested.
- [ ] Add tests for output length, zero-length requests, excessive requests,
  and provider failure.
- [ ] Add a non-repetition smoke test, while documenting that it is not a
  statistical validation of the random generator.

This operation will be used for authorization codes, access and refresh
tokens, sessions, setup credentials, `state`, `nonce`, PKCE verifiers,
password salts, and symmetric keys.

## P1: Constant-Time Comparison

- [ ] Add an equality operation for equal-length byte spans whose execution
  time is independent of byte contents.
- [ ] Provide convenient overloads for the project's supported string-like
  byte sequences.
- [ ] Define that a length mismatch returns false and may reveal that the
  input lengths differ, but does not inspect secret content.
- [ ] Document that protocols which must conceal length need to normalize
  values to a fixed length before comparison.
- [ ] Add tests for equal, unequal, empty, and different-length inputs.

Consumer adoption for tokens, CSRF values, PKCE values, nonces, MACs, and
password-derived values is tracked separately under Consumer Integration.

## P2: HKDF-SHA256 Key Derivation

- [ ] Add HKDF-SHA256 derivation with input key material, optional salt,
  context information, and caller-selected output length.
- [ ] Document that HKDF is for high-entropy input key material and key
  separation, not password hardening; passwords must continue to use
  Argon2id.
- [ ] Require callers to use distinct context information for distinct
  purposes.
- [ ] Define the encoding and composition rules for context information so
  concatenated fields cannot be ambiguous.
- [ ] Enforce the RFC 5869 SHA-256 output limit of 8,160 bytes and the lower
  project-specific allocation limit, if any.
- [ ] Add the applicable RFC 5869 test vectors and input-validation tests.
- [ ] Test empty input, omitted and empty salt, empty context, maximum output,
  and excessive output.

## P2: Authenticated Encryption

- [ ] Extend AES-256-GCM encryption and decryption to accept associated
  authenticated data through new overloads.
- [ ] Preserve source and ciphertext compatibility by making the existing
  methods delegate with empty associated data.
- [ ] Require decryption to fail if the ciphertext, authentication tag, IV,
  key, or associated data is incorrect.
- [ ] Return the same public authentication-failure category for all
  unauthenticated inputs.
- [ ] Document the current envelope as a 12-byte IV, raw ciphertext, and a
  16-byte authentication tag.
- [ ] Define a versioned envelope strategy before changing the serialized
  format, algorithm, IV length, or tag length.
- [ ] Add standard AES-GCM vectors where the internal test seam permits fixed
  IVs.
- [ ] Add round-trip and tampering tests covering plaintext, associated data,
  IVs, tags, keys, empty input, maximum input, and truncated input.

Associated data allows callers to bind encrypted values to a purpose, format
version, realm, issuer, or other unencrypted context. Associated data is not
stored in the current ciphertext envelope and must be supplied again during
decryption.

## P3: Asymmetric Key Operations

- [ ] Introduce an algorithm-specific key-generation options type or overload
  rather than adding an RSA-only parameter to every key type.
- [ ] Make RSA key size explicit while retaining a secure default of at least
  2,048 bits.
- [ ] Reject RSA sizes below the supported minimum and above a documented
  resource limit.
- [ ] Add an operation for deriving or exporting the public key associated
  with a private key.
- [ ] Clearly document supported public- and private-key PEM encodings,
  including whether encrypted private keys and passphrase callbacks are
  supported.
- [ ] Add tests for invalid generation parameters, supported RSA sizes,
  malformed PEM, and public-key derivation for every supported key type.

RSA-2048 with RSA/SHA-256 is sufficient for the initial `nsauth` and
Tailscale interoperability target. Existing EC and Ed25519 public interfaces
must still validate their inputs correctly.

## P3: Binary API and Secret Handling

- [ ] Prefer `std::span<const std::byte>` for non-owning binary input and
  `std::vector<std::byte>` for ordinary owned binary output in new APIs.
- [ ] Define a staged migration plan for existing `std::string` and
  `std::vector<unsigned char>` interfaces before changing them.
- [ ] Add explicit types or wrappers only where they prevent a demonstrated
  risk of confusing plaintext, keys, ciphertext, signatures, or encoded
  text.
- [ ] Ensure any secret-bearing wrapper cannot be accidentally formatted or
  logged.
- [ ] Write a threat model before introducing a secure buffer type.
- [ ] If a secure buffer is adopted, document its copy, move, resize, clear,
  allocation, and exception behavior and test that destruction clears its
  owned storage.
- [ ] Update `CryptoInterface`, `Crypto`, `CryptoMock`, public documentation,
  and migration guidance together for every API change.

Secure erasure does not protect secrets already copied into ordinary strings,
temporary allocations, logs, crash dumps, or swap. Avoid representing secrets
in ordinary copyable types before relying on destruction-time clearing.

## Platform and Provider Support

- [ ] Declare the minimum supported OpenSSL version. The current Argon2id
  implementation requires OpenSSL 3.2 or newer.
- [ ] Enforce the required OpenSSL version in CMake, or make unavailable
  provider algorithms an explicitly documented runtime capability.
- [ ] Define whether callers may supply an `OSSL_LIB_CTX` and provider
  property query, including the policy for FIPS deployments.
- [ ] Test missing or disabled algorithm providers without silently selecting
  a weaker replacement.
- [ ] Document which operations depend on provider availability and how those
  failures are reported.

## Consumer Integration

These tasks belong to `nsauth` or another consuming application. They should
have corresponding consumer issues and integration tests rather than blocking
completion of the libmw primitive that enables them.

- [ ] Replace direct random generation in consumers with
  `CryptoInterface`.
- [ ] Use constant-time comparison for fixed-length tokens, CSRF values, PKCE
  values, nonces, MACs, and password-derived verification values where
  applicable.
- [ ] Define a registry of unambiguous HKDF context values for encryption,
  CSRF authentication, token hashing, and every other key purpose.
- [ ] Derive purpose-specific subkeys instead of reusing one server master
  key for unrelated operations.
- [ ] Bind encrypted application values to their purpose, format version,
  realm, issuer, or other relevant context using associated data.
- [ ] Define migration and rollback behavior for existing stored ciphertext
  before adopting a new envelope or non-empty associated data.
- [ ] Add end-to-end tests proving that values from one purpose, realm, or
  version cannot be accepted in another.
