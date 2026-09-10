# Validate cryptographic algorithms and signature keys

## Status

Proposed.

This document designs the `Algorithm and Key Validation` work in
`todo-crypto.md`. It covers validation of `SignatureAlgorithm`,
`EncryptionAlgorithm`, and `KeyType`, as well as validation of keys supplied
to `Crypto::sign()` and `Crypto::verifySignature()`.

## Context

`mw::Crypto` exposes signatures, key generation, and authenticated
encryption through the public declarations in `includes/mw/crypto.hpp`. The
implementation in `crypto/src/crypto.cpp` delegates cryptographic operations
to OpenSSL's high-level EVP API.

The public signature API supports these algorithms:

- `RSA_PSS_SHA512`;
- `RSA_V1_5_SHA256`;
- `HMAC_SHA256`;
- `ECDSA_P256_SHA256`;
- `ECDSA_P384_SHA384`; and
- `ED25519`.

The public key-generation API supports `ED25519` and `RSA`. The public
encryption API supports `AES_256_GCM`.

The enum types are scoped C++ enums, but a caller can still create an invalid
value with `static_cast`. Values can also cross an ABI, serialization, FFI,
or memory-corruption boundary. Consequently, a `switch` over one of these
enums must not assume that the value is one of its declared enumerators.

The current implementation has several fail-open or provider-dependent
paths:

- an unknown signature algorithm is treated as an asymmetric algorithm;
- `getDigestMethod()` returns `nullptr` both for valid Ed25519 and for an
  unknown algorithm;
- an unknown key type falls back to Ed25519 key generation;
- key parsing proves only that OpenSSL can decode a key, not that the key is
  compatible with the requested signature algorithm;
- an EC key is checked for missing parameters, but not for the required
  P-256 or P-384 curve;
- an RSA key is not checked for a minimum modulus size;
- a PSS-only RSA key and its embedded restrictions are not handled
  explicitly; and
- RSA padding and MGF1 choices are partly left to OpenSSL defaults.

These behaviors make acceptance depend on the active provider and on which
OpenSSL call happens to fail first. They can also turn a programming error,
such as selecting ECDSA while supplying RSA material, into a confusing
provider error.

OpenSSL provides the primitives needed for explicit validation:

- [`EVP_PKEY_is_a()`](https://docs.openssl.org/3.5/man3/EVP_PKEY_is_a/)
  identifies a provider-backed key by algorithm name;
- [`EVP_PKEY_get_bits()`](https://docs.openssl.org/3.5/man3/EVP_PKEY_get_size/)
  reports the RSA modulus size;
- [`EVP_PKEY_get_group_name()`](https://docs.openssl.org/3.5/man3/EVP_PKEY_get_group_name/)
  reports an EC key's group;
- [`EVP_PKEY_public_check()`, `EVP_PKEY_private_check()`, and
  `EVP_PKEY_pairwise_check()`](https://docs.openssl.org/3.5/man3/EVP_PKEY_check/)
  validate key components; and
- OpenSSL's [RSA-PSS support](https://docs.openssl.org/3.5/man7/RSA-PSS/)
  enforces restrictions encoded in PSS-only keys when operation parameters
  are configured.

## Goals

The implementation must:

1. Reject every unknown `SignatureAlgorithm`, `EncryptionAlgorithm`, and
   `KeyType` value.
2. Reject an asymmetric key whose type does not match the requested
   signature algorithm.
3. Require P-256 for `ECDSA_P256_SHA256` and P-384 for
   `ECDSA_P384_SHA384`.
4. Require an RSA modulus of at least 2,048 bits for both supported RSA
   signature algorithms.
5. Treat a PSS-only RSA key according to its encoded restrictions rather
   than silently weakening or replacing the requested signature profile.
6. Require private key material for signing and valid public key material
   for verification.
7. Preserve all existing function signatures and all currently documented
   valid behavior.
8. Return `false` only for an invalid signature. Invalid algorithms,
   malformed keys, incompatible keys, and unusable keys must return an
   `mw::Error`.
9. Test every negative case listed in `todo-crypto.md` and the RSA-PSS cases
   needed to prove the restriction policy.

## Non-goals

This change does not add signature algorithms, key types, or encryption
algorithms.

This change does not add public key-generation options. Configurable RSA key
sizes and EC key generation belong to the later `Asymmetric Key Operations`
work. `generateKeyPair(KeyType::RSA)` continues to generate a 2,048-bit key.

This change does not define maximum PEM, data, signature, or ciphertext
sizes. Those limits and every `size_t`-to-`int` conversion are covered by the
separate `Input and Resource Limits` work. The implementation must not make
those conversions less safe while introducing validation.

This change does not redesign OpenSSL error-queue handling. Public-operation
error boundaries and sanitization are covered by the separate `Error
Handling and Output Safety` work. Errors introduced by this design are
nevertheless deterministic and do not contain key material.

This change does not add encrypted-private-key or passphrase-callback
support. Supported PEM encodings will be documented comprehensively by the
later `Asymmetric Key Operations` work.

This change does not impose a new minimum HMAC key length. An HMAC key is raw
bytes rather than an asymmetric key object, and rejecting short or empty HMAC
keys would change currently valid API behavior. Applications remain
responsible for choosing sufficiently strong HMAC keys until a separate,
explicit compatibility decision changes that contract.

This change does not attempt to infer a signature algorithm from a key. The
caller's enum remains authoritative. Inference would make downgrade and
configuration mistakes harder to detect.

## Compatibility contract

No declaration in `includes/mw/crypto.hpp` changes. `CryptoInterface`,
`Crypto`, and `CryptoMock` retain their current layouts and virtual function
sets. Consumers do not need source changes or a rebuild specifically because
of a public class layout or virtual-table change.

Existing valid calls continue to behave as follows:

- general RSA keys of at least 2,048 bits work with RSA-PSS/SHA-512 and
  RSA PKCS#1 v1.5/SHA-256;
- P-256 keys work with ECDSA/SHA-256;
- P-384 keys work with ECDSA/SHA-384;
- Ed25519 keys work with Ed25519;
- arbitrary byte strings remain HMAC/SHA-256 keys;
- verification with a valid key and mismatched data or signature returns
  `false`;
- RSA and Ed25519 key generation retain their present defaults; and
- AES-256-GCM behavior and ciphertext format do not change.

The following previously provider-dependent or accidentally accepted calls
intentionally become errors:

- signing or verification with the wrong asymmetric key family;
- ECDSA with the wrong curve;
- RSA signing or verification with a modulus smaller than 2,048 bits;
- RSA PKCS#1 v1.5 with a PSS-only key;
- RSA-PSS/SHA-512 with a PSS-only key whose restrictions conflict with the
  exact requested profile;
- signing with a public key;
- use of structurally invalid public or private key material; and
- any operation receiving an unknown public enum value.

This is a behavior-hardening change permitted by the compatibility contract
in `todo-crypto.md`: invalid or unsafe inputs are rejected while signatures
and valid results remain compatible.

## Security properties

The validation layer is fail-closed. It accepts only an explicitly listed
algorithm profile and an explicitly compatible key. No default branch chooses
a cryptographic primitive.

The requested algorithm is validated before the supplied key is interpreted.
This ordering matters for two reasons. First, an unknown algorithm must not
select the asymmetric PEM parser merely because it is not equal to
`HMAC_SHA256`. Second, malformed key material must not hide the caller's more
fundamental unsupported-algorithm error.

Key validation happens before message signing or signature verification.
OpenSSL initialization and key checks may perform cryptographic work, but no
signature is emitted and no signature is accepted until the key has passed
the complete profile validation.

The algorithm profile is exact. In particular, `RSA_PSS_SHA512` means:

- RSA-PSS padding;
- SHA-512 as the message digest;
- MGF1 with SHA-512; and
- a 64-byte salt, equal to the SHA-512 output length.

RFC 8017 defines the independent hash, mask-generation, and salt-length
parameters of RSASSA-PSS. See [RFC 8017, Section
9.1](https://www.rfc-editor.org/rfc/rfc8017.html#section-9.1). Configuring all
three explicitly prevents an OpenSSL default or key restriction from changing
the meaning of the public enum.

The 2,048-bit RSA minimum applies equally to signing and verification. Weak
public keys are not accepted merely because verification does not expose a
private secret. Accepting a weak verification key would still authorize
signatures under an algorithm strength below the library policy.

## Validation policy

### Signature compatibility matrix

| Public algorithm | Accepted key | Required parameters |
| --- | --- | --- |
| `RSA_PSS_SHA512` | RSA or RSA-PSS | >= 2,048 bits; PSS profile below |
| `RSA_V1_5_SHA256` | general RSA only | >= 2,048 bits |
| `HMAC_SHA256` | raw bytes | no new length requirement |
| `ECDSA_P256_SHA256` | EC | named group P-256 |
| `ECDSA_P384_SHA384` | EC | named group P-384 |
| `ED25519` | Ed25519 | no external digest |

`RSA_PSS_SHA512` accepts a general RSA key because a general RSA key can be
used with explicit PSS parameters. It also accepts a PSS-only key if that key
permits the exact profile.

`RSA_V1_5_SHA256` rejects a PSS-only key even if OpenSSL reports it as related
to RSA. A PSS-only key is intentionally restricted to PSS operations, and it
must never be reinterpreted as a general RSA key.

`HMAC_SHA256` does not use PEM parsing. Its `std::string` key is treated as an
opaque sequence of bytes, including embedded NUL bytes. A string that happens
to contain PEM text is still an HMAC key when HMAC is explicitly requested.
This preserves the existing public contract.

### RSA-PSS restriction policy

OpenSSL distinguishes general RSA keys from RSA-PSS keys. A PSS-only key may
encode restrictions for the message digest, MGF1 digest, and minimum salt
length. OpenSSL documents that attempts to configure conflicting operation
parameters fail; see
[`EVP_PKEY_CTX_set_rsa_pss_keygen_md()`](https://docs.openssl.org/3.5/man3/EVP_PKEY_CTX_set_rsa_pss_keygen_md/).

The implementation will not manually decode `RSA_PSS_PARAMS`. That API is
algorithm-specific and deprecated for provider-backed OpenSSL 3 code. Instead,
the implementation will initialize the EVP signature context and explicitly
set the required parameters. This uses the provider that owns the key as the
authority for whether its restrictions are compatible.

A PSS-only key is accepted for `RSA_PSS_SHA512` only if all of these
configuration operations succeed:

1. initialize signing or verification with SHA-512;
2. select `RSA_PKCS1_PSS_PADDING`;
3. select SHA-512 for MGF1; and
4. select `RSA_PSS_SALTLEN_DIGEST`, which is 64 bytes with SHA-512.

The consequences are deliberate:

- a key restricted to SHA-512 is compatible;
- a key restricted to MGF1/SHA-512 is compatible;
- a key whose minimum salt length is at most 64 bytes is compatible with the
  library's 64-byte salt;
- a key restricted to SHA-256 is incompatible;
- a key restricted to MGF1/SHA-256 is incompatible; and
- a key whose minimum salt length exceeds 64 bytes is incompatible.

The implementation must not catch a restriction failure and retry with the
key's parameters. Retrying would silently change the algorithm represented by
`RSA_PSS_SHA512`.

### Key-role policy

`sign()` requires private key material for every asymmetric algorithm.
`PEM_read_bio_PrivateKey()` remains the parser. After parsing and profile
checks, `EVP_PKEY_pairwise_check()` must prove that the private and public
components form a valid pair.

`verifySignature()` requires a public-key PEM for every asymmetric algorithm.
`PEM_read_bio_PUBKEY()` remains the parser. After parsing and profile checks,
`EVP_PKEY_public_check()` must validate the public component.

Pairwise validation is stronger than checking only that a private field is
present. It detects a malformed private key whose public and private
components do not correspond. This cost occurs once per supplied-key
operation under the current string-based API, which already reparses the key
for each call.

The return value of each EVP check is handled exactly:

- `1` means validation succeeded;
- `0` means the key is invalid;
- `-2` means the provider does not support the required check; and
- any other negative value means validation could not be performed.

Only `1` is accepted. The library must not skip a check when a provider
returns `-2`, because that would make key validation depend on provider
capability. Unsupported validation is an operational error, not evidence that
the key is valid.

### EC curve policy

An EC key must first identify as `EC` through `EVP_PKEY_is_a()`. The
implementation then calls `EVP_PKEY_get_group_name()` and normalizes the
returned OpenSSL group name to a numeric identifier with `OBJ_txt2nid()`.

The accepted identifiers are:

- `NID_X9_62_prime256v1` for `ECDSA_P256_SHA256`; and
- `NID_secp384r1` for `ECDSA_P384_SHA384`.

Converting through OpenSSL's object database accepts recognized aliases such
as `prime256v1` and `P-256` without maintaining an incomplete string-alias
list in libmw. A missing group, an unknown group name, or a different group is
an error.

The public-key or pairwise check still runs after the group match. Matching a
curve name alone does not prove that the EC point or private scalar is valid.

### Ed25519 policy

An Ed25519 operation accepts only a key for which
`EVP_PKEY_is_a(key, "ED25519")` returns `1`. X25519, Ed448, and other raw-key
types are rejected even if they have similar encodings or APIs.

Ed25519 uses the one-shot `EVP_DigestSign()` and `EVP_DigestVerify()` calls
with no external digest. The `nullptr` digest is stored only in the already
validated Ed25519 profile. It is never used as the representation of an
unknown algorithm. OpenSSL's
[Ed25519 signature documentation](https://docs.openssl.org/3.5/man7/EVP_SIGNATURE-ED25519/)
describes this no-external-digest form.

### Encryption algorithm and key-type policy

`encrypt()` and `decrypt()` must use an exhaustive algorithm-selection helper
before checking the symmetric key or ciphertext. Today their explicit
inequality check already rejects all values other than `AES_256_GCM`; the
helper makes the fail-closed rule uniform and keeps later additions from
creating inconsistent dispatch.

`generateKeyPair()` must replace its initialized-Ed25519 fallback with an
exhaustive `switch`:

- `KeyType::ED25519` selects Ed25519;
- `KeyType::RSA` selects general RSA and 2,048 bits; and
- `default` returns `Unsupported key type` before allocating a key-generation
  context.

The implementation must not initialize the selected OpenSSL type before the
switch. An unknown enum therefore has no usable fallback value.

## Detailed design

### Internal signature profile

Add private implementation-only types in the anonymous namespace of
`crypto/src/crypto.cpp`. They must not appear in the public header.

```c++
enum class SignatureKeyKind
{
    RSA,
    EC,
    ED25519,
    HMAC
};

struct SignatureProfile
{
    SignatureKeyKind key_kind;
    const EVP_MD* digest;
    int ec_curve_nid;
    bool use_pss;
};
```

The actual implementation may add fields for an OpenSSL algorithm name,
MGF1 digest, or salt policy. It must retain one profile object as the single
source of truth for dispatch and validation. Parallel switches for digest,
key type, curve, and execution mode are forbidden because a future algorithm
could be added to one switch but omitted from another.

The profile lookup has this shape:

```c++
E<SignatureProfile> signatureProfile(SignatureAlgorithm algo);
```

It returns a complete profile for each declared enumerator and returns
`runtimeError("Unsupported signature algorithm")` in the `default` case.
Although the compiler may warn about omitted declared enumerators when there
is no `default`, a `default` is required here to reject cast-integer values at
runtime.

`ED25519` is the only profile allowed to contain a null digest. Code outside
profile construction must not use a null digest to decide that an algorithm
is Ed25519.

### Internal validation functions

Use small named functions instead of one deeply nested function or temporary
closures. Suggested responsibilities are:

```c++
E<void> validatePublicKey(EVP_PKEY* pkey);
E<void> validatePrivateKey(EVP_PKEY* pkey);
E<void> validateKeyType(EVP_PKEY* pkey,
                        const SignatureProfile& profile);
E<void> validateRSAKey(EVP_PKEY* pkey,
                       const SignatureProfile& profile);
E<void> validateECKey(EVP_PKEY* pkey,
                      const SignatureProfile& profile);
E<void> configureSignatureContext(EVP_PKEY_CTX* pkey_ctx,
                                  const SignatureProfile& profile);
```

These names are illustrative but follow the repository's function naming
style. All functions are private to the translation unit, so no new public
interface comments are required.

The responsibilities must stay separated:

- parsing converts bytes into an owned `EVP_PKEY`;
- type validation compares that key with the requested profile;
- parameter validation checks RSA strength or EC group;
- role validation checks public or private components; and
- operation configuration fixes padding, digest, MGF1, and salt choices.

This separation makes each failure test target one policy. It also avoids
using `EVP_DigestSignInit()` as the accidental key-type validator.

### Key type identification

Use `EVP_PKEY_is_a()` instead of `EVP_PKEY_id()` for new validation code.
OpenSSL 3 keys are provider-backed, and `EVP_PKEY_is_a()` compares names and
aliases exposed by the key management implementation.

Identification order matters for RSA:

1. test `RSA-PSS` first;
2. then test `RSA`; and
3. reject the key if neither matches the profile.

Testing PSS first prevents a PSS-only key from being accepted by
`RSA_V1_5_SHA256` if a provider exposes a general RSA alias for it.

The type validator returns whether an RSA key is general RSA or PSS-only to
the caller, either through a small internal enum or a boolean output in the
validated profile state. That result is used to reject PSS-only keys for the
v1.5 algorithm.

Type-validation failure returns the stable message
`Incompatible key type for signature algorithm`. The message does not echo
the PEM or any key parameters.

### RSA validation sequence

For either RSA signature algorithm, perform these steps:

1. Identify the key as general RSA or RSA-PSS.
2. Reject RSA-PSS immediately for `RSA_V1_5_SHA256`.
3. Call `EVP_PKEY_get_bits()`.
4. If the result is zero or negative, return an error because the modulus
   size could not be established.
5. If the result is below `MIN_RSA_BITS`, return
   `RSA key is smaller than 2048 bits`.
6. Run the public or pairwise key check according to the operation.
7. Initialize the signature operation with the profile digest.
8. Configure the exact padding mode.
9. For PSS, configure MGF1/SHA-512 and digest-length salt.
10. Treat any parameter-configuration failure as an incompatible or unusable
    key error. Do not retry with other parameters.

Define the policy constant in the anonymous namespace:

```c++
constexpr int MIN_RSA_BITS = 2048;
```

The constant is an `int` because `EVP_PKEY_get_bits()` returns `int`. There is
no signed/unsigned conversion in the comparison.

For `RSA_V1_5_SHA256`, explicitly call
`EVP_PKEY_CTX_set_rsa_padding(..., RSA_PKCS1_PADDING)`. The current OpenSSL
default is not part of libmw's public contract and must not be relied on.

For `RSA_PSS_SHA512`, call all of:

```c++
EVP_PKEY_CTX_set_rsa_padding(
    pkey_ctx, RSA_PKCS1_PSS_PADDING);
EVP_PKEY_CTX_set_rsa_mgf1_md(pkey_ctx, EVP_sha512());
EVP_PKEY_CTX_set_rsa_pss_saltlen(
    pkey_ctx, RSA_PSS_SALTLEN_DIGEST);
```

Every return value must be checked. A return value less than or equal to zero
is an error.

### EC validation sequence

For either ECDSA algorithm, perform these steps:

1. Require `EVP_PKEY_is_a(pkey, "EC") == 1`.
2. Query the required buffer length with `EVP_PKEY_get_group_name()` or use a
   fixed buffer large enough for OpenSSL object names.
3. Check that group-name retrieval returns `1`.
4. Convert the name with `OBJ_txt2nid()`.
5. Compare the NID with the exact NID in the signature profile.
6. Return `Incompatible EC curve for signature algorithm` if it differs.
7. Run the public or pairwise key check.
8. Initialize ECDSA with the profile digest.

If a two-call length query is used, both calls must be checked. If a fixed
buffer is used, truncation must be impossible or detectable. The
implementation must not compare an uninitialized or truncated group name.

The old `EVP_PKEY_missing_parameters()` check becomes redundant and should
be removed after group retrieval and the full EVP key check are in place.
Keeping both would add a deprecated or legacy-oriented check without adding
a distinct policy guarantee.

### Public and private key validation sequence

Create an `EVP_PKEY_CTX` with `EVP_PKEY_CTX_new_from_pkey(nullptr, pkey,
nullptr)`. Own it with `std::unique_ptr<EVP_PKEY_CTX,
decltype(&EVP_PKEY_CTX_free)>`.

For verification, call `EVP_PKEY_public_check()`. For signing, call
`EVP_PKEY_pairwise_check()`.

If context allocation fails, return an infrastructure error. If a check
returns `0`, return a generic invalid-public-key or invalid-private-key error.
If it returns a negative value, return an operational validation error. The
later error-queue work may enrich infrastructure diagnostics, but the
validation result must not expose key bytes.

The checks run for RSA, EC, and Ed25519. HMAC does not create an asymmetric
key context and therefore does not use these checks.

### Signature execution flow

`Crypto::sign()` follows this order:

1. establish the existing OpenSSL error-queue entry boundary;
2. call `signatureProfile(algo)` and stop on an unknown value;
3. if the profile is HMAC, create the HMAC key and use the HMAC signing path;
4. otherwise parse a private-key PEM;
5. validate key family and algorithm-specific parameters;
6. validate the private/public pair;
7. allocate and initialize the digest-sign context;
8. configure exact algorithm parameters;
9. obtain the required signature length;
10. allocate the output vector;
11. create the signature;
12. resize to the returned length and return it.

`Crypto::verifySignature()` follows this order:

1. establish the existing OpenSSL error-queue entry boundary;
2. call `signatureProfile(algo)` and stop on an unknown value;
3. if the profile is HMAC, create the HMAC key and use constant-time HMAC
   comparison;
4. otherwise parse a public-key PEM;
5. validate key family and algorithm-specific parameters;
6. validate the public component;
7. allocate and initialize the digest-verify context;
8. configure exact algorithm parameters;
9. execute verification; and
10. return `true` for a valid signature, `false` for a cryptographic mismatch,
    or an error if verification could not be performed.

The same profile and helper functions are used by signing and verification.
Duplicating the compatibility logic would allow the two operations to drift.

### PEM parsing behavior

Continue using `PEM_read_bio_PrivateKey()` for signing and
`PEM_read_bio_PUBKEY()` for verification. OpenSSL documents these generic EVP
PEM readers in its
[PEM key documentation](https://docs.openssl.org/3.5/man3/PEM_read_bio_PrivateKey/).

The parser result is necessary but not sufficient. A non-null result moves to
type, parameter, and component validation. A null result returns an error and
never reaches EVP signature initialization.

Supplying a public-key PEM to `sign()` fails in private-key parsing. The
implementation must not add a fallback that parses it as a public key.

Supplying malformed PEM to either operation returns an error. It must not be
treated as an invalid signature because signature bytes were never evaluated
under a valid key.

Strict rejection of extra PEM blocks or trailing non-PEM data is not part of
this change. OpenSSL's PEM reader can skip extraneous content, and tightening
that parsing contract should be considered together with the future PEM-size
and encoding policy.

### Unknown enum handling

Tests will construct unknown values explicitly:

```c++
constexpr auto UNKNOWN_SIGNATURE_ALGORITHM =
    static_cast<mw::SignatureAlgorithm>(-1);
constexpr auto UNKNOWN_ENCRYPTION_ALGORITHM =
    static_cast<mw::EncryptionAlgorithm>(-1);
constexpr auto UNKNOWN_KEY_TYPE = static_cast<mw::KeyType>(-1);
```

Use named `constexpr` values in tests to make intent clear. Each public
operation validates its enum at its entry dispatch:

- both `sign()` and `verifySignature()` reject an unknown
  `SignatureAlgorithm`;
- both `encrypt()` and `decrypt()` reject an unknown
  `EncryptionAlgorithm`; and
- `generateKeyPair()` rejects an unknown `KeyType`.

Unknown signature-algorithm tests should supply malformed key material. This
proves algorithm validation precedes parsing. Unknown encryption-algorithm
tests should supply otherwise valid inputs and verify no result is produced.

Do not add sentinel enum cases such as `UNKNOWN` or `COUNT`. Such cases would
be declared values that callers might incorrectly treat as supported. Runtime
validation at the API boundary is still required even if a sentinel exists.

## Error semantics

This change continues to return `RuntimeError` through `mw::E<T>`. Introducing
a new public validation error type would be an unrelated API decision.

Use stable, secret-free messages for policy failures:

| Condition | Message |
| --- | --- |
| unknown signature enum | `Unsupported signature algorithm` |
| unknown encryption enum | `Unsupported encryption algorithm` |
| unknown key-type enum | `Unsupported key type` |
| wrong asymmetric family | `Incompatible key type for signature algorithm` |
| wrong EC group | `Incompatible EC curve for signature algorithm` |
| RSA modulus below minimum | `RSA key is smaller than 2048 bits` |
| invalid public component | `Invalid public key` |
| invalid private pair | `Invalid private key` |
| incompatible PSS restrictions | `Incompatible RSA-PSS key restrictions` |

Infrastructure failures may retain operation-specific messages under the
current error design. They must not include the supplied key string, message
data, signature bytes, HMAC secret, or private-key parameters.

Malformed PEM may retain the existing `Failed to load public key` or `Failed
to load private key` prefix. Tests should normally assert the error category
and stable policy messages rather than complete provider-generated suffixes.
The later error-queue work will define the final public diagnostics boundary.

Verification outcomes are classified as follows:

| Situation | Result |
| --- | --- |
| correct key, data, and signature | `true` |
| valid compatible key, bad signature | `false` |
| valid compatible key, changed data | `false` |
| malformed signature encoding | `false` if OpenSSL classifies it as mismatch |
| malformed key | error |
| wrong key type or curve | error |
| weak RSA key | error |
| unknown algorithm | error |
| provider cannot perform required validation | error |

The distinction is important to callers. `false` means the requested
verification was well-formed and cryptographically failed. An error means the
library could not validly attempt that verification under its policy.

## Source changes

### `includes/mw/crypto.hpp`

No signatures or enum values change.

Expand public comments for `sign()` and `verifySignature()` to state:

- the exact compatible key type for each algorithm;
- the P-256 and P-384 requirements;
- the 2,048-bit RSA minimum;
- that signing requires private-key PEM;
- that asymmetric verification requires public-key PEM; and
- that incompatible or malformed keys return errors.

Expand the enum comments so each public algorithm value states its exact
primitive. Every public enum and `KeyPair` should have an intention comment if
the header is touched, in accordance with repository style.

### `crypto/src/crypto.cpp`

Add the profile, validation helpers, `MIN_RSA_BITS`, EC group retrieval, and
exhaustive enum dispatch in the anonymous namespace.

Refactor `loadKey()` and `loadPrivateKey()` so they do not decide HMAC versus
PEM by comparing an unvalidated enum. Prefer names that state the material
they parse, such as `loadPublicKeyPEM()`, `loadPrivateKeyPEM()`, and
`createHMACKey()`.

Replace `getDigestMethod()` with the complete profile lookup. Remove the
ambiguous `default: return nullptr` behavior.

Replace `configureRSAPSS()` with a profile-driven signature-context
configuration helper that also explicitly configures RSA PKCS#1 v1.5 and PSS
MGF1.

Remove the two `EVP_PKEY_missing_parameters()` checks after the stronger EC
group and key-component checks are active.

Refactor `generateKeyPair()` to select its OpenSSL key type only inside an
exhaustive switch.

Keep all OpenSSL-owning pointers RAII-managed with `std::unique_ptr`. Add an
`EVP_PKEY_CTX_ptr` alias alongside the existing aliases rather than spelling
the type repeatedly.

### `includes/mw/crypto_mock.hpp`

No change is required because the public virtual interface does not change.
The file must still be compiled by the crypto test target to catch accidental
interface drift.

### `crypto/src/crypto_test.cpp`

Extend the existing test helpers so tests can generate:

- general RSA keys at caller-selected bit sizes;
- RSA-PSS-only keys with compatible and incompatible restrictions;
- P-256 and P-384 keys independently of the tested operation;
- Ed25519 keys; and
- public and private PEM strings.

Every helper must check all OpenSSL return values with `ASSERT_*` in the test
body or return an `mw::E<T>`/nullable RAII object that the test asserts. A test
must not accidentally pass because its fixture-generation operation failed.

Test helper formatting should be brought into repository style when touched:
four-space indentation, braces on new lines, no space before parentheses,
and a soft 80-byte line limit.

## Test plan

### Positive regression tests

Retain and, where useful, table-drive these cases:

1. general RSA-2048 signs and verifies with RSA-PSS/SHA-512;
2. general RSA-2048 signs and verifies with RSA v1.5/SHA-256;
3. P-256 signs and verifies with ECDSA/SHA-256;
4. P-384 signs and verifies with ECDSA/SHA-384;
5. Ed25519 signs and verifies with Ed25519;
6. raw HMAC bytes sign and verify with HMAC/SHA-256;
7. generated RSA keys meet the minimum and work with both RSA profiles where
   current tests exercise them;
8. generated Ed25519 keys work with Ed25519; and
9. tampered data or signature under a compatible key returns `false`.

Add a positive RSA-PSS-only case. Generate a PSS-only 2,048-bit key whose
restrictions permit SHA-512, MGF1/SHA-512, and a 64-byte salt, then sign and
verify with `RSA_PSS_SHA512`. This proves that type validation does not reject
all PSS-only keys.

### Incorrect key-type tests

For both signing and verification, cover the cross-family matrix. At minimum:

- RSA algorithm with EC key;
- RSA algorithm with Ed25519 key;
- ECDSA algorithm with RSA key;
- ECDSA algorithm with Ed25519 key;
- Ed25519 algorithm with RSA key;
- Ed25519 algorithm with EC key; and
- RSA v1.5 algorithm with an RSA-PSS-only key.

Each case must assert an error rather than `false`. Where a stable validation
message is specified, assert it through `mw::errorMsg(result.error())`.

HMAC is excluded from the asymmetric cross-family matrix because its key is
raw bytes. Passing PEM text to HMAC is valid raw-byte input under the current
API.

### Incorrect EC curve tests

Test both directions for both operations:

- P-384 key with `ECDSA_P256_SHA256` signing;
- P-384 key with `ECDSA_P256_SHA256` verification;
- P-256 key with `ECDSA_P384_SHA384` signing; and
- P-256 key with `ECDSA_P384_SHA384` verification.

Use signatures produced with the key's actual matching algorithm for the
verification fixtures. This ensures the signature is well-formed and the
failure is specifically the requested algorithm/key incompatibility.

If practical in the existing OpenSSL test environment, add an EC key on a
third curve, such as P-521, and verify it is rejected by both supported ECDSA
profiles. The two-direction tests above remain mandatory.

### Malformed PEM tests

For every asymmetric family or in a table representative of the shared
parsers, test:

- an empty string;
- ordinary non-PEM text;
- a PEM header with invalid base64 or missing footer; and
- a syntactically valid public/private PEM of an incompatible key type.

Malformed signing keys return an error. Malformed verification keys return an
error, not `false`.

Parser-specific malformed cases need not be repeated for every algorithm if
all algorithms use the same two parsing helpers. Compatibility cases must
still cover every family because they exercise post-parse validation.

### Public key used for signing

For RSA, P-256, P-384, and Ed25519:

1. generate a valid key pair;
2. export only the public key with `PEM_write_bio_PUBKEY()`;
3. call `Crypto::sign()` with the matching algorithm; and
4. assert an error and no signature value.

This test proves that a key's algorithm type alone is insufficient for
signing.

### Weak RSA tests

Generate a 1,024-bit general RSA key in test code. Test both public and private
forms with both RSA algorithms:

- RSA-PSS signing rejects the private key;
- RSA-PSS verification rejects the public key;
- RSA v1.5 signing rejects the private key; and
- RSA v1.5 verification rejects the public key.

The verification test should use any nonempty signature bytes because key
validation must fail before signature evaluation. A stronger fixture may
produce a valid weak-key signature directly with OpenSSL, then prove libmw
still rejects it.

Add boundary coverage with a 2,048-bit RSA key in the positive tests. There is
no public API for generating a 2,047-bit key reliably, so 1,024 and 2,048 are
sufficient for this change unless the provider supports an efficient exact
boundary fixture.

### RSA-PSS restriction tests

Generate RSA-PSS-only keys with `EVP_PKEY_CTX_new_id(EVP_PKEY_RSA_PSS,
nullptr)` and the RSA-PSS key-generation controls.

Cover:

1. an unrestricted PSS-only key, which accepts the exact libmw profile;
2. a key restricted compatibly to SHA-512 and MGF1/SHA-512;
3. a key restricted to SHA-256, which is rejected;
4. a key restricted to MGF1/SHA-256, which is rejected;
5. a key with minimum salt length greater than 64, which is rejected; and
6. any PSS-only key used with RSA v1.5, which is rejected.

Run incompatible restriction cases through signing and verification when the
provider can export both forms. At least one case in each operation must prove
that restrictions are enforced before signature processing.

### Unknown enum tests

Add one test per public dispatch point:

- `sign(UNKNOWN_SIGNATURE_ALGORITHM, ...)` returns an error;
- `verifySignature(UNKNOWN_SIGNATURE_ALGORITHM, ...)` returns an error;
- `encrypt(UNKNOWN_ENCRYPTION_ALGORITHM, ...)` returns an error;
- `decrypt(UNKNOWN_ENCRYPTION_ALGORITHM, ...)` returns an error; and
- `generateKeyPair(UNKNOWN_KEY_TYPE)` returns an error.

For signing and verification, supply malformed PEM and assert the unsupported
algorithm message. This proves dispatch precedes parsing and that an unknown
algorithm does not fall through to Ed25519's null-digest behavior.

For key generation, an unknown key type must return no key pair. It must never
generate Ed25519 as the current fallback does.

### Structural key validation tests

Provider APIs do not always make it easy to serialize deliberately invalid
keys. Add such tests only where fixtures can be created without deprecated
low-level mutation APIs. The mandatory malformed, wrong-role, wrong-type,
wrong-curve, weak-RSA, and restricted-PSS cases already exercise the primary
public contract.

If invalid component fixtures are added, assert that public or pairwise checks
produce an error before the operation emits or accepts a signature.

### Test execution

Build and run the crypto target with the repository's sanitizer settings:

```sh
cmake -S . -B build \
    -DLIBMW_BUILD_TESTS=ON \
    -DLIBMW_BUILD_CRYPTO=ON
cmake --build build -j
ctest --test-dir build --output-on-failure
```

If an existing configured build directory is used, run the narrow
`mw-crypto_test` target first, followed by the full test suite. No test should
depend on the text or order of the OpenSSL error queue beyond the stable
libmw validation messages in this design.

## Implementation sequence

1. Add test helpers for explicit RSA sizes, explicit EC groups, and RSA-PSS
   restricted keys.
2. Add failing tests for unknown enum values. This isolates dispatch behavior
   before key validation is refactored.
3. Introduce `SignatureProfile` and replace `getDigestMethod()`.
4. Split raw HMAC creation from public/private PEM parsing.
5. Make key-generation and encryption dispatch exhaustive.
6. Add provider-aware key-family identification.
7. Add RSA modulus and EC curve checks.
8. Add public and pairwise key-component checks.
9. Centralize exact RSA padding, PSS MGF1, and PSS salt configuration.
10. Add wrong-type, wrong-curve, public-for-signing, weak-RSA, malformed-PEM,
    and RSA-PSS restriction tests.
11. Update public API documentation in `includes/mw/crypto.hpp`.
12. Run the crypto tests under AddressSanitizer and UndefinedBehaviorSanitizer,
    then run the complete repository test suite.

Each intermediate commit should compile. In particular, profile lookup and
dispatch should land together so no unknown-algorithm path temporarily maps
to a null digest.

## Review checklist

- Every public enum dispatch has an explicit unknown-value error.
- Unknown values are rejected before OpenSSL allocation or input parsing.
- No unknown signature algorithm can be confused with Ed25519.
- HMAC remains an opaque raw-byte key and preserves current behavior.
- RSA-PSS accepts only RSA or compatible RSA-PSS keys.
- RSA v1.5 rejects RSA-PSS-only keys.
- Both RSA algorithms enforce `MIN_RSA_BITS` for signing and verification.
- Both ECDSA algorithms enforce their exact curve.
- Ed25519 rejects every other key family.
- Signing parses and validates private key material.
- Verification parses and validates public key material.
- Public, pairwise, and operation-configuration return values are checked.
- PSS digest, MGF1 digest, padding, and salt length are explicit.
- No validation error includes key or message material.
- Signature mismatch still returns `false`; key failure returns an error.
- Existing valid signatures and public function signatures remain compatible.
- `CryptoMock` still compiles without an interface change.
- New and touched code follows the repository's naming and brace style.
- Crypto tests and the full suite pass with sanitizers enabled.

## Future work

The later error-handling work should place a complete error-queue boundary
around the new validation calls and distinguish deterministic validation
errors from provider infrastructure failures without leaking sensitive
details.

The input-limit work should cap PEM size before creating a memory BIO and
validate the `size_t`-to-`int` conversion currently required by
`BIO_new_mem_buf()`.

The asymmetric-key-operations work should define configurable RSA generation
limits, public-key derivation, accepted PEM encodings, encrypted private-key
behavior, and provider/library-context policy.

If repeated parsing and pairwise validation become a measured bottleneck, a
future API may introduce an opaque validated-key object. Such an object must
bind the parsed key to its validated algorithm profile and operation role so
that caching cannot bypass this design's checks. The current string API must
remain compatible even if that optimization is added.
