# Harden cryptographic error handling and output safety

## Status

Proposed.

This document designs the `Error Handling and Output Safety` work in
`todo-crypto.md`. It applies to the existing public hashing, signature, key
generation, authenticated-encryption, and Argon2id operations implemented in
`crypto/src/crypto.cpp`.

## Context

`mw::Crypto` delegates cryptographic operations to OpenSSL. OpenSSL reports
most operational failures through two channels:

1. the immediate return value of the function; and
2. a thread-local error queue containing zero or more diagnostic entries.

These channels have different purposes. The return value is part of the
function's control-flow contract and must always be checked. The error queue is
diagnostic state. It can contain multiple entries, can be empty even when an
operation fails, and persists until code removes its entries or clears the
queue. OpenSSL documents that `ERR_get_error()` removes only the earliest
entry and must be called repeatedly to empty the queue. See
[`ERR_get_error()`](https://docs.openssl.org/3.5/man3/ERR_get_error/).

The current implementation calls `ERR_clear_error()` at the start of most
`Crypto` methods. This is useful but incomplete:

- the public hasher operations do not establish the same entry boundary;
- the helper named `getOpenSSLError()` removes only one error entry;
- several failure paths return without consuming errors produced by OpenSSL;
- a successful operation is not explicitly guaranteed to leave the queue
  empty;
- an empty queue produces an unhelpful `error:00000000` suffix;
- provider-specific error text is included in public `mw::Error` messages;
- AES-GCM authentication failure can expose different messages depending on
  the provider and the state of the queue; and
- plaintext written by `EVP_DecryptUpdate()` is not cleansed when
  `EVP_DecryptFinal_ex()` rejects the authentication tag.

The last point is important because authenticated decryption is intentionally
two-phase. OpenSSL may emit candidate plaintext during `EVP_DecryptUpdate()`.
That plaintext is not trustworthy until `EVP_DecryptFinal_ex()` succeeds.
OpenSSL explicitly says that output must not be used when authenticated
decryption fails. See the authenticated-encryption notes in
[`EVP_DecryptFinal_ex()`](https://docs.openssl.org/3.5/man3/EVP_EncryptInit/).
Libmw already avoids returning that plaintext, but the rejected bytes remain
in the temporary allocation until overwritten or released by the allocator.

The current implementation generally stages outputs in local objects and
returns them only after OpenSSL reports success. Key generation also checks
PEM serialization and memory-BIO extraction. The design preserves that useful
structure and makes it a documented, tested rule for every operation.

## Goals

The implementation must:

1. Establish a clean OpenSSL error-queue boundary for every public crypto
   operation implemented by libmw.
2. Clear stale OpenSSL errors before the first OpenSSL call in an operation.
3. Consume the complete relevant OpenSSL error queue after an infrastructure
   failure.
4. Guarantee that a public crypto operation leaves the calling thread's
   OpenSSL error queue empty on every normal return path.
5. Return stable libmw-controlled messages instead of provider-specific error
   text.
6. Preserve `verifySignature()`'s distinction between an invalid signature
   and an operational error.
7. Return one stable public error for AES-GCM authentication failures.
8. Check every OpenSSL return value that can report failure, including size
   queries, serialization, and BIO extraction.
9. Construct public output only from completely successful OpenSSL output.
10. Cleanse all temporary plaintext produced during authenticated decryption
    before releasing its storage.
11. Prevent keys, passwords, plaintext, derived keys, signatures, and other
    caller-supplied byte strings from being copied into public error messages.
12. Preserve all existing public function signatures and valid results.
13. Add tests that prove the externally observable parts of these properties.

## Non-goals

This change does not introduce a new public error type or error category.
Failures continue to use `mw::RuntimeError` through `runtimeError()`. A future
project-wide typed error taxonomy can distinguish authentication,
configuration, and provider failures without being a prerequisite for this
hardening work.

This change does not add logging, tracing, or an OpenSSL diagnostic callback.
Raw queue data can contain provider-controlled strings and source information.
Sending it to a logger would create a second security-sensitive interface with
its own redaction and retention policy. The queue is drained and discarded.

This change does not define the maximum PEM, plaintext, ciphertext, random, or
derived-key sizes. It also does not complete every `size_t`-to-`int`
conversion check. Those requirements belong to the adjacent `Input and
Resource Limits` work. This design does require checking size values returned
by OpenSSL before using them and documenting every existing narrowing
conversion found by the audit.

This change does not add associated authenticated data or alter the serialized
AES-GCM envelope. Those changes belong to `Authenticated Encryption` in
`todo-crypto.md`.

This change does not adopt a general-purpose secure allocator or secure buffer
for the public API. The `Binary API and Secret Handling` work requires a threat
model before making that choice. The private plaintext buffer designed here is
narrow: it exists only to prevent rejected decryption output from remaining in
an ordinary temporary allocation.

This change does not promise that input objects owned by the caller are
cleansed. For example, `decrypt()` receives the key and ciphertext by const
reference and cannot erase the caller's storage. Similarly, successful
plaintext must be returned in the existing `std::string` API.

This change does not catch allocation exceptions or convert them to
`mw::Error`. The current library API and implementation do not define an
out-of-memory recovery contract. RAII cleanup, including plaintext cleansing,
must nevertheless run during stack unwinding.

## Compatibility contract

No declaration in `includes/mw/crypto.hpp` changes. `CryptoInterface`,
`Crypto`, `CryptoMock`, `HasherInterface`, and the concrete hasher classes
retain their current layouts and virtual function sets. Consumers need no
source changes and no rebuild specifically because of a public class layout or
virtual-table change.

For valid inputs, all returned bytes remain identical except where an
operation intentionally uses randomness:

- SHA-256, SHA-256-half, and SHA-512 digest bytes do not change;
- signatures continue to use the currently selected algorithms and formats;
- signature verification still returns `true` for a valid signature;
- signature verification still returns `false` for a cryptographic mismatch;
- generated keys retain their current PEM encodings and defaults;
- AES-256-GCM retains its 12-byte IV, raw ciphertext, and 16-byte tag envelope;
- existing ciphertexts remain decryptable; and
- Argon2id output does not change.

Failure messages are not a compatibility guarantee in the existing public
API. This change intentionally replaces raw OpenSSL suffixes with stable,
libmw-owned messages. Code must not need provider-specific strings to make a
security decision. Consumers that currently parse those strings must migrate
to the operation result and the stable messages documented below.

The error queue is thread-local. Clearing it affects other OpenSSL calls made
earlier on the same thread, which is why the boundary begins exactly when the
public operation begins. A caller must inspect errors from its own direct
OpenSSL call before invoking libmw. It must not expect libmw to preserve stale
diagnostic state across an unrelated public operation.

## Security model

### Assets

The design protects these values from accidental return or error-message
disclosure:

- symmetric keys;
- HMAC keys;
- private-key PEM;
- passwords and salts;
- cleartext passed to encryption;
- candidate plaintext produced before authentication succeeds;
- derived-key bytes; and
- intermediate signatures, ciphertext, and serialized keys that have not
  completed their producing operation.

Public keys, signatures, salts, and ciphertext are not always confidential,
but the implementation treats all caller-supplied bytes uniformly. This rule
avoids requiring the crypto layer to infer an application's confidentiality
policy.

### Threats addressed

The design addresses:

- a stale queue entry being reported as the cause of a later failure;
- one OpenSSL failure leaving queue entries that contaminate later code;
- authentication behavior differing because one provider supplies error text
  and another leaves the queue empty;
- secret input appearing in an error because it was concatenated into a
  message;
- unauthenticated plaintext remaining in reusable heap storage;
- a negative or zero OpenSSL size being converted to a large allocation; and
- a partially written output becoming observable after a failure.

### Threats not fully addressed

Memory cleansing has limited scope. It does not remove copies made by the
allocator, operating system, debugger, crash dump, swap, OpenSSL internals, or
the caller. It also cannot undo compiler-generated copies that exist outside
the owned buffer. This design still cleanses the known libmw allocation because
doing so materially reduces the lifetime of rejected plaintext without
claiming complete memory secrecy.

Public error messages are designed not to contain secrets, but this does not
control logs written by consumers. Applications must not log arguments next to
the returned error.

## Terminology and failure classification

An **input error** means the caller supplied a value that libmw can reject
without depending on an OpenSSL operation. Examples include an unknown enum,
an AES key with the wrong byte length, and an envelope shorter than the fixed
IV-plus-tag overhead.

An **authentication mismatch** means cryptographic verification completed and
the supplied authenticator did not validate. Signature APIs represent an
ordinary mismatch as `false`. AES-GCM decryption cannot return a boolean, so it
returns a stable `mw::Error` and no plaintext.

An **infrastructure failure** means the requested operation could not be
performed, for example because a context allocation, provider fetch,
initialization, serialization, random generation, or key derivation failed.
Infrastructure failures return stable `mw::Error` messages and consume all
OpenSSL error entries created within the operation.

A **complete output** is an output whose final producing OpenSSL call has
succeeded and whose reported length has been validated. Bytes written during a
failed operation are temporary state, not partial public output.

## Design overview

The implementation adds three private mechanisms:

1. `OpenSSLErrorBoundary` clears the queue on entry and ensures it is empty on
   exit.
2. `openSSLFailure()` consumes the complete queue and creates a fixed public
   error without copying queue text.
3. `PlaintextBuffer` owns and cleanses the temporary AES-GCM plaintext.

The implementation also performs a line-by-line audit of every OpenSSL call.
Each call is assigned an explicit success predicate. Output is staged in an
RAII-owned local object, validated, and moved or copied to the public result
only after the final success predicate passes.

These helpers belong to the crypto implementation. They are not declarations
in `includes/mw/crypto.hpp` and are not available to consumers.

## OpenSSL error-queue boundary

### Required invariant

For every libmw public crypto implementation:

1. the queue is cleared before validating or invoking OpenSSL;
2. no control-flow decision depends on a stale queue entry;
3. an infrastructure-failure helper drains every current entry;
4. a mismatch path discards any diagnostic entries associated with the
   mismatch; and
5. the queue is empty immediately after the public method returns.

OpenSSL documents that `ERR_clear_error()` empties the current thread's queue.
See [`ERR_clear_error()`](https://docs.openssl.org/3.5/man3/ERR_clear_error/).
Because the queue is thread-local, simultaneous operations on different
threads do not clear each other's queues.

### `OpenSSLErrorBoundary`

Add a non-copyable private RAII type in `crypto/src/crypto.cpp`:

```cpp
class OpenSSLErrorBoundary
{
public:
    OpenSSLErrorBoundary()
    {
        ERR_clear_error();
    }

    ~OpenSSLErrorBoundary()
    {
        ERR_clear_error();
    }

    OpenSSLErrorBoundary(const OpenSSLErrorBoundary&) = delete;
    OpenSSLErrorBoundary& operator=(const OpenSSLErrorBoundary&) = delete;
};
```

The exact class name may vary, but both constructor and destructor behavior are
required. The destructor is a defense-in-depth backstop. Failure paths still
drain the queue explicitly through `openSSLFailure()` so the implementation
meets the requirement to consume the complete relevant queue rather than
merely relying on cleanup at scope exit.

Declare an instance as the first statement of each public implementation that
can invoke OpenSSL, before enum validation or other early returns. This
ordering makes the boundary uniform and avoids a future edit accidentally
placing an OpenSSL call before the clear.

The boundary is required in:

- `HasherInterface::hashToHexStr()`;
- `SHA256Hasher::hashToBytes()`;
- `SHA512Hasher::hashToBytes()`;
- `SHA256HalfHasher::hashToBytes()`;
- `Crypto::verifySignature()`;
- `Crypto::sign()`;
- `Crypto::generateKeyPair()`;
- `Crypto::encrypt()`;
- `Crypto::decrypt()`; and
- `Crypto::deriveKeyArgon2id()`.

Some of these functions delegate to another public implementation, creating a
nested boundary. Nested clearing is safe because the outer function has no
pending OpenSSL diagnostic that it needs after making the delegated call. The
benefit is that every public function maintains its contract independently.
This matters for `hashToHexStr()`, whose virtual `hashToBytes()` call may be
implemented by a consumer rather than by libmw.

### Complete queue consumption

Replace `getOpenSSLError()` with a helper that discards every entry:

```cpp
void drainOpenSSLErrors() noexcept
{
    while(ERR_get_error() != 0)
    {}
}

Error openSSLFailure(std::string_view public_message)
{
    drainOpenSSLErrors();
    return runtimeError(public_message);
}
```

`ERR_get_error()` is used instead of `ERR_peek_error()` because peeking does
not remove entries. The loop continues until zero, which OpenSSL defines as an
empty queue. The helper does not call `ERR_error_string()`,
`ERR_get_error_all()`, or append provider data to the public message.

The argument to `openSSLFailure()` must be a fixed string literal selected by
libmw. It must never be built from a key, password, plaintext, ciphertext,
signature, PEM input, OpenSSL error data, file path, provider name, or property
query.

Use `drainOpenSSLErrors()` directly on mismatch paths that return `false` or a
fixed authentication error. This prevents an expected mismatch from leaving
diagnostic entries even if a provider chose to enqueue them.

### Why raw OpenSSL errors are not returned

OpenSSL error strings are useful during development but are not a stable API:

- providers can choose different wording;
- the queue can legitimately be empty;
- one failure can enqueue multiple entries;
- source filenames and provider-supplied auxiliary data can appear in richer
  error APIs; and
- strings can change across OpenSSL versions.

The public error communicates which libmw operation failed. It does not expose
the provider's internal explanation. This gives callers deterministic behavior
and creates a simple non-disclosure rule that can be tested.

## Stable public errors

The following table defines the new messages for OpenSSL-backed failures.
Existing deterministic validation messages introduced by
`design-7-validation.md` remain unchanged.

| Failure point | Public message |
| --- | --- |
| Digest context allocation | `Failed to create hash context` |
| Digest initialization | `Failed to initialize hasher` |
| Digest update | `Failed to update hash` |
| Digest size query or finalization | `Failed to finalize hash` |
| HMAC key creation | `Failed to create HMAC key` |
| Public PEM parsing | `Failed to load public key` |
| Private PEM parsing | `Failed to load private key` |
| Signature context allocation | `Failed to create signature context` |
| Signature initialization | `Failed to initialize signature operation` |
| Signature production | `Failed to create signature` |
| Serious verification failure | `Signature verification failed` |
| Key-validation context failure | `Failed to validate key` |
| Key-generation context failure | `Failed to create key generation context` |
| Key-generation initialization | `Failed to initialize key generation` |
| Key generation | `Failed to generate key` |
| Public-key serialization or extraction | `Failed to serialize public key` |
| Private-key serialization or extraction | `Failed to serialize private key` |
| IV generation | `Failed to generate random IV` |
| Encryption context or operation | `Encryption failed` |
| Decryption context or pre-final operation | `Decryption failed` |
| GCM final authentication failure | `Ciphertext authentication failed` |
| Argon2id fetch or context allocation | `Argon2id is unavailable` |
| Argon2id derivation | `Argon2id derivation failed` |

The implementation should use named `constexpr std::string_view` constants
for messages reused by multiple paths, especially
`Ciphertext authentication failed`. Single-use messages may remain literals.
The constants are private to the translation unit.

An input error remains more specific when it is decided before an OpenSSL
operation. For example:

- an AES key whose size is not 32 bytes returns
  `Invalid key length for AES-256`;
- an envelope shorter than 28 bytes returns `Ciphertext too short`; and
- an unknown enum returns its existing `Unsupported ...` message.

A wrong 32-byte key, modified IV, modified ciphertext, or modified tag reaches
GCM finalization and returns `Ciphertext authentication failed`. These cases
must not expose whether any candidate plaintext was produced or whether the
OpenSSL queue was empty.

## Signature verification semantics

`Crypto::verifySignature()` retains its `E<bool>` contract:

- `true` means the signature is valid;
- `false` means OpenSSL classified the final signature check as a mismatch;
- `mw::Error` means libmw could not perform verification reliably.

For `EVP_DigestVerify()` and `EVP_DigestVerifyFinal()`, handle the result as
follows:

1. `1`: drain any unexpected queue entries defensively and return `true`.
2. `0`: drain the queue and return `false`.
3. any other value: drain the queue through `openSSLFailure()` and return
   `Signature verification failed`.

OpenSSL documents that zero includes data mismatch and invalid signature form,
while other values indicate a more serious error and can sometimes also
represent invalid form. See
[`EVP_DigestVerify()`](https://docs.openssl.org/3.5/man3/EVP_DigestVerifyInit/).
Libmw follows the documented return-value distinction rather than using queue
presence as a classifier. Queue presence is provider-dependent and therefore
cannot define the public result.

HMAC verification computes an expected MAC and compares equal-length values
with `CRYPTO_memcmp()`. A length mismatch or byte mismatch returns `false` and
leaves no partial output. Failure to compute the expected MAC is an
infrastructure error with a fixed message.

## Authenticated-decryption output safety

### Required invariant

No byte written by `EVP_DecryptUpdate()` may become public until
`EVP_DecryptFinal_ex()` returns success. The temporary allocation must be
cleansed whether decryption succeeds, authentication fails, a later OpenSSL
setup call fails, or C++ stack unwinding occurs.

### `PlaintextBuffer`

Add a private owning type. It contains a `std::vector<unsigned char>` and
cleanses the vector's entire allocated logical region in its destructor:

```cpp
class PlaintextBuffer
{
public:
    explicit PlaintextBuffer(size_t size)
            : bytes(size)
    {}

    ~PlaintextBuffer()
    {
        if(!bytes.empty())
        {
            OPENSSL_cleanse(bytes.data(), bytes.size());
        }
    }

    PlaintextBuffer(const PlaintextBuffer&) = delete;
    PlaintextBuffer& operator=(const PlaintextBuffer&) = delete;
    PlaintextBuffer(PlaintextBuffer&&) = delete;
    PlaintextBuffer& operator=(PlaintextBuffer&&) = delete;

    unsigned char* data()
    {
        return bytes.data();
    }

    size_t size() const
    {
        return bytes.size();
    }

private:
    std::vector<unsigned char> bytes;
};
```

The actual implementation may provide additional checked accessors, but it
must not expose ownership or permit copying. Deleting move operations keeps the
destructor associated with the same allocation and avoids subtle questions
about moved-from vector capacity.

OpenSSL itself uses `OPENSSL_cleanse()` when explicit plaintext cleansing is
requested in its SSL layer and notes that applications remain responsible for
their own buffers. See
[`SSL_OP_CLEANSE_PLAINTEXT`][openssl-cleanse].

The wrapper cleanses on successful decryption too. On success, construct the
returned `std::string` from the authenticated prefix first. The local wrapper
then cleanses its redundant copy at scope exit. The returned string remains
available to the caller as required by the public API.

Do not call `resize()` before cleansing. Shrinking a vector changes its
logical size and could leave bytes beyond the new end uncleansed. Keep the
original allocation length in the wrapper, track the authenticated output
length separately, copy only that prefix to the result, and let the destructor
cleanse the full original length.

### Decryption sequence

`Crypto::decrypt()` performs these steps in order:

1. Construct `OpenSSLErrorBoundary`.
2. Validate the encryption enum.
3. Validate the 32-byte key length.
4. Validate that the envelope is at least 28 bytes.
5. Derive non-owning pointers to the IV, ciphertext, and tag.
6. Create and initialize the cipher context.
7. Allocate `PlaintextBuffer` large enough for the documented EVP output.
8. Pass the ciphertext to `EVP_DecryptUpdate()` and record its output length.
9. Set the expected GCM tag and check the control-call return value.
10. Call `EVP_DecryptFinal_ex()` into the unused suffix of the buffer.
11. If finalization does not return a positive value, drain the queue and
    return `Ciphertext authentication failed`. The buffer destructor cleanses
    all candidate plaintext.
12. Validate the two returned lengths before adding them.
13. Construct the public `std::string` from exactly the authenticated prefix.
14. Return the string. The local buffer is cleansed during scope exit.

The code must never build the return string before step 10 succeeds.

## Output staging rules

Every operation follows these rules:

1. Allocate output into an RAII-owned local object.
2. Pass only that local storage to OpenSSL.
3. Check the immediate OpenSSL return value.
4. Validate every length written by OpenSSL before resizing or indexing.
5. Perform all remaining finalization and serialization steps.
6. Return or aggregate output only after all producing steps succeed.

Specific applications are:

- Hashing allocates from a validated digest size and resizes only after
  `EVP_DigestFinal_ex()` succeeds and reports a length within capacity.
- Signing obtains the required signature length, allocates locally, performs
  the second call, validates the final length, and then returns the vector.
- Key generation wraps the raw `EVP_PKEY*` immediately after the keygen call,
  even on an unusual failure that also supplied a pointer. Public and private
  PEM strings remain local until both serializations succeed, after which the
  `KeyPair` is constructed.
- Encryption keeps IV, ciphertext, and tag local until finalization and tag
  extraction both succeed. Only then is the envelope assembled.
- Decryption uses `PlaintextBuffer` and creates a public string only after tag
  verification.
- Argon2id derives into a local vector and returns it only after
  `EVP_KDF_derive()` succeeds.

An `E<T>` that contains an error cannot simultaneously contain a `T`, so the
public return type already prevents direct exposure of a partial value. These
staging rules prevent partial bytes from being copied into some other public
object before the error is selected.

## OpenSSL return-value audit

The implementation change must audit every OpenSSL call in
`crypto/src/crypto.cpp`, not only the calls currently suspected of being
wrong. Record each call against the following required predicate.

| API family | Required success predicate |
| --- | --- |
| `EVP_*_CTX_new*`, `BIO_new*`, `EVP_KDF_fetch` | pointer is not null |
| `EVP_DigestInit*`, update, and final calls | return value is positive |
| `EVP_MD_get_size()` | returned size is positive before conversion |
| `EVP_PKEY_new_mac_key()` | pointer is not null |
| `PEM_read_bio_*()` | returned key pointer is not null |
| `EVP_PKEY_is_a()` | `1` is a match; `0` is not a match |
| `EVP_PKEY_get_bits()` | value is positive before policy comparison |
| `EVP_PKEY_get_group_name()` | return is `1`; length and NUL are validated |
| `OBJ_txt2nid()` | result is not `NID_undef` before comparison |
| `EVP_PKEY_public_check()` | `1` valid, `0` invalid, negative operational |
| `EVP_PKEY_pairwise_check()` | `1` valid, `0` invalid, negative operational |
| RSA context setters | return value is positive |
| `EVP_DigestSign*()` | return value is positive and output length fits |
| `EVP_DigestVerify*()` | classified exactly as described above |
| `EVP_PKEY_keygen*()` | return positive and produced pointer is not null |
| `PEM_write_bio_*()` | return value is `1` |
| `BIO_get_mem_data()` | length positive and borrowed pointer non-null |
| `RAND_bytes()` | return value is `1` |
| cipher initialization and update | return value is positive |
| `EVP_CIPHER_CTX_ctrl()` | return value is positive |
| `EVP_EncryptFinal_ex()` | return value is positive |
| `EVP_DecryptFinal_ex()` for GCM | positive means authenticated |
| `EVP_KDF_derive()` | return value is positive |

OpenSSL documents that a memory BIO returns a borrowed pointer and the amount
of available data through `BIO_get_mem_data()`. See
[`BIO_s_mem()`](https://docs.openssl.org/3.5/man3/BIO_s_mem/). The pointer must
be copied before the BIO is destroyed, and ownership must never be transferred
or freed by libmw.

For length-query APIs, validate both the initial size and the final reported
size. The final size must not exceed the capacity passed to OpenSSL. OpenSSL's
key-size documentation emphasizes that preliminary sizes can be upper bounds
and that the producing operation's returned length is authoritative. See
[`EVP_PKEY_get_size()`](https://docs.openssl.org/3.5/man3/EVP_PKEY_get_size/).

Free functions such as `EVP_PKEY_free()` and `BIO_free()` do not all report
actionable failures. RAII deleters should call the documented free operation;
the audit does not invent checks for `void` functions.

### Relationship to input and resource limits

The audit will find existing narrowing conversions such as PEM length and
plaintext length passed to APIs taking `int`. Each occurrence must be listed in
the implementation change or its review notes. The subsequent limits design
will add public maximums and reject values above `INT_MAX` or a lower project
limit before conversion.

This change must not add a new unchecked narrowing conversion. Where a return
value itself can be invalid independently of resource limits, such as a
negative digest size, this change fixes it immediately.

## Secret-safe error construction

All crypto errors must be constructed from fixed libmw text. The following
patterns are forbidden:

```cpp
runtimeError("Failed for key: " + key);
runtimeError("Failed for input: " + clear_content);
runtimeError(ERR_error_string(ERR_get_error(), nullptr));
runtimeError(provider_supplied_data);
```

It is acceptable to include non-secret public enum names or numeric policy
limits in a future error if those values are generated by libmw rather than
copied from arbitrary input. This change should retain the current concise
messages and avoid adding formatting code.

Do not include PEM parsing positions, password lengths, plaintext prefixes,
or derived-key lengths in provider-failure errors. Even metadata can be
sensitive in some applications, and none of it is necessary to satisfy the
public contract.

The implementation must remove `getOpenSSLError()` entirely. Keeping an unused
raw-error helper makes future accidental disclosure too easy.

## Detailed changes by file

### `includes/mw/crypto.hpp`

No signatures or layouts change.

Update existing public comments where needed to state:

- invalid signatures return `false` while operational failures return an
  error;
- AES-GCM authentication failure returns an error and no plaintext;
- public error messages do not include caller-supplied key or content bytes;
  and
- rejected plaintext is cleared from libmw's temporary output buffer.

Do not promise cleansing of caller-owned inputs or the successfully returned
`std::string`.

### `crypto/src/crypto.cpp`

Add the private boundary, drain, stable-error, and plaintext-buffer helpers.
Remove `getOpenSSLError()` and every `ERR_error_string()` call.

Place a boundary at the beginning of every public operation listed above.
Refactor failures to use stable messages and explicit draining. Refactor
decryption to use the cleansing buffer. Complete the return-value audit and
validate output lengths before conversion, pointer arithmetic, resizing, or
construction of a public result.

Keep all OpenSSL resources RAII-owned with `std::unique_ptr`. Do not introduce
manual cleanup branches.

### `crypto/src/crypto_internal.hpp`

Create this private header only if direct unit testing of `PlaintextBuffer`
requires it. If created, it belongs to `mw::crypto_detail`, is included only by
the crypto implementation and crypto tests, and is not installed or added to
the public include directory.

The header may allow injection of a cleansing function into
`PlaintextBuffer` solely so a unit test can observe the destructor call. The
production default must always be `OPENSSL_cleanse`. The injection point must
not be reachable through `Crypto`, must not be mutable global state, and must
not affect concurrent production operations.

One acceptable constructor shape is:

```cpp
using CleanseFunction = void (*)(void*, size_t);

explicit PlaintextBuffer(
    size_t size, CleanseFunction cleanse_function = OPENSSL_cleanse);
```

The function pointer is stored per buffer. Tests can construct the internal
buffer with an observer; production decryption omits the second argument.

### `crypto/CMakeLists.txt`

If `crypto_internal.hpp` is created, add it only to the crypto target's private
source list as appropriate. Do not install it and do not expose its directory
through a public include path.

### `crypto/src/crypto_test.cpp`

Add the tests described below. Test helpers that call OpenSSL directly must
clean up their own queues so one test cannot contaminate another test.

### `todo-crypto.md`

After implementation and all tests pass, mark the seven `Error Handling and
Output Safety` items complete. Do not mark `Input and Resource Limits`
complete as part of this work.

## Test strategy

### Error-boundary tests

Use `ERR_raise(ERR_LIB_USER, reason)` or the supported equivalent to place at
least two sentinel entries on the current thread's queue. Then invoke each
operation family with a successful input and assert:

1. the operation succeeds; and
2. `ERR_peek_error()` is zero after return.

At minimum, cover hashing, signing or verification, key generation,
encryption and decryption, and Argon2id. These tests prove that stale entries
are cleared and do not alter successful behavior.

Add failure tests that naturally cause OpenSSL to enqueue multiple errors,
such as malformed PEM. Assert that:

1. the result is an error;
2. the exact public message is the stable libmw message;
3. it contains neither `error:` nor provider text; and
4. `ERR_peek_error()` is zero after return.

Do not assert the original number or contents of provider queue entries. Those
details are not portable.

### Authentication tests

Generate one valid AES-GCM envelope. Independently modify:

- one IV byte;
- one ciphertext byte when ciphertext is non-empty;
- one tag byte; and
- the 32-byte key while preserving its length.

For every case, assert the exact message
`Ciphertext authentication failed`, no plaintext value, and an empty OpenSSL
queue. Seed the queue before at least one case to prove stale diagnostics do
not change the message.

Keep separate structural-input tests for a key of the wrong length and an
envelope shorter than 28 bytes. They should retain their deterministic input
errors.

For every signature algorithm, verify a signature against modified data and
assert `false` with an empty queue. Add malformed signature encodings for
ECDSA and Ed25519. Assert `false` when OpenSSL returns zero, or the exact stable
`Signature verification failed` error when it reports a serious failure. The
test must not branch on provider error text.

### Plaintext-cleansing tests

If the internal header seam is used, construct a `PlaintextBuffer` with a test
cleanse function that records:

- the address passed to it;
- the length passed to it; and
- whether all bytes were still available to be overwritten.

Fill the buffer with a nonzero sentinel, destroy it, and assert that the
cleanse function was called exactly once for the original full length. Repeat
through an early return or exception-unwinding helper to prove RAII cleanup.

The integration-level tampered-ciphertext test proves that `decrypt()` uses the
failure path and returns no plaintext. Code review and the direct wrapper test
together prove that the owned candidate buffer is cleansed. Do not attempt to
read a freed allocation; doing so would be undefined behavior and an invalid
test.

### Partial-output tests

Exercise failures after output production has begun where practical:

- malformed or incompatible keys during signing;
- failed private-key parsing after a valid public-key-related test setup;
- GCM tag failure after `EVP_DecryptUpdate()`;
- malformed or unavailable Argon2id parameters; and
- unknown algorithms before allocation.

For each public `E<T>`, assert that it contains an error. C++ `std::expected`
then guarantees that `T` is not active. For key generation and serialization
failure paths that cannot be triggered through supported providers, rely on
the staging invariant and sanitizer-backed tests rather than adding a broad
production backend abstraction solely for fault injection.

### Secret-nondisclosure tests

Use distinctive marker strings for a malformed private key, HMAC key,
password, salt, plaintext, and ciphertext. Trigger applicable failures and
assert that `errorMsg()` contains none of the marker strings.

Also assert that public errors do not contain:

- `BEGIN PRIVATE KEY`;
- `BEGIN PUBLIC KEY`;
- `error:` from `ERR_error_string()`;
- the test password;
- the test plaintext; or
- a hex or base64 encoding of the complete test secret.

These tests are regression guards, not proof against every possible encoding.
The primary guarantee comes from constructing messages exclusively from fixed
libmw literals.

### Return-value and length tests

Add a digest regression test proving that SHA-256 and SHA-512 produce their
documented lengths. Existing key-generation tests must continue to prove that
both public and private PEM strings are non-empty and parseable.

Where a provider failure can be induced without global process mutation, add a
test for the stable infrastructure message and empty queue. Avoid tests that
unload the process-wide default provider while other tests may execute in
parallel. Provider availability and explicit `OSSL_LIB_CTX` injection belong
to the later platform/provider work.

### Concurrency tests

Retain the stateless hasher concurrency tests. Error boundaries use only the
calling thread's OpenSSL queue and introduce no shared mutable state.

If the plaintext-buffer test seam stores a function pointer, it must be stored
per instance. Do not use a global callback, because a global would add a data
race and make concurrent decryption behavior test-dependent.

### Build and sanitizer validation

Build and run `mw-crypto_test` with the repository's AddressSanitizer and
UndefinedBehaviorSanitizer settings. Then run the full configured test suite.
No test may depend on test order or leave an OpenSSL queue entry for a later
test.

## Implementation sequence

Implement in this order:

1. Add `drainOpenSSLErrors()` and `OpenSSLErrorBoundary`.
2. Add boundaries to all public operations without otherwise changing their
   behavior.
3. Add queue-isolation tests for successful operations.
4. Replace `getOpenSSLError()` with fixed messages and complete draining.
5. Add stable-message and queue-empty failure tests.
6. Define `PlaintextBuffer`, including the narrow internal test seam if
   needed.
7. Refactor AES-GCM decryption to stage candidate plaintext in the wrapper.
8. Add authentication and cleansing tests.
9. Audit every OpenSSL call and apply its explicit success predicate.
10. Validate all OpenSSL-produced lengths before allocations and output
    construction.
11. Add partial-output and secret-nondisclosure tests.
12. Update public documentation.
13. Run crypto and full-suite tests under the configured sanitizers.
14. Mark only the completed `Error Handling and Output Safety` checklist
    entries in `todo-crypto.md`.

This order makes queue behavior deterministic before failure messages and
decryption are refactored. It also keeps each review step narrow enough to
identify whether a regression came from boundary management, classification,
cleansing, or return-value handling.

## Review checklist

The implementation is complete only when reviewers can answer yes to every
question:

- Does every public crypto implementation create an error boundary first?
- Is the error queue empty after every success, mismatch, input error, and
  infrastructure error tested?
- Does the infrastructure helper consume until `ERR_get_error()` returns
  zero?
- Has `getOpenSSLError()` and all `ERR_error_string()` use been removed from
  the crypto implementation?
- Are all public provider-failure messages fixed libmw literals?
- Does signature verification use the EVP return value, not queue presence,
  to distinguish mismatch from serious failure?
- Do all GCM final authentication failures return the same message?
- Is candidate plaintext owned by a non-copyable cleansing wrapper before the
  first decrypt update?
- Is the wrapper's original full length cleansed on success and every failure?
- Is public plaintext constructed only after GCM finalization succeeds?
- Is every OpenSSL return value checked according to its documented contract?
- Are negative or zero sizes rejected before conversion or allocation?
- Are final output lengths checked against supplied capacity?
- Are key-pair and encryption envelopes assembled only after every component
  succeeds?
- Do tests prove that distinctive secret markers never appear in errors?
- Do tests avoid reading freed memory or relying on provider-specific queue
  text?
- Are no public signatures, class layouts, or ciphertext formats changed?
- Does the full sanitizer-backed test suite pass?

## Acceptance criteria

The work is accepted when:

1. All seven `Error Handling and Output Safety` items in `todo-crypto.md` are
   implemented and checked.
2. Every libmw public crypto operation begins and ends with an empty OpenSSL
   error queue on the calling thread.
3. Infrastructure failures consume all queue entries and return a fixed,
   secret-free libmw message.
4. Invalid signatures retain the documented `E<bool>` behavior without
   exposing provider error text.
5. All valid-length AES-GCM authentication failures return
   `Ciphertext authentication failed` and no plaintext.
6. Temporary decryption output is cleansed over its full original length on
   success and failure.
7. Every OpenSSL return value in `crypto/src/crypto.cpp` has an explicit,
   documented success predicate and is checked.
8. No failure exposes a partially constructed digest, signature, key pair,
   ciphertext envelope, plaintext, or derived key.
9. Public errors contain no caller-supplied secret markers or raw OpenSSL
   diagnostic strings.
10. Existing valid vectors, ciphertext compatibility, public interfaces, and
    consumer call sites remain unchanged.
11. Crypto tests and the full configured test suite pass with the repository's
    sanitizer configuration.

[openssl-cleanse]: https://docs.openssl.org/3.5/man3/SSL_CTX_set_options/
