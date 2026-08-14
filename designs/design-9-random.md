# Add secure random byte generation

## Status

Proposed.

This document designs the `Secure Random Generation` work in
`todo-crypto.md`. It adds one public operation to `mw::CryptoInterface`, a
production implementation backed by OpenSSL's private random generator, and a
narrow private seam for deterministic failure testing.

## Context

Libmw consumers need unpredictable bytes for authorization codes, access and
refresh tokens, session identifiers, setup credentials, OAuth `state`, OIDC
`nonce`, PKCE verifiers, password salts, and symmetric keys. These values have
different protocol encodings and lifetimes, but they share one primitive
requirement: the source bytes must come from a cryptographically secure random
number generator and generation failure must be observable.

The crypto module currently generates only one random value directly: the
12-byte AES-GCM IV in `Crypto::encrypt()`. That path calls `RAND_bytes()` and
checks its result, but there is no reusable public operation. Consumers would
otherwise need to call OpenSSL directly, invent platform-specific entropy
handling, or hide non-cryptographic generators behind application helpers.
Those approaches duplicate security-sensitive logic and make deterministic
consumer tests harder.

OpenSSL documents `RAND_bytes()` and `RAND_priv_bytes()` as CSPRNG interfaces.
The private variant is intended for secret values and normally uses a
separate per-thread private DRBG, isolating it from the public DRBG. OpenSSL
also documents that entropy-source failure puts the generator into an error
state in which it refuses to produce output. Every return value must therefore
be checked. See
[`RAND_priv_bytes_ex()`](https://docs.openssl.org/3.5/man3/RAND_bytes/)
and the shared-generator description in
[`EVP_RAND`](https://docs.openssl.org/3.5/man7/EVP_RAND/).

The output is pseudorandom in the cryptographic sense. A DRBG expands secret
seed material obtained from an entropy source into bytes that are
computationally unpredictable to an attacker who does not know its internal
state. The relevant standards background is
[NIST SP 800-90A Revision 1](https://csrc.nist.gov/pubs/sp/800/90/a/r1/final).
The public API delegates DRBG selection, seeding, reseeding, and operating
system integration to OpenSSL rather than reimplementing those mechanisms.

## Goals

The implementation must:

1. Add a public operation that returns exactly the requested number of
   cryptographically secure random bytes.
2. Add the operation to `CryptoInterface`, `Crypto`, and `CryptoMock` with one
   consistent signature.
3. Use OpenSSL's private DRBG through `RAND_priv_bytes_ex()` in production.
4. Require a generator security strength of at least 256 bits.
5. Use the default OpenSSL library context so existing provider configuration
   remains effective.
6. Return an error for every OpenSSL result other than success.
7. Never substitute a clock, process identifier, standard-library PRNG,
   deterministic seed, repeated bytes, or another predictable fallback.
8. Define zero-length generation as a successful empty result without calling
   the backend.
9. Reject requests above
   `mw::crypto_limits::MAX_RANDOM_OUTPUT_SIZE` before allocation or OpenSSL.
10. Generate larger accepted outputs in bounded chunks compatible with common
    DRBG per-request limits.
11. Return no partial value when any chunk fails.
12. Cleanse the complete temporary output allocation before returning a
    generation error.
13. Maintain the OpenSSL error-queue boundary established by
    `design-8-safety.md`.
14. Keep production randomness fixed to OpenSSL while allowing consumer tests
    to substitute `CryptoMock`.
15. Add a private, per-call backend seam that exercises the concrete failure
    path without changing global OpenSSL state.
16. Preserve thread safety by avoiding mutable production state.
17. Add focused tests for size semantics, boundaries, provider failure,
    partial failure, cleansing, mocking, concurrency, and non-repetition.

## Non-goals

This change does not add random integers, ranges, shuffling, UUIDs, token
strings, or protocol encodings. Mapping random bytes into a non-power-of-two
range can introduce modulo bias and needs a separate rejection-sampling
design. Base64url, hexadecimal, UUID, and application token formats likewise
belong in their protocol or encoding layers.

This change does not let production callers inject a callback, deterministic
seed, `EVP_RAND_CTX`, or test provider into `Crypto`. A production object whose
random source can be silently replaced is too easy to misconfigure. Tests of
consumers substitute `CryptoMock`; tests of libmw's failure logic use a private
header that is not installed.

This change does not expose `OSSL_LIB_CTX` or an OpenSSL property query in the
public API. Provider and FIPS-context policy remains under `Platform and
Provider Support` in `todo-crypto.md`. The initial implementation uses the
default library context by passing `nullptr` to `RAND_priv_bytes_ex()`.

This change does not call `RAND_seed()`, `RAND_add()`, `RAND_poll()`, or
`RAND_status()`. OpenSSL automatically seeds its default DRBGs on supported
platforms. The generation call's return value is the authoritative result;
performing a separate status check would not make a later generation call
infallible.

This change does not use `RAND_pseudo_bytes()`. OpenSSL deprecated that API,
and a result that merely appears random is not sufficient for tokens or keys.

This change does not fall back from the private DRBG to the public DRBG or to
an operating-system API. OpenSSL already owns operating-system entropy
integration. If the configured private generator is unsupported or fails,
libmw returns an error.

This change does not retry a failed generation request. Failure can indicate
an unavailable entropy source, a provider error, or a DRBG error state. An
immediate retry could obscure a persistent failure without adding a recovery
mechanism.

This change does not replace the existing AES-GCM IV call. GCM IVs must be
unique but are not secret, and `Crypto::encrypt()` already has the stable
`Failed to generate random IV` error contract. Refactoring that path can be
considered with the later authenticated-encryption work.

This change does not promise secure-memory allocation for successful output.
The returned vector is an ordinary copyable container controlled by the
caller. The later `Binary API and Secret Handling` work must define a threat
model before introducing a secure allocator or non-copyable secret type.

This change does not catch `std::bad_alloc` or convert it into `mw::Error`.
That is consistent with the existing crypto API. Size validation still occurs
before allocation so caller-controlled requests cannot exceed the documented
project limit.

This change does not statistically certify OpenSSL output. Unit tests can
detect obvious integration mistakes, but they cannot establish entropy
quality. OpenSSL's implementation, provider validation, and operating-system
entropy source are the relevant security boundary.

## Terminology

### Entropy source

An entropy source obtains nondeterministic information from the operating
system or another trusted source. Libmw does not access it directly. OpenSSL
uses it to instantiate and reseed its DRBG hierarchy.

### DRBG

A deterministic random bit generator maintains secret internal state and
uses a cryptographic algorithm to produce output that is unpredictable
without that state. Deterministic describes the internal construction, not a
promise that application callers can reproduce output.

### CSPRNG

A cryptographically secure pseudorandom number generator is a practical
random-byte service built from an entropy source and a secure generator. This
document uses CSPRNG when discussing the complete OpenSSL service and DRBG
when discussing its stateful generator component.

### Public and private DRBGs

OpenSSL normally maintains thread-local public and private DRBG instances.
`RAND_bytes_ex()` uses the public instance and `RAND_priv_bytes_ex()` uses the
private instance. Separating them limits the effect of a compromise of public
generator state on secret values generated by the private instance.

### Generator strength and output entropy

The `strength` argument requests a minimum security strength from the DRBG.
This design requests 256 bits. That does not give a short output more entropy
than its length permits: an `n`-byte result has at most `8 * n` bits of
entropy. Consumers remain responsible for requesting enough bytes for their
protocol. For example, RFC 7636 recommends a 32-octet random sequence for a
PKCE verifier; see [`RFC 7636, Section 4.1`][rfc7636].

[rfc7636]: https://www.rfc-editor.org/rfc/rfc7636#section-4.1

### Backend seam

The backend seam is a private function-pointer parameter used only by the
implementation and its unit tests. It is not dependency injection in the
public `Crypto` object and cannot be selected by an ordinary consumer.

## Security model

### Assets

The generated bytes may become:

- bearer tokens;
- session identifiers;
- authorization codes;
- CSRF and OAuth correlation values;
- OIDC nonces;
- PKCE verifier material;
- password salts;
- symmetric keys; or
- input keying material for another operation.

Some values, such as salts and protocol nonces, can later become public.
Others, such as bearer tokens and symmetric keys, must remain secret. The
primitive treats every result as potentially secret and always uses the
private DRBG.

### Threats addressed

The design addresses:

- predictable fallback output after provider failure;
- ignored or misclassified OpenSSL return values;
- unbounded caller-controlled output allocation;
- accidental backend calls for an empty request;
- partially generated output escaping after a later chunk fails;
- failed temporary output remaining in ordinary allocator storage;
- stale OpenSSL errors influencing public error text or escaping the call;
- mutable global test hooks racing with production calls;
- direct OpenSSL dependencies spread across consumers; and
- consumers being unable to substitute deterministic bytes in unit tests.

The general requirement is unguessability, not visual irregularity. A simple
statistical test can pass for a predictable sequence. The distinction is also
emphasized by
[`RFC 4086`](https://datatracker.ietf.org/doc/html/rfc4086).

### Threats not fully addressed

The design cannot protect output after it has been returned to the caller.
Callers can copy, log, serialize, swap, or leak the vector.

The design cannot compensate for a compromised process, malicious OpenSSL
provider, compromised operating system, broken platform entropy source, or an
attacker who can read DRBG state.

The design does not make an undersized request safe. A caller that asks for
four bytes receives four unpredictable bytes, but an online or offline
attacker may still exhaust that 32-bit space.

The design does not prevent repeated calls from exhausting memory or CPU at
the application level. The one-call size cap bounds each allocation; callers
must still apply request-rate and authorization policy.

The design relies on OpenSSL for fork detection, thread-local DRBG management,
automatic reseeding, and entropy acquisition. Libmw does not cache an
`EVP_RAND_CTX` or duplicate OpenSSL's lifecycle logic.

## Public API

### Chosen signature

Add the following pure virtual method to `CryptoInterface`:

```cpp
/// Return cryptographically secure random bytes.
///
/// @param output_size The requested number of output bytes. Zero returns an
/// empty vector. Values above
/// `crypto_limits::MAX_RANDOM_OUTPUT_SIZE` return an error.
/// @return Exactly `output_size` random bytes, or an error if the request is
/// excessive or secure randomness is unavailable.
virtual E<std::vector<std::byte>> randomBytes(
    std::size_t output_size) = 0;
```

Add the matching declaration to `Crypto`:

```cpp
E<std::vector<std::byte>> randomBytes(
    std::size_t output_size) override;
```

Add the matching method to `CryptoMock`:

```cpp
MOCK_METHOD(E<std::vector<std::byte>>, randomBytes,
            (std::size_t output_size), (override));
```

The method name is `randomBytes()` because the return value is raw binary
data, not a formatted token or number. Its class and documentation establish
that the production implementation is cryptographically secure.

### Why `std::vector<std::byte>`

This is a new binary-output API. `std::byte` expresses uninterpreted storage
and does not imply text, character encoding, or arithmetic semantics. That
matches the direction stated in the `Binary API and Secret Handling` section
of `todo-crypto.md`.

The existing signature and KDF operations return
`std::vector<unsigned char>`. Those interfaces are not changed here because a
staged migration is required for existing consumers. OpenSSL accepts an
`unsigned char*`, so the implementation uses one local `reinterpret_cast` at
the backend boundary. Backend representation must not dictate the new public
type.

The result is not a C string. It can contain zero bytes and every other byte
value. No terminator is added, and `output_size` excludes any encoding or
terminator.

### Exact output contract

On success:

- the result has exactly `output_size` elements;
- each element is part of the CSPRNG output;
- no prefix, version, length, or terminator is included; and
- an empty request returns an empty vector.

On error, `E<std::vector<std::byte>>` contains no vector value. A caller must
not continue with a placeholder token, zero-filled key, old value, or
application fallback.

### Zero-length behavior

`randomBytes(0)` succeeds with an empty vector. The implementation does not
call OpenSSL or the injected backend.

This behavior makes generic code simpler and avoids passing an empty vector's
possibly null `data()` pointer to an API whose documentation requires a
non-null output pointer. It also makes failure injection deterministic: a
failing backend cannot make a zero-length request fail because no random bits
are needed.

The operation still creates `OpenSSLErrorBoundary` as its first statement, so
a zero-length public call clears stale OpenSSL diagnostics and returns with an
empty queue like every other public crypto operation.

### Maximum output

The existing public constant remains authoritative:

```cpp
inline constexpr std::size_t MAX_RANDOM_OUTPUT_SIZE =
    std::size_t{1} * 1024 * 1024;
```

Requests from zero through the maximum, inclusive, are accepted. A request of
`MAX_RANDOM_OUTPUT_SIZE + 1` returns `Random output is too large` before
allocation and before any backend call.

The cap is an allocation and abuse boundary, not a recommendation that
applications generate one-megabyte tokens. Most consumers should request
dozens of bytes. Protocol-specific code must choose a length based on its
security and encoding requirements.

## OpenSSL backend selection

### Production call

Production uses:

```cpp
RAND_priv_bytes_ex(nullptr, output, output_size, strength)
```

`nullptr` selects the default OpenSSL library context. This preserves provider
configuration already established by the process and avoids adding a partial
library-context policy only for randomness.

The private API is selected for all results because the primitive can produce
keys and bearer secrets. OpenSSL states that the private DRBG is separate from
the public DRBG in its default architecture. The call is available in OpenSSL
3.0 and later, below the version already required by the Argon2id
implementation.

### Security strength

Every backend call passes a strength of 256. OpenSSL documents that its
default CSPRNG supports 256-bit security when successfully seeded. A provider
that cannot satisfy the requested strength causes generation to fail. Libmw
does not silently lower the request.

The strength value applies to the generator. It does not replace consumer
length policy. A 16-byte result still has at most 128 bits of entropy even
when generated by a 256-bit-strength DRBG.

### Chunking

OpenSSL DRBG implementations expose a `max_request` parameter limiting bytes
per generation request; see the parameter description in
[`EVP_RAND`](https://docs.openssl.org/3.5/man3/EVP_RAND/). The public libmw
limit is larger than common single-request limits, so accepted output is
generated in chunks.

Define a private constant:

```cpp
constexpr std::size_t RANDOM_REQUEST_CHUNK_SIZE =
    std::size_t{64} * 1024;
```

For a nonempty output:

1. Set `offset` to zero.
2. Calculate `remaining` as `output_size - offset`.
3. Set `chunk_size` to the smaller of `remaining` and
   `RANDOM_REQUEST_CHUNK_SIZE`.
4. Call the backend for the range beginning at `output.data() + offset`.
5. Require the backend result to equal one.
6. Add `chunk_size` to `offset` only after success.
7. Repeat until `offset == output_size`.

Subtraction from a validated size avoids overflow. Pointer arithmetic stays
inside the allocated vector. A one-megabyte request uses sixteen 64-KiB
backend calls. A request whose size is not a multiple of the chunk size uses
a shorter final call.

Libmw does not query or modify provider `max_request`. A configured provider
with a smaller supported request can reject a chunk, which is handled as a
normal provider failure. This keeps provider configuration outside the
primitive and avoids mutating a thread-local DRBG.

### Return-value classification

Only a return value of one is success. Zero, negative one, and any other value
are errors. OpenSSL documents zero as failure and negative one as unsupported
for the RAND interfaces. Both cases return the same stable libmw error and no
output.

There is no fallback based on the failure value. In particular, unsupported
private generation does not trigger public generation.

## Error and output safety

### Stable errors

Add two fixed implementation messages:

| Condition | Public message |
| --- | --- |
| `output_size` exceeds the public maximum | `Random output is too large` |
| Backend missing, unsupported, or failed | `Failed to generate random bytes` |

No error includes generated bytes, requested output contents, provider text,
source paths, or raw OpenSSL diagnostics.

### Error-queue boundary

`Crypto::randomBytes()` declares `OpenSSLErrorBoundary` as its first
statement. Provider failures call `openSSLFailure()`, which consumes every
queued OpenSSL error and constructs the fixed message. Successful, empty, and
size-rejection paths return with an empty queue through the boundary
destructor.

The directly testable internal helper also establishes a boundary. This
creates a harmless nested boundary in production and makes the helper's
failure tests independent from prior test state.

### Staged output

The implementation allocates a local vector and fills it chunk by chunk. The
vector is returned only after every chunk succeeds. A failed second or later
chunk therefore cannot return the successful prefix.

Before returning a backend error, cleanse the entire vector allocation with
`OPENSSL_cleanse()`, not only the completed prefix. A provider is not assumed
to leave the failed chunk untouched, and cleansing the entire allocation is
simple because its size is already bounded.

The test-only helper may accept a per-call cleansing function so a unit test
can observe the operation. Production always uses `OPENSSL_cleanse`. The
cleansing callback is not stored globally and is not exposed through
`Crypto`.

Successful output is not cleansed because ownership transfers to the caller.
The caller decides when and how to dispose of it under the ordinary vector
contract.

## Private backend seam

### Requirements

The seam must:

- remain in `crypto/src/crypto_internal.hpp`;
- be absent from installed public headers;
- accept a function pointer per invocation;
- have no mutable global production state;
- execute the exact allocation, validation, chunking, error, and cleansing
  logic used by `Crypto::randomBytes()`;
- allow a test backend to return success, failure, or failure after a
  successful prefix; and
- allow a test to observe failure-time cleansing.

### Internal declarations

Extend `mw::crypto_detail` with:

```cpp
/// A random-byte backend compatible with the private generation helper.
using RandomBytesFunction = int (*)(
    unsigned char*, size_t, unsigned int);

/// Generate random bytes through an explicitly supplied private backend.
E<std::vector<std::byte>> generateRandomBytes(
    size_t output_size,
    RandomBytesFunction random_bytes_function,
    CleanseFunction cleanse_function = OPENSSL_cleanse);
```

`crypto_internal.hpp` must include its own dependencies, including
`error.hpp`, so it remains self-contained. The public build does not expose
the private source directory as an include path.

The internal helper validates that both function pointers are non-null before
allocation. A null internal function pointer returns
`Failed to generate random bytes`; it is an implementation or test misuse,
not a public input case.

### Production adapter

Define a fixed adapter in `crypto.cpp`:

```cpp
int privateRandomBytes(unsigned char* output, size_t output_size,
                       unsigned int strength)
{
    return RAND_priv_bytes_ex(
        nullptr, output, output_size, strength);
}
```

`Crypto::randomBytes()` always passes this adapter. There is no constructor,
setter, environment variable, or global callback that can replace it.

### Why not mutate OpenSSL's private DRBG in tests

OpenSSL exposes lower-level APIs for obtaining or replacing shared DRBG
instances. Using them here would couple tests to provider internals and
thread-local lifecycle. It could also contaminate other tests, require complex
cleanup, and race if a test becomes concurrent.

A per-call function pointer is narrower. It tests libmw's concrete control
flow while leaving the process OpenSSL configuration untouched.

### Why `CryptoMock` is still required

The private seam tests libmw itself. It is not available to applications.
Consumers need to make protocol tests deterministic, for example to assert an
encoded `state` value. They receive a `CryptoInterface` and substitute
`CryptoMock::randomBytes()` with a chosen vector.

Determinism in an explicitly supplied mock is safe because the production
`Crypto` object cannot select that behavior. Applications must not ship a
mock or custom deterministic implementation as their production crypto
dependency.

## Concurrency and lifecycle

`Crypto` gains no data member. Concurrent calls through the same `Crypto`
instance therefore do not share libmw state.

OpenSSL's default public and private DRBGs are thread-local and its primary
DRBG performs internal locking for reseeding. The design calls the high-level
RAND API rather than storing a borrowed `EVP_RAND_CTX*`. OpenSSL specifically
warns against sharing pointers to thread-local DRBG instances across threads;
the architecture is described in
[`EVP_RAND`](https://docs.openssl.org/3.5/man7/EVP_RAND/).

The backend and cleansing function pointers are local parameters. Production
does not mutate them. Test fakes that use counters are responsible for keeping
their own tests single-threaded or synchronizing test state.

The API performs synchronous generation. It does not start a worker thread or
add an asynchronous interface. A one-megabyte maximum keeps a single call
bounded, while the provider controls reseeding and system calls.

## Compatibility contract

Adding a pure virtual method changes the `CryptoInterface` virtual table.
Consumers must rebuild before using the new library. This is an ABI change
even though existing call expressions remain source-compatible.

Ordinary users that instantiate `Crypto` need no source changes. Users that
derive from `CryptoInterface` must implement `randomBytes()`. This is the
intentional compatibility rule already stated in `todo-crypto.md` for new
capabilities.

`CryptoMock` changes with the interface so repository and downstream tests can
compile. Existing configured expectations for other methods remain valid.

No existing operation changes its valid output:

- hash bytes remain unchanged;
- signature formats remain unchanged;
- generated key formats remain unchanged;
- AES-GCM's envelope and IV-generation path remain unchanged; and
- Argon2id output remains unchanged.

The existing `MAX_RANDOM_OUTPUT_SIZE` value remains one MiB. This design begins
enforcing a constant that was introduced by the preceding input-limit work.

## Detailed implementation

### Public operation sequence

`Crypto::randomBytes(output_size)` performs these steps in order:

1. Construct `OpenSSLErrorBoundary` as the first statement.
2. Delegate to `crypto_detail::generateRandomBytes()` with
   `privateRandomBytes` and the default cleanser.
3. Return the helper's `E<std::vector<std::byte>>` unchanged.

Keeping public logic thin ensures the failure-tested helper is the production
path rather than a parallel test-only implementation.

### Internal helper sequence

`crypto_detail::generateRandomBytes()` performs these steps:

1. Construct its own `OpenSSLErrorBoundary`.
2. Reject a null backend or null cleanser with the fixed generation error.
3. Reject `output_size > MAX_RANDOM_OUTPUT_SIZE` with the fixed size error.
4. Allocate a vector containing exactly `output_size` bytes.
5. If `output_size == 0`, return the empty vector without calling the backend.
6. Initialize `offset` to zero.
7. Select the next chunk without overflowing or moving past the vector.
8. Call the backend with the chunk pointer, chunk size, and strength 256.
9. If the result is not one, cleanse all `output_size` bytes, drain OpenSSL's
   queue, and return the fixed generation error.
10. Advance `offset` after success.
11. Repeat until every requested byte has been generated.
12. Return the vector by value.

No public result is constructed from an unvalidated length returned by
OpenSSL; the backend writes into the bounded allocation and reports only
success or failure.

### Overflow analysis

The public maximum is much smaller than `SIZE_MAX`, but the implementation
still uses subtraction-based bounds:

```cpp
const size_t remaining = output_size - offset;
const size_t chunk_size =
    std::min(remaining, RANDOM_REQUEST_CHUNK_SIZE);
```

`offset` begins at zero and advances only by a chunk no larger than
`remaining`. It therefore never exceeds `output_size`. Addition is safe
because `offset + chunk_size <= output_size` is established by construction.

`RAND_priv_bytes_ex()` accepts `size_t`, so this new path contains no
`size_t`-to-`int` conversion.

## Changes by file

### `includes/mw/crypto.hpp`

- Add the documented pure virtual `CryptoInterface::randomBytes()` method.
- Add the matching `Crypto::randomBytes()` override.
- Return `std::vector<std::byte>`.
- Reference `crypto_limits::MAX_RANDOM_OUTPUT_SIZE` in the public comment.
- Document zero-length success and exact-length output.

The header already includes `<cstddef>` and `<vector>`.

### `includes/mw/crypto_mock.hpp`

- Add the matching `MOCK_METHOD` declaration.
- Keep the signature exactly aligned with `CryptoInterface`.

### `crypto/src/crypto_internal.hpp`

- Add `RandomBytesFunction`.
- Add the declaration of `generateRandomBytes()`.
- Reuse the existing `CleanseFunction` type.
- Include `error.hpp` and all standard-library dependencies directly.
- Keep all declarations inside `mw::crypto_detail`.

### `crypto/src/crypto.cpp`

- Add `<algorithm>` if `std::min()` is used.
- Add the fixed size and generation error constants.
- Add `RANDOM_SECURITY_STRENGTH` with value 256.
- Add `RANDOM_REQUEST_CHUNK_SIZE` with value 64 KiB.
- Add the fixed `privateRandomBytes()` adapter.
- Implement `crypto_detail::generateRandomBytes()`.
- Implement `Crypto::randomBytes()` with an error boundary.
- Do not add a global backend pointer or alter `Crypto::encrypt()`.

### `crypto/src/crypto_test.cpp`

- Add internal success and failure backends.
- Add per-test counters or state needed to select the failing call.
- Add a cleansing observer that verifies the complete buffer was presented.
- Add the public and private tests described below.
- Ensure fake OpenSSL errors are cleared after each test.

### `crypto/CMakeLists.txt`

No new source file is required. `crypto_internal.hpp` is already a private
source of both the production and test targets. If implementation is split
into another private file, add it to `SOURCE_FILES` but not to public headers.

### `todo-crypto.md`

After implementation and all tests pass, mark the nine Secure Random
Generation checklist items complete. Add a short compatibility note that the
new pure virtual method requires downstream `CryptoInterface`
implementations to update and all consumers to rebuild.

Do not mark Consumer Integration complete. Replacing randomness in `nsauth`
or another application requires separate consumer changes and protocol tests.

## Test strategy

### Public output-length tests

Call production `Crypto::randomBytes()` with representative nonzero sizes,
including one, 16, 32, and a value crossing the 64-KiB internal chunk
boundary. For each result, assert success and exact vector size.

The test does not assert a particular byte value. Production output is
intentionally nondeterministic.

### Zero-length test

Call public `randomBytes(0)` and assert success with an empty vector.

Call the internal helper with output size zero and a fake backend that counts
calls. Assert that the count remains zero. This proves zero length does not
depend on provider availability and does not pass a null buffer to OpenSSL.

Seed the OpenSSL error queue before one zero-length public call and assert the
queue is empty afterward.

### Limit boundary tests

Cover:

- `MAX_RANDOM_OUTPUT_SIZE - 1`, accepted;
- `MAX_RANDOM_OUTPUT_SIZE`, accepted; and
- `MAX_RANDOM_OUTPUT_SIZE + 1`, rejected with
  `Random output is too large`.

The internal success backend can fill deterministic bytes for the two large
accepted cases, keeping the test independent of operating-system entropy and
allowing exact call-count assertions. The above-limit test must prove the
backend was not called.

At the one-MiB maximum, assert sixteen 64-KiB calls. Immediately below the
maximum, assert that the final call is shorter. This verifies chunking rather
than only allocation behavior.

### Production provider-success test

At least one nonempty test must call the concrete production method, not only
the internal seam. Assert success and the requested length. This proves the
adapter is linked to `RAND_priv_bytes_ex()` in the configured test
environment.

### Provider-failure test

Use an internal backend that:

1. fills the supplied chunk with a recognizable sentinel;
2. raises at least two OpenSSL test errors;
3. returns zero; and
4. records its call count.

Call the exact internal helper used by production. Assert:

- the result contains an error and no vector;
- the message is exactly `Failed to generate random bytes`;
- provider error text and sentinel data do not appear in the message;
- the OpenSSL queue is empty after return;
- the backend was called exactly once; and
- the cleansing observer saw the complete allocation and sentinel data.

Repeat the classification with a backend returning negative one to prove the
unsupported case does not fall back.

### Partial-generation failure test

Request more than one internal chunk. Configure a backend to succeed on the
first call and fail after writing on the second.

Assert the same fixed error, no output value, complete-allocation cleansing,
and exactly two backend calls. This is the important staging test: bytes from
the successful first chunk must not escape.

### Null-backend test

Call the internal helper with a null backend and assert the fixed generation
error with no allocation-dependent behavior. This covers internal misuse and
prevents a future accidental null dereference.

### Mock substitution test

Configure `CryptoMock::randomBytes()` to return a small known
`std::vector<std::byte>`. Invoke it through a `CryptoInterface&` and assert the
known result. This proves consumers can make protocol tests deterministic
without changing production `Crypto`.

### Non-repetition smoke test

Generate two independent 32-byte production results and assert they differ.
The collision probability for ideal independent 256-bit strings is
negligible, so equality is a useful smoke-test failure signal.

This test is not an entropy test, a proof of independence, or validation of
the provider. Do not add frequency, runs, chi-square, or similar statistical
tests to the unit suite. Such tests can be flaky and can accept predictable
generators.

### Concurrency test

Use one `Crypto` instance from multiple asynchronous tasks. Each task requests
32 bytes and asserts success and exact length. The test proves that libmw adds
no shared-state race and that the high-level OpenSSL path works from multiple
threads.

Do not assert a total ordering of calls or inspect OpenSSL's thread-local DRBG
pointers.

### Error-boundary tests

Seed stale OpenSSL errors before a successful nonempty public call and assert
the call succeeds and leaves the queue empty.

The provider-failure fake raises fresh errors and verifies full queue
consumption. The oversized and zero-length paths verify that early returns
also leave the queue empty.

### Sanitizer and build validation

Build and run the crypto target under the repository's AddressSanitizer and
UndefinedBehaviorSanitizer settings, then run the full suite:

```sh
cmake -S . -B build \
    -DLIBMW_BUILD_TESTS=ON \
    -DLIBMW_BUILD_CRYPTO=ON
cmake --build build -j
ctest --test-dir build --output-on-failure
```

If LeakSanitizer cannot run during CMake's GoogleTest discovery in the local
environment, disabling leak detection for discovery must not disable
AddressSanitizer or UndefinedBehaviorSanitizer for the actual test run.

## Consumer guidance

Consumers receive raw bytes and must apply protocol-specific encoding after a
successful result. Encoding does not add entropy. Truncating an encoded value
can remove entropy, and mapping bytes directly into a restricted alphabet can
introduce bias.

Consumers must propagate generation errors and abort creation of the token,
key, state value, or session. They must not use:

- an empty placeholder for a nonempty protocol value;
- an incrementing counter;
- wall-clock time;
- a process or thread identifier;
- `std::rand()` or a default-seeded standard engine;
- a previous successful value; or
- a hard-coded test fixture.

For PKCE, protocol code can request 32 bytes and base64url-encode them without
padding as described by RFC 7636. Other protocols must define their own byte
length and encoding rules in their consumer design.

Consumer tests should inject `CryptoInterface` and configure `CryptoMock`.
They should test both deterministic success and an `mw::Error` result so the
application proves it does not continue after entropy failure.

## Alternatives considered

### `RAND_bytes_ex()` instead of `RAND_priv_bytes_ex()`

The public DRBG is suitable for general random values, but this API also
generates keys and bearer secrets. Always selecting the private DRBG gives one
simple contract and benefits from OpenSSL's public/private state separation.

### `RAND_priv_bytes()` instead of the `_ex` form

The non-`_ex` API takes an `int` length and cannot request a minimum security
strength or select a library context. The `_ex` form takes `size_t`, avoids a
narrowing conversion, and is available in every OpenSSL version compatible
with the current Argon2id requirement.

### Direct `EVP_RAND` ownership

Libmw could fetch, instantiate, own, lock, reseed, and free an
`EVP_RAND_CTX`. That would duplicate behavior already provided by OpenSSL's
high-level thread-local DRBG hierarchy and add lifecycle and provider policy.
The high-level RAND API is the smaller and safer abstraction for this
operation.

### A public injectable callback

A public callback would simplify tests of `Crypto`, but it would also make
predictable production output one configuration mistake away. Consumer tests
already have `CryptoInterface` and `CryptoMock`, so production injection is
unnecessary.

### Replacing OpenSSL global or thread-local DRBGs in tests

This would exercise the high-level function directly but mutate OpenSSL state
outside the tested call. It is harder to clean up, sensitive to provider and
version details, and risky under concurrency. The private per-call seam tests
the same libmw control flow without those side effects.

### Returning `std::vector<unsigned char>`

This would match existing OpenSSL-facing APIs and avoid one cast. It would
also extend a legacy binary representation into a new interface despite the
project's stated `std::byte` direction. The design chooses type safety at the
public boundary and confines the cast to the adapter.

### Returning `std::string`

A string is convenient for token encoding but implies character data and is
easy to pass accidentally to text APIs or logs. Random output is binary and
may contain null bytes, so a byte vector is the clearer contract.

### Returning an empty or zero-filled result on failure

This would keep callers moving but turn an infrastructure failure into
predictable security material. The operation must fail closed.

### Retrying or falling back to an operating-system API

OpenSSL already integrates with operating-system entropy sources. A second
path would create different platform behavior and a new error-handling
surface. Returning the checked failure preserves one auditable trust path.

### Rejecting zero-length requests

Zero is harmless and useful to generic callers. A successful empty result is
also easier to compose than a special error. Skipping the backend avoids any
ambiguity around a null data pointer.

## Implementation sequence

1. Add failing compile-time changes for the new pure virtual method in
   `CryptoInterface`, `Crypto`, and `CryptoMock` together.
2. Add public comments documenting exact length, zero, maximum, and failure.
3. Add the private backend function type and helper declaration.
4. Add fixed errors, strength, chunk size, and the production adapter.
5. Implement validation, zero handling, allocation, chunking, failure
   cleansing, and error draining in the internal helper.
6. Implement the thin public delegate with an error boundary.
7. Add zero, length, and limit-boundary tests.
8. Add fake-backend tests for immediate failure, unsupported return, partial
   failure, complete cleansing, and queue draining.
9. Add mock substitution, production success, non-repetition, and concurrency
   tests.
10. Run the crypto test under sanitizers.
11. Run the complete repository test suite.
12. Update `todo-crypto.md` and add the ABI/rebuild note only after all tests
    pass.

Each intermediate implementation commit must compile. In particular, update
the interface, concrete declaration, mock, and concrete definition together
so no target is temporarily left with an abstract `Crypto` or stale mock.

## Review checklist

- The public method returns `E<std::vector<std::byte>>`.
- `CryptoInterface`, `Crypto`, and `CryptoMock` have identical signatures.
- Every new public declaration has an intention-revealing comment.
- Zero returns an empty success and does not call the backend.
- The existing one-MiB public maximum is enforced before allocation.
- The maximum itself is accepted; maximum plus one is rejected.
- Production calls `RAND_priv_bytes_ex()`, not a weaker or deprecated API.
- Production requests 256-bit generator strength.
- Output is generated in chunks no larger than 64 KiB.
- Only a backend result of one is accepted.
- Unsupported and failure results do not trigger a fallback or retry.
- Failure after a successful prefix returns no vector.
- The complete temporary allocation is cleansed after backend failure.
- Public errors are fixed libmw text and contain no provider diagnostics.
- The OpenSSL error queue is empty on every normal return path.
- The test seam is private, per-call, and absent from `Crypto` constructors.
- No mutable global production hook is introduced.
- No borrowed thread-local `EVP_RAND_CTX*` is stored.
- Concurrent calls share no libmw state.
- AES-GCM IV generation and its stable error remain unchanged.
- Allocation exceptions retain the existing project behavior.
- The non-repetition test is explicitly described as a smoke test only.
- Custom `CryptoInterface` implementations and ABI consumers are told to
  update and rebuild.
- Consumer integration remains tracked separately.
- New code follows repository naming, brace, indentation, and line-length
  conventions.

## Acceptance criteria

The Secure Random Generation todo item is complete when:

1. `CryptoInterface` exposes the documented pure virtual operation.
2. `Crypto` returns exact-length private-DRBG output for every accepted
   nonzero request.
3. `CryptoMock` lets consumer tests return deterministic bytes or an error.
4. Zero returns a successful empty vector without a backend call.
5. Requests above the one-MiB maximum fail before allocation and generation.
6. OpenSSL unsupported and failure returns produce
   `Failed to generate random bytes` and no output.
7. No production fallback or deterministic seed exists.
8. Partial generation is staged and the failed allocation is cleansed.
9. The internal seam proves immediate and later-chunk provider failures.
10. Stale and generated OpenSSL errors do not escape the public boundary.
11. Boundary, mock, concurrency, provider-success, and non-repetition tests
    pass under the repository sanitizer configuration.
12. The full repository test suite passes.
13. `todo-crypto.md` records the interface/ABI compatibility impact and marks
    only the implemented libmw work complete.
