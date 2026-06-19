# Make libmw errors extensible with type erasure

## Context

`libmw` uses `mw::E<T>` as the public return type for operations that can fail.
`mw::E<T>` is currently an alias for `std::expected<T, mw::Error>` in
`includes/mw/error.hpp`.

The current `mw::Error` type is a closed `std::variant`:

```cpp
using Error = std::variant<RuntimeError, HTTPError, PolicyError>;
```

This is simple and efficient, but it means the library author must list every
possible error type in `error.hpp`. A user of `libmw` cannot add a domain error
such as `ValidationError`, `AuthError`, or `RateLimitError` unless they modify
the library itself. That is the central limitation to fix.

The existing public error types are:

- `RuntimeError`: a generic error with `std::string msg`.
- `HTTPError`: an HTTP-specific error with `int code` and `std::string msg`.
- `PolicyError`: a caller-policy rejection with `std::string msg`.

The existing helper functions are:

- `runtimeError(std::string_view msg)`.
- `httpError(int code, std::string_view msg)`.
- `policyError(std::string_view msg)`.
- `errorMsg(const Error& e)`.

The rest of the codebase assumes these helpers exist. Some call sites also
inspect the concrete variant alternative with `std::holds_alternative<T>()`,
`std::get<T>()`, or `std::visit()`. Those call sites must be migrated because
they depend directly on `std::variant`.

Useful C++ references:

- [`std::expected`](https://en.cppreference.com/w/cpp/utility/expected)
- [`std::unique_ptr`](https://en.cppreference.com/w/cpp/memory/unique_ptr)
- [`std::type_info`](https://en.cppreference.com/w/cpp/types/type_info)
- [Type erasure overview](https://en.wikibooks.org/wiki/More_C%2B%2B_Idioms/Type_Erasure)

## Goal

Make `mw::Error` an open error container so callers can put their own concrete
error structs inside `mw::E<T>` without changing `libmw`.

The new design must preserve the important parts of the current API:

- Library code still returns `mw::E<T>`.
- Existing helper constructors still work.
- `errorMsg(error)` still returns a message.
- Existing built-in error types remain ordinary structs.
- Callers can still distinguish `HTTPError`, `PolicyError`, and other concrete
  types when they need type-specific behavior.

## Non-goals

Do not introduce exceptions. This library uses `std::expected` for explicit
error propagation, and this design keeps that model.

Do not make every function template over the error type. For example, avoid
changing the alias to `template<class T, class ErrorType> using E = ...`.
That looks flexible, but it spreads error-type choices across every API
boundary. If two components choose different error types, their `E<T>` results
become hard to compose. A single open `mw::Error` type keeps composition simple.

Do not build a runtime registry of error types. Error inspection should be local
and type-safe through C++ templates, not through string names or global mutable
state.

## Required approach

Replace the `std::variant` alias with a real `mw::Error` class that performs
type erasure.

Type erasure means `mw::Error` stores "some concrete error type" while exposing
only the operations that all stored errors must support. The public `Error`
object does not know at compile time whether it contains `RuntimeError`,
`HTTPError`, `PolicyError`, or a user-defined type. Internally, a small virtual
interface performs operations such as copying, reading the message, and checking
the concrete type.

The public shape should be:

```cpp
class Error
{
public:
    /// Construct an error from any supported concrete error type.
    template<class T>
    Error(T error);

    /// Copy an error while preserving the concrete stored type.
    Error(const Error& other);

    /// Move an error.
    Error(Error&& other) noexcept = default;

    /// Copy an error while preserving the concrete stored type.
    Error& operator=(const Error& other);

    /// Move an error.
    Error& operator=(Error&& other) noexcept = default;

    /// Return the human-readable message for this error.
    const std::string& msg() const;

    /// Return the contained error as T, or nullptr if it has another type.
    template<class T>
    const T* as() const;

    /// Return true when the contained error has type T.
    template<class T>
    bool is() const;

private:
    struct Concept;

    template<class T>
    struct Model;

    std::unique_ptr<Concept> self;
};
```

The exact implementation can vary, but the important pieces are:

```cpp
struct Error::Concept
{
    virtual ~Concept() = default;
    virtual const std::string& msg() const = 0;
    virtual std::unique_ptr<Concept> clone() const = 0;
    virtual const std::type_info& type() const = 0;
    virtual const void* ptr() const = 0;
};

template<class T>
struct Error::Model : Concept
{
    T value;

    explicit Model(T error)
            : value(std::move(error))
    {}

    const std::string& msg() const override
    {
        return value.msg;
    }

    std::unique_ptr<Concept> clone() const override
    {
        return std::make_unique<Model<T>>(value);
    }

    const std::type_info& type() const override
    {
        return typeid(T);
    }

    const void* ptr() const override
    {
        return &value;
    }
};
```

`Concept` is the internal abstract interface. It says what `Error` can do with
any stored error. `Model<T>` adapts one concrete type `T` to that interface.
This is why `Error::msg()` can work without knowing `T`.

`clone()` is required because `Error` owns the stored value through
`std::unique_ptr<Concept>`. When copying an `Error`, the copy constructor only
sees the base class pointer. It cannot call `std::make_unique<Concept>` because
`Concept` is abstract, and copying through the base class would slice away the
real `Model<T>` object. `clone()` acts as a virtual copy constructor: each
`Model<T>` knows its own `T`, so it can copy the correct derived object.

## Concrete error type contract

Any concrete error type stored in `mw::Error` must satisfy these requirements:

1. It has a public `std::string msg` member.
2. It is copy constructible.
3. It is movable.

The `msg` requirement keeps the existing `errorMsg()` behavior simple. It also
matches all current built-in error types.

Example user-defined error:

```cpp
struct ValidationError
{
    std::string field;
    std::string msg;
};
```

Example return:

```cpp
mw::E<int> parseAge(std::string_view value)
{
    if(value.empty())
    {
        return std::unexpected(mw::Error(
            ValidationError{"age", "age is required"}));
    }

    return 42;
}
```

Example inspection:

```cpp
mw::E<int> age = parseAge("");
if(!age.has_value())
{
    if(const auto* err = age.error().as<ValidationError>())
    {
        std::println("invalid field: {}", err->field);
    }
}
```

## Header changes

Update `includes/mw/error.hpp`.

Required includes:

```cpp
#include <expected>
#include <memory>
#include <string>
#include <string_view>
#include <type_traits>
#include <typeinfo>
#include <utility>
```

Remove the direct dependency on `<variant>` from `error.hpp` unless another
type in the file still needs it.

Keep the existing concrete structs. They should continue to look like ordinary
data objects:

```cpp
/// A runtime error with a message.
struct RuntimeError
{
    std::string msg;

    bool operator==(const RuntimeError& rhs) const = default;
};
```

Do the same for `HTTPError` and `PolicyError`.

Add `class Error` after the concrete structs. The `Error(T error)` constructor
must avoid accidentally accepting `Error` itself. Use a constraint similar to:

```cpp
template<class T>
    requires(!std::same_as<std::remove_cvref_t<T>, Error>)
Error(T&& error)
        : self(std::make_unique<Model<std::remove_cvref_t<T>>>(
              std::forward<T>(error)))
{}
```

Use `std::remove_cvref_t<T>` so that constructing from `const HTTPError&`,
`HTTPError&`, and `HTTPError&&` all store `HTTPError` as the concrete type.

Add compile-time checks inside the constructor or `Model<T>` so unsupported
types fail with a clear compiler error:

```cpp
static_assert(std::copy_constructible<T>);
static_assert(requires(const T& error) {
    { error.msg } -> std::same_as<const std::string&>;
});
```

If the exact `std::same_as<const std::string&>` check is too strict for the
compiler or style, use a simpler requirement that `error.msg` is a
`std::string`. The goal is to reject a type that cannot provide a stable string
reference.

Keep `mw::E<T>` as:

```cpp
template<class T>
using E = std::expected<T, Error>;
```

Keep helper constructors source-compatible:

```cpp
/// Construct a RuntimeError with a message as an Error.
inline Error runtimeError(std::string_view msg)
{
    return RuntimeError{std::string(msg)};
}

/// Construct an HTTPError as an Error.
inline Error httpError(int code, std::string_view msg)
{
    return HTTPError{code, std::string(msg)};
}

/// Construct a PolicyError with a message as an Error.
inline Error policyError(std::string_view msg)
{
    return PolicyError{std::string(msg)};
}
```

Keep `errorMsg()` source-compatible:

```cpp
/// Extract the error message from an Error.
inline const std::string& errorMsg(const Error& e)
{
    return e.msg();
}
```

## Implementation details

`Error::msg()` should be:

```cpp
const std::string& Error::msg() const
{
    return self->msg();
}
```

`Error::as<T>()` should check the exact stored type:

```cpp
template<class T>
const T* Error::as() const
{
    using Stored = std::remove_cvref_t<T>;
    if(self->type() != typeid(Stored))
    {
        return nullptr;
    }

    return static_cast<const Stored*>(self->ptr());
}
```

`Error::is<T>()` should delegate to `as<T>()`:

```cpp
template<class T>
bool Error::is() const
{
    return as<T>() != nullptr;
}
```

The copy constructor should be:

```cpp
Error::Error(const Error& other)
        : self(other.self->clone())
{}
```

The copy assignment operator should handle self-assignment naturally:

```cpp
Error& Error::operator=(const Error& other)
{
    if(this == &other)
    {
        return *this;
    }

    self = other.self->clone();
    return *this;
}
```

The class does not need a default constructor. An `Error` without a concrete
error value is not meaningful. Avoid adding an empty state unless a real call
site requires it.

## Call site migration

Find every call site that assumes `mw::Error` is a `std::variant`.

Search commands:

```sh
rg -n "holds_alternative|get<|visit" includes src crypto sqlite url http-server
```

Only update the matches that operate on `mw::Error`. The repository also uses
`std::variant` for unrelated types such as socket configuration and process
input/output. Those must not be changed.

### HTTP server response conversion

`includes/mw/http_server.hpp` currently checks for `HTTPError` with
`std::holds_alternative<mw::HTTPError>()`. Change that logic to:

```cpp
if(const mw::HTTPError* e = tmp.error().as<mw::HTTPError>())
{
    res.status = e->code;
    res.set_content(e->msg, "text/plain");
    return;
}
else
{
    res.status = 500;
    res.set_content(errorMsg(tmp.error()), "text/plain");
    return;
}
```

This preserves the current behavior:

- `HTTPError` controls the HTTP status code.
- Every other error type maps to status `500`.
- The response body is still the error message.

### Tests that inspect concrete errors

Tests such as `url/src/http_client_test.cpp` currently use
`std::holds_alternative<RuntimeError>()` and `std::get<RuntimeError>()`. Replace
them with `as<T>()`:

```cpp
const auto* err = result.error().as<RuntimeError>();
ASSERT_NE(err, nullptr);
EXPECT_EQ(err->msg, "...");
```

This is slightly more verbose, but it works for both built-in and user-defined
errors.

### Tests or code that use `std::visit`

For code that only needs the message, replace `std::visit(...)` with
`errorMsg(error)` or `error.msg()`.

Old:

```cpp
std::visit([](const auto& e) { return e.msg; }, result.error())
```

New:

```cpp
errorMsg(result.error())
```

Do not try to reproduce generic `std::visit` for user-defined error types.
Compile-time visitation requires a closed set of types, which conflicts with
the goal of allowing callers to add new types.

## Compatibility notes

This is a source-compatible change for callers that only:

- Return `mw::E<T>`.
- Use `runtimeError()`, `httpError()`, or `policyError()`.
- Use `errorMsg()`.

This is a source-breaking change for callers that treat `mw::Error` as a
`std::variant`, including callers that use:

- `std::holds_alternative<T>(error)`.
- `std::get<T>(error)`.
- `std::visit(visitor, error)`.

The replacement API is:

- `error.is<T>()` instead of `std::holds_alternative<T>(error)`.
- `error.as<T>()` instead of `std::get<T>(error)`.
- `errorMsg(error)` instead of a visitor that only reads `msg`.

This break is acceptable if the library is still evolving. If downstream
compatibility is a major concern, document the migration in `README.adoc` or a
changelog.

## Performance considerations

The current `std::variant` stores the error inline. The new `Error` design
allocates once when an error is created because it stores a
`std::unique_ptr<Concept>`.

That tradeoff is acceptable for this library because errors are the uncommon
path. The successful path of `mw::E<T>` is unchanged. The cost is paid only when
creating or copying an error.

The design keeps `Error` copyable because `std::expected<T, Error>` is easier to
use when both `T` and `Error` are copyable. Making `Error` move-only would avoid
`clone()`, but it would make ordinary expected-value usage more restrictive.

## Edge cases

### Constructing from `Error`

The templated constructor must not accept `Error` itself. If it did, code such
as `Error other = error;` could accidentally store an `Error` inside another
`Error` instead of using the copy constructor.

### Exact type matching

`as<T>()` should match exact stored types. If a caller stores `DerivedError`,
then `as<BaseError>()` should return `nullptr` unless the design explicitly
adds inheritance-aware support. Avoid inheritance-aware matching for now because
it complicates ownership and does not fit the current plain-struct error style.

### Message lifetime

`msg()` and `errorMsg()` return a reference to the message inside the stored
error. That reference is valid only while the `Error` object is alive and not
assigned a different value. This matches the current `std::variant` behavior.

### Equality

The existing concrete error structs can keep `operator==`. Do not add
`operator==` to `mw::Error` in the first implementation. Comparing two erased
objects is possible, but it requires another virtual operation and a policy for
cross-type comparisons. No current production code requires it.

If tests need equality, compare through `as<T>()` and then compare the concrete
structs.

## Testing plan

Add focused tests for `mw::Error` itself. If there is no existing core test file
for `error.hpp`, add tests in the core test target near `src/utils_test.cpp` or
create a small `src/error_test.cpp` and wire it into the existing CMake target.

Required tests:

1. `RuntimeErrorMessage`
   - Construct `mw::Error` from `RuntimeError`.
   - Verify `errorMsg(error)` returns the stored message.

2. `HTTPErrorCanBeInspected`
   - Construct `mw::Error` with `httpError(404, "missing")`.
   - Verify `error.as<HTTPError>()` is not `nullptr`.
   - Verify `code == 404` and `msg == "missing"`.
   - Verify `error.as<RuntimeError>() == nullptr`.

3. `CustomErrorCanBeStored`
   - Define a test-only `CustomError` with at least one field besides `msg`.
   - Store it in `mw::Error`.
   - Verify `errorMsg(error)` and `error.as<CustomError>()`.

4. `ErrorCopyPreservesConcreteType`
   - Store a `CustomError`.
   - Copy the `mw::Error`.
   - Verify the copy still returns `as<CustomError>()`.
   - Verify the copied fields are equal to the original fields.

5. `ExpectedCanReturnCustomError`
   - Write a small local function returning `mw::E<int>`.
   - Return `std::unexpected(mw::Error(CustomError{...}))`.
   - Verify the caller can inspect the custom error.

6. `HTTPServerUsesHTTPErrorStatus`
   - If there is already coverage around `ASSIGN_OR_RESPOND_ERROR`, update it
     to verify the new `as<HTTPError>()` path still sets the response status.
   - If no such test exists, add a small test or rely on existing HTTP server
     behavior tests if they exercise this macro.

Also run the full test suite because this change touches a central header used
by every module.

## Implementation steps

1. Edit `includes/mw/error.hpp`.
2. Add the `Error` class and keep the built-in error structs.
3. Keep `E<T>` as `std::expected<T, Error>`.
4. Reimplement `runtimeError()`, `httpError()`, `policyError()`, and
   `errorMsg()` on top of the new class.
5. Search for `std::variant` operations on `mw::Error`.
6. Replace `std::holds_alternative<T>(error)` with `error.is<T>()` or
   `error.as<T>()`.
7. Replace `std::get<T>(error)` with dereferencing the checked `as<T>()`
   pointer.
8. Replace message-only `std::visit()` calls with `errorMsg(error)`.
9. Add the focused tests listed above.
10. Build and run tests.
11. Update docs if the public API documentation mentions `mw::Error` as a
    `std::variant`.

## Acceptance

- A user can define their own error struct with `std::string msg` and return it
  through `mw::E<T>` without editing `libmw`.
- `runtimeError()`, `httpError()`, `policyError()`, and `errorMsg()` still work.
- Existing `mw::E<T>` function signatures remain valid.
- `HTTPError` can still be detected by HTTP server glue so HTTP status handling
  is preserved.
- Existing tests pass after migrating variant-specific assertions.
- New tests prove custom errors can be stored, copied, returned through
  `mw::E<T>`, and inspected with `as<T>()`.
