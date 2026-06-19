#pragma once

#include <concepts>
#include <expected>
#include <memory>
#include <string>
#include <string_view>
#include <type_traits>
#include <typeinfo>
#include <utility>

namespace mw
{

/// A runtime error with a message.
struct RuntimeError
{
    std::string msg;

    bool operator==(const RuntimeError& rhs) const = default;
};

/// An HTTP error with a status code and a message.
struct HTTPError
{
    int code;
    std::string msg;

    bool operator==(const HTTPError& rhs) const = default;
};

/// An error indicating a request was refused by a caller-installed
/// policy (for example, the HTTP client's address filter rejecting an
/// SSRF target), as opposed to a network or protocol failure. Callers
/// can match on this type to distinguish a deliberate policy block.
struct PolicyError
{
    std::string msg;

    bool operator==(const PolicyError& rhs) const = default;
};

/// An open container for any copyable concrete error type with a
/// `std::string msg` member.
///
/// `Error` uses type erasure: it stores the concrete error object behind a
/// small virtual interface, so `mw::E<T>` can carry built-in errors such as
/// `RuntimeError` and caller-defined errors without changing this header.
/// Copying an `Error` preserves the concrete stored type.
///
/// Library users can define their own error structs:
/// ```
/// struct ValidationError
/// {
///     std::string field;
///     std::string msg;
/// };
/// ```
/// Return one with `std::unexpected(mw::Error(ValidationError{...}))`.
/// Inspect it with `error.as<ValidationError>()`, or use `error.msg()` /
/// `mw::errorMsg(error)` when only the human-readable message is needed.
class Error
{
public:
    /// Construct an error from any supported concrete error type.
    template<class T>
        requires(!std::same_as<std::remove_cvref_t<T>, Error>)
    Error(T&& error)
            : self(std::make_unique<Model<std::remove_cvref_t<T>>>(
                  std::forward<T>(error)))
    {}

    /// Copy an error while preserving the concrete stored type.
    Error(const Error& other)
            : self(other.self->clone())
    {}

    /// Move an error.
    Error(Error&& other) noexcept = default;

    /// Copy an error while preserving the concrete stored type.
    Error& operator=(const Error& other)
    {
        if(this == &other)
        {
            return *this;
        }

        self = other.self->clone();
        return *this;
    }

    /// Move an error.
    Error& operator=(Error&& other) noexcept = default;

    /// Return the human-readable message for this error.
    const std::string& msg() const
    {
        return self->msg();
    }

    /// Return the contained error as T, or nullptr if it has another type.
    template<class T>
    const T* as() const
    {
        using Stored = std::remove_cvref_t<T>;
        if(self->type() != typeid(Stored))
        {
            return nullptr;
        }

        return static_cast<const Stored*>(self->ptr());
    }

    /// Return true when the contained error has type T.
    template<class T>
    bool is() const
    {
        return as<T>() != nullptr;
    }

private:
    struct Concept
    {
        virtual ~Concept() = default;
        virtual const std::string& msg() const = 0;
        virtual std::unique_ptr<Concept> clone() const = 0;
        virtual const std::type_info& type() const = 0;
        virtual const void* ptr() const = 0;
    };

    template<class T>
    struct Model : Concept
    {
        static_assert(std::copy_constructible<T>);
        static_assert(requires(const T& error) {
            { error.msg } -> std::same_as<const std::string&>;
        });

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

    std::unique_ptr<Concept> self;
};

/// This is intended as the return type of any function that could
/// cause an error. For example:
/// ```
/// E<int> convertStringToInt(std::string_view s);
/// ```
template<class T>
using E = std::expected<T, Error>;

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

/// Extract the error message from an Error.
inline const std::string& errorMsg(const Error& e)
{
    return e.msg();
}

} // namespace mw
