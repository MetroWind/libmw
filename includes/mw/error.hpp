#pragma once

#include <expected>
#include <string>
#include <string_view>
#include <variant>

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

/// An error that could be any error type. This is intended to be used
/// with `std::expected`.
using Error = std::variant<RuntimeError, HTTPError>;

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

/// Extract the error message from an Error.
inline const std::string& errorMsg(const Error& e)
{
    return std::visit([](const auto& err) -> const std::string&
    {
        return err.msg;
    }, e);
}

} // namespace mw
