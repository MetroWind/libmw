#pragma once

#include <coroutine>
#include <exception>
#include <expected>
#include <optional>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <utility>

#include "error.hpp"

namespace mw
{

namespace detail
{

template<class T>
struct IsExpectedWithError : std::false_type
{};

template<class V>
struct IsExpectedWithError<std::expected<V, Error>> : std::true_type
{};

inline std::string exceptionMessage(std::exception_ptr ptr)
{
    try
    {
        if(ptr != nullptr)
        {
            std::rethrow_exception(ptr);
        }
    }
    catch(const std::exception& e)
    {
        return e.what();
    }
    catch(...)
    {
        return "unknown coroutine exception";
    }

    return "unknown coroutine exception";
}

} // namespace detail

/// A lazy, move-only coroutine task that can be awaited once.
template<class T>
class Task
{
public:
    /// Promise storage used by C++ coroutine machinery.
    struct promise_type
    {
        /// Return the task object bound to this promise.
        Task get_return_object()
        {
            return Task(std::coroutine_handle<promise_type>::from_promise(
                *this));
        }

        /// Start lazily; the coroutine body runs when the task is awaited.
        std::suspend_always initial_suspend() noexcept
        {
            return {};
        }

        /// Resume the awaiting coroutine when this task finishes.
        auto final_suspend() noexcept
        {
            struct Awaiter
            {
                bool await_ready() noexcept
                {
                    return false;
                }

                std::coroutine_handle<> await_suspend(
                    std::coroutine_handle<promise_type> h) noexcept
                {
                    auto continuation = h.promise().continuation;
                    if(continuation != nullptr)
                    {
                        return continuation;
                    }
                    return std::noop_coroutine();
                }

                void await_resume() noexcept {}
            };

            return Awaiter{};
        }

        /// Store a successfully returned task value.
        template<class U>
        void return_value(U&& v)
        {
            value.emplace(std::forward<U>(v));
        }

        /// Capture unexpected coroutine exceptions for await_resume().
        void unhandled_exception()
        {
            exception = std::current_exception();
        }

        std::optional<T> value;
        std::exception_ptr exception;
        std::coroutine_handle<> continuation = nullptr;
    };

    /// Construct an empty task.
    Task() = default;

    /// Move a task handle.
    Task(Task&& other) noexcept
            : handle(std::exchange(other.handle, nullptr))
    {}

    /// Move-assign a task handle.
    Task& operator=(Task&& other) noexcept
    {
        if(this == &other)
        {
            return *this;
        }

        if(handle != nullptr)
        {
            handle.destroy();
        }
        handle = std::exchange(other.handle, nullptr);
        return *this;
    }

    Task(const Task&) = delete;
    Task& operator=(const Task&) = delete;

    /// Destroy the coroutine frame if this task has not been consumed.
    ~Task()
    {
        if(handle != nullptr)
        {
            handle.destroy();
        }
    }

    /// Await this task and consume its result.
    auto operator co_await() &&
    {
        struct Awaiter
        {
            std::coroutine_handle<promise_type> handle;

            bool await_ready() const noexcept
            {
                return false;
            }

            std::coroutine_handle<> await_suspend(
                std::coroutine_handle<> h) const noexcept
            {
                handle.promise().continuation = h;
                return handle;
            }

            T await_resume()
            {
                auto& promise = handle.promise();
                if(promise.exception != nullptr)
                {
                    if constexpr(detail::IsExpectedWithError<T>::value)
                    {
                        auto result = std::unexpected(runtimeError(
                            detail::exceptionMessage(promise.exception)));
                        handle.destroy();
                        return result;
                    }
                    else
                    {
                        std::exception_ptr exception = promise.exception;
                        handle.destroy();
                        std::rethrow_exception(exception);
                    }
                }

                if(!promise.value.has_value())
                {
                    if constexpr(detail::IsExpectedWithError<T>::value)
                    {
                        auto result = std::unexpected(runtimeError(
                            "coroutine completed without a value"));
                        handle.destroy();
                        return result;
                    }
                    else
                    {
                        handle.destroy();
                        throw std::runtime_error(
                            "coroutine completed without a value");
                    }
                }

                T result = std::move(*promise.value);
                handle.destroy();
                return result;
            }
        };

        auto h = std::exchange(handle, nullptr);
        return Awaiter{h};
    }

private:
    explicit Task(std::coroutine_handle<promise_type> h)
            : handle(h)
    {}

    std::coroutine_handle<promise_type> handle = nullptr;
};

} // namespace mw
