#include <chrono>
#include <algorithm>
#include <condition_variable>
#include <coroutine>
#include <cstddef>
#include <format>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#include <gtest/gtest.h>
#include <httplib.h>

#include "error.hpp"
#include "http_client_async.hpp"
#include "task.hpp"

namespace mw
{

namespace
{

template<class T>
class SyncWaitTask
{
public:
    struct promise_type
    {
        SyncWaitTask get_return_object()
        {
            return SyncWaitTask(
                std::coroutine_handle<promise_type>::from_promise(*this));
        }

        std::suspend_always initial_suspend() noexcept
        {
            return {};
        }

        auto final_suspend() noexcept
        {
            struct Awaiter
            {
                bool await_ready() noexcept
                {
                    return false;
                }

                void await_suspend(
                    std::coroutine_handle<promise_type> h) noexcept
                {
                    auto& promise = h.promise();
                    {
                        std::lock_guard lock(promise.mutex);
                        promise.done = true;
                    }
                    promise.cv.notify_one();
                }

                void await_resume() noexcept {}
            };

            return Awaiter{};
        }

        template<class U>
        void return_value(U&& v)
        {
            value.emplace(std::forward<U>(v));
        }

        void unhandled_exception()
        {
            exception = std::current_exception();
        }

        std::mutex mutex;
        std::condition_variable cv;
        bool done = false;
        std::optional<T> value;
        std::exception_ptr exception;
    };

    explicit SyncWaitTask(std::coroutine_handle<promise_type> handle)
            : handle(handle)
    {}

    SyncWaitTask(SyncWaitTask&& other) noexcept
            : handle(std::exchange(other.handle, nullptr))
    {}

    SyncWaitTask& operator=(SyncWaitTask&& other) noexcept
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

    SyncWaitTask(const SyncWaitTask&) = delete;
    SyncWaitTask& operator=(const SyncWaitTask&) = delete;

    ~SyncWaitTask()
    {
        if(handle != nullptr)
        {
            handle.destroy();
        }
    }

    void start()
    {
        handle.resume();
    }

    T get()
    {
        auto& promise = handle.promise();
        std::unique_lock lock(promise.mutex);
        promise.cv.wait(lock, [&]() { return promise.done; });
        lock.unlock();

        if(promise.exception != nullptr)
        {
            std::rethrow_exception(promise.exception);
        }
        return std::move(*promise.value);
    }

private:
    std::coroutine_handle<promise_type> handle = nullptr;
};

template<class T>
SyncWaitTask<T> makeWaiter(Task<T> task)
{
    co_return co_await std::move(task);
}

template<class T>
T syncWait(Task<T> task)
{
    auto waiter = makeWaiter(std::move(task));
    waiter.start();
    return waiter.get();
}

Task<int> three()
{
    co_return 3;
}

Task<E<int>> expectedError()
{
    co_return std::unexpected(runtimeError("fail"));
}

} // namespace

TEST(Task, ReturnsValue)
{
    EXPECT_EQ(syncWait(three()), 3);
}

TEST(Task, PropagatesExpected)
{
    E<int> result = syncWait(expectedError());
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().msg(), "fail");
}

TEST(HTTPSessionAsync, CanGet)
{
    httplib::Server server;
    server.Get("/", [](const httplib::Request&, httplib::Response& res)
    {
        res.set_content("aaa", "text/plain");
    });
    int port = server.bind_to_any_port("localhost");
    ASSERT_GT(port, 0);
    std::thread thread([&]()
    {
        server.listen_after_bind();
    });
    server.wait_until_ready();

    {
        HTTPSessionAsync session;
        auto result = syncWait(
            session.get(HTTPRequest(std::format(
                "http://localhost:{}/", port))));
        ASSERT_TRUE(result.has_value());
        EXPECT_EQ(result->status, 200);
        EXPECT_EQ(result->payloadAsStr(), "aaa");
        ASSERT_TRUE(result->header.contains("Content-Type"));
        EXPECT_EQ(result->header.at("Content-Type"), "text/plain");
    }

    server.stop();
    thread.join();
}

TEST(HTTPSessionAsync, CanPost)
{
    httplib::Server server;
    server.Post("/", [](const httplib::Request& req,
                        httplib::Response& res)
    {
        if(req.body == "aaa")
        {
            res.set_content("bbb", "text/plain");
            return;
        }
        res.status = 400;
    });
    int port = server.bind_to_any_port("localhost");
    ASSERT_GT(port, 0);
    std::thread thread([&]()
    {
        server.listen_after_bind();
    });
    server.wait_until_ready();

    {
        HTTPSessionAsync session;
        auto result = syncWait(session.post(
            HTTPRequest(std::format("http://localhost:{}/", port))
                .setPayload("aaa")
                .setContentType("text/plain")));
        ASSERT_TRUE(result.has_value());
        EXPECT_EQ(result->status, 200);
        EXPECT_EQ(result->payloadAsStr(), "bbb");
    }

    server.stop();
    thread.join();
}

TEST(HTTPSessionAsync, ConcurrentGets)
{
    using namespace std::chrono_literals;

    httplib::Server server;
    server.Get("/a", [](const httplib::Request&, httplib::Response& res)
    {
        std::this_thread::sleep_for(200ms);
        res.set_content("a", "text/plain");
    });
    server.Get("/b", [](const httplib::Request&, httplib::Response& res)
    {
        std::this_thread::sleep_for(200ms);
        res.set_content("b", "text/plain");
    });
    int port = server.bind_to_any_port("localhost");
    ASSERT_GT(port, 0);
    std::thread thread([&]()
    {
        server.listen_after_bind();
    });
    server.wait_until_ready();

    {
        HTTPSessionAsync session;
        auto a = makeWaiter(session.get(HTTPRequest(std::format(
            "http://localhost:{}/a", port))));
        auto b = makeWaiter(session.get(HTTPRequest(std::format(
            "http://localhost:{}/b", port))));

        auto start = std::chrono::steady_clock::now();
        a.start();
        b.start();
        auto res_a = a.get();
        auto res_b = b.get();
        auto elapsed = std::chrono::steady_clock::now() - start;

        ASSERT_TRUE(res_a.has_value());
        ASSERT_TRUE(res_b.has_value());
        EXPECT_EQ(res_a->payloadAsStr(), "a");
        EXPECT_EQ(res_b->payloadAsStr(), "b");
        EXPECT_LT(elapsed, 375ms);
    }

    server.stop();
    thread.join();
}

TEST(HTTPSessionAsync, AddressFilterBlocksLoopback)
{
    httplib::Server server;
    bool handler_called = false;
    server.Get("/", [&](const httplib::Request&, httplib::Response& res)
    {
        handler_called = true;
        res.set_content("aaa", "text/plain");
    });
    int port = server.bind_to_any_port("localhost");
    ASSERT_GT(port, 0);
    std::thread thread([&]()
    {
        server.listen_after_bind();
    });
    server.wait_until_ready();

    {
        HTTPSessionAsync session;
        int filter_calls = 0;
        session.addressFilter([&](const SockAddr& addr) -> bool
        {
            ++filter_calls;
            if(addr.family == AddressFamily::IPV4 && !addr.address.empty() &&
               addr.address[0] == 127)
            {
                return false;
            }
            if(addr.family == AddressFamily::IPV6 &&
               addr.address.size() == 16 &&
               std::all_of(addr.address.begin(), addr.address.end() - 1,
                           [](std::uint8_t b) { return b == 0; }) &&
               addr.address.back() == 1)
            {
                return false;
            }
            return true;
        });

        auto result = syncWait(session.get(
            HTTPRequest(std::format("http://localhost:{}/", port))));
        ASSERT_FALSE(result.has_value());
        ASSERT_NE(result.error().as<PolicyError>(), nullptr);
        EXPECT_EQ(result.error().msg(), std::string(HTTP_BLOCKED_BY_POLICY));
        EXPECT_GE(filter_calls, 1);
        EXPECT_FALSE(handler_called);
    }

    server.stop();
    thread.join();
}

TEST(HTTPSessionAsync, AllowedProtocolsRejectsDisallowedUrl)
{
    HTTPSessionAsync session;
    ASSERT_TRUE(session.allowedProtocols("https").has_value());
    auto result = syncWait(session.get(HTTPRequest("http://127.0.0.1/")));
    ASSERT_FALSE(result.has_value());
    EXPECT_NE(result.error().as<RuntimeError>(), nullptr);
}

TEST(HTTPSessionAsync, StreamDeliversChunks)
{
    constexpr size_t payload_size = 64 * 1024;
    std::string payload(payload_size, 'x');

    httplib::Server server;
    server.Get("/stream", [&](const httplib::Request&,
                              httplib::Response& res)
    {
        res.set_content(payload, "application/octet-stream");
    });
    int port = server.bind_to_any_port("localhost");
    ASSERT_GT(port, 0);
    std::thread thread([&]()
    {
        server.listen_after_bind();
    });
    server.wait_until_ready();

    {
        HTTPSessionAsync session;
        std::vector<std::byte> received;
        auto result = syncWait(session.getStream(
            HTTPRequest(std::format("http://localhost:{}/stream", port)),
            [&](std::span<const std::byte> chunk) -> bool
            {
                received.insert(received.end(), chunk.begin(), chunk.end());
                return true;
            }));

        ASSERT_TRUE(result.has_value());
        EXPECT_EQ(result->status, 200);
        EXPECT_TRUE(result->payload.empty());
        EXPECT_EQ(received.size(), payload.size());
        EXPECT_EQ(std::string_view(
                      reinterpret_cast<const char*>(received.data()),
                      received.size()),
                  payload);
    }

    server.stop();
    thread.join();
}

TEST(HTTPSessionAsync, StreamCallbackAbort)
{
    constexpr size_t payload_size = 64 * 1024;
    std::string payload(payload_size, 'x');

    httplib::Server server;
    server.Get("/abort", [&](const httplib::Request&, httplib::Response& res)
    {
        res.set_content(payload, "application/octet-stream");
    });
    int port = server.bind_to_any_port("localhost");
    ASSERT_GT(port, 0);
    std::thread thread([&]()
    {
        server.listen_after_bind();
    });
    server.wait_until_ready();

    {
        HTTPSessionAsync session;
        int chunks_seen = 0;
        auto result = syncWait(session.getStream(
            HTTPRequest(std::format("http://localhost:{}/abort", port)),
            [&](std::span<const std::byte>) -> bool
            {
                ++chunks_seen;
                return false;
            }));
        ASSERT_FALSE(result.has_value());
        EXPECT_EQ(result.error().msg(), std::string(HTTP_ABORTED_BY_CALLER));
        EXPECT_EQ(chunks_seen, 1);
    }

    server.stop();
    thread.join();
}

TEST(HTTPSessionAsync, DestructorCancelsStartedRequest)
{
    using namespace std::chrono_literals;

    httplib::Server server;
    server.Get("/slow", [](const httplib::Request&, httplib::Response& res)
    {
        std::this_thread::sleep_for(2s);
        res.set_content("late", "text/plain");
    });
    int port = server.bind_to_any_port("localhost");
    ASSERT_GT(port, 0);
    std::thread thread([&]()
    {
        server.listen_after_bind();
    });
    server.wait_until_ready();

    std::optional<SyncWaitTask<E<HTTPResponse>>> waiter;
    {
        HTTPSessionAsync session;
        waiter.emplace(makeWaiter(session.get(
            HTTPRequest(std::format("http://localhost:{}/slow", port)))));
        waiter->start();
    }

    auto result = waiter->get();
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().msg(), "transfer cancelled");

    server.stop();
    thread.join();
}

} // namespace mw
