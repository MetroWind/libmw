#include <chrono>
#include <cstddef>
#include <format>
#include <iterator>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

#include <httplib.h>
#include <gtest/gtest.h>
#include <curl/curl.h>

#include "error.hpp"
#include "http_client.hpp"

namespace mw
{

class CurlEnv : public ::testing::Environment
{
public:
    ~CurlEnv() override = default;
    void SetUp() override
    {
        curl_global_init(CURL_GLOBAL_ALL);
    }
};

testing::Environment* const curl_env =
    testing::AddGlobalTestEnvironment(new CurlEnv);

TEST(HTTPSession, CanGet)
{
    using namespace std::chrono_literals;

    httplib::Server server;
    server.Get("/", [](const httplib::Request &, httplib::Response &res) {
        res.set_content("aaa", "text/plain");
    });
    int port;
    std::thread t([&]()
    {
        port = server.bind_to_any_port("localhost");
        server.listen_after_bind();
    });
    server.wait_until_ready();

    {
        HTTPSession s;
        auto result = s.get(std::format("http://localhost:{}/", port));
        ASSERT_TRUE(result.has_value());
        const std::vector<std::byte>& payload = (*result)->payload;
        EXPECT_EQ(std::string_view(reinterpret_cast<const char*>(payload.data()),
                                   payload.size()),
                  "aaa");
        EXPECT_EQ((*result)->status, 200);
        ASSERT_TRUE((*result)->header.contains("Content-Type"));
        EXPECT_EQ((*result)->header.at("Content-Type"), "text/plain");

        // HTTP error
        result = s.get(std::format("http://localhost:{}/aaa", port));
        ASSERT_TRUE(result.has_value());
        EXPECT_EQ((*result)->status, 404);

        // cURL error
        result = s.get("http://bad.invalid/");
        EXPECT_FALSE(result.has_value());
    }

    server.stop();
    t.join();
}

TEST(HTTPSession, CanPost)
{
    using namespace std::chrono_literals;

    httplib::Server server;
    server.Post("/", [](const httplib::Request& req, httplib::Response& res) {
        EXPECT_FALSE(req.is_multipart_form_data());
        auto idx = req.headers.find("Content-Type");
        if(req.body == "aaa" && idx != std::end(req.headers) &&
           idx->second == "text/plain")
        {
            res.set_content("bbb", "text/plain");
        }
        else
        {
            res.set_content("error", "text/plain");
            res.status = 401;
        }
    });
    int port;
    std::thread t([&]()
    {
        port = server.bind_to_any_port("localhost");
        server.listen_after_bind();
    });
    server.wait_until_ready();

    {
        HTTPSession s;
        {
            E<const HTTPResponse*> result = s.post(
                HTTPRequest(std::format("http://localhost:{}/", port))
                .setPayload("aaa")
                .setContentType("text/plain"));
            ASSERT_TRUE(result.has_value());
            const HTTPResponse& res = **result;
            EXPECT_EQ(res.status, 200);
            ASSERT_TRUE(res.header.contains("Content-Type"));
            EXPECT_EQ(res.header.at("Content-Type"), "text/plain");
            EXPECT_EQ(std::string_view(
                          reinterpret_cast<const char*>(res.payload.data()),
                          res.payload.size()),
                      "bbb");
        }
        {
            E<const HTTPResponse*> result = s.post(
                HTTPRequest(std::format("http://localhost:{}/", port))
                .addHeader("Content-Type", "text/plain").setPayload("nonono"));
            ASSERT_TRUE(result.has_value());
            const HTTPResponse& res = **result;
            EXPECT_EQ(res.status, 401);
            ASSERT_TRUE(res.header.contains("Content-Type"));
            EXPECT_EQ(res.header.at("Content-Type"), "text/plain");
            EXPECT_EQ(std::string_view(
                          reinterpret_cast<const char*>(res.payload.data()),
                          res.payload.size()),
                      "error");
        }
    }

    server.stop();
    t.join();
}

TEST(HTTPSession, LargeResponseNotTruncated)
{
    // Regression test for the buffer-overwrite bug: writeResponse
    // used to resize-and-overwrite on every libcurl chunk, so any
    // response larger than CURL_MAX_WRITE_SIZE was silently
    // truncated to the size of the final chunk.
    constexpr size_t payload_size = 64 * 1024;
    std::string big_payload;
    big_payload.reserve(payload_size);
    for(size_t i = 0; i < payload_size; ++i)
    {
        big_payload.push_back(static_cast<char>(i & 0xff));
    }

    httplib::Server server;
    server.Get("/big", [&](const httplib::Request&, httplib::Response& res)
    {
        res.set_content(big_payload, "application/octet-stream");
    });
    int port;
    std::thread t([&]()
    {
        port = server.bind_to_any_port("localhost");
        server.listen_after_bind();
    });
    server.wait_until_ready();

    {
        HTTPSession s;
        auto result = s.get(std::format("http://localhost:{}/big", port));
        ASSERT_TRUE(result.has_value());
        const auto& payload = (*result)->payload;
        ASSERT_EQ(payload.size(), payload_size);
        for(size_t i = 0; i < payload_size; ++i)
        {
            ASSERT_EQ(static_cast<unsigned char>(payload[i]),
                      static_cast<unsigned char>(i & 0xff)) << "at " << i;
        }
    }

    server.stop();
    t.join();
}

TEST(HTTPSession, StreamDeliversChunksInOrder)
{
    // Send a body large enough to span multiple libcurl write
    // callbacks; verify the streaming variant reassembles to the
    // original bytes in order.
    constexpr size_t payload_size = 64 * 1024;
    std::string big_payload;
    big_payload.reserve(payload_size);
    for(size_t i = 0; i < payload_size; ++i)
    {
        big_payload.push_back(static_cast<char>((i * 31) & 0xff));
    }

    httplib::Server server;
    server.Get("/stream", [&](const httplib::Request&, httplib::Response& res)
    {
        res.set_content(big_payload, "application/octet-stream");
    });
    int port;
    std::thread t([&]()
    {
        port = server.bind_to_any_port("localhost");
        server.listen_after_bind();
    });
    server.wait_until_ready();

    {
        HTTPSession s;
        std::vector<std::byte> received;
        int chunk_count = 0;
        auto result = s.getStream(
            HTTPRequest(std::format("http://localhost:{}/stream", port)),
            [&](std::span<const std::byte> chunk) -> bool
            {
                ++chunk_count;
                received.insert(received.end(),
                                chunk.begin(), chunk.end());
                return true;
            });
        ASSERT_TRUE(result.has_value());
        EXPECT_EQ(result->status, 200);
        EXPECT_TRUE(result->payload.empty());
        ASSERT_EQ(received.size(), payload_size);
        for(size_t i = 0; i < payload_size; ++i)
        {
            ASSERT_EQ(static_cast<unsigned char>(received[i]),
                      static_cast<unsigned char>((i * 31) & 0xff))
                << "at " << i;
        }
        EXPECT_GE(chunk_count, 1);
    }

    server.stop();
    t.join();
}

TEST(HTTPSession, StreamCallbackAbort)
{
    constexpr size_t payload_size = 64 * 1024;
    std::string big_payload(payload_size, 'x');

    httplib::Server server;
    server.Get("/abort", [&](const httplib::Request&, httplib::Response& res)
    {
        res.set_content(big_payload, "application/octet-stream");
    });
    int port;
    std::thread t([&]()
    {
        port = server.bind_to_any_port("localhost");
        server.listen_after_bind();
    });
    server.wait_until_ready();

    {
        HTTPSession s;
        int chunks_seen = 0;
        auto result = s.getStream(
            HTTPRequest(std::format("http://localhost:{}/abort", port)),
            [&](std::span<const std::byte>) -> bool
            {
                ++chunks_seen;
                // Abort after the first chunk.
                return false;
            });
        ASSERT_FALSE(result.has_value());
        const Error& err = result.error();
        const RuntimeError* runtime_error = err.as<RuntimeError>();
        ASSERT_NE(runtime_error, nullptr);
        EXPECT_EQ(runtime_error->msg, std::string(HTTP_ABORTED_BY_CALLER));
        EXPECT_EQ(chunks_seen, 1);
    }

    server.stop();
    t.join();
}

TEST(HTTPSession, Options)
{
    using namespace std::chrono_literals;

    HTTPSession s;

    // Default values
    EXPECT_EQ(s.transferTimeout().count(), 0);
    EXPECT_EQ(s.connectionTimeout().count(), 60);
    EXPECT_EQ(s.maxSize(), 2147483648);
    EXPECT_EQ(s.maxRedirections(), 0);

    // Set and get
    ASSERT_TRUE(s.transferTimeout(10s).has_value());
    EXPECT_EQ(s.transferTimeout().count(), 10);

    ASSERT_TRUE(s.connectionTimeout(30s).has_value());
    EXPECT_EQ(s.connectionTimeout().count(), 30);

    ASSERT_TRUE(s.maxSize(1024).has_value());
    EXPECT_EQ(s.maxSize(), 1024);

    ASSERT_TRUE(s.maxRedirections(5).has_value());
    EXPECT_EQ(s.maxRedirections(), 5);

    EXPECT_TRUE(s.followRedirects());
    s.followRedirects(false);
    EXPECT_FALSE(s.followRedirects());

    EXPECT_FALSE(s.addressFilter());
    s.addressFilter([](const SockAddr&) { return true; });
    EXPECT_TRUE(s.addressFilter());

    EXPECT_TRUE(s.allowedProtocols("https").has_value());
    EXPECT_TRUE(s.allowedRedirectProtocols("https").has_value());
}

// An installed address filter that rejects loopback addresses must
// cause a request to a loopback server to fail before any data is
// transferred, with the distinguishable HTTP_BLOCKED_BY_POLICY error.
TEST(HTTPSession, AddressFilterBlocksLoopback)
{
    httplib::Server server;
    bool handler_called = false;
    server.Get("/", [&](const httplib::Request&, httplib::Response& res)
    {
        handler_called = true;
        res.set_content("aaa", "text/plain");
    });
    int port = 0;
    std::thread t([&]()
    {
        port = server.bind_to_any_port("127.0.0.1");
        server.listen_after_bind();
    });
    server.wait_until_ready();

    {
        HTTPSession s;
        int filter_calls = 0;
        SockAddr seen;
        s.addressFilter([&](const SockAddr& addr) -> bool
        {
            ++filter_calls;
            seen = addr;
            // Reject IPv4 loopback (127.0.0.0/8).
            if(addr.family == AddressFamily::IPV4 && !addr.address.empty() &&
               addr.address[0] == 127)
            {
                return false;
            }
            return true;
        });

        auto result = s.get(std::format("http://127.0.0.1:{}/", port));
        ASSERT_FALSE(result.has_value());
        const Error& err = result.error();
        // A policy block is a distinct error type, not a network error.
        const PolicyError* policy_error = err.as<PolicyError>();
        ASSERT_NE(policy_error, nullptr);
        EXPECT_EQ(policy_error->msg, std::string(HTTP_BLOCKED_BY_POLICY));
        // The filter saw the address, and the connection was aborted
        // before the server handler ran.
        EXPECT_GE(filter_calls, 1);
        EXPECT_EQ(seen.family, AddressFamily::IPV4);
        EXPECT_FALSE(handler_called);
    }

    server.stop();
    t.join();
}

// A filter that allows the loopback address must let the request
// proceed normally, confirming the open-socket path still connects.
TEST(HTTPSession, AddressFilterAllowsConnection)
{
    httplib::Server server;
    server.Get("/", [](const httplib::Request&, httplib::Response& res)
    {
        res.set_content("ok", "text/plain");
    });
    int port = 0;
    std::thread t([&]()
    {
        port = server.bind_to_any_port("127.0.0.1");
        server.listen_after_bind();
    });
    server.wait_until_ready();

    {
        HTTPSession s;
        s.addressFilter([](const SockAddr&) { return true; });
        auto result = s.get(std::format("http://127.0.0.1:{}/", port));
        ASSERT_TRUE(result.has_value());
        EXPECT_EQ((*result)->status, 200);
        EXPECT_EQ((*result)->payloadAsStr(), "ok");
    }

    server.stop();
    t.join();
}

} // namespace mw
